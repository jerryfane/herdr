//! Linux implementation of `herdr fence-exec`: applies a [`FencePlan`] to the
//! current process and execs the pane command. Runs in the pane's child process
//! (single-threaded, before any user code), never in the server.
//!
//! Order (docs/next/design/pane-fence.md, section 3.2): new mount namespace,
//! slave propagation before any mount, plan mounts, device and /proc binds,
//! Landlock domain, capability drop, re-resolved working directory, exec.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use crate::fence::{FenceMount, FencePlan, PROC_READ_ONLY, RAW_CHAR_DEVICES};

pub(crate) const FENCE_SUPPORTED: bool = true;
/// The pane's child execs the server binary it was forked from, even if the file
/// on disk was replaced by an update.
pub(crate) const FENCE_HELPER_PROGRAM: &str = "/proc/self/exe";

// Mount API (linux/mount.h); defined here so the code does not depend on libc
// exposing them for every target.
const OPEN_TREE_CLONE: libc::c_uint = 1;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const MS_PRIVATE: u64 = 1 << 18;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

// Landlock (linux/landlock.h).
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
/// REFER needs ABI 2 (Linux 5.19).
const LANDLOCK_MIN_ABI: libc::c_long = 2;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

// Capabilities (linux/capability.h).
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn step_error(step: &str, path: Option<&Path>, err: io::Error) -> io::Error {
    match path {
        Some(path) => io::Error::new(
            err.kind(),
            format!("{step} failed for {}: {err}", path.display()),
        ),
        None => io::Error::new(err.kind(), format!("{step} failed: {err}")),
    }
}

fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

struct Fd(libc::c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: the fd is owned by this wrapper and closed once.
        unsafe { libc::close(self.0) };
    }
}

/// Clone the mount (tree) at `path`, change its attributes, and attach the clone
/// on top of `path`. `recursive` covers submounts in both the clone and the attributes.
fn rebind(
    path: &Path,
    recursive: bool,
    attr: Option<&MountAttr>,
    clear_rdonly_top: bool,
) -> io::Result<()> {
    let c_path = cstring(path)?;
    let mut flags = OPEN_TREE_CLONE
        | libc::O_CLOEXEC as libc::c_uint
        | libc::AT_SYMLINK_NOFOLLOW as libc::c_uint;
    if recursive {
        flags |= AT_RECURSIVE;
    }
    // SAFETY: valid NUL-terminated path; the returned fd is owned by `Fd`.
    let fd = Fd(check(unsafe {
        libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, c_path.as_ptr(), flags)
    })? as libc::c_int);
    let empty = c"";
    if let Some(attr) = attr {
        let mut at_flags = libc::AT_EMPTY_PATH as libc::c_uint;
        if recursive {
            at_flags |= AT_RECURSIVE;
        }
        // SAFETY: fd is a detached mount tree; attr points to a live MountAttr of the given size.
        check(unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                fd.0,
                empty.as_ptr(),
                at_flags,
                attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        })?;
    }
    if clear_rdonly_top {
        let clear = MountAttr {
            attr_set: 0,
            attr_clr: MOUNT_ATTR_RDONLY,
            propagation: 0,
            userns_fd: 0,
        };
        // SAFETY: as above; no AT_RECURSIVE, so only the top mount becomes writable.
        check(unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                fd.0,
                empty.as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint,
                &clear as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        })?;
    }
    // SAFETY: attaches the detached tree from fd onto the target path.
    check(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd.0,
            empty.as_ptr(),
            libc::AT_FDCWD,
            c_path.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    })?;
    Ok(())
}

fn private_readonly(extra: u64) -> MountAttr {
    MountAttr {
        attr_set: MOUNT_ATTR_RDONLY | extra,
        attr_clr: 0,
        propagation: MS_PRIVATE,
        userns_fd: 0,
    }
}

fn private_only() -> MountAttr {
    MountAttr {
        attr_set: 0,
        attr_clr: 0,
        propagation: MS_PRIVATE,
        userns_fd: 0,
    }
}

/// Bind an empty read-only file over a socket so `connect()` fails.
fn mask_socket(socket: &Path) -> io::Result<()> {
    let source = cstring(Path::new("/dev/null"))?;
    let flags = OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint;
    // SAFETY: valid path; fd owned by `Fd`.
    let fd = Fd(check(unsafe {
        libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, source.as_ptr(), flags)
    })? as libc::c_int);
    let attr = private_readonly(MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
    let empty = c"";
    // SAFETY: fd is a detached mount; attr is valid for the given size.
    check(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd.0,
            empty.as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    })?;
    let target = cstring(socket)?;
    // SAFETY: attaches the detached /dev/null bind over the socket path.
    check(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd.0,
            empty.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    })?;
    Ok(())
}

/// Block devices (and raw memory/port devices) visible in /dev at pane start.
fn raw_device_nodes() -> Vec<PathBuf> {
    let mut nodes = Vec::new();
    for dir in ["/dev", "/dev/mapper"] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if entry.file_type().is_ok_and(|kind| kind.is_block_device()) {
                nodes.push(entry.path());
            }
        }
    }
    for device in RAW_CHAR_DEVICES {
        let path = Path::new(device);
        if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_char_device()) {
            nodes.push(path.to_path_buf());
        }
    }
    nodes.sort();
    nodes
}

fn apply_mounts(plan: &FencePlan) -> io::Result<()> {
    // SAFETY: plain syscalls on the current (single-threaded) process.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(step_error(
            "unshare(CLONE_NEWNS)",
            None,
            io::Error::last_os_error(),
        ));
    }
    let root = c"/";
    // Slave before any other mount: nothing done in the pane reaches the host.
    // SAFETY: remounting propagation of the caller's own namespace.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_SLAVE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(step_error(
            "make / a slave mount",
            None,
            io::Error::last_os_error(),
        ));
    }

    for mount in &plan.mounts {
        let result = match mount {
            // Keeps the inherited (slave) propagation so host mounts in uncovered areas still appear.
            FenceMount::Anchor(path) => {
                rebind(path, true, None, false).map_err(|e| step_error("anchor", Some(path), e))
            }
            FenceMount::Deny(path) => rebind(path, true, Some(&private_readonly(0)), false)
                .map_err(|e| step_error("read-only bind", Some(path), e)),
            FenceMount::Allow(path) => rebind(path, true, Some(&private_only()), true)
                .map_err(|e| step_error("writable carve-out", Some(path), e)),
            FenceMount::Mask(path) => {
                mask_socket(path).map_err(|e| step_error("socket mask", Some(path), e))
            }
        };
        match result {
            Ok(()) => {}
            // Removed between plan resolution and now: skipped, never created.
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }

    for device in raw_device_nodes() {
        match rebind(
            &device,
            false,
            Some(&private_readonly(MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID)),
            false,
        ) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(step_error("nodev bind", Some(&device), err)),
        }
    }
    for entry in PROC_READ_ONLY {
        let path = Path::new(entry);
        match rebind(path, true, Some(&private_readonly(0)), false) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(step_error("read-only bind", Some(path), err)),
        }
    }
    Ok(())
}

fn apply_landlock() -> io::Result<()> {
    // SAFETY: version query, no pointers.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        return Err(step_error(
            "Landlock (required by the fence)",
            None,
            io::Error::last_os_error(),
        ));
    }
    if abi < LANDLOCK_MIN_ABI {
        return Err(io::Error::other(format!(
            "Landlock ABI {abi} is too old; the fence needs ABI {LANDLOCK_MIN_ABI} (Linux 5.19)"
        )));
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_REFER,
    };
    // SAFETY: attr is valid for its size; the returned fd is owned by `Fd`.
    let ruleset = Fd(check(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    })
    .map_err(|e| step_error("landlock_create_ruleset", None, e))?
        as libc::c_int);
    let root = c"/";
    // SAFETY: O_PATH open of "/"; fd owned by `Fd`.
    let root_fd = Fd(check(
        unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as libc::c_long,
    )
    .map_err(|e| step_error("open /", None, e))? as libc::c_int);
    // Landlock denies cross-directory rename and link in any domain that does not
    // grant REFER, so grant it everywhere; only device-node creation is denied.
    let rule = LandlockPathBeneathAttr {
        allowed_access: LANDLOCK_ACCESS_FS_REFER,
        parent_fd: root_fd.0,
    };
    // SAFETY: rule is a valid path_beneath attr referencing an open fd.
    check(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.0,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule as *const LandlockPathBeneathAttr,
            0u32,
        )
    })
    .map_err(|e| step_error("landlock_add_rule", None, e))?;
    // CAP_SYS_ADMIN is still held, so no_new_privs is not needed.
    // SAFETY: restricts the calling thread (the only one) with the ruleset.
    check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.0, 0u32) })
        .map_err(|e| step_error("landlock_restrict_self", None, e))?;
    Ok(())
}

fn drop_capabilities(caps: &[u8]) -> io::Result<()> {
    for &cap in caps {
        // SAFETY: prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) } != 0 {
            let err = io::Error::last_os_error();
            // EINVAL: the running kernel does not know this capability; nothing to drop.
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(step_error(
                    &format!("drop capability {cap} from the bounding set"),
                    None,
                    err,
                ));
            }
        }
    }
    // SAFETY: prctl with integer arguments.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    } != 0
    {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(step_error("clear ambient capabilities", None, err));
        }
    }
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: header and data are valid for the v3 layout (two data words).
    check(unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    })
    .map_err(|e| step_error("capget", None, e))?;
    for &cap in caps {
        let (word, bit) = (usize::from(cap / 32), 1u32 << (cap % 32));
        data[word].effective &= !bit;
        data[word].permitted &= !bit;
        data[word].inheritable &= !bit;
    }
    // SAFETY: as above.
    check(unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_ptr(),
        )
    })
    .map_err(|e| step_error("capset", None, e))?;
    Ok(())
}

/// Apply the plan and exec the pane command. Returns only on failure.
pub(crate) fn fence_exec(
    plan: &FencePlan,
    notice: &str,
    program: &OsStr,
    argv0: &OsStr,
    args: &[OsString],
) -> io::Error {
    // The cwd was inherited before the mounts and still points at the original
    // (writable) mount; look the same path up again in the fenced view.
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(err) => return step_error("read the working directory", None, err),
    };
    if let Err(err) = apply_mounts(plan) {
        return err;
    }
    if let Err(err) = apply_landlock() {
        return err;
    }
    if let Err(err) = drop_capabilities(&plan.drop_caps) {
        return err;
    }
    if let Err(err) = std::env::set_current_dir(&cwd) {
        return step_error("re-enter the working directory", Some(&cwd), err);
    }

    eprint!("{notice}\r\n");
    let program_c = match CString::new(program.as_bytes()) {
        Ok(value) => value,
        Err(_) => return io::Error::other("program contains a NUL byte"),
    };
    let mut argv_c = Vec::with_capacity(args.len() + 1);
    for arg in std::iter::once(argv0).chain(args.iter().map(OsString::as_os_str)) {
        match CString::new(arg.as_bytes()) {
            Ok(value) => argv_c.push(value),
            Err(_) => return io::Error::other("argument contains a NUL byte"),
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    // SAFETY: NUL-terminated program and argv array; execvp only returns on failure.
    unsafe { libc::execvp(program_c.as_ptr(), argv_ptrs.as_ptr()) };
    step_error("exec", Some(Path::new(program)), io::Error::last_os_error())
}
