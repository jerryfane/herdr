//! Pane fence: the plan every fenced pane process starts under.
//!
//! The server resolves a [`FencePlan`] from `[fence]` when it spawns a pane and
//! rewrites the pane command to run `herdr fence-exec`, which applies the plan in
//! a private mount namespace and then execs the original command. Design and
//! threat model: docs/next/design/pane-fence.md.
//!
//! This module holds the platform-neutral parts (defaults, validation, plan
//! resolution, the command rewrite). The kernel work lives in
//! `crate::platform::fence_exec`.

use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::FenceConfig;

/// Environment variable that carries the resolved plan from the server to `fence-exec`.
/// `fence-exec` removes it before running the pane command.
pub(crate) const PLAN_ENV_VAR: &str = "HERDR_FENCE_PLAN";
/// Set inside fenced panes so tools and users can tell they are fenced.
pub(crate) const FENCE_ENV_VAR: &str = "HERDR_FENCE";
/// Hidden subcommand that applies a plan and execs the pane command.
pub(crate) const FENCE_EXEC_SUBCOMMAND: &str = "fence-exec";
/// Exit status of `fence-exec` when the fence cannot be set up (the pane command never runs).
pub(crate) const FENCE_SETUP_FAILED_STATUS: i32 = 126;

/// Read-only inside fenced panes unless `[fence] deny` replaces the list.
/// Each entry says why. `~` is the server's HOME. Herdr's own config directory is
/// always added (see [`resolve_plan`]), even when it is not under `~/.config/herdr`.
pub(crate) const DEFAULT_DENY: &[&str] = &[
    // OS binaries and libraries. On merged-/usr hosts /bin, /sbin and /lib* resolve into /usr.
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    // Kernel, initramfs and bootloader.
    "/boot",
    // Third-party software installed system-wide.
    "/opt",
    // System configuration: cron, sudoers, sshd, systemd units, /etc/keyring tokens.
    "/etc",
    // Package manager databases.
    "/var/lib/dpkg",
    "/var/lib/apt",
    // systemd state (timers, credentials, linger).
    "/var/lib/systemd",
    // crontab and at jobs run outside the fence.
    "/var/spool/cron",
    // The audit trail of attempts on protected paths.
    "/var/log/audit",
    // Images, containers and volumes of every service on the host.
    "/var/lib/docker",
    "/var/lib/containerd",
    // Hourly snapshots of herdr and gitmoot data (fleetup fleet-state-snapshot).
    "/var/lib/fleet-snapshots",
    // sandboxd state.
    "/var/lib/sandboxd*",
    // Kernel and device settings, including cgroups, bpf and efivars.
    "/sys",
    // Binaries the server and system services execute (herdr, gitmoot).
    "~/.local/bin",
    // Herdr settings, sockets (still connectable) and update binaries.
    "~/.config/herdr",
    // systemd user units would start outside the fence on the next login or boot.
    "~/.config/systemd",
    // SSH keys and authorized_keys.
    "~/.ssh",
];

/// Sockets that run work outside the fence. Masked unless `[fence] mask_sockets`
/// replaces the list.
pub(crate) const DEFAULT_MASK_SOCKETS: &[&str] = &[
    // systemd system manager (systemctl talks to it directly as root).
    "/run/systemd/private",
    // D-Bus system bus: systemd-run, machinectl, loginctl, timedatectl.
    "/run/dbus/system_bus_socket",
    // Per-user D-Bus and systemd user managers.
    "/run/user/*/bus",
    "/run/user/*/systemd/private",
    // Container engines: `docker run -v /:/host` would undo every deny.
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
    // snapd installs and runs software as root.
    "/run/snapd.socket",
];

/// Capabilities removed from every set, including the bounding set, with the reason.
pub(crate) const DROPPED_CAPS: &[(u8, &str, &str)] = &[
    (21, "sys_admin", "mount, umount, setns, new namespaces, bpf"),
    (16, "sys_module", "load or unload kernel modules"),
    (22, "sys_boot", "reboot and kexec"),
    (17, "sys_rawio", "/dev/mem, /dev/port, iopl, raw SCSI"),
    (
        19,
        "sys_ptrace",
        "ptrace and /proc/<pid>/{root,mem} of other processes",
    ),
    (27, "mknod", "device nodes would bypass the nodev binds"),
    (
        2,
        "dac_read_search",
        "open_by_handle_at bypasses read-only binds",
    ),
    (39, "bpf", "BPF programs can write other processes' memory"),
    (38, "perfmon", "perf and BPF tracing"),
    (25, "sys_time", "setting the host clock"),
    (
        12,
        "net_admin",
        "firewall and interfaces of the shared host network",
    ),
    (30, "audit_control", "switching off auditd rules"),
    (29, "audit_write", "forging audit records"),
    (37, "audit_read", "reading the audit stream"),
    (33, "mac_admin", "changing AppArmor policy"),
    (32, "mac_override", "bypassing AppArmor policy"),
    (9, "linux_immutable", "chattr -i on protected files"),
    (34, "syslog", "kernel log control"),
    (35, "wake_alarm", "host power management"),
    (36, "block_suspend", "host power management"),
];

/// One mount of the plan, applied in order (shallow paths first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FenceMount {
    /// Bind the directory onto itself so it cannot be renamed or removed.
    Anchor(PathBuf),
    /// Read-only, recursively, and private so later host mounts below it stay hidden.
    Deny(PathBuf),
    /// Writable again inside a denied parent; the mount point itself cannot be removed.
    Allow(PathBuf),
    /// An empty read-only file over a socket.
    Mask(PathBuf),
}

/// Everything `fence-exec` needs; resolved by the server so the helper and later
/// `herdr fence explain` use the same rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FencePlan {
    pub mounts: Vec<FenceMount>,
    /// Configured entries that matched nothing on this host (skipped, never created).
    pub skipped: Vec<String>,
    /// Capability numbers removed from every set.
    pub drop_caps: Vec<u8>,
}

impl FencePlan {
    pub(crate) fn deny_count(&self) -> usize {
        self.mounts
            .iter()
            .filter(|mount| matches!(mount, FenceMount::Deny(_)))
            .count()
    }
}

/// The fence policy pane spawns use; replaced at startup and on config reload.
/// `Err` means config.toml asks for a fence that could not be loaded: every pane
/// spawn is refused until a valid `[fence]` is reloaded (fail closed).
type Policy = Result<Arc<FenceConfig>, Arc<str>>;

static CURRENT: LazyLock<RwLock<Policy>> =
    LazyLock::new(|| RwLock::new(Ok(Arc::new(FenceConfig::default()))));

fn install(policy: Policy) {
    let mut slot = CURRENT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = policy;
}

/// Install a validated `[fence]` (startup, reload) for pane spawns from now on.
pub(crate) fn set_config(config: &FenceConfig) {
    if config.enabled && !crate::platform::FENCE_SUPPORTED {
        warn!("[fence] enabled = true, but the pane fence is Linux-only; panes start unfenced");
    }
    install(Ok(Arc::new(config.clone())));
}

/// Install the startup policy. `Config::load` replaces the whole config with
/// defaults when any part of config.toml is invalid, which would silently turn a
/// requested fence off. So the `[fence]` table is read from the file on its own:
/// a valid table is used even when another section is broken, and a table (or a
/// file) that cannot be read refuses pane spawns instead of starting them unfenced.
pub(crate) fn set_startup_config(loaded: &FenceConfig) {
    match startup_fence_from_file(&crate::config::config_path()) {
        StartupFence::NotConfigured => set_config(loaded),
        StartupFence::Valid(config) => set_config(&config),
        StartupFence::Invalid(err) => {
            tracing::error!(%err, "[fence] could not be loaded; refusing to start panes until it is fixed");
            install(Err(err.into()));
        }
    }
}

enum StartupFence {
    NotConfigured,
    Valid(FenceConfig),
    Invalid(String),
}

fn startup_fence_from_file(path: &Path) -> StartupFence {
    let content = match crate::config::read_optional_config(path) {
        Ok(Some(content)) => content,
        Ok(None) => return StartupFence::NotConfigured,
        Err(err) => return StartupFence::Invalid(format!("cannot read {}: {err}", path.display())),
    };
    startup_fence_from_str(&content)
}

fn startup_fence_from_str(content: &str) -> StartupFence {
    match content.parse::<toml::Table>() {
        Ok(table) => match table.get("fence") {
            None => StartupFence::NotConfigured,
            Some(value) => match value.clone().try_into::<FenceConfig>() {
                Ok(config) => StartupFence::Valid(config),
                Err(err) => StartupFence::Invalid(format!("invalid [fence]: {err}")),
            },
        },
        // Unparsable file: whether it asks for a fence is unknown, so assume it does
        // when a [fence] header is present.
        Err(err) => {
            let mentions_fence = content
                .lines()
                .any(|line| line.trim_start().starts_with("[fence"));
            if mentions_fence {
                StartupFence::Invalid(format!("config.toml does not parse: {err}"))
            } else {
                StartupFence::NotConfigured
            }
        }
    }
}

fn current_policy() -> Policy {
    CURRENT
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Config-time checks. Every message names the offending entry.
pub(crate) fn validate_config(config: &FenceConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let deny = config.deny.as_deref();
    for entry in deny.into_iter().flatten() {
        if let Err(err) = check_path_syntax(entry) {
            errors.push(format!("fence.deny entry {entry:?}: {err}"));
        }
    }
    for entry in config.mask_sockets.as_deref().into_iter().flatten() {
        if let Err(err) = check_path_syntax(entry) {
            errors.push(format!("fence.mask_sockets entry {entry:?}: {err}"));
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let deny_entries: Vec<String> = match deny {
        Some(entries) => entries.to_vec(),
        None => DEFAULT_DENY.iter().map(|e| (*e).to_string()).collect(),
    };
    // Resolved the same way as at pane start, for allows written through a symlink
    // alias or below a wildcard that only exists on disk.
    let resolved_deny: Vec<PathBuf> = match &home {
        Some(home) => resolve_entries(&deny_entries, home, &mut Vec::new(), "deny"),
        None => Vec::new(),
    };
    for entry in &config.allow {
        if let Err(err) = check_path_syntax(entry) {
            errors.push(format!("fence.allow entry {entry:?}: {err}"));
            continue;
        }
        let path = lexical(entry, home.as_deref());
        let lexically_below = deny_entries
            .iter()
            .any(|deny| pattern_covers(&lexical(deny, home.as_deref()), &path));
        let resolved_below = || match &home {
            Some(home) => {
                resolve_entries(std::slice::from_ref(entry), home, &mut Vec::new(), "allow")
                    .iter()
                    .any(|allow| resolved_deny.iter().any(|deny| covers(deny, allow)))
            }
            None => false,
        };
        if !lexically_below && !resolved_below() {
            errors.push(format!(
                "fence.allow entry {entry:?} is not below any fence.deny entry"
            ));
        }
    }
    errors
}

/// True when `path` is at or below a path matching `pattern` (`*` within a component).
fn pattern_covers(pattern: &Path, path: &Path) -> bool {
    let mut path_parts = path.components();
    for pattern_part in pattern.components() {
        let Some(path_part) = path_parts.next() else {
            return false;
        };
        let matches = match (pattern_part, path_part) {
            (Component::Normal(p), Component::Normal(n)) => match (p.to_str(), n.to_str()) {
                (Some(p), Some(n)) if p.contains('*') => wildcard_match(p, n),
                _ => p == n,
            },
            (p, n) => p == n,
        };
        if !matches {
            return false;
        }
    }
    true
}

fn check_path_syntax(entry: &str) -> Result<(), &'static str> {
    let rest = if entry == "~" {
        ""
    } else if let Some(rest) = entry.strip_prefix("~/") {
        rest
    } else if let Some(rest) = entry.strip_prefix('/') {
        rest
    } else {
        return Err("must be absolute or start with ~/");
    };
    if entry == "/" || rest.trim_matches('/').is_empty() && entry.starts_with('/') {
        return Err("the root directory cannot be fenced");
    }
    if Path::new(rest)
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("must not contain . or .. components");
    }
    Ok(())
}

/// `~` expansion without touching the filesystem (validation only).
fn lexical(entry: &str, home: Option<&Path>) -> PathBuf {
    match (entry.strip_prefix('~'), home) {
        (Some(rest), Some(home)) => home.join(rest.trim_start_matches('/')),
        _ => PathBuf::from(entry),
    }
}

/// True when `path` is `parent` or below it.
fn covers(parent: &Path, path: &Path) -> bool {
    path.starts_with(parent)
}

/// Resolve `[fence]` into the mounts for one pane start on this host.
///
/// Paths are expanded (`~`, `*`) and resolved with `realpath`; entries that match
/// nothing are reported in `skipped`, never created. `always_protected` (herdr's
/// config directory and the config file actually loaded) is read-only whatever
/// the deny and allow lists say: its binds go after every carve-out, and carve-outs
/// inside it are dropped.
pub(crate) fn resolve_plan(
    config: &FenceConfig,
    home: &Path,
    always_protected: &[PathBuf],
) -> FencePlan {
    let mut skipped = Vec::new();

    let deny_entries: Vec<String> = match &config.deny {
        Some(entries) => entries.clone(),
        None => DEFAULT_DENY.iter().map(|e| (*e).to_string()).collect(),
    };
    let deny = resolve_entries(&deny_entries, home, &mut skipped, "deny");
    let mut protected: Vec<PathBuf> = Vec::new();
    for path in always_protected {
        if let Ok(real) = path.canonicalize() {
            protected.push(real);
        }
    }
    protected.sort_by_key(|path| depth(path));
    let mut mandatory: Vec<PathBuf> = Vec::new();
    for path in protected {
        if !mandatory.iter().any(|m| covers(m, &path)) {
            mandatory.push(path);
        }
    }
    let allow: Vec<PathBuf> = resolve_entries(&config.allow, home, &mut skipped, "allow")
        .into_iter()
        .filter(|path| {
            if mandatory.iter().any(|m| covers(m, path)) {
                skipped.push(format!(
                    "allow {}: inside herdr's own config, which stays read-only",
                    path.display()
                ));
                return false;
            }
            let below = deny.iter().any(|d| covers(d, path));
            if !below {
                skipped.push(format!("allow {}: not below a denied path", path.display()));
            }
            below
        })
        .collect();
    let mask_entries: Vec<String> = match &config.mask_sockets {
        Some(entries) => entries.clone(),
        None => DEFAULT_MASK_SOCKETS
            .iter()
            .map(|e| (*e).to_string())
            .collect(),
    };
    let mask = resolve_entries(&mask_entries, home, &mut skipped, "mask");

    // Anchors: every ancestor of a fenced path that stays writable in the pane
    // (outside every deny, or inside a carve-out), so renaming the ancestor cannot
    // move a protected tree away. Read-only ancestors cannot be renamed anyway.
    let read_only = |path: &Path| -> bool {
        // The deepest rule covering the path decides; at equal depth a mandatory
        // deny beats an allow, and an allow beats a deny (the mount order above).
        let mut best: Option<(usize, u8)> = None;
        let rules = deny
            .iter()
            .map(|p| (p, 1u8))
            .chain(allow.iter().map(|p| (p, 2u8)))
            .chain(mandatory.iter().map(|p| (p, 4u8)));
        for (rule, order) in rules {
            if covers(rule, path) {
                let key = (depth(rule), order);
                if best.is_none_or(|b| key > b) {
                    best = Some(key);
                }
            }
        }
        best.is_some_and(|(_, order)| order != 2)
    };
    let mut anchors: Vec<PathBuf> = Vec::new();
    for path in deny.iter().chain(&mandatory).chain(&allow).chain(&mask) {
        for ancestor in path.ancestors().skip(1) {
            if ancestor == Path::new("/") || ancestor.as_os_str().is_empty() {
                continue;
            }
            if read_only(ancestor) || allow.iter().any(|a| a == ancestor) {
                continue;
            }
            if !anchors.iter().any(|a| a == ancestor) {
                anchors.push(ancestor.to_path_buf());
            }
        }
    }

    // Shallow paths first; at equal depth anchors, then denies, then allows, so an
    // allow re-opens a deny of the same path and a deeper deny closes an allow.
    // Masks follow, and the mandatory read-only binds come last at their depth; a
    // shallower allow is applied before them, so it cannot reopen herdr's config.
    let mut mounts: Vec<(usize, u8, FenceMount)> = Vec::new();
    for path in anchors {
        mounts.push((depth(&path), 0, FenceMount::Anchor(path)));
    }
    for path in dedup(deny) {
        mounts.push((depth(&path), 1, FenceMount::Deny(path)));
    }
    for path in dedup(allow) {
        mounts.push((depth(&path), 2, FenceMount::Allow(path)));
    }
    for path in dedup(mask) {
        mounts.push((depth(&path), 3, FenceMount::Mask(path)));
    }
    for path in mandatory {
        mounts.push((depth(&path), 4, FenceMount::Deny(path)));
    }
    mounts.sort_by_key(|(depth, order, _)| (*depth, *order));

    FencePlan {
        mounts: mounts.into_iter().map(|(_, _, mount)| mount).collect(),
        skipped,
        drop_caps: DROPPED_CAPS.iter().map(|(cap, _, _)| *cap).collect(),
    }
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

fn dedup(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort();
    paths.dedup();
    paths
}

fn resolve_entries(
    entries: &[String],
    home: &Path,
    skipped: &mut Vec<String>,
    kind: &str,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in entries {
        let expanded = lexical(entry, Some(home));
        let matches = expand_wildcards(&expanded);
        let mut found = false;
        for candidate in matches {
            match candidate.canonicalize() {
                Ok(real) if real != Path::new("/") => {
                    found = true;
                    out.push(real);
                }
                Ok(_) => skipped.push(format!("{kind} {entry}: resolves to /")),
                Err(_) => {}
            }
        }
        if !found {
            skipped.push(format!("{kind} {entry}: not present"));
        }
    }
    out
}

/// Expand `*` inside path components against the filesystem. Paths without `*`
/// are returned unchanged (existence is checked by the caller).
fn expand_wildcards(path: &Path) -> Vec<PathBuf> {
    let mut current = vec![PathBuf::from("/")];
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let Some(pattern) = name.to_str().filter(|n| n.contains('*')) else {
            for path in &mut current {
                path.push(name);
            }
            continue;
        };
        let mut next = Vec::new();
        for dir in &current {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut names: Vec<OsString> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .filter(|name| name.to_str().is_some_and(|n| wildcard_match(pattern, n)))
                .collect();
            names.sort();
            next.extend(names.into_iter().map(|name| dir.join(name)));
        }
        current = next;
    }
    current
}

/// `*` matches any run of characters (including none); everything else is literal.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || name.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &name[first.len()..];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// Rewrite a pane command so it starts inside the fence. A no-op when the fence is
/// off or unsupported on this platform; an error (the pane does not start) when the
/// fence is on but the plan cannot be built, or when `[fence]` failed to load.
pub(crate) fn fence_pane_command(cmd: &mut CommandBuilder) -> io::Result<()> {
    let config = current_policy().map_err(|err| {
        io::Error::other(format!(
            "pane fence: {err}; not starting the pane. Fix [fence] in config.toml and run `herdr server reload-config`"
        ))
    })?;
    if !config.enabled || !crate::platform::FENCE_SUPPORTED {
        return Ok(());
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("pane fence: HOME is not set; not starting the pane"))?;
    // Herdr's own settings, and the config file actually in use (HERDR_CONFIG_PATH
    // may point outside the config directory), are always read-only.
    let always_protected = [crate::config::config_dir(), crate::config::config_path()];
    let plan = resolve_plan(&config, &home, &always_protected);
    let plan_json = serde_json::to_string(&plan).map_err(io::Error::other)?;
    wrap_command(cmd, &plan_json)
}

fn wrap_command(cmd: &mut CommandBuilder, plan_json: &str) -> io::Result<()> {
    let (program, argv0, rest): (OsString, OsString, Vec<OsString>) = if cmd.is_default_prog() {
        // A login shell: herdr sets SHELL on these builders, and portable-pty would run it
        // with argv0 "-<basename>".
        let shell = cmd
            .get_env("SHELL")
            .filter(|shell| !shell.is_empty())
            .ok_or_else(|| {
                io::Error::other("pane fence: login shell has no SHELL; not starting the pane")
            })?
            .to_os_string();
        let base = Path::new(&shell)
            .file_name()
            .map_or_else(|| shell.clone(), OsStr::to_os_string);
        let mut argv0 = OsString::from("-");
        argv0.push(base);
        (shell, argv0, Vec::new())
    } else {
        let argv = cmd.get_argv();
        (argv[0].clone(), argv[0].clone(), argv[1..].to_vec())
    };
    let mut wrapped: Vec<OsString> = vec![
        crate::platform::FENCE_HELPER_PROGRAM.into(),
        FENCE_EXEC_SUBCOMMAND.into(),
        "--argv0".into(),
        argv0,
        "--".into(),
        program,
    ];
    wrapped.extend(rest);
    *cmd.get_argv_mut() = wrapped;
    cmd.env(PLAN_ENV_VAR, plan_json);
    Ok(())
}

struct ExecRequest {
    argv0: OsString,
    program: OsString,
    args: Vec<OsString>,
}

fn parse_exec_args(args: &[OsString]) -> Result<ExecRequest, String> {
    let usage = "usage: herdr fence-exec --argv0 ARGV0 -- PROGRAM [ARGS...]";
    match args {
        [flag, argv0, separator, program, rest @ ..]
            if flag == OsStr::new("--argv0") && separator == OsStr::new("--") =>
        {
            Ok(ExecRequest {
                argv0: argv0.clone(),
                program: program.clone(),
                args: rest.to_vec(),
            })
        }
        _ => Err(usage.to_string()),
    }
}

/// Entry point of `herdr fence-exec` (args after the subcommand). Applies the plan
/// from [`PLAN_ENV_VAR`] and execs the pane command; never returns. Any failure
/// is shown in the pane and the command never starts.
pub(crate) fn run_fence_exec(args: &[OsString]) -> ! {
    let request = match parse_exec_args(args) {
        Ok(request) => request,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    let plan = std::env::var(PLAN_ENV_VAR)
        .map_err(|_| format!("{PLAN_ENV_VAR} is not set"))
        .and_then(|json| serde_json::from_str::<FencePlan>(&json).map_err(|err| err.to_string()));
    std::env::remove_var(PLAN_ENV_VAR);
    let err = match plan {
        Ok(plan) => {
            std::env::set_var(FENCE_ENV_VAR, "1");
            let notice = setup_notice(&plan);
            crate::platform::fence_exec(
                &plan,
                &notice,
                &request.program,
                &request.argv0,
                &request.args,
            )
        }
        Err(err) => io::Error::other(format!("reading the fence plan: {err}")),
    };
    fail_closed(&err)
}

fn setup_notice(plan: &FencePlan) -> String {
    let mut notice = format!("herdr: pane fenced ({} read-only paths", plan.deny_count());
    if !plan.skipped.is_empty() {
        notice.push_str(&format!(", {} entries not present", plan.skipped.len()));
    }
    notice.push(')');
    notice
}

fn fail_closed(err: &io::Error) -> ! {
    let mut stderr = io::stderr();
    let _ = writeln!(
        stderr,
        "\r\nherdr fence: {err}\r\nNot starting the pane command (fence enabled, failing closed).\r\nPress Enter to close this pane."
    );
    let _ = stderr.flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    std::process::exit(FENCE_SETUP_FAILED_STATUS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "herdr-fence-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create temp root");
        dir.canonicalize().expect("canonical temp root")
    }

    fn config(deny: &[&str], allow: &[&str], mask: &[&str]) -> FenceConfig {
        FenceConfig {
            enabled: true,
            deny: Some(deny.iter().map(|s| (*s).to_string()).collect()),
            allow: allow.iter().map(|s| (*s).to_string()).collect(),
            mask_sockets: Some(mask.iter().map(|s| (*s).to_string()).collect()),
        }
    }

    fn position(plan: &FencePlan, wanted: &FenceMount) -> usize {
        plan.mounts
            .iter()
            .position(|m| m == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} missing from {:?}", plan.mounts))
    }

    #[test]
    fn plan_orders_anchor_deny_allow_and_reports_missing_entries() {
        let root = temp_root("order");
        std::fs::create_dir_all(root.join("data/db")).unwrap();
        std::fs::create_dir_all(root.join("data/db/locked")).unwrap();
        std::fs::create_dir_all(root.join("herdr")).unwrap();
        let data = root.join("data");
        let cfg = config(
            &[
                data.to_str().unwrap(),
                root.join("data/db/locked").to_str().unwrap(),
                root.join("absent").to_str().unwrap(),
            ],
            &[root.join("data/db").to_str().unwrap()],
            &[],
        );
        let plan = resolve_plan(&cfg, &root, &[root.join("herdr")]);

        let anchor = position(&plan, &FenceMount::Anchor(root.clone()));
        let deny = position(&plan, &FenceMount::Deny(data.clone()));
        let allow = position(&plan, &FenceMount::Allow(root.join("data/db")));
        let inner = position(&plan, &FenceMount::Deny(root.join("data/db/locked")));
        assert!(
            anchor < deny && deny < allow && allow < inner,
            "{:?}",
            plan.mounts
        );
        // Herdr's own config dir is always denied.
        position(&plan, &FenceMount::Deny(root.join("herdr")));
        assert!(
            plan.skipped.iter().any(|s| s.contains("absent")),
            "{:?}",
            plan.skipped
        );
        assert!(
            !plan.mounts.contains(&FenceMount::Anchor(data.clone())),
            "a denied path must not be anchored writable"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wildcards_and_home_expand_to_existing_paths_only() {
        let root = temp_root("glob");
        for dir in ["state-a", "state-b", "other"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let cfg = config(&["~/state*"], &[], &[]);
        let plan = resolve_plan(&cfg, &root, &[root.join("missing-herdr")]);
        let denied: Vec<&FenceMount> = plan
            .mounts
            .iter()
            .filter(|m| matches!(m, FenceMount::Deny(_)))
            .collect();
        assert_eq!(
            denied,
            vec![
                &FenceMount::Deny(root.join("state-a")),
                &FenceMount::Deny(root.join("state-b")),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn allow_outside_every_deny_is_a_config_error() {
        let cfg = config(&["/srv/data"], &["/srv/other"], &[]);
        let errors = validate_config(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("/srv/other")),
            "{errors:?}"
        );
        assert!(validate_config(&config(&["/srv/data"], &["/srv/data/db"], &[])).is_empty());
        // A carve-out below a wildcard deny is valid even before the path exists.
        assert!(validate_config(&config(&["/srv/state*"], &["/srv/state-a/db"], &[])).is_empty());
        assert!(!validate_config(&config(&["/srv/state*"], &["/srv/other/db"], &[])).is_empty());
    }

    #[test]
    fn carve_out_cannot_reopen_herdr_config() {
        let root = temp_root("mandatory");
        let herdr = root.join("parent/herdr-dev");
        std::fs::create_dir_all(herdr.join("sub")).unwrap();
        let parent = root.join("parent");
        let cfg = config(
            &[parent.to_str().unwrap()],
            &[herdr.to_str().unwrap(), herdr.join("sub").to_str().unwrap()],
            &[],
        );
        let plan = resolve_plan(&cfg, &root, &[herdr.clone()]);
        assert!(
            !plan
                .mounts
                .iter()
                .any(|m| matches!(m, FenceMount::Allow(_))),
            "no carve-out inside herdr's config may survive: {:?}",
            plan.mounts
        );
        let parent_deny = position(&plan, &FenceMount::Deny(parent));
        let herdr_deny = position(&plan, &FenceMount::Deny(herdr));
        assert!(parent_deny < herdr_deny, "{:?}", plan.mounts);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mandatory_deny_is_applied_after_a_shallower_carve_out() {
        let root = temp_root("mandatory-order");
        let config_file = root.join("srv/project/herdr.toml");
        std::fs::create_dir_all(config_file.parent().unwrap()).unwrap();
        std::fs::write(&config_file, "").unwrap();
        let srv = root.join("srv");
        let project = root.join("srv/project");
        let cfg = config(&[srv.to_str().unwrap()], &[project.to_str().unwrap()], &[]);
        let plan = resolve_plan(&cfg, &root, &[config_file.clone()]);
        let allow = position(&plan, &FenceMount::Allow(project));
        let file_deny = position(&plan, &FenceMount::Deny(config_file));
        assert!(allow < file_deny, "{:?}", plan.mounts);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn startup_fence_fails_closed_on_invalid_or_unreadable_config() {
        assert!(matches!(
            startup_fence_from_str("[ui]\nx = 1\n"),
            StartupFence::NotConfigured
        ));
        assert!(matches!(
            startup_fence_from_str("[fence]\nenabled = true\n"),
            StartupFence::Valid(FenceConfig { enabled: true, .. })
        ));
        // A broken other section must not turn a valid fence off.
        assert!(matches!(
            startup_fence_from_str("[fence]\nenabled = true\n[ui]\nsidebar_width = \"x\"\n"),
            StartupFence::Valid(FenceConfig { enabled: true, .. })
        ));
        assert!(matches!(
            startup_fence_from_str("[fence]\nenabled = true\ndeny = [\"relative\"]\n"),
            StartupFence::Invalid(_)
        ));
        assert!(matches!(
            startup_fence_from_str("[fence]\nenabled = true\n[[broken\n"),
            StartupFence::Invalid(_)
        ));
    }

    #[test]
    fn relative_root_and_dotdot_paths_are_config_errors() {
        for bad in ["relative/path", "/", "/srv/../etc", "~user/x"] {
            let errors = validate_config(&config(&[bad], &[], &[]));
            assert!(!errors.is_empty(), "{bad} should be rejected");
        }
    }

    #[test]
    fn invalid_fence_section_is_rejected_whole() {
        let parsed: Result<FenceConfig, _> =
            toml::from_str("enabled = true\ndeny = [\"relative\"]\n");
        assert!(parsed.is_err());
        let typo: Result<FenceConfig, _> = toml::from_str("enable = true\n");
        assert!(typo.is_err(), "unknown keys must not be silently ignored");
    }

    #[test]
    fn wrap_preserves_login_shell_and_argv() {
        let mut login = CommandBuilder::new_default_prog();
        login.env("SHELL", "/bin/sh");
        wrap_command(&mut login, "{}").expect("wrap login shell");
        let argv: Vec<String> = login
            .get_argv()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            [
                crate::platform::FENCE_HELPER_PROGRAM,
                "fence-exec",
                "--argv0",
                "-sh",
                "--",
                "/bin/sh"
            ]
        );
        assert_eq!(login.get_env(PLAN_ENV_VAR), Some(OsStr::new("{}")));

        let mut command = CommandBuilder::new("sh");
        command.args(["-c", "echo hi"]);
        wrap_command(&mut command, "{}").expect("wrap command");
        let args = parse_exec_args(&command.get_argv()[2..]).expect("parse wrapped args");
        assert_eq!(args.argv0, "sh");
        assert_eq!(args.program, "sh");
        assert_eq!(
            args.args,
            vec![OsString::from("-c"), OsString::from("echo hi")]
        );
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("sandboxd*", "sandboxd-fc"));
        assert!(wildcard_match("sandboxd*", "sandboxd"));
        assert!(wildcard_match("*", "1000"));
        assert!(wildcard_match("a*c*e", "abcde"));
        assert!(!wildcard_match("sandboxd*", "xsandboxd"));
        assert!(!wildcard_match("a*c", "ab"));
    }
}
