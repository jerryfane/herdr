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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, RwLock};

use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::{FenceConfig, FenceProfile, FenceScope};

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
    // gitmoot: config, credentials, runtimes and toolchains it executes, plugins
    // and scripts, review pins, and database backups. The rest of ~/.gitmoot stays
    // writable: every gitmoot CLI call chmods the directory and some subdirectories
    // and opens the database read-write (traced; see DEFAULT_PIN).
    "~/.gitmoot/config.toml*",
    "~/.gitmoot/*.env*",
    "~/.gitmoot/daemon.json",
    "~/.gitmoot/gitmoot.db.bak*",
    "~/.gitmoot/runtimes",
    "~/.gitmoot/toolchains",
    "~/.gitmoot/execbackends",
    "~/.gitmoot/plugins",
    "~/.gitmoot/scripts",
    "~/.gitmoot/skillopt",
    "~/.gitmoot/review-pins",
    // gitmoot's review checkouts and worktrees; its daemon writes them, not agents.
    "~/.gitmoot/checkouts",
    "~/.gitmoot/worktrees",
];

/// Writable inside fenced panes, but bound onto themselves so they cannot be
/// deleted or renamed, unless `[fence] pin` replaces the list.
pub(crate) const DEFAULT_PIN: &[&str] = &[
    // gitmoot's data directory: `rm -rf ~/.gitmoot` must not take the database.
    "~/.gitmoot",
    // The database file. Its -wal and -shm files are not pinned: SQLite deletes and
    // recreates them, and a pane holding an old inode would write where no one reads.
    "~/.gitmoot/gitmoot.db",
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

/// Which `[fence.agents]` entry a terminal's processes are fenced as. `agent.start`,
/// a session restore and an unarchive set it; renaming an agent does not change it,
/// so an agent cannot rename itself out of its fence before a respawn.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceIdentity {
    /// Not started as a named agent: a plain shell or a created pane.
    #[default]
    Anonymous,
    Agent(String),
}

impl FenceIdentity {
    pub(crate) fn from_agent_name(name: Option<String>) -> Self {
        name.map_or(Self::Anonymous, Self::Agent)
    }
}

/// Whether `config` fences a pane started as `identity` (platform support aside).
fn fences(config: &FenceConfig, identity: &FenceIdentity) -> bool {
    if !config.enabled {
        return false;
    }
    let entry = match identity {
        FenceIdentity::Agent(name) => config.agents.get(name),
        FenceIdentity::Anonymous => None,
    };
    match entry {
        Some(agent) => agent.profile == FenceProfile::Default,
        None => config.scope == FenceScope::All,
    }
}

/// Whether a pane started now as `identity` runs inside the fence. An error when
/// `[fence]` failed to load, which refuses every pane start.
fn pane_fenced_as(identity: &FenceIdentity) -> io::Result<bool> {
    let config = loaded_policy()?;
    Ok(crate::platform::FENCE_SUPPORTED && fences(&config, identity))
}

/// Whether the shell process `pid` must be replaced before an agent that is fenced
/// as `identity` is typed into it: it is outside the fence the agent needs, or
/// inside a fence the agent is exempt from. A shell that cannot be inspected is
/// replaced whenever the agent needs the fence.
pub(crate) fn shell_needs_respawn(pid: Option<u32>, identity: &FenceIdentity) -> io::Result<bool> {
    let fenced = pane_fenced_as(identity)?;
    #[cfg(unix)]
    {
        use crate::platform::FencePeer;
        Ok(match pid.map(crate::platform::fence_peer) {
            Some(FencePeer::Unfenced) => fenced,
            Some(FencePeer::Fenced { .. }) => !fenced,
            Some(FencePeer::Unknown) | None => fenced,
        })
    }
    // No fence exists here, so `fenced` is false.
    #[cfg(not(unix))]
    {
        let _ = pid;
        Ok(fenced)
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

/// Set once this server has started (or adopted, after a live handoff) a fenced
/// pane process. Together with `[fence] enabled` it decides whether the API checks
/// callers at all: with the fence off and no fenced pane alive, the API behaves
/// exactly as without the fence. It is never cleared, because a fenced pane keeps
/// its fence after the fence is switched off.
static FENCED_PANES_EXIST: AtomicBool = AtomicBool::new(false);

/// True when API callers must be classified: the fence is on (or failed to load,
/// which is treated as on), or a fenced pane may still be running.
pub(crate) fn api_gate_active() -> bool {
    if !crate::platform::FENCE_SUPPORTED {
        return false;
    }
    FENCED_PANES_EXIST.load(Ordering::Acquire)
        || current_policy().map_or(true, |config| config.enabled)
}

/// True when panes created now are fenced, so a fenced caller may create panes:
/// the new pane cannot be looser than the caller's. Created panes are anonymous.
pub(crate) fn new_panes_are_fenced() -> bool {
    crate::platform::FENCE_SUPPORTED
        && current_policy().is_ok_and(|config| fences(&config, &FenceIdentity::Anonymous))
}

/// Record a pane process this server adopted (live handoff) or started, so the API
/// gate stays on while a fenced one may be alive.
#[cfg(unix)]
pub(crate) fn note_pane_process(pid: u32) {
    if crate::platform::FENCE_SUPPORTED
        && !FENCED_PANES_EXIST.load(Ordering::Acquire)
        && crate::platform::fence_peer(pid) != crate::platform::FencePeer::Unfenced
    {
        FENCED_PANES_EXIST.store(true, Ordering::Release);
    }
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
        // Unparsable file: whether it asks for a fence cannot be known exactly, so
        // fail closed whenever it might. A file that cannot spell the key keeps
        // today's behavior.
        Err(err) => {
            if may_spell_fence_key(content) {
                StartupFence::Invalid(format!("config.toml does not parse: {err}"))
            } else {
                StartupFence::NotConfigured
            }
        }
    }
}

/// True unless `content` provably cannot contain a TOML key that decodes to `fence`.
///
/// TOML keys are bare (`fence`), literal (`'fence'`, no escapes) or basic strings
/// (`"fence"`), and the only escapes in a basic string that can produce a letter are
/// `\u` and `\U`. Keys are case-sensitive and cannot span lines. So a key spelled
/// `fence` needs either the literal text `fence` or a `\u`/`\U` escape somewhere in
/// the file. This over-matches (comments, values) on purpose: it is only consulted
/// for a file that does not parse, where refusing a spawn is the safe outcome.
fn may_spell_fence_key(content: &str) -> bool {
    content.contains("fence") || content.contains("\\u") || content.contains("\\U")
}

fn current_policy() -> Policy {
    CURRENT
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn loaded_policy() -> io::Result<Arc<FenceConfig>> {
    current_policy().map_err(|err| {
        io::Error::other(format!(
            "pane fence: {err}; not starting the pane. Fix [fence] in config.toml and run `herdr server reload-config`"
        ))
    })
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
    for entry in config.pin.as_deref().into_iter().flatten() {
        if let Err(err) = check_path_syntax(entry) {
            errors.push(format!("fence.pin entry {entry:?}: {err}"));
        }
    }
    for (name, agent) in &config.agents {
        if agent.reason.trim().is_empty() {
            errors.push(format!("fence.agents.{name}: reason must not be empty"));
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
        Some(home) => {
            match resolve_entries(
                &deny_entries,
                home,
                &mut Vec::new(),
                &mut Vec::new(),
                "deny",
            ) {
                Ok(paths) => paths,
                // Reported, not read as "no denies": the plan would fail the same way.
                Err(err) => {
                    errors.push(format!("fence.deny: {err}"));
                    Vec::new()
                }
            }
        }
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
        if lexically_below {
            continue;
        }
        let resolved = match &home {
            Some(home) => resolve_entries(
                std::slice::from_ref(entry),
                home,
                &mut Vec::new(),
                &mut Vec::new(),
                "allow",
            ),
            None => Ok(Vec::new()),
        };
        match resolved {
            Ok(allows)
                if allows
                    .iter()
                    .any(|allow| resolved_deny.iter().any(|deny| covers(deny, allow))) => {}
            Ok(_) => errors.push(format!(
                "fence.allow entry {entry:?} is not below any fence.deny entry"
            )),
            Err(err) => errors.push(format!("fence.allow entry {entry:?}: {err}")),
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
///
/// A path entry may reach its target through symlinks (`/bin` on merged-/usr hosts,
/// a symlinked config directory). Those symlink entries are anchored too: otherwise
/// the pane could unlink or replace the alias the host uses, even though the
/// target is read-only. A path that cannot be resolved for any reason other than
/// being absent fails the whole plan, so no protection is silently dropped.
pub(crate) fn resolve_plan(
    config: &FenceConfig,
    home: &Path,
    always_protected: &[PathBuf],
) -> io::Result<FencePlan> {
    let mut skipped = Vec::new();
    // Every path as written (after `~` and `*` expansion); its symlink components
    // are anchored below.
    let mut lexical_paths: Vec<PathBuf> = Vec::new();

    let deny_entries: Vec<String> = match &config.deny {
        Some(entries) => entries.clone(),
        None => DEFAULT_DENY.iter().map(|e| (*e).to_string()).collect(),
    };
    let deny = resolve_entries(
        &deny_entries,
        home,
        &mut skipped,
        &mut lexical_paths,
        "deny",
    )?;
    let mut protected: Vec<PathBuf> = Vec::new();
    for path in always_protected {
        match canonicalize_if_present(path)? {
            Some(real) => {
                lexical_paths.push(path.clone());
                protected.push(real);
            }
            None => skipped.push(format!("protect {}: not present", path.display())),
        }
    }
    protected.sort_by_key(|path| depth(path));
    let mut mandatory: Vec<PathBuf> = Vec::new();
    for path in protected {
        if !mandatory.iter().any(|m| covers(m, &path)) {
            mandatory.push(path);
        }
    }
    let allow: Vec<PathBuf> = resolve_entries(
        &config.allow,
        home,
        &mut skipped,
        &mut lexical_paths,
        "allow",
    )?
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
    let mask = resolve_entries(
        &mask_entries,
        home,
        &mut skipped,
        &mut lexical_paths,
        "mask",
    )?;
    let pin_entries: Vec<String> = match &config.pin {
        Some(entries) => entries.clone(),
        None => DEFAULT_PIN.iter().map(|e| (*e).to_string()).collect(),
    };
    let pins = resolve_entries(&pin_entries, home, &mut skipped, &mut lexical_paths, "pin")?;

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
    for pin in &pins {
        if !anchors.iter().any(|a| a == pin) {
            anchors.push(pin.clone());
        }
    }
    for path in deny
        .iter()
        .chain(&mandatory)
        .chain(&allow)
        .chain(&mask)
        .chain(&pins)
    {
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
    // Symlink components of the paths as written: binding a symlink onto itself
    // pins its directory entry (unlink, rename and replace fail with EBUSY) while
    // lookups still follow it. One inside a read-only tree cannot be changed anyway.
    for path in &lexical_paths {
        for prefix in path.ancestors() {
            if prefix == Path::new("/") || prefix.as_os_str().is_empty() {
                continue;
            }
            let is_symlink = match std::fs::symlink_metadata(prefix) {
                Ok(meta) => meta.file_type().is_symlink(),
                Err(err) if is_absent(&err) => false,
                Err(err) => return Err(path_error("inspect", prefix, err)),
            };
            if is_symlink && !read_only(prefix) && !anchors.iter().any(|a| a == prefix) {
                anchors.push(prefix.to_path_buf());
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

    Ok(FencePlan {
        mounts: mounts.into_iter().map(|(_, _, mount)| mount).collect(),
        skipped,
        drop_caps: DROPPED_CAPS.iter().map(|(cap, _, _)| *cap).collect(),
    })
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
    lexical_paths: &mut Vec<PathBuf>,
    kind: &str,
) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in entries {
        let expanded = lexical(entry, Some(home));
        let mut found = false;
        for candidate in expand_wildcards(&expanded)? {
            match canonicalize_if_present(&candidate)? {
                Some(real) if real != Path::new("/") => {
                    found = true;
                    lexical_paths.push(candidate);
                    out.push(real);
                }
                Some(_) => skipped.push(format!("{kind} {entry}: resolves to /")),
                None => {}
            }
        }
        if !found {
            skipped.push(format!("{kind} {entry}: not present"));
        }
    }
    Ok(out)
}

/// A path that does not exist (or has a non-directory in the middle) is absent
/// and skipped. Any other failure (permission, I/O, stale handle) means the
/// protection cannot be established, so the plan fails.
fn is_absent(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn path_error(action: &str, path: &Path, err: io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!(
            "pane fence: cannot {action} {}: {err}; not starting the pane",
            path.display()
        ),
    )
}

fn canonicalize_if_present(path: &Path) -> io::Result<Option<PathBuf>> {
    match path.canonicalize() {
        Ok(real) => Ok(Some(real)),
        Err(err) if is_absent(&err) => Ok(None),
        Err(err) => Err(path_error("resolve", path, err)),
    }
}

/// Expand `*` inside path components against the filesystem. Paths without `*`
/// are returned unchanged (existence is checked by the caller).
fn expand_wildcards(path: &Path) -> io::Result<Vec<PathBuf>> {
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
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(err) if is_absent(&err) => continue,
                Err(err) => return Err(path_error("list", dir, err)),
            };
            let mut names = Vec::new();
            for entry in entries {
                let name = entry
                    .map_err(|err| path_error("list", dir, err))?
                    .file_name();
                if name.to_str().is_some_and(|n| wildcard_match(pattern, n)) {
                    names.push(name);
                }
            }
            names.sort();
            next.extend(names.into_iter().map(|name| dir.join(name)));
        }
        current = next;
    }
    Ok(current)
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

/// Rewrite a pane command so it starts inside the fence. A no-op when `identity` is
/// not fenced (fence off, not in scope, or unsupported on this platform); an error
/// (the pane does not start) when the plan cannot be built, or when `[fence]` failed
/// to load.
pub(crate) fn fence_pane_command(
    cmd: &mut CommandBuilder,
    identity: &FenceIdentity,
) -> io::Result<()> {
    let config = loaded_policy()?;
    if !crate::platform::FENCE_SUPPORTED || !fences(&config, identity) {
        return Ok(());
    }
    let plan = pane_plan(&config)?;
    let plan_json = serde_json::to_string(&plan).map_err(io::Error::other)?;
    wrap_command(cmd, &plan_json)?;
    FENCED_PANES_EXIST.store(true, Ordering::Release);
    Ok(())
}

fn server_home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("pane fence: HOME is not set; not starting the pane"))
}

/// The plan a fenced pane started now gets.
fn pane_plan(config: &FenceConfig) -> io::Result<FencePlan> {
    let home = server_home()?;
    // Herdr's own settings, and the config file actually in use (HERDR_CONFIG_PATH
    // may point outside the config directory), are always read-only.
    let always_protected = [crate::config::config_dir(), crate::config::config_path()];
    let mut plan = resolve_plan(config, &home, &always_protected)?;
    // The private TUI client socket attaches to any pane and types into it; agents
    // never need it. It sits below the read-only config dir, so its mask is applied
    // after every other mount (docs/next/design/pane-fence.md, section 8).
    if let Some(client_socket) =
        canonicalize_if_present(&crate::server::socket_paths::client_socket_path())?
    {
        let mask = FenceMount::Mask(client_socket);
        if !plan.mounts.contains(&mask) {
            plan.mounts.push(mask);
        }
    }
    Ok(plan)
}

/// What `herdr fence explain` reports for one pane (docs/next/design/pane-fence.md,
/// section 9). `config_*` fields describe the current config, which a restart of
/// the pane would get; `running_fenced` and `PathExplanation::enforced_read_only`
/// describe the process that runs now, which may have started under an older config.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Explanation {
    pub agent: Option<String>,
    pub running_fenced: Option<bool>,
    pub config_fences: bool,
    pub deny_count: Option<usize>,
    pub missing: Vec<String>,
    pub path: Option<PathExplanation>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PathExplanation {
    pub path: String,
    pub resolved: PathBuf,
    pub access: Access,
    pub rule: String,
    pub pinned: bool,
    /// From the running pane's mount table; `None` when it cannot be read.
    pub enforced_read_only: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Writable,
    ReadOnly,
    Masked,
}

pub(crate) fn explain(
    identity: &FenceIdentity,
    pid: Option<u32>,
    path: Option<&str>,
) -> io::Result<Explanation> {
    let config = loaded_policy()?;
    let config_fences = crate::platform::FENCE_SUPPORTED && fences(&config, identity);
    let plan = if config_fences {
        Some(pane_plan(&config)?)
    } else {
        None
    };
    #[cfg(unix)]
    let running_fenced = pid.and_then(|pid| match crate::platform::fence_peer(pid) {
        crate::platform::FencePeer::Unfenced => Some(false),
        crate::platform::FencePeer::Fenced { .. } => Some(true),
        crate::platform::FencePeer::Unknown => None,
    });
    #[cfg(not(unix))]
    let running_fenced = pid.map(|_| false);
    let path = match path {
        Some(path) => {
            if !path.starts_with('/') && path != "~" && !path.starts_with("~/") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path must be absolute or start with ~/",
                ));
            }
            let resolved = resolve_for_explain(&lexical(path, Some(&server_home()?)))?;
            let verdict = match &plan {
                Some(plan) => path_verdict(plan, &resolved),
                None => PathVerdict {
                    access: Access::Writable,
                    rule: "not fenced: the current config does not fence this pane".into(),
                    pinned: false,
                },
            };
            Some(PathExplanation {
                path: path.to_string(),
                enforced_read_only: pid
                    .and_then(|pid| crate::platform::fenced_path_read_only(pid, &resolved)),
                resolved,
                access: verdict.access,
                rule: verdict.rule,
                pinned: verdict.pinned,
            })
        }
        None => None,
    };
    Ok(Explanation {
        agent: match identity {
            FenceIdentity::Agent(name) => Some(name.clone()),
            FenceIdentity::Anonymous => None,
        },
        running_fenced,
        config_fences,
        deny_count: plan.as_ref().map(FencePlan::deny_count),
        missing: plan.map(|plan| plan.skipped).unwrap_or_default(),
        path,
    })
}

/// Resolve `path` as the kernel would when the pane opens it: symlinks in its
/// deepest existing ancestor are followed, and the missing rest is appended, so
/// `/bin/newtool` on a merged-/usr host is judged as `/usr/bin/newtool`.
fn resolve_for_explain(path: &Path) -> io::Result<PathBuf> {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        match std::fs::canonicalize(existing) {
            Ok(resolved) => {
                return Ok(missing
                    .iter()
                    .rev()
                    .fold(resolved, |acc: PathBuf, part| acc.join(part)))
            }
            Err(err) if is_absent(&err) => {}
            Err(err) => {
                return Err(io::Error::new(
                    err.kind(),
                    format!(
                        "fence explain: cannot resolve {}: {err}",
                        existing.display()
                    ),
                ))
            }
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                missing.push(name.to_os_string());
                existing = parent;
            }
            _ => return Ok(path.to_path_buf()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PathVerdict {
    access: Access,
    rule: String,
    pinned: bool,
}

/// The access a plan gives `path` (already resolved): the deepest deny, allow or mask
/// at or above it decides, the later one on a tie, because mounts are applied
/// shallow first and a later mount covers an earlier one at the same place.
fn path_verdict(plan: &FencePlan, path: &Path) -> PathVerdict {
    let mut deciding: Option<&FenceMount> = None;
    for mount in &plan.mounts {
        let at = match mount {
            FenceMount::Deny(at) | FenceMount::Allow(at) | FenceMount::Mask(at) => at,
            FenceMount::Anchor(_) => continue,
        };
        if !covers(at, path) {
            continue;
        }
        let deeper_or_same = match deciding {
            Some(
                FenceMount::Deny(current) | FenceMount::Allow(current) | FenceMount::Mask(current),
            ) => depth(at) >= depth(current),
            _ => true,
        };
        if deeper_or_same {
            deciding = Some(mount);
        }
    }
    let (access, rule) = match deciding {
        Some(FenceMount::Deny(at)) => (Access::ReadOnly, format!("deny {}", at.display())),
        Some(FenceMount::Allow(at)) => (Access::Writable, format!("allow {}", at.display())),
        Some(FenceMount::Mask(at)) => (Access::Masked, format!("mask {}", at.display())),
        _ => (Access::Writable, "not denied".into()),
    };
    // A mount point cannot be removed or renamed from inside the pane.
    let pinned = plan.mounts.iter().any(|mount| match mount {
        FenceMount::Anchor(at)
        | FenceMount::Deny(at)
        | FenceMount::Allow(at)
        | FenceMount::Mask(at) => at == path,
    });
    PathVerdict {
        access,
        rule,
        pinned,
    }
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
    notice.push_str("); `herdr fence explain <pane> <path>` shows why a path is read-only");
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
            pin: Some(Vec::new()),
            ..FenceConfig::default()
        }
    }

    fn parse_fence(toml: &str) -> Result<FenceConfig, String> {
        let table: toml::Table = toml.parse().map_err(|err| format!("{err}"))?;
        table["fence"]
            .clone()
            .try_into::<FenceConfig>()
            .map_err(|err| err.to_string())
    }

    fn agent(name: &str) -> FenceIdentity {
        FenceIdentity::Agent(name.into())
    }

    /// `fence explain` must name the rule the kernel applies: the deepest mount at or
    /// above the path, the later one at the same place.
    #[test]
    fn path_verdict_names_the_deciding_rule() {
        use Access as FenceAccess;
        let p = PathBuf::from;
        let plan = FencePlan {
            mounts: vec![
                FenceMount::Anchor(p("/home/u/.gitmoot")),
                FenceMount::Deny(p("/home/u/.gitmoot/config.toml")),
                FenceMount::Deny(p("/srv")),
                FenceMount::Allow(p("/srv/app/data")),
                FenceMount::Deny(p("/srv/app/data/secrets")),
                FenceMount::Mask(p("/run/docker.sock")),
                FenceMount::Deny(p("/cfg")),
                FenceMount::Deny(p("/cfg/x")),
                FenceMount::Allow(p("/cfg/x")),
            ],
            ..FencePlan::default()
        };
        let v = |path: &str| path_verdict(&plan, Path::new(path));
        assert_eq!(
            (v("/srv/app/x").access, v("/srv/app/x").rule),
            (FenceAccess::ReadOnly, "deny /srv".into())
        );
        assert_eq!(v("/srv/app/data/db").access, FenceAccess::Writable);
        assert_eq!(v("/srv/app/data/db").rule, "allow /srv/app/data");
        assert_eq!(v("/srv/app/data/secrets/k").access, FenceAccess::ReadOnly);
        assert_eq!(v("/srvx").rule, "not denied", "component prefix only");
        assert_eq!(v("/run/docker.sock").access, FenceAccess::Masked);
        assert_eq!(
            v("/cfg/x/y").access,
            FenceAccess::Writable,
            "later mount wins a tie"
        );
        let pinned = v("/home/u/.gitmoot");
        assert_eq!(
            (pinned.access, pinned.pinned),
            (FenceAccess::Writable, true)
        );
        assert!(!v("/home/u/.gitmoot/gitmoot.db-wal").pinned);
        assert_eq!(
            v("/home/u/.gitmoot/config.toml").access,
            FenceAccess::ReadOnly
        );
    }

    /// A path that does not exist yet must still be judged through its parent's
    /// symlinks, as the kernel resolves it (merged-/usr `/bin/newtool`).
    #[cfg(unix)]
    #[test]
    fn explain_resolves_missing_paths_through_existing_symlinks() {
        let root = temp_root("explain-resolve");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();
        assert_eq!(
            resolve_for_explain(&root.join("bin/newtool/sub")).unwrap(),
            root.join("usr/bin/newtool/sub")
        );
        assert_eq!(
            resolve_for_explain(&root.join("bin")).unwrap(),
            root.join("usr/bin")
        );
        let plan = FencePlan {
            mounts: vec![FenceMount::Deny(root.join("usr"))],
            ..FencePlan::default()
        };
        let resolved = resolve_for_explain(&root.join("bin/newtool")).unwrap();
        assert_eq!(path_verdict(&plan, &resolved).access, Access::ReadOnly);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn agents_scope_fences_only_listed_agents() {
        let config = parse_fence(
            r#"[fence]
enabled = true
scope = "agents"
[fence.agents.real-estate]
reason = "pilot"
[fence.agents.jarvis]
profile = "unfenced"
reason = "coordinator"
"#,
        )
        .expect("valid");
        assert!(fences(&config, &agent("real-estate")));
        assert!(!fences(&config, &agent("jarvis")));
        assert!(!fences(&config, &agent("drivekey")));
        assert!(!fences(&config, &FenceIdentity::Anonymous));

        let off = FenceConfig {
            enabled: false,
            ..config
        };
        assert!(!fences(&off, &agent("real-estate")));
    }

    #[test]
    fn all_scope_fences_everyone_but_unfenced_agents() {
        let config = parse_fence(
            "[fence]\nenabled = true\n[fence.agents.fleetup]\nprofile = \"unfenced\"\nreason = \"installer\"\n",
        )
        .expect("valid");
        assert_eq!(config.scope, FenceScope::All);
        assert!(fences(&config, &FenceIdentity::Anonymous));
        assert!(fences(&config, &agent("real-estate")));
        assert!(!fences(&config, &agent("fleetup")));
    }

    #[test]
    fn agent_entries_need_a_reason_and_a_known_profile() {
        for (toml, needle) in [
            ("[fence.agents.a]\nprofile = \"default\"\n", "reason"),
            (
                "[fence.agents.a]\nreason = \"  \"\n",
                "reason must not be empty",
            ),
            (
                "[fence.agents.a]\nprofile = \"loose\"\nreason = \"x\"\n",
                "loose",
            ),
            (
                "[fence.agents.a]\nreason = \"x\"\nallow = [\"/x\"]\n",
                "allow",
            ),
            ("[fence]\nscope = \"some\"\n", "some"),
        ] {
            let toml = if toml.starts_with("[fence]") {
                toml.to_string()
            } else {
                format!("[fence]\n{toml}")
            };
            let err = parse_fence(&toml).expect_err(&toml);
            assert!(err.contains(needle), "{toml}: {err}");
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
        let plan = resolve_plan(&cfg, &root, &[root.join("herdr")]).expect("plan");

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
        let plan = resolve_plan(&cfg, &root, &[root.join("missing-herdr")]).expect("plan");
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

    #[cfg(unix)]
    #[test]
    fn config_validation_reports_unresolvable_paths() {
        // An allow below a deny that cannot be resolved (a symlink loop) must be
        // reported as a resolution failure, not as "not below any deny".
        let root = temp_root("validate-loop");
        std::os::unix::fs::symlink(root.join("loop"), root.join("loop")).unwrap();
        let deny = root.join("loop");
        let allow = root.join("loop/db");
        let errors = validate_config(&config(
            &[deny.to_str().unwrap()],
            &[allow.to_str().unwrap()],
            &[],
        ));
        // The allow is lexically below the deny, so it is valid; the deny's
        // resolution failure is reported on its own.
        assert!(
            errors.iter().any(|e| e.starts_with("fence.deny:")),
            "{errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("not below any")),
            "{errors:?}"
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
        let plan = resolve_plan(&cfg, &root, std::slice::from_ref(&herdr)).expect("plan");
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
        let plan = resolve_plan(&cfg, &root, std::slice::from_ref(&config_file)).expect("plan");
        let allow = position(&plan, &FenceMount::Allow(project));
        let file_deny = position(&plan, &FenceMount::Deny(config_file));
        assert!(allow < file_deny, "{:?}", plan.mounts);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_entries_are_pinned_not_only_their_targets() {
        // Merged-/usr: /bin is a symlink to usr/bin. Denying /bin must also pin the
        // symlink itself, or a fenced pane could unlink the alias the host uses.
        let root = temp_root("symlinks");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();
        // A symlinked herdr config dir: replacing the link would redirect the server.
        std::fs::create_dir_all(root.join("data/herdr")).unwrap();
        std::fs::create_dir_all(root.join("home/.config")).unwrap();
        std::os::unix::fs::symlink(root.join("data/herdr"), root.join("home/.config/herdr"))
            .unwrap();

        let cfg = config(&[root.join("bin").to_str().unwrap()], &[], &[]);
        let plan = resolve_plan(&cfg, &root, &[root.join("home/.config/herdr")]).expect("plan");
        position(&plan, &FenceMount::Deny(root.join("usr/bin")));
        position(&plan, &FenceMount::Anchor(root.join("bin")));
        position(&plan, &FenceMount::Deny(root.join("data/herdr")));
        position(&plan, &FenceMount::Anchor(root.join("home/.config/herdr")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn default_gitmoot_rules_keep_the_database_writable_and_undeletable() {
        let home = temp_root("gitmoot");
        let gm = home.join(".gitmoot");
        for dir in ["runtimes", "logs", "workspaces", "evals/blobs"] {
            std::fs::create_dir_all(gm.join(dir)).unwrap();
        }
        for file in [
            "gitmoot.db",
            "gitmoot.db-wal",
            "config.toml",
            "config.toml.bak-1",
            "runtime-auth.env",
        ] {
            std::fs::write(gm.join(file), "").unwrap();
        }
        // Only the deny and pin defaults are under test. The socket defaults live in
        // directories a non-root runner cannot read (/run/podman).
        let cfg = FenceConfig {
            enabled: true,
            mask_sockets: Some(Vec::new()),
            ..FenceConfig::default()
        };
        let plan = resolve_plan(&cfg, &home, &[]).expect("plan");
        // Pinned: writable, but the directory and the database cannot be removed.
        position(&plan, &FenceMount::Anchor(gm.clone()));
        position(&plan, &FenceMount::Anchor(gm.join("gitmoot.db")));
        // Read-only: config (with backups), credentials, code it executes.
        for denied in [
            "config.toml",
            "config.toml.bak-1",
            "runtime-auth.env",
            "runtimes",
        ] {
            position(&plan, &FenceMount::Deny(gm.join(denied)));
        }
        // The CLI writes these: they must not be read-only, and the -wal file must
        // not be pinned (SQLite replaces it).
        for writable in [
            "",
            "logs",
            "workspaces",
            "evals",
            "evals/blobs",
            "gitmoot.db",
            "gitmoot.db-wal",
        ] {
            let path = if writable.is_empty() {
                gm.clone()
            } else {
                gm.join(writable)
            };
            assert!(
                !plan.mounts.contains(&FenceMount::Deny(path.clone())),
                "{path:?} denied"
            );
        }
        assert!(!plan
            .mounts
            .contains(&FenceMount::Anchor(gm.join("gitmoot.db-wal"))));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn resolution_failures_other_than_absence_fail_the_plan() {
        // A symlink loop cannot be resolved (ELOOP). Unlike a missing path, the
        // protection cannot be established, so the pane must not start without it.
        let root = temp_root("loop");
        std::os::unix::fs::symlink(root.join("loop"), root.join("loop")).unwrap();
        let cfg = config(&[root.join("loop").to_str().unwrap()], &[], &[]);
        assert!(resolve_plan(&cfg, &root, &[]).is_err());
        // A missing path is still just skipped.
        let cfg = config(&[root.join("absent").to_str().unwrap()], &[], &[]);
        let plan = resolve_plan(&cfg, &root, &[]).expect("absent paths are skipped");
        assert!(
            plan.skipped.iter().any(|s| s.contains("absent")),
            "{:?}",
            plan.skipped
        );
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
        // Every TOML spelling of the fence key, in a file that does not parse,
        // including unicode escapes in basic-string keys.
        for fence in [
            "[ fence ]\nenabled = true",
            "[\"fence\"]\nenabled = true",
            "['fence']\nenabled = true",
            "fence.enabled = true",
            "\"fence\".enabled = true",
            "fence = { enabled = true }",
            "[\"f\\u0065nce\"]\nenabled = true",
            "\"\\u0066ence\".enabled = true",
            "\"fenc\\U00000065\" = { enabled = true }",
        ] {
            // Each spelling really is the fence key when the file parses.
            let parsed: toml::Table = format!("{fence}\n").parse().expect("valid on its own");
            assert!(
                parsed.contains_key("fence"),
                "{fence:?} should decode to `fence`"
            );
            let content = format!("{fence}\n[ui]\nsidebar_width = [\n");
            assert!(
                matches!(startup_fence_from_str(&content), StartupFence::Invalid(_)),
                "{fence:?} in an unparsable file must fail closed"
            );
        }
        // An unparsable file that cannot spell the fence key keeps today's behavior.
        for content in [
            "[ui]\nsidebar_width = [\n",
            "[fencing_off]\n[[x\n",
            "[ui]\nname = \"F\\tE\"\n[[broken\n",
        ] {
            assert!(
                matches!(startup_fence_from_str(content), StartupFence::NotConfigured),
                "{content:?}"
            );
        }
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
