//! Whether this process is the one a service supervisor is watching, and whether that
//! supervisor can follow a live handoff.
//!
//! This exists because of a real incident. `server.apply_staged_update` performs a live
//! handoff: it spawns a replacement, hands over the sockets and PTYs, then the OLD main
//! process exits. That is seamless when herdr owns its own lifetime — and destructive
//! under systemd when systemd is not told about the replacement.
//!
//! A `Type=simple` unit's main process exiting DEACTIVATES the unit, and the default
//! `KillMode=control-group` then kills everything left in the cgroup — including the
//! replacement and every pane it just imported. On this fleet that killed 30 live panes
//! while the API had already answered `ok`, and the panes came back from the session
//! snapshot under the WRONG ACCOUNT, so ~2 hours of work appeared to vanish (it was
//! intact, in the other account's transcript).
//!
//! The handoff cannot detect that from its own success: spawn, import and validation all
//! succeed, and the process is killed a moment later by the supervisor. So the check has
//! to happen BEFORE anything is torn down.
//!
//! A `Type=notify` unit can follow the handoff instead. Once the replacement is ready,
//! and while the handoff can still be undone, the OLD process — still the unit's main
//! process, so any `NotifyAccess=` other than `none` accepts it — sends
//! `MAINPID=<replacement>`, waits on `BARRIER=1`, and reads the unit's `MainPID` back.
//! When the manager names the replacement, the handoff commits and the old process
//! exits, and its exit is no longer the unit's: the replacement is the main process,
//! the cgroup survives, and `KillMode=` still stops every pane on a real stop. The
//! replacement is stopped only when the manager names another process; when the
//! manager can't say, the handoff commits (see [`hand_over_main_pid`]).
//! The process that decided the switch was safe is the one that makes it safe, so it
//! never depends on what the new build does. How to reach the manager is the
//! platform's (`crate::platform::systemd_notify` and friends); this module decides.

/// How this process is being supervised, as far as it can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Supervision {
    /// Nothing is watching this process' lifetime; it may hand off and exit freely.
    None,
    /// systemd is watching THIS process as the unit's main process and can't be told
    /// about a replacement. Exiting deactivates the unit and takes the cgroup —
    /// replacement and panes included — down with it.
    SystemdMainProcess,
    /// systemd is watching THIS process as the main process of a `Type=notify` unit that
    /// accepts `MAINPID=` from it: a handoff that moves the main pid first is safe.
    SystemdFollowsMainPid,
}

impl Supervision {
    /// Whether exiting after a handoff would take the replacement down too.
    pub(crate) fn forbids_process_handoff(self) -> bool {
        matches!(self, Self::SystemdMainProcess)
    }

    /// Whether the handoff must move the unit's main pid to the replacement before this
    /// process exits.
    pub(crate) fn hands_over_main_pid(self) -> bool {
        matches!(self, Self::SystemdFollowsMainPid)
    }
}

/// Why a handoff was refused, for every caller that asks for one.
pub(crate) const HANDOFF_REFUSAL: &str = "refusing a live handoff: this process is the main \
     process of a systemd unit that can't follow a replacement (that needs Type=notify and \
     NotifyAccess=main or all), so exiting after the handoff would deactivate the unit and kill \
     the replacement and every pane with it";

/// What the manager reports about the unit this process runs in
/// (`systemctl show -p InvocationID -p MainPID -p Type -p NotifyAccess`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnitProperties {
    pub(crate) invocation_id: String,
    pub(crate) main_pid: Option<u32>,
    pub(crate) service_type: String,
    pub(crate) notify_access: String,
}

/// What the supervisor injected into this process' environment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemdEnv<'a> {
    /// `INVOCATION_ID`: set by systemd for every unit it starts.
    pub(crate) invocation_id: Option<&'a str>,
    /// `SYSTEMD_EXEC_PID`: the process systemd started as the unit's main one, or the
    /// replacement that took the main pid over in a handoff (see
    /// [`take_systemd_environment`]).
    pub(crate) exec_pid: Option<&'a str>,
    pub(crate) our_pid: u32,
    /// `NOTIFY_SOCKET` was set, so the unit accepts notifications at all.
    pub(crate) notify_socket: bool,
}

pub(crate) const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";
const EXEC_PID_ENV: &str = "SYSTEMD_EXEC_PID";
/// Set only on a handoff replacement that is to become the unit's main process.
const TAKES_MAIN_PID_ENV: &str = "HERDR_SYSTEMD_TAKES_MAIN_PID";

static NOTIFY_SOCKET: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
    std::env::var(NOTIFY_SOCKET_ENV)
        .ok()
        .filter(|socket| !socket.is_empty())
});

/// Run first thing in a server process, before any thread starts.
///
/// Reads `NOTIFY_SOCKET` once and takes it out of the environment, as `sd_notify` does
/// with `unset_environment`: panes, plugins and the update guard must not inherit the
/// unit's notification socket.
///
/// A handoff replacement that is to become the unit's main process inherited its
/// predecessor's `SYSTEMD_EXEC_PID`, which would read as "a child inside the unit". It
/// names itself instead, exactly as systemd names a process it starts, so it and the
/// panes it spawns see the same main pid systemd will.
pub(crate) fn take_systemd_environment() {
    if notify_socket().is_some() {
        std::env::remove_var(NOTIFY_SOCKET_ENV);
    }
    if std::env::var_os(TAKES_MAIN_PID_ENV).is_some() {
        std::env::remove_var(TAKES_MAIN_PID_ENV);
        std::env::set_var(EXEC_PID_ENV, std::process::id().to_string());
    }
}

/// The unit's notification socket, if the supervisor gave this process one.
pub(crate) fn notify_socket() -> Option<&'static str> {
    NOTIFY_SOCKET.as_deref()
}

/// Give a handoff replacement what it needs to become the unit's main process: the
/// notification socket this process took out of its own environment, and the marker
/// [`take_systemd_environment`] reads. `SYSTEMD_EXEC_PID` names this process, so it is
/// dropped: a build that doesn't know the marker then has no main pid to compare with
/// and fails closed, instead of reading itself as a child whose exit is harmless.
pub(crate) fn prepare_main_pid_successor(command: &mut std::process::Command) {
    if let Some(socket) = notify_socket() {
        command.env(NOTIFY_SOCKET_ENV, socket);
    }
    command.env_remove(EXEC_PID_ENV);
    command.env(TAKES_MAIN_PID_ENV, "1");
}

fn current_env<'a>(
    invocation_id: &'a Option<String>,
    exec_pid: &'a Option<String>,
) -> SystemdEnv<'a> {
    SystemdEnv {
        invocation_id: invocation_id.as_deref(),
        exec_pid: exec_pid.as_deref(),
        our_pid: std::process::id(),
        notify_socket: notify_socket().is_some(),
    }
}

/// Detect supervision from the environment the supervisor injected and, when this is a
/// unit's main process, from the manager itself.
///
/// `SYSTEMD_EXEC_PID` is what makes the first step precise rather than merely cautious.
/// A herdr spawned as a CHILD inside a systemd unit inherits `INVOCATION_ID` but is not
/// the main process, so its exit is harmless — treating it as supervised would block
/// handoffs that are perfectly safe. When systemd is too old to set the pid, fall back to
/// assuming we ARE the main process: refusing a safe handoff costs an operator one manual
/// restart, while allowing an unsafe one costs every live pane.
pub(crate) fn detect() -> Supervision {
    let invocation_id = std::env::var("INVOCATION_ID").ok();
    let exec_pid = std::env::var(EXEC_PID_ENV).ok();
    detect_from(&current_env(&invocation_id, &exec_pid), || {
        query_unit(std::time::Instant::now() + MANAGER_TIMEOUT)
    })
}

/// The decision, split out from the environment and the manager so it can be tested
/// without either. `query` is asked only when this is the unit's main process.
pub(crate) fn detect_from(
    env: &SystemdEnv<'_>,
    query: impl FnOnce() -> Option<UnitProperties>,
) -> Supervision {
    let Some(invocation_id) = main_process_invocation(env) else {
        return Supervision::None;
    };
    // Without a notification socket nothing can tell systemd about a replacement.
    if !env.notify_socket {
        return Supervision::SystemdMainProcess;
    }
    // FAIL CLOSED from here: anything the manager does not confirm refuses.
    let Some(unit) = query() else {
        return Supervision::SystemdMainProcess;
    };
    let same_unit = unit.invocation_id == invocation_id;
    let we_are_main = unit.main_pid == Some(env.our_pid);
    // `notify-reload` would send SIGHUP on `systemctl reload`, which the server ignores.
    let notify_unit = unit.service_type == "notify";
    // MAINPID= is sent by the main process itself, which `main`, `exec` and `all` accept.
    let accepts_main_pid = matches!(unit.notify_access.as_str(), "main" | "exec" | "all");
    if same_unit && we_are_main && notify_unit && accepts_main_pid {
        Supervision::SystemdFollowsMainPid
    } else {
        Supervision::SystemdMainProcess
    }
}

/// The unit's invocation id when this process' exit would be the unit's exit.
fn main_process_invocation<'a>(env: &SystemdEnv<'a>) -> Option<&'a str> {
    // No unit at all: not supervised.
    let invocation_id = env.invocation_id.filter(|id| !id.is_empty())?;
    match env
        .exec_pid
        .map(str::trim)
        .and_then(|pid| pid.parse::<u32>().ok())
    {
        // Systemd named a main pid and it is not us — we are a child, our exit is our own.
        Some(main_pid) if main_pid != env.our_pid => None,
        // It is us, or systemd did not say: assume our exit is the unit's exit.
        _ => Some(invocation_id),
    }
}

/// Tell a `Type=notify` unit the server is up. Only the main process speaks for the
/// unit, so a herdr started inside some other notify unit stays quiet.
pub(crate) fn notify_ready() {
    let invocation_id = std::env::var("INVOCATION_ID").ok();
    let exec_pid = std::env::var(EXEC_PID_ENV).ok();
    if main_process_invocation(&current_env(&invocation_id, &exec_pid)).is_none() {
        return;
    }
    let Some(socket) = notify_socket() else {
        return;
    };
    let deadline = std::time::Instant::now() + MANAGER_TIMEOUT;
    if let Err(err) = crate::platform::systemd_notify(socket, "READY=1", deadline) {
        tracing::warn!(%err, "could not tell systemd the server is ready");
    }
}

/// The manager, as a handover needs it, split out so the policy can be tested
/// without one. Each call is bounded by the deadline it is given.
#[derive(Clone, Copy)]
pub(crate) struct Manager<'a> {
    /// Send one notification. Err means it never left this process.
    pub(crate) send: &'a dyn Fn(&str, std::time::Instant) -> std::io::Result<()>,
    /// `BARRIER=1`: Ok once the manager has processed everything sent before it.
    pub(crate) barrier: &'a dyn Fn(std::time::Instant) -> std::io::Result<()>,
    /// The unit's `MainPID`, for this process' own invocation of it.
    pub(crate) main_pid: &'a dyn Fn(std::time::Instant) -> Option<u32>,
}

impl Manager<'static> {
    /// The systemd manager that runs this process' unit.
    pub(crate) fn systemd() -> Self {
        Self {
            send: &send_notification,
            barrier: &send_barrier,
            main_pid: &invocation_main_pid,
        }
    }
}

fn send_notification(message: &str, deadline: std::time::Instant) -> std::io::Result<()> {
    crate::platform::systemd_notify(own_notify_socket()?, message, deadline)
}

fn send_barrier(deadline: std::time::Instant) -> std::io::Result<()> {
    crate::platform::systemd_notify_barrier(own_notify_socket()?, deadline)
}

fn own_notify_socket() -> std::io::Result<&'static str> {
    notify_socket().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no systemd notification socket",
        )
    })
}

/// Who the manager follows as the unit's main process once a handover was tried.
/// Exactly one answer lets the replacement be stopped: stopping the unit's main
/// process deactivates the unit and kills every pane with it.
#[derive(Debug)]
pub(crate) enum MainPidOwner {
    /// The manager names the replacement.
    Replacement,
    /// The manager names a process other than the replacement (this one, normally),
    /// or `MAINPID=<replacement>` never reached it. Why the handover failed.
    Ours(std::io::Error),
    /// `MAINPID=<replacement>` reached the manager and nothing shows it was refused
    /// or undone: the replacement may be the main process.
    Unknown(std::io::Error),
}

impl MainPidOwner {
    /// Only a manager that follows something else lets the replacement be stopped.
    pub(crate) fn allows_stopping_the_replacement(&self) -> bool {
        matches!(self, Self::Ours(_))
    }
}

/// One `MAINPID=` handover and what the manager said about it.
#[derive(Debug)]
enum Attempt {
    /// The message never left this process, so nothing changed.
    NotSent(std::io::Error),
    /// The manager names `pid`.
    Taken,
    /// The manager names this other process.
    Refused(u32),
    /// Sent, but the manager did not say who it follows by the deadline.
    Unanswered(std::io::Error),
}

/// Send `MAINPID=<pid>`, wait on `BARRIER=1`, and read the unit's `MainPID` back.
///
/// `BARRIER=1` proves the manager processed the datagrams before it, not that it
/// ACCEPTED `MAINPID=`: systemd answers barriers before it checks `NotifyAccess=`, so
/// a rejected `MAINPID=` still closes the barrier. Only the manager's own `MainPID`
/// read back afterwards says who the unit's main process is. One deadline bounds
/// every step, the sends included, so a stalled manager can't hold the server.
fn attempt_main_pid(pid: u32, manager: Manager<'_>) -> Attempt {
    let deadline = std::time::Instant::now() + MANAGER_TIMEOUT;
    if let Err(err) = (manager.send)(&format!("MAINPID={pid}"), deadline) {
        return Attempt::NotSent(err);
    }
    if let Err(err) = (manager.barrier)(deadline) {
        return Attempt::Unanswered(err);
    }
    match (manager.main_pid)(deadline) {
        Some(main) if main == pid => Attempt::Taken,
        Some(main) => Attempt::Refused(main),
        None => Attempt::Unanswered(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "systemd did not say who the unit's main process is",
        )),
    }
}

/// Hand the unit's main pid to `child` before the handoff commits.
///
/// [`MainPidOwner::Replacement`]: commit. [`MainPidOwner::Ours`]: abort, stop the
/// replacement and keep serving. [`MainPidOwner::Unknown`]: commit anyway.
///
/// Once `MAINPID=child` has reached the manager, the replacement may be the unit's
/// main process, and stopping it then ends the unit and every pane. Under
/// `NotifyAccess=main` this process can't take the main pid back then either: only
/// the replacement may send `MAINPID=`. So an unknown owner is never resolved by
/// stopping the replacement. It is ready and authorized, and letting it finish
/// taking over is the only direction that can't be the main process dying. That
/// is also the likely truth: preflight confirmed this process as main with a
/// `NotifyAccess=` that accepts `MAINPID=` from it. The one case it gets wrong (the
/// manager refused `MAINPID=` AND stopped answering) can't be told apart from here.
pub(crate) fn hand_over_main_pid(child: u32, ours: u32, manager: Manager<'_>) -> MainPidOwner {
    match attempt_main_pid(child, manager) {
        Attempt::Taken => MainPidOwner::Replacement,
        Attempt::NotSent(err) => MainPidOwner::Ours(err),
        Attempt::Refused(main) => MainPidOwner::Ours(std::io::Error::other(format!(
            "systemd did not accept MAINPID={child}: the unit's main process is still {main}"
        ))),
        Attempt::Unanswered(err) => take_main_pid_back(child, ours, manager, err),
    }
}

/// Ask the manager to follow this process (`ours`) again instead of `child`, and
/// find out whom it follows. `why` is the failure that made this necessary.
///
/// Under `NotifyAccess=main` the manager refuses this once it follows `child`, and
/// says so; under `all` it takes this process back. Whatever it can't confirm is
/// [`MainPidOwner::Unknown`], never [`MainPidOwner::Ours`].
pub(crate) fn take_main_pid_back(
    child: u32,
    ours: u32,
    manager: Manager<'_>,
    why: std::io::Error,
) -> MainPidOwner {
    let restore_err = match attempt_main_pid(ours, manager) {
        Attempt::Taken => return MainPidOwner::Ours(why),
        Attempt::Refused(main) if main == child => return MainPidOwner::Replacement,
        Attempt::Refused(_) => return MainPidOwner::Ours(why),
        Attempt::NotSent(err) | Attempt::Unanswered(err) => err,
    };
    match (manager.main_pid)(std::time::Instant::now() + MANAGER_TIMEOUT) {
        Some(main) if main == child => MainPidOwner::Replacement,
        Some(_) => MainPidOwner::Ours(why),
        None => MainPidOwner::Unknown(std::io::Error::other(format!(
            "{why}; restoring MAINPID={ours} was not confirmed either: {restore_err}"
        ))),
    }
}

/// The unit's `MainPID` by `deadline`, provided the manager still runs this process'
/// own invocation of it: a `MainPID` of any other invocation confirms nothing.
pub(crate) fn invocation_main_pid(deadline: std::time::Instant) -> Option<u32> {
    let invocation_id = std::env::var("INVOCATION_ID").ok()?;
    query_unit(deadline)
        .filter(|unit| unit.invocation_id == invocation_id)
        .and_then(|unit| unit.main_pid)
}

const MANAGER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Parse `systemctl show` output (`Key=Value` lines).
pub(crate) fn parse_unit_properties(text: &str) -> Option<UnitProperties> {
    let mut invocation_id = None;
    let mut main_pid = None;
    let mut service_type = None;
    let mut notify_access = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "InvocationID" => invocation_id = Some(value.to_string()),
            "MainPID" => main_pid = Some(value.parse::<u32>().ok().filter(|pid| *pid != 0)),
            "Type" => service_type = Some(value.to_string()),
            "NotifyAccess" => notify_access = Some(value.to_string()),
            _ => {}
        }
    }
    Some(UnitProperties {
        invocation_id: invocation_id.filter(|id| !id.is_empty())?,
        main_pid: main_pid?,
        service_type: service_type?,
        notify_access: notify_access?,
    })
}

/// Ask the manager that runs this process' unit for the properties the decision needs.
fn query_unit(deadline: std::time::Instant) -> Option<UnitProperties> {
    let output = crate::platform::show_own_systemd_unit(
        &["InvocationID", "MainPID", "Type", "NotifyAccess"],
        deadline,
    )?;
    let properties = parse_unit_properties(&output);
    if properties.is_none() {
        tracing::warn!("systemd did not describe the server's unit");
    }
    properties
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(
        invocation_id: Option<&'a str>,
        exec_pid: Option<&'a str>,
        our_pid: u32,
    ) -> SystemdEnv<'a> {
        SystemdEnv {
            invocation_id,
            exec_pid,
            our_pid,
            notify_socket: false,
        }
    }

    fn unit(main_pid: u32, service_type: &str, notify_access: &str) -> UnitProperties {
        UnitProperties {
            invocation_id: "abc123".into(),
            main_pid: Some(main_pid),
            service_type: service_type.into(),
            notify_access: notify_access.into(),
        }
    }

    fn never_asked() -> Option<UnitProperties> {
        panic!("the manager must not be asked")
    }

    #[test]
    fn no_unit_means_unsupervised() {
        assert_eq!(
            detect_from(&env(None, None, 42), never_asked),
            Supervision::None
        );
        assert_eq!(
            detect_from(&env(Some(""), None, 42), never_asked),
            Supervision::None
        );
    }

    /// The incident's exact shape: a `Type=simple` unit's main process. There is no
    /// notification socket, so exiting deactivates the unit and the cgroup kill takes
    /// the replacement and every pane with it.
    #[test]
    fn systemd_main_process_forbids_handoff() {
        let s = detect_from(&env(Some("abc123"), Some("42"), 42), never_asked);
        assert_eq!(s, Supervision::SystemdMainProcess);
        assert!(s.forbids_process_handoff());
        assert!(!s.hands_over_main_pid());
    }

    /// A CHILD inside a systemd unit inherits INVOCATION_ID but is not the main process.
    /// Blocking it would refuse handoffs that are actually safe, so the pid comparison is
    /// what keeps this a guard rather than a blanket ban.
    #[test]
    fn a_child_inside_a_unit_is_not_the_main_process() {
        let s = detect_from(
            &SystemdEnv {
                notify_socket: true,
                ..env(Some("abc123"), Some("42"), 99)
            },
            never_asked,
        );
        assert_eq!(s, Supervision::None);
        assert!(!s.forbids_process_handoff());
        assert!(!s.hands_over_main_pid());
    }

    /// Unparsable or absent main pid under a unit: FAIL CLOSED. Refusing a safe handoff
    /// costs one manual restart; allowing an unsafe one costs every live pane.
    #[test]
    fn an_unknown_main_pid_under_a_unit_fails_closed() {
        assert_eq!(
            detect_from(&env(Some("abc123"), None, 42), never_asked),
            Supervision::SystemdMainProcess
        );
        assert_eq!(
            detect_from(&env(Some("abc123"), Some("not-a-pid"), 42), never_asked),
            Supervision::SystemdMainProcess
        );
    }

    /// The supported shape: the main process of a `Type=notify` unit whose manager
    /// accepts `MAINPID=` from it may hand off, moving the main pid first.
    #[test]
    fn a_notify_unit_follows_the_handoff() {
        for access in ["main", "exec", "all"] {
            let s = detect_from(
                &SystemdEnv {
                    notify_socket: true,
                    ..env(Some("abc123"), Some("42"), 42)
                },
                || Some(unit(42, "notify", access)),
            );
            assert_eq!(
                s,
                Supervision::SystemdFollowsMainPid,
                "NotifyAccess={access}"
            );
            assert!(!s.forbids_process_handoff());
            assert!(s.hands_over_main_pid());
        }
    }

    /// Everything the manager does not confirm keeps today's refusal.
    #[test]
    fn a_unit_that_cannot_follow_keeps_the_refusal() {
        let main = SystemdEnv {
            notify_socket: true,
            ..env(Some("abc123"), Some("42"), 42)
        };
        let refused = [
            ("manager unreachable", None),
            ("Type=simple", Some(unit(42, "simple", "all"))),
            ("Type=notify-reload", Some(unit(42, "notify-reload", "all"))),
            ("NotifyAccess=none", Some(unit(42, "notify", "none"))),
            ("another main pid", Some(unit(7, "notify", "all"))),
            (
                "another unit",
                Some(UnitProperties {
                    invocation_id: "def456".into(),
                    ..unit(42, "notify", "all")
                }),
            ),
        ];
        for (case, properties) in refused {
            assert_eq!(
                detect_from(&main, || properties),
                Supervision::SystemdMainProcess,
                "{case}"
            );
        }
        // No socket: the unit could never hear MAINPID=, so the manager isn't asked.
        assert_eq!(
            detect_from(&env(Some("abc123"), Some("42"), 42), never_asked),
            Supervision::SystemdMainProcess
        );
    }

    /// A replacement that took over the main pid names itself in SYSTEMD_EXEC_PID, but
    /// the manager still decides: only the manager naming it main lets its own next
    /// handoff (an update, or the guard's handoff back) run.
    #[test]
    fn a_replacement_asks_the_manager_whether_it_is_main() {
        let replacement = SystemdEnv {
            notify_socket: true,
            ..env(Some("abc123"), Some("99"), 99)
        };
        assert_eq!(
            detect_from(&replacement, || Some(unit(99, "notify", "main"))),
            Supervision::SystemdFollowsMainPid
        );
        // The predecessor could not move the main pid, so the manager still names it.
        assert_eq!(
            detect_from(&replacement, || Some(unit(42, "notify", "main"))),
            Supervision::SystemdMainProcess
        );
    }

    /// A successor gets the marker and loses its predecessor's SYSTEMD_EXEC_PID, so a
    /// build that ignores the marker fails closed rather than reading itself as a child.
    #[test]
    fn a_main_pid_successor_drops_the_predecessor_pid() {
        let mut command = std::process::Command::new("true");
        command.env(EXEC_PID_ENV, "42");
        prepare_main_pid_successor(&mut command);
        let envs: std::collections::HashMap<_, _> = command.get_envs().collect();
        assert_eq!(
            envs.get(std::ffi::OsStr::new(TAKES_MAIN_PID_ENV)),
            Some(&Some(std::ffi::OsStr::new("1")))
        );
        assert_eq!(envs.get(std::ffi::OsStr::new(EXEC_PID_ENV)), Some(&None));
        assert_eq!(
            detect_from(&env(Some("abc123"), None, 99), never_asked),
            Supervision::SystemdMainProcess
        );
    }

    #[test]
    fn systemctl_show_output_parses() {
        let text = "Type=notify\nNotifyAccess=all\nMainPID=4242\nInvocationID=9e2980d4c2cd414d9ce86697755e9d10\n";
        assert_eq!(
            parse_unit_properties(text),
            Some(UnitProperties {
                invocation_id: "9e2980d4c2cd414d9ce86697755e9d10".into(),
                main_pid: Some(4242),
                service_type: "notify".into(),
                notify_access: "all".into(),
            })
        );
        // A stopped unit: no main pid, no invocation.
        assert_eq!(
            parse_unit_properties("Type=notify\nNotifyAccess=all\nMainPID=0\nInvocationID=\n"),
            None
        );
        assert_eq!(
            parse_unit_properties("Type=notify\nNotifyAccess=all\nMainPID=0\nInvocationID=abc\n")
                .and_then(|unit| unit.main_pid),
            None
        );
    }

    const OURS: u32 = 17;
    const CHILD: u32 = 4242;

    /// Who may send `MAINPID=`; every message here comes from this process (`OURS`).
    #[derive(Clone, Copy, PartialEq)]
    enum Access {
        /// `MAINPID=` is refused, as when `NotifyAccess=` changed to `none`.
        Refused,
        /// `NotifyAccess=main`: only while this process is the main one.
        Main,
        /// `NotifyAccess=all`.
        All,
    }

    /// A manager that follows `main` and answers the `n`th `MainPID` query only when
    /// `answers(n)`. Every barrier closes.
    struct FakeManager {
        main: std::cell::Cell<u32>,
        access: Access,
        sends_fail: bool,
        answers: fn(usize) -> bool,
        queries: std::cell::Cell<usize>,
        sent: std::cell::RefCell<Vec<String>>,
    }

    impl FakeManager {
        fn new(access: Access, answers: fn(usize) -> bool) -> Self {
            Self {
                main: std::cell::Cell::new(OURS),
                access,
                sends_fail: false,
                answers,
                queries: std::cell::Cell::new(0),
                sent: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn send(&self, message: &str) -> std::io::Result<()> {
            if self.sends_fail {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "systemd's notification queue stayed full",
                ));
            }
            self.sent.borrow_mut().push(message.to_string());
            let pid = message.strip_prefix("MAINPID=").unwrap().parse().unwrap();
            let accepted = match self.access {
                Access::Refused => false,
                Access::Main => self.main.get() == OURS,
                Access::All => true,
            };
            if accepted {
                self.main.set(pid);
            }
            Ok(())
        }

        fn main_pid(&self) -> Option<u32> {
            let n = self.queries.get();
            self.queries.set(n + 1);
            (self.answers)(n).then(|| self.main.get())
        }

        fn with<R>(&self, f: impl FnOnce(Manager<'_>) -> R) -> R {
            let send = |message: &str, _: std::time::Instant| self.send(message);
            let barrier = |_: std::time::Instant| -> std::io::Result<()> { Ok(()) };
            let main_pid = |_: std::time::Instant| self.main_pid();
            f(Manager {
                send: &send,
                barrier: &barrier,
                main_pid: &main_pid,
            })
        }

        fn sent(&self) -> Vec<String> {
            self.sent.borrow().clone()
        }
    }

    fn always(_: usize) -> bool {
        true
    }

    fn never(_: usize) -> bool {
        false
    }

    fn after_the_first(n: usize) -> bool {
        n > 0
    }

    /// F2: an unconfirmed handover names this process again, and the manager
    /// confirming that is what lets the handoff abort and stop the replacement.
    #[test]
    fn an_unconfirmed_handover_restores_this_process_and_aborts() {
        let manager = FakeManager::new(Access::All, after_the_first);
        let owner = manager.with(|m| hand_over_main_pid(CHILD, OURS, m));
        assert!(matches!(owner, MainPidOwner::Ours(_)), "{owner:?}");
        assert!(owner.allows_stopping_the_replacement());
        assert_eq!(manager.sent(), ["MAINPID=4242", "MAINPID=17"]);
        assert_eq!(manager.main.get(), OURS);

        // A MAINPID= that never left this process changed nothing.
        let manager = FakeManager {
            sends_fail: true,
            ..FakeManager::new(Access::Main, always)
        };
        let owner = manager.with(|m| hand_over_main_pid(CHILD, OURS, m));
        assert!(owner.allows_stopping_the_replacement(), "{owner:?}");
    }

    /// P1 of review 2: once MAINPID=<replacement> reached the manager, only the
    /// manager naming another process lets the replacement be stopped. Under
    /// NotifyAccess=main it now follows the replacement and refuses this process'
    /// MAINPID=; if it also stops answering, stopping the replacement would be the
    /// unit's main process dying, so the owner is unknown and the handoff commits.
    #[test]
    fn an_unknown_owner_after_a_delivered_main_pid_never_stops_the_replacement() {
        let manager = FakeManager::new(Access::Main, never);
        let owner = manager.with(|m| hand_over_main_pid(CHILD, OURS, m));
        assert!(matches!(owner, MainPidOwner::Unknown(_)), "{owner:?}");
        assert!(!owner.allows_stopping_the_replacement());
        assert_eq!(manager.sent(), ["MAINPID=4242", "MAINPID=17"]);
        assert_eq!(manager.main.get(), CHILD, "the replacement is main");

        // Answering late: the manager refuses this process and names the replacement.
        let manager = FakeManager::new(Access::Main, after_the_first);
        let owner = manager.with(|m| hand_over_main_pid(CHILD, OURS, m));
        assert!(matches!(owner, MainPidOwner::Replacement), "{owner:?}");

        // A failed commit asks the same question before the replacement is stopped.
        let why = || std::io::Error::other("commit failed");
        for (access, answers, stop) in [
            (Access::Main, never as fn(usize) -> bool, false),
            (Access::Main, always, false),
            (Access::All, always, true),
            (Access::All, never, false),
        ] {
            let manager = FakeManager::new(access, answers);
            manager.main.set(CHILD);
            let owner = manager.with(|m| take_main_pid_back(CHILD, OURS, m, why()));
            assert_eq!(owner.allows_stopping_the_replacement(), stop, "{owner:?}");
        }
    }

    /// F1: a closed barrier is not an accepted `MAINPID=`; the manager's own
    /// `MainPID` decides, and anything but the replacement keeps this process.
    #[test]
    fn a_main_pid_the_manager_did_not_take_refuses_the_exit() {
        let manager = FakeManager::new(Access::Refused, always);
        let owner = manager.with(|m| hand_over_main_pid(CHILD, OURS, m));
        assert!(matches!(owner, MainPidOwner::Ours(_)), "{owner:?}");
        assert_eq!(manager.sent(), ["MAINPID=4242"]);

        let manager = FakeManager::new(Access::Main, always);
        let owner = manager.with(|m| hand_over_main_pid(CHILD, OURS, m));
        assert!(matches!(owner, MainPidOwner::Replacement), "{owner:?}");
        assert_eq!(manager.sent(), ["MAINPID=4242"]);
    }
}
