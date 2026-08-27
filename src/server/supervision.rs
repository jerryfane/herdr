//! Whether this process is the one a service supervisor is watching.
//!
//! This exists because of a real incident. `server.apply_staged_update` performs a live
//! handoff: it spawns a replacement, hands over the sockets and PTYs, then the OLD main
//! process exits. That is seamless when herdr owns its own lifetime — and destructive
//! under systemd.
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

/// How this process is being supervised, as far as it can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Supervision {
    /// Nothing is watching this process' lifetime; it may hand off and exit freely.
    None,
    /// systemd is watching THIS process as the unit's main process. Exiting deactivates
    /// the unit and takes the cgroup — replacement and panes included — down with it.
    SystemdMainProcess,
}

impl Supervision {
    /// Whether exiting after a handoff would take the replacement down too.
    pub(crate) fn forbids_process_handoff(self) -> bool {
        matches!(self, Self::SystemdMainProcess)
    }
}

/// Detect supervision from the environment the supervisor injected.
///
/// `INVOCATION_ID` is set by systemd for every unit it starts, and `SYSTEMD_EXEC_PID`
/// names the process systemd considers the unit's main one. Both together answer the
/// only question that matters: *would this process exiting tear down the unit?*
///
/// `SYSTEMD_EXEC_PID` is what makes this precise rather than merely cautious. A herdr
/// spawned as a CHILD inside a systemd unit inherits `INVOCATION_ID` but is not the main
/// process, so its exit is harmless — treating it as supervised would block handoffs that
/// are perfectly safe. When systemd is too old to set the pid, fall back to assuming we
/// ARE the main process: refusing a safe handoff costs an operator one manual restart,
/// while allowing an unsafe one costs every live pane.
pub(crate) fn detect() -> Supervision {
    detect_from(
        std::env::var("INVOCATION_ID").ok().as_deref(),
        std::env::var("SYSTEMD_EXEC_PID").ok().as_deref(),
        std::process::id(),
    )
}

/// The decision, split out from the environment so it can be tested without one.
pub(crate) fn detect_from(
    invocation_id: Option<&str>,
    systemd_exec_pid: Option<&str>,
    our_pid: u32,
) -> Supervision {
    // No unit at all: not supervised.
    let Some(invocation_id) = invocation_id else {
        return Supervision::None;
    };
    if invocation_id.is_empty() {
        return Supervision::None;
    }
    match systemd_exec_pid
        .map(str::trim)
        .and_then(|pid| pid.parse::<u32>().ok())
    {
        // Systemd named a main pid and it is not us — we are a child, our exit is our own.
        Some(main_pid) if main_pid != our_pid => Supervision::None,
        // It is us, or systemd did not say: assume our exit is the unit's exit.
        _ => Supervision::SystemdMainProcess,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_unit_means_unsupervised() {
        assert_eq!(detect_from(None, None, 42), Supervision::None);
        assert_eq!(detect_from(Some(""), None, 42), Supervision::None);
    }

    /// The incident's exact shape: systemd's main process. Exiting here deactivates the
    /// unit and the cgroup kill takes the replacement and every pane with it.
    #[test]
    fn systemd_main_process_forbids_handoff() {
        let s = detect_from(Some("abc123"), Some("42"), 42);
        assert_eq!(s, Supervision::SystemdMainProcess);
        assert!(s.forbids_process_handoff());
    }

    /// A CHILD inside a systemd unit inherits INVOCATION_ID but is not the main process.
    /// Blocking it would refuse handoffs that are actually safe, so the pid comparison is
    /// what keeps this a guard rather than a blanket ban.
    #[test]
    fn a_child_inside_a_unit_is_not_the_main_process() {
        let s = detect_from(Some("abc123"), Some("42"), 99);
        assert_eq!(s, Supervision::None);
        assert!(!s.forbids_process_handoff());
    }

    /// Unparsable or absent main pid under a unit: FAIL CLOSED. Refusing a safe handoff
    /// costs one manual restart; allowing an unsafe one costs every live pane.
    #[test]
    fn an_unknown_main_pid_under_a_unit_fails_closed() {
        assert_eq!(
            detect_from(Some("abc123"), None, 42),
            Supervision::SystemdMainProcess
        );
        assert_eq!(
            detect_from(Some("abc123"), Some("not-a-pid"), 42),
            Supervision::SystemdMainProcess
        );
    }
}
