//! What a caller inside a pane fence may ask the herdr API to do
//! (docs/next/design/pane-fence.md, section 8).
//!
//! The table is an allow list: a method that is not named here is refused, so a new
//! API method stays closed to fenced callers until someone decides otherwise.

use super::schema::Method;

/// The pane or agent a fenced caller wants to act on, as written in the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnTarget {
    /// A pane id. `None` means the request left it out (the focused pane), which a
    /// fenced caller may not do: the focused pane is usually someone else's.
    Pane(Option<String>),
    /// An agent target (name, label or pane).
    Agent(String),
}

/// The class of a method for a fenced caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FencedAccess {
    /// Reads and waits. Allowed for any target, also on other machines.
    Read,
    /// Talking to an agent (prompt, answer). Allowed for any local agent: that
    /// agent has its own fence. Refused for agents on other machines.
    Talk,
    /// Creating a pane, tab or workspace. Allowed while new panes start fenced, so the
    /// new pane is never looser than the caller's.
    Create,
    /// Acting on one pane or agent, which must be the caller's own.
    Own(OwnTarget),
    /// `pane.input.stream`: every frame must still target the caller's own pane.
    OwnStream,
    /// Everything else: other panes, server lifecycle and config, plugins, worktrees,
    /// accounts, guests, layouts.
    Denied,
}

/// Classify a request for a fenced caller.
pub(crate) fn fenced_access(method: &Method) -> FencedAccess {
    use FencedAccess::Own;
    use OwnTarget::{Agent, Pane};
    match method {
        Method::PaneSendText(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneSendKeys(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneSendInput(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneInputSet(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneRename(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneScroll(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneResize(p) => Own(Pane(p.pane_id.clone())),
        Method::PaneZoom(p) => Own(Pane(p.pane_id.clone())),
        Method::PaneSetPtySize(p) => Own(Pane(p.pane_id.clone())),
        Method::PaneClear(p) | Method::PaneFocus(p) | Method::PaneClose(p) => {
            Own(Pane(Some(p.pane_id.clone())))
        }
        Method::PaneReportAgent(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneReportAgentSession(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneReportAgentControl(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::AgentTopicsClose(p) | Method::AgentTopicsReopen(p) => Own(Agent(p.target.clone())),
        Method::AgentTopicsRename(p) => Own(Agent(p.target.clone())),
        Method::PaneReportMetadata(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneClearAgentAuthority(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::PaneReleaseAgent(p) => Own(Pane(Some(p.pane_id.clone()))),
        Method::AgentSendKeys(p) => Own(Agent(p.target.clone())),
        Method::AgentRename(p) => Own(Agent(p.target.clone())),
        Method::AgentAvatarSet(p) => Own(Agent(p.target.clone())),
        Method::AgentFocus(p) => Own(Agent(p.target.clone())),
        Method::PaneInputStream(_) => FencedAccess::OwnStream,
        // The internal open handshake of a fenced input stream is checked as an
        // own-pane request (it validates the pane without writing to it).
        Method::PaneInputStreamOpen(p) => Own(Pane(Some(p.pane_id.clone()))),
        other => access_by_name(other.operation().name),
    }
}

/// Reads, waits and Gram. Gram is mail held by the server: reading and sending it
/// runs nothing. `gram.relay` (the reverse SSH gateway) stays owner-only.
const READ: &[&str] = &[
    "ping",
    "agent.list",
    "agent.get",
    "agent.read",
    "agent.transcript",
    "agent.topics.list",
    "agent.explain",
    "fence.explain",
    "agent.avatar.get",
    "agent.groups.get",
    "agent.kinds",
    "agent.wait",
    "accounts.list",
    "pane.list",
    "pane.current",
    "pane.get",
    "pane.read",
    "pane.history",
    "pane.turns",
    "pane.stream",
    "pane.wait_for_output",
    "pane.process_info",
    "pane.neighbor",
    "pane.edges",
    "layout.export",
    "events.subscribe",
    "events.wait",
    "session.snapshot",
    "workspace.list",
    "workspace.get",
    "tab.list",
    "tab.get",
    "worktree.list",
    "fs.list_dir",
    "machine.status",
    "plugin.list",
    "plugin.action.list",
    "integration.list",
    "notifications.status",
    "gram.relay_status",
    "gram.send",
    "gram.post",
    "gram.list",
    "gram.grab",
    "gram.mark_read",
    "gram.delete",
    "gram.upload_chunk",
    "gram.upload.discard",
    "gram.upload.stream",
    "gram.get_file",
    "gram.get_file_chunk",
];

const TALK: &[&str] = &[
    "agent.prompt",
    "agent.answer",
    "agent.answer_form",
    "agent.dismiss_ask",
    "agent.topics.new",
    "agent.topics.send",
];

const CREATE: &[&str] = &["pane.split", "tab.create", "workspace.create"];

fn access_by_name(name: &str) -> FencedAccess {
    if READ.contains(&name) {
        FencedAccess::Read
    } else if TALK.contains(&name) {
        FencedAccess::Talk
    } else if CREATE.contains(&name) {
        FencedAccess::Create
    } else {
        FencedAccess::Denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::{Method, Request};

    fn method(json: &str) -> Method {
        serde_json::from_str::<Request>(json)
            .unwrap_or_else(|err| panic!("{json}: {err}"))
            .method
    }

    #[test]
    fn methods_that_run_or_reconfigure_something_are_denied() {
        for name in [
            "server.stop",
            "server.live_handoff",
            "server.reload_config",
            "server.update_apply",
            "server.apply_staged_update",
            "server.ssh_agent.register",
            "plugin.link",
            "plugin.action.invoke",
            "plugin.pane.open",
            "command.invoke",
            "worktree.create",
            "worktree.remove",
            "agent.start",
            "agent.restart",
            "agent.transfer_session",
            "accounts.create",
            "integration.install",
            "layout.apply",
            "pane.link.activate",
            "gram.relay",
            "guest.invite.create",
            "workspace.close",
            "tab.close",
        ] {
            assert_eq!(access_by_name(name), FencedAccess::Denied, "{name}");
        }
    }

    #[test]
    fn every_allowed_name_is_a_real_method() {
        // A misspelt entry would silently keep a method closed.
        let names: Vec<&str> = Method::OPERATIONS.iter().map(|op| op.name).collect();
        for name in READ.iter().chain(TALK).chain(CREATE) {
            assert!(names.contains(name), "{name} is not an API method");
        }
    }

    #[test]
    fn pane_and_agent_mutations_name_their_target() {
        assert_eq!(
            fenced_access(&method(
                r#"{"id":"1","method":"pane.send_text","params":{"pane_id":"w1:p2","text":"ls\n"}}"#
            )),
            FencedAccess::Own(OwnTarget::Pane(Some("w1:p2".into())))
        );
        assert_eq!(
            fenced_access(&method(
                r#"{"id":"1","method":"agent.send_keys","params":{"target":"builder","keys":["Enter"]}}"#
            )),
            FencedAccess::Own(OwnTarget::Agent("builder".into()))
        );
        assert_eq!(
            fenced_access(&method(
                r#"{"id":"1","method":"pane.close","params":{"pane_id":"w1:p2"}}"#
            )),
            FencedAccess::Own(OwnTarget::Pane(Some("w1:p2".into())))
        );
        // Leaving the pane out means "the focused pane", which is refused later.
        assert_eq!(
            fenced_access(&method(
                r#"{"id":"1","method":"pane.zoom","params":{"mode":"toggle"}}"#
            )),
            FencedAccess::Own(OwnTarget::Pane(None))
        );
        assert_eq!(
            fenced_access(&method(
                r#"{"id":"1","method":"pane.input.stream","params":{"pane_id":"w1:p2"}}"#
            )),
            FencedAccess::OwnStream
        );
    }
}

#[cfg(test)]
mod topic_tests {
    use super::*;
    use crate::api::schema::Request;

    fn access(json: &str) -> FencedAccess {
        fenced_access(
            &serde_json::from_str::<Request>(json)
                .unwrap_or_else(|err| panic!("{json}: {err}"))
                .method,
        )
    }

    #[test]
    fn fence_classifies_agent_control_and_topics_like_their_agent_peers() {
        assert_eq!(
            access(
                r#"{"id":"1","method":"pane.report_agent_control","params":{"pane_id":"w1:p2","source":"herdr:omp","agent":"omp","agent_process_pid":7}}"#
            ),
            FencedAccess::Own(OwnTarget::Pane(Some("w1:p2".into())))
        );
        assert_eq!(
            access(r#"{"id":"1","method":"agent.topics.list","params":{"target":"builder"}}"#),
            FencedAccess::Read
        );
        for (method, extra) in [
            ("agent.topics.new", r#","title":"t","message":"m""#),
            ("agent.topics.send", r#","topic_id":"T","message":"m""#),
        ] {
            assert_eq!(
                access(&format!(
                    r#"{{"id":"1","method":"{method}","params":{{"target":"builder"{extra}}}}}"#
                )),
                FencedAccess::Talk,
                "{method}"
            );
        }
        for (method, extra) in [
            ("agent.topics.close", r#","topic_id":"T""#),
            ("agent.topics.reopen", r#","topic_id":"T""#),
            ("agent.topics.rename", r#","topic_id":"T","title":"t""#),
        ] {
            assert_eq!(
                access(&format!(
                    r#"{{"id":"1","method":"{method}","params":{{"target":"builder"{extra}}}}}"#
                )),
                FencedAccess::Own(OwnTarget::Agent("builder".into())),
                "{method}"
            );
        }
    }
}
