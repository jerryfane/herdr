//! Requests from callers inside a pane fence that may act only on their own pane
//! or agent (docs/next/design/pane-fence.md, section 8).

use crate::api::fence_policy::{fenced_access, FencedAccess, OwnTarget};
use crate::api::schema::{FenceScopedParams, Method, Request};

use super::responses::encode_error;
use crate::app::App;

impl App {
    /// Run `params.method` only when it targets the pane whose process runs in
    /// the caller's mount namespace. The caller's pane is looked up again on every
    /// request: a respawned pane has a new namespace, so a process left over from
    /// the old one no longer owns it.
    pub(super) fn handle_fence_scoped(&mut self, id: String, params: FenceScopedParams) -> String {
        let FenceScopedParams {
            mount_namespace,
            method,
        } = params;
        let target = match fenced_access(&method) {
            FencedAccess::Own(target) => target,
            _ => return refused(id, method.operation().name, "is not an own-pane request"),
        };
        let Some(own_terminal) = self.terminal_in_mount_namespace(mount_namespace) else {
            return refused(
                id,
                method.operation().name,
                "comes from a fenced process that no longer belongs to a running pane",
            );
        };
        let target_terminal = match &target {
            OwnTarget::Pane(None) => {
                return refused(
                    id,
                    method.operation().name,
                    "must name its pane (the focused pane may belong to someone else)",
                );
            }
            OwnTarget::Pane(Some(pane_id)) => {
                self.parse_pane_id(pane_id).and_then(|(ws_idx, pane_id)| {
                    self.state
                        .workspaces
                        .get(ws_idx)?
                        .terminal_id(pane_id)
                        .map(|terminal| terminal.as_str().to_owned())
                })
            }
            OwnTarget::Agent(target) => self
                .resolve_agent_target(target)
                .ok()
                .map(|resolved| resolved.terminal_id),
        };
        if target_terminal.as_deref() != Some(own_terminal.as_str()) {
            return refused(
                id,
                method.operation().name,
                "targets a pane that is not the caller's own",
            );
        }
        if let Some(why) = self.fenced_close_reaches_beyond_pane(&method) {
            return refused(id, method.operation().name, why);
        }
        self.handle_api_request_after_internal_events_drained(Request {
            id,
            method: *method,
        })
    }

    /// `pane.close` of the caller's own pane is allowed only when it closes nothing
    /// else. Closing the last pane of a workspace closes the workspace, and when that
    /// workspace leads a worktree group (and `confirm_close` is off) the linked
    /// workspaces with all their panes go too.
    fn fenced_close_reaches_beyond_pane(&self, method: &Method) -> Option<&'static str> {
        let Method::PaneClose(target) = method else {
            return None;
        };
        let (ws_idx, pane_id) = self.parse_pane_id(&target.pane_id)?;
        (self.state.close_pane_would_close_workspace(ws_idx, pane_id)
            && self.state.workspace_close_indices(ws_idx) != [ws_idx])
        .then_some("would also close other workspaces in its worktree group")
    }

    /// The terminal whose pane process runs in `mount_namespace`.
    #[cfg(unix)]
    fn terminal_in_mount_namespace(&self, mount_namespace: u64) -> Option<String> {
        self.terminal_runtimes
            .iter()
            .find_map(|(terminal_id, runtime)| {
                let pid = runtime.child_pid()?;
                (crate::platform::process_mount_namespace(pid) == Some(mount_namespace))
                    .then(|| terminal_id.as_str().to_owned())
            })
    }
}

/// Fenced callers exist only on Linux; elsewhere no pane can own a request.
#[cfg(not(unix))]
impl App {
    fn terminal_in_mount_namespace(&self, _mount_namespace: u64) -> Option<String> {
        None
    }
}

fn refused(id: String, method: &str, why: &str) -> String {
    encode_error(
        id,
        "fence_refused",
        format!(
            "refused by pane fence: {method} {why}. A fenced pane may act only on its own pane and agent; see herdr fence explain"
        ),
    )
}

#[cfg(test)]
mod tests {
    use crate::api::schema::{FenceScopedParams, Method, Request};
    use crate::app::App;
    use crate::config::Config;

    fn app() -> App {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        App::new(
            &Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            api_rx,
            crate::api::EventHub::default(),
        )
    }

    fn scoped(json: &str) -> FenceScopedParams {
        let request: Request = serde_json::from_str(json).expect("request");
        FenceScopedParams {
            mount_namespace: 1,
            method: Box::new(request.method),
        }
    }

    #[test]
    fn a_caller_that_owns_no_pane_is_refused() {
        // No pane runs in mount namespace 1, so the caller owns nothing: fail closed.
        let response = app().handle_fence_scoped(
            "1".into(),
            scoped(
                r#"{"id":"1","method":"pane.send_text","params":{"pane_id":"w1:p1","text":"x"}}"#,
            ),
        );
        assert!(response.contains("fence_refused"), "{response}");
        assert!(response.contains("no longer belongs"), "{response}");
    }

    fn close(app: &App, ws_idx: usize) -> Method {
        let pane = app.state.workspaces[ws_idx].tabs[0].root_pane;
        let pane_id = app.pane_info(ws_idx, pane).expect("pane").pane_id;
        Method::PaneClose(crate::api::schema::PaneTarget { pane_id })
    }

    fn worktree(checkout: &str, linked: bool) -> crate::workspace::WorktreeSpaceMembership {
        crate::workspace::WorktreeSpaceMembership {
            key: "repo-key".into(),
            label: "herdr".into(),
            repo_root: "/repo/herdr".into(),
            checkout_path: checkout.into(),
            is_linked_worktree: linked,
        }
    }

    #[test]
    fn closing_the_last_pane_of_a_worktree_group_parent_is_refused() {
        let mut app = app();
        let mut parent = crate::workspace::Workspace::test_new("parent");
        parent.worktree_space = Some(worktree("/repo/herdr", false));
        let mut child = crate::workspace::Workspace::test_new("child");
        child.worktree_space = Some(worktree("/repo/herdr-child", true));
        let plain = crate::workspace::Workspace::test_new("plain");
        app.state.workspaces = vec![parent, child, plain];
        app.state.ensure_test_terminals();

        // The parent's only pane: closing it would close the linked child workspace too.
        assert!(app
            .fenced_close_reaches_beyond_pane(&close(&app, 0))
            .is_some());
        // Control: the last pane of a workspace outside any group closes only itself.
        assert_eq!(app.fenced_close_reaches_beyond_pane(&close(&app, 2)), None);
        // Other methods are not affected.
        assert_eq!(
            app.fenced_close_reaches_beyond_pane(&Method::ServerReloadConfig(Default::default())),
            None
        );
    }

    #[test]
    fn a_scoped_request_must_be_an_own_pane_request() {
        let params = FenceScopedParams {
            mount_namespace: 1,
            method: Box::new(Method::ServerReloadConfig(Default::default())),
        };
        let response = app().handle_fence_scoped("1".into(), params);
        assert!(response.contains("fence_refused"), "{response}");
    }
}
