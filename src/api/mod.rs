pub mod client;
mod event_hub;
pub mod schema;
mod server;
mod status;
mod subscriptions;
mod wait;

pub use event_hub::EventHub;
pub(crate) use server::cancel_inactive_pane_graphics_streams;
pub use server::{start_server, start_server_with_capabilities, ServerHandle};
pub use status::{read_runtime_status_at, RuntimeStatus};

use std::path::PathBuf;

use tokio::sync::mpsc;

use crate::api::schema::{Method, Request};

pub const SOCKET_PATH_ENV_VAR: &str = "HERDR_SOCKET_PATH";

pub(crate) fn request_changes_ui(request: &Request) -> bool {
    matches!(
        &request.method,
        Method::ServerReloadConfig(_)
            | Method::ServerReloadAgentManifests(_)
            | Method::NotificationShow(_)
            | Method::WorkspaceCreate(_)
            | Method::WorkspaceFocus(_)
            | Method::WorkspaceRename(_)
            | Method::WorkspaceMove(_)
            | Method::WorkspaceMoveBlock(_)
            | Method::WorkspaceReportMetadata(_)
            | Method::WorkspaceClose(_)
            | Method::WorktreeCreate(_)
            | Method::WorktreeOpen(_)
            | Method::WorktreeRemove(_)
            | Method::TabCreate(_)
            | Method::TabFocus(_)
            | Method::TabRename(_)
            | Method::TabMove(_)
            | Method::TabClose(_)
            | Method::LayoutApply(_)
            | Method::LayoutSetSplitRatio(_)
            | Method::AgentRename(_)
            | Method::AgentViewSet(_)
            | Method::AgentViewClear(_)
            | Method::AgentFocus(_)
            | Method::AgentStart(_)
            | Method::AgentAcpRegister(_)
            | Method::AgentAcpEndpoint(_)
            | Method::AgentAcpStatus(_)
            | Method::AgentAcpAttach(_)
            | Method::AgentAcpDetach(_)
            | Method::AgentPrompt(_)
            | Method::AgentSendKeys(_)
            | Method::PaneSplit(_)
            | Method::PaneSwap(_)
            | Method::PaneMove(_)
            | Method::PaneZoom(_)
            | Method::PaneFocusDirection(_)
            | Method::PaneResize(_)
            | Method::PaneFocus(_)
            | Method::PaneRename(_)
            | Method::PaneGraphicsSet(_)
            | Method::PaneGraphicsClear(_)
            | Method::PaneGraphicsStream(_)
            | Method::PaneGraphicsStreamSet(_)
            | Method::PaneGraphicsStreamOpen(_)
            | Method::PaneGraphicsStreamClose(_)
            | Method::PaneReportAgent(_)
            | Method::PaneReportAgentSession(_)
            | Method::PaneReportMetadata(_)
            | Method::PaneClearAgentAuthority(_)
            | Method::PaneReleaseAgent(_)
            | Method::PaneClose(_)
            | Method::PopupClose(_)
            | Method::PluginUnlink(_)
            | Method::PluginDisable(_)
            | Method::PluginActionInvoke(_)
            | Method::PluginPaneOpen(_)
            | Method::PluginPaneFocus(_)
            | Method::PluginPaneClose(_)
    )
}

pub struct ApiRequestMessage {
    pub request: Request,
    pub respond_to: std::sync::mpsc::Sender<String>,
    pub response_write_complete: Option<std::sync::mpsc::Receiver<()>>,
}

pub type ApiRequestSender = mpsc::UnboundedSender<ApiRequestMessage>;

pub fn socket_path() -> PathBuf {
    crate::session::active_api_socket_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_acp_request_is_classified_as_ui_changing() {
        let requests = [
            serde_json::json!({
                "id": "register",
                "method": "agent.acp_register",
                "params": {
                    "name": "worker",
                    "kind": "codex",
                    "pane_id": "w1:p1",
                    "cwd": "/work",
                    "session": {"mode": "new"}
                }
            }),
            serde_json::json!({
                "id": "endpoint",
                "method": "agent.acp_endpoint",
                "params": {"target": "worker"}
            }),
            serde_json::json!({
                "id": "status",
                "method": "agent.acp_status",
                "params": {"target": "worker"}
            }),
            serde_json::json!({
                "id": "attach",
                "method": "agent.acp_attach",
                "params": {"target": "worker", "generation": 1, "ticket": "ticket"}
            }),
            serde_json::json!({
                "id": "detach",
                "method": "agent.acp_detach",
                "params": {"target": "worker", "generation": 1, "lease": "lease"}
            }),
        ];

        for value in requests {
            let request: Request = serde_json::from_value(value).unwrap();
            assert!(request_changes_ui(&request));
        }
    }
}
