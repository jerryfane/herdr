use crate::api::schema::ResponseResult;

use super::*;

impl App {
    pub(super) fn handle_machine_status(&self, id: String) -> String {
        let endpoint_statuses = self.endpoint_statuses();
        let machines = self
            .federation_manager
            .as_ref()
            .map_or_else(Default::default, |manager| {
                manager.machine_statuses_with_endpoint_statuses(&endpoint_statuses)
            });
        responses::encode_success(id, ResponseResult::MachineStatus { machines })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::SuccessResponse;

    #[test]
    fn machine_status_is_empty_without_a_coordinator_manager() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let app = App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        let response: SuccessResponse =
            serde_json::from_str(&app.handle_machine_status("status".into())).unwrap();
        let ResponseResult::MachineStatus { machines } = response.result else {
            panic!("expected machine status");
        };
        assert!(machines.is_empty());
    }

    #[test]
    fn endpoint_status_uses_live_clients_and_clears_on_disconnect() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.record_client_endpoint_status(
            7,
            "profile".into(),
            crate::api::schema::MachineEndpointStatus::Reconnecting,
        );
        app.record_client_endpoint_status(
            8,
            "profile".into(),
            crate::api::schema::MachineEndpointStatus::Online,
        );
        assert_eq!(
            app.endpoint_statuses()["profile"],
            crate::api::schema::MachineEndpointStatus::Online
        );
        app.remove_client_endpoint_statuses(8);
        assert_eq!(
            app.endpoint_statuses()["profile"],
            crate::api::schema::MachineEndpointStatus::Reconnecting
        );
        app.remove_client_endpoint_statuses(7);
        assert!(app.endpoint_statuses().is_empty());
    }
}
