use serde::{Deserialize, Serialize};

use crate::api::federation_store::Reachability;

use super::ServerCapabilities;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SavedMachineState {
    Disabled,
    Untrusted,
    CoordinatorDisabled,
    Coordinated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MachineEndpointStatus {
    Connecting,
    Online,
    Reconnecting,
    Attention,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FederationPollErrorClass {
    AuthenticationFailed,
    IdentityMismatch,
    Protocol,
    Transport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoordinatorMachineStatus {
    pub profile_id: String,
    pub display_label: String,
    pub remote_session: String,
    pub saved_state: SavedMachineState,
    /// Policy presence is independent of whether the saved SSH profile is enabled.
    #[serde(default)]
    pub federation_configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_status: Option<MachineEndpointStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated_machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_reachability: Option<Reachability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_class: Option<FederationPollErrorClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_protocol: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_capabilities: Option<ServerCapabilities>,
    pub stale: bool,
}
