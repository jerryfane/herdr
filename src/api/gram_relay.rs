//! Effective Gram relay consent for both roles.
//!
//! The coordinator allows saved peers (routing alias = saved-machine profile
//! id) from `[gram_relay] peers`. The remote forwards its local Gram calls to
//! the reverse socket derived from `[gram_relay] coordinator_machine_id`. The
//! legacy process environment variables stay honoured for upgrades, but never
//! broaden durable configuration: when both are set and differ, the role is
//! disabled with a `conflict` error. `apply` runs at boot and on every
//! `reload-config`; an invalid section keeps the previous effective setting.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};

use tracing::{error, info, warn};

use crate::api::schema::{
    GramRelayCoordinatorStatus, GramRelayEnvironment, GramRelayErrorCode, GramRelayRemoteStatus,
    GramRelaySource,
};
use crate::config::GramRelayConfig;

pub(crate) const PEERS_ENV: &str = "HERDR_GRAM_RELAY_PEERS";
pub(crate) const SOCKET_ENV: &str = "HERDR_GRAM_REVERSE_SOCKET";

/// Stable remote socket name for one coordinator/remote install pair. SSH
/// creates it with an owner-only bind mask.
pub(crate) fn reverse_socket_path(coordinator_id: &str, remote_id: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("herdr-gram:{coordinator_id}:{remote_id}"));
    let suffix: String = digest[..12].iter().map(|b| format!("{b:02x}")).collect();
    PathBuf::from("/tmp").join(format!("herdr-gram-{suffix}.sock"))
}

/// The two legacy opt-ins as seen in this process's environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RelayEnvironment {
    pub(crate) peers: Option<String>,
    pub(crate) socket: Option<PathBuf>,
}

impl RelayEnvironment {
    pub(crate) fn from_process() -> Self {
        Self {
            peers: std::env::var(PEERS_ENV).ok(),
            socket: std::env::var_os(SOCKET_ENV).map(PathBuf::from),
        }
    }

    /// Legacy parsing: comma-separated, trimmed, empty names ignored. A set but
    /// empty variable is present with no peers, never the same as unset.
    fn peer_set(&self) -> Option<BTreeSet<String>> {
        Some(
            self.peers
                .as_deref()?
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect(),
        )
    }

    /// A set but empty variable is present and means "disabled".
    fn socket_path(&self) -> Option<PathBuf> {
        self.socket.clone()
    }
}

/// Outcome of the precedence table for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved<T> {
    pub(crate) effective: Option<T>,
    pub(crate) source: GramRelaySource,
    pub(crate) error: Option<GramRelayErrorCode>,
}

/// Config wins when equal; environment alone is honoured (deprecated); a
/// mismatch disables the role instead of choosing either side. Presence is
/// what counts: an explicitly empty value (`peers = []`,
/// `coordinator_machine_id = ""`, or a set but empty variable) is a value that
/// grants nothing, so it can only disable or conflict, never defer to the other
/// source.
pub(crate) fn resolve<T: PartialEq>(configured: Option<T>, environment: Option<T>) -> Resolved<T> {
    match (configured, environment) {
        (None, None) => Resolved {
            effective: None,
            source: GramRelaySource::None,
            error: None,
        },
        (Some(configured), None) => Resolved {
            effective: Some(configured),
            source: GramRelaySource::Config,
            error: None,
        },
        (None, Some(environment)) => Resolved {
            effective: Some(environment),
            source: GramRelaySource::Environment,
            error: None,
        },
        (Some(configured), Some(environment)) if configured == environment => Resolved {
            effective: Some(configured),
            source: GramRelaySource::Config,
            error: None,
        },
        (Some(_), Some(_)) => Resolved {
            effective: None,
            source: GramRelaySource::None,
            error: Some(GramRelayErrorCode::Conflict),
        },
    }
}

#[derive(Debug, Clone, Default)]
struct RoleState<T> {
    configured: Option<T>,
    environment: bool,
    effective: Option<T>,
    source: GramRelaySource,
    error: Option<GramRelayErrorCode>,
    message: Option<String>,
}

impl<T: Clone + PartialEq> RoleState<T> {
    fn resolved(configured: Option<T>, environment: Option<T>, role: &str, key: &str) -> Self {
        let has_environment = environment.is_some();
        let resolved = resolve(configured.clone(), environment);
        let message = match (&resolved.error, resolved.source) {
            (Some(_), _) => Some(format!(
                "{key} and the {role} environment variable differ; Gram relay disabled until they match or the variable is removed"
            )),
            (None, GramRelaySource::Environment) => Some(format!(
                "the {role} environment variable is deprecated; set {key} in config.toml"
            )),
            _ => None,
        };
        Self {
            configured,
            environment: has_environment,
            effective: resolved.effective,
            source: resolved.source,
            error: resolved.error,
            message,
        }
    }

    /// Keep the prior effective setting and report why the new one was refused.
    fn keep_after_invalid(&mut self, message: &str) {
        self.error = Some(GramRelayErrorCode::InvalidConfig);
        self.message = Some(format!("{message}; kept the previous effective setting"));
    }

    fn log_change(&self, previous: &Self, role: &str) {
        if self.error == Some(GramRelayErrorCode::Conflict) {
            error!(role, message = ?self.message, "Gram relay conflict");
        } else if self.source == GramRelaySource::Environment {
            warn!(role, message = ?self.message, "Gram relay deprecated environment opt-in");
        }
        if self.effective != previous.effective || self.source != previous.source {
            info!(role, source = ?self.source, enabled = self.effective.is_some(), "Gram relay setting applied");
        }
    }
}

impl RoleState<PathBuf> {
    /// The effective socket, unless it is the explicit "disabled" empty path.
    fn enabled_socket(&self) -> Option<&PathBuf> {
        self.effective
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty())
    }
}

#[derive(Debug, Clone, Default)]
struct RelayState {
    coordinator: RoleState<BTreeSet<String>>,
    configured_coordinator_machine_id: Option<String>,
    remote: RoleState<PathBuf>,
}

/// Live effective relay policy shared by the gateway supervisors, the
/// per-request coordinator check, and the remote forwarder.
#[derive(Debug, Default)]
pub(crate) struct GramRelayPolicy {
    state: RwLock<RelayState>,
}

impl GramRelayPolicy {
    /// Apply a successfully parsed `[gram_relay]` section. `own_machine_id`
    /// runs only when a coordinator pin is configured.
    pub(crate) fn apply(
        &self,
        config: &GramRelayConfig,
        environment: &RelayEnvironment,
        own_machine_id: impl FnOnce() -> String,
    ) {
        let configured_peers: Option<BTreeSet<String>> = config
            .peers
            .as_ref()
            .map(|peers| peers.iter().cloned().collect());
        // An explicitly empty pin is the "disabled" value, an empty path.
        let configured_socket = config.coordinator_machine_id.as_deref().map(|coordinator| {
            if coordinator.is_empty() {
                PathBuf::new()
            } else {
                reverse_socket_path(coordinator, &own_machine_id())
            }
        });
        let next = RelayState {
            coordinator: RoleState::resolved(
                configured_peers,
                environment.peer_set(),
                PEERS_ENV,
                "gram_relay.peers",
            ),
            configured_coordinator_machine_id: config.coordinator_machine_id.clone(),
            remote: RoleState::resolved(
                configured_socket,
                environment.socket_path(),
                SOCKET_ENV,
                "gram_relay.coordinator_machine_id",
            ),
        };
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        next.coordinator
            .log_change(&state.coordinator, "coordinator");
        next.remote.log_change(&state.remote, "remote");
        *state = next;
    }

    /// Record a refused `[gram_relay]` section without touching the effective
    /// setting, matching reload-config's keep-current behaviour.
    pub(crate) fn reject(&self, message: &str) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.coordinator.keep_after_invalid(message);
        state.remote.keep_after_invalid(message);
        error!(%message, "invalid [gram_relay] config; kept the previous effective setting");
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, RelayState> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Coordinator consent for one saved peer routing alias.
    #[cfg(unix)]
    pub(crate) fn allows(&self, alias: &str) -> bool {
        self.read()
            .coordinator
            .effective
            .as_ref()
            .is_some_and(|peers| peers.contains(alias))
    }

    /// Effective coordinator peer set, sorted.
    pub(crate) fn allowed_peers(&self) -> Vec<String> {
        self.read()
            .coordinator
            .effective
            .iter()
            .flatten()
            .cloned()
            .collect()
    }

    /// Remote reverse socket Gram calls are forwarded to, if enabled.
    #[cfg(unix)]
    pub(crate) fn remote_socket(&self) -> Option<PathBuf> {
        self.read().remote.enabled_socket().cloned()
    }

    pub(crate) fn coordinator_status(
        &self,
        peers: Vec<crate::api::schema::GramRelayPeerStatus>,
    ) -> GramRelayCoordinatorStatus {
        let state = self.read();
        let role = &state.coordinator;
        GramRelayCoordinatorStatus {
            configured: role
                .configured
                .as_ref()
                .map(|peers| peers.iter().cloned().collect()),
            environment: GramRelayEnvironment::from_present(role.environment),
            effective: role
                .effective
                .as_ref()
                .map(|peers| peers.iter().cloned().collect()),
            source: role.source,
            error: role.error,
            message: role.message.clone(),
            peers,
        }
    }

    pub(crate) fn remote_status(
        &self,
        accepting: impl FnOnce(&Path) -> bool,
    ) -> GramRelayRemoteStatus {
        let state = self.read();
        let role = &state.remote;
        GramRelayRemoteStatus {
            configured_coordinator_machine_id: state.configured_coordinator_machine_id.clone(),
            configured_socket: role
                .configured
                .as_ref()
                .map(|path| path.display().to_string()),
            environment: GramRelayEnvironment::from_present(role.environment),
            effective_socket: role.enabled_socket().map(|path| path.display().to_string()),
            source: role.source,
            error: role.error,
            message: role.message.clone(),
            accepting: role.enabled_socket().map(|path| accepting(path)),
        }
    }
}

static POLICY: LazyLock<GramRelayPolicy> = LazyLock::new(GramRelayPolicy::default);

/// The daemon's live policy. Before the first `apply` nothing is allowed.
pub(crate) fn policy() -> &'static GramRelayPolicy {
    &POLICY
}

/// Whether `gram.post` may address an agent of the saved peer with routing
/// `alias`: the live coordinator consent, so `agent.list` and the post check
/// agree and both follow a reload. No platform without the relay reaches one.
pub(crate) fn gram_reachable(alias: &str) -> bool {
    #[cfg(unix)]
    {
        policy().allows(alias)
    }
    #[cfg(not(unix))]
    {
        let _ = alias;
        false
    }
}

/// Apply this daemon's `[gram_relay]` config against its real environment.
pub(crate) fn apply_config(config: &GramRelayConfig) {
    policy().apply(
        config,
        &RelayEnvironment::from_process(),
        crate::persist::machine::get_or_create,
    );
}

// The consent accessors exist only on unix, where the relay runs.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const PEER_A: &str = "8195b6326f748f4da1945364a4e205b9";
    const PEER_B: &str = "55ed9db5d219bd8d78dd09d5b37f8e8e";
    const COORDINATOR: &str = "machine_f872cca4c7743d39c1fad1fa5a74a087";
    const OTHER_COORDINATOR: &str = "machine_3417306ea71c7044dcbb76ad128e7c68";
    const OWN: &str = "machine_cf86dc42c063eac7b83162361990ae59";

    /// An empty `peers` slice leaves the key unset.
    fn config(peers: &[&str], coordinator: Option<&str>) -> GramRelayConfig {
        GramRelayConfig {
            peers: (!peers.is_empty())
                .then(|| peers.iter().map(|peer| (*peer).to_owned()).collect()),
            coordinator_machine_id: coordinator.map(str::to_owned),
        }
    }

    fn env(peers: Option<&str>, socket: Option<PathBuf>) -> RelayEnvironment {
        RelayEnvironment {
            peers: peers.map(str::to_owned),
            socket,
        }
    }

    fn applied(config: &GramRelayConfig, environment: &RelayEnvironment) -> GramRelayPolicy {
        let policy = GramRelayPolicy::default();
        policy.apply(config, environment, || OWN.to_owned());
        policy
    }

    fn socket_for(coordinator: &str) -> PathBuf {
        reverse_socket_path(coordinator, OWN)
    }

    #[test]
    fn config_parses_and_rejects_malformed_identifiers() {
        let parsed: crate::config::Config = toml::from_str(&format!(
            "[gram_relay]\npeers = [\"{PEER_A}\", \"{PEER_B}\"]\ncoordinator_machine_id = \"{COORDINATOR}\"\n"
        ))
        .unwrap();
        assert_eq!(
            parsed.gram_relay,
            config(&[PEER_A, PEER_B], Some(COORDINATOR))
        );

        let default: crate::config::Config = toml::from_str("").unwrap();
        assert_eq!(default.gram_relay, GramRelayConfig::default());
        assert_eq!(default.gram_relay.peers, None);

        let explicit: crate::config::Config =
            toml::from_str("[gram_relay]\npeers = []\ncoordinator_machine_id = \"\"\n").unwrap();
        assert_eq!(explicit.gram_relay.peers, Some(Vec::new()));
        assert_eq!(
            explicit.gram_relay.coordinator_machine_id.as_deref(),
            Some("")
        );

        for bad in [
            "[gram_relay]\npeers = [\"jerrys-mac-studio\"]\n",
            "[gram_relay]\npeers = [\"8195B6326F748F4DA1945364A4E205B9\"]\n",
            "[gram_relay]\ncoordinator_machine_id = \"f872cca4c7743d39c1fad1fa5a74a087\"\n",
            "[gram_relay]\ncoordinator_machine_id = \"machine_f872cca4\"\n",
            "[gram_relay]\nreverse_socket = \"/tmp/x.sock\"\n",
        ] {
            let parsed = toml::from_str::<crate::config::Config>(bad);
            let unknown_key_ignored = parsed
                .as_ref()
                .is_ok_and(|config| config.gram_relay == GramRelayConfig::default());
            assert!(parsed.is_err() || unknown_key_ignored, "{bad}");
        }
    }

    #[test]
    fn explicit_empty_peers_revoke_even_when_the_environment_names_the_peer() {
        let environment = env(Some(PEER_A), None);
        let policy = applied(&config(&[PEER_A], None), &environment);
        assert!(policy.allows(PEER_A));

        let explicit_none = GramRelayConfig {
            peers: Some(Vec::new()),
            coordinator_machine_id: None,
        };
        policy.apply(&explicit_none, &environment, || OWN.into());
        assert!(
            !policy.allows(PEER_A),
            "peers = [] must not defer to the environment"
        );
        let status = policy.coordinator_status(Vec::new());
        assert_eq!(status.configured, Some(Vec::new()));
        assert_eq!(status.effective, None);
        assert_eq!(status.error, Some(GramRelayErrorCode::Conflict));

        let alone = applied(&explicit_none, &RelayEnvironment::default());
        assert!(!alone.allows(PEER_A));
        assert_eq!(
            alone.coordinator_status(Vec::new()).source,
            GramRelaySource::Config
        );
    }

    #[test]
    fn empty_environment_is_present_and_never_ignored() {
        let policy = applied(&config(&[PEER_A], None), &env(Some(""), None));
        assert!(!policy.allows(PEER_A));
        let status = policy.coordinator_status(Vec::new());
        assert_eq!(status.environment, GramRelayEnvironment::Present);
        assert_eq!(status.error, Some(GramRelayErrorCode::Conflict));

        let remote = applied(
            &config(&[], Some(COORDINATOR)),
            &env(None, Some(PathBuf::new())),
        );
        assert_eq!(remote.remote_socket(), None);
        let status = remote.remote_status(|_| true);
        assert_eq!(status.environment, GramRelayEnvironment::Present);
        assert_eq!(status.error, Some(GramRelayErrorCode::Conflict));
        assert_eq!(status.accepting, None);

        let env_only = applied(
            &GramRelayConfig::default(),
            &env(Some(" , "), Some(PathBuf::new())),
        );
        assert!(!env_only.allows(PEER_A));
        assert_eq!(env_only.remote_socket(), None);
        assert_eq!(env_only.remote_status(|_| true).effective_socket, None);
    }

    #[test]
    fn explicit_empty_coordinator_pin_disables_a_legacy_socket() {
        let legacy = env(None, Some(socket_for(COORDINATOR)));
        let policy = applied(&config(&[], Some(COORDINATOR)), &legacy);
        assert_eq!(policy.remote_socket(), Some(socket_for(COORDINATOR)));

        policy.apply(&config(&[], Some("")), &legacy, || {
            unreachable!("an empty pin derives no socket")
        });
        assert_eq!(policy.remote_socket(), None);
        let status = policy.remote_status(|_| true);
        assert_eq!(status.error, Some(GramRelayErrorCode::Conflict));
        assert_eq!(status.effective_socket, None);

        let alone = applied(&config(&[], Some("")), &RelayEnvironment::default());
        assert_eq!(alone.remote_socket(), None);
        assert_eq!(
            alone.remote_status(|_| true).source,
            GramRelaySource::Config
        );
    }

    #[test]
    fn precedence_table() {
        let cases = [
            (Some(1), None, Some(1), GramRelaySource::Config, None),
            (None, Some(2), Some(2), GramRelaySource::Environment, None),
            (Some(3), Some(3), Some(3), GramRelaySource::Config, None),
            (
                Some(4),
                Some(5),
                None,
                GramRelaySource::None,
                Some(GramRelayErrorCode::Conflict),
            ),
            (None, None, None, GramRelaySource::None, None),
        ];
        for (configured, environment, effective, source, error) in cases {
            assert_eq!(
                resolve(configured, environment),
                Resolved {
                    effective,
                    source,
                    error
                },
                "config={configured:?} env={environment:?}"
            );
        }
    }

    #[test]
    fn coordinator_conflict_disables_every_peer_and_reports_it() {
        let policy = applied(
            &config(&[PEER_A], None),
            &env(Some(&format!("{PEER_A},{PEER_B}")), None),
        );
        assert!(!policy.allows(PEER_A));
        assert!(!policy.allows(PEER_B));
        let status = policy.coordinator_status(Vec::new());
        assert_eq!(status.error, Some(GramRelayErrorCode::Conflict));
        assert_eq!(status.effective, None);
        assert_eq!(status.environment, GramRelayEnvironment::Present);
    }

    #[test]
    fn legacy_env_equal_to_config_reports_config_and_stays_enabled() {
        let policy = applied(
            &config(&[PEER_B, PEER_A], Some(COORDINATOR)),
            &env(
                Some(&format!(" {PEER_A}, ,{PEER_B}")),
                Some(socket_for(COORDINATOR)),
            ),
        );
        assert!(policy.allows(PEER_A) && policy.allows(PEER_B));
        let coordinator = policy.coordinator_status(Vec::new());
        assert_eq!(coordinator.source, GramRelaySource::Config);
        assert_eq!(coordinator.error, None);
        let remote = policy.remote_status(|_| false);
        assert_eq!(remote.source, GramRelaySource::Config);
        assert_eq!(remote.error, None);
        assert_eq!(policy.remote_socket(), Some(socket_for(COORDINATOR)));
    }

    #[test]
    fn environment_only_is_honoured_with_a_deprecation() {
        let policy = applied(
            &GramRelayConfig::default(),
            &env(Some(PEER_A), Some("/tmp/legacy.sock".into())),
        );
        assert!(policy.allows(PEER_A));
        assert_eq!(
            policy.remote_socket(),
            Some(PathBuf::from("/tmp/legacy.sock"))
        );
        let status = policy.coordinator_status(Vec::new());
        assert_eq!(status.source, GramRelaySource::Environment);
        assert!(status.message.unwrap().contains("deprecated"));
    }

    #[test]
    fn default_config_grants_nothing() {
        let policy = applied(&GramRelayConfig::default(), &RelayEnvironment::default());
        assert!(!policy.allows(PEER_A));
        assert_eq!(policy.remote_socket(), None);
        assert_eq!(
            policy.remote_status(|_| true).accepting,
            None,
            "no socket is probed while disabled"
        );
    }

    #[test]
    fn remote_socket_follows_config_changes_and_conflicts() {
        let policy = applied(
            &config(&[], Some(COORDINATOR)),
            &RelayEnvironment::default(),
        );
        assert_eq!(policy.remote_socket(), Some(socket_for(COORDINATOR)));

        policy.apply(
            &config(&[], Some(OTHER_COORDINATOR)),
            &RelayEnvironment::default(),
            || OWN.into(),
        );
        assert_eq!(policy.remote_socket(), Some(socket_for(OTHER_COORDINATOR)));

        policy.apply(
            &config(&[], Some(OTHER_COORDINATOR)),
            &env(None, Some(socket_for(COORDINATOR))),
            || OWN.into(),
        );
        assert_eq!(policy.remote_socket(), None);
        assert_eq!(
            policy.remote_status(|_| true).error,
            Some(GramRelayErrorCode::Conflict)
        );

        policy.apply(
            &GramRelayConfig::default(),
            &RelayEnvironment::default(),
            || OWN.into(),
        );
        assert_eq!(policy.remote_socket(), None);
    }

    #[test]
    fn rejected_section_keeps_the_previous_effective_setting() {
        let policy = applied(
            &config(&[PEER_A], Some(COORDINATOR)),
            &RelayEnvironment::default(),
        );
        policy.reject("invalid gram relay config: bad machine id");
        assert!(policy.allows(PEER_A));
        assert_eq!(policy.remote_socket(), Some(socket_for(COORDINATOR)));
        let status = policy.remote_status(|_| false);
        assert_eq!(status.error, Some(GramRelayErrorCode::InvalidConfig));
        assert!(status.message.unwrap().contains("bad machine id"));
    }
}
