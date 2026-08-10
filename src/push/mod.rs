//! Remote push (APNs) delivery of agent-state transitions to registered devices.
//!
//! Design: Herdr does no in-process outbound networking (see `src/update.rs`,
//! which shells out to curl). This module keeps that property — the APNs auth
//! JWT is signed in-process with `p256` (see `jwt`), and each alert is delivered
//! by spawning `curl --http2` (see `apns`). Delivery is best-effort and always
//! runs off the app loop: failures are logged via `tracing`, never propagated.
//!
//! Secrets: the `.p8` key is read from `push.key_path` at send time only; its
//! contents are never persisted or logged. Only device tokens and per-device
//! preferences live in `devices.json`.

mod apns;
mod jwt;

use std::collections::HashSet;

use crate::config::PushConfig;
use crate::persist::devices::RegisteredDevice;

use self::apns::DeliveryOutcome;

/// Which agent transition triggered a push, used to match per-device prefs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushKind {
    /// Agent is blocked / needs input or attention.
    NeedsInput,
    /// Agent finished a turn.
    Finished,
    /// Agent pane process exited.
    Died,
    /// An agent sent the owner a gram message.
    Gram,
}

/// One agent-state transition to deliver as an APNs alert. `pane_id` and
/// `workspace_id` are the public API ids so the mobile client can deep-link.
#[derive(Debug, Clone)]
pub(crate) struct PushNotification {
    pub title: String,
    pub body: String,
    pub pane_id: String,
    pub workspace_id: String,
    pub kind: PushKind,
}

/// True when the push config is complete enough to attempt delivery: the master
/// switch is on and every required identifier is present and non-blank. A blank
/// or whitespace-only value is treated as unset (it would only produce broken
/// requests).
pub(crate) fn enabled(cfg: &PushConfig) -> bool {
    cfg.enabled
        && is_present(&cfg.key_path)
        && is_present(&cfg.key_id)
        && is_present(&cfg.team_id)
        && is_present(&cfg.topic)
}

fn is_present(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn device_wants(device: &RegisteredDevice, kind: PushKind) -> bool {
    match kind {
        PushKind::NeedsInput => device.notify_needs_input,
        PushKind::Finished => device.notify_finishes,
        PushKind::Died => device.notify_dies,
        PushKind::Gram => device.notify_gram,
    }
}

fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Deliver a batch of agent transitions to every registered device that opted
/// into the matching notification kind. Intended to be called on a detached
/// thread: it reads the device store, mints/reuses one JWT, sends each alert via
/// curl, and prunes any tokens APNs reports as permanently invalid.
///
/// Best-effort throughout: every failure is logged and swallowed so a slow or
/// failing push never affects the app loop.
pub(crate) fn deliver(cfg: PushConfig, notifications: Vec<PushNotification>) {
    if notifications.is_empty() || !enabled(&cfg) {
        return;
    }
    // `enabled` guarantees these are all `Some`.
    let (Some(key_path), Some(key_id), Some(team_id), Some(topic)) = (
        cfg.key_path.as_deref(),
        cfg.key_id.as_deref(),
        cfg.team_id.as_deref(),
        cfg.topic.as_deref(),
    ) else {
        return;
    };

    let devices = crate::persist::devices::load();
    if devices.is_empty() {
        return;
    }

    // `key_path` is host config, not a secret: expand `~` (the form the docs and
    // config example use) and log the resolved path on failure.
    let resolved_key_path = crate::worktree::expand_tilde_path(key_path);
    let pem = match std::fs::read_to_string(&resolved_key_path) {
        Ok(pem) => pem,
        Err(err) => {
            tracing::warn!(
                path = %resolved_key_path.display(),
                error = %err,
                "failed to read APNs signing key; skipping push"
            );
            return;
        }
    };

    let mut jwt = match jwt::auth_token(&pem, key_id, team_id, unix_secs_now()) {
        Ok(jwt) => jwt,
        Err(err) => {
            tracing::warn!(error = %err, "failed to build APNs auth token; skipping push");
            return;
        }
    };
    // A 403 (bad token / clock skew) invalidates the cached JWT; re-mint it once
    // and retry. If it 403s again the credentials are wrong, so we stop rather
    // than hammer APNs with the whole batch.
    let mut reminted = false;

    let mut tokens_to_prune: HashSet<String> = HashSet::new();
    'batch: for notification in &notifications {
        let payload = apns::payload_body(notification);
        for device in &devices {
            // A token already flagged for pruning gets no further sends.
            if tokens_to_prune.contains(&device.device_token) {
                continue;
            }
            if !device_wants(device, notification.kind) {
                continue;
            }
            let mut outcome =
                apns::deliver_one(&device.device_token, &jwt, topic, cfg.sandbox, &payload);
            if outcome == DeliveryOutcome::AuthExpired && !reminted {
                reminted = true;
                jwt::clear_cache();
                match jwt::auth_token(&pem, key_id, team_id, unix_secs_now()) {
                    Ok(fresh) => {
                        jwt = fresh;
                        outcome = apns::deliver_one(
                            &device.device_token,
                            &jwt,
                            topic,
                            cfg.sandbox,
                            &payload,
                        );
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to re-mint APNs auth token after 403; aborting push batch");
                        break 'batch;
                    }
                }
            }
            match outcome {
                DeliveryOutcome::Delivered => {}
                DeliveryOutcome::PruneToken => {
                    tokens_to_prune.insert(device.device_token.clone());
                }
                DeliveryOutcome::AuthExpired => {
                    // Still 403 after re-mint (or a repeat): credentials are
                    // wrong, not transient. Stop the batch (deliver_one already
                    // logged the status and reason).
                    tracing::warn!(
                        "apns auth token rejected (403) after re-mint; aborting push batch"
                    );
                    break 'batch;
                }
                DeliveryOutcome::Failed => {
                    // deliver_one already logged the status and APNs reason.
                }
            }
        }
    }

    for token in tokens_to_prune {
        match crate::persist::devices::remove_token(&token) {
            Ok(true) => tracing::info!("pruned an unregistered APNs device token"),
            Ok(false) => {}
            Err(err) => tracing::warn!(error = %err, "failed to prune APNs device token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, fill: bool) -> PushConfig {
        PushConfig {
            enabled,
            key_path: fill.then(|| "/tmp/AuthKey.p8".to_string()),
            key_id: fill.then(|| "ABC123DEFG".to_string()),
            team_id: fill.then(|| "TEAM123456".to_string()),
            topic: fill.then(|| "com.example.herdr".to_string()),
            sandbox: false,
        }
    }

    fn device(needs_input: bool, dies: bool, finishes: bool) -> RegisteredDevice {
        RegisteredDevice {
            device_token: "token".to_string(),
            platform: "ios".to_string(),
            notify_needs_input: needs_input,
            notify_dies: dies,
            notify_finishes: finishes,
            notify_gram: false,
            registered_unix_ms: 0,
        }
    }

    #[test]
    fn enabled_requires_switch_and_all_identifiers() {
        assert!(enabled(&cfg(true, true)));
        assert!(!enabled(&cfg(false, true)));
        assert!(!enabled(&cfg(true, false)));

        // A blank / whitespace-only identifier counts as unset.
        let mut blank = cfg(true, true);
        blank.topic = Some("   ".to_string());
        assert!(!enabled(&blank));
        let mut empty = cfg(true, true);
        empty.key_id = Some(String::new());
        assert!(!enabled(&empty));
    }

    #[test]
    fn device_wants_matches_kind_to_pref() {
        let d = device(true, false, false);
        assert!(device_wants(&d, PushKind::NeedsInput));
        assert!(!device_wants(&d, PushKind::Died));
        assert!(!device_wants(&d, PushKind::Finished));

        let d = device(false, true, true);
        assert!(device_wants(&d, PushKind::Died));
        assert!(device_wants(&d, PushKind::Finished));
        assert!(!device_wants(&d, PushKind::NeedsInput));
        // notify_gram is independent of the agent-transition prefs.
        assert!(!device_wants(&d, PushKind::Gram));
    }

    #[test]
    fn device_wants_gram_follows_notify_gram() {
        let mut d = device(false, false, false);
        assert!(!device_wants(&d, PushKind::Gram));
        d.notify_gram = true;
        assert!(device_wants(&d, PushKind::Gram));
    }
}
