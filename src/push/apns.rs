//! APNs HTTP/2 delivery for one alert to one device token.
//!
//! Delivery shells out to `curl --http2` (mirroring `herdr update`) so Herdr
//! adds no in-process HTTP/TLS stack. The auth JWT (team-wide, ~60 min) and the
//! JSON payload are secrets-adjacent, so they are NOT placed on curl's argv
//! (which is world-readable via `/proc/<pid>/cmdline` to any same-user process,
//! including agent panes Herdr spawns). Instead they are passed through a curl
//! config document fed on stdin via `--config -`. The config/argv builders and
//! the status classifier are pure functions, unit-tested without spawning curl.
//!
//! Follow-up (not in this change): set `apns-collapse-id` to coalesce repeated
//! alerts for the same pane.

use std::io::Write;
use std::process::Stdio;

use super::{PushKind, PushNotification};

const PROD_HOST: &str = "https://api.push.apple.com";
const SANDBOX_HOST: &str = "https://api.sandbox.push.apple.com";

/// curl writes the numeric HTTP status after the (small) APNs JSON body, on its
/// own line, so the trailing line of stdout is the status and the line(s) before
/// it are the body used to surface the APNs `reason`.
const HTTP_CODE_WRITEOUT: &str = "\n%{http_code}";

/// Outcome of a single delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeliveryOutcome {
    Delivered,
    /// APNs reported the token as permanently unregistered (410) — prune it.
    PruneToken,
    /// APNs rejected the auth token (403: InvalidProviderToken / clock skew /
    /// wrong key id or team id). The cached JWT should be cleared and re-minted.
    AuthExpired,
    /// Transient or unexpected failure — keep the token, log, and move on.
    Failed,
}

/// Map a Herdr agent transition to the APNs alert body. `pane_id`/`workspace_id`
/// are the public API ids so the mobile client can deep-link.
pub(super) fn payload_body(notification: &PushNotification) -> String {
    let mut payload = serde_json::json!({
        "aps": {
            "alert": {
                "title": notification.title,
                "body": notification.body,
            },
            "sound": "default",
        },
        "pane_id": notification.pane_id,
        "workspace_id": notification.workspace_id,
    });
    // A gram alert deep-links to the app's Gram page, not a pane. The `gram`
    // marker lets the client branch on tap; `pane_id`/`workspace_id` are empty
    // for these and must be ignored when `gram` is present.
    if notification.kind == PushKind::Gram {
        payload["gram"] = serde_json::Value::Bool(true);
    }
    payload.to_string()
}

fn device_url(sandbox: bool, device_token: &str) -> String {
    let host = if sandbox { SANDBOX_HOST } else { PROD_HOST };
    format!("{host}/3/device/{device_token}")
}

/// The non-sensitive curl argv. The JWT, headers, url, and payload are delivered
/// out-of-band via the stdin config (`--config -`) so no secret lands on argv.
fn build_curl_argv() -> Vec<String> {
    vec![
        "--http2".to_string(),
        "-s".to_string(),
        "--connect-timeout".to_string(),
        "10".to_string(),
        "--max-time".to_string(),
        "20".to_string(),
        "-w".to_string(),
        HTTP_CODE_WRITEOUT.to_string(),
        "--config".to_string(),
        "-".to_string(),
    ]
}

/// Escape a value for a curl config double-quoted string. curl un-escapes `\\`
/// and `\"` inside quotes, so backslashes MUST be escaped before double-quotes
/// (order matters — escaping quotes first would then double-escape the added
/// backslashes). The JSON payload contains `"`, so this has to be exact.
fn quote_config_value(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Build the curl config document (one directive per line) that carries the
/// url, method, headers (including the bearer JWT), and JSON body. Pure: no I/O,
/// so the escaping and header set can be asserted directly.
pub(super) fn build_curl_config(url: &str, jwt: &str, topic: &str, payload: &str) -> String {
    let mut config = String::new();
    config.push_str(&format!("url = {}\n", quote_config_value(url)));
    config.push_str("request = \"POST\"\n");
    config.push_str(&format!(
        "header = {}\n",
        quote_config_value(&format!("authorization: bearer {jwt}"))
    ));
    config.push_str(&format!(
        "header = {}\n",
        quote_config_value(&format!("apns-topic: {topic}"))
    ));
    config.push_str("header = \"apns-push-type: alert\"\n");
    config.push_str("header = \"apns-priority: 10\"\n");
    config.push_str(&format!("data = {}\n", quote_config_value(payload)));
    config
}

/// Split curl's combined stdout into `(body, status)`. `stdout` is
/// `<body>\n<http_code>`.
fn split_body_status(stdout: &str) -> (&str, &str) {
    let stdout = stdout.trim_end();
    match stdout.rsplit_once('\n') {
        Some((body, status)) => (body, status.trim()),
        None => ("", stdout.trim()),
    }
}

/// Extract the APNs `reason` string from a `{"reason":"..."}` error body.
fn reason_from_body(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
}

fn classify_status(status: &str) -> DeliveryOutcome {
    match status {
        "200" => DeliveryOutcome::Delivered,
        // 410 Unregistered is Apple's one documented permanent "token is dead"
        // signal. A 400 BadDeviceToken can also mean the token was minted for
        // the OTHER environment (prod vs sandbox), so pruning on it would delete
        // every token when `push.sandbox` is misconfigured — treat it as Failed.
        "410" => DeliveryOutcome::PruneToken,
        "403" => DeliveryOutcome::AuthExpired,
        _ => DeliveryOutcome::Failed,
    }
}

/// Classify curl's combined output. Test-only convenience that mirrors what
/// `deliver_one` does (split then classify) so the end-to-end parsing is
/// unit-tested; production splits once to also surface the reason.
#[cfg(test)]
fn classify(stdout: &str) -> DeliveryOutcome {
    let (_, status) = split_body_status(stdout);
    classify_status(status)
}

/// Deliver one alert to one device token by spawning curl and feeding the
/// sensitive directives on stdin. Best-effort: any spawn/IO failure is logged
/// and treated as a transient failure (token kept).
pub(super) fn deliver_one(
    device_token: &str,
    jwt: &str,
    topic: &str,
    sandbox: bool,
    payload: &str,
) -> DeliveryOutcome {
    let url = device_url(sandbox, device_token);
    let config = build_curl_config(&url, jwt, topic, payload);

    let mut child = match crate::noninteractive_process::curl_command()
        .args(build_curl_argv())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!(error = %err, "apns curl failed to spawn");
            return DeliveryOutcome::Failed;
        }
    };

    // Write the config to stdin and close it (EOF) before draining stdout. The
    // config is tiny and curl reads it fully before issuing the request, so this
    // cannot deadlock.
    {
        let Some(mut stdin) = child.stdin.take() else {
            tracing::warn!("apns curl child stdin was unavailable");
            let _ = child.kill();
            let _ = child.wait();
            return DeliveryOutcome::Failed;
        };
        if let Err(err) = stdin.write_all(config.as_bytes()) {
            tracing::warn!(error = %err, "failed to write curl config to stdin");
            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            return DeliveryOutcome::Failed;
        }
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(err) => {
            tracing::warn!(error = %err, "failed to collect curl output");
            return DeliveryOutcome::Failed;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, status) = split_body_status(&stdout);
    let outcome = classify_status(status);
    if matches!(
        outcome,
        DeliveryOutcome::Failed | DeliveryOutcome::AuthExpired
    ) {
        // Status and APNs reason are diagnostics, not secrets.
        tracing::warn!(
            status = %status,
            reason = %reason_from_body(body).unwrap_or_else(|| "unknown".to_string()),
            "apns push delivery rejected"
        );
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::super::PushKind;
    use super::*;

    fn sample_notification() -> PushNotification {
        PushNotification {
            title: "claude finished".to_string(),
            body: "herdr · 1".to_string(),
            pane_id: "w1-1".to_string(),
            workspace_id: "w_1".to_string(),
            kind: PushKind::Finished,
        }
    }

    #[test]
    fn payload_body_carries_alert_sound_and_public_ids() {
        let payload: serde_json::Value =
            serde_json::from_str(&payload_body(&sample_notification())).unwrap();
        assert_eq!(payload["aps"]["alert"]["title"], "claude finished");
        assert_eq!(payload["aps"]["alert"]["body"], "herdr · 1");
        assert_eq!(payload["aps"]["sound"], "default");
        assert_eq!(payload["pane_id"], "w1-1");
        assert_eq!(payload["workspace_id"], "w_1");
        // Agent-transition alerts carry no gram marker.
        assert!(payload.get("gram").is_none());
    }

    #[test]
    fn payload_body_marks_gram_alerts() {
        let mut notification = sample_notification();
        notification.kind = PushKind::Gram;
        notification.pane_id = String::new();
        notification.workspace_id = String::new();
        let payload: serde_json::Value =
            serde_json::from_str(&payload_body(&notification)).unwrap();
        assert_eq!(payload["gram"], serde_json::Value::Bool(true));
    }

    #[test]
    fn quote_config_value_escapes_backslash_before_quote() {
        // Backslash must be escaped first; escaping the quote first would then
        // double-escape the inserted backslash.
        assert_eq!(quote_config_value(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn curl_config_carries_secrets_and_argv_does_not() {
        let payload = payload_body(&sample_notification());
        let url = device_url(false, "dev-token");
        let config = build_curl_config(&url, "jwt-abc", "com.example.herdr", &payload);

        assert!(config.contains(&format!("url = \"{url}\"")));
        assert!(config.contains("request = \"POST\""));
        assert!(config.contains("header = \"authorization: bearer jwt-abc\""));
        assert!(config.contains("header = \"apns-topic: com.example.herdr\""));
        assert!(config.contains("header = \"apns-push-type: alert\""));
        assert!(config.contains("header = \"apns-priority: 10\""));
        assert!(config.contains("data = "));
        // The JSON payload's double-quotes are escaped for the config format.
        assert!(config.contains("\\\""));

        // The secret JWT and the payload must never appear on the argv.
        let argv = build_curl_argv();
        assert!(argv.iter().all(|arg| !arg.contains("jwt-abc")));
        assert!(!argv.contains(&payload));
        assert!(argv.contains(&"--config".to_string()));
        assert!(argv.contains(&"-".to_string()));
        assert!(argv.contains(&"--http2".to_string()));
        assert_eq!(
            argv[argv.iter().position(|arg| arg == "-w").unwrap() + 1],
            HTTP_CODE_WRITEOUT
        );
    }

    #[test]
    fn device_url_selects_host_by_environment() {
        assert_eq!(
            device_url(false, "tok"),
            "https://api.push.apple.com/3/device/tok"
        );
        assert_eq!(
            device_url(true, "tok"),
            "https://api.sandbox.push.apple.com/3/device/tok"
        );
    }

    #[test]
    fn classify_prunes_only_on_410_and_flags_403() {
        assert_eq!(classify("\n200"), DeliveryOutcome::Delivered);
        assert_eq!(
            classify("{\"reason\":\"Unregistered\"}\n410"),
            DeliveryOutcome::PruneToken
        );
        assert_eq!(
            classify("{\"reason\":\"InvalidProviderToken\"}\n403"),
            DeliveryOutcome::AuthExpired
        );
        // 400 BadDeviceToken is NOT a prune: a prod token hitting the sandbox
        // host (or vice-versa) returns this, and pruning would wipe every token.
        assert_eq!(
            classify("{\"reason\":\"BadDeviceToken\"}\n400"),
            DeliveryOutcome::Failed
        );
        assert_eq!(classify("\n500"), DeliveryOutcome::Failed);
        assert_eq!(classify(""), DeliveryOutcome::Failed);
    }

    #[test]
    fn reason_from_body_extracts_apns_reason() {
        assert_eq!(
            reason_from_body("{\"reason\":\"BadDeviceToken\"}").as_deref(),
            Some("BadDeviceToken")
        );
        assert_eq!(reason_from_body("").as_deref(), None);
        assert_eq!(reason_from_body("not json").as_deref(), None);
    }
}
