//! Live provider account-usage fetch (Phase 1).
//!
//! Runs OFF the app loop on a background OS thread; the result is delivered as
//! `AppEvent::UsageRefreshed` and read from a per-account TTL cache by the
//! synchronous `accounts.list` handler, which always falls back to the local
//! read while a fetch is in flight. Nothing here is ever called on the app loop.
//!
//! SECURITY (non-negotiable): the account access token is passed to `curl`
//! ONLY through a mode-0600 config file (`curl -K <file>`), never in argv (argv
//! is visible in `ps`). That file — and the response body file — are removed as
//! soon as the call returns (a `Drop` guard removes them even on early return).
//! Only parsed usage NUMBERS ever leave this module; a token is never logged or
//! returned. A Codex token refresh writes the rotated tokens back to THIS
//! account's own `auth.json` and nowhere else.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::api::schema::{AccountUsage, UsageWindow};

/// Codex quota moves fast (5h window); refresh the cache often.
const USAGE_CODEX_TTL: Duration = Duration::from_secs(60);
/// Claude's endpoint 429s more readily, so cache its result longer.
const USAGE_CLAUDE_TTL: Duration = Duration::from_secs(300);
/// Hard per-request bound so a hung network never strands the fetch thread.
const CURL_MAX_TIME_SECS: u64 = 4;

const CODEX_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
/// Codex CLI OAuth client id (mirrors `codex-usage-api`'s reference flow).
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CLAUDE_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
const USAGE_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// A cached live-usage result for one account, held on `App`.
pub(crate) struct CachedUsage {
    pub(crate) fetched_at: Instant,
    pub(crate) usage: AccountUsage,
    pub(crate) active: bool,
}

/// Per-kind cache-staleness bound (Codex 60s, Claude 300s).
pub(crate) fn usage_ttl(kind: &str) -> Duration {
    match kind {
        "claude" => USAGE_CLAUDE_TTL,
        _ => USAGE_CODEX_TTL,
    }
}

/// Whether a kind has a live-usage provider fetch at all (Codex / Claude only).
pub(crate) fn kind_supports_live_usage(kind: &str) -> bool {
    matches!(kind, "codex" | "claude")
}

/// Synchronous entry, called ONLY from a background thread (it blocks on
/// `curl`). Returns `(usage_with_source_live, active)` or `None` on any
/// failure/timeout so the caller can fall back to the local read.
pub(crate) fn fetch_live_usage(kind: &str, config_dir: &str) -> Option<(AccountUsage, bool)> {
    match kind {
        "codex" => fetch_codex_live(config_dir),
        "claude" => fetch_claude_live(config_dir),
        // Kimi and any unknown kind: no live provider endpoint.
        _ => None,
    }
}

// --- Codex --------------------------------------------------------------------

fn fetch_codex_live(config_dir: &str) -> Option<(AccountUsage, bool)> {
    let auth_path = Path::new(config_dir).join("auth.json");
    let auth: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&auth_path).ok()?).ok()?;
    let tokens = auth.get("tokens")?;
    let access_token = tokens
        .get("access_token")
        .and_then(|v| v.as_str())?
        .to_string();
    let account_id = tokens
        .get("account_id")
        .and_then(|v| v.as_str())?
        .to_string();

    // Attempt with the on-disk access token first.
    let (code, body) = codex_usage_request(&access_token, &account_id)?;
    if is_success(code) {
        return body.as_ref().and_then(parse_codex_usage);
    }

    // An expired/invalid token (401/403): refresh once, persist, retry.
    if !matches!(code, 401 | 403) {
        return None;
    }
    let refresh_token = tokens.get("refresh_token").and_then(|v| v.as_str())?;
    let refreshed = codex_refresh_token(refresh_token)?;
    let new_access = refreshed
        .get("access_token")
        .and_then(|v| v.as_str())?
        .to_string();
    persist_codex_tokens(&auth_path, &auth, &refreshed);

    let (code, body) = codex_usage_request(&new_access, &account_id)?;
    if is_success(code) {
        return body.as_ref().and_then(parse_codex_usage);
    }
    None
}

fn codex_usage_request(
    access_token: &str,
    account_id: &str,
) -> Option<(u16, Option<serde_json::Value>)> {
    if !config_safe(access_token) || !config_safe(account_id) {
        return None;
    }
    let config_lines = [
        format!("header = \"Authorization: Bearer {access_token}\""),
        format!("header = \"chatgpt-account-id: {account_id}\""),
        "header = \"Accept: application/json\"".to_string(),
    ];
    curl_request(CODEX_USAGE_URL, &config_lines)
}

/// Exchange a refresh token for a fresh access token (mirrors the
/// `codex-usage-api` reference: form POST to the OAuth token endpoint). The
/// refresh token goes in the `-K` config body (not argv); it is form-encoded so
/// it can never break out of the config line.
fn codex_refresh_token(refresh_token: &str) -> Option<serde_json::Value> {
    let body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={CODEX_CLIENT_ID}",
        form_encode(refresh_token)
    );
    let config_lines = [
        "header = \"Content-Type: application/x-www-form-urlencoded\"".to_string(),
        format!("data = \"{body}\""),
    ];
    let (code, response) = curl_request(CODEX_TOKEN_URL, &config_lines)?;
    if !is_success(code) {
        return None;
    }
    let response = response?;
    response
        .get("access_token")
        .and_then(|v| v.as_str())
        .is_some()
        .then_some(response)
}

/// Persist a Codex token refresh back to THIS account's own `auth.json` and
/// nowhere else (security invariant). Best-effort: a write failure only logs and
/// never fails the usage fetch. Rewrites only the token fields the refresh
/// returned, leaving every other field intact, via a private temp file renamed
/// into place (same directory, so the rename is atomic on one filesystem).
fn persist_codex_tokens(
    auth_path: &Path,
    original: &serde_json::Value,
    refreshed: &serde_json::Value,
) {
    let mut updated = original.clone();
    let Some(tokens) = updated.get_mut("tokens").and_then(|t| t.as_object_mut()) else {
        return;
    };
    let mut changed = false;
    for key in ["access_token", "refresh_token", "id_token"] {
        if let Some(value) = refreshed.get(key).and_then(|v| v.as_str()) {
            tokens.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
            changed = true;
        }
    }
    if !changed {
        return;
    }
    let Ok(serialized) = serde_json::to_string_pretty(&updated) else {
        return;
    };
    let Some(dir) = auth_path.parent() else {
        return;
    };
    let tmp_path = dir.join(format!(".auth.json.herdr-usage-{}.tmp", unique_suffix()));
    let tmp = ScopedPath(tmp_path);
    let write_result = (|| -> std::io::Result<()> {
        let mut file = create_private_file(&tmp.0)?;
        file.write_all(serialized.as_bytes())?;
        file.sync_all()
    })();
    if write_result.is_err() {
        tracing::warn!("usage fetch: failed to write refreshed codex tokens");
        return;
    }
    if let Err(err) = std::fs::rename(&tmp.0, auth_path) {
        tracing::warn!(error = %err, "usage fetch: failed to replace codex auth.json");
        return;
    }
    // Renamed away: nothing for the guard to remove.
    std::mem::forget(tmp);
}

/// Parse a Codex `wham/usage` body into `(usage, active)`. Pure. `None` for a
/// body without a `rate_limit` object (an error / rate-limited / garbage body).
fn parse_codex_usage(body: &serde_json::Value) -> Option<(AccountUsage, bool)> {
    let rate_limit = body.get("rate_limit")?;
    let primary = rate_limit.get("primary_window");
    let secondary = rate_limit.get("secondary_window");
    let primary_used = window_used_percent(primary, "used_percent");
    let secondary_used = window_used_percent(secondary, "used_percent");
    let plan = body
        .get("plan_type")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let limit_reached = rate_limit
        .get("limit_reached")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || body
            .get("rate_limit_reached_type")
            .is_some_and(|value| !value.is_null());
    let exhausted = limit_reached
        || primary_used.is_some_and(|used| used >= 100.0)
        || secondary_used.is_some_and(|used| used >= 100.0);

    let mut windows = Vec::new();
    if is_object(primary) {
        windows.push(UsageWindow {
            label: "5h".to_string(),
            used_percent: primary_used,
            resets_at: window_resets_at(primary, &["reset_at", "resets_at"]),
            status: Some(window_status(primary_used, limit_reached)),
        });
    }
    if is_object(secondary) {
        windows.push(UsageWindow {
            label: "weekly".to_string(),
            used_percent: secondary_used,
            resets_at: window_resets_at(secondary, &["reset_at", "resets_at"]),
            status: Some(window_status(secondary_used, false)),
        });
    }
    // A rate_limit object carrying neither a window nor a plan is not usage.
    if windows.is_empty() && plan.is_none() {
        return None;
    }

    let mut usage = AccountUsage {
        windows,
        source: Some("live".to_string()),
        plan,
        ..Default::default()
    };
    usage.backfill_flat_fields();
    Some((usage, !exhausted))
}

// --- Claude -------------------------------------------------------------------

fn fetch_claude_live(config_dir: &str) -> Option<(AccountUsage, bool)> {
    let creds_path = Path::new(config_dir).join(".credentials.json");
    let creds: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&creds_path).ok()?).ok()?;
    let oauth = creds.get("claudeAiOauth")?;
    let access_token = oauth.get("accessToken").and_then(|v| v.as_str())?;
    if !config_safe(access_token) {
        return None;
    }

    let config_lines = [
        format!("header = \"Authorization: Bearer {access_token}\""),
        "header = \"anthropic-beta: oauth-2025-04-20\"".to_string(),
        "header = \"Accept: application/json\"".to_string(),
    ];
    let (code, body) = curl_request(CLAUDE_USAGE_URL, &config_lines)?;
    // A 429 (or any non-2xx) means back off and fall back to the local read.
    if !is_success(code) {
        return None;
    }
    let (mut usage, active) = parse_claude_usage(&body?)?;
    // The usage endpoint omits plan/tier; enrich from the same on-disk
    // credentials so a live result never regresses the locally-shown plan.
    // Only the two label strings are read — never the token.
    usage.plan = oauth
        .get("subscriptionType")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    usage.tier = oauth
        .get("rateLimitTier")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some((usage, active))
}

/// Parse a Claude `/api/oauth/usage` body into `(usage, active)`. Pure. Maps the
/// `five_hour` bucket to a "5h" window and `seven_day` to a "weekly" window,
/// each `utilization` -> used_percent. `None` for a body with neither bucket
/// (an error / 429 / garbage body).
fn parse_claude_usage(body: &serde_json::Value) -> Option<(AccountUsage, bool)> {
    let five_hour = body.get("five_hour");
    let seven_day = body.get("seven_day");
    let five_used = window_used_percent(five_hour, "utilization");
    let seven_used = window_used_percent(seven_day, "utilization");

    let mut windows = Vec::new();
    if is_object(five_hour) {
        windows.push(UsageWindow {
            label: "5h".to_string(),
            used_percent: five_used,
            resets_at: window_resets_at(five_hour, &["resets_at"]),
            status: Some(window_status(five_used, false)),
        });
    }
    if is_object(seven_day) {
        windows.push(UsageWindow {
            label: "weekly".to_string(),
            used_percent: seven_used,
            resets_at: window_resets_at(seven_day, &["resets_at"]),
            status: Some(window_status(seven_used, false)),
        });
    }
    if windows.is_empty() {
        return None;
    }

    let exhausted =
        five_used.is_some_and(|used| used >= 100.0) || seven_used.is_some_and(|used| used >= 100.0);
    let mut usage = AccountUsage {
        windows,
        source: Some("live".to_string()),
        ..Default::default()
    };
    usage.backfill_flat_fields();
    Some((usage, !exhausted))
}

// --- shared parse helpers -----------------------------------------------------

fn is_object(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(serde_json::Value::is_object)
}

fn window_used_percent(window: Option<&serde_json::Value>, key: &str) -> Option<f32> {
    let used = window?.get(key)?.as_f64()?;
    Some(used.clamp(0.0, 100.0) as f32)
}

/// The first present reset marker among `keys`, rendered as a string (epoch
/// numbers stringify, matching the local reader's `resets_at`).
fn window_resets_at(window: Option<&serde_json::Value>, keys: &[&str]) -> Option<String> {
    let window = window?;
    keys.iter()
        .find_map(|key| window.get(*key))
        .and_then(json_scalar_to_string)
}

fn json_scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn window_status(used_percent: Option<f32>, reached: bool) -> String {
    if reached || used_percent.is_some_and(|used| used >= 100.0) {
        "exhausted".to_string()
    } else {
        "ok".to_string()
    }
}

fn is_success(code: u16) -> bool {
    (200..300).contains(&code)
}

// --- curl plumbing (token never in argv) -------------------------------------

/// A filesystem path removed when dropped, so a token-bearing config file or a
/// response-body file never lingers — even on an early return / error path.
struct ScopedPath(PathBuf);

impl Drop for ScopedPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Run one `curl` request whose secret-bearing lines (Authorization header,
/// POST data) are written to a mode-0600 `-K` config file — never argv. Returns
/// the HTTP status and the parsed JSON body (parsed only when the body is valid
/// JSON). `None` only when curl could not run or produced no status code.
fn curl_request(url: &str, config_lines: &[String]) -> Option<(u16, Option<serde_json::Value>)> {
    let config = ScopedPath(unique_temp_path("cfg"));
    {
        // Written and closed (flushed) before curl reads the file below.
        let mut file = match create_private_file(&config.0) {
            Ok(file) => file,
            Err(err) => {
                tracing::warn!(error = %err, "usage fetch: failed to create curl config");
                return None;
            }
        };
        for line in config_lines {
            if writeln!(file, "{line}").is_err() {
                return None;
            }
        }
    }

    let body = ScopedPath(unique_temp_path("body"));
    // Pre-create the response file 0600 so a body carrying account PII (the
    // Codex usage response includes an email + user id) is never briefly
    // world-readable; curl's `-o` opens it with O_TRUNC and keeps these perms.
    if let Err(err) = create_private_file(&body.0) {
        tracing::warn!(error = %err, "usage fetch: failed to create response file");
        return None;
    }
    let output = crate::noninteractive_process::curl_command()
        .arg("-sS")
        .arg("-K")
        .arg(&config.0)
        .arg("-A")
        .arg(USAGE_USER_AGENT)
        .arg("--max-time")
        .arg(CURL_MAX_TIME_SECS.to_string())
        .arg("-o")
        .arg(&body.0)
        .arg("-w")
        .arg("%{http_code}")
        .arg(url)
        .output()
        .ok()?;

    let code: u16 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;
    if code == 0 {
        return None;
    }
    let parsed = std::fs::read(&body.0)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    Some((code, parsed))
}

/// Reject any secret value that would break — or inject into — a curl config
/// line. OAuth access tokens are JWT/base64url and never contain these, so a
/// value that does is treated as malformed and the fetch is abandoned.
fn config_safe(value: &str) -> bool {
    !value.chars().any(|character| {
        character == '"'
            || character == '\\'
            || character == '\n'
            || character == '\r'
            || character.is_control()
    })
}

/// Percent-encode a value for an `application/x-www-form-urlencoded` body
/// (unreserved chars pass through; everything else is `%XX`). Used for the
/// refresh token so the POST body is always config-line safe.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Create a new file readable/writable only by the owner (0600 on Unix).
/// `create_new` guarantees we never adopt a pre-existing file's permissions.
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn unique_temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("herdr-usage-{tag}-{}", unique_suffix()))
}

/// A process-unique, collision-resistant suffix (pid + nanos + counter).
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{seq}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_usage_fixture_parses_windows_plan_and_active() {
        let body = serde_json::json!({
            "plan_type": "pro",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 42.5,
                    "limit_window_seconds": 18000,
                    "reset_at": 1_789_827_841i64
                },
                "secondary_window": {
                    "used_percent": 12.0,
                    "reset_at": 1_790_000_000i64
                }
            },
            "rate_limit_reached_type": serde_json::Value::Null
        });

        let (usage, active) = parse_codex_usage(&body).expect("fixture should parse");
        assert!(active, "under-quota snapshot is active");
        assert_eq!(usage.source.as_deref(), Some("live"));
        assert_eq!(usage.plan.as_deref(), Some("pro"));
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].label, "5h");
        assert_eq!(usage.windows[0].used_percent, Some(42.5));
        assert_eq!(usage.windows[0].resets_at.as_deref(), Some("1789827841"));
        assert_eq!(usage.windows[0].status.as_deref(), Some("ok"));
        assert_eq!(usage.windows[1].label, "weekly");
        assert_eq!(usage.windows[1].used_percent, Some(12.0));
        // Flat back-compat fields mirror the first two windows.
        assert_eq!(usage.primary_used_percent, Some(42.5));
        assert_eq!(usage.secondary_used_percent, Some(12.0));
        assert_eq!(usage.resets_at.as_deref(), Some("1789827841"));
    }

    #[test]
    fn codex_usage_marks_reached_inactive_and_drops_null_window() {
        let body = serde_json::json!({
            "plan_type": "pro",
            "rate_limit": {
                "limit_reached": true,
                "primary_window": {"used_percent": 100.0, "reset_at": 1_789_827_841i64},
                "secondary_window": serde_json::Value::Null
            },
            "rate_limit_reached_type": {"type": "rate_limit_reached", "details": "default"}
        });

        let (usage, active) = parse_codex_usage(&body).expect("fixture should parse");
        assert!(!active, "rate-limit-reached snapshot is inactive");
        assert_eq!(usage.windows.len(), 1, "null secondary window is skipped");
        assert_eq!(usage.windows[0].status.as_deref(), Some("exhausted"));
    }

    #[test]
    fn codex_usage_garbage_body_is_none() {
        let body = serde_json::json!({"error": {"message": "unauthorized"}});
        assert!(parse_codex_usage(&body).is_none());
    }

    #[test]
    fn claude_usage_fixture_parses_windows_and_active() {
        let body = serde_json::json!({
            "five_hour": {"utilization": 31.0, "resets_at": "2026-08-20T16:49:59Z"},
            "seven_day": {"utilization": 61.0, "resets_at": "2026-08-22T23:59:59Z"},
            "limits": []
        });

        let (usage, active) = parse_claude_usage(&body).expect("fixture should parse");
        assert!(active);
        assert_eq!(usage.source.as_deref(), Some("live"));
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].label, "5h");
        assert_eq!(usage.windows[0].used_percent, Some(31.0));
        assert_eq!(
            usage.windows[0].resets_at.as_deref(),
            Some("2026-08-20T16:49:59Z")
        );
        assert_eq!(usage.windows[1].label, "weekly");
        assert_eq!(usage.windows[1].used_percent, Some(61.0));
        assert_eq!(usage.primary_used_percent, Some(31.0));
        assert_eq!(usage.secondary_used_percent, Some(61.0));
    }

    #[test]
    fn claude_usage_over_quota_is_inactive() {
        let body = serde_json::json!({
            "five_hour": {"utilization": 100.0, "resets_at": "2026-08-20T16:49:59Z"},
            "seven_day": {"utilization": 50.0}
        });

        let (_usage, active) = parse_claude_usage(&body).expect("fixture should parse");
        assert!(!active, "a window at 100% is inactive");
    }

    #[test]
    fn claude_usage_rate_limit_error_body_is_none() {
        let body = serde_json::json!({
            "type": "error",
            "error": {"type": "rate_limit_error", "message": "too many requests"}
        });
        assert!(parse_claude_usage(&body).is_none());
    }

    #[test]
    fn backfill_flat_fields_mirrors_first_two_windows() {
        let mut usage = AccountUsage {
            windows: vec![
                UsageWindow {
                    label: "5h".to_string(),
                    used_percent: Some(20.0),
                    resets_at: Some("1700000000".to_string()),
                    status: Some("ok".to_string()),
                },
                UsageWindow {
                    label: "weekly".to_string(),
                    used_percent: Some(70.0),
                    resets_at: None,
                    status: Some("ok".to_string()),
                },
            ],
            source: Some("live".to_string()),
            ..Default::default()
        };
        assert_eq!(usage.primary_used_percent, None);
        usage.backfill_flat_fields();
        assert_eq!(usage.primary_used_percent, Some(20.0));
        assert_eq!(usage.secondary_used_percent, Some(70.0));
        assert_eq!(usage.resets_at.as_deref(), Some("1700000000"));
    }

    #[test]
    fn config_safe_rejects_injection_and_control_chars() {
        assert!(config_safe("eyJhbGciOi.JIUzI1NiIsInR5-cCI_6.abc~123"));
        assert!(!config_safe("tok\"en"));
        assert!(!config_safe("tok\nen"));
        assert!(!config_safe("tok\\en"));
    }

    #[test]
    fn form_encode_percent_encodes_reserved_bytes() {
        assert_eq!(form_encode("abcXYZ0-9._~"), "abcXYZ0-9._~");
        assert_eq!(form_encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn unknown_kind_has_no_live_fetch() {
        assert!(fetch_live_usage("kimi", "/tmp/does-not-matter").is_none());
        assert!(!kind_supports_live_usage("kimi"));
        assert!(kind_supports_live_usage("codex"));
        assert!(kind_supports_live_usage("claude"));
    }

    #[test]
    fn ttl_is_per_kind() {
        assert_eq!(usage_ttl("codex"), USAGE_CODEX_TTL);
        assert_eq!(usage_ttl("claude"), USAGE_CLAUDE_TTL);
    }
}
