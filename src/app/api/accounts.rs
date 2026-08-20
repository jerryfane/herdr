use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::api::schema::{AccountInfo, AccountUsage, ResponseResult, UsageWindow};
use crate::app::App;
use crate::config::AccountConfig;

use super::responses::encode_success;

/// Newest session files to scan for a Codex rate-limit snapshot.
const CODEX_SESSIONS_TO_SCAN: usize = 16;
/// Upper bound on session files enumerated before ranking by mtime.
const CODEX_SESSIONS_TO_ENUMERATE: usize = 512;
/// Tail bytes read from a session file when hunting for the newest rate-limit
/// line — bounds work for large append-only logs.
const CODEX_SESSION_TAIL_BYTES: u64 = 256 * 1024;

/// Why an account id could not be resolved to a launch env.
#[derive(Debug)]
pub(crate) enum AccountResolveError {
    Unknown(String),
    KindMismatch {
        account: String,
        account_kind: String,
        agent_kind: String,
    },
}

impl App {
    /// The complete, deliberate `accounts.list` response: every configured
    /// account with best-effort, locally-derived usage. Read-only; returns only
    /// paths, labels, and usage NUMBERS — never a credential value.
    pub(super) fn handle_accounts_list(&mut self, id: String) -> String {
        // Clone the config (small: ids/labels/paths only) so the loop can take
        // `&mut self` to read the cache and kick background fetches.
        let loaded_accounts = self.loaded_accounts.clone();
        let accounts = loaded_accounts
            .iter()
            .map(|account| {
                let (usage, active) = self.account_usage_cached(account);
                AccountInfo {
                    id: account.id.clone(),
                    kind: account.kind.clone(),
                    label: account.label.clone(),
                    active,
                    email: account_email(account),
                    usage,
                }
            })
            .collect();
        encode_success(id, ResponseResult::AccountsList { accounts })
    }

    /// The usage to report for one account, without ever blocking the app loop.
    ///
    /// For a kind with a live provider (Codex/Claude): serve a fresh (< per-kind
    /// TTL) live-cache entry when present; otherwise kick at most one background
    /// live fetch and, for THIS response, fall back to the local read. Kimi and
    /// unknown kinds skip the fetch entirely and use the local read.
    fn account_usage_cached(&mut self, account: &AccountConfig) -> (Option<AccountUsage>, bool) {
        if super::usage_fetch::kind_supports_live_usage(&account.kind) {
            if let Some(cached) = self.usage_cache.get(&account.id) {
                if cached.fetched_at.elapsed() < super::usage_fetch::usage_ttl(&account.kind) {
                    return (Some(cached.usage.clone()), cached.active);
                }
            }
            // Missing or stale: kick a background refresh if one isn't already
            // running for this account. `insert` returns false when present.
            if self.usage_refresh_inflight.insert(account.id.clone()) {
                spawn_usage_fetch(
                    self.event_tx.clone(),
                    account.id.clone(),
                    account.kind.clone(),
                    account.config_dir.clone(),
                );
            }
        }
        // This response falls back to the honest local read while any live fetch
        // is in flight.
        account_usage(account)
    }

    /// Resolve an account id (matching the agent's kind) to the single
    /// `(env_var, config_dir)` launch env that points the harness at that
    /// account's config-home directory.
    pub(crate) fn resolve_account_launch_env(
        &self,
        account_id: &str,
        agent_kind: &str,
    ) -> Result<Vec<(String, String)>, AccountResolveError> {
        let Some(account) = self
            .loaded_accounts
            .iter()
            .find(|account| account.id == account_id)
        else {
            return Err(AccountResolveError::Unknown(account_id.to_string()));
        };
        if account.kind != agent_kind {
            return Err(AccountResolveError::KindMismatch {
                account: account_id.to_string(),
                account_kind: account.kind.clone(),
                agent_kind: agent_kind.to_string(),
            });
        }
        account
            .launch_env()
            .ok_or_else(|| AccountResolveError::Unknown(account_id.to_string()))
    }
}

impl AccountResolveError {
    pub(crate) fn into_error_body(self) -> crate::api::schema::ErrorBody {
        match self {
            AccountResolveError::Unknown(account) => crate::api::schema::ErrorBody {
                code: "unknown_account".into(),
                message: format!("no configured account with id {account} for this agent kind"),
            },
            AccountResolveError::KindMismatch {
                account,
                account_kind,
                agent_kind,
            } => crate::api::schema::ErrorBody {
                code: "account_kind_mismatch".into(),
                message: format!("account {account} is for kind {account_kind}, not {agent_kind}"),
            },
        }
    }
}

/// Spawn a background live-usage fetch on its own OS thread and deliver the
/// result as `AppEvent::UsageRefreshed`. An OS thread (not `tokio::spawn`) is
/// used because `fetch_live_usage` blocks on a `curl` subprocess, which must not
/// run on a tokio worker — mirroring the repo's other blocking-curl paths
/// (`git_refresh`, `push`). The app loop is never blocked: it only clones the
/// ids and returns.
fn spawn_usage_fetch(
    event_tx: tokio::sync::mpsc::Sender<crate::events::AppEvent>,
    account_id: String,
    kind: String,
    config_dir: String,
) {
    std::thread::spawn(move || {
        let usage = super::usage_fetch::fetch_live_usage(&kind, &config_dir);
        let _ =
            event_tx.blocking_send(crate::events::AppEvent::UsageRefreshed { account_id, usage });
    });
}

/// Best-effort `(usage, active)` for an account. Never fails the caller: an
/// unreadable or missing source degrades to `(None, true)`.
fn account_usage(account: &AccountConfig) -> (Option<AccountUsage>, bool) {
    match account.kind.as_str() {
        // Codex publishes a rate-limit snapshot inside each session log.
        "codex" => read_codex_usage(&account.config_dir),
        // Claude exposes plan/tier locally but no live quota.
        "claude" => (read_claude_plan_tier(&account.config_dir), true),
        // Kimi (and any unknown kind): no local usage.
        _ => (None, true),
    }
}

/// Parse the newest Codex rate-limit snapshot under `<config_dir>/sessions`.
/// Returns `(usage, active)`; `active` is false only when the snapshot proves
/// exhaustion (a bucket at/over 100% or a rate-limit-reached marker).
fn read_codex_usage(config_dir: &str) -> (Option<AccountUsage>, bool) {
    let sessions_dir = Path::new(config_dir).join("sessions");
    let mut files = collect_jsonl_files(&sessions_dir, CODEX_SESSIONS_TO_ENUMERATE);
    // Newest mtime first, then scan a bounded head of that list.
    files.sort_by_key(|(_, mtime)| std::cmp::Reverse(*mtime));

    let mut best: Option<(String, serde_json::Value)> = None;
    for (path, _) in files.iter().take(CODEX_SESSIONS_TO_SCAN) {
        if let Some((timestamp, rate_limits)) = newest_rate_limits_in_file(path) {
            let newer = best
                .as_ref()
                .map(|(best_ts, _)| timestamp > *best_ts)
                .unwrap_or(true);
            if newer {
                best = Some((timestamp, rate_limits));
            }
        }
    }

    let Some((_, rate_limits)) = best else {
        return (None, true);
    };

    let primary = rate_limits.get("primary");
    let secondary = rate_limits.get("secondary");
    let primary_used = bucket_used_percent(primary);
    let secondary_used = bucket_used_percent(secondary);
    let resets_at = primary
        .and_then(|bucket| bucket.get("resets_at"))
        .and_then(json_scalar_to_string);
    let plan = rate_limits
        .get("plan_type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let rate_limit_reached = rate_limits
        .get("rate_limit_reached_type")
        .is_some_and(|value| !value.is_null());

    let exhausted = rate_limit_reached
        || primary_used.is_some_and(|used| used >= 100.0)
        || secondary_used.is_some_and(|used| used >= 100.0);

    let mut windows = Vec::new();
    if primary.is_some() {
        windows.push(UsageWindow {
            // Codex windows are not fixed 5h/weekly slots — derive the label from
            // the bucket's `window_minutes` rather than its position (a pro plan's
            // primary bucket is the 7-day one).
            label: codex_local_window_label(primary, "5h"),
            used_percent: primary_used,
            resets_at,
            status: Some(window_status(primary_used, rate_limit_reached)),
        });
    }
    if secondary.is_some() {
        let secondary_resets = secondary
            .and_then(|bucket| bucket.get("resets_at"))
            .and_then(json_scalar_to_string);
        windows.push(UsageWindow {
            label: codex_local_window_label(secondary, "weekly"),
            used_percent: secondary_used,
            resets_at: secondary_resets,
            status: Some(window_status(secondary_used, false)),
        });
    }

    let mut usage = AccountUsage {
        windows,
        source: Some("local".to_string()),
        plan,
        ..Default::default()
    };
    usage.backfill_flat_fields();
    (Some(usage), !exhausted)
}

/// "exhausted" when a bucket is at/over 100% or a rate-limit-reached marker is
/// set for it, else "ok".
fn window_status(used_percent: Option<f32>, rate_limit_reached: bool) -> String {
    if rate_limit_reached || used_percent.is_some_and(|used| used >= 100.0) {
        "exhausted".to_string()
    } else {
        "ok".to_string()
    }
}

fn bucket_used_percent(bucket: Option<&serde_json::Value>) -> Option<f32> {
    let value = bucket?.get("used_percent")?.as_f64()?.clamp(0.0, 100.0);
    Some(value as f32)
}

/// Label for a local Codex session-log bucket from its `window_minutes`,
/// falling back to `fallback` when absent. Shares the duration→label mapping
/// with the live reader so both derive the label from the window length.
fn codex_local_window_label(bucket: Option<&serde_json::Value>, fallback: &str) -> String {
    bucket
        .and_then(|b| b.get("window_minutes"))
        .and_then(serde_json::Value::as_u64)
        .map(|minutes| super::usage_fetch::window_label_from_seconds(minutes.saturating_mul(60)))
        .unwrap_or_else(|| fallback.to_string())
}

fn json_scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// The newest `(timestamp, rate_limits)` in one session log, scanning the tail
/// from the end. Tolerant of partial/garbage lines.
fn newest_rate_limits_in_file(path: &Path) -> Option<(String, serde_json::Value)> {
    let tail = read_tail(path, CODEX_SESSION_TAIL_BYTES)?;
    for raw_line in tail.split(|&byte| byte == b'\n').rev() {
        let Ok(line) = std::str::from_utf8(raw_line) else {
            continue;
        };
        if !line.contains("\"rate_limits\"") {
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let rate_limits = event
            .get("payload")
            .and_then(|payload| payload.get("rate_limits"))
            .or_else(|| event.get("rate_limits"));
        let Some(rate_limits) = rate_limits else {
            continue;
        };
        if rate_limits.is_null() {
            continue;
        }
        let timestamp = event
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        return Some((timestamp, rate_limits.clone()));
    }
    None
}

fn read_tail(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buffer = Vec::new();
    file.take(max_bytes).read_to_end(&mut buffer).ok()?;
    Some(buffer)
}

/// Recursively enumerate `*.jsonl` files under `dir` with their mtimes, bounded
/// to `limit` entries so a huge session tree cannot stall the call.
///
/// Codex nests session logs as `sessions/YYYY/MM/DD/…`, whose directory names
/// sort chronologically, so subdirectories are visited in DESCENDING name order
/// and the `limit` bound therefore keeps the NEWEST-dated logs — the ones that
/// carry the current rate-limit snapshot — instead of an arbitrary traversal
/// slice. (A default home can hold tens of thousands of logs, far above the
/// bound; a traversal-order cut would routinely miss the recent ones.) Callers
/// still sort the result by mtime before scanning.
fn collect_jsonl_files(dir: &Path, limit: usize) -> Vec<(PathBuf, std::time::SystemTime)> {
    let mut found = Vec::new();
    collect_jsonl_files_into(dir, limit, &mut found);
    found
}

fn collect_jsonl_files_into(
    dir: &Path,
    limit: usize,
    found: &mut Vec<(PathBuf, std::time::SystemTime)>,
) {
    if found.len() >= limit {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            subdirs.push(path);
        } else if path.extension().is_some_and(|ext| ext == "jsonl") {
            if found.len() >= limit {
                return;
            }
            let mtime = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            found.push((path, mtime));
        }
    }
    // Newest-named subdirectory first (dates sort chronologically), so the
    // `limit` bound retains recent logs rather than an arbitrary slice.
    subdirs.sort_unstable_by(|a, b| b.file_name().cmp(&a.file_name()));
    for sub in subdirs {
        if found.len() >= limit {
            break;
        }
        collect_jsonl_files_into(&sub, limit, found);
    }
}

/// Extract only Claude's plan/tier from `<config_dir>/.credentials.json`.
///
/// SECURITY: this file also holds OAuth tokens. This reads ONLY the
/// `subscriptionType` and `rateLimitTier` string fields and never returns, logs,
/// or otherwise surfaces the token or any other field.
fn read_claude_plan_tier(config_dir: &str) -> Option<AccountUsage> {
    let path = Path::new(config_dir).join(".credentials.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let plan = find_string_field(&value, "subscriptionType");
    let tier = find_string_field(&value, "rateLimitTier");
    if plan.is_none() && tier.is_none() {
        return None;
    }
    Some(AccountUsage {
        plan,
        tier,
        source: Some("local".to_string()),
        ..Default::default()
    })
}

/// The first string value stored under `key` anywhere in a JSON tree. Matches
/// the exact key only, so sibling secrets under other keys are never returned.
fn find_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(text)) = map.get(key) {
                return Some(text.clone());
            }
            map.values().find_map(|child| find_string_field(child, key))
        }
        serde_json::Value::Array(items) => {
            items.iter().find_map(|item| find_string_field(item, key))
        }
        _ => None,
    }
}

/// Best-effort login email for an account, from its config-home. Identity only —
/// never reads or returns a token. None for kinds/accounts with no local email.
fn account_email(account: &AccountConfig) -> Option<String> {
    match account.kind.as_str() {
        "claude" => read_claude_email(&account.config_dir),
        "codex" => read_codex_email(&account.config_dir),
        _ => None,
    }
}

/// Claude email: `<config_dir>/.claude.json` -> `oauthAccount.emailAddress`
/// (a scoped lookup — `.claude.json` is large, so avoid a tree-wide search).
fn read_claude_email(config_dir: &str) -> Option<String> {
    let path = Path::new(config_dir).join(".claude.json");
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).ok()?).ok()?;
    value
        .get("oauthAccount")
        .and_then(|oauth| oauth.get("emailAddress"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Codex email: the `email` claim inside `<config_dir>/auth.json` ->
/// `tokens.id_token` (a JWT). Only the non-secret email claim is read; the token
/// itself is never returned or logged.
fn read_codex_email(config_dir: &str) -> Option<String> {
    let path = Path::new(config_dir).join("auth.json");
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).ok()?).ok()?;
    let id_token = value
        .get("tokens")
        .and_then(|tokens| tokens.get("id_token"))
        .and_then(serde_json::Value::as_str)?;
    decode_jwt_email(id_token)
}

/// Read ONLY the `email` claim from a JWT's payload (the middle segment),
/// without verifying the signature. Pad-tolerant base64url decode. Never
/// surfaces any other claim or the token itself.
fn decode_jwt_email(jwt: &str) -> Option<String> {
    use base64::Engine;
    let payload = jwt.split('.').nth(1)?.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app_with_accounts(accounts: Vec<AccountConfig>) -> App {
        let config = crate::config::Config {
            accounts,
            ..Default::default()
        };
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        App::new(&config, true, None, api_rx, crate::api::EventHub::default())
    }

    fn account(id: &str, kind: &str, config_dir: &str) -> AccountConfig {
        AccountConfig {
            id: id.into(),
            kind: kind.into(),
            label: format!("{id} label"),
            config_dir: config_dir.into(),
        }
    }

    #[test]
    fn resolve_account_launch_env_finds_by_id_and_kind() {
        let app = test_app_with_accounts(vec![
            account("work", "codex", "/home/x/.codex-work"),
            account("personal", "claude", "/home/x/.claude-personal"),
        ]);

        assert_eq!(
            app.resolve_account_launch_env("work", "codex").unwrap(),
            vec![("CODEX_HOME".to_string(), "/home/x/.codex-work".to_string())]
        );
        assert_eq!(
            app.resolve_account_launch_env("personal", "claude")
                .unwrap(),
            vec![(
                "CLAUDE_CONFIG_DIR".to_string(),
                "/home/x/.claude-personal".to_string()
            )]
        );
    }

    #[test]
    fn resolve_account_launch_env_errors_on_unknown_id() {
        let app = test_app_with_accounts(vec![account("work", "codex", "/tmp/c")]);
        let err = app.resolve_account_launch_env("nope", "codex").unwrap_err();
        assert_eq!(err.into_error_body().code, "unknown_account");
    }

    #[test]
    fn resolve_account_launch_env_errors_on_kind_mismatch() {
        let app = test_app_with_accounts(vec![account("work", "codex", "/tmp/c")]);
        let err = app
            .resolve_account_launch_env("work", "claude")
            .unwrap_err();
        assert_eq!(err.into_error_body().code, "account_kind_mismatch");
    }

    #[test]
    fn accounts_list_returns_configured_accounts() {
        let mut app = test_app_with_accounts(vec![
            account("work", "codex", "/tmp/does-not-exist-codex"),
            account("kimi-main", "kimi", "/tmp/does-not-exist-kimi"),
        ]);

        let response = app.handle_accounts_list("req".into());
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let accounts = value["result"]["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0]["id"], "work");
        assert_eq!(accounts[0]["kind"], "codex");
        assert_eq!(accounts[0]["label"], "work label");
        // Missing usage sources degrade to no usage / active.
        assert_eq!(accounts[0]["active"], true);
        assert!(accounts[0].get("usage").is_none());
        assert_eq!(accounts[1]["id"], "kimi-main");
        assert_eq!(accounts[1]["active"], true);
        // Kimi has no live provider, so it is never scheduled for a fetch.
        assert!(!app.usage_refresh_inflight.contains("kimi-main"));
    }

    #[test]
    fn accounts_list_serves_a_fresh_live_cache_entry() {
        let mut app = test_app_with_accounts(vec![account(
            "work",
            "codex",
            "/tmp/does-not-exist-codex-live",
        )]);
        let mut usage = AccountUsage {
            windows: vec![UsageWindow {
                label: "5h".to_string(),
                used_percent: Some(37.0),
                resets_at: Some("1789827841".to_string()),
                status: Some("ok".to_string()),
            }],
            source: Some("live".to_string()),
            plan: Some("pro".to_string()),
            ..Default::default()
        };
        usage.backfill_flat_fields();
        app.usage_cache.insert(
            "work".to_string(),
            crate::app::api::usage_fetch::CachedUsage {
                fetched_at: std::time::Instant::now(),
                usage,
                active: true,
            },
        );

        let response = app.handle_accounts_list("req".into());
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let account = &value["result"]["accounts"][0];
        assert_eq!(account["usage"]["source"], "live");
        assert_eq!(account["usage"]["primary_used_percent"], 37.0);
        assert_eq!(account["usage"]["plan"], "pro");
        // A fresh cache hit is served WITHOUT scheduling another fetch.
        assert!(!app.usage_refresh_inflight.contains("work"));
    }

    #[test]
    fn accounts_list_kicks_one_background_fetch_on_cache_miss() {
        // A missing config dir keeps the spawned fetch offline: it reads a
        // nonexistent auth.json and returns before any network call.
        let mut app = test_app_with_accounts(vec![account(
            "work",
            "codex",
            "/tmp/does-not-exist-codex-miss",
        )]);
        // Cold cache: the handler schedules exactly one fetch and, for this
        // response, falls back to the (empty) local read.
        let response = app.handle_accounts_list("req".into());
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(value["result"]["accounts"][0].get("usage").is_none());
        assert!(app.usage_refresh_inflight.contains("work"));

        // A second call while still in flight does NOT schedule a duplicate.
        let _ = app.handle_accounts_list("req2".into());
        assert_eq!(app.usage_refresh_inflight.len(), 1);
    }

    #[test]
    fn stale_live_cache_entry_falls_back_and_reschedules() {
        let mut app = test_app_with_accounts(vec![account(
            "work",
            "codex",
            "/tmp/does-not-exist-codex-stale",
        )]);
        let usage = AccountUsage {
            windows: vec![UsageWindow {
                label: "5h".to_string(),
                used_percent: Some(50.0),
                resets_at: None,
                status: Some("ok".to_string()),
            }],
            source: Some("live".to_string()),
            ..Default::default()
        };
        // Fetched well beyond the codex TTL (60s).
        app.usage_cache.insert(
            "work".to_string(),
            crate::app::api::usage_fetch::CachedUsage {
                fetched_at: std::time::Instant::now() - std::time::Duration::from_secs(600),
                usage,
                active: true,
            },
        );

        let response = app.handle_accounts_list("req".into());
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        // Stale entry is NOT served; this response uses the local read (none
        // here) and a refresh is scheduled.
        assert!(value["result"]["accounts"][0].get("usage").is_none());
        assert!(app.usage_refresh_inflight.contains("work"));
    }

    #[test]
    fn usage_refreshed_event_populates_and_clears_inflight() {
        let mut app = test_app_with_accounts(vec![account("work", "codex", "/tmp/x")]);
        app.usage_refresh_inflight.insert("work".to_string());
        let mut usage = AccountUsage {
            windows: vec![UsageWindow {
                label: "5h".to_string(),
                used_percent: Some(12.0),
                resets_at: None,
                status: Some("ok".to_string()),
            }],
            source: Some("live".to_string()),
            ..Default::default()
        };
        usage.backfill_flat_fields();

        app.handle_internal_event(crate::events::AppEvent::UsageRefreshed {
            account_id: "work".to_string(),
            usage: Some((usage, false)),
        });

        assert!(!app.usage_refresh_inflight.contains("work"));
        let cached = app.usage_cache.get("work").expect("cache populated");
        assert!(!cached.active);
        assert_eq!(cached.usage.primary_used_percent, Some(12.0));
    }

    #[test]
    fn usage_refreshed_failure_clears_inflight_without_caching() {
        let mut app = test_app_with_accounts(vec![account("work", "codex", "/tmp/x")]);
        app.usage_refresh_inflight.insert("work".to_string());

        app.handle_internal_event(crate::events::AppEvent::UsageRefreshed {
            account_id: "work".to_string(),
            usage: None,
        });

        assert!(!app.usage_refresh_inflight.contains("work"));
        assert!(!app.usage_cache.contains_key("work"));
    }

    #[test]
    fn codex_usage_fixture_parses_percentages_and_plan() {
        let dir = std::env::temp_dir().join(format!("herdr-codex-usage-{}", std::process::id()));
        let sessions = dir.join("sessions").join("2026").join("08");
        std::fs::create_dir_all(&sessions).unwrap();
        let line = serde_json::json!({
            "timestamp": "2026-08-20T10:00:00Z",
            "payload": {
                "rate_limits": {
                    "plan_type": "pro",
                    "primary": {"used_percent": 42.5, "window_minutes": 300, "resets_at": 1_760_000_000i64},
                    "secondary": {"used_percent": 12.0, "window_minutes": 10080}
                }
            }
        })
        .to_string();
        // An earlier non-rate-limit line plus the snapshot line.
        std::fs::write(
            sessions.join("session.jsonl"),
            format!("{{\"timestamp\":\"2026-08-20T09:00:00Z\",\"payload\":{{}}}}\n{line}\n"),
        )
        .unwrap();

        let (usage, active) = read_codex_usage(&dir.display().to_string());
        let usage = usage.expect("fixture should parse");
        assert_eq!(usage.primary_used_percent, Some(42.5));
        assert_eq!(usage.secondary_used_percent, Some(12.0));
        assert_eq!(usage.plan.as_deref(), Some("pro"));
        assert_eq!(usage.resets_at.as_deref(), Some("1760000000"));
        assert!(active, "under-quota snapshot is active");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_usage_marks_exhausted_inactive() {
        let dir = std::env::temp_dir().join(format!("herdr-codex-full-{}", std::process::id()));
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let line = serde_json::json!({
            "timestamp": "2026-08-20T10:00:00Z",
            "rate_limits": {
                "primary": {"used_percent": 100.0},
                "secondary": {"used_percent": 100.0},
                "rate_limit_reached_type": "primary"
            }
        })
        .to_string();
        std::fs::write(sessions.join("s.jsonl"), format!("{line}\n")).unwrap();

        let (usage, active) = read_codex_usage(&dir.display().to_string());
        assert!(usage.is_some());
        assert!(!active, "exhausted snapshot is inactive");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_jsonl_files_keeps_newest_date_dir_within_limit() {
        // Codex nests sessions as YYYY/MM/DD. With a bound smaller than the
        // total file count, the collector must retain the NEWEST-dated logs
        // (which carry the current rate-limit snapshot), not an arbitrary
        // traversal slice — a real default home holds far more logs than the
        // bound, so a traversal-order cut would routinely drop the recent ones.
        let root = std::env::temp_dir().join(format!("herdr-codex-recency-{}", std::process::id()));
        for day in ["01", "10", "20"] {
            let d = root.join("2026").join("08").join(day);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("rollout.jsonl"), b"{}\n").unwrap();
        }
        // Bound to a single file: it must be the newest day's (20), regardless
        // of the filesystem's directory-read order.
        let files = collect_jsonl_files(&root, 1);
        assert_eq!(files.len(), 1);
        let newest = root
            .join("2026")
            .join("08")
            .join("20")
            .join("rollout.jsonl");
        assert_eq!(
            files[0].0, newest,
            "expected the newest day's log within the bound"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn codex_usage_missing_dir_degrades_to_none() {
        let (usage, active) = read_codex_usage("/tmp/herdr-nonexistent-codex-home-xyz");
        assert!(usage.is_none());
        assert!(active);
    }

    #[test]
    fn claude_plan_tier_extracts_only_named_fields_never_the_token() {
        let dir = std::env::temp_dir().join(format!("herdr-claude-creds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".credentials.json"),
            serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": "SECRET-TOKEN-VALUE",
                    "refreshToken": "SECRET-REFRESH",
                    "subscriptionType": "max",
                    "rateLimitTier": "default_claude_ai"
                }
            })
            .to_string(),
        )
        .unwrap();

        let usage = read_claude_plan_tier(&dir.display().to_string()).expect("should parse");
        assert_eq!(usage.plan.as_deref(), Some("max"));
        assert_eq!(usage.tier.as_deref(), Some("default_claude_ai"));
        assert!(usage.primary_used_percent.is_none());
        // The extracted values never include the token.
        assert_ne!(usage.plan.as_deref(), Some("SECRET-TOKEN-VALUE"));
        assert_ne!(usage.tier.as_deref(), Some("SECRET-TOKEN-VALUE"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_plan_tier_missing_file_degrades_to_none() {
        assert!(read_claude_plan_tier("/tmp/herdr-nonexistent-claude-home-xyz").is_none());
    }

    #[test]
    fn codex_local_window_label_derives_from_minutes() {
        let weekly = serde_json::json!({"window_minutes": 10080});
        let five_h = serde_json::json!({"window_minutes": 300});
        assert_eq!(codex_local_window_label(Some(&weekly), "x"), "weekly");
        assert_eq!(codex_local_window_label(Some(&five_h), "x"), "5h");
        // Missing duration → fallback.
        assert_eq!(
            codex_local_window_label(Some(&serde_json::json!({})), "fb"),
            "fb"
        );
    }

    #[test]
    fn claude_email_reads_only_oauth_email_address() {
        let dir = std::env::temp_dir().join(format!("herdr-claude-email-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".claude.json"),
            serde_json::json!({
                "oauthAccount": {"emailAddress": "user@example.com", "accountUuid": "abc"},
                "someToken": "SECRET-should-not-be-read"
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            read_claude_email(&dir.display().to_string()).as_deref(),
            Some("user@example.com")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_email_reads_only_the_email_claim_from_the_id_token() {
        use base64::Engine;
        // A JWT whose payload carries an email claim (+ an unrelated secret claim).
        let payload =
            serde_json::json!({"email": "codex@example.com", "sub": "user-1", "secret": "nope"});
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let jwt = format!("aGVhZGVy.{encoded}.c2ln");
        let dir = std::env::temp_dir().join(format!("herdr-codex-email-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("auth.json"),
            serde_json::json!({"tokens": {"id_token": jwt, "access_token": "SECRET"}}).to_string(),
        )
        .unwrap();
        assert_eq!(
            read_codex_email(&dir.display().to_string()).as_deref(),
            Some("codex@example.com")
        );
        assert_eq!(decode_jwt_email("not.a.jwt-with-bad-b64!!"), None);
        assert_eq!(decode_jwt_email("only-one-segment"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn account_email_none_for_kimi_and_unknown() {
        let mk = |kind: &str| crate::config::AccountConfig {
            id: "x".into(),
            kind: kind.into(),
            label: "x".into(),
            config_dir: "/tmp/herdr-nonexistent-email-home".into(),
        };
        assert!(account_email(&mk("kimi")).is_none());
        assert!(account_email(&mk("codex")).is_none()); // missing dir → None
    }
}
