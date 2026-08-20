use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::api::schema::{AccountInfo, AccountUsage, ResponseResult};
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
        let accounts = self
            .loaded_accounts
            .iter()
            .map(|account| {
                let (usage, active) = account_usage(account);
                AccountInfo {
                    id: account.id.clone(),
                    kind: account.kind.clone(),
                    label: account.label.clone(),
                    active,
                    usage,
                }
            })
            .collect();
        encode_success(id, ResponseResult::AccountsList { accounts })
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

    let usage = AccountUsage {
        primary_used_percent: primary_used,
        secondary_used_percent: secondary_used,
        resets_at,
        plan,
        tier: None,
    };
    (Some(usage), !exhausted)
}

fn bucket_used_percent(bucket: Option<&serde_json::Value>) -> Option<f32> {
    let value = bucket?.get("used_percent")?.as_f64()?.clamp(0.0, 100.0);
    Some(value as f32)
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
fn collect_jsonl_files(dir: &Path, limit: usize) -> Vec<(PathBuf, std::time::SystemTime)> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if found.len() >= limit {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            if found.len() >= limit {
                break;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "jsonl") {
                let mtime = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                found.push((path, mtime));
            }
        }
    }
    found
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
}
