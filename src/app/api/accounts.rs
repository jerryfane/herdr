use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::api::schema::{
    AccountInfo, AccountReadiness, AccountUsage, ResponseResult, UsageWindow,
};
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

/// Pick a config-home for a new account of `kind`: the harness default (`~/.claude`),
/// else `~/.claude-2`, `-3`, … — the first that is neither already registered nor
/// present on disk (so a new account never clobbers an existing config-home). `None`
/// when the kind has no default config-home lever.
fn derive_fresh_config_dir(accounts: &[AccountConfig], kind: &str) -> Option<String> {
    let base = crate::config::default_config_dir(kind)?
        .to_string_lossy()
        .into_owned();
    for n in 1..1000u32 {
        let candidate = if n == 1 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let taken = accounts
            .iter()
            .any(|account| account.config_dir == candidate)
            || Path::new(&candidate).exists();
        if !taken {
            return Some(candidate);
        }
    }
    None
}

/// A fresh, unique account id: a lowercase slug of the label (fallback: the kind),
/// suffixed `-2`, `-3`, … if that base is already an account id.
fn fresh_account_id(accounts: &[AccountConfig], kind: &str, label: &str) -> String {
    let slug: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-').to_string();
    let base = if slug.is_empty() {
        kind.to_string()
    } else {
        slug
    };
    if !accounts.iter().any(|account| account.id == base) {
        return base;
    }
    for n in 2..1000u32 {
        let candidate = format!("{base}-{n}");
        if !accounts.iter().any(|account| account.id == candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", accounts.len() + 1)
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
                    config_dir: account.config_dir.clone(),
                    active,
                    email: account_email(account),
                    usage,
                    readiness: account_readiness(account),
                }
            })
            .collect();
        encode_success(id, ResponseResult::AccountsList { accounts })
    }

    /// `accounts.create`: register a NEW account. Validates the kind, derives a fresh
    /// unique id + config-home (or takes the caller's), creates the directory, appends
    /// an `[[accounts]]` block to config.toml (append-only), reloads, and returns the
    /// refreshed `accounts.list`. Writes only non-secret metadata — the client drives
    /// login into the new config-home separately.
    pub(super) fn handle_accounts_create(
        &mut self,
        id: String,
        params: crate::api::schema::AccountsCreateParams,
    ) -> String {
        let kind = params.kind.trim().to_string();
        let label = params.label.trim().to_string();
        if crate::config::env_var_for_kind(&kind).is_none() {
            return super::responses::encode_error(
                id,
                "invalid_kind",
                format!("unknown account kind '{kind}' (expected claude, codex, or kimi)"),
            );
        }
        if label.is_empty() {
            return super::responses::encode_error(
                id,
                "invalid_label",
                "label must not be empty".to_string(),
            );
        }
        let config_dir = match params
            .config_dir
            .map(|dir| dir.trim().to_string())
            .filter(|dir| !dir.is_empty())
        {
            Some(dir) => dir,
            None => match derive_fresh_config_dir(&self.loaded_accounts, &kind) {
                Some(dir) => dir,
                None => {
                    return super::responses::encode_error(
                        id,
                        "no_default_config_dir",
                        format!("couldn't derive a config-home for '{kind}'; pass config_dir"),
                    )
                }
            },
        };
        if self
            .loaded_accounts
            .iter()
            .any(|account| account.config_dir == config_dir)
        {
            return super::responses::encode_error(
                id,
                "config_dir_in_use",
                format!("an account already uses {config_dir}"),
            );
        }
        let account_id = fresh_account_id(&self.loaded_accounts, &kind, &label);
        if let Err(err) = std::fs::create_dir_all(&config_dir) {
            return super::responses::encode_error(
                id,
                "config_dir_create_failed",
                format!("couldn't create {config_dir}: {err}"),
            );
        }
        let (write_id, write_kind, write_label, write_dir) = (account_id, kind, label, config_dir);
        let wrote = self.update_config_file("new account", move |content| {
            crate::config::append_accounts_block(
                content,
                &write_id,
                &write_kind,
                &write_label,
                &write_dir,
            )
        });
        if !wrote {
            return super::responses::encode_error(
                id,
                "config_write_failed",
                "couldn't write the new account to config.toml".to_string(),
            );
        }
        self.apply_config_from_disk(false);
        // Return the refreshed list so the client picks up the new account.
        self.handle_accounts_list(id)
    }

    /// `accounts.remove`: unregister an account by id — remove its `[[accounts]]` block
    /// from config.toml and reload. Does NOT delete the config-home directory or any
    /// credentials (the entry can be re-added later). Returns the refreshed
    /// `accounts.list`; errors if the id is not a known account.
    pub(super) fn handle_accounts_remove(
        &mut self,
        id: String,
        params: crate::api::schema::AccountsRemoveParams,
    ) -> String {
        let target = params.id.trim().to_string();
        if !self
            .loaded_accounts
            .iter()
            .any(|account| account.id == target)
        {
            return super::responses::encode_error(
                id,
                "unknown_account",
                format!("no account with id '{target}'"),
            );
        }
        let removed_id = target;
        let wrote = self.update_config_file("remove account", move |content| {
            crate::config::remove_accounts_block(content, &removed_id)
        });
        if !wrote {
            return super::responses::encode_error(
                id,
                "config_write_failed",
                "couldn't update config.toml".to_string(),
            );
        }
        self.apply_config_from_disk(false);
        self.handle_accounts_list(id)
    }

    /// The usage to report for one account, without ever blocking the app loop.
    ///
    /// For a kind with a live provider (Codex/Claude): serve a fresh (< per-kind
    /// TTL) live-cache entry when present; otherwise kick at most one background
    /// live fetch and, for THIS response, fall back to the local read. Kimi and
    /// unknown kinds skip the fetch entirely and use the local read.
    fn account_usage_cached(&mut self, account: &AccountConfig) -> (Option<AccountUsage>, bool) {
        if super::usage_fetch::kind_supports_live_usage(&account.kind) {
            // Copy out what this response needs so the immutable cache borrow ends before
            // the in-flight set below is touched mutably.
            let cached = self
                .usage_cache
                .get(&account.id)
                .map(|cached| (cached.fetched_at, cached.usage.clone(), cached.active));
            let fresh = cached.as_ref().is_some_and(|(fetched_at, _, _)| {
                fetched_at.elapsed() < super::usage_fetch::usage_ttl(&account.kind)
            });
            if !fresh {
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
            // SERVE A STALE READING RATHER THAN A BLANK ONE.
            //
            // A merely-stale cache used to be discarded here, dropping the response to the
            // local read below — which for claude reports NO usage windows at all, because
            // claude has no local usage source the way codex does. The visible effect was
            // a meter that emptied itself the moment the TTL lapsed and stayed empty for
            // as long as live fetches kept failing, which reads as "my usage disappeared"
            // rather than "this number is a few minutes old".
            //
            // A slightly old number is strictly better than no number, and the refresh
            // kicked above replaces it as soon as it lands. Only a genuinely empty cache
            // falls through to the local read.
            if let Some((_, usage, active)) = cached {
                return (Some(usage), active);
            }
        }
        // No cached reading at all: the honest local read (a real snapshot for codex,
        // metadata-only for claude).
        account_usage(account)
    }

    /// Resolve an account id (matching the agent's kind) to the launch env that
    /// points the harness at that account's config-home AND clears credentials
    /// that would outrank it. Note the override set can be empty while the
    /// clear-list is not — see [`crate::config::AccountLaunchEnv`].
    pub(crate) fn resolve_account_launch_env(
        &self,
        account_id: &str,
        agent_kind: &str,
    ) -> Result<crate::config::AccountLaunchEnv, AccountResolveError> {
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

/// Whether an account could host a resumed agent, for `accounts.list`.
///
/// Delegates to the SAME gate the swap path enforces
/// (`super::agents::claude_account_launch_blocker`) rather than restating its rules —
/// a second copy would drift, and then the list would promise a readiness the swap
/// refuses. Passing `cwd: None` deliberately limits this to account-wide blockers
/// (logged out, first run incomplete); per-directory trust is not an account property
/// and cannot be judged without knowing where an agent would resume.
///
/// Returns `None` for kinds with no readiness gate. `None` is NOT "ready" — the field
/// is documented as "not assessed" so a client cannot read a missing value as a pass.
fn account_readiness(account: &AccountConfig) -> Option<AccountReadiness> {
    if account.kind != "claude" {
        return None;
    }
    Some(
        match super::agents::claude_account_launch_blocker(&account.config_dir, None) {
            None => AccountReadiness {
                ready: true,
                blocker: None,
                detail: None,
            },
            Some(blocker) => AccountReadiness {
                ready: false,
                blocker: Some(blocker.code().to_string()),
                detail: Some(blocker.message(&account.id)),
            },
        },
    )
}

/// Claude email: `<config_dir>/.claude.json` -> `oauthAccount.emailAddress`
/// (a scoped lookup — `.claude.json` is large, so avoid a tree-wide search).
fn read_claude_email(config_dir: &str) -> Option<String> {
    read_claude_config_json(config_dir)?
        .get("oauthAccount")
        .and_then(|oauth| oauth.get("emailAddress"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Load Claude's `.claude.json`. Normally `<config_dir>/.claude.json`, but a
/// DEFAULT install keeps that file as a SIBLING of `~/.claude`
/// (i.e. `~/.claude.json`), not inside it. So when `config_dir` is the default
/// config-home and has no inner `.claude.json`, fall back to `$HOME/.claude.json`
/// — otherwise the primary account's email always reads as null. See issue #94.
fn read_claude_config_json(config_dir: &str) -> Option<serde_json::Value> {
    let inner = Path::new(config_dir).join(".claude.json");
    let raw = match std::fs::read_to_string(&inner) {
        Ok(text) => text,
        Err(_) if crate::config::is_default_config_dir("claude", config_dir) => {
            let fallback = crate::config::default_config_dir("claude")?
                .parent()?
                .join(".claude.json");
            std::fs::read_to_string(fallback).ok()?
        }
        Err(_) => return None,
    };
    serde_json::from_str(&raw).ok()
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

    fn acct(id: &str, kind: &str, config_dir: &str) -> AccountConfig {
        AccountConfig {
            id: id.to_string(),
            kind: kind.to_string(),
            label: id.to_string(),
            config_dir: config_dir.to_string(),
        }
    }

    #[test]
    fn fresh_account_id_slugs_the_label_and_dedupes() {
        let existing = vec![acct("claude", "claude", "/root/.claude")];
        assert_eq!(fresh_account_id(&existing, "claude", "My Work!"), "my-work");
        // Base already an id → suffix.
        assert_eq!(fresh_account_id(&existing, "claude", "claude"), "claude-2");
        // Empty/symbol-only label → fall back to the kind.
        assert_eq!(fresh_account_id(&existing, "codex", "  ---  "), "codex");
    }

    #[test]
    fn derive_fresh_config_dir_is_none_for_a_kind_without_a_default() {
        assert_eq!(derive_fresh_config_dir(&[], "gemini"), None);
    }

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
            crate::config::AccountLaunchEnv {
                vars: vec![("CODEX_HOME".to_string(), "/home/x/.codex-work".to_string())],
                clear_vars: Vec::new(),
            }
        );
        assert_eq!(
            app.resolve_account_launch_env("personal", "claude")
                .unwrap(),
            crate::config::AccountLaunchEnv {
                vars: vec![(
                    "CLAUDE_CONFIG_DIR".to_string(),
                    "/home/x/.claude-personal".to_string()
                )],
                clear_vars: vec!["CLAUDE_CODE_OAUTH_TOKEN".to_string()],
            }
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
    fn accounts_list_response_carries_readiness_on_the_wire() {
        // The struct field is not the deliverable — the client reads JSON. This asserts the
        // shape a client actually receives, including that a codex account carries NO
        // readiness key at all rather than an optimistic one.
        let dir = std::env::temp_dir().join(format!("herdr-wire-readiness-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".credentials.json"), "{\"claudeAiOauth\":{}}").unwrap();
        std::fs::write(dir.join(".claude.json"), "{\"oauthAccount\":{}}").unwrap();

        let mut app = test_app_with_accounts(vec![
            account("signed-in", "claude", &dir.display().to_string()),
            account("cx", "codex", "/tmp/does-not-exist-codex-readiness"),
        ]);
        let response = app.handle_accounts_list("req".into());
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();

        let claude = &value["result"]["accounts"][0];
        assert_eq!(claude["readiness"]["ready"], serde_json::json!(false));
        assert_eq!(
            claude["readiness"]["blocker"],
            serde_json::json!("account_onboarding_incomplete")
        );
        // Absent, not `ready: true` — a client must not read silence as a pass.
        assert!(value["result"]["accounts"][1].get("readiness").is_none());

        let _ = std::fs::remove_dir_all(&dir);
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

    /// A STALE reading is still served, and a refresh is scheduled behind it.
    ///
    /// This test previously asserted the opposite — that a stale entry is discarded and the
    /// response drops to the local read. That WAS the behaviour, and it is what made the
    /// owner's usage "disappear": claude has no local usage source (codex does), so
    /// discarding a stale entry emptied the meter the instant the TTL lapsed, and it stayed
    /// empty for as long as live fetches kept failing. A few-minutes-old number is strictly
    /// better than no number.
    #[test]
    fn stale_live_cache_entry_is_still_served_while_it_refreshes() {
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
        // The stale numbers are still there ...
        let usage = &value["result"]["accounts"][0]["usage"];
        assert_eq!(usage["windows"][0]["label"], "5h");
        assert_eq!(usage["windows"][0]["used_percent"], 50.0);
        // ... and a refresh is scheduled to replace them.
        assert!(app.usage_refresh_inflight.contains("work"));
    }

    /// The claude shape specifically: no local usage source, so discarding a stale cache
    /// leaves NOTHING. This is the exact case the owner hit — a meter that emptied itself —
    /// and it is why serving stale matters more for claude than for codex.
    #[test]
    fn a_stale_claude_reading_does_not_blank_the_meter() {
        let mut app = test_app_with_accounts(vec![account(
            "primary",
            "claude",
            "/tmp/does-not-exist-claude-stale",
        )]);
        let mut usage = AccountUsage {
            windows: vec![
                UsageWindow {
                    label: "5h".to_string(),
                    used_percent: Some(32.0),
                    resets_at: None,
                    status: Some("ok".to_string()),
                },
                UsageWindow {
                    label: "weekly".to_string(),
                    used_percent: Some(24.0),
                    resets_at: None,
                    status: Some("ok".to_string()),
                },
            ],
            source: Some("live".to_string()),
            ..Default::default()
        };
        usage.backfill_flat_fields();
        // Well beyond the claude TTL (300s).
        app.usage_cache.insert(
            "primary".to_string(),
            crate::app::api::usage_fetch::CachedUsage {
                fetched_at: std::time::Instant::now() - std::time::Duration::from_secs(3_600),
                usage,
                active: true,
            },
        );

        let response = app.handle_accounts_list("req".into());
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let usage = &value["result"]["accounts"][0]["usage"];
        assert_eq!(
            usage["windows"].as_array().map(Vec::len),
            Some(2),
            "a stale claude reading must not collapse to an empty meter"
        );
        assert_eq!(usage["windows"][0]["used_percent"], 32.0);
        assert!(app.usage_refresh_inflight.contains("primary"));
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

    fn claude_account(id: &str, config_dir: &str) -> AccountConfig {
        AccountConfig {
            id: id.to_string(),
            kind: "claude".to_string(),
            label: id.to_string(),
            config_dir: config_dir.to_string(),
        }
    }

    #[test]
    fn readiness_reports_signed_in_but_unprepared_as_not_ready() {
        // The exact shape `claude auth login` leaves behind, and the reason this field
        // exists: credentials present, first run never completed. `accounts.list` used to
        // show this account as a normal signed-in account, so nothing warned anybody
        // until a swap destroyed the seat.
        let dir = std::env::temp_dir().join(format!("herdr-readiness-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".credentials.json"), "{\"claudeAiOauth\":{}}").unwrap();
        std::fs::write(
            dir.join(".claude.json"),
            serde_json::json!({"oauthAccount": {"emailAddress": "user@example.com"}}).to_string(),
        )
        .unwrap();

        let readiness =
            account_readiness(&claude_account("acc", &dir.display().to_string())).unwrap();
        assert!(!readiness.ready);
        assert_eq!(
            readiness.blocker.as_deref(),
            Some("account_onboarding_incomplete")
        );
        assert!(readiness
            .detail
            .is_some_and(|detail| detail.contains("acc")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readiness_is_ready_once_first_run_is_complete_and_ignores_per_directory_trust() {
        // Trust is per working directory and cannot be judged from a list with no cwd, so
        // an onboarded account with NO trusted directories must still read ready here.
        // Reporting it as blocked would make every account look broken in the list.
        let dir = std::env::temp_dir().join(format!("herdr-readiness-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".credentials.json"), "{\"claudeAiOauth\":{}}").unwrap();
        std::fs::write(
            dir.join(".claude.json"),
            serde_json::json!({"hasCompletedOnboarding": true, "projects": {}}).to_string(),
        )
        .unwrap();

        let readiness =
            account_readiness(&claude_account("acc", &dir.display().to_string())).unwrap();
        assert!(readiness.ready);
        assert_eq!(readiness.blocker, None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readiness_reports_a_logged_out_account_before_onboarding() {
        // Order matters: an empty config-home is logged out, not un-onboarded. Reporting
        // onboarding here would send someone to run `prepare` on an account that needs a
        // login, and the wall would just move.
        let dir = std::env::temp_dir().join(format!("herdr-readiness-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let readiness =
            account_readiness(&claude_account("acc", &dir.display().to_string())).unwrap();
        assert!(!readiness.ready);
        assert_eq!(
            readiness.blocker.as_deref(),
            Some("account_not_authenticated")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readiness_is_none_for_kinds_with_no_gate() {
        // None means NOT ASSESSED. A client that reads a missing value as "ready" is
        // wrong, which is why the field is documented that way and codex returns None
        // rather than an optimistic `ready: true`.
        let mut account = claude_account("cx", "/nonexistent");
        account.kind = "codex".to_string();
        assert!(account_readiness(&account).is_none());
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
    fn claude_email_falls_back_to_sibling_for_the_default_home() {
        // Default install layout: config-home ~/.claude has NO inner .claude.json;
        // the real config file is the sibling ~/.claude.json. The primary account's
        // email must resolve from that sibling (issue #94), not read as null.
        let _guard = crate::config::test_config_env_lock().lock().unwrap();
        let prev = std::env::var_os("HOME");
        let home = std::env::temp_dir().join(format!("herdr-claude-home-{}", std::process::id()));
        let claude_dir = home.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            home.join(".claude.json"),
            serde_json::json!({
                "oauthAccount": {"emailAddress": "primary@example.com"}
            })
            .to_string(),
        )
        .unwrap();
        std::env::set_var("HOME", &home);

        // config_dir == $HOME/.claude, inner .claude.json absent -> sibling used.
        assert_eq!(
            read_claude_email(&claude_dir.display().to_string()).as_deref(),
            Some("primary@example.com")
        );
        // A non-default dir with no .claude.json still yields None (no sibling scan).
        assert!(read_claude_email(&home.join(".claude-other").display().to_string()).is_none());

        match prev {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
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
