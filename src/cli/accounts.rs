//! `herdr accounts list [--json]` — read-only account DEFINITIONS from config.
//!
//! Reads `config.toml` directly (via `Config::load`, no daemon required) and emits, per configured
//! `[[accounts]]` entry, its id/kind/label/config_dir plus the RESOLVED launch env. This is the
//! offline contract gitmoot consumes to select an account and inject its env: it hands back
//! `AccountConfig::launch_env()` as a value so gitmoot never has to re-derive the (non-trivial)
//! default-config-home rule. That rule — `is_default_config_dir` → inject NO env — exists because
//! Claude Code keeps `~/.claude.json` as a sibling of `~/.claude`, so forcing `CLAUDE_CONFIG_DIR` on a
//! default install strands it and boots a blank profile (issue #94). Emitting the resolved env means
//! that rule lives in exactly one place.
//!
//! Definitions ONLY — no usage / active. Live usage stays on the daemon's `accounts.list`
//! (definitions offline, live signal online).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::{AccountConfig, Config};

pub(super) fn run_accounts_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(|arg| arg.as_str()) {
        Some("list") => run_list(&args[1..]),
        None | Some("--help") | Some("-h") | Some("help") => {
            print_help();
            Ok(0)
        }
        Some(other) => {
            eprintln!("unknown accounts command: {other}");
            print_help();
            Ok(2)
        }
    }
}

fn run_list(args: &[String]) -> std::io::Result<i32> {
    let json = match args.first().map(|arg| arg.as_str()) {
        None => false,
        Some("--json") if args.len() == 1 => true,
        _ => {
            eprintln!("usage: herdr accounts list [--json]");
            return Ok(2);
        }
    };

    let rows: Vec<AccountRow> = Config::load()
        .config
        .accounts
        .iter()
        .map(AccountRow::from)
        .collect();

    if json {
        // Pretty, stable (BTreeMap keys sort) JSON array — the contract gitmoot parses.
        match serde_json::to_string_pretty(&rows) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("error: could not serialize accounts: {err}");
                return Ok(1);
            }
        }
    } else {
        print_table(&rows);
    }
    Ok(0)
}

/// One account's offline definition + its resolved launch env.
#[derive(Debug, Serialize)]
struct AccountRow {
    id: String,
    kind: String,
    label: String,
    config_dir: String,
    /// The env to set when launching this account, resolved from `AccountConfig::launch_env`:
    /// `{}` for a default-config-home account (issue #94 — inject nothing), `{VAR: path}` otherwise,
    /// and `null` when the kind has no config-home lever (unknown/unsupported kind).
    launch_env: Option<BTreeMap<String, String>>,
}

impl From<&AccountConfig> for AccountRow {
    fn from(account: &AccountConfig) -> Self {
        let launch_env = account
            .launch_env()
            .map(|pairs| pairs.into_iter().collect::<BTreeMap<String, String>>());
        Self {
            id: account.id.clone(),
            kind: account.kind.clone(),
            label: account.label.clone(),
            config_dir: account.config_dir.clone(),
            launch_env,
        }
    }
}

fn print_table(rows: &[AccountRow]) {
    if rows.is_empty() {
        println!("no accounts configured (see [[accounts]] in config.toml)");
        return;
    }
    println!("{:<22} {:<8} {:<22} {}", "id", "kind", "config_dir", "launch env");
    for row in rows {
        let env = match &row.launch_env {
            None => "(no env lever for this kind)".to_string(),
            Some(map) if map.is_empty() => "(default install — no override)".to_string(),
            Some(map) => map
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", "),
        };
        println!(
            "{:<22} {:<8} {:<22} {}",
            row.id, row.kind, row.config_dir, env
        );
    }
}

fn print_help() {
    println!("usage: herdr accounts list [--json]");
    println!();
    println!("List the configured [[accounts]] and the launch env each one injects.");
    println!("Reads config.toml directly — no running daemon required. Definitions only;");
    println!("live usage/active is available from the daemon via `accounts.list`.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_config_dir;

    fn account(id: &str, kind: &str, config_dir: &str) -> AccountConfig {
        AccountConfig {
            id: id.to_string(),
            kind: kind.to_string(),
            label: id.to_string(),
            config_dir: config_dir.to_string(),
        }
    }

    #[test]
    fn default_config_home_account_injects_no_env() {
        // A claude account sitting at the harness default config-home must resolve to an EMPTY env
        // ({} in JSON), never CLAUDE_CONFIG_DIR — issue #94, or it strands ~/.claude.json.
        let default_dir = default_config_dir("claude")
            .expect("claude has a default config dir")
            .to_string_lossy()
            .into_owned();
        let row = AccountRow::from(&account("claude-primary", "claude", &default_dir));
        assert_eq!(row.launch_env, Some(BTreeMap::new()));
        assert_eq!(
            serde_json::to_value(&row).unwrap()["launch_env"],
            serde_json::json!({})
        );
    }

    #[test]
    fn non_default_config_home_account_injects_its_env() {
        let row = AccountRow::from(&account("codex-work", "codex", "/opt/gitmoot-runtime/codex-work"));
        assert_eq!(
            row.launch_env,
            Some(BTreeMap::from([(
                "CODEX_HOME".to_string(),
                "/opt/gitmoot-runtime/codex-work".to_string()
            )]))
        );
    }

    #[test]
    fn unknown_kind_has_null_launch_env() {
        let row = AccountRow::from(&account("mystery", "gemini", "/opt/whatever"));
        assert_eq!(row.launch_env, None);
        assert_eq!(
            serde_json::to_value(&row).unwrap()["launch_env"],
            serde_json::Value::Null
        );
    }
}
