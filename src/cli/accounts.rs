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
        Some("prepare") => run_prepare(&args[1..]),
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

/// `herdr accounts prepare <id> [--trust <dir>]…` — complete Claude Code's first run for
/// an account's config-home so a resumed agent launches instead of hitting a picker.
///
/// This exists because signing in is not the same as being ready. `claude auth login`
/// writes credentials and `oauthAccount` and, by design, nothing else — so an account
/// added through the app is authenticated and still opens the theme picker on first
/// launch. Moving a live seat onto it destroys that seat to reach a modal, which is the
/// Aug 27 incident. `accounts.list` now REPORTS that state; this is the remedy for it.
///
/// Writes only the keys a real first run writes, verified 2026-08-30 by A/B on a copy of
/// a real profile: with them, `claude` reaches the composer directly; without them the
/// same profile in the same directory shows the theme picker.
fn run_prepare(args: &[String]) -> std::io::Result<i32> {
    let mut id: Option<&str> = None;
    let mut trust: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(0);
            }
            "--trust" => {
                i += 1;
                match args.get(i) {
                    // Trust keys are absolute paths. A relative one would be written
                    // verbatim and then never match the cwd an agent resumes in — a
                    // silent no-op, so refuse instead of writing something inert.
                    Some(dir) if dir.starts_with('/') => trust.push(dir.clone()),
                    Some(dir) => {
                        eprintln!("--trust needs an absolute path, got {dir:?}");
                        return Ok(2);
                    }
                    None => {
                        eprintln!("--trust takes a directory");
                        return Ok(2);
                    }
                }
            }
            other if id.is_none() && !other.starts_with('-') => id = Some(other),
            other => {
                eprintln!("unknown option {other:?}");
                print_help();
                return Ok(2);
            }
        }
        i += 1;
    }

    let Some(id) = id else {
        eprintln!("usage: herdr accounts prepare <id> [--trust <dir>]...");
        return Ok(2);
    };

    let config = Config::load().config;
    let Some(account) = config.accounts.iter().find(|account| account.id == id) else {
        eprintln!("no account {id:?} in config.toml");
        return Ok(1);
    };
    if account.kind != "claude" {
        eprintln!(
            "account {id:?} is kind {:?}; only claude accounts have a first-run to complete",
            account.kind
        );
        return Ok(1);
    }
    // Preparing a logged-out profile would satisfy the onboarding gate and then strand the
    // seat on the NEXT one, which reads as the fix having done nothing.
    if !crate::app::claude_account_has_credentials(&account.config_dir) {
        eprintln!(
            "account {id:?} has no credentials in {} — sign it in first",
            account.config_dir
        );
        return Ok(1);
    }

    // Ask the harness its version rather than inventing one: `lastOnboardingVersion` is a
    // claim about which first run completed, and a made-up value is a false claim. This is
    // a CLI, so a subprocess is fine here — the rule against one applies to the request
    // handler, which must not block.
    let version = match claude_version() {
        Some(version) => version,
        None => {
            eprintln!("could not run `claude --version` to record which first run completed");
            return Ok(1);
        }
    };

    // Resolve through the shared helper: a DEFAULT config-home keeps `.claude.json` as a
    // SIBLING (issue #94), and writing an inner copy there would produce a file Claude
    // Code never reads while every check reported success.
    let path = crate::app::claude_config_file(&account.config_dir);
    if let Err(err) = write_prepared_config(&path, &version, &trust) {
        eprintln!("could not prepare {}: {err}", path.display());
        return Ok(1);
    }

    println!("prepared {id} ({})", path.display());
    println!("  hasCompletedOnboarding  true");
    println!("  lastOnboardingVersion   {version}");
    if trust.is_empty() {
        println!("  trusted directories     none requested — an agent resuming in an");
        println!("                          untrusted cwd will still be refused");
    } else {
        for dir in &trust {
            println!("  trusted directory       {dir}");
        }
    }
    Ok(0)
}

/// Merge the first-run keys into an existing Claude config file, in place.
///
/// MERGES, never replaces. The file it is handed is a real profile carrying
/// `oauthAccount`, per-project history and caches; rewriting it from scratch would log
/// the account out and lose every other directory's trust while reporting success.
fn write_prepared_config(
    path: &std::path::Path,
    version: &str,
    trust: &[String],
) -> std::io::Result<()> {
    let mut doc = match std::fs::read_to_string(path) {
        // An unparsable file is NOT treated as absent: overwriting it would discard a
        // profile we failed to understand. Refuse and let a person look at it.
        Ok(raw) => serde_json::from_str::<serde_json::Value>(&raw).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("existing config is not valid JSON ({err}); refusing to overwrite it"),
            )
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(err) => return Err(err),
    };
    let Some(object) = doc.as_object_mut() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "existing config is not a JSON object; refusing to overwrite it",
        ));
    };

    object.insert(
        "hasCompletedOnboarding".into(),
        serde_json::Value::Bool(true),
    );
    object.insert(
        "lastOnboardingVersion".into(),
        serde_json::Value::String(version.to_string()),
    );

    let projects = object
        .entry("projects")
        .or_insert_with(|| serde_json::json!({}));
    if !projects.is_object() {
        *projects = serde_json::json!({});
    }
    if let Some(projects) = projects.as_object_mut() {
        for dir in trust {
            let entry = projects
                .entry(dir.clone())
                .or_insert_with(|| serde_json::json!({}));
            if !entry.is_object() {
                *entry = serde_json::json!({});
            }
            if let Some(entry) = entry.as_object_mut() {
                entry.insert(
                    "hasTrustDialogAccepted".into(),
                    serde_json::Value::Bool(true),
                );
            }
        }
    }

    let serialized = serde_json::to_string_pretty(&doc)
        .map(|text| format!("{text}\n"))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    // Write-then-rename: Claude Code rewrites this file constantly, and a half-written
    // config is worse than an unprepared one.
    let temp = path.with_extension("json.herdr-prepare");
    std::fs::write(&temp, serialized)?;
    std::fs::rename(&temp, path)
}

/// The installed harness version, as `claude --version` reports it (`2.1.251 (Claude Code)`
/// -> `2.1.251`). `None` when the binary cannot be run or prints nothing usable.
fn claude_version() -> Option<String> {
    let output = std::process::Command::new("claude")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.split_whitespace().next()?;
    // Guard against a banner or a warning line arriving first: only a dotted numeric
    // version is a version.
    if first.split('.').count() >= 2 && first.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        Some(first.to_string())
    } else {
        None
    }
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
            .map(|env| env.vars.into_iter().collect::<BTreeMap<String, String>>());
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
    println!(
        "{:<22} {:<8} {:<22} {}",
        "id", "kind", "config_dir", "launch env"
    );
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
    println!("       herdr accounts prepare <id> [--trust <dir>]...");
    println!();
    println!("list     List the configured [[accounts]] and the launch env each one injects.");
    println!("         Reads config.toml directly — no running daemon required. Definitions");
    println!("         only; live usage/active comes from the daemon via `accounts.list`.");
    println!();
    println!("prepare  Complete Claude Code's first run for an account's config-home, and");
    println!("         trust the directories agents will resume in. Signing in does NOT do");
    println!("         this: `claude auth login` writes credentials and nothing else, so a");
    println!("         freshly signed-in account still opens the theme picker on launch and");
    println!("         any agent moved onto it is destroyed reaching that picker.");
    println!();
    println!("         Run it while the account is idle — Claude Code rewrites this file as");
    println!("         it runs, and a concurrent write would be lost.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_config_dir;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "herdr-prepare-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn prepare_merges_and_never_discards_the_existing_profile() {
        // The failure this guards is silent and total: a prepare that REPLACED the file
        // would clear the gate, report success, and log the account out — because
        // `oauthAccount` lives in this same file. It would look like it worked.
        let dir = temp_dir("merge");
        let path = dir.join(".claude.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "oauthAccount": {"emailAddress": "user@example.com"},
                "userID": "keep-me",
                "projects": {
                    "/already/trusted": {"hasTrustDialogAccepted": true, "allowedTools": ["Bash"]}
                }
            })
            .to_string(),
        )
        .unwrap();

        write_prepared_config(&path, "2.1.251", &["/root/new".to_string()]).unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["hasCompletedOnboarding"], serde_json::json!(true));
        assert_eq!(doc["lastOnboardingVersion"], serde_json::json!("2.1.251"));
        // Identity and unrelated state survive.
        assert_eq!(doc["oauthAccount"]["emailAddress"], "user@example.com");
        assert_eq!(doc["userID"], "keep-me");
        // A pre-existing project keeps its own keys, not just its trust flag.
        assert_eq!(
            doc["projects"]["/already/trusted"]["allowedTools"][0],
            "Bash"
        );
        assert_eq!(
            doc["projects"]["/root/new"]["hasTrustDialogAccepted"],
            serde_json::json!(true)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_flips_an_existing_untrusted_directory_rather_than_skipping_it() {
        // `claude -p` leaves an entry with hasTrustDialogAccepted FALSE. An
        // entry-exists-so-leave-it implementation would silently do nothing here and the
        // swap would still be refused.
        let dir = temp_dir("flip");
        let path = dir.join(".claude.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "projects": {"/root/repo": {"hasTrustDialogAccepted": false}}
            })
            .to_string(),
        )
        .unwrap();

        write_prepared_config(&path, "2.1.251", &["/root/repo".to_string()]).unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            doc["projects"]["/root/repo"]["hasTrustDialogAccepted"],
            serde_json::json!(true)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_refuses_an_unparsable_config_instead_of_replacing_it() {
        let dir = temp_dir("garbage");
        let path = dir.join(".claude.json");
        std::fs::write(&path, "{not json").unwrap();

        let err = write_prepared_config(&path, "2.1.251", &[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // Untouched: refusing means refusing, not refusing-after-writing.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_creates_the_config_when_the_home_has_none_yet() {
        let dir = temp_dir("fresh");
        let path = dir.join(".claude.json");
        write_prepared_config(&path, "2.1.251", &[]).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["hasCompletedOnboarding"], serde_json::json!(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_refuses_a_relative_trust_path() {
        // A relative path would be written verbatim and never match the absolute cwd an
        // agent resumes in — a write that changes the file and fixes nothing.
        let args = vec![
            "some-account".to_string(),
            "--trust".to_string(),
            "relative/dir".to_string(),
        ];
        assert_eq!(run_prepare(&args).unwrap(), 2);
    }

    #[test]
    fn prepare_needs_an_account_id() {
        assert_eq!(run_prepare(&[]).unwrap(), 2);
    }

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
        let row = AccountRow::from(&account(
            "codex-work",
            "codex",
            "/opt/gitmoot-runtime/codex-work",
        ));
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
