use serde::{Deserialize, Serialize};

/// A configured credential/config-home account, as returned by `accounts.list`.
///
/// Reports only non-secret metadata: the account id, harness kind, label, and
/// best-effort usage NUMBERS. It never carries a token, key, or any credential
/// value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccountInfo {
    pub id: String,
    pub kind: String,
    pub label: String,
    /// The account's config-home directory (e.g. `/root/.claude-2`) — where its
    /// credentials live. A non-secret path, not a credential. The app needs it to
    /// point a login/logout at the right account (`CLAUDE_CONFIG_DIR=<config_dir>`).
    pub config_dir: String,
    /// Whether the account is usable right now. `false` only when local usage
    /// data proves exhaustion (Codex over quota / rate-limit-reached); `true`
    /// otherwise, including when exhaustion cannot be detected locally.
    pub active: bool,
    /// The account's login email, when derivable from its config-home (Claude's
    /// `.claude.json`, Codex's `auth.json` id-token). Identity only — never a
    /// token or secret. None for kinds/accounts with no local email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<AccountUsage>,
    /// Whether this account could host a resumed agent right now, and if not, the
    /// first reason why. `None` means NOT ASSESSED for this kind — it does not mean
    /// ready. Only Claude accounts have a readiness gate today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<AccountReadiness>,
}

/// Whether an account is in a state that can host a resumed agent.
///
/// This exists because authentication is not readiness. An account can hold valid
/// credentials and still strand every agent moved onto it: a config-home that has
/// never completed Claude Code's first run opens the theme picker instead of resuming,
/// which is how the Aug 27 bulk-switch destroyed eleven live seats. The daemon has
/// always known this at swap time; reporting it in `accounts.list` is what lets a
/// client say so BEFORE someone moves a seat onto the account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccountReadiness {
    /// True when nothing detectable locally would stop a resumed agent from launching.
    pub ready: bool,
    /// Stable machine code of the FIRST blocker found, e.g. `account_not_authenticated`
    /// or `account_onboarding_incomplete`. `None` when `ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    /// Human-readable explanation of that blocker, suitable for showing to a person.
    /// `None` when `ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// `accounts.create` — register a NEW credential account (in-app add-account). Creates
/// the config-home directory and appends an `[[accounts]]` entry to config.toml, then
/// reloads so it shows up in `accounts.list`. The client then drives login into it. It
/// stores only non-secret metadata; no credential is written here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccountsCreateParams {
    /// Harness kind: claude/codex/kimi.
    pub kind: String,
    /// Human label shown in the list.
    pub label: String,
    /// Config-home directory to use. Absent → the server derives a fresh default for the
    /// kind (e.g. `~/.claude-<n>`) that does not collide with an existing account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<String>,
}

/// `accounts.remove` — unregister an account (in-app remove-account). Removes its
/// `[[accounts]]` entry from config.toml and reloads. Does NOT delete the config-home
/// directory or any credentials — the entry can be re-added later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccountsRemoveParams {
    /// The account id to unregister.
    pub id: String,
}

/// One rate-limit window for an account (e.g. a 5-hour or weekly bucket).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct UsageWindow {
    /// Short window label, e.g. "5h", "weekly", "7d".
    pub label: String,
    /// Percent of this window consumed (0..100), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_percent: Option<f32>,
    /// When this window resets (opaque string; may be an epoch or timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    /// Window status, e.g. "ok" or "exhausted", when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Best-effort usage for an account. Every field is optional so the call
/// degrades honestly when a harness exposes nothing (Kimi), only a plan
/// (Claude), or a full snapshot (Codex). Percentages only — no token is read.
///
/// `windows` is the current shape (any number of rate-limit buckets). The flat
/// `primary_used_percent`/`secondary_used_percent`/`resets_at` mirror the first
/// two windows and are kept ONLY for back-compat with app versions shipped
/// before `windows` existed — populate them from `windows` when building this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct AccountUsage {
    /// Per-window usage buckets (5h / weekly / …). The forward-looking shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<UsageWindow>,
    /// Where the numbers came from: "live" (fetched from the provider) or
    /// "local" (read from on-disk session logs / credentials). None when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Back-compat: primary (e.g. 5h) window used-percent (= `windows[0]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_used_percent: Option<f32>,
    /// Back-compat: secondary (e.g. weekly) window used-percent (= `windows[1]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_used_percent: Option<f32>,
    /// Back-compat: when the primary window resets (= `windows[0].resets_at`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    /// Plan/subscription name, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Rate-limit tier string, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

impl AccountUsage {
    /// Fill the back-compat flat fields from `windows` (the first two buckets)
    /// so app versions predating `windows` still render usage. Call after
    /// setting `windows`.
    pub fn backfill_flat_fields(&mut self) {
        if let Some(primary) = self.windows.first() {
            self.primary_used_percent = primary.used_percent;
            if self.resets_at.is_none() {
                self.resets_at = primary.resets_at.clone();
            }
        }
        if let Some(secondary) = self.windows.get(1) {
            self.secondary_used_percent = secondary.used_percent;
        }
    }
}
