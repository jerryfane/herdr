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
    /// Whether the account is usable right now. `false` only when local usage
    /// data proves exhaustion (Codex over quota / rate-limit-reached); `true`
    /// otherwise, including when exhaustion cannot be detected locally.
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<AccountUsage>,
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
