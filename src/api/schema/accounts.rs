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

/// Best-effort, locally-derived usage for an account. Every field is optional so
/// the call degrades honestly when a harness exposes nothing (Kimi), only a plan
/// (Claude), or a full snapshot (Codex). Percentages only — no token is read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct AccountUsage {
    /// Primary (e.g. 5h) window used-percent, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_used_percent: Option<f32>,
    /// Secondary (e.g. weekly) window used-percent, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_used_percent: Option<f32>,
    /// When the primary window resets, as reported by the harness (opaque
    /// string; may be an epoch or timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    /// Plan/subscription name, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Rate-limit tier string, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}
