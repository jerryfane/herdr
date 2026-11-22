//! Owner access (`owner_access.*`): the owner's own browsers, each allowed on
//! this machine by an owner grant. Owner only: guests, federation peers and
//! fenced callers are refused. The apps call these on each machine over SSH;
//! there is no `machine` routing, and unknown params (a `machine` included)
//! are refused rather than ignored.
//!
//! Every key and statement is unpadded base64url (RFC 4648 §5); padding is
//! refused.

use serde::{Deserialize, Serialize};

/// What a granted browser may do on this machine.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnerScope {
    /// Agents only: read and talk to local agents.
    Chat,
    /// Agents and their terminals. A terminal is a shell on this machine.
    #[default]
    Terminal,
}

/// `owner_access.info`: this machine's relay identity, created on first use.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessInfoParams {}

/// `owner_access.list`: every owner grant kept, revoked and expired ones
/// included until they are deleted 30 days after they ended.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessListParams {}

/// `owner_access.add`: allow one browser key on this machine, bound to the
/// account of the device approving it. A live grant for the same key is
/// replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessAddParams {
    /// The browser's X25519 key (its Noise key), unpadded base64url of 32
    /// bytes.
    pub device_pub: String,
    /// For example `Chrome on macOS`: 1 to 64 printable characters.
    pub device_name: String,
    /// Default: `terminal`.
    #[serde(default)]
    pub scope: OwnerScope,
    /// Grant lifetime in seconds, 3600 to 2592000 (1 hour to 30 days).
    /// Anything else is refused with `owner_ttl_invalid`, never clamped.
    pub ttl_secs: u64,
    /// The approving device's own account statement for this machine
    /// (`aud` = `host_id` from `owner_access.info`). Its `sub` becomes the
    /// grant's account.
    pub account_statement: String,
    /// The approving device's name, for display: 1 to 64 printable
    /// characters.
    pub approved_by: String,
}

/// `owner_access.renew`: `expires = now + ttl_secs` (not added to the time
/// left). Revives an expired grant that was not removed, within 30 days of
/// its expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessRenewParams {
    pub grant_id: String,
    /// 3600 to 2592000, as for `owner_access.add`.
    pub ttl_secs: u64,
    /// Change the scope; unchanged when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<OwnerScope>,
}

/// `owner_access.remove`: exactly one of `grant_id`, `device_pub` or
/// `fingerprint`. Unknown or already removed grants answer `removed: []`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessRemoveParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// One owner grant. The account it is bound to is never shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerGrantInfo {
    pub grant_id: String,
    /// The browser's key, unpadded base64url.
    pub device_pub: String,
    /// `SHA256:` plus the first 8 bytes of SHA-256(device key), as for guests.
    pub fingerprint: String,
    pub device: String,
    pub scope: OwnerScope,
    pub approved_by: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub renewed_ms: Option<u64>,
    pub last_seen_ms: Option<u64>,
    /// Removed (`owner_access.remove`) or replaced by a newer grant for the
    /// same key. A revoked grant is never renewed.
    pub revoked: bool,
}
