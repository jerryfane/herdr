//! Device keys (`pair.*`): the SSH keys of the owner's devices, kept in this
//! machine's `~/.ssh/authorized_keys` with the `herdr-pair` marker. Owner
//! only: guests, owner browsers, federation peers and fenced callers are
//! refused. macOS and Linux only (ping reports `pair_add_key`). Unknown
//! params are refused rather than ignored.

use serde::{Deserialize, Serialize};

/// `pair.add_key`: authorize one device key for SSH as this machine's user.
/// The line written is `ssh-ed25519 <material> herdr-pair:<label>`; the key's
/// own comment is dropped. Adding a key whose material is already in the
/// file changes nothing and replies `added: false, already: true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairAddKeyParams {
    /// An OpenSSH `ssh-ed25519` public key line. Other key types are refused
    /// with `pair_key_invalid`.
    pub public_key: String,
    /// The device's name: 1 to 80 characters without newlines or other
    /// control characters (else `pair_label_invalid`). It is stored reduced to
    /// letters, digits, spaces and `-_.'`, at most 48 characters.
    pub label: String,
}

/// `pair.keys.list`: the `herdr-pair` lines of `authorized_keys`. Other
/// lines are never listed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairKeysListParams {}

/// `pair.keys.remove`: remove the `herdr-pair` lines holding this key. Other
/// lines, a user's own line for the same key included, are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairKeysRemoveParams {
    /// `SHA256:…`, as `pair.keys.list` and `ssh-keygen -l` show it.
    pub fingerprint: String,
}

/// One `herdr-pair` line of `authorized_keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PairKeyInfo {
    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub fingerprint: String,
    /// The text after `herdr-pair:`; empty for a bare marker.
    pub label: String,
    /// Everything after the key material.
    pub comment: String,
}
