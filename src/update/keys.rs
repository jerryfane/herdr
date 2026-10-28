//! The minisign public keys trusted to sign `distribution/preview.json`.
//!
//! Each entry is the base64 key line of a `minisign.pub` file (its second
//! line, `RW…`). Order is primary first, then the offline backup used for a
//! rotation. A manifest signed by any listed key is accepted; nothing else is.
//!
//! The production key is generated in the owner's keyring and has not been
//! published yet. Until its line is added here, every manifest is refused with
//! `update_signature_invalid`, so neither `herdr update` nor the in-app update
//! installs anything.
pub(super) const RELEASE_PUBLIC_KEYS: &[&str] = &[];
