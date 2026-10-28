//! The minisign public keys trusted to sign `distribution/preview.json`.
//!
//! Each entry is the base64 key line of a `minisign.pub` file (its second
//! line, `RW…`). Order is primary first, then the offline backup used for a
//! rotation. A manifest signed by any listed key is accepted; nothing else is.
//!
//! The primary key lives in the owner's keyring and is never exported; release
//! signing goes through the keyring's `minisign/herdr-release` route. The
//! offline backup key is still to be made.
pub(super) const RELEASE_PUBLIC_KEYS: &[&str] = &[
    // herdr-release, minisign key id 1909BF13AB4A7686.
    "RWSGdkqrE78JGWTn7MjyejRu2MVri68/C2eM+3OMvY0Sh+WV1QH+tr4f",
];
