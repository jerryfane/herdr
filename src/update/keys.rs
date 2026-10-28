//! The minisign public keys trusted to sign `distribution/preview.json`.
//!
//! Each entry is the base64 key line of a `minisign.pub` file (its second
//! line, `RW…`). Order is primary first, then the offline backup used for a
//! rotation. A manifest signed by any listed key is accepted; nothing else is.
//!
//! The primary key lives in the owner's keyring and is never exported; release
//! signing goes through the keyring's `minisign/herdr-release` route. The
//! backup key is kept offline by the owner and signs only during a rotation.
pub(super) const RELEASE_PUBLIC_KEYS: &[&str] = &[
    // herdr-release, minisign key id 1909BF13AB4A7686.
    "RWSGdkqrE78JGWTn7MjyejRu2MVri68/C2eM+3OMvY0Sh+WV1QH+tr4f",
    // herdr-release backup (offline), minisign key id 4EC2A8E66B478CBA.
    "RWS6jEdr5qjCTpeiTt4iNnIcgKUwz9q+o5NvIj36ZfR/0XUY0vAwDUpO",
];
