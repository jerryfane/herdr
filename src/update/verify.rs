//! The signed preview manifest, shared by `herdr update` and the
//! `server.update_*` API.
//!
//! The manifest and its `.minisig` come only from the compiled-in URL and its
//! sibling. The signature must be a prehashed (`ED`) minisign signature by one
//! of the keys in [`super::keys`]; legacy signatures are refused. Its trusted
//! comment must be `herdr-preview <build_id> <commit>` for this very manifest,
//! so a signature can't be paired with another build's manifest. The signed
//! `commit_time` is what stops a replayed old manifest from downgrading a
//! server ([`RunningBuild::is_older_than`]).
//!
//! Debug builds accept three environment overrides so integration tests can
//! serve a manifest from a loopback origin, sign it with a throwaway key, and
//! offer the test binary to itself. Release builds compile all of them out.

use super::{PreviewManifest, EXPECTED_RELEASE_ROOT, PREVIEW_UPDATE_MANIFEST_URL};

const TRUSTED_COMMENT_PREFIX: &str = "herdr-preview ";
const MANIFEST_SCHEMA_VERSION: u32 = 2;
/// Upper bound for any asset, whatever size the manifest states.
pub(super) const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4 * 1024;
/// Longest accepted `build_id`; real ones are `YYYY-MM-DD-<12 hex>`.
const MAX_BUILD_ID_LEN: usize = 64;
#[cfg(debug_assertions)]
const DISTRIBUTION_ROOT: &str =
    "https://raw.githubusercontent.com/jerryfane/herdr/master/distribution/";

/// Debug builds only: a `http://127.0.0.1:<port>` origin that stands in for
/// both `raw.githubusercontent.com/…/distribution/` and the release root.
#[cfg(debug_assertions)]
pub(crate) const TEST_ORIGIN_ENV: &str = "HERDR_UPDATE_TEST_ORIGIN";
/// Debug builds only: one more trusted public key, for a test's own key pair.
#[cfg(debug_assertions)]
pub(crate) const TEST_PUBLIC_KEY_ENV: &str = "HERDR_UPDATE_TEST_PUBLIC_KEY";
/// Debug builds only: the short commit the running server reports to the
/// downgrade guard, so a test can offer a copy of its own binary as newer.
#[cfg(debug_assertions)]
pub(crate) const TEST_RUNNING_COMMIT_ENV: &str = "HERDR_UPDATE_TEST_RUNNING_COMMIT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// The manifest or its signature could not be fetched.
    Unreachable(String),
    /// The manifest is published but its signature is not (yet).
    NotReady,
    SignatureInvalid(String),
    ManifestInvalid(String),
}

impl VerifyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "update_manifest_unreachable",
            Self::NotReady | Self::SignatureInvalid(_) => "update_signature_invalid",
            Self::ManifestInvalid(_) => "update_manifest_invalid",
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(detail) => write!(f, "can't fetch the update manifest: {detail}"),
            Self::NotReady => write!(
                f,
                "update not ready yet: the newest preview build has no published signature"
            ),
            Self::SignatureInvalid(detail) => {
                write!(f, "update manifest signature is invalid: {detail}")
            }
            Self::ManifestInvalid(detail) => write!(f, "update manifest is invalid: {detail}"),
        }
    }
}

/// The build that is running, as the downgrade guard sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RunningBuild {
    pub(super) commit: Option<String>,
    pub(super) build_id: Option<String>,
    pub(super) commit_time: Option<i64>,
}

impl RunningBuild {
    pub(super) fn current() -> Self {
        #[cfg(debug_assertions)]
        if let Some(commit) = std::env::var(TEST_RUNNING_COMMIT_ENV)
            .ok()
            .filter(|commit| !commit.trim().is_empty())
        {
            return Self {
                commit: Some(commit.trim().to_string()),
                build_id: None,
                commit_time: crate::build_info::commit_time(),
            };
        }
        Self {
            commit: crate::build_info::commit().map(str::to_string),
            build_id: crate::build_info::build_id().map(str::to_string),
            commit_time: crate::build_info::commit_time(),
        }
    }

    fn is_build(&self, manifest: &PreviewManifest) -> bool {
        self.build_id.as_deref() == Some(manifest.build_id.as_str())
            || self
                .commit
                .as_deref()
                .is_some_and(|commit| commit.len() >= 7 && manifest.commit.starts_with(commit))
    }

    /// True only when `manifest` is a different commit with a strictly newer
    /// signed commit time. A build without a commit time is never offered
    /// anything: it can't tell newer from older.
    pub(super) fn is_older_than(&self, manifest: &PreviewManifest) -> bool {
        match (self.commit_time, manifest.commit_time) {
            (Some(running), Some(published)) => !self.is_build(manifest) && published > running,
            _ => false,
        }
    }
}

/// A manifest asset that passed [`release_asset`]'s checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseAsset {
    pub(crate) url: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

/// The verified asset for this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlatformAsset {
    pub(super) url: String,
    pub(super) sha256: String,
    pub(super) size: u64,
    #[cfg(windows)]
    pub(super) package_format: String,
}

pub(super) fn platform_asset_key() -> String {
    let (os, arch) = super::platform_target();
    format!("{os}-{arch}")
}

/// The manifest's asset for this platform, or `None` when it publishes none.
/// It must pass [`release_asset`]'s checks.
pub(super) fn platform_asset(
    manifest: &PreviewManifest,
) -> Result<Option<PlatformAsset>, VerifyError> {
    let key = platform_asset_key();
    let Some(asset) = release_asset(manifest, &key)? else {
        return Ok(None);
    };
    Ok(Some(PlatformAsset {
        url: asset.url,
        sha256: asset.sha256,
        size: asset.size,
        #[cfg(windows)]
        package_format: manifest.assets[&key]
            .package_format()
            .map_err(VerifyError::ManifestInvalid)?,
    }))
}

/// The manifest's asset under `key` (`<os>-<arch>`), or `None` when it
/// publishes none. The URL must sit under the manifest build's own release
/// tag, and the sha256 and a size within [`MAX_ASSET_BYTES`] are required.
fn release_asset(
    manifest: &PreviewManifest,
    key: &str,
) -> Result<Option<ReleaseAsset>, VerifyError> {
    let Some(asset) = manifest.assets.get(key) else {
        return Ok(None);
    };
    super::ensure_fork_release_asset(&asset.url).map_err(VerifyError::ManifestInvalid)?;
    let release_dir = format!("{EXPECTED_RELEASE_ROOT}preview-{}/", manifest.build_id);
    if !asset.url.starts_with(&release_dir) {
        return Err(VerifyError::ManifestInvalid(format!(
            "asset {} is not in the release for build {}",
            asset.url, manifest.build_id
        )));
    }
    let sha256 = asset
        .sha256
        .as_deref()
        .map(str::to_ascii_lowercase)
        .filter(|sha| is_hex(sha, 64))
        .ok_or_else(|| VerifyError::ManifestInvalid(format!("asset {key} has no valid sha256")))?;
    let size = asset
        .size
        .filter(|size| (1..=MAX_ASSET_BYTES).contains(size))
        .ok_or_else(|| {
            VerifyError::ManifestInvalid(format!(
                "asset {key} needs a size between 1 and {MAX_ASSET_BYTES} bytes"
            ))
        })?;
    Ok(Some(ReleaseAsset {
        url: asset.url.clone(),
        sha256,
        size,
    }))
}

/// The signed manifest's `asset_key` binary of the running build, which
/// seeding installs on a remote host. Only the manifest's own build is used:
/// its archived `builds` are unsigned-era entries without a size.
pub(crate) fn remote_seed_asset(
    asset_key: &str,
    protocol: u32,
) -> Result<ReleaseAsset, VerifyError> {
    let (bytes, minisig) = fetch_signed(PREVIEW_UPDATE_MANIFEST_URL)?;
    seed_asset(
        &bytes,
        &minisig,
        &trusted_public_keys(),
        asset_key,
        protocol,
        &RunningBuild::current(),
    )
}

/// Verify the manifest, then pick `running`'s `asset_key` asset from it.
fn seed_asset(
    bytes: &[u8],
    minisig: &str,
    keys: &[String],
    asset_key: &str,
    protocol: u32,
    running: &RunningBuild,
) -> Result<ReleaseAsset, VerifyError> {
    let manifest = verify_signed_manifest(bytes, minisig, keys)?;
    if !running.is_build(&manifest) {
        return Err(VerifyError::ManifestInvalid(format!(
            "it publishes build {} ({}), not this build {}, and a remote only gets the build running here",
            manifest.build_id,
            manifest.commit,
            running
                .build_id
                .as_deref()
                .or(running.commit.as_deref())
                .unwrap_or("(unstamped)")
        )));
    }
    if manifest.protocol != protocol {
        return Err(VerifyError::ManifestInvalid(format!(
            "build {} speaks protocol {}, but this build speaks {protocol}",
            manifest.build_id, manifest.protocol
        )));
    }
    release_asset(&manifest, asset_key)?.ok_or_else(|| {
        VerifyError::ManifestInvalid(format!(
            "no {asset_key} binary for build {}",
            manifest.build_id
        ))
    })
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A `build_id` names a directory under `updates/` that every apply removes
/// and recreates, so it must be a plain name of its own there: at most
/// `MAX_BUILD_ID_LEN` of `[A-Za-z0-9._-]`, starting with a letter or digit
/// (so never `.`, `..` or a temp file), and not one of the layout's names.
fn is_build_id(value: &str) -> bool {
    (1..=MAX_BUILD_ID_LEN).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !super::state::LAYOUT_NAMES.contains(&value)
}

/// Fetch `manifest_url` and `<manifest_url>.minisig`, and verify them.
pub(super) fn fetch_signed_manifest(manifest_url: &str) -> Result<PreviewManifest, VerifyError> {
    fetch_signed_manifest_files(manifest_url).map(|signed| signed.manifest)
}

/// A verified manifest with the exact bytes and signature it came from, so
/// the update guard can verify the same files again from disk.
#[cfg(unix)]
pub(super) struct SignedManifest {
    pub(super) manifest: PreviewManifest,
    pub(super) bytes: Vec<u8>,
    pub(super) minisig: String,
}

#[cfg(not(unix))]
pub(super) struct SignedManifest {
    pub(super) manifest: PreviewManifest,
}

pub(super) fn fetch_signed_manifest_files(
    manifest_url: &str,
) -> Result<SignedManifest, VerifyError> {
    let (bytes, minisig) = fetch_signed(manifest_url)?;
    let manifest = verify_trusted(&bytes, &minisig)?;
    Ok(SignedManifest {
        manifest,
        #[cfg(unix)]
        bytes,
        #[cfg(unix)]
        minisig,
    })
}

/// Verify `minisig` over `bytes` against the keys this build trusts.
pub(super) fn verify_trusted(bytes: &[u8], minisig: &str) -> Result<PreviewManifest, VerifyError> {
    verify_signed_manifest(bytes, minisig, &trusted_public_keys())
}

/// Fetch `manifest_url` and its `.minisig`, unverified.
fn fetch_signed(manifest_url: &str) -> Result<(Vec<u8>, String), VerifyError> {
    let bytes = match fetch(manifest_url, MAX_MANIFEST_BYTES)? {
        Fetched::Body(bytes) => bytes,
        Fetched::NotFound => {
            return Err(VerifyError::Unreachable(
                "the manifest is not published (HTTP 404)".into(),
            ))
        }
    };
    let minisig = match fetch(&format!("{manifest_url}.minisig"), MAX_SIGNATURE_BYTES)? {
        Fetched::Body(bytes) => String::from_utf8(bytes)
            .map_err(|_| VerifyError::SignatureInvalid("the signature is not UTF-8".into()))?,
        Fetched::NotFound => return Err(VerifyError::NotReady),
    };
    Ok((bytes, minisig))
}

/// Verify `minisig` over `bytes` against `keys`, then the manifest itself.
pub(super) fn verify_signed_manifest(
    bytes: &[u8],
    minisig: &str,
    keys: &[String],
) -> Result<PreviewManifest, VerifyError> {
    let signature = minisign_verify::Signature::decode(minisig)
        .map_err(|err| VerifyError::SignatureInvalid(format!("malformed signature: {err}")))?;
    if keys.is_empty() {
        return Err(VerifyError::SignatureInvalid(
            "this build trusts no release signing key yet".into(),
        ));
    }
    let mut refusal = "not signed by a trusted release key".to_string();
    let mut verified = false;
    for key in keys {
        let public_key = minisign_verify::PublicKey::from_base64(key).map_err(|err| {
            VerifyError::SignatureInvalid(format!("unusable trusted key {key}: {err}"))
        })?;
        match public_key.verify(bytes, &signature, false) {
            Ok(()) => {
                verified = true;
                break;
            }
            Err(minisign_verify::Error::UnexpectedKeyId) => {}
            Err(minisign_verify::Error::UnexpectedAlgorithm) => {
                refusal = "legacy (not prehashed) signatures are refused".into();
            }
            Err(err) => refusal = err.to_string(),
        }
    }
    if !verified {
        return Err(VerifyError::SignatureInvalid(refusal));
    }

    let manifest: PreviewManifest = serde_json::from_slice(bytes)
        .map_err(|err| VerifyError::ManifestInvalid(format!("unreadable JSON: {err}")))?;
    let expected_comment = format!(
        "{TRUSTED_COMMENT_PREFIX}{} {}",
        manifest.build_id, manifest.commit
    );
    if signature.trusted_comment() != expected_comment {
        return Err(VerifyError::SignatureInvalid(format!(
            "the signature names `{}`, but the manifest is `{expected_comment}`",
            signature.trusted_comment()
        )));
    }
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &PreviewManifest) -> Result<(), VerifyError> {
    let invalid =
        |detail: String| -> Result<(), VerifyError> { Err(VerifyError::ManifestInvalid(detail)) };
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return invalid(format!(
            "schema_version {} (this build reads {MANIFEST_SCHEMA_VERSION})",
            manifest.schema_version
        ));
    }
    if manifest.channel != "preview" {
        return invalid(format!("channel {}", manifest.channel));
    }
    if !is_build_id(&manifest.build_id) {
        return invalid(format!("build_id {:?}", manifest.build_id));
    }
    if !is_hex(&manifest.commit, 40) {
        return invalid(format!(
            "commit {:?} is not a full commit id",
            manifest.commit
        ));
    }
    if manifest.commit_time.is_none_or(|time| time <= 0) {
        return invalid("commit_time is missing".into());
    }
    if super::Version::parse(&manifest.base_version).is_none() {
        return invalid(format!("base_version {}", manifest.base_version));
    }
    if manifest.notes.trim().is_empty() {
        return invalid("notes are empty".into());
    }
    Ok(())
}

/// The keys a manifest signature may come from.
fn trusted_public_keys() -> Vec<String> {
    super::keys::RELEASE_PUBLIC_KEYS
        .iter()
        .map(|key| (*key).to_string())
        .chain(test_public_key())
        .collect()
}

#[cfg(debug_assertions)]
fn test_public_key() -> Option<String> {
    std::env::var(TEST_PUBLIC_KEY_ENV)
        .ok()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
}

#[cfg(not(debug_assertions))]
fn test_public_key() -> Option<String> {
    None
}

/// A loopback origin for tests, in debug builds only.
#[cfg(debug_assertions)]
fn test_origin() -> Option<String> {
    std::env::var(TEST_ORIGIN_ENV)
        .ok()
        .map(|origin| origin.trim().trim_end_matches('/').to_string())
        .filter(|origin| origin.starts_with("http://127.0.0.1:"))
}

/// The URL actually fetched for a pinned URL: itself, except under a debug
/// build's test origin.
pub(crate) fn fetch_url(url: &str) -> String {
    #[cfg(debug_assertions)]
    if let Some(origin) = test_origin() {
        for (root, local) in [
            (DISTRIBUTION_ROOT, "/distribution/"),
            (EXPECTED_RELEASE_ROOT, "/releases/download/"),
        ] {
            if let Some(rest) = url.strip_prefix(root) {
                return format!("{origin}{local}{rest}");
            }
        }
    }
    url.to_string()
}

/// curl `--proto`/`--proto-redir` value: HTTPS only, plus HTTP under a debug
/// build's loopback test origin.
pub(crate) fn allowed_protocols() -> &'static str {
    #[cfg(debug_assertions)]
    if test_origin().is_some() {
        return "=http,https";
    }
    "=https"
}

enum Fetched {
    Body(Vec<u8>),
    NotFound,
}

fn fetch(url: &str, limit: usize) -> Result<Fetched, VerifyError> {
    let protocols = allowed_protocols();
    let output = crate::noninteractive_process::curl_command()
        .args(["-sL", "--proto", protocols, "--proto-redir", protocols])
        .args([
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
        ])
        .args(["--max-filesize", &limit.to_string()])
        .args(["-w", "%{stderr}%{http_code}"])
        .arg(fetch_url(url))
        .output()
        .map_err(|err| VerifyError::Unreachable(format!("curl failed: {err}")))?;
    if !output.status.success() {
        return Err(VerifyError::Unreachable(format!(
            "curl exited with {}",
            output.status
        )));
    }
    match String::from_utf8_lossy(&output.stderr).trim() {
        "200" if output.stdout.len() <= limit => Ok(Fetched::Body(output.stdout)),
        "200" => Err(VerifyError::Unreachable(format!(
            "{url} is larger than {limit} bytes"
        ))),
        "404" => Ok(Fetched::NotFound),
        status => Err(VerifyError::Unreachable(format!(
            "{url} answered HTTP {status}"
        ))),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::test_signing::TestSigner;
    use super::*;

    const BUILD_ID: &str = "2026-10-28-0123456789ab";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn manifest_json(build_id: &str, commit: &str, commit_time: i64) -> String {
        let key = platform_asset_key();
        serde_json::json!({
            "schema_version": 2,
            "channel": "preview",
            "base_version": "0.9.6",
            "build_id": build_id,
            "commit": commit,
            "commit_time": commit_time,
            "built_at": "2026-10-28T08:00:00Z",
            "protocol": 22,
            "endpoint_generation": 1,
            "notes": "Preview build",
            "assets": {
                key.clone(): {
                    "url": format!("{EXPECTED_RELEASE_ROOT}preview-{build_id}/herdr-{key}"),
                    "sha256": "a".repeat(64),
                    "size": 4096
                }
            }
        })
        .to_string()
    }

    fn comment(build_id: &str, commit: &str) -> String {
        format!("herdr-preview {build_id} {commit}")
    }

    fn keys(signers: &[&TestSigner]) -> Vec<String> {
        signers.iter().map(|signer| signer.public_key()).collect()
    }

    #[test]
    fn manifest_signed_by_the_primary_key_verifies() {
        let primary = TestSigner::new(1);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let minisig = primary.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));

        let manifest = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
            .expect("valid signature");

        assert_eq!(manifest.build_id, BUILD_ID);
        assert_eq!(manifest.commit_time, Some(1_800_000_000));
    }

    #[test]
    fn manifest_signed_by_the_backup_key_verifies() {
        let primary = TestSigner::new(1);
        let backup = TestSigner::new(2);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let minisig = backup.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));

        verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary, &backup]))
            .expect("the backup key is trusted for rotation");
    }

    #[test]
    fn manifest_signed_by_an_untrusted_key_is_refused() {
        let primary = TestSigner::new(1);
        let stranger = TestSigner::new(9);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let minisig = stranger.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));

        let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
            .err()
            .expect("an untrusted key must be refused");
        assert_eq!(err.code(), "update_signature_invalid");
    }

    #[test]
    fn one_flipped_manifest_byte_breaks_the_signature() {
        let primary = TestSigner::new(1);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let minisig = primary.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));
        let tampered = json.replacen("4096", "4097", 1);
        assert_ne!(tampered, json);

        let err = verify_signed_manifest(tampered.as_bytes(), &minisig, &keys(&[&primary]))
            .err()
            .expect("a changed manifest must be refused");
        assert_eq!(err.code(), "update_signature_invalid");
    }

    #[test]
    fn legacy_signature_is_refused() {
        let primary = TestSigner::new(1);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let minisig = primary.sign_legacy(json.as_bytes(), &comment(BUILD_ID, COMMIT));

        let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
            .err()
            .expect("legacy signatures must be refused");
        assert_eq!(
            err,
            VerifyError::SignatureInvalid("legacy (not prehashed) signatures are refused".into())
        );
    }

    #[test]
    fn signature_for_another_build_is_refused() {
        let primary = TestSigner::new(1);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let other_commit = "f".repeat(40);
        for trusted_comment in [
            comment("2026-10-01-0123456789ab", COMMIT),
            comment(BUILD_ID, &other_commit),
            "timestamp:1800000000\tfile:preview.json".to_string(),
        ] {
            let minisig = primary.sign(json.as_bytes(), &trusted_comment);
            let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
                .err()
                .expect("a signature naming another build must be refused");
            assert_eq!(err.code(), "update_signature_invalid", "{trusted_comment}");
        }
    }

    #[test]
    fn no_trusted_key_refuses_every_manifest() {
        let primary = TestSigner::new(1);
        let json = manifest_json(BUILD_ID, COMMIT, 1_800_000_000);
        let minisig = primary.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));

        let err = verify_signed_manifest(json.as_bytes(), &minisig, &[])
            .err()
            .expect("no key, no update");
        assert_eq!(err.code(), "update_signature_invalid");
    }

    #[test]
    fn signed_v1_manifest_without_commit_time_is_refused() {
        let primary = TestSigner::new(1);
        let mut value: serde_json::Value =
            serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
        value["schema_version"] = 1.into();
        value.as_object_mut().unwrap().remove("commit_time");
        let json = value.to_string();
        let minisig = primary.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));

        let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
            .err()
            .expect("v1 manifests carry no commit_time");
        assert_eq!(err.code(), "update_manifest_invalid");
    }

    #[test]
    fn release_keys_are_the_keyring_primary_then_the_offline_backup() {
        use base64::Engine as _;
        let ids: Vec<String> = super::super::keys::RELEASE_PUBLIC_KEYS
            .iter()
            .map(|key| {
                let bin = base64::engine::general_purpose::STANDARD
                    .decode(key)
                    .unwrap();
                assert_eq!(bin.len(), 42, "{key}");
                assert_eq!(&bin[..2], b"Ed", "{key}");
                minisign_verify::PublicKey::from_base64(key).unwrap();
                // minisign prints the little-endian key number as hex.
                bin[2..10]
                    .iter()
                    .rev()
                    .map(|b| format!("{b:02X}"))
                    .collect()
            })
            .collect();
        assert_eq!(ids, ["1909BF13AB4A7686", "4EC2A8E66B478CBA"]);
    }

    #[test]
    fn embedded_release_keys_are_minisign_public_keys() {
        for key in super::super::keys::RELEASE_PUBLIC_KEYS {
            minisign_verify::PublicKey::from_base64(key)
                .unwrap_or_else(|err| panic!("{key}: {err}"));
        }
    }

    fn manifest(build_id: &str, commit: &str, commit_time: i64) -> PreviewManifest {
        serde_json::from_str(&manifest_json(build_id, commit, commit_time)).unwrap()
    }

    #[test]
    fn only_a_newer_different_commit_is_offered() {
        let running = RunningBuild {
            commit: Some("abcdef0".into()),
            build_id: Some("2026-10-20-abcdef012345".into()),
            commit_time: Some(1_800_000_000),
        };

        assert!(running.is_older_than(&manifest(BUILD_ID, COMMIT, 1_800_000_001)));
        // A replayed older manifest, or one from the same instant, is a downgrade.
        assert!(!running.is_older_than(&manifest(BUILD_ID, COMMIT, 1_799_999_999)));
        assert!(!running.is_older_than(&manifest(BUILD_ID, COMMIT, 1_800_000_000)));
        // The running commit itself is never offered, whatever its time says.
        let same_commit = format!("abcdef0{}", "1".repeat(33));
        assert!(!running.is_older_than(&manifest(BUILD_ID, &same_commit, 1_900_000_000)));
        assert!(!running.is_older_than(&manifest(
            "2026-10-20-abcdef012345",
            COMMIT,
            1_900_000_000
        )));
        // Without its own commit time a build can't tell newer from older.
        let unstamped = RunningBuild {
            commit_time: None,
            ..running
        };
        assert!(!unstamped.is_older_than(&manifest(BUILD_ID, COMMIT, 1_900_000_000)));
    }

    #[test]
    fn asset_outside_this_builds_release_is_refused() {
        let key = platform_asset_key();
        let mut value: serde_json::Value =
            serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
        value["assets"][&key]["url"] =
            format!("{EXPECTED_RELEASE_ROOT}preview-2026-01-01-000000000000/herdr-{key}").into();
        let manifest: PreviewManifest = serde_json::from_value(value).unwrap();

        let err = platform_asset(&manifest).expect_err("wrong release tag");
        assert_eq!(err.code(), "update_manifest_invalid");
    }

    #[test]
    fn asset_without_a_valid_sha256_is_refused() {
        let key = platform_asset_key();
        for sha in [
            serde_json::Value::Null,
            "deadbeef".into(),
            "g".repeat(64).into(),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
            value["assets"][&key]["sha256"] = sha.clone();
            let manifest: PreviewManifest = serde_json::from_value(value).unwrap();
            let err = platform_asset(&manifest).expect_err("sha256 required");
            assert_eq!(err.code(), "update_manifest_invalid", "{sha}");
        }
    }

    #[test]
    fn asset_size_must_be_present_and_under_the_cap() {
        let key = platform_asset_key();
        for size in [
            serde_json::Value::Null,
            0.into(),
            (MAX_ASSET_BYTES + 1).into(),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
            value["assets"][&key]["size"] = size.clone();
            let manifest: PreviewManifest = serde_json::from_value(value).unwrap();
            let err = platform_asset(&manifest).expect_err("size required");
            assert_eq!(err.code(), "update_manifest_invalid", "{size}");
        }
        let manifest = manifest(BUILD_ID, COMMIT, 1_800_000_000);
        let asset = platform_asset(&manifest).unwrap().unwrap();
        assert_eq!(asset.size, 4096);
        assert_eq!(asset.sha256, "a".repeat(64));
    }

    #[test]
    fn manifest_with_empty_notes_is_refused() {
        let primary = TestSigner::new(1);
        for notes in ["", " \n"] {
            let mut value: serde_json::Value =
                serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
            value["notes"] = notes.into();
            let json = value.to_string();
            let minisig = primary.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));

            let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
                .err()
                .expect("notes are required");
            assert_eq!(err.code(), "update_manifest_invalid", "{notes:?}");
        }
    }

    #[test]
    fn manifest_with_a_build_id_that_is_not_a_plain_name_is_refused() {
        // The build id names a directory under `updates/` that an apply
        // removes and recreates, so it must not leave that directory or
        // name anything else there.
        let primary = TestSigner::new(1);
        let too_long = "a".repeat(MAX_BUILD_ID_LEN + 1);
        let refused = [
            "",
            ".",
            "..",
            ".hidden",
            "-flag",
            "a/b",
            "a\\b",
            "a b",
            "a:b",
            "é",
            too_long.as_str(),
            "previous",
            "state.json",
            "lock",
            "guard.log",
        ];
        for build_id in refused {
            let mut value: serde_json::Value =
                serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
            value["build_id"] = build_id.into();
            let json = value.to_string();
            let minisig = primary.sign(json.as_bytes(), &comment(build_id, COMMIT));

            let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
                .err()
                .expect("the build id must be refused");
            assert_eq!(err.code(), "update_manifest_invalid", "{build_id:?}");
        }
        assert!(is_build_id("2026-10-28-8a02b8342805"));
        assert!(is_build_id(&"a".repeat(MAX_BUILD_ID_LEN)));
        assert!(is_build_id("v1.2_rc-3"));
    }

    const PROTOCOL: u32 = 22;

    /// Another platform than this one, as a remote host would be.
    fn remote_key() -> &'static str {
        if platform_asset_key() == "linux-aarch64" {
            "linux-x86_64"
        } else {
            "linux-aarch64"
        }
    }

    fn seed_manifest(build_id: &str) -> serde_json::Value {
        let mut value: serde_json::Value =
            serde_json::from_str(&manifest_json(build_id, COMMIT, 1_800_000_000)).unwrap();
        let key = remote_key();
        value["assets"][key] = serde_json::json!({
            "url": format!("{EXPECTED_RELEASE_ROOT}preview-{build_id}/herdr-{key}"),
            "sha256": "b".repeat(64),
            "size": 8192
        });
        value
    }

    fn running(build_id: &str) -> RunningBuild {
        RunningBuild {
            commit: None,
            build_id: Some(build_id.into()),
            commit_time: Some(1_800_000_000),
        }
    }

    /// Sign `value` correctly and seed `remote_key()` from it.
    fn seed(
        value: &serde_json::Value,
        signer: &TestSigner,
        running: &RunningBuild,
    ) -> Result<ReleaseAsset, VerifyError> {
        let json = value.to_string();
        let minisig = signer.sign(
            json.as_bytes(),
            &comment(
                value["build_id"].as_str().unwrap(),
                value["commit"].as_str().unwrap(),
            ),
        );
        seed_asset(
            json.as_bytes(),
            &minisig,
            &keys(&[signer]),
            remote_key(),
            PROTOCOL,
            running,
        )
    }

    #[test]
    fn seeding_picks_the_remote_platforms_asset_of_the_running_build() {
        let signer = TestSigner::new(1);
        let key = remote_key();

        let asset = seed(&seed_manifest(BUILD_ID), &signer, &running(BUILD_ID))
            .expect("the signed manifest of the running build");

        assert_eq!(
            asset,
            ReleaseAsset {
                url: format!("{EXPECTED_RELEASE_ROOT}preview-{BUILD_ID}/herdr-{key}"),
                sha256: "b".repeat(64),
                size: 8192,
            }
        );
        // A build stamped with only its commit is matched by the commit.
        let by_commit = RunningBuild {
            commit: Some(COMMIT[..12].into()),
            build_id: None,
            commit_time: None,
        };
        assert_eq!(
            seed(&seed_manifest(BUILD_ID), &signer, &by_commit)
                .unwrap()
                .url,
            asset.url
        );
    }

    #[test]
    fn seeding_refuses_a_tampered_manifest() {
        let signer = TestSigner::new(1);
        let json = seed_manifest(BUILD_ID).to_string();
        let minisig = signer.sign(json.as_bytes(), &comment(BUILD_ID, COMMIT));
        let tampered = json.replacen("8192", "8193", 1);
        assert_ne!(tampered, json);

        let err = seed_asset(
            tampered.as_bytes(),
            &minisig,
            &keys(&[&signer]),
            remote_key(),
            PROTOCOL,
            &running(BUILD_ID),
        )
        .expect_err("a changed manifest must not seed a remote");
        assert_eq!(err.code(), "update_signature_invalid");
    }

    #[test]
    fn seeding_refuses_an_unsigned_manifest() {
        let signer = TestSigner::new(1);
        let json = seed_manifest(BUILD_ID).to_string();
        let garbage = format!(
            "untrusted comment: x\nRWQ=\ntrusted comment: {}\nRWQ=\n",
            comment(BUILD_ID, COMMIT)
        );
        for minisig in ["", "not a signature", garbage.as_str()] {
            let err = seed_asset(
                json.as_bytes(),
                minisig,
                &keys(&[&signer]),
                remote_key(),
                PROTOCOL,
                &running(BUILD_ID),
            )
            .expect_err("an unsigned manifest must not seed a remote");
            assert_eq!(err.code(), "update_signature_invalid", "{minisig:?}");
        }
    }

    #[test]
    fn seeding_refuses_an_asset_in_another_release() {
        let signer = TestSigner::new(1);
        let key = remote_key();
        let mut value = seed_manifest(BUILD_ID);
        value["assets"][key]["url"] =
            format!("{EXPECTED_RELEASE_ROOT}preview-2026-01-01-000000000000/herdr-{key}").into();

        let err = seed(&value, &signer, &running(BUILD_ID)).expect_err("wrong release tag");
        assert_eq!(err.code(), "update_manifest_invalid");
    }

    #[test]
    fn seeding_refuses_an_asset_without_sha256_or_size() {
        let signer = TestSigner::new(1);
        for field in ["sha256", "size"] {
            let mut value = seed_manifest(BUILD_ID);
            value["assets"][remote_key()]
                .as_object_mut()
                .unwrap()
                .remove(field);

            let err = seed(&value, &signer, &running(BUILD_ID)).expect_err(field);
            assert_eq!(err.code(), "update_manifest_invalid", "{field}");
        }
    }

    #[test]
    fn seeding_refuses_a_manifest_of_another_build() {
        let signer = TestSigner::new(1);
        let key = remote_key();
        // The running build survives only in the unsigned-era `builds` archive.
        let archived = "2026-10-01-fedcba987654";
        let mut value = seed_manifest(BUILD_ID);
        value["builds"][archived] = serde_json::json!({
            "protocol": PROTOCOL,
            "assets": {
                key: {
                    "url": format!("{EXPECTED_RELEASE_ROOT}preview-{archived}/herdr-{key}"),
                    "sha256": "c".repeat(64)
                }
            }
        });

        let err = seed(&value, &signer, &running(archived)).expect_err("archived build");
        assert_eq!(err.code(), "update_manifest_invalid");
        let unstamped = RunningBuild {
            commit: None,
            build_id: None,
            commit_time: None,
        };
        let err = seed(&value, &signer, &unstamped).expect_err("unstamped build");
        assert_eq!(err.code(), "update_manifest_invalid");
    }

    #[test]
    fn seeding_refuses_a_build_of_another_protocol() {
        let signer = TestSigner::new(1);
        let mut value = seed_manifest(BUILD_ID);
        value["protocol"] = (PROTOCOL + 1).into();

        let err = seed(&value, &signer, &running(BUILD_ID)).expect_err("protocol mismatch");
        assert_eq!(err.code(), "update_manifest_invalid");
    }
}
