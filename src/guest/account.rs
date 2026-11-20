//! Account-bound guest shares (herdr#440): HerdrUp account statements.
//!
//! A guest who binds a share to their HerdrUp account presents a statement
//! with every hello: a compact JWS (`alg` EdDSA, `typ` `herdrup-device+jwt`)
//! from the account service saying "device key `dev` belongs to the account
//! whose pairwise id on this host is `sub`", valid for about ten minutes. The
//! host checks it against the service's published Ed25519 keys (JWKS), cached
//! in `<config>/guest/account_keys.json`:
//!
//! - fresh for [`KEYS_FRESH_MS`]; an unknown `kid` refetches, at most once per
//!   [`REFETCH_INTERVAL_MS`];
//! - when the service cannot be reached, the cached keys still admit devices
//!   already on a share for up to [`KEYS_GRACE_MS`], but a device new to a share
//!   needs keys fetched within [`KEYS_FRESH_MS`] (`account_keys_stale`);
//! - a `kid` the service lists in `revoked_kids` is dropped and never accepted
//!   again.
//!
//! Plain shares never reach this module: keys are fetched only when a hello
//! carries a statement.

use std::path::Path;
use std::time::Duration;

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use super::store::{b64url, b64url_decode, load_side, update_side};

/// The key cache beside `guests.json`.
pub(crate) const KEYS_FILE: &str = "account_keys.json";
/// Where the issuer publishes its keys.
const JWKS_PATH: &str = "/.well-known/jwks.json";
/// Clock skew allowed on both ends of a statement's validity.
pub(crate) const SKEW_SECS: u64 = 60;
/// A statement valid for longer than this is refused: the service issues ten
/// minutes, and the deadline of an account-bound session follows `exp`.
const MAX_LIFETIME_SECS: u64 = 60 * 60;
/// Statements are about 430 bytes.
const MAX_STATEMENT_LEN: usize = 4096;
/// Cached keys count as current this long after a successful fetch.
pub(crate) const KEYS_FRESH_MS: u64 = 60 * 60 * 1000;
/// At most one fetch attempt per this interval.
pub(crate) const REFETCH_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// Without a successful fetch for this long the cached keys admit no one.
pub(crate) const KEYS_GRACE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Revoked kids remembered; the service lists each for at least 30 days.
const MAX_REVOKED_KIDS: usize = 256;
const STATEMENT_TYP: &str = "herdrup-device+jwt";

/// Refusal and close codes a guest client acts on.
pub(crate) mod codes {
    /// An account-bound share's hello carried no statement.
    pub(crate) const REQUIRED: &str = "account_required";
    /// Malformed, badly signed, or for another issuer, host or device.
    pub(crate) const INVALID: &str = "statement_invalid";
    /// Expired or not yet valid; the session deadline also closes with it.
    pub(crate) const EXPIRED: &str = "statement_expired";
    /// The keys could not be refreshed recently enough; retry later.
    pub(crate) const KEYS_STALE: &str = "account_keys_stale";
    /// `[guest] accounts = false` on this host.
    pub(crate) const DISABLED: &str = "accounts_disabled";
    /// The statement names another account than the share's.
    pub(crate) const MISMATCH: &str = "account_mismatch";
    /// The owner removed this device from the share.
    pub(crate) const DEVICE_REMOVED: &str = "device_removed";
}

/// Why a statement failed, as the golden vectors name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Malformed,
    Unsupported,
    UnknownKid,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    WrongDevice,
    Expired,
    NotYetValid,
}

impl Failure {
    #[cfg(test)]
    fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
            Self::UnknownKid => "unknown_kid",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::WrongDevice => "wrong_device",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
        }
    }

    /// The refusal code the guest sees.
    fn code(self) -> &'static str {
        match self {
            Self::Expired | Self::NotYetValid => codes::EXPIRED,
            _ => codes::INVALID,
        }
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    kid: String,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

/// A statement's payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Claims {
    pub v: u64,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub dev: String,
    pub iat: u64,
    pub exp: u64,
}

/// What a statement must say to be accepted here.
pub(crate) struct Expected<'a> {
    pub issuer: &'a str,
    /// This host's id (the invite's `host_id`).
    pub host_id: &'a str,
    /// b64url of the device key the Noise handshake proved.
    pub device: &'a str,
}

fn decode_json<T: serde::de::DeserializeOwned>(part: &str) -> Result<T, Failure> {
    let bytes = b64url_decode(part).ok_or(Failure::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| Failure::Malformed)
}

/// The three segments of a compact JWS.
fn segments(jws: &str) -> Result<[&str; 3], Failure> {
    if jws.len() > MAX_STATEMENT_LEN {
        return Err(Failure::Malformed);
    }
    let mut parts = jws.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(signature), None) => Ok([header, payload, signature]),
        _ => Err(Failure::Malformed),
    }
}

/// The `kid` a statement names, read before any key is looked up.
fn statement_kid(jws: &str) -> Result<String, Failure> {
    let [header, _, _] = segments(jws)?;
    Ok(decode_json::<Header>(header)?.kid)
}

/// A pairwise account id: 22 base64url characters from the service, with
/// some room.
fn valid_sub(sub: &str) -> bool {
    (16..=64).contains(&sub.len())
        && sub
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Verifies `jws` with `keys` at `now_secs`: the signature first, then the
/// claims. Never fetches.
pub(crate) fn verify(
    jws: &str,
    keys: &KeyCache,
    expected: &Expected<'_>,
    now_secs: u64,
) -> Result<Claims, Failure> {
    let [header_part, payload_part, signature_part] = segments(jws)?;
    let header: Header = decode_json(header_part)?;
    if header.alg != "EdDSA"
        || header.typ.as_deref() != Some(STATEMENT_TYP)
        || header.crit.is_some()
    {
        return Err(Failure::Unsupported);
    }
    let key = keys.key(&header.kid).ok_or(Failure::UnknownKid)?;
    let signature = b64url_decode(signature_part)
        .filter(|signature| signature.len() == 64)
        .ok_or(Failure::Malformed)?;
    let signed = &jws[..header_part.len() + 1 + payload_part.len()];
    UnparsedPublicKey::new(&ED25519, key)
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| Failure::BadSignature)?;
    let claims: Claims = decode_json(payload_part)?;
    if claims.v != 1 {
        return Err(Failure::Unsupported);
    }
    if claims.exp <= claims.iat
        || claims.exp - claims.iat > MAX_LIFETIME_SECS
        || !valid_sub(&claims.sub)
    {
        return Err(Failure::Malformed);
    }
    if claims.iss != expected.issuer {
        return Err(Failure::WrongIssuer);
    }
    if claims.aud != expected.host_id {
        return Err(Failure::WrongAudience);
    }
    if claims.dev != expected.device {
        return Err(Failure::WrongDevice);
    }
    if now_secs < claims.iat.saturating_sub(SKEW_SECS) {
        return Err(Failure::NotYetValid);
    }
    if now_secs > claims.exp.saturating_add(SKEW_SECS) {
        return Err(Failure::Expired);
    }
    Ok(claims)
}

/// One cached Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedKey {
    pub kid: String,
    /// b64url of the 32-byte public key.
    pub x: String,
}

/// `account_keys.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeyCache {
    /// The issuer these keys belong to; another issuer's cache is ignored.
    #[serde(default)]
    pub issuer: String,
    /// Last successful fetch.
    #[serde(default)]
    pub fetched_ms: Option<u64>,
    /// Last fetch attempt, successful or not.
    #[serde(default)]
    pub attempt_ms: Option<u64>,
    #[serde(default)]
    pub keys: Vec<CachedKey>,
    /// Every revoked kid seen, newest last; never accepted again.
    #[serde(default)]
    pub revoked_kids: Vec<String>,
}

impl KeyCache {
    fn for_issuer(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            ..Self::default()
        }
    }

    /// The key for `kid`, unless it was revoked.
    fn key(&self, kid: &str) -> Option<[u8; 32]> {
        if self.revoked(kid) {
            return None;
        }
        self.keys
            .iter()
            .find(|key| key.kid == kid)
            .and_then(|key| b64url_decode(&key.x)?.try_into().ok())
    }

    fn revoked(&self, kid: &str) -> bool {
        self.revoked_kids.iter().any(|revoked| revoked == kid)
    }

    /// Replaces the keys with a fetched JWKS at `now`, remembering its revoked
    /// kids on top of those seen before.
    fn apply(&mut self, jwks: Jwks, now: u64) {
        for kid in jwks.revoked_kids {
            if !self.revoked(&kid) {
                self.revoked_kids.push(kid);
            }
        }
        let excess = self.revoked_kids.len().saturating_sub(MAX_REVOKED_KIDS);
        self.revoked_kids.drain(..excess);
        let keys = jwks
            .keys
            .into_iter()
            .filter_map(|key| serde_json::from_value::<Jwk>(key).ok())
            .filter(Jwk::usable)
            .map(|key| CachedKey {
                kid: key.kid,
                x: key.x,
            })
            .collect::<Vec<_>>();
        self.keys = keys
            .into_iter()
            .filter(|key| !self.revoked(&key.kid))
            .collect();
        self.fetched_ms = Some(now);
        self.attempt_ms = Some(now);
    }

    fn age(&self, now: u64) -> Option<u64> {
        self.fetched_ms.map(|at| now.saturating_sub(at))
    }

    /// The last attempt failed (or none succeeded yet).
    fn last_attempt_failed(&self) -> bool {
        self.attempt_ms
            .is_some_and(|attempt| self.fetched_ms.is_none_or(|fetched| attempt > fetched))
    }
}

/// `/.well-known/jwks.json`. Keys that are not usable Ed25519 signing keys
/// are skipped, not fatal.
#[derive(Debug, Deserialize)]
pub(crate) struct Jwks {
    keys: Vec<serde_json::Value>,
    #[serde(default)]
    revoked_kids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    kid: String,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

impl Jwk {
    fn usable(&self) -> bool {
        self.kty == "OKP"
            && self.crv == "Ed25519"
            && !self.kid.is_empty()
            && self.usage.as_deref().is_none_or(|usage| usage == "sig")
            && self.alg.as_deref().is_none_or(|alg| alg == "EdDSA")
            && b64url_decode(&self.x).is_some_and(|x| x.len() == 32)
    }
}

/// `[guest] accounts` and `[guest] account_issuer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub enabled: bool,
    /// Without a trailing slash: statements' `iss` must equal it.
    pub issuer: String,
}

impl Settings {
    pub(crate) fn configured() -> Self {
        let guest = crate::config::Config::load().config.guest;
        Self {
            enabled: guest.accounts,
            issuer: guest.account_issuer.trim_end_matches('/').to_owned(),
        }
    }
}

/// GET the issuer's JWKS; the body of a 200.
pub(crate) fn fetch_jwks(issuer: &str) -> Result<Vec<u8>, String> {
    let response = crate::guest::link::https::get(
        "account service",
        "account_issuer",
        issuer,
        JWKS_PATH,
        MAX_JWKS_BYTES,
        FETCH_TIMEOUT,
    )?;
    if response.status != 200 {
        return Err(format!("account service answered HTTP {}", response.status));
    }
    Ok(response.body)
}

/// What admission needs from the account service, and how it tells the
/// owner about a person's new device. Production uses
/// [`Env::PRODUCTION`]; tests supply their own.
pub(crate) struct Env<'a> {
    /// Read only when a hello carries a statement.
    pub settings: &'a (dyn Fn() -> Settings + Sync),
    /// The JWKS body for an issuer.
    pub fetch_keys: &'a (dyn Fn(&str) -> Result<Vec<u8>, String> + Sync),
    /// Called once per device a person adds to an account-bound share.
    pub notify_owner: &'a (dyn Fn(crate::push::PushNotification) + Sync),
}

impl Env<'static> {
    pub(crate) const PRODUCTION: Self = Self {
        settings: &Settings::configured,
        fetch_keys: &fetch_jwks,
        notify_owner: &notify_owner,
    };
}

/// Pushes an alert to the owner's devices, best effort.
fn notify_owner(notification: crate::push::PushNotification) {
    let push = crate::config::Config::load().config.push;
    if crate::push::may_deliver(&push) {
        crate::push::dispatch(push, vec![notification]);
    }
}

/// A statement that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verified {
    /// The account's pairwise id on this host.
    pub sub: String,
    /// When a session admitted with it must have a newer one: `exp` plus the
    /// skew, in unix ms.
    pub deadline_ms: u64,
    /// The keys were fetched within [`KEYS_FRESH_MS`], so a device new to a
    /// share may be added.
    pub keys_fresh: bool,
}

/// Checks `jws` for `device_pub` at this host, fetching the issuer's keys
/// when the cache is stale or lacks the statement's `kid`. Errors are the
/// refusal codes in [`codes`].
pub(crate) fn check(
    dir: &Path,
    settings: &Settings,
    fetch: &(dyn Fn(&str) -> Result<Vec<u8>, String> + Sync),
    host_id: &str,
    device_pub: &[u8; 32],
    jws: &str,
    now_ms: u64,
) -> Result<Verified, &'static str> {
    let kid = statement_kid(jws).map_err(Failure::code)?;
    let keys = current_keys(dir, settings, fetch, &kid, now_ms)?;
    let device = b64url(device_pub);
    let expected = Expected {
        issuer: &settings.issuer,
        host_id,
        device: &device,
    };
    let claims = match verify(jws, &keys, &expected, now_ms / 1000) {
        Ok(claims) => claims,
        // The service may have rotated while it could not be reached.
        Err(Failure::UnknownKid) if keys.last_attempt_failed() && !keys.revoked(&kid) => {
            return Err(codes::KEYS_STALE)
        }
        Err(failure) => {
            tracing::debug!(?failure, "guest account statement refused");
            return Err(failure.code());
        }
    };
    let age = keys.age(now_ms).unwrap_or(u64::MAX);
    if age >= KEYS_GRACE_MS {
        return Err(codes::KEYS_STALE);
    }
    Ok(Verified {
        sub: claims.sub,
        deadline_ms: claims.exp.saturating_add(SKEW_SECS).saturating_mul(1000),
        keys_fresh: age < KEYS_FRESH_MS,
    })
}

/// The cached keys, refreshed first when stale or missing `kid` (and no
/// attempt ran within [`REFETCH_INTERVAL_MS`]). A revoked `kid` never
/// triggers a fetch.
fn current_keys(
    dir: &Path,
    settings: &Settings,
    fetch: &(dyn Fn(&str) -> Result<Vec<u8>, String> + Sync),
    kid: &str,
    now: u64,
) -> Result<KeyCache, &'static str> {
    let issuer = settings.issuer.as_str();
    let store_failed = |err: std::io::Error| {
        tracing::warn!(err = %err, "guest account key cache unavailable");
        codes::KEYS_STALE
    };
    let cached: KeyCache = load_side(dir, KEYS_FILE).map_err(store_failed)?;
    let cached = if cached.issuer == issuer {
        cached
    } else {
        KeyCache::for_issuer(issuer)
    };
    let current = cached.age(now).is_some_and(|age| age < KEYS_FRESH_MS);
    if cached.revoked(kid) || (current && cached.key(kid).is_some()) {
        return Ok(cached);
    }
    // Claim the attempt under the lock, so concurrent hellos fetch once.
    let claimed = update_side(dir, KEYS_FILE, |cache: &mut KeyCache| {
        if cache.issuer != issuer {
            *cache = KeyCache::for_issuer(issuer);
        }
        let due = cache
            .attempt_ms
            .is_none_or(|at| now.saturating_sub(at) >= REFETCH_INTERVAL_MS);
        if due {
            cache.attempt_ms = Some(now);
        }
        ((due, cache.clone()), due)
    })
    .map_err(store_failed)?;
    let (due, claimed) = claimed;
    if !due {
        return Ok(claimed);
    }
    let fetched = fetch(issuer).and_then(|body| {
        serde_json::from_slice::<Jwks>(&body).map_err(|err| format!("account keys: {err}"))
    });
    match fetched {
        Ok(jwks) => update_side(dir, KEYS_FILE, |cache: &mut KeyCache| {
            if cache.issuer != issuer {
                *cache = KeyCache::for_issuer(issuer);
            }
            cache.apply(jwks, now);
            (cache.clone(), true)
        })
        .map_err(store_failed),
        Err(error) => {
            tracing::warn!(error = %error, "guest account keys not refreshed");
            Ok(claimed)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::{json, Value};

    use super::*;
    use crate::guest::store::tests::TempDir;

    pub(crate) const ISSUER: &str = "https://accounts.test";

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/herdrup-accounts/statement-v1.json"
        ))
        .unwrap()
    }

    fn cache_of(jwks: &Value, issuer: &str) -> KeyCache {
        let mut cache = KeyCache::for_issuer(issuer);
        cache.apply(serde_json::from_value(jwks.clone()).unwrap(), 0);
        cache
    }

    /// The golden statements from the account service (herdrup
    /// AccountService/test/vectors/statement-v1.json) verify, and each
    /// negative case fails as the file says.
    #[test]
    fn golden_statements_verify_and_negative_cases_fail_as_listed() {
        let vectors = vectors();
        let issuer = vectors["issuer"].as_str().unwrap();
        let keys = cache_of(&vectors["jwks"], issuer);
        let cases = vectors["cases"].as_array().unwrap();
        assert!(cases.len() >= 9, "every case is covered");
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let expected = Expected {
                issuer,
                host_id: case["host_id"].as_str().unwrap(),
                device: case["noise_device_pub"].as_str().unwrap(),
            };
            let outcome = verify(
                case["jws"].as_str().unwrap(),
                &keys,
                &expected,
                case["now"].as_u64().unwrap(),
            );
            match case["expect"].as_str().unwrap() {
                "valid" => {
                    let claims = outcome.unwrap_or_else(|failure| panic!("{name}: {failure:?}"));
                    assert_eq!(claims.sub, vectors["issued"]["sub"], "{name}");
                    if let Some(listed) = case.get("claims") {
                        let listed: Claims = serde_json::from_value(listed.clone()).unwrap();
                        assert_eq!(claims, listed, "{name}");
                    }
                }
                failure => assert_eq!(outcome.map_err(Failure::as_str), Err(failure), "{name}"),
            }
        }
        // The issued statement is the valid case.
        let issued = &vectors["issued"];
        let claims = verify(
            issued["jws"].as_str().unwrap(),
            &keys,
            &Expected {
                issuer,
                host_id: issued["host_id"].as_str().unwrap(),
                device: issued["dev"].as_str().unwrap(),
            },
            issued["iat"].as_u64().unwrap(),
        )
        .unwrap();
        assert_ne!(claims.sub, vectors["other_host_sub"]);
    }

    #[test]
    fn another_issuer_and_revoked_kids_are_refused() {
        let vectors = vectors();
        let issued = &vectors["issued"];
        let expected = Expected {
            issuer: "https://accounts.example",
            host_id: issued["host_id"].as_str().unwrap(),
            device: issued["dev"].as_str().unwrap(),
        };
        let jws = issued["jws"].as_str().unwrap();
        let now = issued["iat"].as_u64().unwrap();
        let keys = cache_of(&vectors["jwks"], ISSUER);
        assert_eq!(
            verify(jws, &keys, &expected, now),
            Err(Failure::WrongIssuer)
        );

        let mut revoked = vectors["jwks"].clone();
        revoked["revoked_kids"] = json!(["test-2026-11a"]);
        let keys = cache_of(&revoked, ISSUER);
        assert!(
            keys.keys.is_empty(),
            "a revoked kid is dropped from the cache"
        );
        let expected = Expected {
            issuer: vectors["issuer"].as_str().unwrap(),
            ..expected
        };
        assert_eq!(verify(jws, &keys, &expected, now), Err(Failure::UnknownKid));

        // A later JWKS listing the key again does not bring it back.
        let mut keys = keys;
        keys.apply(serde_json::from_value(vectors["jwks"].clone()).unwrap(), 1);
        assert_eq!(verify(jws, &keys, &expected, now), Err(Failure::UnknownKid));
    }

    #[test]
    fn malformed_and_unsupported_statements_are_refused() {
        let issuer = Issuer::new("k1");
        let keys = issuer.cache();
        let device = b64url(&[7; 32]);
        let expected = Expected {
            issuer: ISSUER,
            host_id: "HostIdExample-01234567",
            device: &device,
        };
        let claims = issuer.claims(
            "HostIdExample-01234567",
            &[7; 32],
            "sub-Example-012345678",
            1_000,
        );
        assert!(verify(&issuer.sign(&claims), &keys, &expected, 1_000).is_ok());
        for (jws, failure) in [
            ("".to_string(), Failure::Malformed),
            ("a.b".to_string(), Failure::Malformed),
            (format!("{}.x", issuer.sign(&claims)), Failure::Malformed),
            (issuer.sign_with(json!({"alg": "none", "typ": STATEMENT_TYP, "kid": "k1"}), &claims), Failure::Unsupported),
            (issuer.sign_with(json!({"alg": "EdDSA", "typ": "JWT", "kid": "k1"}), &claims), Failure::Unsupported),
            (issuer.sign_with(json!({"alg": "EdDSA", "typ": STATEMENT_TYP, "kid": "k1", "crit": ["exp"]}), &claims), Failure::Unsupported),
            (issuer.sign(&json!({"v": 2, "iss": ISSUER, "aud": "HostIdExample-01234567", "sub": "sub-Example-012345678", "dev": device, "iat": 1_000, "exp": 1_600})), Failure::Unsupported),
            (issuer.sign(&json!({"v": 1, "iss": ISSUER, "aud": "HostIdExample-01234567", "sub": "sub-Example-012345678", "dev": device, "iat": 1_000, "exp": 1_000 + MAX_LIFETIME_SECS + 1})), Failure::Malformed),
            (issuer.sign(&json!({"v": 1, "iss": ISSUER, "aud": "HostIdExample-01234567", "sub": "short", "dev": device, "iat": 1_000, "exp": 1_600})), Failure::Malformed),
            ("x".repeat(MAX_STATEMENT_LEN + 1), Failure::Malformed),
        ] {
            assert_eq!(verify(&jws, &keys, &expected, 1_000), Err(failure), "{jws}");
        }
    }

    /// A throwaway signing key standing in for the account service.
    pub(crate) struct Issuer {
        pair: Ed25519KeyPair,
        pub kid: String,
    }

    impl Issuer {
        pub(crate) fn new(kid: &str) -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self {
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
                kid: kid.to_owned(),
            }
        }

        pub(crate) fn jwk(&self) -> Value {
            json!({"kty": "OKP", "crv": "Ed25519", "x": b64url(self.pair.public_key().as_ref()), "kid": self.kid, "use": "sig", "alg": "EdDSA"})
        }

        pub(crate) fn jwks(&self) -> Value {
            json!({"keys": [self.jwk()], "revoked_kids": []})
        }

        fn cache(&self) -> KeyCache {
            cache_of(&self.jwks(), ISSUER)
        }

        /// Claims for `device` at `host_id`, issued at `iat` (unix seconds)
        /// for ten minutes.
        pub(crate) fn claims(
            &self,
            host_id: &str,
            device: &[u8; 32],
            sub: &str,
            iat: u64,
        ) -> Value {
            json!({"v": 1, "iss": ISSUER, "aud": host_id, "sub": sub, "dev": b64url(device), "iat": iat, "exp": iat + 600})
        }

        pub(crate) fn sign(&self, claims: &Value) -> String {
            self.sign_with(
                json!({"alg": "EdDSA", "typ": STATEMENT_TYP, "kid": self.kid}),
                claims,
            )
        }

        fn sign_with(&self, header: Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                b64url(header.to_string().as_bytes()),
                b64url(claims.to_string().as_bytes())
            );
            let signature = self.pair.sign(input.as_bytes());
            format!("{input}.{}", b64url(signature.as_ref()))
        }

        /// A statement for `device` at `host_id`, issued now.
        pub(crate) fn statement(&self, host_id: &str, device: &[u8; 32], sub: &str) -> String {
            self.sign(&self.claims(host_id, device, sub, crate::guest::store::now_ms() / 1000))
        }
    }

    /// A key server for [`Env::fetch_keys`]: serves `jwks`, or fails while
    /// `jwks` is `None`, counting requests.
    pub(crate) struct KeyServer {
        pub jwks: Mutex<Option<Value>>,
        pub fetches: AtomicUsize,
    }

    impl KeyServer {
        pub(crate) fn serving(jwks: Value) -> Self {
            Self {
                jwks: Mutex::new(Some(jwks)),
                fetches: AtomicUsize::new(0),
            }
        }

        pub(crate) fn fetch(&self, issuer: &str) -> Result<Vec<u8>, String> {
            assert_eq!(issuer, ISSUER);
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.jwks
                .lock()
                .unwrap()
                .as_ref()
                .map(|jwks| jwks.to_string().into_bytes())
                .ok_or_else(|| "account service unreachable".to_string())
        }

        pub(crate) fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    pub(crate) fn settings() -> Settings {
        Settings {
            enabled: true,
            issuer: ISSUER.into(),
        }
    }

    const HOST: &str = "HostIdExample-01234567";
    const SUB: &str = "sub-Example-012345678";
    const MINUTE: u64 = 60 * 1000;

    fn check_at(
        dir: &Path,
        server: &KeyServer,
        jws: &str,
        device: &[u8; 32],
        now_ms: u64,
    ) -> Result<Verified, &'static str> {
        check(
            dir,
            &settings(),
            &|issuer: &str| server.fetch(issuer),
            HOST,
            device,
            jws,
            now_ms,
        )
    }

    fn statement_at(issuer: &Issuer, device: &[u8; 32], now_ms: u64) -> String {
        issuer.sign(&issuer.claims(HOST, device, SUB, now_ms / 1000))
    }

    #[test]
    fn keys_are_fetched_once_cached_on_disk_and_refreshed_hourly() {
        let dir = TempDir::new("acct-cache");
        let issuer = Issuer::new("k1");
        let server = KeyServer::serving(issuer.jwks());
        let t0 = 1_800_000_000_000;
        let verified = check_at(
            &dir.0,
            &server,
            &statement_at(&issuer, &[7; 32], t0),
            &[7; 32],
            t0,
        )
        .unwrap();
        assert_eq!(verified.sub, SUB);
        assert!(verified.keys_fresh);
        assert_eq!(verified.deadline_ms, (t0 / 1000 + 600 + SKEW_SECS) * 1000);
        assert_eq!(server.fetches(), 1);
        let cached: KeyCache = load_side(&dir.0, KEYS_FILE).unwrap();
        assert_eq!(cached.fetched_ms, Some(t0));
        assert_eq!(cached.keys.len(), 1);

        let later = t0 + 59 * MINUTE;
        check_at(
            &dir.0,
            &server,
            &statement_at(&issuer, &[7; 32], later),
            &[7; 32],
            later,
        )
        .unwrap();
        assert_eq!(server.fetches(), 1, "fresh for an hour");

        let stale = t0 + 61 * MINUTE;
        check_at(
            &dir.0,
            &server,
            &statement_at(&issuer, &[7; 32], stale),
            &[7; 32],
            stale,
        )
        .unwrap();
        assert_eq!(server.fetches(), 2, "refreshed after an hour");
    }

    #[test]
    fn an_unknown_kid_refetches_at_most_once_per_five_minutes() {
        let dir = TempDir::new("acct-kid");
        let old = Issuer::new("k1");
        let new = Issuer::new("k2");
        let server = KeyServer::serving(old.jwks());
        let t0 = 1_800_000_000_000;
        check_at(
            &dir.0,
            &server,
            &statement_at(&old, &[7; 32], t0),
            &[7; 32],
            t0,
        )
        .unwrap();

        // Rotation: the new kid is unknown until a refetch, which is
        // throttled to one per five minutes.
        *server.jwks.lock().unwrap() = Some(json!({"keys": [new.jwk(), old.jwk()]}));
        let soon = t0 + MINUTE;
        assert_eq!(
            check_at(
                &dir.0,
                &server,
                &statement_at(&new, &[7; 32], soon),
                &[7; 32],
                soon
            ),
            Err(codes::INVALID)
        );
        assert_eq!(server.fetches(), 1, "throttled");
        let after = t0 + 5 * MINUTE;
        let verified = check_at(
            &dir.0,
            &server,
            &statement_at(&new, &[7; 32], after),
            &[7; 32],
            after,
        )
        .unwrap();
        assert!(verified.keys_fresh);
        assert_eq!(server.fetches(), 2, "unknown kid refetched");
        let bogus = Issuer::new("k3");
        let next = after + MINUTE;
        assert_eq!(
            check_at(
                &dir.0,
                &server,
                &statement_at(&bogus, &[7; 32], next),
                &[7; 32],
                next
            ),
            Err(codes::INVALID)
        );
        assert_eq!(server.fetches(), 2, "a bogus kid cannot force fetches");
    }

    #[test]
    fn stale_keys_admit_known_devices_for_seven_days_but_never_new_ones() {
        let dir = TempDir::new("acct-grace");
        let issuer = Issuer::new("k1");
        let server = KeyServer::serving(issuer.jwks());
        let t0 = 1_800_000_000_000;
        check_at(
            &dir.0,
            &server,
            &statement_at(&issuer, &[7; 32], t0),
            &[7; 32],
            t0,
        )
        .unwrap();
        *server.jwks.lock().unwrap() = None;

        let day = 24 * 60 * MINUTE;
        let later = t0 + 2 * day;
        let verified = check_at(
            &dir.0,
            &server,
            &statement_at(&issuer, &[7; 32], later),
            &[7; 32],
            later,
        )
        .unwrap();
        assert!(!verified.keys_fresh, "stale keys: existing devices only");
        assert_eq!(server.fetches(), 2, "the refresh was tried");

        let past_grace = t0 + 7 * day;
        assert_eq!(
            check_at(
                &dir.0,
                &server,
                &statement_at(&issuer, &[7; 32], past_grace),
                &[7; 32],
                past_grace
            ),
            Err(codes::KEYS_STALE)
        );

        // A rotated kid while the service is unreachable: retry later.
        let rotated = Issuer::new("k2");
        let at = past_grace + 10 * MINUTE;
        assert_eq!(
            check_at(
                &dir.0,
                &server,
                &statement_at(&rotated, &[7; 32], at),
                &[7; 32],
                at
            ),
            Err(codes::KEYS_STALE)
        );

        // Back online: fresh again.
        *server.jwks.lock().unwrap() = Some(issuer.jwks());
        let back = at + 10 * MINUTE;
        assert!(
            check_at(
                &dir.0,
                &server,
                &statement_at(&issuer, &[7; 32], back),
                &[7; 32],
                back
            )
            .unwrap()
            .keys_fresh
        );
    }

    #[test]
    fn no_keys_at_all_is_a_retry_not_a_forgery() {
        let dir = TempDir::new("acct-nokeys");
        let issuer = Issuer::new("k1");
        let server = KeyServer {
            jwks: Mutex::new(None),
            fetches: AtomicUsize::new(0),
        };
        let t0 = 1_800_000_000_000;
        assert_eq!(
            check_at(
                &dir.0,
                &server,
                &statement_at(&issuer, &[7; 32], t0),
                &[7; 32],
                t0
            ),
            Err(codes::KEYS_STALE)
        );
    }

    #[test]
    fn statements_for_another_device_host_or_time_are_refused() {
        let dir = TempDir::new("acct-claims");
        let issuer = Issuer::new("k1");
        let server = KeyServer::serving(issuer.jwks());
        let t0 = 1_800_000_000_000;
        let jws = statement_at(&issuer, &[7; 32], t0);
        assert_eq!(
            check_at(&dir.0, &server, &jws, &[8; 32], t0),
            Err(codes::INVALID)
        );
        assert_eq!(
            check_at(&dir.0, &server, &jws, &[7; 32], t0 + 11 * MINUTE + 1000),
            Err(codes::EXPIRED)
        );
        let other_host =
            issuer.sign(&issuer.claims("OtherHostExample-01234", &[7; 32], SUB, t0 / 1000));
        assert_eq!(
            check_at(&dir.0, &server, &other_host, &[7; 32], t0),
            Err(codes::INVALID)
        );
        assert_eq!(server.fetches(), 1);
    }
}
