//! APNs auth-token (ES256 JWT) minting, signed in-process with `p256`.
//!
//! Apple's provider API authenticates with a short-lived ES256 JWT rather than a
//! TLS client certificate, so no networking stack is required to build it — only
//! ECDSA/P-256 signing (RustCrypto `p256`, deterministic RFC6979, no RNG). Tokens
//! may be reused for up to 60 minutes; we cache and refresh at ~50 minutes.
//!
//! The `.p8` PEM passed here is APNs key material: it is never logged, and parse
//! failures are reported with a static message rather than echoing the input.

use std::sync::Mutex;

use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

/// Refresh the cached token once it is older than this. Apple caps reuse at 60
/// minutes; 50 leaves a comfortable margin.
const TOKEN_REFRESH_AFTER_SECS: u64 = 50 * 60;

#[derive(Clone)]
struct CachedToken {
    token: String,
    issued_at_unix: u64,
    key_id: String,
    team_id: String,
}

static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

/// True when a token minted at `issued_at_unix` is still fresh enough to reuse
/// for the same key/team at `now_unix`. Pure, so the reuse policy is testable.
///
/// A backward clock jump (`now_unix < issued_at_unix`) forces a refresh: without
/// this guard the saturating subtraction would read as age 0 and keep a token
/// "fresh forever" after the clock rewinds.
fn cached_token_is_fresh(cached: &CachedToken, key_id: &str, team_id: &str, now_unix: u64) -> bool {
    cached.key_id == key_id
        && cached.team_id == team_id
        && now_unix >= cached.issued_at_unix
        && now_unix.saturating_sub(cached.issued_at_unix) < TOKEN_REFRESH_AFTER_SECS
}

/// Drop any cached token so the next `auth_token` mints a fresh one. Called when
/// APNs rejects the token with 403 (InvalidProviderToken / clock skew). Recovers
/// from a poisoned lock so a bad token is always cleared.
pub(super) fn clear_cache() {
    let mut guard = TOKEN_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Return a valid APNs auth JWT, reusing a process-cached token until it ages
/// past ~50 minutes. `pem` is the PKCS#8 `.p8` contents and is never logged.
pub(super) fn auth_token(
    pem: &str,
    key_id: &str,
    team_id: &str,
    now_unix: u64,
) -> Result<String, String> {
    // A poisoned lock should not stop delivery: fall back to an uncached mint.
    let Ok(mut guard) = TOKEN_CACHE.lock() else {
        return sign_jwt(pem, key_id, team_id, now_unix);
    };
    if let Some(cached) = guard.as_ref() {
        if cached_token_is_fresh(cached, key_id, team_id, now_unix) {
            return Ok(cached.token.clone());
        }
    }
    let token = sign_jwt(pem, key_id, team_id, now_unix)?;
    *guard = Some(CachedToken {
        token: token.clone(),
        issued_at_unix: now_unix,
        key_id: key_id.to_string(),
        team_id: team_id.to_string(),
    });
    Ok(token)
}

/// Build and ES256-sign one APNs auth JWT. Deterministic given its inputs, so it
/// is directly unit-testable; `now_unix` is the `iat` claim.
fn sign_jwt(pem: &str, key_id: &str, team_id: &str, now_unix: u64) -> Result<String, String> {
    let secret = p256::SecretKey::from_pkcs8_pem(pem)
        .map_err(|_| "failed to parse APNs signing key (.p8)".to_string())?;
    let signing_key = SigningKey::from(&secret);

    let header = serde_json::json!({ "alg": "ES256", "kid": key_id });
    let claims = serde_json::json!({ "iss": team_id, "iat": now_unix });

    let header_segment = base64url(
        &serde_json::to_vec(&header)
            .map_err(|err| format!("failed to encode JWT header: {err}"))?,
    );
    let claims_segment = base64url(
        &serde_json::to_vec(&claims)
            .map_err(|err| format!("failed to encode JWT claims: {err}"))?,
    );
    let signing_input = format!("{header_segment}.{claims_segment}");

    let signature: Signature = signing_key
        .try_sign(signing_input.as_bytes())
        .map_err(|err| format!("failed to sign APNs auth token: {err}"))?;
    let signature_segment = base64url(signature.to_bytes().as_slice());

    Ok(format!("{signing_input}.{signature_segment}"))
}

fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    // Throwaway P-256 key generated only for this test. Not an Apple key and not
    // used for any real APNs topic.
    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc0TCsXV015Y7jRII\n\
TWS/Pl/mxw5V+ZKn/ApTyUXhbkahRANCAATVRnA8IaJoAlQ1R0VdOCv5lIQ5rJBz\n\
vL6kDjG2WoCWOAn81uKLHgk6KHFtF9x0R0A/UYt7lEDzCLiZzeJZlXxL\n\
-----END PRIVATE KEY-----\n";

    fn decode(segment: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("segment is valid base64url")
    }

    #[test]
    fn mints_and_signs_a_verifiable_es256_jwt() {
        let now = 1_700_000_000u64;
        let token = sign_jwt(TEST_PEM, "ABC123DEFG", "TEAM123456", now).unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWT has three dot-separated segments");

        let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "ABC123DEFG");

        let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["iat"], now);

        // Round-trip: verify the signature against the public key derived from
        // the same secret, over the exact `header.claims` signing input.
        let secret = p256::SecretKey::from_pkcs8_pem(TEST_PEM).unwrap();
        let verifying_key = VerifyingKey::from(&SigningKey::from(&secret));
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = Signature::from_slice(&decode(parts[2])).unwrap();
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verifies against the derived public key");
    }

    #[test]
    fn cached_token_freshness_tracks_the_50_minute_window() {
        let cached = CachedToken {
            token: "t".to_string(),
            issued_at_unix: 1_000,
            key_id: "KID".to_string(),
            team_id: "TEAM".to_string(),
        };
        // Same key/team, within the window -> reuse.
        assert!(cached_token_is_fresh(
            &cached,
            "KID",
            "TEAM",
            1_000 + 10 * 60
        ));
        // Aged past the window -> refresh.
        assert!(!cached_token_is_fresh(
            &cached,
            "KID",
            "TEAM",
            1_000 + TOKEN_REFRESH_AFTER_SECS
        ));
        // Different key or team -> never reuse.
        assert!(!cached_token_is_fresh(&cached, "OTHER", "TEAM", 1_000));
        assert!(!cached_token_is_fresh(&cached, "KID", "OTHER", 1_000));
        // Backward clock jump -> refresh, never "fresh forever".
        assert!(!cached_token_is_fresh(&cached, "KID", "TEAM", 500));
    }
}
