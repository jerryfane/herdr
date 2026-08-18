//! Shared shapes for the federation TCP transport handshake.
//!
//! A federation TCP client sends one `federation.hello` line carrying a shared
//! token before any request. The inbound listener ([`crate::api::server`])
//! validates that token in constant time before it will dispatch a single
//! request on the connection, and the outbound client ([`crate::api::client`])
//! writes the same line right after it connects. Both sides agree on the exact
//! wire shape here so neither can drift from the other.

use serde::{Deserialize, Serialize};

/// The `type` discriminator every federation hello line carries.
pub(crate) const FEDERATION_HELLO_TYPE: &str = "federation.hello";

/// First line a federation TCP client sends: a shared-token hello.
///
/// The wire form is exactly `{"type":"federation.hello","token":"<t>"}`. A
/// request line (which has no `token` field, or a different `type`) fails to
/// deserialize into this struct or fails the [`FEDERATION_HELLO_TYPE`] check,
/// so a client that skips the hello is rejected rather than dispatched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FederationHello {
    #[serde(rename = "type")]
    pub kind: String,
    pub token: String,
}

impl FederationHello {
    pub(crate) fn new(token: impl Into<String>) -> Self {
        Self {
            kind: FEDERATION_HELLO_TYPE.to_string(),
            token: token.into(),
        }
    }

    /// Serialize to the single-line wire form (no trailing newline).
    pub(crate) fn to_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a received hello line and return the token only when the line is a
    /// well-formed hello with the expected `type`. Any other shape (a stray
    /// request line, wrong `type`, missing `token`) yields `None`.
    pub(crate) fn token_from_line(line: &str) -> Option<String> {
        match serde_json::from_str::<FederationHello>(line) {
            Ok(hello) if hello.kind == FEDERATION_HELLO_TYPE => Some(hello.token),
            _ => None,
        }
    }
}

/// Compare two byte strings without an early return, so the time taken does not
/// reveal how many leading bytes matched. Length still short-circuits — a token
/// length is not a useful secret — but the byte comparison itself is uniform.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// True when `candidate` matches any configured token. Every token is checked
/// (no short-circuit across the set) so acceptance timing does not reveal which
/// token matched or how many were configured.
pub(crate) fn token_is_authorized(candidate: &str, tokens: &[String]) -> bool {
    let mut matched = false;
    for token in tokens {
        matched |= constant_time_eq(candidate.as_bytes(), token.as_bytes());
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips_to_the_exact_wire_shape() {
        let line = FederationHello::new("s3cret").to_line().unwrap();
        assert_eq!(line, r#"{"type":"federation.hello","token":"s3cret"}"#);
        assert_eq!(
            FederationHello::token_from_line(&line).as_deref(),
            Some("s3cret")
        );
    }

    #[test]
    fn a_request_line_is_not_a_hello() {
        // A normal request line has no token field and a different (absent) type.
        assert!(FederationHello::token_from_line(r#"{"id":"1","method":"ping"}"#).is_none());
        // Right shape, wrong type discriminator.
        assert!(FederationHello::token_from_line(r#"{"type":"other","token":"x"}"#).is_none());
        // Not JSON at all.
        assert!(FederationHello::token_from_line("garbage").is_none());
    }

    #[test]
    fn constant_time_eq_matches_std_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn token_is_authorized_accepts_any_configured_token() {
        let tokens = vec!["alpha".to_string(), "beta".to_string()];
        assert!(token_is_authorized("alpha", &tokens));
        assert!(token_is_authorized("beta", &tokens));
        assert!(!token_is_authorized("gamma", &tokens));
        assert!(!token_is_authorized("alpha", &[]));
    }
}
