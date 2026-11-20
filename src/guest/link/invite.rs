//! Short invite links. The v1 invite JSON is sealed with AES-128-GCM under a
//! fresh key and stored encrypted on the guest relay (`PUT /v1/invite/{id}`).
//! The key is in the link's path (`/i/{id}{key}`, not a fragment, which some
//! messengers cut off), so the relay sees it whenever the link is opened
//! through it: the stored copy is encrypted, the link is not end-to-end.
//! Requests are one-shot HTTP/1.1 over the same rustls setup as the host
//! socket ([`super::https`]), each bounded from DNS to the status line: the
//! store by [`PUT_BUDGETS`], the delete by [`TIMEOUT`].

use std::io;
use std::time::Duration;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN};

use super::https::{self, Body, Endpoint};
use crate::guest::store::{b64url, random_bytes, HostIdentity};

/// Random bytes in a blob id: 12 base64url characters.
const ID_BYTES: usize = 9;
/// AES-128 key bytes: 22 base64url characters.
const KEY_BYTES: usize = 16;
const TAG_LEN: usize = 16;
/// Largest blob the relay stores.
const MAX_BLOB: usize = 2048;
/// Whole-request bound for a delete.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The store's bound, then a fresh one for its single retry. The owner waits
/// on both for the invite reply before falling back to the long link.
const PUT_BUDGETS: [Duration; 2] = [Duration::from_secs(5), Duration::from_secs(8)];

/// A sealed invite stored on the relay.
pub(crate) struct Published {
    pub id: String,
    pub web_url: String,
}

/// The short web link: one path segment, the 12-character id followed by the
/// 22-character key. The only place the short link's shape is built.
fn short_web_url(relay: &str, id: &str, key: &str) -> String {
    format!("{}/i/{id}{key}", relay.trim_end_matches('/'))
}

/// A blob id as the relay accepts it: 12 base64url characters.
pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 12 && is_b64url(id)
}

fn is_b64url(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// `nonce || ciphertext || tag` under a fresh random nonce, with the blob id
/// as associated data so a blob cannot be served under another id.
fn seal(key: &[u8; KEY_BYTES], id: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = random_bytes::<NONCE_LEN>().map_err(|error| format!("randomness: {error}"))?;
    seal_with_nonce(key, id, nonce, plaintext)
}

fn seal_with_nonce(
    key: &[u8; KEY_BYTES],
    id: &str,
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_128_GCM, key).map_err(|_| "invite key rejected".to_string())?,
    );
    let mut blob = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(plaintext);
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(id.as_bytes()),
            &mut blob[NONCE_LEN..],
        )
        .map_err(|_| "invite sealing failed".to_string())?;
    blob.extend_from_slice(tag.as_ref());
    if blob.len() > MAX_BLOB {
        return Err(format!("sealed invite is {} bytes", blob.len()));
    }
    Ok(blob)
}

/// Seal `payload`, the v1 invite JSON, and store it on the relay until
/// `expires_unix`. The short link is returned only once the relay answered 201.
pub(crate) fn publish(
    relay_url: &str,
    host: &HostIdentity,
    expires_unix: u64,
    payload: &[u8],
) -> Result<Published, String> {
    publish_within(relay_url, host, expires_unix, payload, PUT_BUDGETS)
}

/// [`publish`] with the PUT sent at most twice, under `budgets` in turn. Only
/// a PUT without an answer is sent again, byte for byte: the first may have
/// been stored after all, and the relay takes the same blob again from the
/// host that stored it. An answer other than 201 is final.
fn publish_within(
    relay_url: &str,
    host: &HostIdentity,
    expires_unix: u64,
    payload: &[u8],
    budgets: [Duration; 2],
) -> Result<Published, String> {
    let random = |error: io::Error| format!("randomness: {error}");
    let id = b64url(&random_bytes::<ID_BYTES>().map_err(random)?);
    let key = random_bytes::<KEY_BYTES>().map_err(random)?;
    let blob = seal(&key, &id, payload)?;
    let expires = expires_unix.to_string();
    let (endpoint, put) = request(
        relay_url,
        host,
        "PUT",
        &id,
        &[
            ("X-Herdr-Expires", &expires),
            ("Content-Type", "application/octet-stream"),
        ],
        &blob,
    )?;
    let [first, retry] = budgets;
    // One error for both attempts, so the caller's single warning tells it all.
    let status = match exchange(endpoint.clone(), put.clone(), first) {
        Ok(status) => status,
        Err(first) => {
            exchange(endpoint, put, retry).map_err(|retry| format!("{first}; retried: {retry}"))?
        }
    };
    match status {
        201 => Ok(Published {
            web_url: short_web_url(relay_url, &id, &b64url(&key)),
            id,
        }),
        status => Err(format!("relay answered HTTP {status}")),
    }
}

/// Drop blob `id` from the relay. Already gone counts as deleted.
pub(crate) fn delete(relay_url: &str, host: &HostIdentity, id: &str) -> Result<(), String> {
    let (endpoint, bytes) = request(relay_url, host, "DELETE", id, &[], &[])?;
    match exchange(endpoint, bytes, TIMEOUT)? {
        200 | 204 | 404 => Ok(()),
        status => Err(format!("relay answered HTTP {status}")),
    }
}

/// One host-authenticated request: where it goes and its bytes.
fn request(
    relay_url: &str,
    host: &HostIdentity,
    method: &str,
    id: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(Endpoint, Vec<u8>), String> {
    if !valid_id(id) {
        return Err("invite blob id is not 12 base64url characters".into());
    }
    // Both land in headers: anything but base64url could smuggle a header.
    if !is_b64url(&host.host_id) || !is_b64url(&host.relay_secret) {
        return Err("host identity is not base64url".into());
    }
    let endpoint = Endpoint::new("relay_url", relay_url, &format!("/v1/invite/{id}"))?;
    let mut request = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nX-Herdr-Host: {}\r\n",
        endpoint.path, endpoint.authority, host.relay_secret, host.host_id
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut request = request.into_bytes();
    request.extend_from_slice(body);
    Ok((endpoint, request))
}

/// Sends a [`request`] within `timeout`; the HTTP status.
fn exchange(endpoint: Endpoint, request: Vec<u8>, timeout: Duration) -> Result<u16, String> {
    https::exchange("relay", endpoint, request, Body::Ignore, timeout)
        .map(|response| response.status)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    use super::*;
    use crate::guest::store::b64url_decode;

    /// Opens a blob as a client does: AES-128-GCM with the id as AAD.
    pub(crate) fn open(key: &[u8], id: &str, blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let (nonce, sealed) = blob.split_at(NONCE_LEN);
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).ok()?);
        let mut sealed = sealed.to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).ok()?,
                Aad::from(id.as_bytes()),
                &mut sealed,
            )
            .ok()?;
        Some(plaintext.to_vec())
    }

    /// One request as the stub relay received it.
    #[derive(Debug)]
    pub(crate) struct Received {
        pub method: String,
        pub path: String,
        /// Lowercased names.
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
    }

    /// How the stub relay meets one request.
    #[derive(Clone, Copy)]
    pub(crate) enum Reply {
        /// This status, after this long.
        Late(Duration, u16),
        /// Closes the connection without an answer.
        HangUp,
    }

    /// A plain-HTTP relay stub; each request gets the status `respond` picks.
    pub(crate) struct StubInviteRelay {
        pub url: String,
        pub received: mpsc::Receiver<Received>,
    }

    impl StubInviteRelay {
        pub(crate) fn start(status: u16) -> Self {
            Self::start_with(move || status)
        }

        pub(crate) fn start_with(respond: impl Fn() -> u16 + Send + 'static) -> Self {
            Self::start_replying(move || Reply::Late(Duration::ZERO, respond()))
        }

        /// Meets each request as `reply` picks, on its own thread, so a late
        /// answer holds up no later request.
        pub(crate) fn start_replying(reply: impl Fn() -> Reply + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (sender, received) = mpsc::channel();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let Some(request) = read_request(&stream) else {
                        continue;
                    };
                    let reply = reply();
                    if sender.send(request).is_err() {
                        return;
                    }
                    thread::spawn(move || match reply {
                        Reply::Late(after, status) => {
                            thread::sleep(after);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 {status} Stub\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                        Reply::HangUp => drop(stream),
                    });
                }
            });
            Self { url, received }
        }

        /// Replies in turn from `replies`, then the last one again.
        pub(crate) fn start_in_turn(replies: Vec<Reply>) -> Self {
            let next = std::sync::atomic::AtomicUsize::new(0);
            Self::start_replying(move || {
                let turn = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                replies[turn.min(replies.len() - 1)]
            })
        }

        pub(crate) fn next(&self) -> Received {
            self.received
                .recv_timeout(Duration::from_secs(10))
                .expect("the relay stub received a request")
        }
    }

    fn read_request(stream: &TcpStream) -> Option<Received> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let mut parts = line.split_whitespace();
        let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
        let mut headers = HashMap::new();
        loop {
            line.clear();
            reader.read_line(&mut line).ok()?;
            let header = line.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':')?;
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length = headers
            .get("content-length")
            .and_then(|length| length.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
        Some(Received {
            method,
            path,
            headers,
            body,
        })
    }

    pub(crate) fn host() -> HostIdentity {
        HostIdentity {
            host_id: "h".repeat(22),
            relay_secret: "s".repeat(43),
        }
    }

    #[test]
    fn a_sealed_blob_opens_only_with_its_key_and_id() {
        let key = [7u8; KEY_BYTES];
        let blob = seal(&key, "AAAAAAAAAAAA", b"{\"v\":1}").unwrap();
        assert_eq!(blob.len(), NONCE_LEN + 7 + TAG_LEN);
        assert_eq!(
            open(&key, "AAAAAAAAAAAA", &blob).as_deref(),
            Some(&b"{\"v\":1}"[..])
        );
        assert!(
            open(&key, "BBBBBBBBBBBB", &blob).is_none(),
            "AAD binds the id"
        );
        assert!(open(&[8u8; KEY_BYTES], "AAAAAAAAAAAA", &blob).is_none());
        let mut tampered = blob.clone();
        tampered[NONCE_LEN] ^= 1;
        assert!(open(&key, "AAAAAAAAAAAA", &tampered).is_none());
        // Fresh nonces: the same plaintext never seals to the same blob.
        assert_ne!(seal(&key, "AAAAAAAAAAAA", b"{\"v\":1}").unwrap(), blob);
        assert!(seal(&key, "AAAAAAAAAAAA", &[0; MAX_BLOB]).is_err());
    }

    /// Known-answer vector shared with the relay page and the iOS app
    /// (produced independently with Python `cryptography`; synthetic ids).
    #[test]
    fn the_shared_known_answer_vector_seals_opens_and_links_identically() {
        use base64::Engine as _;
        const ID: &str = "AQIDBAUGBwgJ";
        const KEY: &str = "EBESExQVFhcYGRobHB0eHw";
        const LINK: &str =
            "https://guest.herdrup.themartian.app/i/AQIDBAUGBwgJEBESExQVFhcYGRobHB0eHw";
        const NONCE_HEX: &str = "303132333435363738393a3b";
        const BLOB_B64: &str = "MDEyMzQ1Njc4OTo76HmMcTjDzE3OdSaDaK9beuTqzPLVVEUBKIa8OWJbqs8XDxQL0uQJSTWFeZvgkikIe1wxOA3sk7Hb4x6wjfHjOvVi3zfizc3/SM6+90bB9XIi6BXSmuiq8Z6OGZXR7UrLkh6Inxwh/qbAALuB4Rutr24iIC1sU1lG5r7/RWTqMxLRqqDKR32zUCL9iDYu8gaErdUgZeTfpeik9cwTC2mS9pAAakSI/hIczZymbpBb/IrgIv1W3sHDAfC08BLtejXbbxeRGf9jCWTISaVmJu0US2YeF36Re83O9PTtHSl952NNjZtz9hsOMylQomFWeNSDDtRe9oRVNidH/AW4KZnvLpFPC8I0/kZw6IIj18rkR0tEUuZ6ftnsFbrAvQs7hsQn4o6LtYtbJsZ6qhrglLQsb2yiyz5ilcqpXIOl+XaAEjfijL7c8KyX2hbUvWFDH6GS2VWqnlXnKt0SW0rQEaZ4ZBTtBAhU9uehul9N9CJXoQq1";
        const PLAINTEXT: &str = r#"{"agent_name":"demo","expires_unix":4102444800,"guest_name":"guest","host_id":"QUFBQUFBQUFBQUFBQUFBQQ","host_pub":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","invite_id":"Q0NDQ0NDQ0NDQ0NDQ0NDQw","machine_label":"test-box","owner_name":"Owner","relay":"https://guest.herdrup.themartian.app","secret":"REREREREREREREREREREREREREREREREREREREREREQ","v":1}"#;

        let key: [u8; KEY_BYTES] = b64url_decode(KEY).unwrap().try_into().unwrap();
        let nonce: [u8; NONCE_LEN] = (0..NONCE_LEN)
            .map(|i| u8::from_str_radix(&NONCE_HEX[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let blob = base64::engine::general_purpose::STANDARD
            .decode(BLOB_B64)
            .unwrap();

        assert_eq!(open(&key, ID, &blob).as_deref(), Some(PLAINTEXT.as_bytes()));
        assert_eq!(
            seal_with_nonce(&key, ID, nonce, PLAINTEXT.as_bytes()).unwrap(),
            blob
        );
        assert_eq!(
            short_web_url("https://guest.herdrup.themartian.app", ID, KEY),
            LINK
        );
        assert!(valid_id(ID));
    }

    #[test]
    fn blob_ids_are_twelve_base64url_characters() {
        assert!(valid_id("k7Qp2xRmA1b_"));
        assert!(valid_id("-_-_-_-_-_-_"));
        assert!(!valid_id("k7Qp2xRmA1b"));
        assert!(!valid_id("k7Qp2xRmA1bCD"));
        assert!(!valid_id("k7Qp2xRm/1bC"));
        assert!(!valid_id("../v1/host/x"));
        assert!(!valid_id("k7Qp2xRmA1b="));
    }

    #[test]
    fn publish_puts_the_sealed_invite_and_returns_the_short_link() {
        let relay = StubInviteRelay::start(201);
        let payload = br#"{"v":1,"secret":"x"}"#;
        let published = publish(&format!("{}/", relay.url), &host(), 1_900_000_000, payload)
            .expect("published");
        let request = relay.next();
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, format!("/v1/invite/{}", published.id));
        assert_eq!(
            request.headers["authorization"],
            format!("Bearer {}", "s".repeat(43))
        );
        assert_eq!(request.headers["x-herdr-host"], "h".repeat(22));
        assert_eq!(request.headers["x-herdr-expires"], "1900000000");
        assert_eq!(request.headers["content-type"], "application/octet-stream");

        let segment = published
            .web_url
            .strip_prefix(&format!("{}/i/", relay.url))
            .expect("relay origin, /i/ path");
        assert_eq!(segment.len(), 34, "{}", published.web_url);
        assert!(is_b64url(segment));
        let (id, key) = segment.split_at(12);
        assert_eq!(id, published.id);
        assert!(valid_id(id));
        let key = b64url_decode(key).expect("b64url key");
        assert_eq!(key.len(), KEY_BYTES);
        assert_eq!(open(&key, id, &request.body).as_deref(), Some(&payload[..]));
    }

    #[test]
    fn publish_fails_unless_the_relay_stored_the_blob() {
        for status in [200, 401, 404, 409, 429, 500] {
            let relay = StubInviteRelay::start(status);
            let error = publish(&relay.url, &host(), 1_900_000_000, b"{}")
                .err()
                .unwrap_or_else(|| panic!("HTTP {status} is a failure"));
            assert_eq!(error, format!("relay answered HTTP {status}"));
        }
        // Nothing listening.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        assert!(publish(&url, &host(), 1_900_000_000, b"{}").is_err());
        assert!(publish("ftp://relay.test", &host(), 1_900_000_000, b"{}").is_err());
    }

    /// Nothing more reaches `relay` within a beat.
    fn no_more(relay: &StubInviteRelay) -> bool {
        relay
            .received
            .recv_timeout(Duration::from_millis(300))
            .is_err()
    }

    #[test]
    fn a_put_that_times_out_is_sent_once_more_with_a_fresh_budget() {
        // The first answer comes past its budget. The retry's comes later than
        // the first budget too, so only a fresh budget of its own lets it count.
        let relay = StubInviteRelay::start_in_turn(vec![
            Reply::Late(Duration::from_millis(600), 201),
            Reply::Late(Duration::from_millis(400), 201),
        ]);
        let budgets = [Duration::from_millis(200), Duration::from_secs(2)];
        let payload = br#"{"v":1,"secret":"x"}"#;
        let published = publish_within(&relay.url, &host(), 1_900_000_000, payload, budgets)
            .expect("the retry stored it");
        let (first, retry) = (relay.next(), relay.next());
        assert!(no_more(&relay), "one retry only");
        for request in [&first, &retry] {
            assert_eq!(request.method, "PUT");
            assert_eq!(request.path, format!("/v1/invite/{}", published.id));
        }
        assert_eq!(retry.headers, first.headers);
        // The same sealed bytes: the relay takes them again from the same host.
        assert_eq!(retry.body, first.body);
        let key = b64url_decode(&published.web_url[published.web_url.len() - 22..]).unwrap();
        assert_eq!(
            open(&key, &published.id, &retry.body).as_deref(),
            Some(&payload[..])
        );
    }

    #[test]
    fn publish_sends_a_put_left_without_an_answer_once_more() {
        let relay =
            StubInviteRelay::start_in_turn(vec![Reply::HangUp, Reply::Late(Duration::ZERO, 201)]);
        let published = publish(&relay.url, &host(), 1_900_000_000, b"{}").expect("short link");
        let (first, retry) = (relay.next(), relay.next());
        assert!(no_more(&relay), "one retry only");
        assert_eq!(retry.path, format!("/v1/invite/{}", published.id));
        assert_eq!(retry.body, first.body);
    }

    #[test]
    fn a_put_that_times_out_twice_fails_with_both_errors() {
        let relay = StubInviteRelay::start_in_turn(vec![Reply::Late(Duration::from_secs(1), 201)]);
        let budgets = [Duration::from_millis(100), Duration::from_millis(200)];
        let started = std::time::Instant::now();
        let error = publish_within(&relay.url, &host(), 1_900_000_000, b"{}", budgets)
            .err()
            .expect("no answer in either budget");
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "both budgets in full"
        );
        let (first, retry) = error.split_once("; retried: ").expect(&error);
        for attempt in [first, retry] {
            assert!(attempt.starts_with("relay "), "{error}");
            assert!(!attempt.contains("answered"), "{error}");
        }
        relay.next();
        relay.next();
        assert!(no_more(&relay), "one retry only");
    }

    #[test]
    fn a_relay_refusal_is_final_and_never_retried() {
        for status in [409, 401, 429, 500] {
            let relay = StubInviteRelay::start(status);
            let error = publish(&relay.url, &host(), 1_900_000_000, b"{}")
                .err()
                .unwrap_or_else(|| panic!("HTTP {status} is a failure"));
            assert_eq!(error, format!("relay answered HTTP {status}"));
            assert_eq!(relay.next().method, "PUT");
            assert!(no_more(&relay), "HTTP {status} was retried");
        }
    }

    #[test]
    fn errors_never_carry_the_relay_secret() {
        let relay = StubInviteRelay::start(401);
        let error = publish(&relay.url, &host(), 1_900_000_000, b"{}")
            .err()
            .expect("refused");
        assert!(!error.contains(&"s".repeat(43)), "{error}");
    }

    #[test]
    fn delete_is_host_authenticated_and_gone_counts_as_deleted() {
        let relay = StubInviteRelay::start(204);
        delete(&relay.url, &host(), "AAAAAAAAAAAA").unwrap();
        let request = relay.next();
        assert_eq!(request.method, "DELETE");
        assert_eq!(request.path, "/v1/invite/AAAAAAAAAAAA");
        assert_eq!(
            request.headers["authorization"],
            format!("Bearer {}", "s".repeat(43))
        );
        assert_eq!(request.headers["x-herdr-host"], "h".repeat(22));
        assert!(delete(&StubInviteRelay::start(404).url, &host(), "AAAAAAAAAAAA").is_ok());
        assert!(delete(&StubInviteRelay::start(401).url, &host(), "AAAAAAAAAAAA").is_err());
        assert!(delete(&relay.url, &host(), "../v1/host/x").is_err());
    }
}
