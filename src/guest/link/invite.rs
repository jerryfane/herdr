//! Short invite links. The v1 invite JSON is sealed with AES-128-GCM under a
//! fresh key and stored on the guest relay (`PUT /v1/invite/{id}`); the link
//! carries the id and the key, so the relay holds only ciphertext it cannot
//! open. Requests are one-shot HTTP/1.1 over the same rustls setup as the host
//! socket, bounded by [`TIMEOUT`] from DNS to the status line.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN};
use tungstenite::http::Uri;

use super::relay;
use crate::guest::store::{b64url, random_bytes, HostIdentity};

/// Random bytes in a blob id: 12 base64url characters.
const ID_BYTES: usize = 9;
/// AES-128 key bytes: 22 base64url characters.
const KEY_BYTES: usize = 16;
const TAG_LEN: usize = 16;
/// Largest blob the relay stores.
const MAX_BLOB: usize = 2048;
/// Whole-request bound: the owner waits on it for the invite reply.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The status line must arrive within this many bytes.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

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
    let random = |error: io::Error| format!("randomness: {error}");
    let id = b64url(&random_bytes::<ID_BYTES>().map_err(random)?);
    let key = random_bytes::<KEY_BYTES>().map_err(random)?;
    let blob = seal(&key, &id, payload)?;
    let expires = expires_unix.to_string();
    match send(
        relay_url,
        host,
        "PUT",
        &id,
        &[
            ("X-Herdr-Expires", &expires),
            ("Content-Type", "application/octet-stream"),
        ],
        &blob,
    )? {
        201 => Ok(Published {
            web_url: short_web_url(relay_url, &id, &b64url(&key)),
            id,
        }),
        status => Err(format!("relay answered HTTP {status}")),
    }
}

/// Drop blob `id` from the relay. Already gone counts as deleted.
pub(crate) fn delete(relay_url: &str, host: &HostIdentity, id: &str) -> Result<(), String> {
    match send(relay_url, host, "DELETE", id, &[], &[])? {
        200 | 204 | 404 => Ok(()),
        status => Err(format!("relay answered HTTP {status}")),
    }
}

/// Where `/v1/invite/{id}` lives on the relay. Production relays use TLS;
/// tests also accept a plain `http://` stub.
struct Endpoint {
    tls: bool,
    /// Host name or address, without IPv6 brackets.
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Endpoint {
    fn new(relay_url: &str, id: &str) -> Result<Self, String> {
        let invalid = || format!("relay_url {relay_url:?} is not an https:// URL");
        let uri: Uri = relay_url
            .trim_end_matches('/')
            .parse()
            .map_err(|_| invalid())?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") if cfg!(test) => false,
            _ => return Err(invalid()),
        };
        let authority = uri.authority().ok_or_else(invalid)?.as_str().to_owned();
        if authority.contains('@') || uri.query().is_some() {
            return Err(invalid());
        }
        let host = uri
            .host()
            .ok_or_else(invalid)?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        Ok(Self {
            tls,
            port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
            path: format!("{}/v1/invite/{id}", uri.path().trim_end_matches('/')),
            host,
            authority,
        })
    }
}

/// One host-authenticated request; the HTTP status.
fn send(
    relay_url: &str,
    host: &HostIdentity,
    method: &str,
    id: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<u16, String> {
    if !valid_id(id) {
        return Err("invite blob id is not 12 base64url characters".into());
    }
    // Both land in headers: anything but base64url could smuggle a header.
    if !is_b64url(&host.host_id) || !is_b64url(&host.relay_secret) {
        return Err("host identity is not base64url".into());
    }
    let endpoint = Endpoint::new(relay_url, id)?;
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
    exchange(endpoint, request)
}

/// Runs the request on a helper thread, since DNS cannot be given a timeout.
/// A lookup that outlives the deadline finishes in the background and its
/// result is discarded.
fn exchange(endpoint: Endpoint, request: Vec<u8>) -> Result<u16, String> {
    let deadline = Instant::now() + TIMEOUT;
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("herdr-guest-invite".into())
        .spawn(move || {
            let _ = sender.send(exchange_blocking(&endpoint, &request, deadline));
        })
        .map_err(|error| format!("relay unreachable: {error}"))?;
    receiver
        .recv_timeout(TIMEOUT)
        .unwrap_or_else(|_| Err("relay timed out".into()))
}

fn exchange_blocking(
    endpoint: &Endpoint,
    request: &[u8],
    deadline: Instant,
) -> Result<u16, String> {
    let tcp = relay::connect_blocking(&endpoint.host, endpoint.port, deadline)
        .map_err(|error| format!("relay unreachable: {error}"))?;
    let stream = Bounded { tcp, deadline };
    if !endpoint.tls {
        return status(stream, request);
    }
    let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
        .map_err(|_| "relay host is not a TLS server name".to_string())?;
    let connection = rustls::ClientConnection::new(relay::tls_config()?, name)
        .map_err(|error| format!("tls setup: {error}"))?;
    status(rustls::StreamOwned::new(connection, stream), request)
}

/// Writes the request and reads up to the status line; the rest of the
/// response is never read.
fn status(mut stream: impl Read + Write, request: &[u8]) -> Result<u16, String> {
    stream
        .write_all(request)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("relay write: {error}"))?;
    let mut head = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        if let Some(end) = head.windows(2).position(|pair| pair == b"\r\n") {
            return parse_status(&head[..end]).ok_or_else(|| "relay sent no HTTP status".into());
        }
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err("relay sent no HTTP status".into());
        }
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("relay read: {error}"))?;
        if read == 0 {
            return Err("relay closed the connection".into());
        }
        head.extend_from_slice(&buffer[..read]);
    }
}

fn parse_status(line: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    (code.len() == 3).then(|| code.parse().ok()).flatten()
}

/// A socket whose every read and write is bounded by what is left of the
/// request's deadline.
struct Bounded {
    tcp: TcpStream,
    deadline: Instant,
}

impl Bounded {
    fn left(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "timed out"))
    }
}

impl Read for Bounded {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.left()?))?;
        self.tcp.read(buf)
    }
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.left()?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead as _, BufReader};
    use std::net::TcpListener;

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
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (sender, received) = mpsc::channel();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    let Some(request) = read_request(&stream) else {
                        continue;
                    };
                    let mut stream = stream;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {} Stub\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        respond()
                    );
                    if sender.send(request).is_err() {
                        return;
                    }
                }
            });
            Self { url, received }
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
