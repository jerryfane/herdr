//! One-shot HTTP/1.1 requests over the link's rustls setup: the short invite
//! links' store and delete on the guest relay ([`super::invite`]), and the
//! account service's signing keys ([`crate::guest::account`]). Each request is
//! bounded by its timeout from DNS to the last byte read.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tungstenite::http::Uri;

use super::relay;

/// The response head must end within this many bytes.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// Where a request goes. Production endpoints use TLS; tests also accept a
/// plain `http://` stub.
pub(crate) struct Endpoint {
    tls: bool,
    /// Host name or address, without IPv6 brackets.
    host: String,
    port: u16,
    pub(crate) authority: String,
    pub(crate) path: String,
}

impl Endpoint {
    /// `path` below `base_url`'s own path. `setting` names the config key in
    /// errors.
    pub(crate) fn new(setting: &str, base_url: &str, path: &str) -> Result<Self, String> {
        let invalid = || format!("{setting} {base_url:?} is not an https:// URL");
        let uri: Uri = base_url
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
            path: format!("{}{path}", uri.path().trim_end_matches('/')),
            host,
            authority,
        })
    }
}

/// How much of the response a request wants.
#[derive(Clone, Copy)]
pub(crate) enum Body {
    /// Only the status line; the rest is never read.
    Ignore,
    /// The whole body, refused when longer than this many bytes.
    Read(usize),
}

pub(crate) struct Response {
    pub(crate) status: u16,
    /// Empty for [`Body::Ignore`].
    pub(crate) body: Vec<u8>,
}

/// `GET` `path` below `base_url`, reading a body of at most `max_body` bytes.
/// `peer` names the server in errors.
pub(crate) fn get(
    peer: &'static str,
    setting: &str,
    base_url: &str,
    path: &str,
    max_body: usize,
    timeout: Duration,
) -> Result<Response, String> {
    let endpoint = Endpoint::new(setting, base_url, path)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        endpoint.path, endpoint.authority
    );
    exchange(
        peer,
        endpoint,
        request.into_bytes(),
        Body::Read(max_body),
        timeout,
    )
}

/// Runs the request on a helper thread, since DNS cannot be given a timeout.
/// A lookup that outlives the deadline finishes in the background and its
/// result is discarded.
pub(crate) fn exchange(
    peer: &'static str,
    endpoint: Endpoint,
    request: Vec<u8>,
    body: Body,
    timeout: Duration,
) -> Result<Response, String> {
    let deadline = Instant::now() + timeout;
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("herdr-guest-https".into())
        .spawn(move || {
            let _ = sender.send(exchange_blocking(peer, &endpoint, &request, body, deadline));
        })
        .map_err(|error| format!("{peer} unreachable: {error}"))?;
    receiver
        .recv_timeout(timeout)
        .unwrap_or_else(|_| Err(format!("{peer} timed out")))
}

fn exchange_blocking(
    peer: &'static str,
    endpoint: &Endpoint,
    request: &[u8],
    body: Body,
    deadline: Instant,
) -> Result<Response, String> {
    let tcp = relay::connect_blocking(&endpoint.host, endpoint.port, deadline)
        .map_err(|error| format!("{peer} unreachable: {error}"))?;
    let stream = Bounded { tcp, deadline };
    if !endpoint.tls {
        return respond(peer, stream, request, body);
    }
    let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
        .map_err(|_| format!("{peer} host is not a TLS server name"))?;
    let connection = rustls::ClientConnection::new(relay::tls_config()?, name)
        .map_err(|error| format!("tls setup: {error}"))?;
    respond(
        peer,
        rustls::StreamOwned::new(connection, stream),
        request,
        body,
    )
}

/// Writes the request and reads the status line, then the body if wanted.
fn respond(
    peer: &'static str,
    mut stream: impl Read + Write,
    request: &[u8],
    body: Body,
) -> Result<Response, String> {
    stream
        .write_all(request)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("{peer} write: {error}"))?;
    let no_status = || format!("{peer} sent no HTTP status");
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut read = |received: &mut Vec<u8>| -> Result<bool, String> {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("{peer} read: {error}"))?;
        received.extend_from_slice(&buffer[..count]);
        Ok(count > 0)
    };
    let status = loop {
        if let Some(end) = find(&received, b"\r\n") {
            break parse_status(&received[..end]).ok_or_else(no_status)?;
        }
        if received.len() >= MAX_RESPONSE_HEAD {
            return Err(no_status());
        }
        if !read(&mut received)? {
            return Err(format!("{peer} closed the connection"));
        }
    };
    let Body::Read(max_body) = body else {
        return Ok(Response {
            status,
            body: Vec::new(),
        });
    };
    let head_end = loop {
        if let Some(end) = find(&received, b"\r\n\r\n") {
            break end;
        }
        if received.len() >= MAX_RESPONSE_HEAD {
            return Err(format!("{peer} sent an oversized response head"));
        }
        if !read(&mut received)? {
            return Err(format!("{peer} closed the connection"));
        }
    };
    let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
    let chunked = header(&head, "transfer-encoding").is_some_and(|value| value.contains("chunked"));
    let length = header(&head, "content-length").and_then(|value| value.parse::<usize>().ok());
    if length.is_some_and(|length| length > max_body) {
        return Err(format!("{peer} response is over {max_body} bytes"));
    }
    // Chunk framing is at most a few bytes per chunk on top of the body.
    let limit = head_end + 4 + max_body.saturating_mul(2) + 1024;
    let mut rest = received.split_off(head_end + 4);
    loop {
        if let Some(length) = length {
            if rest.len() >= length {
                rest.truncate(length);
                break;
            }
        }
        if head_end + 4 + rest.len() > limit {
            return Err(format!("{peer} response is over {max_body} bytes"));
        }
        if !read(&mut rest)? {
            if length.is_some() {
                return Err(format!("{peer} closed the connection"));
            }
            break;
        }
    }
    let body = if chunked {
        dechunk(&rest).ok_or_else(|| format!("{peer} sent a malformed chunked body"))?
    } else {
        rest
    };
    if body.len() > max_body {
        return Err(format!("{peer} response is over {max_body} bytes"));
    }
    Ok(Response { status, body })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A header's value in a lowercased response head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then(|| value.trim())
    })
}

/// The body of a complete `Transfer-Encoding: chunked` payload.
fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = find(data, b"\r\n")?;
        let size_text = std::str::from_utf8(&data[..line_end]).ok()?;
        let size_text = size_text.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if data.len() < size + 2 || &data[size..size + 2] != b"\r\n" {
            return None;
        }
        body.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
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
    use std::io::{BufRead as _, BufReader};
    use std::net::TcpListener;

    use super::*;

    /// A plain-HTTP server answering every request with `respond(path)`:
    /// the raw response bytes after the request head was read.
    pub(crate) struct StubServer {
        pub url: String,
        pub paths: mpsc::Receiver<String>,
    }

    impl StubServer {
        pub(crate) fn start(respond: impl Fn(&str) -> Vec<u8> + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (sender, paths) = mpsc::channel();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut reader = BufReader::new(&stream);
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    let path = line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned();
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                            break;
                        }
                    }
                    let _ = stream.write_all(&respond(&path));
                    if sender.send(path).is_err() {
                        return;
                    }
                }
            });
            Self { url, paths }
        }

        /// Answers `status` with `body` and a Content-Length.
        pub(crate) fn json(status: u16, body: String) -> Self {
            Self::start(move |_| {
                format!(
                    "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            })
        }
    }

    fn get_from(url: &str, max_body: usize) -> Result<Response, String> {
        get(
            "stub",
            "url",
            url,
            "/x/y.json",
            max_body,
            Duration::from_secs(5),
        )
    }

    #[test]
    fn get_reads_the_body_by_length_and_chunked() {
        let stub = StubServer::json(200, "{\"keys\":[]}".into());
        let response = get_from(&stub.url, 1024).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"keys\":[]}");
        assert_eq!(stub.paths.recv().unwrap(), "/x/y.json");

        let chunked = StubServer::start(|_| {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\n{\"a\"\r\n3;ext=1\r\n:1}\r\n0\r\n\r\n"
                .to_vec()
        });
        assert_eq!(get_from(&chunked.url, 1024).unwrap().body, b"{\"a\":1}");

        let until_close = StubServer::start(|_| b"HTTP/1.1 503 Busy\r\n\r\nlater".to_vec());
        let response = get_from(&until_close.url, 1024).unwrap();
        assert_eq!(
            (response.status, response.body.as_slice()),
            (503, &b"later"[..])
        );
    }

    #[test]
    fn get_refuses_oversized_and_malformed_bodies() {
        let big = StubServer::json(200, "x".repeat(100));
        assert!(get_from(&big.url, 99)
            .unwrap_err()
            .contains("over 99 bytes"));
        let unframed = StubServer::start(|_| {
            let mut response = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
            response.extend(std::iter::repeat_n(b'x', 5000));
            response
        });
        assert!(get_from(&unframed.url, 1000).is_err());
        let broken = StubServer::start(|_| {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec()
        });
        assert!(get_from(&broken.url, 1000).unwrap_err().contains("chunked"));
        assert!(get_from("ftp://keys.test", 10).is_err());
    }
}
