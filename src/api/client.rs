use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::api::schema::{
    ErrorResponse, Method, PingParams, Request, ResponseResult, SuccessResponse,
};
use crate::api::ssh_transport;
use crate::api::ApiStream;

/// Credential used for an outbound SSH federation connection.
///
/// v1 supports key-based auth only. [`SshCredential::Password`] is reserved for
/// a future version and is NOT implemented — constructing an SSH transport with
/// it is rejected.
// Constructed by the federation tests and the SSH transport now; CLI wiring that
// builds these from `[federation]` peer config lands in a later part.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshCredential {
    Key,
    Password(String),
}

/// An outbound SSH federation target reached via `herdr api-bridge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    pub host: String,
    pub user: Option<String>,
    pub credential: SshCredential,
}

/// API connection target resolved by clients at the process edge.
///
/// The `Tcp`/`Ssh` federation variants are constructed by tests and the SSH
/// transport now; the CLI surface that builds them from `[federation]` peer
/// config lands in a later part, so they read as unconstructed in a non-test
/// build until then.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTarget {
    LocalSession(Option<String>),
    SocketPath(PathBuf),
    /// A federation TCP peer. `token`, when set, is sent as the
    /// `federation.hello` line right after connecting, before any request.
    Tcp {
        addr: SocketAddr,
        token: Option<String>,
    },
    /// A federation peer reached over key-based SSH (`herdr api-bridge`).
    Ssh(SshTarget),
}

impl ConnectionTarget {
    /// Local socket path for the socket-backed targets. Only meaningful for
    /// `LocalSession`/`SocketPath`; TCP and SSH targets have no socket path and
    /// return an empty path (they never reach the local-connect path).
    fn socket_path(&self) -> PathBuf {
        match self {
            Self::LocalSession(None) => crate::api::socket_path(),
            Self::LocalSession(Some(name)) => crate::session::api_socket_path_for(Some(name)),
            Self::SocketPath(path) => path.clone(),
            Self::Tcp { .. } | Self::Ssh(_) => PathBuf::new(),
        }
    }
}

/// Reusable client for Herdr's newline-delimited JSON API.
#[derive(Debug, Clone)]
pub struct ApiClient {
    target: ConnectionTarget,
}

impl ApiClient {
    pub fn local() -> Self {
        Self::for_target(ConnectionTarget::LocalSession(None))
    }

    pub fn for_target(target: ConnectionTarget) -> Self {
        Self { target }
    }

    pub fn socket_path(&self) -> PathBuf {
        self.target.socket_path()
    }

    pub fn request(&self, request: Request) -> Result<SuccessResponse, ApiClientError> {
        let value = self.request_value(&request)?;
        parse_response_value(value)
    }

    pub fn request_value(&self, request: &Request) -> Result<serde_json::Value, ApiClientError> {
        // request_value is "the first line of request_stream": one request in,
        // the first NDJSON reply out.
        let mut lines = self.request_stream(request)?;
        match lines.next() {
            Some(Ok(value)) => Ok(value),
            Some(Err(err)) => Err(ApiClientError::Io(err)),
            None => Err(ApiClientError::EmptyResponse),
        }
    }

    /// Send `request` and yield every NDJSON reply line until the peer closes
    /// the connection. A round-trip request yields exactly one line; a streaming
    /// request (`events.subscribe`, `pane.stream`, …) yields many and terminates
    /// when the stream closes.
    ///
    /// Works over every transport: Local/TCP connect then write the request and
    /// read replies off the stream; SSH spawns a per-request `api-bridge` child
    /// with the request embedded and reads replies off its stdout.
    pub fn request_stream(&self, request: &Request) -> io::Result<ResponseLines> {
        match &self.target {
            ConnectionTarget::Ssh(target) => {
                let json = serde_json::to_string(request)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                let stream = ssh_transport::spawn_request(target, &json)?;
                Ok(ResponseLines::over(stream))
            }
            _ => {
                let mut stream = self.connect()?;
                write_request_line(&mut stream, request)?;
                Ok(ResponseLines::over(stream))
            }
        }
    }

    pub fn request_value_with_timeout(
        &self,
        request: &Request,
        timeout: Duration,
    ) -> Result<serde_json::Value, ApiClientError> {
        if let ConnectionTarget::Ssh(target) = &self.target {
            // The per-request SSH child has no socket-level timeout knob; the
            // ssh client's own ConnectTimeout/ServerAlive settings govern.
            let json = serde_json::to_string(request)?;
            let stream = ssh_transport::spawn_request(target, &json)?;
            let mut lines = ResponseLines::over(stream);
            return match lines.next() {
                Some(Ok(value)) => Ok(value),
                Some(Err(err)) => Err(ApiClientError::Io(err)),
                None => Err(ApiClientError::EmptyResponse),
            };
        }

        let mut stream = self.connect()?;
        set_timeout_best_effort(&mut stream, TimeoutKind::Send, timeout)?;
        set_timeout_best_effort(&mut stream, TimeoutKind::Recv, timeout)?;
        write_request_line(&mut stream, request)?;

        let mut reader = BufReader::new(stream);
        read_json_line(&mut reader)
    }

    pub fn status(&self) -> Result<crate::api::RuntimeStatus, ApiClientError> {
        let response = self.request(Request {
            id: "api-client:status".into(),
            method: Method::Ping(PingParams::default()),
        })?;
        match response.result {
            ResponseResult::Pong {
                version,
                protocol,
                capabilities,
            } => Ok(crate::api::RuntimeStatus {
                version: Some(version),
                protocol: Some(protocol),
                capabilities,
            }),
            result => Err(ApiClientError::UnexpectedResult(format!("{result:?}"))),
        }
    }

    /// Connect for the socket-backed and TCP transports (never SSH, which is
    /// per-request). For TCP with a token, the `federation.hello` line is written
    /// before this returns, so the caller may write the request immediately.
    fn connect(&self) -> io::Result<ApiStream> {
        match &self.target {
            ConnectionTarget::LocalSession(_) | ConnectionTarget::SocketPath(_) => Ok(
                ApiStream::Local(crate::ipc::connect_local_stream(&self.socket_path())?),
            ),
            ConnectionTarget::Tcp { addr, token } => {
                let mut stream = ApiStream::Tcp(TcpStream::connect(addr)?);
                if let Some(token) = token {
                    write_federation_hello(&mut stream, token)?;
                }
                Ok(stream)
            }
            ConnectionTarget::Ssh(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ssh federation targets connect per-request; use request_value or request_stream",
            )),
        }
    }
}

/// Iterator over the NDJSON reply lines of a request. Owns the underlying
/// transport (including any SSH child process), so dropping it tears the
/// connection down.
pub struct ResponseLines {
    reader: BufReader<ApiStream>,
}

impl ResponseLines {
    fn over(stream: ApiStream) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }
}

impl Iterator for ResponseLines {
    type Item = io::Result<serde_json::Value>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    return Some(
                        serde_json::from_str(trimmed)
                            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
                    );
                }
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

enum TimeoutKind {
    Send,
    Recv,
}

fn set_timeout_best_effort(
    stream: &mut ApiStream,
    kind: TimeoutKind,
    timeout: Duration,
) -> io::Result<()> {
    let result = match kind {
        TimeoutKind::Send => stream.set_send_timeout(Some(timeout)),
        TimeoutKind::Recv => stream.set_recv_timeout(Some(timeout)),
    };
    match result {
        Ok(()) => Ok(()),
        // Named-pipe / some transports report timeouts as unsupported; the
        // request still proceeds without an enforced deadline.
        Err(err) if err.kind() == io::ErrorKind::Unsupported => Ok(()),
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
pub enum ApiClientError {
    Io(io::Error),
    Json(serde_json::Error),
    ErrorResponse(ErrorResponse),
    EmptyResponse,
    UnexpectedResult(String),
}

impl fmt::Display for ApiClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::ErrorResponse(response) => write!(f, "{}", response.error.message),
            Self::EmptyResponse => write!(f, "empty api response"),
            Self::UnexpectedResult(result) => write!(f, "unexpected api result: {result}"),
        }
    }
}

impl std::error::Error for ApiClientError {}

impl From<io::Error> for ApiClientError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for ApiClientError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

fn write_request_line(stream: &mut ApiStream, request: &Request) -> io::Result<()> {
    let encoded = serde_json::to_string(request)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    stream.write_all(encoded.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// Write the versioned `federation.hello` line. Must match the exact shape the
/// listener expects — both sides share [`crate::api::federation::FederationHello`].
///
/// `FederationHello::new` stamps the current `FEDERATION_PROTOCOL_VERSION` and an
/// empty `machine_id`: no persisted machine id exists yet (a later workstream),
/// and `machine_id` is informational in this version — the token is the
/// authenticator — so an empty placeholder is sent for now.
fn write_federation_hello(stream: &mut ApiStream, token: &str) -> io::Result<()> {
    let line = crate::api::federation::FederationHello::new(token)
        .to_line()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn read_json_line<T, R>(reader: &mut R) -> Result<T, ApiClientError>
where
    T: DeserializeOwned,
    R: BufRead,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line)?;
    if read == 0 || line.trim().is_empty() {
        return Err(ApiClientError::EmptyResponse);
    }
    serde_json::from_str(&line).map_err(ApiClientError::Json)
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum WireResponse {
    Success(Box<SuccessResponse>),
    Error(ErrorResponse),
}

pub(crate) fn parse_response_value(
    value: serde_json::Value,
) -> Result<SuccessResponse, ApiClientError> {
    match serde_json::from_value(value)? {
        WireResponse::Success(response) => Ok(*response),
        WireResponse::Error(response) => Err(ApiClientError::ErrorResponse(response)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_session_target_resolves_named_session_socket() {
        let client = ApiClient::for_target(ConnectionTarget::LocalSession(Some("work".into())));
        assert!(client.socket_path().ends_with("sessions/work/herdr.sock"));
    }

    #[test]
    fn socket_path_target_uses_explicit_path() {
        let path = PathBuf::from("/tmp/herdr-test.sock");
        let client = ApiClient::for_target(ConnectionTarget::SocketPath(path.clone()));
        assert_eq!(client.socket_path(), path);
    }

    #[test]
    fn tcp_and_ssh_targets_have_no_socket_path() {
        let tcp = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: "127.0.0.1:9000".parse().unwrap(),
            token: Some("t".into()),
        });
        assert_eq!(tcp.socket_path(), PathBuf::new());

        let ssh = ApiClient::for_target(ConnectionTarget::Ssh(SshTarget {
            host: "example".into(),
            user: None,
            credential: SshCredential::Key,
        }));
        assert_eq!(ssh.socket_path(), PathBuf::new());
    }
}
