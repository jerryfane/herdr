//! Explicit, machine-scoped Gram reverse gateway over a saved SSH connection.
//!
//! The coordinator never forwards its unrestricted API socket. A private socket
//! accepts only the five Gram relay operations below, stamps the saved peer's
//! verified routing alias, and is reverse-forwarded to that peer by SSH. A local
//! process on either trusted machine can impersonate a pane of that machine;
//! this is not a per-process security boundary.

use interprocess::local_socket::{
    traits::{Listener, Stream},
    ListenerNonblockingMode,
};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::api::client::{ApiClient, ConnectionTarget};
use crate::api::federation_manager::PeerRoute;
use crate::api::schema::{GramRelayCall, GramRelayParams, Method, Request};
use crate::api::ApiRequestSender;

const MAX_LINE: usize = 1_100_000; // one 512-KiB chunk encoded as JSON/base64
const RESPONSE_LIMIT: usize = 2_000_000;

/// Operator consent: comma-separated peer routing aliases, set on the
/// coordinator daemon *before* starting it. A saved profile alone never grants
/// Gram access. Changing this requires restarting the daemon.
pub(crate) fn allowed_alias(alias: &str) -> bool {
    std::env::var("HERDR_GRAM_RELAY_PEERS")
        .ok()
        .is_some_and(|list| {
            list.split(',')
                .any(|name| !name.is_empty() && name.trim() == alias)
        })
}

/// Stable remote socket name. The remote daemon must opt in with this path in
/// HERDR_GRAM_REVERSE_SOCKET; SSH creates it with an owner-only bind mask.
pub(crate) fn reverse_socket_path(coordinator_id: &str, remote_id: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("herdr-gram:{coordinator_id}:{remote_id}"));
    let suffix: String = digest[..12].iter().map(|b| format!("{b:02x}")).collect();
    PathBuf::from("/tmp").join(format!("herdr-gram-{suffix}.sock"))
}

pub(crate) fn forward_local(request: &Request) -> Option<String> {
    let path = std::env::var_os("HERDR_GRAM_REVERSE_SOCKET")?;
    let method = &request.method;
    if !matches!(
        method,
        Method::GramSend(_)
            | Method::GramList(_)
            | Method::GramUploadChunk(_)
            | Method::GramGetFileChunk(_)
            | Method::GramDelete(_)
    ) {
        let name = crate::api::server::api_method_name(method);
        return name.starts_with("gram.").then(|| {
            serde_json::json!({"id":request.id,"error":{
                "code":"gram_relay_unsupported",
                "message":format!("{name} is unavailable through the restricted Gram relay; use the coordinator")
            }})
            .to_string()
        });
    }
    let client = ApiClient::for_target(ConnectionTarget::SocketPath(path.into()));
    let reply =
        client.request_value_bounded(request, RESPONSE_LIMIT, Duration::from_secs(30), None);
    Some(match reply {
        Ok(value) => value.to_string(),
        Err(error) => serde_json::json!({"id":request.id,"error":{
            "code":"gram_relay_unavailable", "message":format!("Gram relay unavailable: {error}")
        }})
        .to_string(),
    })
}

/// The transport is authenticated by the saved SSH host key and profile. Only
/// one alias is bound to each private gateway listener; request-supplied aliases
/// are never read. There is no TCP listener and no raw gram.* policy exception.
fn serve_one(
    mut conn: crate::ipc::LocalStream,
    alias: &str,
    tx: &ApiRequestSender,
    route: &PeerRoute,
) -> io::Result<()> {
    conn.set_recv_timeout(Some(Duration::from_secs(30)))?;
    conn.set_send_timeout(Some(Duration::from_secs(30)))?;
    let mut line = Vec::new();
    let mut reader = BufReader::new(&mut conn);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete Gram relay request",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if line.len() + consumed > MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Gram relay request exceeds bound",
            ));
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    drop(reader);
    let request: Request = serde_json::from_slice(&line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let id = request.id.clone();
    let result = if !route.identity_validated() {
        serde_json::json!({"id":id,"error":{"code":"federation_identity_unverified","message":"saved peer identity not pinned"}}).to_string()
    } else {
        let call = match request.method {
            Method::GramSend(params) => Some(GramRelayCall::Send(params)),
            Method::GramList(params) => Some(GramRelayCall::List(params)),
            Method::GramUploadChunk(params) => Some(GramRelayCall::UploadChunk(params)),
            Method::GramGetFileChunk(params) => Some(GramRelayCall::GetFileChunk(params)),
            Method::GramDelete(params) => Some(GramRelayCall::Delete(params)),
            _ => None,
        };
        match call {
            Some(call) => crate::api::server::handle_reverse_gram(
                Request { id: id.clone(), method: Method::GramRelay(GramRelayParams { peer_alias: alias.to_owned(), call }) }, tx),
            None => serde_json::json!({"id":id,"error":{"code":"forbidden","message":"method unavailable on Gram relay"}}).to_string(),
        }
    };
    if result.len() > RESPONSE_LIMIT {
        let too_large = serde_json::json!({"id":id,"error":{
            "code":"gram_relay_response_too_large",
            "message":"Gram relay response exceeds bound; request a smaller list page"
        }})
        .to_string();
        conn.write_all(too_large.as_bytes())?;
        return conn.write_all(b"\n");
    }
    conn.write_all(result.as_bytes())?;
    conn.write_all(b"\n")
}

pub(crate) struct ReverseGateway {
    stop: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    ssh: Option<JoinHandle<()>>,
    socket: PathBuf,
    socket_identity: crate::ipc::SocketFileIdentity,
}

impl ReverseGateway {
    pub(crate) fn start(
        profile_id: &str,
        ssh_target: &str,
        session: &str,
        alias: String,
        remote_machine_id: &str,
        route: PeerRoute,
        tx: ApiRequestSender,
        running: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let coordinator_id = crate::persist::machine::get_or_create();
        let remote = reverse_socket_path(&coordinator_id, remote_machine_id);
        let socket = crate::platform::remote_bridge_endpoint_path(
            &format!(
                "herdr-gram-gateway-{}-{}.sock",
                std::process::id(),
                profile_id
            ),
            &format!("hg-{}-{}.sock", std::process::id(), &profile_id[..16]),
        );
        let listener = crate::ipc::bind_private_local_listener(&socket)?;
        let socket_identity = crate::ipc::socket_file_identity(&socket)?;
        crate::ipc::restrict_socket_permissions(&socket, 0o600)?;
        listener.set_nonblocking(ListenerNonblockingMode::Accept)?;
        // ExitOnForwardFailure makes a failed remote bind terminate SSH. Do not
        // advertise a ready gateway until the initial forwarding attempt has
        // survived its setup interval. The request path still fails closed until
        // the route's pinned machine identity is validated by federation polling.
        let first_child = (|| -> io::Result<std::process::Child> {
            let mut command = crate::remote::reverse_forward_command(
                profile_id, ssh_target, session, &remote, &socket,
            )?;
            let mut child = command.spawn()?;
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(100));
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "Gram relay SSH reverse bind failed: {status}"
                    )));
                }
            }
            Ok(child)
        })();
        let first_child = match first_child {
            Ok(child) => child,
            Err(error) => {
                let _ = crate::ipc::remove_socket_file_if_owned(&socket, &socket_identity);
                return Err(error);
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let listener_stop = Arc::clone(&stop);
        let listener_running = Arc::clone(&running);
        let active = Arc::new(AtomicUsize::new(0));
        let mut last_sweep = std::time::Instant::now() - Duration::from_secs(60 * 60);
        let listener_thread = std::thread::spawn(move || {
            while !listener_stop.load(Ordering::Relaxed) && listener_running.load(Ordering::Relaxed)
            {
                if last_sweep.elapsed() >= Duration::from_secs(60 * 60) {
                    crate::persist::gram_files::sweep_stale_uploads();
                    last_sweep = std::time::Instant::now();
                }
                match listener.accept() {
                    Ok(conn) => {
                        if active.fetch_add(1, Ordering::AcqRel) >= 8 {
                            active.fetch_sub(1, Ordering::AcqRel);
                            continue;
                        }
                        let active = Arc::clone(&active);
                        let alias = alias.clone();
                        let tx = tx.clone();
                        let route = route.clone();
                        std::thread::spawn(move || {
                            let _ = serve_one(conn, &alias, &tx, &route);
                            active.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25))
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Gram relay gateway listener failed");
                        break;
                    }
                }
            }
        });
        let profile_id = profile_id.to_owned();
        let ssh_target = ssh_target.to_owned();
        let session = session.to_owned();
        let ssh_socket = socket.clone();
        let ssh_stop = Arc::clone(&stop);
        let mut first_child = Some(first_child);
        let ssh_thread = std::thread::spawn(move || {
            while !ssh_stop.load(Ordering::Relaxed) && running.load(Ordering::Relaxed) {
                let child = match first_child.take() {
                    Some(child) => Ok(child),
                    None => crate::remote::reverse_forward_command(
                        &profile_id,
                        &ssh_target,
                        &session,
                        &remote,
                        &ssh_socket,
                    )
                    .and_then(|mut command| command.spawn()),
                };
                match child {
                    Ok(mut child) => {
                        while !ssh_stop.load(Ordering::Relaxed) && running.load(Ordering::Relaxed) {
                            match child.try_wait() {
                                Ok(Some(status)) => {
                                    tracing::warn!(%status, "Gram relay SSH forward exited");
                                    break;
                                }
                                Ok(None) => std::thread::sleep(Duration::from_millis(250)),
                                Err(error) => {
                                    tracing::warn!(%error, "Gram relay SSH forward failed");
                                    break;
                                }
                            }
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    Err(error) => tracing::warn!(%error, "Gram relay SSH forward could not start"),
                }
                if !ssh_stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        });
        Ok(Self {
            stop,
            listener: Some(listener_thread),
            ssh: Some(ssh_thread),
            socket,
            socket_identity,
        })
    }
}

impl Drop for ReverseGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(ssh) = self.ssh.take() {
            let _ = ssh.join();
        }
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        let _ = crate::ipc::remove_socket_file_if_owned(&self.socket, &self.socket_identity);
    }
}
