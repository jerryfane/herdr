use std::io;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use interprocess::local_socket::traits::{Listener as _, Stream as _};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::ipc::LocalListener;
use crate::server::client_transport::{self, ServerEvent};

/// Accepts pending thin-client connections and starts their handshake readers.
pub(crate) fn accept_pending_client_connections(
    listener: &LocalListener,
    next_client_id: &mut u64,
    should_quit: &Arc<AtomicBool>,
    server_event_tx: &mpsc::Sender<ServerEvent>,
) -> io::Result<()> {
    loop {
        if should_quit.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok(stream) => {
                // The private client socket attaches to any pane and types into it.
                // Fenced panes have it masked; refuse them here too, in case they
                // reach it another way (docs/next/design/pane-fence.md, section 8).
                if crate::fence::api_gate_active()
                    && crate::platform::local_stream_fence_peer(&stream)
                        != crate::platform::FencePeer::Unfenced
                {
                    warn!("refusing client connection from a fenced or unidentified process");
                    continue;
                }
                let client_id = *next_client_id;
                *next_client_id = next_client_id.saturating_add(1);

                if let Err(err) = stream.set_nonblocking(true) {
                    warn!(err = %err, "failed to set client stream nonblocking");
                    continue;
                }

                let should_quit = should_quit.clone();
                let server_event_tx = server_event_tx.clone();
                let spawned = crate::thread_spawn::spawn_named("herdr-client-conn", move || {
                    if let Err(err) = client_transport::handle_client_handshake(
                        stream,
                        client_id,
                        &server_event_tx,
                        &should_quit,
                    ) {
                        debug!(client_id, err = %err, "client handshake failed");
                    }
                });
                if let Err(err) = spawned {
                    warn!(client_id, err = %err, "failed to spawn client connection thread; dropping connection");
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => {
                error!(err = %err, "client listener accept failed");
                break;
            }
        }
    }

    Ok(())
}

/// Drains pending thin-client connections without starting handshakes.
///
/// During live handoff the old server must not let clients sit in the Unix
/// listener backlog waiting for a welcome frame that will never be sent.
pub(crate) fn reject_pending_client_connections(listener: &LocalListener) -> io::Result<()> {
    loop {
        match listener.accept() {
            Ok(_stream) => {}
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => {
                error!(err = %err, "client listener reject failed");
                break;
            }
        }
    }

    Ok(())
}
