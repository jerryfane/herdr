//! Topics (#474): the long-lived worker conversations inside one omp agent.
//!
//! An interactive omp launch with `topics.enabled` serves its topics on a
//! local control socket guarded by a per-launch token. The Herdr integration
//! running inside that omp process hands the endpoint over with
//! `pane.report_agent_control`; Herdr keeps it here, in server memory only,
//! per terminal, for as long as the agent process that offered it runs. It is
//! never persisted, exported in a live handoff, logged, or returned by the
//! API: anything that can reach the socket with the token controls the agent.

pub(crate) mod control;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::api::schema::AgentControlToken;
use crate::terminal::TerminalId;

/// The only control protocol this build speaks.
pub(crate) const CONTROL_PROTOCOL: u32 = 1;

/// Where one agent process serves its topics, and the secret it asks for.
/// `Debug` redacts the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlEndpoint {
    pub(crate) socket_path: PathBuf,
    pub(crate) token: AgentControlToken,
    /// The agent process that must serve the socket.
    pub(crate) pid: u32,
}

/// One registered endpoint, as a request worker takes it off the app thread.
#[derive(Clone)]
pub(crate) struct ControlHandle {
    pub(crate) endpoint: Arc<ControlEndpoint>,
    /// Changes whenever the terminal's endpoint is replaced, so topic updates
    /// read from an older one are dropped.
    pub(crate) generation: u64,
    pub(crate) updates: Arc<UpdatesSlot>,
}

/// The registered endpoints, by terminal.
#[derive(Default)]
pub(crate) struct AgentControls {
    entries: HashMap<TerminalId, Registered>,
    next_generation: u64,
    /// Tests stand in for herdr's foreground probe: `Some(pid)` is what it
    /// identifies as the pane's omp process.
    #[cfg(test)]
    pub(crate) inspected_pid_for_test: Option<Option<u32>>,
}

struct Registered {
    endpoint: Arc<ControlEndpoint>,
    generation: u64,
    updates: Arc<UpdatesSlot>,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.updates.cancel();
    }
}

impl AgentControls {
    /// Register `endpoint` for `terminal_id`, replacing any other. The same
    /// endpoint reported again keeps its generation and its update stream.
    pub(crate) fn register(&mut self, terminal_id: TerminalId, endpoint: ControlEndpoint) {
        if self
            .entries
            .get(&terminal_id)
            .is_some_and(|registered| *registered.endpoint == endpoint)
        {
            return;
        }
        self.next_generation += 1;
        self.entries.insert(
            terminal_id,
            Registered {
                endpoint: Arc::new(endpoint),
                generation: self.next_generation,
                updates: Arc::default(),
            },
        );
    }

    /// Forget the terminal's endpoint and end its update stream.
    pub(crate) fn remove(&mut self, terminal_id: &str) -> bool {
        self.entries.remove(terminal_id).is_some()
    }

    pub(crate) fn handle(&self, terminal_id: &str) -> Option<ControlHandle> {
        self.entries
            .get(terminal_id)
            .map(|registered| ControlHandle {
                endpoint: Arc::clone(&registered.endpoint),
                generation: registered.generation,
                updates: Arc::clone(&registered.updates),
            })
    }

    /// The agent process the terminal's endpoint was offered by.
    pub(crate) fn pid(&self, terminal_id: &str) -> Option<u32> {
        self.entries
            .get(terminal_id)
            .map(|registered| registered.endpoint.pid)
    }

    pub(crate) fn is_current(&self, terminal_id: &str, generation: u64) -> bool {
        self.entries
            .get(terminal_id)
            .is_some_and(|registered| registered.generation == generation)
    }
}

/// The `topic_update` stream of one registered endpoint, opened on the first
/// `agent.topics.*` request and ended when the endpoint is dropped.
#[derive(Default)]
pub(crate) struct UpdatesSlot {
    state: Mutex<UpdatesState>,
}

#[derive(Default)]
struct UpdatesState {
    /// The endpoint was dropped: no stream may start or stay.
    cancelled: bool,
    /// A reader owns the stream (or is opening it).
    running: bool,
    stream: Option<std::os::unix::net::UnixStream>,
}

impl UpdatesSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, UpdatesState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Claim the slot for a new reader; false while one runs or once the
    /// endpoint is gone.
    pub(crate) fn claim(&self) -> bool {
        let mut state = self.lock();
        if state.cancelled || state.running {
            return false;
        }
        state.running = true;
        true
    }

    /// Keep a handle on the reader's stream so dropping the endpoint can end
    /// it; false (and the stream shut) when the endpoint is already gone.
    pub(crate) fn attach(&self, stream: std::os::unix::net::UnixStream) -> bool {
        let mut state = self.lock();
        if state.cancelled {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return false;
        }
        state.stream = Some(stream);
        true
    }

    /// The reader stopped; a later request may open a new stream.
    pub(crate) fn release(&self) {
        let mut state = self.lock();
        state.running = false;
        state.stream = None;
    }

    fn cancel(&self) {
        let mut state = self.lock();
        state.cancelled = true;
        if let Some(stream) = state.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(path: &str, pid: u32) -> ControlEndpoint {
        ControlEndpoint {
            socket_path: PathBuf::from(path),
            token: AgentControlToken::new("t".repeat(32)),
            pid,
        }
    }

    #[test]
    fn re_registering_the_same_endpoint_keeps_its_generation() {
        let mut controls = AgentControls::default();
        let terminal = TerminalId::from_persisted("term_1".into());
        controls.register(terminal.clone(), endpoint("/tmp/a.sock", 7));
        let first = controls.handle("term_1").unwrap().generation;
        controls.register(terminal.clone(), endpoint("/tmp/a.sock", 7));
        assert!(controls.is_current("term_1", first));
        controls.register(terminal, endpoint("/tmp/b.sock", 7));
        assert!(!controls.is_current("term_1", first));
        assert!(controls.remove("term_1"));
        assert_eq!(controls.pid("term_1"), None);
    }

    #[test]
    fn dropping_an_endpoint_ends_its_update_stream() {
        let mut controls = AgentControls::default();
        controls.register(
            TerminalId::from_persisted("term_1".into()),
            endpoint("/tmp/a.sock", 7),
        );
        let updates = controls.handle("term_1").unwrap().updates;
        assert!(updates.claim());
        assert!(!updates.claim(), "one reader at a time");
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(updates.attach(ours));
        controls.remove("term_1");
        let mut byte = [0u8; 1];
        // The reader's end was shut down, so its peer reads end-of-stream.
        assert_eq!(std::io::Read::read(&mut &theirs, &mut byte).unwrap(), 0);
        assert!(!updates.claim(), "a dropped endpoint never streams again");
    }
}
