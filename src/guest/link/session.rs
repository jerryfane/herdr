//! Guest sessions: one per relay OPEN. A session thread runs the Noise
//! responder and admission, then pumps decrypted guest bytes into the API
//! stream while a second thread encrypts the API's output back out. An
//! account-bound session also ends at its statement deadline unless the guest
//! sends a newer statement in-band (`account.refresh`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::debug;

use super::frame;
use super::host::{AccountSession, Admission, GuestHost};
use super::noise::{Responder, ResponderKeys, Transport, MAX_MESSAGE, MAX_PLAINTEXT};
use super::Waker;

/// Largest in-band `account.refresh` message; statements are about 430 bytes.
const MAX_REFRESH: usize = 8 * 1024;

/// `{"t":"account.refresh","account":"<jws>"}`: one whole transport message
/// of an account-bound session, never forwarded to the API.
#[derive(serde::Deserialize)]
struct Refresh {
    t: String,
    account: String,
}

/// The statement in an in-band refresh message, or `None` for API bytes.
fn refresh_statement(plaintext: &[u8]) -> Option<String> {
    if plaintext.len() > MAX_REFRESH || plaintext.first() != Some(&b'{') {
        return None;
    }
    let refresh: Refresh = serde_json::from_slice(plaintext).ok()?;
    (refresh.t == "account.refresh").then_some(refresh.account)
}

/// Live sessions per host socket; the relay enforces the same cap.
pub(super) const MAX_SESSIONS: usize = 32;
/// Guest messages buffered per session before it is closed as overloaded. A
/// guest has one request in flight at a time, so this only trips on abuse.
const INBOUND_QUEUE: usize = 32;

/// Session output for the connection thread to put on the socket. Each
/// carries the generation of the session that produced it, because the relay
/// may reuse an id: output of a replaced session must never reach its successor.
pub(super) enum Outbound {
    Data {
        session: u32,
        generation: u64,
        frame: Vec<u8>,
    },
    Close {
        session: u32,
        generation: u64,
        reason: String,
    },
    /// A CLOSE for a session the host refused or dropped itself.
    Refused {
        session: u32,
        generation: u64,
        frame: Vec<u8>,
    },
}

/// The session's end of its API stream, once admitted.
enum Stream {
    Pending,
    Live(UnixStream),
    Closed,
}

/// Shared between the connection thread and the session's threads, so either
/// side can end the session.
struct Shared {
    stream: Mutex<Stream>,
}

impl Shared {
    /// Registers the admitted stream, or refuses when the session already ended.
    fn attach(&self, stream: &UnixStream) -> bool {
        let mut slot = self.stream.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*slot, Stream::Closed) {
            return false;
        }
        match stream.try_clone() {
            Ok(clone) => {
                *slot = Stream::Live(clone);
                true
            }
            Err(_) => false,
        }
    }

    /// Ends the API stream: `serve` and both pumps see EOF.
    fn shut(&self) {
        let mut slot = self.stream.lock().unwrap_or_else(PoisonError::into_inner);
        if let Stream::Live(stream) = std::mem::replace(&mut *slot, Stream::Closed) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

struct Handle {
    generation: u64,
    inbound: SyncSender<Bytes>,
    shared: Arc<Shared>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shared.shut();
    }
}

/// The sessions of one host socket. Dropping it ends them all.
pub(super) struct Sessions<H: GuestHost> {
    host: Arc<H>,
    keys: Arc<ResponderKeys>,
    live: HashMap<u32, Handle>,
    /// Stamped on each OPEN, so a reused id is a different session.
    next_generation: u64,
    outbound: SyncSender<Outbound>,
    waker: Waker,
    handshake_timeout: Duration,
}

impl<H: GuestHost> Sessions<H> {
    pub(super) fn new(
        host: Arc<H>,
        keys: Arc<ResponderKeys>,
        outbound: SyncSender<Outbound>,
        waker: Waker,
        handshake_timeout: Duration,
    ) -> Self {
        Self {
            host,
            keys,
            live: HashMap::new(),
            next_generation: 0,
            outbound,
            waker,
            handshake_timeout,
        }
    }

    /// Starts a session for a relay OPEN, or refuses it with a CLOSE.
    pub(super) fn open(&mut self, id: u32) {
        // A reused id replaces the stale session, whose output then drops.
        self.live.remove(&id);
        let generation = self.next_generation;
        self.next_generation += 1;
        if self.live.len() >= MAX_SESSIONS {
            return self.refuse(id, generation, "host_busy");
        }
        let (inbound, receiver) = mpsc::sync_channel(INBOUND_QUEUE);
        let shared = Arc::new(Shared {
            stream: Mutex::new(Stream::Pending),
        });
        let session = Session {
            id,
            generation,
            host: Arc::clone(&self.host),
            keys: Arc::clone(&self.keys),
            inbound: receiver,
            outbound: self.outbound.clone(),
            waker: self.waker.clone(),
            shared: Arc::clone(&shared),
            handshake_timeout: self.handshake_timeout,
        };
        let spawned = thread::Builder::new()
            .name(format!("herdr-guest-session-{id}"))
            .spawn(move || session.run());
        if spawned.is_err() {
            return self.refuse(id, generation, "internal");
        }
        self.live.insert(
            id,
            Handle {
                generation,
                inbound,
                shared,
            },
        );
    }

    /// Hands a guest message to its session, closing a session that is not
    /// keeping up; messages for unknown sessions drop.
    pub(super) fn data(&mut self, id: u32, payload: Bytes) {
        let Some(handle) = self.live.get(&id) else {
            return;
        };
        if let Err(TrySendError::Full(_)) = handle.inbound.try_send(payload) {
            let generation = handle.generation;
            self.live.remove(&id);
            self.refuse(id, generation, "overloaded");
        }
    }

    /// Queues a CLOSE for a session the host will not serve. A relay that
    /// floods OPENs faster than the socket drains loses these CLOSEs rather
    /// than growing memory; the relay closes such guests on its own timeouts.
    fn refuse(&self, id: u32, generation: u64, reason: &str) {
        match self.outbound.try_send(Outbound::Refused {
            session: id,
            generation,
            frame: frame::close(id, reason),
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => debug!("guest session {id}: queue full, CLOSE dropped"),
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// The relay closed a session.
    pub(super) fn close(&mut self, id: u32) {
        self.live.remove(&id);
    }

    /// Turns session output into a frame, dropping output of ended or
    /// replaced sessions.
    pub(super) fn outbound(&mut self, message: Outbound) -> Option<Vec<u8>> {
        let current = |live: &HashMap<u32, Handle>, session, generation| {
            live.get(&session)
                .is_some_and(|handle| handle.generation == generation)
        };
        match message {
            Outbound::Data {
                session,
                generation,
                frame,
            } => current(&self.live, session, generation).then_some(frame),
            Outbound::Close {
                session,
                generation,
                reason,
            } => current(&self.live, session, generation).then(|| {
                self.live.remove(&session);
                frame::close(session, &reason)
            }),
            // A refused session was never live, or was removed when refused,
            // so any live handle under its id is a later session.
            Outbound::Refused {
                session,
                generation,
                frame,
            } => self
                .live
                .get(&session)
                .is_none_or(|handle| handle.generation == generation)
                .then_some(frame),
        }
    }
}

struct Session<H: GuestHost> {
    id: u32,
    generation: u64,
    host: Arc<H>,
    keys: Arc<ResponderKeys>,
    inbound: Receiver<Bytes>,
    outbound: SyncSender<Outbound>,
    waker: Waker,
    shared: Arc<Shared>,
    handshake_timeout: Duration,
}

impl<H: GuestHost> Session<H> {
    fn run(self) {
        let admitted = match self.handshake() {
            Ok(admitted) => admitted,
            Err(reason) => {
                debug!(
                    "guest session {}: closed during handshake: {reason}",
                    self.id
                );
                self.close(reason);
                return;
            }
        };
        let (transport, principal, account) = admitted;
        if let Err(reason) = self.serve(Arc::new(transport), principal, account) {
            // Close before ending the stream, so the reason wins over the
            // pump's plain close on EOF.
            self.close(reason);
            self.shared.shut();
        }
    }

    /// Reads message 1, asks the host, and answers with message 2.
    fn handshake(&self) -> Result<(Transport, H::Principal, Option<AccountSession>), &'static str> {
        let message = match self.inbound.recv_timeout(self.handshake_timeout) {
            Ok(message) => message,
            Err(RecvTimeoutError::Timeout) => return Err("handshake_timeout"),
            Err(RecvTimeoutError::Disconnected) => return Err("closed"),
        };
        let mut responder = Responder::new(&self.keys).map_err(|_| "internal")?;
        let hello = responder.read_hello(&message).map_err(|error| {
            debug!("guest session {}: {error}", self.id);
            error.close_reason()
        })?;
        match self.host.admit(hello.device_pub, &hello.payload) {
            Admission::Admitted {
                principal,
                reply,
                account,
            } => {
                let (message, transport) = responder
                    .reply(&reply)
                    .map_err(|error| error.close_reason())?;
                self.send_data(frame::data(self.id, &message))?;
                Ok((transport, principal, account))
            }
            Admission::Refused(code) => {
                let reply = serde_json::json!({ "ok": false, "error": code });
                let (message, _) = responder
                    .reply(&reply)
                    .map_err(|error| error.close_reason())?;
                self.send_data(frame::data(self.id, &message))?;
                Err(code)
            }
        }
    }

    /// Runs the guest's API connection until either side ends it. The
    /// connection starts with the guest's first request bytes, so the API's
    /// request timeout covers the request, not the round trip before it.
    fn serve(
        &self,
        transport: Arc<Transport>,
        principal: H::Principal,
        mut account: Option<AccountSession>,
    ) -> Result<(), &'static str> {
        let mut plaintext = vec![0; MAX_MESSAGE];
        let len = loop {
            let Some(message) = self.receive(Some(self.handshake_timeout), account.as_ref())?
            else {
                return Err("closed");
            };
            let len = self.decrypt(&transport, &message, &mut plaintext)?;
            if !self.refreshed(&mut account, &plaintext[..len])? {
                break len;
            }
        };

        let (mut ours, theirs) = UnixStream::pair().map_err(|_| "internal")?;
        if !self.shared.attach(&ours) {
            return Err("closed");
        }
        let reader = ours.try_clone().map_err(|_| "internal")?;

        let host = Arc::clone(&self.host);
        thread::Builder::new()
            .name(format!("herdr-guest-serve-{}", self.id))
            .spawn(move || host.serve(principal, theirs))
            .map_err(|_| "internal")?;

        let pump = Pump {
            id: self.id,
            generation: self.generation,
            outbound: self.outbound.clone(),
            waker: self.waker.clone(),
        };
        let encrypt = Arc::clone(&transport);
        let spawned = thread::Builder::new()
            .name(format!("herdr-guest-pump-{}", self.id))
            .spawn(move || pump.run(reader, &encrypt));
        if spawned.is_err() {
            return Err("internal");
        }

        if ours.write_all(&plaintext[..len]).is_err() {
            // The API side ended; the pump reports it.
            return Ok(());
        }
        self.forward(&transport, ours, plaintext, account)
    }

    /// Decrypts guest messages into the API stream until either side ends,
    /// or an account-bound session reaches its statement deadline.
    fn forward(
        &self,
        transport: &Transport,
        mut ours: UnixStream,
        mut plaintext: Vec<u8>,
        mut account: Option<AccountSession>,
    ) -> Result<(), &'static str> {
        while let Some(message) = self.receive(None, account.as_ref())? {
            let len = self.decrypt(transport, &message, &mut plaintext)?;
            if self.refreshed(&mut account, &plaintext[..len])? {
                continue;
            }
            if ours.write_all(&plaintext[..len]).is_err() {
                break;
            }
        }
        Ok(())
    }

    /// The next guest message, waiting at most `wait` (without limit when
    /// `None`) and never past an account-bound session's deadline, which ends
    /// it with `statement_expired`. `None` once the relay side is gone.
    fn receive(
        &self,
        wait: Option<Duration>,
        account: Option<&AccountSession>,
    ) -> Result<Option<Bytes>, &'static str> {
        let now = Instant::now();
        let deadline = account.map(|account| now + account.left());
        let until = match (wait.map(|wait| now + wait), deadline) {
            (Some(wait), Some(deadline)) => Some(wait.min(deadline)),
            (wait, deadline) => wait.or(deadline),
        };
        let received = match until {
            None => self
                .inbound
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
            Some(until) => self
                .inbound
                .recv_timeout(until.saturating_duration_since(Instant::now())),
        };
        let expired = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
        match received {
            Ok(_) | Err(RecvTimeoutError::Timeout) if expired() => {
                Err(crate::guest::account::codes::EXPIRED)
            }
            Ok(message) => Ok(Some(message)),
            Err(RecvTimeoutError::Timeout) => Err("request_timeout"),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    /// Handles `plaintext` when it is an account-bound session's in-band
    /// `{"t":"account.refresh","account":"<jws>"}` message, which never
    /// reaches the API: a valid statement moves the deadline, any other ends
    /// the session with the host's code. `false` for API bytes.
    fn refreshed(
        &self,
        account: &mut Option<AccountSession>,
        plaintext: &[u8],
    ) -> Result<bool, &'static str> {
        let Some(session) = account.as_mut() else {
            return Ok(false);
        };
        let Some(jws) = refresh_statement(plaintext) else {
            return Ok(false);
        };
        let deadline_ms = self.host.refresh_account(session, &jws)?;
        session.deadline_ms = deadline_ms;
        debug!("guest session {}: account statement refreshed", self.id);
        Ok(true)
    }

    /// A message that fails to decrypt (tampered, replayed or reordered) ends
    /// the session.
    fn decrypt(
        &self,
        transport: &Transport,
        message: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, &'static str> {
        transport.decrypt(message, plaintext).map_err(|error| {
            debug!("guest session {}: decrypt failed: {error}", self.id);
            "decrypt_failed"
        })
    }

    fn send_data(&self, frame: Vec<u8>) -> Result<(), &'static str> {
        let sent = self.outbound.send(Outbound::Data {
            session: self.id,
            generation: self.generation,
            frame,
        });
        self.waker.wake();
        sent.map_err(|_| "closed")
    }

    fn close(&self, reason: &str) {
        let _ = self.outbound.send(Outbound::Close {
            session: self.id,
            generation: self.generation,
            reason: reason.to_owned(),
        });
        self.waker.wake();
    }
}

/// Encrypts the API's output into DATA frames, then closes the session.
struct Pump {
    id: u32,
    generation: u64,
    outbound: SyncSender<Outbound>,
    waker: Waker,
}

impl Pump {
    fn run(self, mut reader: UnixStream, transport: &Transport) {
        let mut plaintext = vec![0; MAX_PLAINTEXT];
        let reason = loop {
            let len = match reader.read(&mut plaintext) {
                Ok(0) => break "",
                Ok(len) => len,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break "",
            };
            let Ok(frame) = transport.encrypt_frame(self.id, &plaintext[..len]) else {
                break "internal";
            };
            let sent = self.outbound.send(Outbound::Data {
                session: self.id,
                generation: self.generation,
                frame,
            });
            self.waker.wake();
            if sent.is_err() {
                return;
            }
        };
        let _ = self.outbound.send(Outbound::Close {
            session: self.id,
            generation: self.generation,
            reason: reason.to_owned(),
        });
        self.waker.wake();
    }
}
