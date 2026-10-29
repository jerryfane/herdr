//! Guest access relay link: the host side of the HerdrUp guest relay.
//!
//! Networking exception: Herdr otherwise keeps TLS and internet traffic out of
//! process (`src/update.rs` and push delivery shell out to curl). Guest
//! access needs a long-lived, bidirectional socket that curl cannot provide, so
//! this module, and only this module, links tungstenite, rustls, webpki-roots
//! and ring. It dials a single configured relay URL (`[guest] relay_url`, https
//! only), and only while at least one guest or open invite exists. The relay
//! never sees plaintext: every guest session is end-to-end encrypted with
//! Noise IK against the node key, and admission happens inside the handshake.
//!
//! One socket carries every session as `OPEN`/`DATA`/`CLOSE` frames
//! ([`frame`]). Each session runs a Noise responder ([`noise`]); an admitted
//! guest is served over a `UnixStream::pair()` by [`GuestHost::serve`].

mod frame;
pub(crate) mod host;
mod noise;
mod relay;
mod session;
#[cfg(test)]
pub(crate) mod tests;

use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use self::host::{DaemonGuestHost, GuestHost, LinkState};

/// Link timings; tests shorten them.
#[derive(Clone, Copy)]
struct Timing {
    ping_interval: Duration,
    /// The socket is dropped and redialled when no pong arrives for this long.
    pong_timeout: Duration,
    backoff_base: Duration,
    backoff_cap: Duration,
    /// Budget for dialling and upgrading the host socket, and for a guest's
    /// first handshake message.
    handshake_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(25),
            pong_timeout: Duration::from_secs(60),
            backoff_base: Duration::from_secs(2),
            backoff_cap: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(20),
        }
    }
}

/// Re-check `link_wanted` this often while idle, besides change notifications.
const IDLE_RECHECK: Duration = Duration::from_secs(60);

/// Reconnect delays: doubling from the base to the cap, each shortened by up
/// to a quarter so hosts that dropped together do not redial in lockstep.
struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Backoff {
    fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
        }
    }

    fn reset(&mut self) {
        self.attempt = 0;
    }

    fn next(&mut self, entropy: u64) -> Duration {
        let full = self
            .base
            .saturating_mul(1 << self.attempt.min(16))
            .min(self.cap);
        self.attempt = self.attempt.saturating_add(1);
        let spread = u64::try_from((full / 4).as_micros()).unwrap_or(u64::MAX);
        full - Duration::from_micros(entropy % spread.saturating_add(1))
    }
}

/// Per-process random bits for jitter, without an RNG dependency.
fn entropy() -> u64 {
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// Wakes the link thread out of `poll`: the write half of a nonblocking
/// socket pair whose read half the link thread polls.
#[derive(Clone)]
struct Waker(Arc<UnixStream>);

impl Waker {
    fn wake(&self) {
        // A full buffer means a wake-up is already pending.
        let _ = (&*self.0).write(&[1]);
    }
}

struct WakeReceiver(UnixStream);

impl WakeReceiver {
    fn drain(&self) {
        let mut sink = [0; 64];
        while matches!((&self.0).read(&mut sink), Ok(n) if n > 0) {}
    }

    fn fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

fn wake_pair() -> io::Result<(Waker, WakeReceiver)> {
    let (receiver, sender) = UnixStream::pair()?;
    receiver.set_nonblocking(true)?;
    sender.set_nonblocking(true)?;
    Ok((Waker(Arc::new(sender)), WakeReceiver(receiver)))
}

/// Waits until one of `fds` is ready or `timeout` passes, ignoring EINTR.
fn poll(fds: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    // Round up so a sub-millisecond remainder does not spin.
    let millis = timeout.as_micros().div_ceil(1000);
    let millis = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
    let count = libc::nfds_t::try_from(fds.len()).unwrap_or(libc::nfds_t::MAX);
    // SAFETY: `fds` is a valid, exclusively borrowed slice of `count` pollfds.
    if unsafe { libc::poll(fds.as_mut_ptr(), count, millis) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

/// Flags shared by the link thread, its change listener and the handle.
struct Signals {
    stop: AtomicBool,
    changed: AtomicBool,
    waker: Waker,
}

impl Signals {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn take_changed(&self) -> bool {
        self.changed.swap(false, Ordering::Relaxed)
    }
}

/// How often the change listener re-checks for a stopped link.
const LISTENER_TICK: Duration = Duration::from_millis(100);

/// The running relay link. Dropping it stops the link and returns once the
/// relay socket is closed: live guest sessions end and the status turns `off`.
pub(crate) struct GuestLink {
    signals: Arc<Signals>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl GuestLink {
    /// Starts the daemon's link over the guest store, in the default session
    /// only ([`crate::guest::session_serves_guests`]). Guest access is
    /// optional: a failure is logged and the daemon carries on without it.
    pub(crate) fn start_for_daemon() -> Option<Self> {
        Self::start_in_session(
            crate::session::active_name().as_deref(),
            Arc::new(DaemonGuestHost),
            Timing::default(),
        )
    }

    #[cfg(test)]
    pub(crate) fn start<H: GuestHost>(host: Arc<H>) -> io::Result<Self> {
        Self::start_with(host, Timing::default())
    }

    /// `None` for a named session (`session` is `None` for the default one):
    /// it shares the default session's guest store and relay identity, so its
    /// socket would replace the default session's at the relay.
    fn start_in_session<H: GuestHost>(
        session: Option<&str>,
        host: Arc<H>,
        timing: Timing,
    ) -> Option<Self> {
        if !crate::guest::session_serves_guests(session) {
            info!(
                session = session.unwrap_or_default(),
                "guest link is off in this named session; the default session serves guests"
            );
            return None;
        }
        Self::start_with(host, timing)
            .inspect_err(|err| warn!(err = %err, "guest link failed to start"))
            .ok()
    }

    fn start_with<H: GuestHost>(host: Arc<H>, timing: Timing) -> io::Result<Self> {
        let (waker, wake) = wake_pair()?;
        let signals = Arc::new(Signals {
            stop: AtomicBool::new(false),
            changed: AtomicBool::new(false),
            waker,
        });

        // Dropping `link` on a failed spawn stops and joins what did start.
        let mut link = Self {
            signals,
            threads: Vec::with_capacity(2),
        };

        let changes = host.subscribe_changes();
        let listener = Arc::clone(&link.signals);
        link.threads.push(
            thread::Builder::new()
                .name("herdr-guest-link-changes".into())
                .spawn(move || listen(&changes, &listener))?,
        );

        let signals = Arc::clone(&link.signals);
        link.threads.push(
            thread::Builder::new()
                .name("herdr-guest-link".into())
                .spawn(move || supervise(&host, &signals, &wake, timing))?,
        );
        Ok(link)
    }
}

impl Drop for GuestLink {
    fn drop(&mut self) {
        self.signals.stop.store(true, Ordering::Relaxed);
        self.signals.waker.wake();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Forwards guest/invite changes to the link thread until the link stops; the
/// receiver drops with this thread.
fn listen(changes: &mpsc::Receiver<()>, signals: &Signals) {
    while !signals.stopped() {
        match changes.recv_timeout(LISTENER_TICK) {
            Ok(()) => {
                signals.changed.store(true, Ordering::Relaxed);
                signals.waker.wake();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// How one relay connection ended.
enum Ended {
    Stopped,
    /// No guest or invite needs the link any more.
    Unwanted,
    /// The relay handed the host slot to a newer socket for this host.
    Replaced,
    Failed(String),
}

/// Keeps the link up while it is wanted: dial, serve, back off, repeat.
fn supervise<H: GuestHost>(
    host: &Arc<H>,
    signals: &Arc<Signals>,
    wake: &WakeReceiver,
    timing: Timing,
) {
    let mut backoff = Backoff::new(timing.backoff_base, timing.backoff_cap);
    let mut last_error: Option<String> = None;
    while !signals.stopped() {
        signals.take_changed();
        if !host.link_wanted() {
            host.set_link_status(LinkState::Off, None);
            backoff.reset();
            last_error = None;
            wait(signals, wake, Instant::now() + IDLE_RECHECK);
            continue;
        }

        host.set_link_status(LinkState::Connecting, last_error.clone());
        let ended = match relay::Connection::open(&**host, &timing, signals) {
            Ok(connection) => {
                info!("guest link: connected to relay");
                host.set_link_status(LinkState::Up, None);
                let up_since = Instant::now();
                let ended = connection.run(host, signals, wake, &timing);
                if matches!(ended, Ended::Failed(_)) && up_since.elapsed() >= timing.backoff_cap {
                    backoff.reset();
                }
                ended
            }
            Err(ended) => ended,
        };
        let error = match ended {
            Ended::Stopped => break,
            Ended::Unwanted => continue,
            // Never reset: two hosts sharing one secret must not evict each
            // other in a tight loop.
            Ended::Replaced => "replaced by another connection for this host".to_owned(),
            Ended::Failed(error) => error,
        };
        warn!("guest link: {error}");
        host.set_link_status(LinkState::Retrying, Some(error.clone()));
        last_error = Some(error);
        let deadline = Instant::now() + backoff.next(entropy());
        // A change that leaves nothing to serve ends the wait early; the loop
        // top then reports `off`.
        while let Woke::Changed = wait(signals, wake, deadline) {
            if !host.link_wanted() {
                break;
            }
        }
    }
    host.set_link_status(LinkState::Off, None);
}

enum Woke {
    Stopped,
    Changed,
    Deadline,
}

/// Sleeps until stopped, a guest/invite change, or `deadline`.
fn wait(signals: &Signals, wake: &WakeReceiver, deadline: Instant) -> Woke {
    loop {
        if signals.stopped() {
            return Woke::Stopped;
        }
        if signals.take_changed() {
            return Woke::Changed;
        }
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Woke::Deadline;
        };
        let mut fds = [libc::pollfd {
            fd: wake.fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if poll(&mut fds, left).is_err() {
            thread::sleep(left.min(Duration::from_millis(100)));
        }
        wake.drain();
    }
}
