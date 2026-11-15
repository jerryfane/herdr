//! The reply side of `herdr api-bridge --multi`: one writer thread that owns
//! stdout and every reply waiting for it.
//!
//! Until a client opts in with `bridge.hello {frames: true}`, replies go out
//! as whole lines, one after another, exactly as older bridges wrote them.
//! After the hello reply, every reply is cut into frames of at most
//! [`FRAME_BYTES`] and the writer takes turns between the replies waiting, so
//! a megabyte reply no longer holds a small one behind it:
//!
//! ```text
//! {"frame":"<id>","len":<n>,"last":<bool>}\n<n bytes of the reply line>
//! ```
//!
//! A reply's frames are its line's bytes in order, without the newline; the
//! frame with `"last":true` completes it. `"abort":true` (with `len` 0) drops
//! the bytes a cancelled reply already sent; its `cancelled` error follows as
//! a reply of its own.
//!
//! A framed client may also ask for gzip (`bridge.hello {compress: "gzip"}`).
//! Then a reply line of at least [`COMPRESS_MIN_BYTES`] is gzipped by the
//! worker that produced it, before it is queued, and every frame of it says
//! `"enc":"gzip"`: its frames' bytes are one gzip member whose content is the
//! reply line. Smaller replies, and replies queued before the hello reply was
//! written, stay plain. Unframed replies are never compressed.
//!
//! Workers hand over one reply at a time and wait until it has been written
//! or cancelled, so the bridge never buffers more than one reply per worker,
//! the same bound the old whole-line writer had. The request reader never
//! waits on output, so it always reads the next `bridge.cancel`: it posts its
//! own small replies without waiting. A reply to work the bridge refused (an
//! error, `busy`, the answer to a cancel that stopped nothing) is dropped
//! past [`MAX_POSTED`] pending. A reply owed to a request it accepted (the
//! request's `cancelled` error, which its worker posts, and the answer to the
//! cancel that stopped it) is never dropped; the reader accepts no request
//! while [`MAX_OWED`] of them wait, which keeps them bounded.

use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::remote::API_BRIDGE_COMPRESS_MIN_BYTES as COMPRESS_MIN_BYTES;
use crate::remote::API_BRIDGE_FRAME_BYTES as FRAME_BYTES;
use crate::remote::API_BRIDGE_MULTI_MAX_IN_FLIGHT as MULTI_MAX_IN_FLIGHT;

/// Replies to refused work the request reader may have waiting to be written
/// at once. They are one short line each; a client flooding the bridge with
/// more requests than it can answer loses the excess replies rather than
/// stalling the reader.
pub(super) const MAX_POSTED: usize = 64;
/// How the bridge writes replies, as the client's `bridge.hello` set it. Both
/// only ever turn on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Session {
    /// Replies are framed and interleaved.
    pub(super) frames: bool,
    /// Large replies are gzipped. Only ever set together with `frames`.
    pub(super) gzip: bool,
}

/// Owed replies waiting to be written at which the reader stops accepting
/// requests (it answers `busy`): what a full admission (16 running, 16
/// waiting), every request cancelled, owes. Each accepted request owes at
/// most two, so fewer than `MAX_OWED` + 64 are ever queued.
pub(super) const MAX_OWED: usize = 4 * MULTI_MAX_IN_FLIGHT;

/// How one reply left the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Delivery {
    Written,
    /// `bridge.cancel` stopped it before (all of) it was written.
    Cancelled,
}

/// A request a `bridge.cancel` can reach, from the moment it is read until
/// its worker finishes.
pub(super) type RequestKey = u64;

#[derive(Default)]
pub(super) struct Outbox {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    /// How replies are written now: the hello reply that turned it on has
    /// been written.
    session: Session,
    /// What `bridge.hello` requests have asked for so far: every hello reply
    /// says so and turns it on once written, never before.
    requested: Session,
    /// Every reply not yet fully written. The writer serves the first one it
    /// may write and moves a reply it has not finished behind every other
    /// waiting reply, so a new reply cannot keep overtaking an unfinished
    /// one. A reply waits behind an earlier one (lower ticket) with the same
    /// id, so one id's replies never interleave.
    queue: Vec<Reply>,
    next_ticket: u64,
    finished: HashMap<u64, Delivery>,
    next_key: RequestKey,
    active: HashMap<RequestKey, Active>,
    /// Posted replies to refused work in `queue`.
    posted: usize,
    /// Owed replies in `queue`.
    owed: usize,
    /// No producer is left; the writer drains the queue and returns.
    closed: bool,
    /// Writing failed; nothing more can be delivered.
    failed: bool,
}

struct Active {
    id: String,
    cancelled: bool,
    /// A reply line was fully written; a cancel can no longer stop it.
    answered: bool,
    /// Ends the request's API connection, so a cancelled request stops
    /// waiting for (and the server stops sending) its reply.
    on_cancel: Option<CancelHook>,
}

pub(super) type CancelHook = Box<dyn Fn() + Send>;

struct Reply {
    ticket: u64,
    key: Option<RequestKey>,
    id: String,
    bytes: Vec<u8>,
    sent: usize,
    /// Bytes of this reply the writer is writing right now, outside the lock.
    in_write: usize,
    cancelled: bool,
    /// The bytes are a gzip member of the reply line (sent as `"enc":"gzip"`).
    gzip: bool,
    /// The `bridge.hello` reply: the session it turns on once written.
    switches_to: Option<Session>,
    /// Who learns how it left the bridge.
    waiter: Waiter,
}

/// Who learns how a reply left the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waiter {
    /// Its producer, waiting in [`Outbox::send`].
    Producer,
    /// Nobody: a reply to refused work, dropped past [`MAX_POSTED`].
    Posted,
    /// Nobody, and never dropped: it completes an accepted request.
    Owed,
}

impl Reply {
    fn started(&self) -> bool {
        self.sent > 0 || self.in_write > 0
    }
}

impl Outbox {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues the `bridge.hello` reply without waiting for it to be written,
    /// so the reader stays free to read `bridge.cancel` while output is
    /// backed up. Adds `frames` and `gzip` (which needs frames) to what was
    /// requested before; `reply` builds the reply from that session, which
    /// replies written after it follow. A hello that asks for something new
    /// is never dropped; any other is a posted reply, dropped past
    /// [`MAX_POSTED`]. Fails once output has failed.
    pub(super) fn post_hello(
        &self,
        id: &str,
        frames: bool,
        gzip: bool,
        reply: impl FnOnce(Session) -> Vec<u8>,
    ) -> io::Result<()> {
        let mut state = self.state();
        if state.failed {
            return Err(output_gone());
        }
        let before = state.requested;
        let frames = before.frames || frames;
        let wanted = Session {
            frames,
            gzip: before.gzip || (gzip && frames),
        };
        state.requested = wanted;
        let waiter = if wanted != before {
            state.owed += 1;
            Waiter::Owed
        } else if state.posted < MAX_POSTED {
            state.posted += 1;
            Waiter::Posted
        } else {
            return Ok(());
        };
        state.push(None, id, reply(wanted), false, Some(wanted), waiter);
        self.changed.notify_all();
        Ok(())
    }

    /// Registers a request under `id` until [`Outbox::end`].
    pub(super) fn begin(&self, id: &str) -> RequestKey {
        let mut state = self.state();
        let key = state.next_key;
        state.next_key += 1;
        state.active.insert(
            key,
            Active {
                id: id.to_owned(),
                cancelled: false,
                answered: false,
                on_cancel: None,
            },
        );
        key
    }

    /// Runs `hook` when the request is cancelled; at once (returning `false`)
    /// if it already is.
    pub(super) fn on_cancel(&self, key: RequestKey, hook: CancelHook) -> bool {
        let mut state = self.state();
        match state.active.get_mut(&key) {
            Some(active) if active.cancelled => {
                drop(state);
                hook();
                false
            }
            Some(active) => {
                active.on_cancel = Some(hook);
                true
            }
            None => true,
        }
    }

    pub(super) fn end(&self, key: RequestKey) {
        self.state().active.remove(&key);
    }

    pub(super) fn is_cancelled(&self, key: RequestKey) -> bool {
        self.state()
            .active
            .get(&key)
            .is_some_and(|active| active.cancelled)
    }

    /// Cancels every unanswered request named `id`: replies not started are
    /// dropped, a framed reply already started ends with an abort frame, and
    /// later replies for it are refused. A reply line already being written
    /// whole (unframed), or a framed reply whose last frame is being written,
    /// cannot be stopped and is not cancelled. Returns whether any request
    /// was cancelled.
    pub(super) fn cancel(&self, id: &str) -> bool {
        let mut state = self.state();
        let state = &mut *state;
        let framed = state.session.frames;
        let mut cancelled = false;
        for (key, active) in state.active.iter_mut() {
            if active.id != id || active.answered || active.cancelled {
                continue;
            }
            let writing = state.queue.iter().find(|reply| {
                reply.key == Some(*key)
                    && reply.in_write > 0
                    && (!framed || reply.sent + reply.in_write == reply.bytes.len())
            });
            if writing.is_some() {
                continue;
            }
            active.cancelled = true;
            if let Some(hook) = active.on_cancel.take() {
                hook();
            }
            cancelled = true;
        }
        if !cancelled {
            return false;
        }
        let mut index = 0;
        while index < state.queue.len() {
            let reply = &mut state.queue[index];
            let hit = reply
                .key
                .and_then(|key| state.active.get(&key))
                .is_some_and(|active| active.cancelled);
            if !hit {
                index += 1;
                continue;
            }
            if reply.started() {
                // The writer ends it with an abort frame.
                reply.cancelled = true;
                index += 1;
            } else {
                let reply = state.queue.remove(index);
                state.finish(&reply, Delivery::Cancelled);
            }
        }
        self.changed.notify_all();
        true
    }

    /// Queues `line` (one reply, without its newline) for `id` and waits until
    /// it has been written or cancelled. `key` ties it to a cancellable
    /// request. Fails once output has failed.
    pub(super) fn send(
        &self,
        key: Option<RequestKey>,
        id: &str,
        line: Vec<u8>,
    ) -> io::Result<Delivery> {
        // Compress here, on the producer's thread, so the writer never waits
        // for it. A session with gzip is framed, and stays so, so the reply
        // will be written as frames.
        let gzipped = (line.len() >= COMPRESS_MIN_BYTES && self.state().session.gzip)
            .then(|| gzip(&line))
            .filter(|gzipped| gzipped.len() < line.len());
        match gzipped {
            Some(gzipped) => self.enqueue(key, id, gzipped, true),
            None => self.enqueue(key, id, line, false),
        }
    }

    /// Queues `line` (one reply to refused work, without its newline) for
    /// `id` without waiting for it to be written. Returns `false`, dropping
    /// it, when [`MAX_POSTED`] such replies are already waiting. Fails once
    /// output has failed.
    pub(super) fn post(&self, id: &str, line: Vec<u8>) -> io::Result<bool> {
        let mut state = self.state();
        if state.failed {
            return Err(output_gone());
        }
        if state.posted >= MAX_POSTED {
            return Ok(false);
        }
        state.posted += 1;
        state.push(None, id, line, false, None, Waiter::Posted);
        self.changed.notify_all();
        Ok(true)
    }

    /// Queues `line` (one reply, without its newline) for `id` without
    /// waiting, like [`Outbox::post`], but never drops it: it completes a
    /// request the bridge accepted. [`Outbox::admits`] keeps these bounded.
    /// Fails once output has failed.
    pub(super) fn post_owed(&self, id: &str, line: Vec<u8>) -> io::Result<()> {
        let mut state = self.state();
        if state.failed {
            return Err(output_gone());
        }
        state.owed += 1;
        state.push(None, id, line, false, None, Waiter::Owed);
        self.changed.notify_all();
        Ok(())
    }

    /// Whether the reader may accept another request: fewer than
    /// [`MAX_OWED`] owed replies are waiting for output.
    pub(super) fn admits(&self) -> bool {
        self.state().owed < MAX_OWED
    }

    fn enqueue(
        &self,
        key: Option<RequestKey>,
        id: &str,
        bytes: Vec<u8>,
        gzip: bool,
    ) -> io::Result<Delivery> {
        let mut state = self.state();
        if state.failed {
            return Err(output_gone());
        }
        if key.is_some_and(|key| {
            state
                .active
                .get(&key)
                .is_some_and(|active| active.cancelled)
        }) {
            return Ok(Delivery::Cancelled);
        }
        let ticket = state.push(key, id, bytes, gzip, None, Waiter::Producer);
        self.changed.notify_all();
        loop {
            if let Some(delivery) = state.finished.remove(&ticket) {
                return Ok(delivery);
            }
            if state.failed {
                return Err(output_gone());
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// No more replies will be queued: the writer finishes what is queued and
    /// returns.
    pub(super) fn close(&self) {
        self.state().closed = true;
        self.changed.notify_all();
    }

    /// Writes queued replies to `out` until [`Outbox::close`] and an empty
    /// queue. A write failure fails every waiting producer and is returned.
    pub(super) fn run_writer<W: Write>(&self, mut out: W) -> io::Result<()> {
        // Builds frame headers and frames only; a whole line is written from
        // its own buffer.
        let mut buf = Vec::new();
        loop {
            let mut line = None;
            let (ticket, written) = {
                let mut state = self.state();
                let index = loop {
                    if let Some(index) = state.next_index() {
                        break index;
                    }
                    if state.closed && state.queue.is_empty() {
                        return Ok(());
                    }
                    state = self
                        .changed
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                };
                let framed = state.session.frames;
                let reply = &mut state.queue[index];
                buf.clear();
                let ticket = reply.ticket;
                if reply.cancelled {
                    // Started and framed: tell the client to drop it.
                    push_header(&mut buf, &reply.id, 0, true, ABORT);
                    let reply = state.queue.remove(index);
                    state.finish(&reply, Delivery::Cancelled);
                    self.changed.notify_all();
                    drop(state);
                    if let Err(err) = out.write_all(&buf).and_then(|()| out.flush()) {
                        return Err(self.fail(err));
                    }
                    continue;
                }
                let written = if framed {
                    let len = (reply.bytes.len() - reply.sent).min(FRAME_BYTES);
                    let last = reply.sent + len == reply.bytes.len();
                    let mark = if reply.gzip { GZIP } else { b"" };
                    push_header(&mut buf, &reply.id, len, last, mark);
                    buf.extend_from_slice(&reply.bytes[reply.sent..reply.sent + len]);
                    len
                } else {
                    debug_assert!(!reply.gzip, "only a framed session compresses");
                    // Unframed replies go whole: the bytes leave the queue
                    // with the writer, which leaves `sent == bytes.len()`.
                    line = Some(std::mem::take(&mut reply.bytes));
                    0
                };
                // Mark it even when empty so a cancel cannot take it mid-write.
                reply.in_write = written.max(1);
                (ticket, written)
            };

            let result = match &line {
                Some(line) => out.write_all(line).and_then(|()| out.write_all(b"\n")),
                None => out.write_all(&buf),
            };
            if let Err(err) = result.and_then(|()| out.flush()) {
                return Err(self.fail(err));
            }

            let mut state = self.state();
            let index = state
                .queue
                .iter()
                .position(|reply| reply.ticket == ticket)
                .expect("a reply being written stays queued");
            let reply = &mut state.queue[index];
            reply.sent += written;
            reply.in_write = 0;
            if reply.sent < reply.bytes.len() {
                // Round robin: behind everything already waiting.
                let reply = state.queue.remove(index);
                state.queue.push(reply);
            } else {
                let reply = state.queue.remove(index);
                if let Some(active) = reply.key.and_then(|key| state.active.get_mut(&key)) {
                    active.answered = true;
                }
                if let Some(session) = reply.switches_to {
                    state.session.frames |= session.frames;
                    state.session.gzip |= session.gzip;
                }
                state.finish(&reply, Delivery::Written);
            }
            self.changed.notify_all();
        }
    }

    fn fail(&self, err: io::Error) -> io::Error {
        let mut state = self.state();
        state.failed = true;
        state.queue.clear();
        state.posted = 0;
        state.owed = 0;
        drop(state);
        self.changed.notify_all();
        err
    }
}

impl State {
    /// Queues a reply and returns its ticket.
    fn push(
        &mut self,
        key: Option<RequestKey>,
        id: &str,
        bytes: Vec<u8>,
        gzip: bool,
        switches_to: Option<Session>,
        waiter: Waiter,
    ) -> u64 {
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        self.queue.push(Reply {
            ticket,
            key,
            id: id.to_owned(),
            bytes,
            sent: 0,
            in_write: 0,
            cancelled: false,
            gzip,
            switches_to,
            waiter,
        });
        ticket
    }

    /// Records how `reply`, just taken off the queue, left the bridge, for
    /// the producer waiting on it (a posted or owed reply has none).
    fn finish(&mut self, reply: &Reply, delivery: Delivery) {
        match reply.waiter {
            Waiter::Producer => {
                self.finished.insert(reply.ticket, delivery);
            }
            Waiter::Posted => self.posted -= 1,
            Waiter::Owed => self.owed -= 1,
        }
    }

    /// The next reply to write from: the first in the rotation that does not
    /// wait behind an earlier reply (lower ticket) with the same id.
    fn next_index(&self) -> Option<usize> {
        self.queue.iter().position(|reply| {
            !self
                .queue
                .iter()
                .any(|other| other.id == reply.id && other.ticket < reply.ticket)
        })
    }
}

/// Header fields after `last`: an aborted reply, or a gzipped one.
const ABORT: &[u8] = b",\"abort\":true";
const GZIP: &[u8] = b",\"enc\":\"gzip\"";

fn push_header(buf: &mut Vec<u8>, id: &str, len: usize, last: bool, mark: &[u8]) {
    buf.extend_from_slice(b"{\"frame\":");
    // Serializing a `&str` cannot fail.
    serde_json::to_writer(&mut *buf, id).expect("frame id serializes");
    let _ = write!(buf, ",\"len\":{len},\"last\":{last}");
    buf.extend_from_slice(mark);
    buf.extend_from_slice(b"}\n");
}

/// One gzip member of `line`: a fixed 10-byte header (no name, comment or
/// extra field, `FLG` 0), the deflate stream, then CRC-32 and size. A client
/// without a gzip reader can drop those 10 + 8 bytes and inflate the rest as
/// raw deflate.
fn gzip(line: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(line.len() / 4), Compression::default());
    // Writing to a `Vec` cannot fail.
    encoder.write_all(line).expect("gzip into memory");
    encoder.finish().expect("gzip into memory")
}

fn output_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "api-bridge: output closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    /// Output that hands each flushed frame to the test and waits for leave
    /// to go on, so the test can queue replies while a frame is being written.
    struct GatedOutput {
        buf: Vec<u8>,
        written: mpsc::Sender<String>,
        permits: mpsc::Receiver<()>,
    }

    impl Write for GatedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buf.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            let header_end = self.buf.iter().position(|&b| b == b'\n').unwrap();
            let header: serde_json::Value =
                serde_json::from_slice(&self.buf[..header_end]).unwrap();
            self.buf.clear();
            let id = header["frame"].as_str().unwrap().to_owned();
            self.written.send(id).unwrap();
            self.permits.recv().map_err(|_| output_gone())
        }
    }

    /// Small replies arriving while others are written cannot keep a big
    /// reply waiting: it gets a turn after every reply already queued.
    #[test]
    fn new_small_replies_do_not_starve_an_unfinished_big_one() {
        let outbox = Outbox::default();
        outbox.state().session.frames = true;
        assert!(outbox.post("big", vec![b'x'; 3 * FRAME_BYTES]).unwrap());
        assert!(outbox.post("small0", b"{}".to_vec()).unwrap());

        let (written, frames) = mpsc::channel();
        let (permit, permits) = mpsc::channel();
        thread::scope(|scope| {
            let writer = scope.spawn(|| {
                outbox.run_writer(GatedOutput {
                    buf: Vec::new(),
                    written,
                    permits,
                })
            });
            let mut order = Vec::new();
            let smalls = 9;
            for _ in 0..3 + smalls {
                order.push(frames.recv().unwrap());
                // A new small reply arrives during every write.
                let next = order.iter().filter(|id| id.starts_with("small")).count()
                    + order.iter().filter(|id| *id == "big").count();
                if next < smalls {
                    assert!(outbox
                        .post(&format!("small{next}"), b"{}".to_vec())
                        .unwrap());
                }
                permit.send(()).unwrap();
            }
            outbox.close();
            writer.join().unwrap().unwrap();

            // Between two turns of `big`, only replies already queued when
            // the first turn was written may go: `small{n}` was posted while
            // frame `n` of the order was written.
            let mut last_big = None;
            for (index, id) in order.iter().enumerate() {
                if id == "big" {
                    last_big = Some(index);
                } else if let Some(turn) = last_big {
                    let n: usize = id["small".len()..].parse().unwrap();
                    assert!(n <= turn + 1, "{id} overtook big: {order:?}");
                }
            }
            assert_eq!(
                order.iter().filter(|id| *id == "big").count(),
                3,
                "{order:?}"
            );
        });
    }
}
