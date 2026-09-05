//! Line/length framing reads for the held-open streaming connections.
//!
//! Three streaming modules read newline-delimited frames off a connection the
//! server thread owns for the channel's lifetime: `pane.graphics.stream`
//! (`pane_graphics_stream`), `pane.input.stream` (`pane_input_stream`), and
//! `gram.upload.stream` (`gram_upload_stream`). Each needs the same three
//! properties — a deadline on a partially written frame, a stop check against
//! both the server's `running` flag and the channel's own `stream_active`, and a
//! platform fallback when the transport cannot take a receive timeout — so the
//! machinery lives here once instead of once per module.
//!
//! What stays at the call site: the byte cap, the idle/total deadlines, and the
//! frame `label` used in the timeout messages. Those are per-protocol decisions
//! (a keystroke frame is tiny and near-instant; a 512 KiB upload frame is not),
//! and the timeout text is part of each module's observable error surface.

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::ApiStream;
use crate::ipc::is_connection_closed_error;

use super::CONNECTION_POLL_INTERVAL;

/// First poll interval on the no-socket-timeout fallback path.
pub(super) const FALLBACK_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Polls served at [`FALLBACK_POLL_INTERVAL`] before the interval starts
/// doubling, so a burst stays responsive without spinning for a whole session.
pub(super) const FALLBACK_FAST_POLLS: u8 = 32;
/// Read-buffer size for a length-prefixed frame body. An internal buffering
/// choice, not a protocol cap — the body length is bounded by the caller.
const BODY_READ_CHUNK_BYTES: usize = 64 * 1024;

/// A streaming channel keeps reading only while the server is up AND this
/// channel has not been retired (the app side flips `stream_active` when the
/// pane or stream goes away).
pub(super) fn stream_is_running(running: &AtomicBool, stream_active: &AtomicBool) -> bool {
    running.load(Ordering::Relaxed) && stream_active.load(Ordering::Acquire)
}

/// Read one newline-terminated frame ONE BYTE AT A TIME, or `None` when the peer
/// closed or the channel was stopped. `label` names the frame in the timeout and
/// oversize errors (e.g. `"input frame"` -> `"timed out reading input frame"`).
///
/// Byte-at-a-time is deliberate here and matches the daemon's own
/// `read_initial_request_line`: `pane.graphics.stream` reads a header LINE and
/// then a binary body off the same connection, so a reader that over-reads past
/// the newline would swallow body bytes. A channel whose frames are all text
/// should use [`LineReader`] instead — one syscall per byte costs ~1 MB/s, which
/// is fine for keystrokes and ruinous for a 700 KB upload frame.
pub(super) fn read_line(
    stream: &mut ApiStream,
    running: &Arc<AtomicBool>,
    stream_active: &Arc<AtomicBool>,
    max_bytes: usize,
    idle_timeout: Duration,
    total_timeout: Duration,
    label: &str,
) -> std::io::Result<Option<String>> {
    // Built ONCE: this loop reads a single byte per iteration, so formatting inside
    // it would cost a heap allocation per byte on the keystroke path.
    let timeout_message = format!("timed out reading {label}");
    with_timed_reads(stream, |stream, mut wait| {
        let mut bytes = Vec::new();
        let mut byte = [0_u8; 1];
        let mut total_deadline = None;
        let mut idle_deadline = None;

        loop {
            if !stream_is_running(running, stream_active) {
                return Ok(None);
            }
            ensure_before_deadlines(idle_deadline, total_deadline, &timeout_message)?;
            match stream.read(&mut byte) {
                Ok(0) => return Ok(None),
                Ok(_) => {
                    wait.on_progress();
                    let now = Instant::now();
                    let total_deadline_at =
                        *total_deadline.get_or_insert_with(|| now + total_timeout);
                    idle_deadline = Some(now + idle_timeout);
                    if now >= total_deadline_at {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("timed out reading {label}"),
                        ));
                    }
                    bytes.push(byte[0]);
                    if byte[0] == b'\n' {
                        return String::from_utf8(bytes)
                            .map(Some)
                            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
                    }
                    if bytes.len() > max_bytes {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{label} is too large"),
                        ));
                    }
                }
                Err(err) if read_should_retry(&err) => {
                    wait.after_retry(idle_deadline, total_deadline);
                }
                Err(err) if is_connection_closed_error(&err) => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    })
}

/// Buffered line framing for a channel whose frames are ALL newline-delimited
/// text, so over-reading past a newline is safe (nothing else shares the
/// connection). One `read` syscall serves many frames instead of one syscall per
/// byte; on the upload channel that is the difference between ~1 MB/s and
/// transport speed.
///
/// One reader per channel — the leftover bytes of a partially received frame
/// live in it between calls, so a per-call reader would drop them.
pub(super) struct LineReader {
    pending: Vec<u8>,
    scratch: Vec<u8>,
}

impl LineReader {
    pub(super) fn new() -> Self {
        Self {
            pending: Vec::new(),
            scratch: vec![0_u8; BODY_READ_CHUNK_BYTES],
        }
    }

    /// Next complete line, or `None` on peer close / channel stop. Semantics
    /// match [`read_line`]: the deadlines cover a frame that has STARTED
    /// arriving, an idle wait between frames is unbounded, and a partial line
    /// at EOF is discarded with the close.
    pub(super) fn read_line(
        &mut self,
        stream: &mut ApiStream,
        running: &Arc<AtomicBool>,
        stream_active: &Arc<AtomicBool>,
        max_bytes: usize,
        idle_timeout: Duration,
        total_timeout: Duration,
        label: &str,
    ) -> std::io::Result<Option<String>> {
        // A line already buffered from a previous over-read goes through the same cap
        // check as one just read. With today's only caller it cannot actually trip:
        // `pending` only accumulates while it holds no newline, so the remainder
        // `take_line` leaves is a strict suffix of ONE read — at most
        // `BODY_READ_CHUNK_BYTES` (64 KiB), well under the 1 MiB upload frame cap.
        // It is here so a future caller with a cap below the read chunk size does not
        // silently get an unchecked line; the same-read overflow case is caught by
        // the in-loop check.
        if let Some(line) = take_line(&mut self.pending)? {
            return oversize_or_line(line, max_bytes, label);
        }

        let timeout_message = format!("timed out reading {label}");
        let pending = &mut self.pending;
        let scratch = &mut self.scratch;
        with_timed_reads(stream, |stream, mut wait| {
            // A frame already half-received is on the clock from the first read.
            let mut total_deadline = (!pending.is_empty()).then(|| Instant::now() + total_timeout);
            let mut idle_deadline = None;

            loop {
                if !stream_is_running(running, stream_active) {
                    return Ok(None);
                }
                ensure_before_deadlines(idle_deadline, total_deadline, &timeout_message)?;
                match stream.read(scratch) {
                    Ok(0) => return Ok(None),
                    Ok(read) => {
                        wait.on_progress();
                        let now = Instant::now();
                        let total_deadline_at =
                            *total_deadline.get_or_insert_with(|| now + total_timeout);
                        idle_deadline = Some(now + idle_timeout);
                        if now >= total_deadline_at {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                timeout_message.clone(),
                            ));
                        }
                        pending.extend_from_slice(&scratch[..read]);
                        if let Some(line) = take_line(pending)? {
                            return oversize_or_line(line, max_bytes, label);
                        }
                        if pending.len() > max_bytes {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("{label} is too large"),
                            ));
                        }
                    }
                    Err(err) if read_should_retry(&err) => {
                        wait.after_retry(idle_deadline, total_deadline);
                    }
                    Err(err) if is_connection_closed_error(&err) => return Ok(None),
                    Err(err) => return Err(err),
                }
            }
        })
    }
}

/// Split the first complete line (newline included) out of `pending`, leaving
/// the remainder for the next call.
fn take_line(pending: &mut Vec<u8>) -> std::io::Result<Option<String>> {
    let Some(end) = pending.iter().position(|byte| *byte == b'\n') else {
        return Ok(None);
    };
    let rest = pending.split_off(end + 1);
    let line = std::mem::replace(pending, rest);
    String::from_utf8(line)
        .map(Some)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// A complete line, or the oversize error. The cap has to be re-tested on a line
/// the buffered reader RETURNS, not only on the unterminated remainder: a frame
/// whose newline lands in the same read that pushes it past `max_bytes` never
/// leaves an over-cap remainder behind to catch.
///
/// The terminator is excluded from the measurement, because `take_line` returns it
/// and the byte-at-a-time [`read_line`] counts only non-newline bytes. Measuring
/// the whole line would make this reader one byte tighter than the reference — and
/// tighter than the sibling remainder check in the same function.
fn oversize_or_line(
    line: String,
    max_bytes: usize,
    label: &str,
) -> std::io::Result<Option<String>> {
    let payload = line.strip_suffix('\n').unwrap_or(&line).len();
    if payload > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} is too large"),
        ));
    }
    Ok(Some(line))
}

/// Read exactly `len` bytes of a length-prefixed frame body. `None` means the
/// peer closed (or the channel stopped) before any body byte arrived; a close
/// mid-body is an error, because the frame header already promised the bytes.
pub(super) fn read_exact(
    stream: &mut ApiStream,
    len: usize,
    running: &Arc<AtomicBool>,
    stream_active: &Arc<AtomicBool>,
    idle_timeout: Duration,
    total_timeout: Duration,
    label: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    with_timed_reads(stream, |stream, mut wait| {
        let mut data = Vec::new();
        let mut chunk = vec![0_u8; BODY_READ_CHUNK_BYTES.min(len)];
        let total_deadline = Instant::now() + total_timeout;
        let mut idle_deadline = Instant::now() + idle_timeout;

        while data.len() < len {
            if !stream_is_running(running, stream_active) {
                return Ok(None);
            }
            ensure_before_deadlines(
                Some(idle_deadline),
                Some(total_deadline),
                &format!("timed out reading {label}"),
            )?;
            let remaining = len - data.len();
            let read_len = remaining.min(chunk.len());
            match stream.read(&mut chunk[..read_len]) {
                Ok(0) if data.is_empty() => return Ok(None),
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended mid-frame",
                    ));
                }
                Ok(n) => {
                    wait.on_progress();
                    let now = Instant::now();
                    if now >= total_deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("timed out reading {label}"),
                        ));
                    }
                    data.extend_from_slice(&chunk[..n]);
                    idle_deadline = now + idle_timeout;
                }
                Err(err) if read_should_retry(&err) => {
                    wait.after_retry(Some(idle_deadline), Some(total_deadline));
                }
                Err(err) if is_connection_closed_error(&err) && data.is_empty() => return Ok(None),
                Err(err) => return Err(err),
            }
        }

        Ok(Some(data))
    })
}

#[derive(Clone, Copy)]
enum ReadWait {
    SocketTimeout,
    Poll(PollBackoff),
}

impl ReadWait {
    fn after_retry(&mut self, idle_deadline: Option<Instant>, total_deadline: Option<Instant>) {
        if let Self::Poll(backoff) = self {
            sleep_until_poll(idle_deadline, total_deadline, backoff.interval);
            backoff.advance();
        }
    }

    fn on_progress(&mut self) {
        if let Self::Poll(backoff) = self {
            backoff.reset();
        }
    }
}

#[derive(Clone, Copy)]
struct PollBackoff {
    interval: Duration,
    fast_polls_remaining: u8,
}

impl PollBackoff {
    fn new() -> Self {
        Self {
            interval: FALLBACK_POLL_INTERVAL,
            fast_polls_remaining: FALLBACK_FAST_POLLS,
        }
    }

    fn advance(&mut self) {
        if self.fast_polls_remaining > 0 {
            self.fast_polls_remaining -= 1;
            return;
        }
        self.interval = (self.interval * 2).min(CONNECTION_POLL_INTERVAL);
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

fn with_timed_reads<T>(
    stream: &mut ApiStream,
    read: impl FnOnce(&mut ApiStream, ReadWait) -> std::io::Result<Option<T>>,
) -> std::io::Result<Option<T>> {
    match stream.set_recv_timeout(Some(CONNECTION_POLL_INTERVAL)) {
        Ok(()) => {
            let result = read(stream, ReadWait::SocketTimeout);
            finish_timed_read(result, || stream.set_recv_timeout(None))
        }
        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
            stream.set_nonblocking(true)?;
            let result = read(stream, ReadWait::Poll(PollBackoff::new()));
            finish_timed_read(result, || stream.set_nonblocking(false))
        }
        // A peer can disconnect after the caller's running check but before
        // setsockopt; macOS reports that closed-socket race as EINVAL.
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => Ok(None),
        Err(err) => Err(err),
    }
}

fn finish_timed_read<T>(
    result: std::io::Result<Option<T>>,
    reset: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<Option<T>> {
    match result {
        Ok(None) => Ok(None),
        Ok(value) => {
            reset()?;
            Ok(value)
        }
        Err(err) => {
            let _ = reset();
            Err(err)
        }
    }
}

fn ensure_before_deadlines(
    idle_deadline: Option<Instant>,
    total_deadline: Option<Instant>,
    message: &str,
) -> std::io::Result<()> {
    let now = Instant::now();
    if idle_deadline.is_some_and(|deadline| now >= deadline)
        || total_deadline.is_some_and(|deadline| now >= deadline)
    {
        return Err(io::Error::new(io::ErrorKind::TimedOut, message));
    }
    Ok(())
}

fn sleep_until_poll(
    idle_deadline: Option<Instant>,
    total_deadline: Option<Instant>,
    poll_interval: Duration,
) {
    let now = Instant::now();
    let until_deadline = [idle_deadline, total_deadline]
        .into_iter()
        .flatten()
        .filter_map(|deadline| deadline.checked_duration_since(now))
        .min()
        .unwrap_or(poll_interval);
    std::thread::sleep(poll_interval.min(until_deadline));
}

fn read_should_retry(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_read_skips_reset_after_stream_ends() {
        let mut reset_called = false;
        let result = finish_timed_read::<()>(Ok(None), || {
            reset_called = true;
            Ok(())
        });

        assert!(result.unwrap().is_none());
        assert!(!reset_called);
    }

    #[test]
    fn fallback_poll_backoff_preserves_fast_window_then_reaches_poll_ceiling() {
        let mut backoff = PollBackoff::new();
        for _ in 0..FALLBACK_FAST_POLLS {
            backoff.advance();
            assert_eq!(backoff.interval, FALLBACK_POLL_INTERVAL);
        }

        backoff.advance();
        assert_eq!(backoff.interval, Duration::from_millis(2));
        for _ in 0..6 {
            backoff.advance();
        }
        assert_eq!(backoff.interval, CONNECTION_POLL_INTERVAL);

        backoff.reset();
        assert_eq!(backoff.interval, FALLBACK_POLL_INTERVAL);
        assert_eq!(backoff.fast_polls_remaining, FALLBACK_FAST_POLLS);
    }
}
