//! Outbound `pane.stream` server: a persistent server->client raw PTY byte
//! firehose. Unlike the inbound streams (`pane_input_stream`,
//! `gram_upload_stream`) it never reads frames from the client: it drains a
//! pane's bounded [`OutputRing`] and writes newline-delimited JSON frames.
//!
//! Lifecycle: dispatch `PaneStreamOpen` to the app (validate + attach + publish
//! the ring), look the ring up off the app loop, write the `stream_started` ack
//! and a `reset` seed, then a Condvar-woken drain loop that coalesces ready
//! bytes into `data` frames, interleaves `resize`, heartbeats with `ping`, and
//! emits `exited` when the runtime is gone. On exit it dispatches
//! `PaneStreamClose` to release the viewer.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;

use crate::api::output_registry;
use crate::api::schema::{
    ErrorBody, ErrorResponse, Method, PaneStreamParams, Request, ResponseResult, SuccessResponse,
};
use crate::api::{ApiRequestSender, ApiStream};
use crate::ipc::is_connection_closed_error;
use crate::pane::{clamp_max_frame_bytes, OutputDrain, OutputRing, OutputSnapshot, OutputWait};

use super::{
    api_response_outcome, dispatch_to_app_with_timeout, should_stop_connection,
    write_text_line_allow_disconnect, APP_RESPONSE_TIMEOUT,
};

/// Idle heartbeat / dead-peer reap cadence.
const PING_INTERVAL: Duration = Duration::from_secs(20);

const STREAM_TAG: &str = "pane.bytes";

/// Most scrollback rows one keyframe carries; the same ceiling `pane.read`
/// applies to `recent`, so a keyframe stays a bounded single line.
const MAX_KEYFRAME_HISTORY_LINES: usize = 1000;

/// Scrollback rows each `reset` keyframe should carry: `scrollback_lines`,
/// clamped, unless the client opted out with `include_history: false`.
fn keyframe_history_lines(params: &PaneStreamParams) -> usize {
    if !params.include_history {
        return 0;
    }
    params
        .scrollback_lines
        .unwrap_or(0)
        .min(MAX_KEYFRAME_HISTORY_LINES)
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// One newline-delimited `pane.stream` frame line.
#[derive(serde::Serialize)]
struct StreamFrameLine {
    stream: &'static str,
    frame: &'static str,
    seq: u64,
    epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_b64: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    lagged: bool,
    /// Base64 ANSI scrollback rows above a `reset` keyframe's screen, oldest
    /// first, captured atomically with it. Present only when the stream asked
    /// for `scrollback_lines`; empty when the pane has no history to give.
    #[serde(skip_serializing_if = "Option::is_none")]
    history_b64: Option<String>,
    /// `pane.history` cursor for the first row of `history_b64`; present only
    /// when older rows remain above it.
    #[serde(skip_serializing_if = "Option::is_none")]
    history_cursor: Option<String>,
}

impl StreamFrameLine {
    fn base(frame: &'static str, seq: u64, epoch: u64) -> Self {
        Self {
            stream: STREAM_TAG,
            frame,
            seq,
            epoch,
            cols: None,
            rows: None,
            data_b64: None,
            lagged: false,
            history_b64: None,
            history_cursor: None,
        }
    }

    fn reset(seq: u64, epoch: u64, seed: &OutputSnapshot, lagged: bool) -> Self {
        Self {
            cols: Some(seed.cols),
            rows: Some(seed.rows),
            data_b64: Some(encode_bytes(seed.ansi.as_bytes())),
            history_b64: seed
                .history
                .as_deref()
                .map(|history| encode_bytes(history.as_bytes())),
            history_cursor: seed.history_cursor.clone(),
            lagged,
            ..Self::base("reset", seq, epoch)
        }
    }

    fn data(seq: u64, epoch: u64, data_b64: String) -> Self {
        Self {
            data_b64: Some(data_b64),
            ..Self::base("data", seq, epoch)
        }
    }

    fn resize(seq: u64, epoch: u64, cols: u16, rows: u16) -> Self {
        Self {
            cols: Some(cols),
            rows: Some(rows),
            ..Self::base("resize", seq, epoch)
        }
    }

    fn ping(seq: u64, epoch: u64) -> Self {
        Self::base("ping", seq, epoch)
    }

    fn exited(seq: u64, epoch: u64) -> Self {
        Self::base("exited", seq, epoch)
    }
}

fn encode_bytes(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(super) fn serve(
    mut stream: ApiStream,
    request_id: String,
    params: PaneStreamParams,
    api_tx: &ApiRequestSender,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    serve_watched(&mut stream, request_id, params, api_tx, running, None)
}

/// Called before every frame, on idle ticks, and with `closed = true` when the
/// runtime ended. A returned line is written as the final frame and the
/// stream closes.
pub(super) type StreamWatch<'a> = &'a mut dyn FnMut(bool) -> Option<String>;

/// Poll cadence for a watched stream, so a watch fires promptly while idle.
const WATCH_POLL: Duration = Duration::from_millis(250);

/// How long one frame write may make no progress before the stream ends. A
/// slow link drains a little at a time and never gets here; a reader that is
/// gone without closing (a suspended phone whose SSH channel is still up) does.
const STALL_LIMIT: Duration = Duration::from_secs(60);
/// A blocked write wakes this often to count its stall and notice shutdown.
const STALL_POLL: Duration = Duration::from_millis(500);
/// A frame write that blocked at least this long means the reader is behind.
const BACKPRESSURE_WRITE: Duration = Duration::from_millis(250);
/// A reader behind by more than this skips the backlog for a fresh keyframe:
/// a screen plus its history is 50-140 KB on the wire, the backlog up to the
/// ring's 1 MiB (about 1.4 MB as base64).
const RESYNC_BACKLOG_BYTES: u64 = 256 * 1024;
/// Stall budget for the error line that says why a stream ended.
const FAREWELL_STALL_LIMIT: Duration = Duration::from_secs(2);

/// Writes a stream's frame lines, waiting out a slow reader rather than
/// failing on the connection's 5 s write timeout.
struct FrameWriter<'a> {
    stream: &'a mut ApiStream,
    running: &'a AtomicBool,
    stall_limit: Duration,
    /// The last line's write blocked at least [`BACKPRESSURE_WRITE`].
    behind: bool,
    /// The rest of a line a stall cut off part way; the farewell finishes it
    /// so the error line after it parses.
    unsent: Vec<u8>,
}

impl<'a> FrameWriter<'a> {
    fn new(stream: &'a mut ApiStream, running: &'a AtomicBool) -> Self {
        if let Err(err) = stream.set_send_timeout(Some(STALL_POLL)) {
            tracing::debug!(err = %err, "pane.stream write poll unavailable");
        }
        Self {
            stream,
            running,
            stall_limit: STALL_LIMIT,
            behind: false,
            unsent: Vec::new(),
        }
    }

    fn write_json<T: serde::Serialize>(&mut self, value: &T) -> std::io::Result<bool> {
        let mut line = serde_json::to_vec(value)
            .map_err(|err| std::io::Error::other(format!("failed to encode json: {err}")))?;
        line.push(b'\n');
        self.write_line(&line)
    }

    fn write_text(&mut self, text: &str) -> std::io::Result<bool> {
        let mut line = Vec::with_capacity(text.len() + 1);
        line.extend_from_slice(text.as_bytes());
        line.push(b'\n');
        self.write_line(&line)
    }

    /// Writes `line` (ending in `\n`) whole. `Ok(false)`: the client closed
    /// the stream or the server is stopping. Fails once a write makes no
    /// progress for `stall_limit`.
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<bool> {
        let started = Instant::now();
        let mut last_progress = started;
        let mut written = 0;
        while written < line.len() {
            match self.stream.write(&line[written..]) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    written += n;
                    last_progress = Instant::now();
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) if is_connection_closed_error(&err) => return Ok(false),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if !self.running.load(Ordering::Relaxed) {
                        return Ok(false);
                    }
                    if last_progress.elapsed() >= self.stall_limit {
                        if written > 0 {
                            self.unsent = line[written..].to_vec();
                        }
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "the client read nothing for {} s",
                                self.stall_limit.as_secs()
                            ),
                        ));
                    }
                }
                Err(err) => return Err(err),
            }
        }
        match self.stream.flush() {
            Err(err) if is_connection_closed_error(&err) => return Ok(false),
            result => result?,
        }
        self.behind = started.elapsed() >= BACKPRESSURE_WRITE;
        Ok(true)
    }

    /// Tells the client why the stream ends after `err`: finishes a line a
    /// stall cut off, then writes a `stream_stalled` (no progress for the
    /// stall limit) or `stream_failed` error line, each within a short stall
    /// budget. A reader that is gone gets nothing, as before.
    fn farewell(&mut self, request_id: &str, err: &std::io::Error) {
        let code = if err.kind() == std::io::ErrorKind::TimedOut {
            "stream_stalled"
        } else {
            "stream_failed"
        };
        self.stall_limit = FAREWELL_STALL_LIMIT;
        let unsent = std::mem::take(&mut self.unsent);
        if !unsent.is_empty() && !matches!(self.write_line(&unsent), Ok(true)) {
            return;
        }
        let _ = self.write_json(&ErrorResponse {
            id: request_id.to_string(),
            error: ErrorBody {
                code: code.into(),
                message: format!("pane.stream ended: {err}; reconnect to resync"),
            },
        });
    }
}

/// Whether a stream should drop its backlog for a fresh keyframe: its reader
/// is behind (the last frame write blocked) and more is waiting than a
/// keyframe costs.
fn skip_to_keyframe(behind: bool, backlog: u64) -> bool {
    behind && backlog > RESYNC_BACKLOG_BYTES
}

/// `pane.stream` with an optional watch (the guest gate's pause/revoke check).
/// The stream is spent when this returns: the caller closes it.
pub(super) fn serve_watched(
    stream: &mut ApiStream,
    request_id: String,
    params: PaneStreamParams,
    api_tx: &ApiRequestSender,
    running: &Arc<AtomicBool>,
    watch: Option<StreamWatch<'_>>,
) -> std::io::Result<()> {
    let pane_id = params.pane_id.clone();
    // Capture the viewer id from the OPEN params before they are moved into the
    // open request, so the synthesized close can drop exactly this viewer's width
    // lease (#137). The close params are built fresh below and would otherwise
    // carry no viewer id.
    let viewer_id = params.viewer_id.clone();
    let max_frame_bytes = clamp_max_frame_bytes(params.max_frame_bytes);
    let history_lines = keyframe_history_lines(&params);

    // Validate + attach + publish the ring on the app loop.
    let open_response = dispatch_to_app_with_timeout(
        Request {
            id: request_id.clone(),
            method: Method::PaneStreamOpen(params),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );

    // The open request has been *sent* to the app queue. Even if we timed out
    // waiting for its reply, the app may still process it later and attach a
    // viewer/ring. So on EVERY exit path — including a failed or timed-out open —
    // dispatch a matching close. Both messages travel the same FIFO channel, so
    // a late open is always followed by this close and cannot leak an attach. On
    // a genuine synchronous failure (e.g. pane_not_found) no ring was created and
    // the close is a harmless no-op.
    let result = if api_response_outcome(&open_response) == "ok" {
        let mut writer = FrameWriter::new(stream, running);
        let result = serve_attached(
            &mut writer,
            &request_id,
            &pane_id,
            max_frame_bytes,
            history_lines,
            running,
            watch,
        );
        if let Err(err) = &result {
            writer.farewell(&request_id, err);
        }
        result
    } else {
        write_text_line_allow_disconnect(stream, &open_response)
    };
    dispatch_close(&pane_id, viewer_id, api_tx);
    result
}

fn serve_attached(
    writer: &mut FrameWriter<'_>,
    request_id: &str,
    pane_id: &str,
    max_frame_bytes: usize,
    history_lines: usize,
    running: &Arc<AtomicBool>,
    mut watch: Option<StreamWatch<'_>>,
) -> std::io::Result<()> {
    let Some(ring) = output_registry::lookup(pane_id) else {
        // The ring vanished between attach and lookup (pane closed). Report it
        // rather than silently hanging.
        return writer
            .write_json(&ErrorResponse {
                id: request_id.to_string(),
                error: ErrorBody {
                    code: "pane_not_found".into(),
                    message: format!("pane {pane_id} has no live output stream"),
                },
            })
            .map(drop);
    };

    let epoch = ring.epoch();
    let Some(seed) = ring.snapshot(history_lines) else {
        // The runtime is already gone; tell the client and close.
        return finish_exited(writer, &mut watch, 0, epoch);
    };

    // stream_started ack carries the geometry the client lacks today.
    if !emit_watched(
        writer,
        &mut watch,
        &SuccessResponse {
            id: request_id.to_string(),
            result: ResponseResult::StreamStarted {
                pane_id: pane_id.to_string(),
                epoch,
                cols: seed.cols,
                rows: seed.rows,
                base_seq: seed.cursor,
                resync: true,
            },
        },
    )? {
        return Ok(());
    }

    // reset seed: base64 full-screen ANSI at exactly `base_seq`, with the
    // requested scrollback captured in the same critical section.
    if !emit_watched(
        writer,
        &mut watch,
        &StreamFrameLine::reset(seed.cursor, epoch, &seed, false),
    )? {
        return Ok(());
    }

    let mut cursor = seed.cursor;
    let mut resize_id = seed.resize_id;

    let wait = if watch.is_some() {
        WATCH_POLL
    } else {
        PING_INTERVAL
    };
    let mut last_ping = std::time::Instant::now();
    loop {
        if !running.load(Ordering::Relaxed) {
            return Ok(());
        }
        match ring.wait_for_activity(cursor, resize_id, wait) {
            OutputWait::Closed => {
                return finish_exited(writer, &mut watch, cursor, epoch);
            }
            OutputWait::Idle => {
                // On the idle tick, reap a dead peer before heartbeating.
                if should_stop_connection(writer.stream, running)? {
                    return Ok(());
                }
                // An idle watched stream still closes promptly on pause or revoke.
                if let Some(line) = watch.as_mut().and_then(|watch| watch(false)) {
                    return writer.write_text(&line).map(drop);
                }
                if watch.is_none() || last_ping.elapsed() >= PING_INTERVAL {
                    last_ping = std::time::Instant::now();
                    if !emit_watched(writer, &mut watch, &StreamFrameLine::ping(cursor, epoch))? {
                        return Ok(());
                    }
                }
            }
            // A reader that fell behind under backpressure gets the current
            // screen instead of every byte it missed.
            OutputWait::Ready if skip_to_keyframe(writer.behind, ring.backlog(cursor)) => {
                let Some((next_cursor, next_resize_id)) =
                    resync(writer, &mut watch, &ring, history_lines, epoch, cursor)?
                else {
                    return Ok(());
                };
                cursor = next_cursor;
                resize_id = next_resize_id;
            }
            OutputWait::Ready => match ring.drain(cursor, resize_id, max_frame_bytes) {
                OutputDrain::Lagged => {
                    let Some((next_cursor, next_resize_id)) =
                        resync(writer, &mut watch, &ring, history_lines, epoch, cursor)?
                    else {
                        return Ok(());
                    };
                    cursor = next_cursor;
                    resize_id = next_resize_id;
                }
                OutputDrain::Resize {
                    cols,
                    rows,
                    resize_id: next_resize_id,
                } => {
                    if !emit_watched(
                        writer,
                        &mut watch,
                        &StreamFrameLine::resize(cursor, epoch, cols, rows),
                    )? {
                        return Ok(());
                    }
                    resize_id = next_resize_id;
                }
                OutputDrain::Data {
                    chunks,
                    cursor: next_cursor,
                } => {
                    // Concatenate the shared `Bytes` slices and base64-encode the
                    // frame OUTSIDE the ring lock (drain already released it), so
                    // the reader thread's `append` is never blocked behind framing.
                    let total: usize = chunks.iter().map(|chunk| chunk.len()).sum();
                    let mut payload = Vec::with_capacity(total);
                    for chunk in &chunks {
                        payload.extend_from_slice(chunk);
                    }
                    if !emit_watched(
                        writer,
                        &mut watch,
                        &StreamFrameLine::data(cursor, epoch, encode_bytes(&payload)),
                    )? {
                        return Ok(());
                    }
                    cursor = next_cursor;
                }
                OutputDrain::Idle => {}
            },
        }
    }
}

/// Snapshot-collapse resync: discard the backlog, re-seed one full-screen
/// keyframe (`lagged: true`), and jump the cursor to the live edge. It carries
/// history too: the bytes dropped from the backlog may have scrolled into it.
/// Returns the new cursor and resize id, or `None` once the stream is done.
fn resync(
    writer: &mut FrameWriter<'_>,
    watch: &mut Option<StreamWatch<'_>>,
    ring: &OutputRing,
    history_lines: usize,
    epoch: u64,
    cursor: u64,
) -> std::io::Result<Option<(u64, u64)>> {
    let Some(seed) = ring.snapshot(history_lines) else {
        finish_exited(writer, watch, cursor, epoch)?;
        return Ok(None);
    };
    if !emit_watched(
        writer,
        watch,
        &StreamFrameLine::reset(seed.cursor, epoch, &seed, true),
    )? {
        return Ok(None);
    }
    Ok(Some((seed.cursor, seed.resize_id)))
}

/// End the stream because the runtime ended. A watched stream reports it
/// through its watch instead of an `exited` frame.
fn finish_exited(
    writer: &mut FrameWriter<'_>,
    watch: &mut Option<StreamWatch<'_>>,
    cursor: u64,
    epoch: u64,
) -> std::io::Result<()> {
    if let Some(line) = watch.as_mut().and_then(|watch| watch(true)) {
        return writer.write_text(&line).map(drop);
    }
    writer
        .write_json(&StreamFrameLine::exited(cursor, epoch))
        .map(drop)
}

/// Write a frame after asking the watch whether the stream may still send.
/// Every frame is checked, so no output follows a pause or revoke; a refusal
/// writes the watch's line and reports `false` to stop. `false` also means
/// the client closed the stream.
fn emit_watched<T: serde::Serialize>(
    writer: &mut FrameWriter<'_>,
    watch: &mut Option<StreamWatch<'_>>,
    value: &T,
) -> std::io::Result<bool> {
    if let Some(line) = watch.as_mut().and_then(|watch| watch(false)) {
        writer.write_text(&line)?;
        return Ok(false);
    }
    writer.write_json(value)
}

fn dispatch_close(pane_id: &str, viewer_id: Option<String>, api_tx: &ApiRequestSender) {
    let _response = dispatch_to_app_with_timeout(
        Request {
            id: format!("pane.stream.close:{pane_id}"),
            method: Method::PaneStreamClose(PaneStreamParams {
                pane_id: pane_id.to_string(),
                include_history: true,
                resume_from: None,
                epoch: None,
                max_frame_bytes: None,
                scrollback_lines: None,
                // Threaded from the open so the close drops this viewer's lease.
                viewer_id,
            }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    use interprocess::local_socket::traits::{ListenerExt as _, Stream as _};

    use crate::ipc::LocalStream;

    /// A connected local socket pair: the server end as an [`ApiStream`] with
    /// the API server's 5 s write timeout, and the client end.
    fn socket_pair(name: &str) -> (ApiStream, LocalStream) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "hps-{name}-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let client = crate::ipc::connect_local_stream(&path).unwrap();
        let server = listener.incoming().next().unwrap().unwrap();
        let _ = std::fs::remove_file(&path);
        let mut server = ApiStream::Local(server);
        server
            .set_send_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (server, client)
    }

    /// Answers the stream's open and close on the "app loop".
    fn app_loop() -> (ApiRequestSender, std::thread::JoinHandle<()>) {
        let (api_tx, mut api_rx) = tokio::sync::mpsc::unbounded_channel::<
            crate::api::ApiRequestMessage,
        >();
        let app = std::thread::spawn(move || {
            while let Some(message) = api_rx.blocking_recv() {
                let close = matches!(message.request.method, Method::PaneStreamClose(_));
                let reply = serde_json::to_string(&SuccessResponse {
                    id: message.request.id.clone(),
                    result: ResponseResult::Ok {},
                })
                .unwrap();
                let _ = message.respond_to.send(reply);
                if close {
                    return;
                }
            }
        });
        (api_tx, app)
    }

    fn stream_params(pane_id: &str) -> PaneStreamParams {
        serde_json::from_value(serde_json::json!({"pane_id": pane_id})).unwrap()
    }

    fn read_frame(reader: &mut BufReader<LocalStream>) -> Option<serde_json::Value> {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(serde_json::from_str(&line).expect("a whole JSON line")),
        }
    }

    /// A burst the reader cannot keep up with (the measured 3G case): the
    /// reader stops reading for longer than the API server's 5 s write
    /// timeout. The stream used to end there without a word; now it waits,
    /// skips the backlog with a fresh keyframe, and keeps streaming.
    #[test]
    fn a_reader_that_stalls_past_the_write_timeout_gets_a_keyframe_not_a_dead_stream() {
        let tokio = tokio::runtime::Runtime::new().unwrap();
        let _enter = tokio.enter();
        let runtime = crate::terminal::TerminalRuntime::test_with_screen_bytes(80, 24, b"hello");
        let ring = runtime.attach_output_stream(crate::pane::OUTPUT_RING_CAPACITY_BYTES);
        let pane_id = format!("stall-{}", std::process::id());
        output_registry::register(&pane_id, &ring);
        let (mut server, client) = socket_pair("stall");
        let (api_tx, app) = app_loop();
        let running = Arc::new(AtomicBool::new(true));

        let serve = {
            let pane_id = pane_id.clone();
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                serve_watched(
                    &mut server,
                    "s".into(),
                    stream_params(&pane_id),
                    &api_tx,
                    &running,
                    None,
                )
            })
        };
        client
            .set_recv_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut reader = BufReader::new(client);
        assert_eq!(read_frame(&mut reader).unwrap()["result"]["type"], "stream_started");
        assert_eq!(read_frame(&mut reader).unwrap()["frame"], "reset");

        // 960 KiB of output (about 1.3 MB as base64 frames), more than the
        // socket buffers hold, while nobody reads for longer than the 5 s
        // write timeout.
        for _ in 0..15 {
            ring.append(&[b'x'; 64 * 1024]);
        }
        std::thread::sleep(Duration::from_secs(7));

        let mut skipped = 0;
        loop {
            let frame = read_frame(&mut reader).expect("the stream ended under backpressure");
            assert!(frame.get("error").is_none(), "{frame}");
            if frame["frame"] == "reset" {
                assert_eq!(frame["lagged"], true);
                break;
            }
            assert_eq!(frame["frame"], "data", "{frame}");
            skipped += 1;
            assert!(skipped < 15, "the backlog was replayed instead of skipped");
        }

        // The stream is alive after the keyframe: new output arrives.
        ring.append(b"live tail");
        let frame = read_frame(&mut reader).expect("the stream ended after the keyframe");
        assert_eq!(frame["frame"], "data", "{frame}");
        let data = base64::engine::general_purpose::STANDARD
            .decode(frame["data_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data, b"live tail");

        running.store(false, Ordering::Relaxed);
        ring.mark_closed();
        drop(reader);
        serve.join().unwrap().unwrap();
        app.join().unwrap();
        output_registry::unregister(&pane_id);
    }

    /// A reader that reads nothing at all ends the stream after the stall
    /// limit, and a reader that comes back finds the cut line finished and an
    /// error line saying why, not a silent close.
    #[test]
    fn a_stalled_stream_ends_with_an_error_line() {
        let (mut server, client) = socket_pair("farewell");
        let running = AtomicBool::new(true);
        let mut writer = FrameWriter::new(&mut server, &running);
        writer.stall_limit = Duration::from_secs(1);
        let frame = StreamFrameLine::data(1, 2, "A".repeat(256 * 1024));

        let err = loop {
            match writer.write_json(&frame) {
                Ok(true) => {}
                Ok(false) => panic!("the client is still connected"),
                Err(err) => break err,
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut client = client;
            let _ = client.read_to_end(&mut bytes);
            bytes
        });
        writer.farewell("s", &err);
        drop(writer);
        drop(server);
        let bytes = reader.join().unwrap();
        let lines: Vec<serde_json::Value> = bytes
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("every line whole"))
            .collect();
        let last = lines.last().unwrap();
        assert_eq!(last["id"], "s");
        assert_eq!(last["error"]["code"], "stream_stalled");
        assert!(lines[..lines.len() - 1]
            .iter()
            .all(|line| line["frame"] == "data"));
    }

    #[test]
    fn only_a_reader_behind_by_more_than_a_keyframe_skips_ahead() {
        assert!(!skip_to_keyframe(false, 10 * RESYNC_BACKLOG_BYTES));
        assert!(!skip_to_keyframe(true, RESYNC_BACKLOG_BYTES));
        assert!(skip_to_keyframe(true, RESYNC_BACKLOG_BYTES + 1));
    }

    fn seed(history: Option<&str>) -> OutputSnapshot {
        OutputSnapshot {
            ansi: "seed".into(),
            history: history.map(str::to_string),
            history_cursor: None,
            cursor: 918_273,
            resize_id: 0,
            cols: 80,
            rows: 24,
        }
    }

    #[test]
    fn reset_frame_shape_includes_geometry_and_omits_lagged_when_false() {
        let frame = StreamFrameLine::reset(918_273, 7, &seed(None), false);
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["stream"], "pane.bytes");
        assert_eq!(value["frame"], "reset");
        assert_eq!(value["seq"], 918_273);
        assert_eq!(value["epoch"], 7);
        assert_eq!(value["cols"], 80);
        assert_eq!(value["rows"], 24);
        assert_eq!(value["data_b64"], "c2VlZA==");
        assert!(value.get("lagged").is_none());
        // No history requested: the frame is byte-for-byte what old clients parse.
        assert!(value.get("history_b64").is_none());
        assert!(value.get("history_cursor").is_none());
    }

    #[test]
    fn reset_frame_carries_requested_history_even_when_empty() {
        let value =
            serde_json::to_value(StreamFrameLine::reset(1, 7, &seed(Some("old")), false)).unwrap();
        assert_eq!(value["history_b64"], "b2xk");
        let value =
            serde_json::to_value(StreamFrameLine::reset(1, 7, &seed(Some("")), false)).unwrap();
        assert_eq!(
            value["history_b64"], "",
            "asked-for-but-empty must stay distinguishable from not-sent"
        );
    }

    #[test]
    fn reset_frame_carries_history_cursor_only_when_older_rows_exist() {
        let value =
            serde_json::to_value(StreamFrameLine::reset(1, 7, &seed(Some("old")), false)).unwrap();
        assert!(
            value.get("history_cursor").is_none(),
            "history reaching the start of scrollback offers no paging"
        );

        let mut paged = seed(Some("old"));
        paged.history_cursor = Some("tok".into());
        let value = serde_json::to_value(StreamFrameLine::reset(1, 7, &paged, false)).unwrap();
        assert_eq!(value["history_b64"], "b2xk");
        assert_eq!(value["history_cursor"], "tok");
    }

    #[test]
    fn keyframe_history_lines_follow_the_request_and_are_bounded() {
        let params = |include_history, scrollback_lines| PaneStreamParams {
            pane_id: "p".into(),
            include_history,
            resume_from: None,
            epoch: None,
            max_frame_bytes: None,
            scrollback_lines,
            viewer_id: None,
        };
        assert_eq!(keyframe_history_lines(&params(true, None)), 0);
        assert_eq!(keyframe_history_lines(&params(true, Some(400))), 400);
        assert_eq!(
            keyframe_history_lines(&params(true, Some(50_000))),
            MAX_KEYFRAME_HISTORY_LINES
        );
        assert_eq!(keyframe_history_lines(&params(false, Some(400))), 0);
    }

    #[test]
    fn lagged_reset_sets_flag() {
        let frame = StreamFrameLine::reset(1, 7, &seed(None), true);
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["lagged"], true);
    }

    #[test]
    fn data_frame_carries_only_payload() {
        let frame = StreamFrameLine::data(42, 7, encode_bytes(b"hi"));
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["frame"], "data");
        assert_eq!(value["seq"], 42);
        assert_eq!(value["data_b64"], "aGk=");
        assert!(value.get("cols").is_none());
        assert!(value.get("rows").is_none());
    }

    #[test]
    fn resize_and_control_frames_shape() {
        let resize = serde_json::to_value(StreamFrameLine::resize(5, 7, 100, 30)).unwrap();
        assert_eq!(resize["frame"], "resize");
        assert_eq!(resize["cols"], 100);
        assert_eq!(resize["rows"], 30);
        assert!(resize.get("data_b64").is_none());

        let ping = serde_json::to_value(StreamFrameLine::ping(9, 7)).unwrap();
        assert_eq!(ping["frame"], "ping");
        assert!(ping.get("data_b64").is_none());

        let exited = serde_json::to_value(StreamFrameLine::exited(9, 7)).unwrap();
        assert_eq!(exited["frame"], "exited");
    }
}
