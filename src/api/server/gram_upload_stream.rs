//! Streaming file upload for gram attachments (`gram.upload.stream`).
//!
//! `gram.upload_chunk` costs one API connection per chunk, and over the app's SSH
//! transport one `herdr api-bridge` process spawn per chunk — a 100 MB file is
//! ~2100 of them, which is what makes a large attachment slow. That path is
//! round-trip bound, not bandwidth bound.
//!
//! This method opens ONE connection, acks it, then reads newline-delimited chunk
//! frames on that same connection until EOF, acking each one. Every frame lands
//! through the same [`crate::persist::gram_files::append_chunk`] under the same
//! `upload_id`, and the file is still attached by passing that `upload_id` in a
//! later `gram.send`/`gram.post` — so staging, finalize, hashing and the caps are
//! untouched, and a client that cannot use this method keeps working per-chunk.
//!
//! Why the appends run here rather than on the app loop: `gram_files` is pure
//! filesystem (no `App` state, no channel), and the ONLY app-owned state the
//! per-chunk handler consults is `no_session`. So the open handshake asks the app
//! that one question and every frame after it is served on this thread — the app
//! loop never sees the bytes.
//!
//! Line-framing reads come from [`super::stream_read`], shared with
//! `pane_input_stream` and `pane_graphics_stream`; only this channel's byte cap
//! and deadlines are set here.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine as _;

use crate::api::schema::{
    ErrorBody, ErrorResponse, GramUploadStreamParams, Method, Request, ResponseResult,
    SuccessResponse,
};
use crate::api::{ApiRequestSender, ApiStream};
use crate::ipc::is_connection_closed_error;

use super::stream_read::{stream_is_running, LineReader};
use super::{
    api_response_outcome, dispatch_stream_open, write_json_line, write_json_line_allow_disconnect,
    write_text_line_allow_disconnect, APP_RESPONSE_TIMEOUT,
};

/// One frame's max wire size. A 512 KiB raw chunk (the daemon's
/// [`crate::persist::gram_files::MAX_CHUNK_BYTES`]) is ~700 KB of base64 plus a
/// small envelope, so this leaves headroom while staying at the daemon's own
/// request-line ceiling.
const MAX_UPLOAD_FRAME_BYTES: usize = 1024 * 1024;
/// Gap between bytes of one frame. Generous versus the input stream's 5s: an
/// upload frame is ~700 KB, not a keystroke.
const UPLOAD_FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// Total budget for one frame — 1 MiB at ~100 kbit/s is ~84s, so the input
/// stream's 30s would fail a legitimate upload on a weak link.
const UPLOAD_FRAME_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Upload ids with a live streaming channel. `append_chunk` is read-then-write
/// with no lock, and the app loop no longer serializes chunks, so two writers on
/// one `upload_id` could interleave. The offset rule makes that LOUD rather than
/// silent, but a second writer is always a client bug — refuse it. Consulted by
/// BOTH writers: a second stream is refused at open here, and a concurrent
/// per-chunk `gram.upload_chunk` is refused by the app handler through
/// [`upload_is_streaming`] (an `offset: 0` chunk would otherwise TRUNCATE bytes
/// this channel has already acked).
static STREAMING_UPLOADS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Whether a streaming channel currently owns this `upload_id`.
pub(super) fn upload_is_streaming(upload_id: &str) -> bool {
    STREAMING_UPLOADS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(upload_id)
}

/// Holds the single-writer claim on one `upload_id` for the channel's lifetime.
/// `Drop` releases it, so every exit path — EOF, frame error, timeout, server
/// shutdown, a write failure to a vanished peer — frees the id.
struct UploadClaim {
    upload_id: String,
}

impl UploadClaim {
    /// `None` when another channel already holds this `upload_id`.
    fn acquire(upload_id: &str) -> Option<Self> {
        let mut live = STREAMING_UPLOADS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !live.insert(upload_id.to_string()) {
            return None;
        }
        Some(Self {
            upload_id: upload_id.to_string(),
        })
    }
}

impl Drop for UploadClaim {
    fn drop(&mut self) {
        STREAMING_UPLOADS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.upload_id);
    }
}

/// One inbound chunk frame. Unlike an input frame there is no `ack` field: every
/// upload frame is acked, because an upload has no echo channel to confirm it and
/// the ack is the client's only backpressure and error signal.
#[derive(serde::Deserialize)]
struct UploadFrame {
    seq: u64,
    offset: u64,
    data_base64: String,
}

#[derive(serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct UploadAck {
    seq: u64,
    ok: bool,
}

#[derive(serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct UploadFrameError {
    seq: u64,
    error: ErrorBody,
}

pub(super) fn serve(
    stream: ApiStream,
    request_id: String,
    params: GramUploadStreamParams,
    api_tx: &ApiRequestSender,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    serve_with_open_timeout(
        stream,
        request_id,
        params,
        api_tx,
        running,
        APP_RESPONSE_TIMEOUT,
    )
}

fn serve_with_open_timeout(
    mut stream: ApiStream,
    request_id: String,
    params: GramUploadStreamParams,
    api_tx: &ApiRequestSender,
    running: &Arc<AtomicBool>,
    open_timeout: Duration,
) -> std::io::Result<()> {
    let upload_id = params.upload_id.clone();
    let stream_active = Arc::new(AtomicBool::new(true));

    // Refuse a duplicate BEFORE the app is asked and before the ack: two
    // concurrent appenders on one upload_id cannot produce a consistent file.
    let Some(_claim) = UploadClaim::acquire(&upload_id) else {
        stream_active.store(false, Ordering::Release);
        return write_json_line_allow_disconnect(
            &mut stream,
            &ErrorResponse {
                id: request_id,
                error: ErrorBody {
                    code: "upload_in_progress".into(),
                    message: "another stream is already uploading this upload_id".into(),
                },
            },
        );
    };

    // Open handshake: the app answers whether gram is available at all
    // (`no_session`) before the connection is upgraded into a frame loop.
    let open_response = dispatch_stream_open(
        Request {
            id: request_id.clone(),
            method: Method::GramUploadStreamOpen(params),
        },
        api_tx,
        open_timeout,
        Arc::clone(&stream_active),
    );
    if api_response_outcome(&open_response) != "ok" {
        stream_active.store(false, Ordering::Release);
        return write_text_line_allow_disconnect(&mut stream, &open_response);
    }

    if let Err(err) = write_json_line(
        &mut stream,
        &SuccessResponse {
            id: request_id.clone(),
            result: ResponseResult::Ok {},
        },
    ) {
        stream_active.store(false, Ordering::Release);
        if is_connection_closed_error(&err) {
            return Ok(());
        }
        return Err(err);
    }

    let result = serve_frames(
        &mut stream,
        &request_id,
        &upload_id,
        running,
        &stream_active,
    );
    stream_active.store(false, Ordering::Release);
    result
}

fn serve_frames(
    stream: &mut ApiStream,
    request_id: &str,
    upload_id: &str,
    running: &Arc<AtomicBool>,
    stream_active: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut last_seq: Option<u64> = None;
    // One reader for the channel: it holds the tail of a partially received
    // frame between calls, and buffers so a 700 KB base64 frame is a handful of
    // reads rather than one syscall per byte.
    let mut reader = LineReader::new();
    while stream_is_running(running, stream_active) {
        let Some(line) = reader.read_line(
            stream,
            running,
            stream_active,
            MAX_UPLOAD_FRAME_BYTES,
            UPLOAD_FRAME_IDLE_TIMEOUT,
            UPLOAD_FRAME_TOTAL_TIMEOUT,
            "upload frame",
        )?
        else {
            // EOF is the clean end of an upload: the client has sent every chunk
            // and closed. The staged file is attached by a later `gram.post`
            // carrying this `upload_id`, so there is no close-side bookkeeping.
            return Ok(());
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let frame = match serde_json::from_str::<UploadFrame>(line) {
            Ok(frame) => frame,
            Err(err) => {
                write_json_line_allow_disconnect(
                    stream,
                    &ErrorResponse {
                        id: request_id.to_string(),
                        error: ErrorBody {
                            code: "invalid_frame".into(),
                            message: format!("invalid upload frame: {err}"),
                        },
                    },
                )?;
                return Ok(());
            }
        };

        // Strictly increasing seq is a cheap ordering tripwire; the offset rule
        // in `append_chunk` is the real integrity check, but a repeat or a
        // decrease means a client bug and is worth failing loudly.
        if last_seq.is_some_and(|prev| frame.seq <= prev) {
            write_json_line_allow_disconnect(
                stream,
                &UploadFrameError {
                    seq: frame.seq,
                    error: ErrorBody {
                        code: "invalid_sequence".into(),
                        message: "seq must be strictly increasing".into(),
                    },
                },
            )?;
            return Ok(());
        }
        last_seq = Some(frame.seq);

        let seq = frame.seq;
        let Ok(bytes) =
            base64::engine::general_purpose::STANDARD.decode(frame.data_base64.as_bytes())
        else {
            return frame_error(
                stream,
                seq,
                "invalid_params",
                "data_base64 is not valid base64",
            );
        };

        // A rejected chunk closes the channel on purpose: staging is append-only,
        // so once a chunk is refused the stream can no longer be consistent. The
        // client restarts at offset 0 or falls back to per-chunk uploads. The
        // error codes match `gram.upload_chunk`, so no client mapping changes.
        match crate::persist::gram_files::append_chunk(upload_id, frame.offset, &bytes) {
            Ok(()) => {
                write_json_line_allow_disconnect(stream, &UploadAck { seq, ok: true })?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                return frame_error(stream, seq, "invalid_params", &err.to_string());
            }
            Err(err) => {
                return frame_error(stream, seq, "gram_file_error", &err.to_string());
            }
        }
    }

    Ok(())
}

fn frame_error(stream: &mut ApiStream, seq: u64, code: &str, message: &str) -> std::io::Result<()> {
    write_json_line_allow_disconnect(
        stream,
        &UploadFrameError {
            seq,
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiRequestMessage;
    #[cfg(unix)]
    use crate::api::EventHub;
    use crate::ipc::LocalStream;
    use interprocess::local_socket::traits::Listener as _;
    use std::io::{BufRead, BufReader, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::mpsc;

    static NEXT_LOCAL_STREAM_ID: AtomicU64 = AtomicU64::new(1);

    fn local_stream_pair() -> (LocalStream, LocalStream, PathBuf) {
        let unique = format!(
            "hgu-{}-{}.sock",
            std::process::id(),
            NEXT_LOCAL_STREAM_ID.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let client = crate::ipc::connect_local_stream(&path).unwrap();
        let server = listener.accept().unwrap();
        (client, server, path)
    }

    /// Point `config_dir()` (and so gram staging) at a per-test directory, under
    /// the repo's config-env lock so a sibling test cannot observe the swap, and
    /// restore the previous value on drop.
    struct ConfigDirGuard {
        dir: PathBuf,
        previous: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for ConfigDirGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn isolate_config_dir(tag: &str) -> ConfigDirGuard {
        let lock = crate::config::test_config_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "hgu-cfg-{}-{}-{tag}",
            std::process::id(),
            NEXT_LOCAL_STREAM_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        ConfigDirGuard {
            dir,
            previous,
            _lock: lock,
        }
    }

    fn staging_path(upload_id: &str) -> PathBuf {
        crate::config::config_dir()
            .join("gram-files")
            .join(".staging")
            .join(upload_id)
    }

    fn staged_bytes(upload_id: &str) -> Vec<u8> {
        std::fs::read(staging_path(upload_id)).unwrap()
    }

    fn read_response_line(stream: &mut LocalStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line
    }

    fn write_line(stream: &mut LocalStream, line: &str) {
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    fn respond_ok(message: ApiRequestMessage) {
        let response = serde_json::to_string(&SuccessResponse {
            id: message.request.id,
            result: ResponseResult::Ok {},
        })
        .unwrap();
        message.respond_to.send(response).unwrap();
    }

    fn respond_error(message: ApiRequestMessage, code: &str, msg: &str) {
        let response = serde_json::to_string(&ErrorResponse {
            id: message.request.id,
            error: ErrorBody {
                code: code.into(),
                message: msg.into(),
            },
        })
        .unwrap();
        message.respond_to.send(response).unwrap();
    }

    fn frame(seq: u64, offset: u64, bytes: &[u8]) -> String {
        let data = base64::engine::general_purpose::STANDARD.encode(bytes);
        format!(r#"{{"seq":{seq},"offset":{offset},"data_base64":"{data}"}}"#)
    }

    /// The threaded form is mandatory: `handle_connection` holds the connection
    /// open for the channel's lifetime, so calling it inline would deadlock.
    #[cfg(unix)]
    fn spawn_server(
        server: LocalStream,
        api_tx: crate::api::ApiRequestSender,
        running: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<std::io::Result<()>> {
        let event_hub = EventHub::default();
        std::thread::spawn(move || {
            super::super::handle_connection(server, &api_tx, &event_hub, &running, None)
        })
    }

    #[cfg(unix)]
    fn open_ok(
        client: &mut LocalStream,
        api_rx: &mut mpsc::UnboundedReceiver<ApiRequestMessage>,
        upload_id: &str,
    ) {
        write_line(
            client,
            &format!(
                r#"{{"id":"up_1","method":"gram.upload.stream","params":{{"upload_id":"{upload_id}"}}}}"#
            ),
        );

        let open = api_rx.blocking_recv().unwrap();
        match &open.request.method {
            Method::GramUploadStreamOpen(params) => assert_eq!(params.upload_id, upload_id),
            other => panic!("unexpected open request: {other:?}"),
        }
        respond_ok(open);

        let ack: SuccessResponse = serde_json::from_str(&read_response_line(client)).unwrap();
        assert_eq!(ack.id, "up_1");
        assert_eq!(ack.result, ResponseResult::Ok {});
    }

    #[cfg(unix)]
    #[test]
    fn streams_two_frames_and_assembles_the_file() {
        let _config = isolate_config_dir("assemble");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-stream-1");

        // Two frames, ONE connection: the app thread answered only the open
        // handshake above and is never asked again, which is the whole point.
        write_line(&mut client, &frame(1, 0, b"hello "));
        let ack1: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!((ack1.seq, ack1.ok), (1, true));

        write_line(&mut client, &frame(2, 6, b"world"));
        let ack2: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!((ack2.seq, ack2.ok), (2, true));

        // EOF ends the upload cleanly.
        drop(client);
        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());

        assert_eq!(staged_bytes("up-stream-1"), b"hello world");
        assert!(api_rx.try_recv().is_err(), "no frame reached the app loop");
    }

    /// Frames PIPELINED into one write: nothing in the protocol makes a client wait
    /// for ack N before writing frame N+1, so one `read` can carry several frames.
    /// This is the property the buffered reader exists for — it must keep the
    /// over-read remainder, not discard it. Without that, frames after the first in
    /// a read are silently dropped: no ack, no error, and the client blocks forever
    /// (measured: this test hangs under that mutation and passes in ~10ms without).
    #[cfg(unix)]
    #[test]
    fn assembles_frames_pipelined_into_one_write() {
        let _config = isolate_config_dir("pipelined");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-pipelined");

        // Three frames, ONE write_all, no waiting for acks in between.
        let batch = format!(
            "{}\n{}\n{}\n",
            frame(1, 0, b"one "),
            frame(2, 4, b"two "),
            frame(3, 8, b"three")
        );
        client.write_all(batch.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(&mut client);
        for expected in 1..=3_u64 {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let ack: UploadAck = serde_json::from_str(&line).unwrap();
            assert_eq!(
                (ack.seq, ack.ok),
                (expected, true),
                "missing ack {expected}"
            );
        }

        drop(client);
        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());

        assert_eq!(staged_bytes("up-pipelined"), b"one two three");
        assert!(api_rx.try_recv().is_err(), "no frame reached the app loop");
    }

    /// The frame cap is INCLUSIVE, matching the byte-at-a-time reader the other
    /// streams use: a line of exactly `MAX_UPLOAD_FRAME_BYTES` (plus its newline) is
    /// served, one byte more is refused. Worth pinning in the ACCEPT direction — a
    /// cap that counts the terminator is silently one byte tighter than the reference,
    /// and an over-cap line closes the channel with no protocol error line, which is
    /// indistinguishable from a dropped connection.
    ///
    /// The length is padded with an ignored field rather than payload: 1 MiB of base64
    /// would decode past `MAX_CHUNK_BYTES` and be refused for a different reason.
    #[cfg(unix)]
    #[test]
    fn accepts_a_frame_at_the_cap_and_refuses_one_byte_more() {
        let _config = isolate_config_dir("framecap");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-framecap");

        // Pad the frame to an exact wire length with a field the daemon ignores.
        let padded = |seq: u64, offset: u64, total: usize| {
            let head = format!(
                r#"{{"seq":{seq},"offset":{offset},"data_base64":"{}","pad":""#,
                base64::engine::general_purpose::STANDARD.encode(b"hi")
            );
            let tail = r#""}"#;
            let pad = total - head.len() - tail.len();
            format!("{head}{}{tail}", "x".repeat(pad))
        };

        write_line(&mut client, &padded(1, 0, MAX_UPLOAD_FRAME_BYTES));
        let ack: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(
            (ack.seq, ack.ok),
            (1, true),
            "a frame AT the cap must be served"
        );

        // One byte past the cap: the read fails, so the channel closes without a
        // protocol line rather than acking.
        write_line(&mut client, &padded(2, 2, MAX_UPLOAD_FRAME_BYTES + 1));
        let mut reader = BufReader::new(&mut client);
        let mut trailing = String::new();
        reader.read_line(&mut trailing).unwrap();
        assert!(
            trailing.is_empty(),
            "an over-cap frame was served: {trailing}"
        );

        running.store(false, Ordering::Relaxed);
        // The over-cap read is an `InvalidData` error, propagated by `serve_frames`,
        // so the connection ends in Err rather than the clean EOF an upload gets.
        let outcome = server_thread.join().unwrap();
        let err = outcome.expect_err("an over-cap frame must fail the connection");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("upload frame is too large"),
            "got: {err}"
        );

        // Only the in-cap frame's payload landed.
        assert_eq!(staged_bytes("up-framecap"), b"hi");
    }

    /// The round-trip claim, measured: 8 MiB uploads as 16 frames of 512 KiB over
    /// a SINGLE `handle_connection` call. A per-chunk implementation cannot
    /// satisfy this — each chunk would need its own connection and its own app
    /// dispatch, and both are asserted absent here.
    #[cfg(unix)]
    #[test]
    fn uploads_eight_mib_over_one_connection_with_no_app_dispatch_per_frame() {
        let _config = isolate_config_dir("roundtrips");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-8mib");

        let chunk = vec![0xAB_u8; crate::persist::gram_files::MAX_CHUNK_BYTES];
        let frames = (8 * 1024 * 1024) / chunk.len();
        let mut offset = 0_u64;
        for seq in 1..=frames {
            write_line(&mut client, &frame(seq as u64, offset, &chunk));
            let ack: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
            assert_eq!((ack.seq, ack.ok), (seq as u64, true));
            offset += chunk.len() as u64;
        }
        assert_eq!(frames, 16);

        drop(client);
        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());

        assert_eq!(staged_bytes("up-8mib").len(), 8 * 1024 * 1024);
        assert!(
            api_rx.try_recv().is_err(),
            "the app loop served only the open handshake, never a frame"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_offset_mismatch_with_invalid_params_and_closes() {
        let _config = isolate_config_dir("offset");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-offset");

        // Offset 99 on a fresh upload: append-only staging refuses it.
        write_line(&mut client, &frame(1, 99, b"nope"));
        let err: UploadFrameError = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(err.seq, 1);
        assert_eq!(err.error.code, "invalid_params");

        // The channel is closed, not merely error-reporting: the server thread
        // returned, and the client's next read is EOF rather than another ack.
        assert!(server_thread.join().unwrap().is_ok());
        let mut reader = BufReader::new(&mut client);
        let mut trailing = String::new();
        reader.read_line(&mut trailing).unwrap();
        assert!(trailing.is_empty(), "channel stayed open: {trailing}");

        // Nothing was staged: the rejected chunk never reached the file.
        assert!(!staging_path("up-offset").exists());

        running.store(false, Ordering::Relaxed);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_increasing_seq_and_closes() {
        let _config = isolate_config_dir("seq");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-seq");

        write_line(&mut client, &frame(5, 0, b"a"));
        let ack: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(ack.seq, 5);

        write_line(&mut client, &frame(5, 1, b"b"));
        let err: UploadFrameError = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(err.seq, 5);
        assert_eq!(err.error.code, "invalid_sequence");

        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_malformed_frame_and_closes() {
        let _config = isolate_config_dir("malformed");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-malformed");

        write_line(&mut client, r#"{"seq":1,"offset":0}"#);
        let err: ErrorResponse = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(err.id, "up_1");
        assert_eq!(err.error.code, "invalid_frame");

        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_base64_payload_with_invalid_params() {
        let _config = isolate_config_dir("base64");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-base64");

        write_line(
            &mut client,
            r#"{"seq":1,"offset":0,"data_base64":"not!base64"}"#,
        );
        let err: UploadFrameError = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(err.seq, 1);
        assert_eq!(err.error.code, "invalid_params");
        assert_eq!(err.error.message, "data_base64 is not valid base64");

        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_second_stream_for_the_same_upload_id() {
        let _config = isolate_config_dir("dupe");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut first, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let first_thread = spawn_server(server, api_tx.clone(), Arc::clone(&running));

        open_ok(&mut first, &mut api_rx, "up-dupe");

        // Second channel, same upload_id: refused BEFORE any ack, and the app is
        // never asked (a duplicate is a client bug, not an app-state question).
        let (mut second, server2, _path2) = local_stream_pair();
        let second_thread = spawn_server(server2, api_tx.clone(), Arc::clone(&running));
        write_line(
            &mut second,
            r#"{"id":"up_2","method":"gram.upload.stream","params":{"upload_id":"up-dupe"}}"#,
        );
        let err: ErrorResponse = serde_json::from_str(&read_response_line(&mut second)).unwrap();
        assert_eq!(err.id, "up_2");
        assert_eq!(err.error.code, "upload_in_progress");
        assert!(api_rx.try_recv().is_err());
        assert!(second_thread.join().unwrap().is_ok());

        // The first channel still owns the id and keeps working.
        write_line(&mut first, &frame(1, 0, b"ok"));
        let ack: UploadAck = serde_json::from_str(&read_response_line(&mut first)).unwrap();
        assert!(ack.ok);

        // Once it closes the claim is dropped, so the id can be claimed again —
        // otherwise a dropped connection would wedge that upload_id forever.
        drop(first);
        assert!(first_thread.join().unwrap().is_ok());
        let (mut third, server3, _path3) = local_stream_pair();
        let third_thread = spawn_server(server3, api_tx, Arc::clone(&running));
        open_ok(&mut third, &mut api_rx, "up-dupe");

        drop(third);
        running.store(false, Ordering::Relaxed);
        assert!(third_thread.join().unwrap().is_ok());
    }

    /// A concurrent per-chunk `gram.upload_chunk` on a STREAMING upload_id is
    /// refused by the real app handler, through the real request dispatch — an
    /// `offset: 0` chunk truncates the staging file, which would discard bytes this
    /// channel already acked. A different upload_id is unaffected, so the guard
    /// cannot be a blanket refusal.
    #[cfg(unix)]
    #[test]
    fn refuses_a_per_chunk_write_while_a_stream_owns_the_upload_id() {
        let _config = isolate_config_dir("mixedwriters");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-mixed");
        write_line(&mut client, &frame(1, 0, b"streamed"));
        let ack: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert!(ack.ok);

        // A REAL app, answering a REAL `gram.upload_chunk` request through the
        // production dispatch — not the claim predicate in isolation.
        let (_unused_tx, app_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            false,
            None,
            app_rx,
            crate::api::EventHub::default(),
        );
        let chunk_request = |upload_id: &str| crate::api::schema::Request {
            id: "chunk".into(),
            method: Method::GramUploadChunk(crate::api::schema::GramUploadChunkParams {
                upload_id: upload_id.to_string(),
                offset: 0,
                data_base64: base64::engine::general_purpose::STANDARD.encode(b"clobber"),
            }),
        };

        let refused: serde_json::Value =
            serde_json::from_str(&app.handle_api_request(chunk_request("up-mixed"))).unwrap();
        assert_eq!(refused["error"]["code"], "upload_in_progress");

        // An unrelated upload_id still uploads per-chunk.
        let allowed: serde_json::Value =
            serde_json::from_str(&app.handle_api_request(chunk_request("up-unrelated"))).unwrap();
        assert_eq!(allowed["result"]["type"], "ok");

        // The streamed bytes survived the attempted clobber.
        drop(client);
        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());
        assert_eq!(staged_bytes("up-mixed"), b"streamed");
    }

    /// `gram.post` FINALIZES a staging file — reads its size, hashes it, renames it —
    /// and is the other writer that appends are no longer serialized against. While a
    /// stream owns the upload it must be refused: a frame landing mid-sequence would
    /// record a sha256 taken over more bytes than the recorded size, and a frame
    /// after the rename would land inside the finalized message file. Both are silent
    /// corruption of the integrity fields a client verifies a download against.
    #[cfg(unix)]
    #[test]
    fn refuses_to_finalize_an_upload_a_stream_still_owns() {
        let _config = isolate_config_dir("finalize");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-finalize");
        write_line(&mut client, &frame(1, 0, b"half"));
        let ack: UploadAck = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert!(ack.ok);

        let (_unused_tx, app_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let mut app = crate::app::App::new(
            &crate::config::Config::default(),
            false,
            None,
            app_rx,
            crate::api::EventHub::default(),
        );
        let post = |upload_id: &str| crate::api::schema::Request {
            id: "post".into(),
            method: Method::GramPost(crate::api::schema::GramPostParams {
                text: String::new(),
                to: None,
                file: Some(crate::api::schema::GramFileUpload {
                    upload_id: upload_id.to_string(),
                    name: "half.bin".into(),
                    mime: "application/octet-stream".into(),
                }),
            }),
        };

        let refused: serde_json::Value =
            serde_json::from_str(&app.handle_api_request(post("up-finalize"))).unwrap();
        assert_eq!(refused["error"]["code"], "upload_in_progress");
        // Refused BEFORE finalize ran: the staging file is untouched, so the upload
        // can still be completed and attached once the channel closes.
        assert_eq!(staged_bytes("up-finalize"), b"half");

        drop(client);
        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());

        // With the claim released, the same post succeeds and consumes staging.
        let posted: serde_json::Value =
            serde_json::from_str(&app.handle_api_request(post("up-finalize"))).unwrap();
        assert_eq!(posted["result"]["message"]["file"]["size"], 4);
        assert!(!staging_path("up-finalize").exists());
    }

    /// A client that writes bytes and NEVER a newline is the only thing that can grow
    /// the reader's buffer without bound: `take_line` never returns, so nothing
    /// consumes `pending`. The unterminated cap is that bound, and it is the one
    /// check the terminated-frame test above cannot reach.
    #[cfg(unix)]
    #[test]
    fn refuses_an_unterminated_frame_past_the_cap() {
        let _config = isolate_config_dir("unterminated");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        open_ok(&mut client, &mut api_rx, "up-unterminated");

        // No newline, ever. The write may fail partway once the server closes, which
        // is itself the pass condition, so a broken pipe here is not a test failure.
        let blob = vec![b'x'; MAX_UPLOAD_FRAME_BYTES + 4096];
        let _ = client.write_all(&blob);
        let _ = client.flush();

        // NOT stopping `running` first: a stop makes the reader return a clean
        // `Ok(None)`, which would mask the cap and let this test pass against a
        // daemon with no bound at all. The connection must fail on its own.
        let err = server_thread
            .join()
            .unwrap()
            .expect_err("an unterminated over-cap frame must fail the connection");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("upload frame is too large"),
            "got: {err}"
        );
        assert!(!staging_path("up-unterminated").exists());
        running.store(false, Ordering::Relaxed);
    }

    #[cfg(unix)]
    #[test]
    fn reports_open_error_when_the_app_has_no_session() {
        let _config = isolate_config_dir("nosession");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair();
        let running = Arc::new(AtomicBool::new(true));
        let server_thread = spawn_server(server, api_tx, Arc::clone(&running));

        write_line(
            &mut client,
            r#"{"id":"up_1","method":"gram.upload.stream","params":{"upload_id":"up-nosession"}}"#,
        );

        let open = api_rx.blocking_recv().unwrap();
        respond_error(open, "gram_unavailable", "gram is unavailable");

        let err: ErrorResponse = serde_json::from_str(&read_response_line(&mut client)).unwrap();
        assert_eq!(err.id, "up_1");
        assert_eq!(err.error.code, "gram_unavailable");

        // No frame is read after a failed open: the channel is already closed.
        running.store(false, Ordering::Relaxed);
        assert!(server_thread.join().unwrap().is_ok());
    }

    #[test]
    fn upload_frame_requires_seq_offset_and_data() {
        let frame: UploadFrame =
            serde_json::from_str(r#"{"seq":3,"offset":12,"data_base64":"aGk="}"#).unwrap();
        assert_eq!((frame.seq, frame.offset), (3, 12));
        assert_eq!(frame.data_base64, "aGk=");

        // Every field is mandatory — a frame missing `offset` cannot be guessed,
        // because append-only staging validates it.
        assert!(serde_json::from_str::<UploadFrame>(r#"{"seq":3,"data_base64":"aGk="}"#).is_err());
    }
}
