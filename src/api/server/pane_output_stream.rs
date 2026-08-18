//! Outbound `pane.stream` server: a persistent server->client raw PTY byte
//! firehose. Structurally cloned from `pane_graphics_stream::serve` but running
//! the opposite direction — it never reads frames from the client, it drains a
//! pane's bounded [`OutputRing`] and writes newline-delimited JSON frames.
//!
//! Lifecycle: dispatch `PaneStreamOpen` to the app (validate + attach + publish
//! the ring), look the ring up off the app loop, write the `stream_started` ack
//! and a `reset` seed, then a Condvar-woken drain loop that coalesces ready
//! bytes into `data` frames, interleaves `resize`, heartbeats with `ping`, and
//! emits `exited` when the runtime is gone. On exit it dispatches
//! `PaneStreamClose` to release the viewer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use crate::api::output_registry;
use crate::api::schema::{
    ErrorBody, ErrorResponse, Method, PaneStreamParams, Request, ResponseResult, SuccessResponse,
};
use crate::api::{ApiRequestSender, ApiStream};
use crate::ipc::is_connection_closed_error;
use crate::pane::{clamp_max_frame_bytes, OutputDrain, OutputWait};

use super::{
    api_response_outcome, dispatch_to_app_with_timeout, should_stop_connection, write_json_line,
    write_text_line_allow_disconnect, APP_RESPONSE_TIMEOUT,
};

/// Idle heartbeat / dead-peer reap cadence.
const PING_INTERVAL: Duration = Duration::from_secs(20);

const STREAM_TAG: &str = "pane.bytes";

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
        }
    }

    fn reset(seq: u64, epoch: u64, cols: u16, rows: u16, data_b64: String, lagged: bool) -> Self {
        Self {
            cols: Some(cols),
            rows: Some(rows),
            data_b64: Some(data_b64),
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
    let pane_id = params.pane_id.clone();
    let max_frame_bytes = clamp_max_frame_bytes(params.max_frame_bytes);

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
        serve_attached(&mut stream, &request_id, &pane_id, max_frame_bytes, running)
    } else {
        write_text_line_allow_disconnect(&mut stream, &open_response)
    };
    dispatch_close(&pane_id, api_tx);
    result
}

fn serve_attached(
    stream: &mut ApiStream,
    request_id: &str,
    pane_id: &str,
    max_frame_bytes: usize,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let Some(ring) = output_registry::lookup(pane_id) else {
        // The ring vanished between attach and lookup (pane closed). Report it
        // rather than silently hanging.
        return write_json_line(
            stream,
            &ErrorResponse {
                id: request_id.to_string(),
                error: ErrorBody {
                    code: "pane_not_found".into(),
                    message: format!("pane {pane_id} has no live output stream"),
                },
            },
        )
        .or_else(swallow_disconnect);
    };

    let epoch = ring.epoch();
    let Some(seed) = ring.snapshot() else {
        // The runtime is already gone; tell the client and close.
        emit(stream, &StreamFrameLine::exited(0, epoch))?;
        return Ok(());
    };

    // stream_started ack carries the geometry the client lacks today.
    if !emit(
        stream,
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

    // reset seed: base64 full-screen ANSI at exactly `base_seq`.
    if !emit(
        stream,
        &StreamFrameLine::reset(
            seed.cursor,
            epoch,
            seed.cols,
            seed.rows,
            encode_bytes(seed.ansi.as_bytes()),
            false,
        ),
    )? {
        return Ok(());
    }

    let mut cursor = seed.cursor;
    let mut resize_id = seed.resize_id;

    loop {
        if !running.load(Ordering::Relaxed) {
            return Ok(());
        }
        match ring.wait_for_activity(cursor, resize_id, PING_INTERVAL) {
            OutputWait::Closed => {
                emit(stream, &StreamFrameLine::exited(cursor, epoch))?;
                return Ok(());
            }
            OutputWait::Idle => {
                // On the idle tick, reap a dead peer before heartbeating.
                if should_stop_connection(stream, running)? {
                    return Ok(());
                }
                if !emit(stream, &StreamFrameLine::ping(cursor, epoch))? {
                    return Ok(());
                }
            }
            OutputWait::Ready => match ring.drain(cursor, resize_id, max_frame_bytes) {
                OutputDrain::Lagged => {
                    // Snapshot-collapse resync: discard the backlog, re-seed one
                    // full-screen keyframe, and jump the cursor to the live edge.
                    let Some(seed) = ring.snapshot() else {
                        emit(stream, &StreamFrameLine::exited(cursor, epoch))?;
                        return Ok(());
                    };
                    if !emit(
                        stream,
                        &StreamFrameLine::reset(
                            seed.cursor,
                            epoch,
                            seed.cols,
                            seed.rows,
                            encode_bytes(seed.ansi.as_bytes()),
                            true,
                        ),
                    )? {
                        return Ok(());
                    }
                    cursor = seed.cursor;
                    resize_id = seed.resize_id;
                }
                OutputDrain::Resize {
                    cols,
                    rows,
                    resize_id: next_resize_id,
                } => {
                    if !emit(stream, &StreamFrameLine::resize(cursor, epoch, cols, rows))? {
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
                    if !emit(
                        stream,
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

/// Write one frame/response line, reporting `false` when the peer has closed so
/// the caller can stop cleanly. A wedged socket write times out via the
/// connection-wide send timeout and tears down only this connection.
fn emit<T: serde::Serialize>(stream: &mut ApiStream, value: &T) -> std::io::Result<bool> {
    match write_json_line(stream, value) {
        Ok(()) => Ok(true),
        Err(err) if is_connection_closed_error(&err) => Ok(false),
        Err(err) => Err(err),
    }
}

fn swallow_disconnect(err: std::io::Error) -> std::io::Result<()> {
    if is_connection_closed_error(&err) {
        Ok(())
    } else {
        Err(err)
    }
}

fn dispatch_close(pane_id: &str, api_tx: &ApiRequestSender) {
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
            }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_frame_shape_includes_geometry_and_omits_lagged_when_false() {
        let frame = StreamFrameLine::reset(918_273, 7, 80, 24, "c2VlZA==".into(), false);
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["stream"], "pane.bytes");
        assert_eq!(value["frame"], "reset");
        assert_eq!(value["seq"], 918_273);
        assert_eq!(value["epoch"], 7);
        assert_eq!(value["cols"], 80);
        assert_eq!(value["rows"], 24);
        assert_eq!(value["data_b64"], "c2VlZA==");
        assert!(value.get("lagged").is_none());
    }

    #[test]
    fn lagged_reset_sets_flag() {
        let frame = StreamFrameLine::reset(1, 7, 80, 24, String::new(), true);
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
