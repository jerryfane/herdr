//! What both relay gates share: the guest gate (`guest_gate`) and the owner
//! browser gate (`owner_gate`). Each gate is its own allowlist; this module
//! holds the pieces they must apply the same way: the API server context,
//! the agent probe, throttled audit, remote resize bounds, the session's
//! wait for its next request, and menu keys with their per-terminal commit
//! record.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{
    dispatch_to_app_with_timeout, parse_request_line, read_initial_request_line,
    write_json_line_allow_disconnect, ApiRequestSender, EventHub,
};
use crate::api::schema::{
    AgentInfo, GuestAgentProbeParams, GuestAuditEvent, InputSource, Method, PaneSendKeysParams,
    Request,
    ResponseResult, SuccessResponse,
};
use crate::api::transport::{ApiStream, ApiStreamRead};

#[cfg(test)]
pub(super) mod test_app;

/// Most keys one menu `pane.send_keys` carries: enough to walk a long menu.
const SEND_KEYS_MAX: usize = 32;
/// How often a relay stream re-checks its grant and the live-agent check.
pub(super) const WATCH_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Throttled events (a guest's reads and resizes, an owner browser's
/// refusals) are audited at most once per interval per key: the apps read
/// the scrollback again on every stream reseed and reconnect, and resize on
/// every rotation or layout change.
const AUDIT_INTERVAL: Duration = Duration::from_secs(60);
/// Bounds of a remote viewer's terminal size and width-lease TTL. The TTL is
/// the backstop when the viewer vanishes without closing its stream.
const RESIZE_COLS: std::ops::RangeInclusive<u16> = 20..=500;
const RESIZE_ROWS: std::ops::RangeInclusive<u16> = 5..=300;
const RESIZE_TTL_MS: std::ops::RangeInclusive<u64> = 1_000..=60_000;
const RESIZE_DEFAULT_TTL_MS: u64 = 30_000;

/// When each throttled event was last audited, per key (a guest id, a guest
/// id and Gram id for file opens, or an owner grant and method).
static AUDITED: Mutex<Vec<(GuestAuditEvent, String, Instant)>> = Mutex::new(Vec::new());

/// Whether `event` for `key` should be audited now; records it if so.
pub(super) fn audit_due(event: GuestAuditEvent, key: &str) -> bool {
    let now = Instant::now();
    let mut audited = AUDITED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    audited.retain(|(_, _, at)| now.duration_since(*at) < AUDIT_INTERVAL);
    if audited
        .iter()
        .any(|(seen, seen_key, _)| *seen == event && seen_key == key)
    {
        return false;
    }
    audited.push((event, key.to_string(), now));
    true
}

#[derive(Clone)]
struct ServerContext {
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    running: Arc<AtomicBool>,
}

static CONTEXT: Mutex<Option<ServerContext>> = Mutex::new(None);

/// The API server's channels, once it is up (see [`install_context`]).
pub(super) fn context() -> Option<(ApiRequestSender, EventHub, Arc<AtomicBool>)> {
    CONTEXT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .map(|context| (context.api_tx, context.event_hub, context.running))
}

/// A remote viewer's `pane.set_pty_size` within the bounds guests and owner
/// browsers get: `(cols, rows, ttl_ms)`.
pub(super) fn clamp_resize(cols: u16, rows: u16, ttl_ms: Option<u64>) -> (u16, u16, u64) {
    (
        cols.clamp(*RESIZE_COLS.start(), *RESIZE_COLS.end()),
        rows.clamp(*RESIZE_ROWS.start(), *RESIZE_ROWS.end()),
        ttl_ms
            .unwrap_or(RESIZE_DEFAULT_TTL_MS)
            .clamp(*RESIZE_TTL_MS.start(), *RESIZE_TTL_MS.end()),
    )
}

/// Called once the API server is up, so `serve` can run guest connections.
pub(super) fn install_context(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    running: Arc<AtomicBool>,
) {
    *CONTEXT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ServerContext {
        api_tx,
        event_hub,
        running,
    });
}

/// What the app reports for one pane: its public id, the agent in it (if
/// any), and the `agent.prompt` live-agent check.
pub(super) struct Probe {
    pub pane_id: String,
    pub agent: Option<AgentInfo>,
    pub running: bool,
    /// The terminal's picture, agent or not.
    pub avatar: Option<crate::api::schema::AgentAvatar>,
}

/// Probe by terminal id (any pane) or by agent target (agent panes only).
/// Errors return the app's error line.
pub(super) fn probe_target(
    api_tx: &ApiRequestSender,
    terminal_id: Option<&str>,
    target: Option<&str>,
) -> Result<Probe, String> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: "guest:probe".into(),
            method: Method::GuestAgentProbe(GuestAgentProbeParams {
                terminal_id: terminal_id.map(str::to_string),
                target: target.map(str::to_string),
            }),
        },
        api_tx,
        Some(PROBE_TIMEOUT),
    );
    match serde_json::from_str::<SuccessResponse>(&response) {
        Ok(SuccessResponse {
            result:
                ResponseResult::GuestAgentProbed {
                    pane_id,
                    agent,
                    running,
                    avatar,
                },
            ..
        }) => Ok(Probe {
            pane_id,
            agent,
            running,
            avatar,
        }),
        _ => Err(response),
    }
}

/// A key a relay viewer may send to a menu, in the form the app parses;
/// `None` for anything else. Named keys match any case; characters match
/// exactly, so `Y` (shift) and every modifier combination are refused.
pub(super) fn menu_key(key: &str) -> Option<&'static str> {
    const NAMED: [&str; 8] = [
        "up", "down", "left", "right", "enter", "tab", "escape", "space",
    ];
    const CHARS: [&str; 11] = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "y", "n"];
    NAMED
        .into_iter()
        .find(|name| name.eq_ignore_ascii_case(key))
        .or_else(|| CHARS.into_iter().find(|ch| *ch == key))
}

/// A key that acts on the menu (chooses, confirms or dismisses it), after
/// which the menu may be gone; the others only move within it.
fn commits_menu(key: &str) -> bool {
    !matches!(key, "up" | "down" | "left" | "right" | "tab" | "space")
}

/// A menu `pane.send_keys` batch in the form the app parses: 1 to
/// [`SEND_KEYS_MAX`] menu keys, at most one of them committing, and that one
/// last, so no key can land after the menu closes. `None` refuses the batch.
pub(super) fn menu_batch(keys: &[String]) -> Option<Vec<&'static str>> {
    if !(1..=SEND_KEYS_MAX).contains(&keys.len()) {
        return None;
    }
    let keys = keys
        .iter()
        .map(|key| menu_key(key))
        .collect::<Option<Vec<_>>>()?;
    let (_, before_last) = keys.split_last()?;
    if before_last.iter().any(|key| commits_menu(key)) {
        return None;
    }
    Some(keys)
}

/// The agent is waiting on a menu: an ask, a plan approval or a permission
/// prompt. A free-text prompt is no menu.
fn awaits_menu_input(agent: &AgentInfo) -> bool {
    use crate::detect::InputPromptKind;
    match agent.input_prompt_kind {
        Some(InputPromptKind::Confirm | InputPromptKind::Select) => true,
        Some(InputPromptKind::FreeText) => false,
        Some(InputPromptKind::Unknown) | None => {
            agent.agent_status == crate::api::schema::AgentStatus::Blocked
        }
    }
}

/// Per store and terminal, the agent's `state_change_seq` when a menu batch
/// (a guest's or an owner browser's) last committed a choice. Until detection
/// has seen the agent change state since, the menu on record may already be
/// gone and the keys would reach whatever runs there next (on unix, the
/// pane's shell), so no menu keys are accepted.
///
/// Each terminal has its own lock, held by a batch from its check through
/// its write, so a concurrent batch for that terminal sees this one's commit.
/// The map's own lock is only held to find that entry: a slow write to one
/// terminal never holds up menu keys to another.
static MENU_COMMITS: Mutex<Option<HashMap<MenuMarker, MenuCommit>>> = Mutex::new(None);

type MenuMarker = (std::path::PathBuf, String);

/// One terminal's last committed `state_change_seq`, if any.
type MenuCommit = Arc<Mutex<Option<u64>>>;

/// The commit record for `marker`, created on first use.
fn menu_commit(marker: MenuMarker) -> MenuCommit {
    let mut commits = MENU_COMMITS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(
        commits
            .get_or_insert_with(HashMap::new)
            .entry(marker)
            .or_default(),
    )
}

/// Sends a [`menu_batch`] to `agent`, the agent as just probed, while it
/// awaits a menu and no committing batch since its last state change is on
/// record for its terminal (in the store at `dir`). The record is held from
/// that check through the write. `accepted` runs once the batch passes,
/// before the write (the caller's audit). `input_source` is the gate's own
/// decision for this principal: `Some(App)` for an owner browser, `None` for a
/// guest. Returns the app's reply, or `None` when the batch is refused.
pub(super) fn send_menu_keys(
    api_tx: &ApiRequestSender,
    dir: &std::path::Path,
    agent: &AgentInfo,
    keys: Vec<&'static str>,
    id: &str,
    input_source: Option<InputSource>,
    accepted: impl FnOnce(&[&'static str]),
) -> Option<String> {
    let commit = menu_commit((dir.to_path_buf(), agent.terminal_id.clone()));
    let mut committed_at = commit
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stale = committed_at.is_some_and(|seq| agent.state_change_seq <= seq);
    if stale || !awaits_menu_input(agent) {
        return None;
    }
    *committed_at = None;
    accepted(&keys);
    let commits_choice = keys.last().is_some_and(|key| commits_menu(key));
    let request = Request {
        id: id.to_owned(),
        method: Method::PaneSendKeys(PaneSendKeysParams {
            pane_id: agent.pane_id.clone(),
            keys: keys.into_iter().map(str::to_owned).collect(),
            input_source,
        }),
    };
    let response = dispatch_to_app_with_timeout(request, api_tx, None);
    if commits_choice {
        *committed_at = Some(agent.state_change_seq);
    }
    Some(response)
}

/// A relay session's next request, or `None` when the session ends first.
/// An unparseable line is answered with `invalid_request` and ends it.
pub(super) fn next_request(
    stream: &mut ApiStream,
    live: &crate::guest::LiveSession,
    running: &AtomicBool,
    idle: Duration,
) -> std::io::Result<Option<Request>> {
    if !await_request(stream, live, running, idle)? {
        return Ok(None);
    }
    let Some(line) = read_initial_request_line(stream)? else {
        return Ok(None);
    };
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    match parse_request_line(line) {
        Ok(request) => Ok(Some(request)),
        Err(response) => {
            write_json_line_allow_disconnect(stream, &response)?;
            Ok(None)
        }
    }
}

/// Waits until request bytes arrive (true), or the viewer closes, its access
/// is revoked, the server stops, or `idle` passes (false). Nothing is
/// consumed.
fn await_request(
    stream: &mut ApiStream,
    live: &crate::guest::LiveSession,
    running: &AtomicBool,
    idle: Duration,
) -> std::io::Result<bool> {
    stream.set_polling(true)?;
    let result = poll_for_request(stream, live, running, idle);
    stream.set_polling(false)?;
    result
}

fn poll_for_request(
    stream: &mut ApiStream,
    live: &crate::guest::LiveSession,
    running: &AtomicBool,
    idle: Duration,
) -> std::io::Result<bool> {
    let deadline = Instant::now() + idle;
    let mut probe = [0u8; 1];
    loop {
        match stream.poll_peek(&mut probe)? {
            // No peek on this transport: let the line reader find out.
            Some(ApiStreamRead::Data(_)) | None => return Ok(true),
            Some(ApiStreamRead::Closed) => return Ok(false),
            Some(ApiStreamRead::Pending) => {}
        }
        if live.revoked() || !running.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let wait = (deadline - now).min(WATCH_INTERVAL);
        if !stream.wait_readable(wait)? {
            std::thread::sleep(wait);
        }
    }
}
