//! `agent.transcript`: an omp agent's conversation, read from the session
//! JSONL omp appends as it runs, normalised into chat entries and paged by
//! turns from the newest end.
//!
//! The file is a tree (`id`/`parentId`); only the active branch, the parent
//! chain of the newest entry, is shown. A per-file index (see `index`) keeps
//! one small record per entry so a page reads only the lines it renders.

pub(crate) mod ask_form;
mod history;
mod index;
mod normalize;
mod origin;
mod subagents;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine as _;

use crate::api::schema::{AskFormAnswer, PendingAsk};
use crate::api::schema::{
    TranscriptEntry, TranscriptModel, TranscriptPlanItem, TranscriptRecap, TranscriptStepStatus,
    TranscriptSubagent, TranscriptTurnStatus, TranscriptWorking,
};
use index::{read_line, Kind, SessionIndex};
use normalize::{AssistantLine, NoteLine, ResultLine, StampLine, UserLine, SUMMARY_TEXT};
#[cfg(test)]
pub(crate) use origin::PENDING_PROMPT_LIMIT;
pub(crate) use origin::{OtherPrompt, OtherPromptLog, PromptOutcome, TooManyPendingPrompts};

pub(crate) const DEFAULT_TURNS: u32 = 20;
pub(crate) const MAX_TURNS: u32 = 50;
/// Rendered entries one page reads at most. A turn longer than this (hours of
/// autonomous work) is split, so a page never parses a whole giant session.
const PAGE_RECORD_BUDGET: usize = 1500;
/// Session indexes kept warm; each is a few MB for a very long session.
const CACHED_SESSIONS: usize = 8;

#[derive(Debug, Clone, Default)]
pub(crate) struct PageRequest {
    pub(crate) before: Option<String>,
    pub(crate) after: Option<String>,
    pub(crate) limit: Option<u32>,
    /// Byte budget for a newest or `before` page's entries (their JSON).
    /// Ignored for `after` pages.
    pub(crate) max_bytes: Option<u32>,
    /// Page this subagent's own session file instead of the agent's.
    pub(crate) subagent: Option<String>,
    /// The pane's remembered non-owner prompts, oldest first; their user
    /// turns are marked `origin: "other"`. Ignored for subagent pages.
    pub(crate) other_prompts: Vec<OtherPrompt>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Page {
    pub(crate) session_id: String,
    pub(crate) entries: Vec<TranscriptEntry>,
    pub(crate) before: Option<String>,
    pub(crate) after: String,
    pub(crate) pending_ask: Option<PendingAsk>,
    pub(crate) working: Option<TranscriptWorking>,
    pub(crate) model: Option<TranscriptModel>,
    pub(crate) plan: Option<Vec<TranscriptPlanItem>>,
    pub(crate) recap: Option<TranscriptRecap>,
    pub(crate) subagents: Option<Vec<TranscriptSubagent>>,
}

#[derive(Debug)]
pub(crate) enum TranscriptError {
    /// The session file is unreadable, or missing along with its directory
    /// (a missing file in an existing directory is a new, empty session).
    Unavailable(std::io::Error),
    /// The cursor no longer names this file's active branch.
    CursorExpired,
    InvalidRequest(&'static str),
    /// No subagent of this session has that id.
    SubagentNotFound,
}

impl TranscriptError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "transcript_unavailable",
            Self::CursorExpired => "cursor_expired",
            Self::InvalidRequest(_) => "invalid_request",
            Self::SubagentNotFound => "subagent_not_found",
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Unavailable(error) => format!("the agent's session file is unreadable: {error}"),
            Self::CursorExpired => {
                "the transcript changed under this cursor; reload the newest page".into()
            }
            Self::InvalidRequest(message) => (*message).into(),
            Self::SubagentNotFound => "no subagent of this agent has that id".into(),
        }
    }
}

impl From<std::io::Error> for TranscriptError {
    fn from(error: std::io::Error) -> Self {
        Self::Unavailable(error)
    }
}

static CACHE: LazyLock<Mutex<Vec<Arc<Mutex<SessionIndex>>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// The warm index for `path`, most recently used last.
fn cached_index(path: &Path) -> Arc<Mutex<SessionIndex>> {
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let found = cache.iter().position(|index| {
        index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .path()
            == path
    });
    let index = match found {
        Some(position) => cache.remove(position),
        None => Arc::new(Mutex::new(SessionIndex::new(path))),
    };
    cache.push(index.clone());
    if cache.len() > CACHED_SESSIONS {
        cache.remove(0);
    }
    index
}

fn with_index<T>(
    path: &Path,
    read: impl FnOnce(&View<'_>) -> Result<T, TranscriptError>,
) -> Result<T, TranscriptError> {
    let index = cached_index(path);
    let mut index = index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let file = match index.refresh() {
        Ok(file) => file,
        Err(error) => {
            // Forget a file that vanished so a later one at the path starts clean.
            *index = SessionIndex::new(path);
            return Err(error.into());
        }
    };
    let view = View {
        index: &index,
        branch: index.branch(),
        file: Mutex::new(file),
    };
    read(&view)
}

/// One page of `path`'s conversation, as the owner sees it, or of its
/// subagent `request.subagent`'s own conversation.
pub(crate) fn read_page(path: &Path, request: &PageRequest) -> Result<Page, TranscriptError> {
    if request.before.is_some() && request.after.is_some() {
        return Err(TranscriptError::InvalidRequest(
            "pass either before or after, not both",
        ));
    }
    let limit = request.limit.unwrap_or(DEFAULT_TURNS).clamp(1, MAX_TURNS) as usize;
    match request.subagent.as_deref() {
        Some(id) => {
            let child =
                subagents::child_session(path, id).ok_or(TranscriptError::SubagentNotFound)?;
            with_index(&child, |view| view.page(request, limit, &[]))
        }
        None => match with_index(path, |view| {
            view.page(request, limit, &request.other_prompts)
        }) {
            Err(TranscriptError::Unavailable(error)) if not_written_yet(path, &error) => {
                unwritten_page(path, request)
            }
            read => read,
        },
    }
}

/// omp names a new session's file before its first turn creates it: the file
/// is missing but the directory omp writes it to exists. A missing directory
/// (or any other error) stays unreadable.
fn not_written_yet(path: &Path, error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound && path.parent().is_some_and(Path::is_dir)
}

/// Where a page ending at `end` starts so its newest records' entries fit in
/// `max_bytes` of JSON (each entry counted with the comma that separates it).
/// The newest record that renders anything is kept even when it alone is over.
/// `marks` holds each rendered position with the count of entries before it,
/// offset by `base`; `entries` starts at `base`.
fn budget_start(
    entries: &[TranscriptEntry],
    marks: &[(usize, usize)],
    base: usize,
    end: usize,
    max_bytes: usize,
) -> usize {
    let mut total = 0;
    let mut kept = end;
    let mut entries_end = entries.len();
    for &(position, first) in marks.iter().rev() {
        let first = first - base;
        let size: usize = entries[first..entries_end]
            .iter()
            .map(|entry| json_len(entry) + 1)
            .sum();
        if size > 0 && total > 0 && total + size > max_bytes {
            break;
        }
        total += size;
        kept = position;
        entries_end = first;
    }
    kept
}

/// Length of `value` serialized as JSON, without building the string.
fn json_len(value: &impl serde::Serialize) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // Writing to a counter cannot fail; an entry always serializes.
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// The page of a session whose file omp has not written yet: an empty
/// conversation whose `after` cursor is the one the file accepts once omp
/// writes it, so the next poll returns the first turn.
fn unwritten_page(path: &Path, request: &PageRequest) -> Result<Page, TranscriptError> {
    let session_id = file_session_id(path).unwrap_or_default().to_owned();
    // There are no records yet: only an `after` cursor that has seen none
    // still names a position here.
    let valid = match (&request.before, &request.after) {
        (Some(_), _) => false,
        (None, Some(token)) => matches!(
            Cursor::decode(token, &session_id)?,
            Cursor::After {
                seen: 0,
                tip: None,
                ..
            }
        ),
        (None, None) => true,
    };
    if !valid {
        return Err(TranscriptError::CursorExpired);
    }
    let after = Cursor::After {
        seen: 0,
        tip: None,
        origins: Some(origin::fingerprint(&request.other_prompts)),
    }
    .encode(&session_id);
    Ok(Page {
        session_id,
        entries: Vec::new(),
        before: None,
        after,
        pending_ask: None,
        working: None,
        model: None,
        plan: None,
        recap: None,
        subagents: None,
    })
}

/// The session id in omp's file name (`<timestamp>_<id>.jsonl`), for a file
/// whose `session` header is not written yet.
fn file_session_id(path: &Path) -> Option<&str> {
    let (_, id) = path.file_stem()?.to_str()?.split_once('_')?;
    (!id.is_empty()).then_some(id)
}

/// The newest `ask` on the active branch still waiting for its answer.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "agent.answer and its push (herdr#308/#309) call it"
    )
)]
pub(crate) fn pending_ask(session_path: &Path) -> std::io::Result<Option<PendingAsk>> {
    match with_index(session_path, |view| Ok(view.live_state()?.ask)) {
        Ok(ask) => Ok(ask),
        Err(TranscriptError::Unavailable(error)) => Err(error),
        Err(other) => Err(std::io::Error::other(other.message())),
    }
}

/// The pending `ask` and, for a form ask, its form HTML
/// (`agent.answer_form` drives the form from it).
pub(crate) fn pending_ask_with_form(
    session_path: &Path,
) -> std::io::Result<Option<(PendingAsk, Option<String>)>> {
    let read = with_index(session_path, |view| {
        let state = view.live_state()?;
        Ok(state.ask.map(|ask| (ask, state.form_html)))
    });
    match read {
        Ok(ask) => Ok(ask),
        Err(TranscriptError::Unavailable(error)) => Err(error),
        Err(other) => Err(std::io::Error::other(other.message())),
    }
}

/// A form `ask` call's recorded result.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FormAskOutcome {
    /// `details.answers`.
    pub(crate) answers: Vec<AskFormAnswer>,
    /// The submitted data from the result text, when it parses.
    pub(crate) data: Option<serde_json::Map<String, serde_json::Value>>,
    pub(crate) timed_out: bool,
}

/// The result recorded for the form `ask` call `ask_id`, once written;
/// `None` while it is unanswered.
pub(crate) fn form_ask_outcome(
    session_path: &Path,
    ask_id: &str,
) -> std::io::Result<Option<FormAskOutcome>> {
    let read = with_index(session_path, |view| {
        let Some(result) = view.index.result_for(ask_id) else {
            return Ok(None);
        };
        let failed = view.index.record(result).failed;
        let line: ResultLine = view.parse(result)?.ok_or(TranscriptError::CursorExpired)?;
        let details = line.message.details.as_ref();
        let (answers, status) = normalize::form_result(details, failed);
        Ok(Some(FormAskOutcome {
            answers,
            data: (!failed)
                .then(|| normalize::form_result_data(&line.message.content))
                .flatten(),
            timed_out: status == crate::api::schema::AskFormStatus::TimedOut,
        }))
    });
    match read {
        Ok(outcome) => Ok(outcome),
        Err(TranscriptError::Unavailable(error)) => Err(error),
        Err(other) => Err(std::io::Error::other(other.message())),
    }
}

/// The selection recorded for the `ask` call `ask_id`, once its result is
/// written; `None` while it is unanswered (or not an ask in this file).
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "agent.answer and its push (herdr#308/#309) call it"
    )
)]
pub(crate) fn ask_result(
    session_path: &Path,
    ask_id: &str,
) -> std::io::Result<Option<Vec<String>>> {
    let read = with_index(session_path, |view| {
        let Some(result) = view.index.result_for(ask_id) else {
            return Ok(None);
        };
        let line: ResultLine = view.parse(result)?.ok_or(TranscriptError::CursorExpired)?;
        Ok(Some(normalize::ask_answer(line.message.details.as_ref())))
    });
    match read {
        Ok(answer) => Ok(answer),
        Err(TranscriptError::Unavailable(error)) => Err(error),
        Err(other) => Err(std::io::Error::other(other.message())),
    }
}

/// Opaque cursors. `before` names the first record of a page. `after` holds
/// the number of records seen and the newest active-branch record among them
/// (`tip`), which must still be on the active branch: after a rewind the
/// client's view is gone and it reloads.
#[derive(Debug, PartialEq, Eq)]
enum Cursor {
    Before {
        record: u32,
        id: String,
    },
    After {
        seen: u32,
        tip: Option<(u32, String)>,
        /// [`origin::fingerprint`] of the non-owner prompts the page was
        /// marked with; `None` in a cursor from before origins existed.
        origins: Option<u64>,
    },
}

impl Cursor {
    fn encode(&self, session_id: &str) -> String {
        let raw = match self {
            Self::Before { record, id } => format!("1\nb\n{session_id}\n{record}\n{id}"),
            Self::After { seen, tip, origins } => {
                let tip = tip
                    .as_ref()
                    .map(|(tip, id)| format!("{tip} {id}"))
                    .unwrap_or_default();
                let origins = origins
                    .map(|origins| format!("\n{origins:x}"))
                    .unwrap_or_default();
                format!("1\na\n{session_id}\n{seen}\n{tip}{origins}")
            }
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    /// Any cursor this file did not issue (another session, a garbled or
    /// foreign token) is expired: the client restarts from the newest page.
    fn decode(token: &str, session_id: &str) -> Result<Self, TranscriptError> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .ok()
            .and_then(|raw| String::from_utf8(raw).ok())
            .ok_or(TranscriptError::CursorExpired)?;
        let mut fields = raw.splitn(5, '\n');
        let (Some("1"), Some(kind), Some(session), Some(number), Some(id)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(TranscriptError::CursorExpired);
        };
        if session != session_id {
            return Err(TranscriptError::CursorExpired);
        }
        let number = number.parse().map_err(|_| TranscriptError::CursorExpired)?;
        match kind {
            "b" => Ok(Self::Before {
                record: number,
                id: id.to_owned(),
            }),
            "a" => {
                let (tip, origins) = match id.split_once('\n') {
                    Some((tip, origins)) => (
                        tip,
                        Some(
                            u64::from_str_radix(origins, 16)
                                .map_err(|_| TranscriptError::CursorExpired)?,
                        ),
                    ),
                    None => (id, None),
                };
                let tip = if tip.is_empty() {
                    None
                } else {
                    let (tip, id) = tip.split_once(' ').ok_or(TranscriptError::CursorExpired)?;
                    let tip = tip.parse().map_err(|_| TranscriptError::CursorExpired)?;
                    Some((tip, id.to_owned()))
                };
                Ok(Self::After {
                    seen: number,
                    tip,
                    origins,
                })
            }
            _ => Err(TranscriptError::CursorExpired),
        }
    }
}

struct View<'a> {
    index: &'a SessionIndex,
    /// Visible active branch: record indices, root first.
    branch: &'a [u32],
    file: Mutex<File>,
}

impl View<'_> {
    /// The `session` header's id; until omp writes it, the id in the file
    /// name, so cursors issued before the header still resolve after it.
    fn session_id(&self) -> &str {
        self.index
            .session_id
            .as_deref()
            .or_else(|| file_session_id(self.index.path()))
            .unwrap_or_default()
    }

    fn kind(&self, position: usize) -> Kind {
        self.index.record(self.branch[position]).kind
    }

    /// Branch position of `record`, if it is on the visible branch.
    fn position_of(&self, record: u32) -> Option<usize> {
        self.branch.binary_search(&record).ok()
    }

    /// Parse one record's line; `None` when it no longer parses as `T`.
    fn parse<T: serde::de::DeserializeOwned>(
        &self,
        record: u32,
    ) -> Result<Option<T>, TranscriptError> {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let line = read_line(&mut file, self.index.record(record))?;
        Ok(serde_json::from_slice(&line).ok())
    }

    /// Branch positions and ids of the user turns the remembered non-owner
    /// prompts produced. Matching runs over the branch's user turns since the
    /// oldest prompt, so every page sees the same marks whatever its window.
    fn other_user_turns(
        &self,
        prompts: &[OtherPrompt],
    ) -> Result<Vec<(usize, String)>, TranscriptError> {
        let Some(earliest_ms) = origin::earliest_turn_ms(prompts) else {
            return Ok(Vec::new());
        };
        let mut positions = Vec::new();
        let mut turns = Vec::new();
        for position in (0..self.branch.len()).rev() {
            if self.kind(position) != Kind::User {
                continue;
            }
            let record = self.branch[position];
            let Some(line) = self.parse::<UserLine>(record)? else {
                continue;
            };
            let ts_ms = normalize::ts_ms(line.message.timestamp, line.timestamp.as_deref());
            if ts_ms < earliest_ms {
                break;
            }
            let text = normalize::content_text(&line.message.content);
            if text.trim().is_empty() {
                continue;
            }
            positions.push(position);
            turns.push(origin::UserTurn {
                id: self.index.record(record).id.to_string(),
                ts_ms,
                sha256: origin::text_digest(&text),
            });
        }
        positions.reverse();
        turns.reverse();
        let matched = origin::matched_turns(prompts, &turns);
        Ok(positions
            .into_iter()
            .zip(turns)
            .filter(|(_, turn)| matched.contains(&turn.id))
            .map(|(position, turn)| (position, turn.id))
            .collect())
    }

    fn page(
        &self,
        request: &PageRequest,
        limit: usize,
        other_prompts: &[OtherPrompt],
    ) -> Result<Page, TranscriptError> {
        let session_id = self.session_id().to_owned();
        let origins = origin::fingerprint(other_prompts);
        let (start, end, changed_since, served_origins) = match (&request.before, &request.after) {
            (Some(token), _) => {
                let Cursor::Before { record, id } = Cursor::decode(token, &session_id)? else {
                    return Err(TranscriptError::CursorExpired);
                };
                let end = self
                    .valid_record(record, &id)
                    .and_then(|record| self.position_of(record))
                    .ok_or(TranscriptError::CursorExpired)?;
                (self.page_start(end, limit), end, None, None)
            }
            (None, Some(token)) => {
                let Cursor::After { seen, tip, origins } = Cursor::decode(token, &session_id)?
                else {
                    return Err(TranscriptError::CursorExpired);
                };
                if seen as usize > self.index.records.len() {
                    return Err(TranscriptError::CursorExpired);
                }
                if let Some((tip, id)) = tip {
                    self.valid_record(tip, &id)
                        .and_then(|record| self.position_of(record))
                        .ok_or(TranscriptError::CursorExpired)?;
                }
                let start = self.branch.partition_point(|&record| record < seen);
                (start, self.budget_end(start), Some(seen), origins)
            }
            (None, None) => {
                let end = self.branch.len();
                (self.page_start(end, limit), end, None, None)
            }
        };
        let mut entries = Vec::new();
        // The prompts this client was served with changed (a prompt was
        // delivered, or one was forgotten): re-send, under the same ids, every
        // user entry before its cursor that is now marked, since it may have
        // gone out unmarked.
        let resend_origins = changed_since.is_some() && served_origins != Some(origins);
        let mut others = None;
        if resend_origins {
            let matched = self.other_user_turns(other_prompts)?;
            for (position, _) in matched.iter().filter(|(position, _)| *position < start) {
                self.render(*position, position + 1, &mut entries)?;
            }
            others = Some(matched);
        }
        if let Some(seen) = changed_since {
            self.resend_changed(seen, start, &mut entries)?;
        }
        let start = match request.max_bytes {
            Some(max_bytes) if changed_since.is_none() => {
                self.render_within(start, end, max_bytes as usize, &mut entries)?
            }
            _ => {
                self.render(start, end, &mut entries)?;
                start
            }
        };
        let has_user = entries
            .iter()
            .any(|entry| matches!(entry, TranscriptEntry::User { .. }));
        let others = match others {
            Some(others) => others,
            None if has_user => self.other_user_turns(other_prompts)?,
            None => Vec::new(),
        };
        for entry in &mut entries {
            if let TranscriptEntry::User { id, origin, .. } = entry {
                if others.iter().any(|(_, other)| other == id) {
                    *origin = Some(crate::terminal::TurnOrigin::Other);
                }
            }
        }
        let before = (changed_since.is_none() && start > 0).then(|| {
            let record = self.branch[start];
            Cursor::Before {
                record,
                id: self.index.record(record).id.to_string(),
            }
            .encode(&session_id)
        });
        // An `after` page that hit the budget continues from where it stopped.
        let seen = match changed_since {
            Some(_) if end < self.branch.len() => self.branch[end],
            _ => self.index.records.len() as u32,
        };
        let tip = self.branch[..self.branch.partition_point(|&record| record < seen)]
            .last()
            .map(|&tip| (tip, self.index.record(tip).id.to_string()));
        let after = Cursor::After {
            seen,
            tip,
            origins: Some(origins),
        }
        .encode(&session_id);
        let LiveState {
            ask: pending_ask,
            working,
            form_html: _,
        } = self.live_state()?;
        Ok(Page {
            session_id,
            entries,
            before,
            after,
            pending_ask,
            working,
            model: self.current_model()?,
            plan: self.current_plan()?,
            recap: self.current_recap()?,
            subagents: self.current_subagents()?,
        })
    }

    /// The selected model with the effort omp runs it at.
    fn current_model(&self) -> Result<Option<TranscriptModel>, TranscriptError> {
        let Some((provider, id)) = self.selected_model()? else {
            return Ok(None);
        };
        let (thinking_level, thinking_auto) = self.thinking_level()?;
        Ok(Some(TranscriptModel {
            provider,
            id,
            thinking_level,
            thinking_auto,
        }))
    }

    /// The newest `thinking_level_change`: its level when it is a real effort
    /// (not off, inherit or unknown), and whether omp picks it per turn.
    /// Entries older than the `configured` field fall back to `thinkingLevel`.
    fn thinking_level(&self) -> Result<(Option<String>, bool), TranscriptError> {
        #[derive(serde::Deserialize)]
        struct ThinkingLevelChange {
            #[serde(rename = "thinkingLevel", default)]
            thinking_level: Option<String>,
            #[serde(default)]
            configured: Option<String>,
        }
        let Some(record) = self.index.thinking_record() else {
            return Ok((None, false));
        };
        let Some(change) = self.parse::<ThinkingLevelChange>(record)? else {
            return Ok((None, false));
        };
        let level = change
            .thinking_level
            .filter(|level| normalize::THINKING_LEVELS.contains(&level.as_str()));
        Ok((level, change.configured.as_deref() == Some("auto")))
    }

    fn selected_model(&self) -> Result<Option<(String, String)>, TranscriptError> {
        let mut read_assistant = false;
        for record in self.index.model_records() {
            if self.index.record(record).kind == Kind::ModelChange {
                #[derive(serde::Deserialize)]
                struct ModelChange {
                    model: String,
                }
                return Ok(self.parse::<ModelChange>(record)?.and_then(|change| {
                    let (provider, id) = change.model.split_once('/')?;
                    (!provider.is_empty() && !id.is_empty())
                        .then(|| (provider.to_owned(), id.to_owned()))
                }));
            }
            if !read_assistant {
                read_assistant = true;
                if let Some(model) = self.parse::<AssistantLine>(record)?.and_then(|line| {
                    let provider = line.message.provider?;
                    let id = line.message.model?;
                    (!provider.is_empty() && !id.is_empty()).then_some((provider, id))
                }) {
                    return Ok(Some(model));
                }
            }
        }
        Ok(None)
    }

    fn current_plan(&self) -> Result<Option<Vec<TranscriptPlanItem>>, TranscriptError> {
        let record = self
            .branch
            .iter()
            .rev()
            .copied()
            .find(|&record| self.index.record(record).kind == Kind::TodoResult);
        match record {
            Some(record) => Ok(self
                .parse::<ResultLine>(record)?
                .and_then(|line| normalize::plan_items(line.message.details.as_ref()))),
            None => Ok(None),
        }
    }

    /// The completion recap for the newest turn. A session whose omp writes
    /// turn-bound `completion-recap` records is read from those alone; older omp
    /// only saves recaps to its `history.db`, matched to the turn by time.
    fn current_recap(&self) -> Result<Option<TranscriptRecap>, TranscriptError> {
        if self
            .branch
            .iter()
            .any(|&record| self.index.record(record).kind == Kind::Recap)
        {
            self.turn_bound_recap()
        } else {
            self.history_recap()
        }
    }

    /// A `history.db` recap is current only when written after the newest
    /// conversational entry and that entry is the assistant's reply. Rows keep
    /// whole seconds, so an entry in the recap's own second counts as newer.
    fn history_recap(&self) -> Result<Option<TranscriptRecap>, TranscriptError> {
        let Some(&latest) = self.branch.iter().rev().find(|&&record| {
            matches!(
                self.index.record(record).kind,
                Kind::User
                    | Kind::Assistant
                    | Kind::ToolResult
                    | Kind::TaskResult
                    | Kind::TodoResult
                    | Kind::Compaction
                    | Kind::ResetBoundary
            )
        }) else {
            return Ok(None);
        };
        let entry = self.index.record(latest);
        if entry.kind != Kind::Assistant {
            return Ok(None);
        }
        let Some(latest_ms) = self
            .parse::<StampLine>(latest)?
            .and_then(|line| line.timestamp)
            .and_then(|stamp| normalize::parse_iso8601_ms(&stamp))
        else {
            return Ok(None);
        };
        let Some(recap) = history::latest_recap(self.index.path(), self.session_id()) else {
            return Ok(None);
        };
        let text = recap.text.trim();
        Ok(
            (latest_ms < recap.created_at_ms && !text.is_empty()).then(|| TranscriptRecap {
                turn_id: entry.id.to_string(),
                text: text.to_owned(),
            }),
        )
    }

    fn turn_bound_recap(&self) -> Result<Option<TranscriptRecap>, TranscriptError> {
        #[derive(serde::Deserialize)]
        struct RecapLine {
            data: RecapData,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RecapData {
            version: u32,
            session_id: String,
            turn_id: String,
            state: String,
            #[serde(default)]
            text: Option<String>,
        }
        for &record in self.branch.iter().rev() {
            match self.index.record(record).kind {
                Kind::Recap => {
                    let Some(line) = self.parse::<RecapLine>(record)? else {
                        return Ok(None);
                    };
                    let data = line.data;
                    if data.version != 1
                        || data.state != "available"
                        || data.session_id != self.session_id()
                    {
                        return Ok(None);
                    }
                    let latest_assistant = self
                        .branch
                        .iter()
                        .rev()
                        .map(|&id| self.index.record(id))
                        .find(|entry| {
                            matches!(
                                entry.kind,
                                Kind::User
                                    | Kind::Assistant
                                    | Kind::ToolResult
                                    | Kind::TaskResult
                                    | Kind::TodoResult
                                    | Kind::Compaction
                                    | Kind::ResetBoundary
                            )
                        })
                        .filter(|entry| entry.kind == Kind::Assistant)
                        .map(|entry| entry.id.as_ref());
                    if latest_assistant != Some(data.turn_id.as_str()) {
                        return Ok(None);
                    }
                    return Ok(data
                        .text
                        .filter(|text| !text.trim().is_empty())
                        .map(|text| TranscriptRecap {
                            turn_id: data.turn_id,
                            text,
                        }));
                }
                Kind::User
                | Kind::Assistant
                | Kind::ToolResult
                | Kind::TaskResult
                | Kind::TodoResult
                | Kind::Compaction
                | Kind::ResetBoundary => return Ok(None),
                _ => {}
            }
        }
        Ok(None)
    }

    fn valid_record(&self, record: u32, id: &str) -> Option<u32> {
        let found = self.index.records.get(record as usize)?;
        (*found.id == *id).then_some(record)
    }

    /// Where a page ending before `end` starts: `limit` turns back, each turn
    /// starting at a user entry, but never more than the record budget. A
    /// single turn over budget is split mid-turn.
    fn page_start(&self, end: usize, limit: usize) -> usize {
        let mut turns = 0;
        let mut cost = 0;
        let mut last_turn_start = None;
        let mut position = end;
        while position > 0 {
            position -= 1;
            let kind = self.kind(position);
            if kind.is_rendered() {
                cost += 1;
            }
            if kind == Kind::User {
                turns += 1;
                last_turn_start = Some(position);
                if turns == limit {
                    return position;
                }
            }
            if cost >= PAGE_RECORD_BUDGET {
                return last_turn_start.unwrap_or(position);
            }
        }
        0
    }

    /// The end of an `after` page starting at `start`, within the budget.
    fn budget_end(&self, start: usize) -> usize {
        let mut cost = 0;
        for position in start..self.branch.len() {
            if self.kind(position).is_rendered() {
                cost += 1;
                if cost > PAGE_RECORD_BUDGET {
                    return position;
                }
            }
        }
        self.branch.len()
    }

    /// The turn (its user entry, or the branch start) `position` belongs to.
    fn turn_start(&self, position: usize) -> usize {
        (0..=position)
            .rev()
            .find(|&candidate| self.kind(candidate) == Kind::User)
            .unwrap_or(0)
    }

    fn turn_end(&self, position: usize) -> usize {
        (position + 1..self.branch.len())
            .find(|&candidate| self.kind(candidate) == Kind::User)
            .unwrap_or(self.branch.len())
    }

    /// omp may continue after a stop (retries, todo nudges, a pending async
    /// wake): the turn settled only if what comes next is not more model
    /// output, i.e. the user, a note that wakes the agent, an exit, or nothing.
    fn continues_after(&self, position: usize) -> bool {
        (position + 1..self.branch.len())
            .map(|candidate| self.kind(candidate))
            .find(|kind| {
                matches!(
                    kind,
                    Kind::User
                        | Kind::Assistant
                        | Kind::Note
                        | Kind::AsyncResult
                        | Kind::SessionExit
                )
            })
            == Some(Kind::Assistant)
    }

    fn assistant_after(&self, position: usize) -> bool {
        (position + 1..self.branch.len())
            .any(|candidate| matches!(self.kind(candidate), Kind::Assistant | Kind::SessionExit))
    }

    fn render(
        &self,
        start: usize,
        end: usize,
        entries: &mut Vec<TranscriptEntry>,
    ) -> Result<(), TranscriptError> {
        self.render_marked(start, end, entries, None)
    }

    /// Renders `start..end` keeping only the newest records whose entries'
    /// JSON fits in `max_bytes` (at least one record that renders anything),
    /// and returns where the kept records start. Rendering a shorter range can
    /// move a turn's plan to a later record, so it trims until it fits.
    fn render_within(
        &self,
        start: usize,
        end: usize,
        max_bytes: usize,
        entries: &mut Vec<TranscriptEntry>,
    ) -> Result<usize, TranscriptError> {
        let base = entries.len();
        let mut start = start;
        let mut marks = Vec::new();
        loop {
            entries.truncate(base);
            marks.clear();
            self.render_marked(start, end, entries, Some(&mut marks))?;
            let kept = budget_start(&entries[base..], &marks, base, end, max_bytes);
            if kept == start {
                return Ok(start);
            }
            start = kept;
        }
    }

    /// [`View::render`], recording in `marks` each position with the number of
    /// entries rendered before it.
    fn render_marked(
        &self,
        start: usize,
        end: usize,
        entries: &mut Vec<TranscriptEntry>,
        mut marks: Option<&mut Vec<(usize, usize)>>,
    ) -> Result<(), TranscriptError> {
        let mut planned = HashSet::new();
        for position in start..end {
            if let Some(marks) = marks.as_mut() {
                marks.push((position, entries.len()));
            }
            let record = self.branch[position];
            let id = &*self.index.record(record).id;
            match self.kind(position) {
                Kind::User => {
                    if let Some(line) = self.parse::<UserLine>(record)? {
                        let text = normalize::content_text(&line.message.content);
                        if text.trim().is_empty() {
                            continue;
                        }
                        let (author, author_name, text) = normalize::user_author(&text);
                        entries.push(TranscriptEntry::User {
                            id: id.to_owned(),
                            ts_ms: normalize::ts_ms(
                                line.message.timestamp,
                                line.timestamp.as_deref(),
                            ),
                            text,
                            author,
                            author_name,
                            origin: None,
                        });
                    }
                }
                Kind::Assistant => self.render_assistant(position, None, entries)?,
                Kind::TodoResult => {
                    let turn = self.turn_start(position);
                    if planned.insert(turn) {
                        entries.extend(self.plan(turn)?);
                    }
                }
                Kind::Note | Kind::AsyncResult => {
                    if let Some(line) = self.parse::<NoteLine>(record)? {
                        if let Some(note) = normalize::note(&line) {
                            entries.push(TranscriptEntry::Note {
                                id: id.to_owned(),
                                ts_ms: normalize::ts_ms(None, line.timestamp.as_deref()),
                                source: note.source,
                                title: note.title,
                                from: note.from,
                                body: note.body,
                            });
                        }
                    }
                }
                Kind::Compaction => {
                    let ts_ms = self
                        .parse::<StampLine>(record)?
                        .map(|line| normalize::ts_ms(None, line.timestamp.as_deref()))
                        .unwrap_or(0);
                    entries.push(TranscriptEntry::Summary {
                        id: id.to_owned(),
                        ts_ms,
                        text: SUMMARY_TEXT.to_owned(),
                    });
                }
                Kind::ToolResult
                | Kind::TaskResult
                | Kind::ResetBoundary
                | Kind::SessionExit
                | Kind::Hidden
                | Kind::ModelChange
                | Kind::ThinkingLevelChange
                | Kind::Recap => {}
            }
        }
        Ok(())
    }

    /// An assistant message: its thinking, its reply, one step per tool call
    /// (an `ask` call as an ask card), then the turn end if it settled the
    /// turn. With `changed_since`, only the steps and asks whose result
    /// arrived at or after that record (their status changed).
    fn render_assistant(
        &self,
        position: usize,
        changed_since: Option<u32>,
        entries: &mut Vec<TranscriptEntry>,
    ) -> Result<(), TranscriptError> {
        let record = self.branch[position];
        let id = &*self.index.record(record).id;
        let Some(line) = self.parse::<AssistantLine>(record)? else {
            return Ok(());
        };
        let message = &line.message;
        let ts_ms = normalize::ts_ms(message.timestamp, line.timestamp.as_deref());
        let resend_only = changed_since.is_some();
        if !resend_only {
            let thinking = message
                .content
                .iter()
                .filter(|part| part.kind == "thinking")
                .filter_map(|part| part.thinking.as_deref())
                .filter(|text| !text.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n\n");
            if !thinking.is_empty() {
                entries.push(TranscriptEntry::Thinking {
                    id: format!("{id}:thinking"),
                    ts_ms,
                    text: thinking,
                });
            }
            let reply = message
                .content
                .iter()
                .filter(|part| part.kind == "text")
                .filter_map(|part| part.text.as_deref())
                .filter(|text| !text.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n\n");
            if !reply.is_empty() {
                entries.push(TranscriptEntry::Reply {
                    id: format!("{id}:reply"),
                    ts_ms,
                    text: reply,
                    is_final: normalize::is_final_stop(message.stop_reason.as_deref()),
                });
            }
        }
        let lost = self.assistant_after(position);
        for part in message
            .content
            .iter()
            .filter(|part| part.kind == "toolCall")
        {
            let (Some(call_id), Some(tool)) = (part.id.as_deref(), part.name.as_deref()) else {
                continue;
            };
            if tool == "todo" {
                continue;
            }
            let result = self.index.result_for(call_id);
            if let Some(seen) = changed_since {
                // Re-send only what moved since the client's cursor: a result
                // that landed after it, or a call that will never get one.
                let moved = match result {
                    Some(result) => result >= seen,
                    None => lost,
                };
                if !moved {
                    continue;
                }
            }
            if tool == "ask" {
                let form = ask_form::form_html(part.arguments.as_ref())
                    .map(ask_form::parse)
                    .map(|parsed| {
                        let wire = parsed.to_wire();
                        (parsed.compat_questions(&wire), wire)
                    });
                let (questions, form) = match form {
                    Some((questions, wire)) => (questions, Some(wire)),
                    None => (normalize::ask_questions(part.arguments.as_ref()), None),
                };
                let (answer, form_answer, form_status) = match result {
                    Some(result) => {
                        let failed = self.index.record(result).failed;
                        let line = self.parse::<ResultLine>(result)?;
                        let details = line.as_ref().and_then(|line| line.message.details.as_ref());
                        match &form {
                            Some(wire) => {
                                let (answers, status) = normalize::form_result(details, failed);
                                let lines = normalize::form_answer_lines(wire, &answers);
                                (
                                    (!lines.is_empty()).then_some(lines),
                                    Some(answers),
                                    Some(status),
                                )
                            }
                            None => {
                                // An ask with no selection (cancelled, failed) has no answer.
                                let answer = normalize::ask_answer(details);
                                ((!answer.is_empty()).then_some(answer), None, None)
                            }
                        }
                    }
                    None => (None, None, None),
                };
                entries.push(TranscriptEntry::Ask {
                    id: call_id.to_owned(),
                    ts_ms,
                    questions,
                    answer,
                    form,
                    form_answer,
                    form_status,
                });
                continue;
            }
            let status = match result {
                Some(result) if self.index.record(result).failed => TranscriptStepStatus::Error,
                Some(_) => TranscriptStepStatus::Ok,
                // A later model message or an exit means the call never finished.
                None if lost => TranscriptStepStatus::Error,
                None => TranscriptStepStatus::Running,
            };
            entries.push(TranscriptEntry::Step {
                id: format!("{id}:{call_id}"),
                ts_ms,
                tool: tool.to_owned(),
                intent: normalize::step_intent(part),
                status,
                detail: normalize::step_detail(tool, part.arguments.as_ref()),
            });
        }
        if resend_only {
            return Ok(());
        }
        if let Some(status) = normalize::turn_status(message.stop_reason.as_deref()) {
            if !self.continues_after(position) {
                let error = (status == TranscriptTurnStatus::Error)
                    .then(|| message.error_message.clone())
                    .flatten();
                entries.push(TranscriptEntry::TurnEnd {
                    id: format!("{id}:end"),
                    ts_ms: message.completed_at.unwrap_or(ts_ms),
                    status,
                    error,
                });
            }
        }
        Ok(())
    }

    /// The turn's todo list: one entry per turn (id from the turn's first
    /// record), holding the newest todo state the turn has written so far.
    fn plan(&self, turn: usize) -> Result<Option<TranscriptEntry>, TranscriptError> {
        let end = self.turn_end(turn);
        for position in (turn..end).rev() {
            if self.kind(position) != Kind::TodoResult {
                continue;
            }
            let Some(line) = self.parse::<ResultLine>(self.branch[position])? else {
                continue;
            };
            let Some(items) = normalize::plan_items(line.message.details.as_ref()) else {
                continue;
            };
            let turn_id = &self.index.record(self.branch[turn]).id;
            return Ok(Some(TranscriptEntry::Plan {
                id: format!("{turn_id}:plan"),
                ts_ms: normalize::ts_ms(line.message.timestamp, line.timestamp.as_deref()),
                items,
            }));
        }
        Ok(None)
    }

    /// Entries emitted before the client's `after` cursor whose state moved
    /// since: the steps and asks of the newest earlier model message (its
    /// results land after it). A changed plan needs nothing here: its new todo
    /// result is in the range and re-renders the plan under the turn's id.
    fn resend_changed(
        &self,
        seen: u32,
        start: usize,
        entries: &mut Vec<TranscriptEntry>,
    ) -> Result<(), TranscriptError> {
        if let Some(position) = (0..start)
            .rev()
            .find(|&position| self.kind(position) == Kind::Assistant)
        {
            self.render_assistant(position, Some(seen), entries)?;
        }
        Ok(())
    }

    /// The ask waiting for an answer and the step running now, both from the
    /// newest model message (an exit after it cancels both), plus the pending
    /// ask's form HTML when it is a form ask.
    fn live_state(&self) -> Result<LiveState, TranscriptError> {
        let none = || LiveState {
            ask: None,
            working: None,
            form_html: None,
        };
        let Some(position) = (0..self.branch.len())
            .rev()
            .find(|&position| matches!(self.kind(position), Kind::Assistant | Kind::SessionExit))
        else {
            return Ok(none());
        };
        if self.kind(position) == Kind::SessionExit {
            return Ok(none());
        }
        let Some(line) = self.parse::<AssistantLine>(self.branch[position])? else {
            return Ok(none());
        };
        let message = &line.message;
        let open = message.content.iter().filter(|part| {
            part.kind == "toolCall"
                && part
                    .id
                    .as_deref()
                    .is_some_and(|call_id| self.index.result_for(call_id).is_none())
        });
        // A prompt typed after the ask means the user moved on without it.
        let abandoned =
            (position + 1..self.branch.len()).any(|later| self.kind(later) == Kind::User);
        let mut ask = None;
        let mut form_html = None;
        let mut running = None;
        for part in open {
            if part.name.as_deref() == Some("ask") {
                if abandoned {
                    continue;
                }
                let id = part.id.clone().unwrap_or_default();
                let html = ask_form::form_html(part.arguments.as_ref());
                ask = Some(match html {
                    Some(html) => {
                        let parsed = ask_form::parse(html);
                        let wire = parsed.to_wire();
                        PendingAsk {
                            id,
                            questions: parsed.compat_questions(&wire),
                            answerable: false,
                            form: Some(wire),
                            form_answerable: parsed.drivable(),
                        }
                    }
                    None => {
                        let questions = normalize::ask_questions(part.arguments.as_ref());
                        let answerable = matches!(questions.as_slice(), [only] if !only.multi && !only.options.is_empty());
                        PendingAsk {
                            id,
                            questions,
                            answerable,
                            form: None,
                            form_answerable: false,
                        }
                    }
                });
                form_html = html.map(str::to_owned);
            } else {
                running = Some(part);
            }
        }
        let working = match (&ask, running) {
            (None, Some(part)) => Some(TranscriptWorking {
                intent: normalize::step_intent(part),
                tool: part.name.clone().unwrap_or_default(),
                since_ms: message.completed_at.unwrap_or_else(|| {
                    normalize::ts_ms(message.timestamp, line.timestamp.as_deref())
                }),
            }),
            _ => None,
        };
        Ok(LiveState {
            ask,
            working,
            form_html,
        })
    }
}

struct LiveState {
    ask: Option<PendingAsk>,
    working: Option<TranscriptWorking>,
    form_html: Option<String>,
}
