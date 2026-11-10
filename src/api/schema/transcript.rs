//! Wire shapes of `agent.transcript`: an omp agent's conversation read from its
//! session file and normalised into chat entries.

use serde::{Deserialize, Serialize};

use crate::cli::agent::bindings;
use crate::cli::projection::{cli_params, Field};

cli_params! {
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
    pub struct AgentTranscriptParams => AgentTranscriptProjection {
        pub target: String => Field::new(String::new()).input(bindings::target()),
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub before: Option<String> => Field::new(None).input(bindings::transcript_before()),
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub after: Option<String> => Field::new(None).input(bindings::transcript_after()),
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<u32> => Field::new(None).input(bindings::transcript_limit()),
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subagent: Option<String> => Field::new(None).input(bindings::transcript_subagent()),
    }
}

/// Who wrote a `user` entry: the owner at the terminal, or a guest whose prompt
/// arrived through HerdrUp with the `<name> (via HerdrUp): ` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptAuthor {
    Owner,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStepStatus {
    Running,
    Ok,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptNoteSource {
    Gitmoot,
    AsyncResult,
    Advisor,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptTurnStatus {
    Done,
    Error,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptModel {
    pub provider: String,
    pub id: String,
    /// The effort omp runs the model at: minimal, low, medium, high, xhigh or
    /// max. Absent when thinking is off or the level is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    /// omp picks the level per turn (`/thinking auto`).
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub thinking_auto: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptSubagentStatus {
    Running,
    Completed,
    Failed,
    Aborted,
    Unknown,
}

/// A subagent the agent spawned with omp's `task` tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptSubagent {
    /// The omp agent id, also its job id.
    pub id: String,
    /// The agent type, e.g. `reviewer`; may be empty.
    pub agent: String,
    /// The spawn's description, else its name.
    pub label: Option<String>,
    /// The assignment, at most 300 characters; owner only.
    pub task: Option<String>,
    pub status: TranscriptSubagentStatus,
    pub started_ms: u64,
    pub finished_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    /// The newest tool intent in the subagent's own session file.
    pub last_intent: Option<String>,
    pub last_ms: Option<u64>,
    /// `agent.transcript` with `subagent` set to `id` pages its conversation.
    pub has_transcript: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptRecap {
    pub turn_id: String,
    pub text: String,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptTaskStatus {
    Pending,
    InProgress,
    Completed,
    Blocked,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptPlanItem {
    pub text: String,
    pub done: bool,
    #[serde(default)]
    pub status: TranscriptTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
}

/// One question of an omp `ask` tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AskQuestion {
    pub question: String,
    pub options: Vec<String>,
    pub multi: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended: Option<u32>,
}

/// An omp (≥ 18.18.3) `ask` HTML form, reduced the way omp's terminal form
/// draws it (upstream `packages/tui/src/html-form/parse.ts`). Hidden inputs
/// are left out: omp submits them itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AskForm {
    /// Plain text of the context blocks before the first section or field;
    /// paragraphs are separated by a blank line.
    #[serde(default)]
    pub intro: Option<String>,
    /// The answerable fields in document (and terminal focus) order.
    pub fields: Vec<AskFormField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AskFormFieldKind {
    /// A radio group, checkbox group or `<select>`.
    Choice,
    /// A text `<input>` or `<textarea>`.
    Text,
}

/// One field of an [`AskForm`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AskFormField {
    /// The control `name`; the key of this field in `agent.answer_form` values.
    pub name: String,
    pub kind: AskFormFieldKind,
    /// The section `<legend>`, else the field's own label, else null.
    #[serde(default)]
    pub title: Option<String>,
    /// Plain text of the context blocks in this field's section before it.
    #[serde(default)]
    pub description: Option<String>,
    /// A checkbox group or `<select multiple>`.
    #[serde(default)]
    pub multi: bool,
    /// Drawn from a `<select>` (never has Other).
    #[serde(default)]
    pub select: bool,
    /// omp adds a free-text "Other: type your own" answer to this group.
    #[serde(default)]
    pub other: bool,
    #[serde(default)]
    pub required: bool,
    /// Choice fields only; empty for text fields.
    #[serde(default)]
    pub options: Vec<AskFormOption>,
    /// Text fields only: the `<input type>` (`text`, `number`, `email`, …) or
    /// `textarea`.
    #[serde(default)]
    pub input_type: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    /// Text fields only: the prefilled text (the default answer).
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub min: Option<serde_json::Number>,
    #[serde(default)]
    pub max: Option<serde_json::Number>,
    #[serde(default)]
    pub minlength: Option<u64>,
    #[serde(default)]
    pub maxlength: Option<u64>,
    #[serde(default)]
    pub pattern: Option<String>,
}

/// One option of a choice field. `checked` marks the agent's recommendation,
/// which is also the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AskFormOption {
    pub value: String,
    pub label: String,
    #[serde(default)]
    pub checked: bool,
    #[serde(default)]
    pub disabled: bool,
}

/// One answered field, copied from the ask result's `details.answers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AskFormAnswer {
    pub name: String,
    pub question: String,
    /// The chosen label, `Other: <text>`, comma-joined labels, or the text.
    pub answer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AskFormStatus {
    Answered,
    /// The form timed out (`details.timedOut`); omp submitted the defaults.
    TimedOut,
    /// The ask failed or was cancelled (an error result or empty details).
    Cancelled,
}

/// The newest `ask` still waiting for an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PendingAsk {
    /// The ask's tool call id.
    pub id: String,
    pub questions: Vec<AskQuestion>,
    /// One single-select question with at least one option, and a caller that
    /// may answer it. Always false for an HTML form ask.
    pub answerable: bool,
    /// An HTML form ask (omp ≥ 18.18.3); `questions` then lists one
    /// compatibility entry per choice field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<AskForm>,
    /// herdr can drive this form through `agent.answer_form` for this caller.
    #[serde(default)]
    pub form_answerable: bool,
}

/// The tool step the agent is running now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptWorking {
    pub intent: String,
    pub tool: String,
    pub since_ms: u64,
}

/// One chat entry. Every entry has a stable, unique `id` and a `ts_ms`
/// (milliseconds since the Unix epoch); clients ignore kinds they do not know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TranscriptEntry {
    User {
        id: String,
        ts_ms: u64,
        text: String,
        author: TranscriptAuthor,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        author_name: Option<String>,
        /// `other` when herdr brokered this prompt for someone other than the
        /// owner (a script, the CLI, gitmoot, another agent or a guest);
        /// omitted for the owner's turns and when unknown.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<crate::terminal::TurnOrigin>,
    },
    /// Assistant text parts joined with a blank line; `final` marks an answer
    /// that ended the model's turn (stop reason `stop`/`length`).
    Reply {
        id: String,
        ts_ms: u64,
        text: String,
        #[serde(rename = "final")]
        is_final: bool,
    },
    Thinking {
        id: String,
        ts_ms: u64,
        text: String,
    },
    Step {
        id: String,
        ts_ms: u64,
        tool: String,
        intent: String,
        status: TranscriptStepStatus,
        /// The command or path, at most 300 characters; owner only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Fleet traffic delivered into the session (gitmoot inbox, async job
    /// results, advisors); owner only.
    Note {
        id: String,
        ts_ms: u64,
        source: TranscriptNoteSource,
        title: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        body: String,
    },
    /// The turn's todo list; one per turn, re-sent with the same id when it changes.
    Plan {
        id: String,
        ts_ms: u64,
        items: Vec<TranscriptPlanItem>,
    },
    /// An `ask` tool call; `id` is the tool call id, `answer` the selection once made.
    /// For an HTML form ask, `form` holds the form, `questions`/`answer` stay as a
    /// compatibility view and `form_answer`/`form_status` arrive with the result.
    Ask {
        id: String,
        ts_ms: u64,
        questions: Vec<AskQuestion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answer: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        form: Option<AskForm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        form_answer: Option<Vec<AskFormAnswer>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        form_status: Option<AskFormStatus>,
    },
    TurnEnd {
        id: String,
        ts_ms: u64,
        status: TranscriptTurnStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// A compaction: the agent's earlier context was replaced by a summary.
    Summary {
        id: String,
        ts_ms: u64,
        text: String,
    },
}
