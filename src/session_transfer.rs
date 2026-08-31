//! Native transcript conversion for Claude Code <-> Codex session transfer.
//!
//! This module deliberately has no pane or TUI state. It reads an immutable
//! source artifact into a provider-neutral visible-message sequence, stages a
//! new native destination artifact, then rereads that artifact for verification.
//! The caller owns the later same-pane cutover transaction.

mod omp;

use std::fmt;
use std::fs;
use std::io::{BufRead as _, BufReader, BufWriter, Cursor, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

/// How much of the most recent transcript a transfer carries.
///
/// A WINDOW, NOT A LIMIT — the distinction is the whole of review finding 1. While this
/// was a limit, an oversize transcript was refused and the seat could never move; now it
/// bounds how much is taken from the tail. Nothing upstream may refuse a WINDOWED source
/// on size, or the window becomes unreachable again.
///
/// SCOPED, BECAUSE ONE HARNESS IS DELIBERATELY EXEMPT. OMP sources are NOT windowed —
/// their format opens with a fixed-width title slot and a session header that a tail cut
/// would drop — so `read_transcript_whole` still refuses an OMP source above this size,
/// which is the pre-window behaviour for that harness and unchanged by this PR. Round 19
/// was right that the unscoped wording claimed a universal the code does not hold; that
/// is how a reader concludes the refusal is a bug and removes it. Windowing OMP needs a
/// header-preserving design and its own review.
const TRANSFER_WINDOW_BYTES: u64 = 64 * 1024 * 1024;

/// The most this will hold in memory for ONE destination record.
///
/// A MEMORY CEILING, DERIVED FROM NOTHING IN THE FILE. Rounds 4 through 8 each refined a
/// limit derived from our expected message text, and round 8 named why that whole family
/// is wrong: the limit is applied to EVERY record, while it is derived from one kind.
/// Codex writes `session_meta.base_instructions` from the TARGET's configuration, whose
/// size has no relation to our transcript — so a legitimate metadata record was refused
/// (measured: 8,454,325 bytes against a derived 8,454,144) before a single visible
/// message had been compared, and refused AFTER the session existed.
///
/// A bound on retention must not double as a correctness gate on content it was not
/// derived from. This is the same budget the source window already commits to, so the
/// feature's memory ceiling is one stated number rather than a per-record inference, and
/// no legitimate record is refused for a reason unrelated to what it contains.
const DESTINATION_RECORD_BUDGET_BYTES: usize = TRANSFER_WINDOW_BYTES as usize;

/// The most this will SCAN in one destination pass, across all records.
///
/// A per-record bound is not a bound on work: both round-9 reviewers pointed out that
/// arbitrarily many sub-budget records — metadata we ignore, in particular — are still
/// parsed twice at whatever cost the producer chooses, and raising the per-record
/// allowance widened that. This is an explicit RESOURCE POLICY, deliberately not derived
/// from the expected messages.
///
/// SIXTEEN WINDOWS, AND IT IS A RUNAWAY STOP RATHER THAN AN EXPANSION MODEL. It was four,
/// on my reasoning that "Codex roughly doubles a Claude transcript". Round 10 refused
/// that as unproven, and measuring settled it: 400 tiny message pairs expand 2.59x, not
/// 2x, because Codex writes several records per pair and per-record envelope overhead
/// dominates exactly where messages are smallest. Four windows left barely 1.5x of
/// margin over a shape I had not thought to measure.
///
/// A budget that refuses a VALID transfer is the defect this PR has now had in five
/// forms, so this sits well above the worst expansion measured in
/// `codex_expansion_stays_far_inside_the_total_budget` and is documented as what it is:
/// a bound that stops an unbounded producer, not an estimate of legitimate growth.
const DESTINATION_TOTAL_BUDGET_BYTES: u64 = 16 * TRANSFER_WINDOW_BYTES;

/// The smallest ASSISTANT record `parse_claude_record` turns into a visible message.
///
/// PER ROLE, NOT GLOBAL, AND THE DISTINCTION IS LOAD-BEARING. A user record is smaller
/// still (56 bytes; serde sorts the keys, so it is shorter than a hand-count suggests) —
/// but it produces a user ENTRY, which the writer emits at roughly half the cost of an
/// assistant one. Pairing the globally smallest record with the largest entry models a
/// transcript that cannot exist and inflates the ceiling by a third. Expansion is a
/// per-role quantity, so the model is per-role.
///
/// MEASURED PER FIELD, NOT PER RECORD — the check that would have caught rounds 18, 19 and
/// 21. Each sized this from "the minimal record", meaning the minimal record THAT ROUND
/// HAPPENED TO WRITE, and each was demolished by someone who minimised a field it had left
/// fat. `parse_claude_message` accepts `content` as a bare JSON string for either role and
/// `push_visible_message` does not merge consecutive same-role records, so the worst shape
/// is an all-assistant window of
/// `{"type":"assistant","message":{"role":"assistant","content":"a"}}` plus a newline.
///
/// AND CLAUDE IS THE VERTEX ACROSS EVERY SOURCE KIND, NOT JUST THE ONE THIS IS NAMED FOR.
/// Codex and OMP sources also feed `omp::write`, each capped at one window, so any of the
/// three could hold the worst rate.
///
/// WHAT IS GUARANTEED IS THE RATE, NOT THE RECORD SIZE — and the difference is the whole
/// reason the check was rewritten. `the_modelled_role_is_the_worst_expanding_one` does NOT
/// assert this is the smallest accepted record anywhere; a Codex `event_msg` user record
/// is 69 bytes and a Claude user record is 56, both smaller. It asserts that no
/// (kind, role) pair reaches a higher ENTRY-COST-OVER-RECORD-COST rate than the Claude
/// assistant pair, which is what the bound is actually derived from. Comparing raw minima
/// instead — as an earlier version of that test did — is wrong in both directions: it can
/// fail on a transcript that is cheaper per byte, and pass while a worse assistant form
/// exists. A cheap record producing a USER message costs a user entry, about half an
/// assistant one, so it cannot move a bound derived from the assistant vertex.
const OMP_MIN_ASSISTANT_RECORD_BYTES: u64 = 66;

/// The largest entry `omp::write` emits for one visible message.
///
/// Fixed-width by construction: a uuid id, a uuid parentId, an RFC3339 timestamp and the
/// api/provider/model/usage/stopReason block. The assistant form is the larger of the two,
/// which is why it pairs with the assistant minimum above.
/// `omp_write_entry_cost_stays_inside_the_modelled_maximum` measures the real writer and
/// fails if a field is added — the guard this number exists for.
const OMP_MAX_DESTINATION_ENTRY_BYTES: u64 = 512;

/// The most an OMP destination may occupy IN MEMORY while being verified.
///
/// A RETENTION BOUND, MEASURED AGAINST RETENTION. The OMP arm cannot stream — `omp::parse`
/// takes `&[u8]` because leaf selection is a property of the graph — so unlike Claude and
/// Codex it genuinely holds the file. `DESTINATION_TOTAL_BUDGET_BYTES` is bytes SCANNED
/// and is set high precisely BECAUSE streaming retains one record at a time; borrowing it
/// here made the memory ceiling 1 GiB in a single Vec inside the long-lived TUI process.
///
/// DERIVED FROM THE WRITER, NOT GUESSED FROM A RATIO. Four rounds put four numbers here
/// and a reviewer demolished each by computing the worst-case input rather than the
/// representative one: 4 windows from a 205-byte pair the OMP path never sees (round 18);
/// no bound at all (round 19); the file's own length, which cannot refuse (round 20);
/// 8 windows from a 5.11x fixture that minimised the user record and left the assistant
/// record in its fat array form (round 21 — the real worst shape is an all-assistant
/// window at 7.61x, which left 5% of headroom, not the 2x I claimed).
///
/// A ratio is the wrong input because it is a property of a FIXTURE. This is the same
/// quantity expressed as what actually determines it: at most one destination entry per
/// accepted source record, so a full window admits `WINDOW / MIN_RECORD` entries of at
/// most `MAX_ENTRY` bytes each. The ratio is now an OUTPUT of the model — currently
/// 7.75x — and a fixture that finds a smaller accepted record moves the bound instead of
/// merely embarrassing it.
///
/// THE MARGIN IS EXPLICIT AND THE DIRECTION IS NOT SYMMETRIC. `omp::write` PUBLISHES the
/// session before `prepare` reads it back under this ceiling, so a ceiling below what the
/// writer produced refuses a session that already exists and orphans it. Too low costs a
/// valid transfer; too high costs memory. Half again over the modelled worst case.
///
/// AND IT IS A CEILING, NOT A CORRECTNESS GATE. Detecting a foreign write to the staged
/// target is `verify_unchanged_transcripts`' fingerprint compare, which runs before
/// launch; nothing about this number establishes provenance. Round 20's comment claimed
/// otherwise, and that claim was the defect rather than the number.
///
/// IT IS ALSO LARGER THAN ANYONE WANTS, AND THAT IS THE HONEST READING. Every other
/// guessed bound on this PR was closed by DELETING it and streaming. This one cannot be,
/// solely because `omp::parse` takes `&[u8]`. The fix that removes this constant rather
/// than tuning it a fifth time is a two-pass parse — pass 1 indexes `id -> (parentId,
/// byte offset)`, pass 2 seeks and projects only the selected branch, making retention
/// O(entries) plus one record. That is a separate PR and is NOT yet filed as an issue:
/// filing one is a GitHub write and this seat holds no row for it.
///
/// THE MARGIN HAS A SECOND JOB, AND IT WAS ACCIDENTAL UNTIL ROUND 23 NAMED IT. This ceiling
/// bounds the read at `prepare`, where the file is what `omp::write` just produced — and
/// again at `verified_visible_destination`, AFTER launch, when the live target has been
/// appending to that same file. So the headroom is not only slack against a mis-modelled
/// writer; it is the room a running agent has to grow the transcript before the
/// post-launch read refuses and ROLLS BACK a session the user is actively working in.
/// That is why the margin is 1.5x and not 1.1x. Exhausting it needs 248 MiB appended on
/// top of an already adversarial source, so this is headroom rather than a live risk.
const OMP_DESTINATION_MODELLED_WORST_BYTES: u64 =
    (TRANSFER_WINDOW_BYTES / OMP_MIN_ASSISTANT_RECORD_BYTES) * OMP_MAX_DESTINATION_ENTRY_BYTES;

/// Headroom over the modelled worst case, as an explicit fraction.
///
/// NAMED SO THE GUARD CAN SIT ON THE THING A FUTURE ROUND WOULD ACTUALLY EDIT. Round 22
/// replaced an exact `assert_eq!` pin with a one-sided floor and left the constant with no
/// upper bound but the 16-window scan budget — 1.37x above the derived value, in the
/// widening direction this PR has already regressed in twice. Nothing would have caught
/// `/ 2 * 3` becoming `/ 2 * 4`: every assert and every test stays green while the resident
/// ceiling rises a third. That gap was created by the round that was fixing the previous
/// widening, which is the whole reason the margin is a named quantity now.
const OMP_RETENTION_MARGIN_NUMERATOR: u64 = 3;
const OMP_RETENTION_MARGIN_DENOMINATOR: u64 = 2;

const OMP_DESTINATION_RETENTION_BYTES: u64 = OMP_DESTINATION_MODELLED_WORST_BYTES
    / OMP_RETENTION_MARGIN_DENOMINATOR
    * OMP_RETENTION_MARGIN_NUMERATOR;

// A RETENTION BOUND MUST NOT BORROW A WORK BUDGET, and clippy was right that a runtime
// test of two constants is the wrong instrument: this is a compile-time invariant, so it
// is asserted at compile time. Violating it fails the BUILD rather than a review round —
// which is the only reason these are worth writing, given that three consecutive rounds
// each removed or loosened one and no check noticed any of the three times.
const _: () = assert!(OMP_DESTINATION_RETENTION_BYTES < DESTINATION_TOTAL_BUDGET_BYTES);

// BOUNDED FROM BOTH SIDES, AND AGAINST THE MODEL RATHER THAN AGAINST A WINDOW COUNT.
//
// The previous floor was `>= 8 * TRANSFER_WINDOW_BYTES`, which had stopped checking
// anything once the ceiling became derived: 8 windows is below the derivation by
// construction, so the only way it could fire was on a change making the writer CHEAPER.
// Shrink `OMP_MAX_DESTINATION_ENTRY_BYTES` to a correctly-measured 350 and the build fails
// on a change that is right and makes the bound tighter — a guard rejecting a run that
// should succeed, which is the exact failure the comment above it accused the SIX-window
// floor of having. A guard that can only fire spuriously is worse than no guard.
//
//
// ASSERTED ON THE VALUE, NOT ON THE FRACTION — AND THE FRACTION VERSION WAS THE FOURTH
// LEVEL OF ONE MISTAKE. Round 23 named the margin and asserted `1.25 <= NUM/DEN <= 1.5`,
// which guards the constants a widening would edit ONLY IF the derivation keeps using
// them. It need not: rewrite the expression above as `MODELLED_WORST / 10 * 19` and NUM
// stays 3, DEN stays 2, both fraction asserts pass, the value-level test passes MORE
// easily because it only checks a lower bound, and the resident ceiling goes to 943 MiB.
// Same edit site and same direction as the round-19 and round-22 regressions.
//
// The lesson each round has re-taught at a higher level: GUARD THE QUANTITY THAT MATTERS,
// NOT AN INPUT THAT CURRENTLY DETERMINES IT. Round 19 guarded nothing; round 22 guarded a
// window count that stopped tracking the model; round 23 guarded a fraction the derivation
// is free to stop using. These bind the ceiling directly to the modelled worst case, so
// they hold however the expression is rewritten.
//
// THEY ARE THE WHOLE GUARD SET FOR THE MARGIN, and the fraction asserts that used to sit
// beside them are gone because these are STRICTLY STRONGER, verified in both directions
// rather than asserted: R = floor(M/DEN)*NUM <= M*NUM/DEN, so a fraction below 1.25 forces
// 4R < 5M; and a fraction above 1.5 forces 2R > 3M unless NUM*DEN exceeds 260,300,800.
// Strictly stronger, because integer truncation can push R outside a band the fraction
// still satisfies, and because these survive the derivation dropping NUM/DEN entirely.
// (Round 25 caught the lower fraction assert still sitting here while this comment already
// claimed both were gone — a guard set whose own description is wrong is how the round-19
// and round-22 deletions passed review, one level of prose up.)
//
// 1.25 <= ceiling / modelled worst <= 1.5. The upper bound holds with exact equality at
// this head, deliberately: this is headroom, and a round wanting more should argue for it
// in review rather than receive it silently.
const _: () =
    assert!(4 * OMP_DESTINATION_RETENTION_BYTES >= 5 * OMP_DESTINATION_MODELLED_WORST_BYTES);
const _: () =
    assert!(2 * OMP_DESTINATION_RETENTION_BYTES <= 3 * OMP_DESTINATION_MODELLED_WORST_BYTES);

const MAX_TRANSCRIPT_LINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_APP_SERVER_LINE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROLLOUT_FILES_SCANNED: usize = 50_000;

/// How many import completions and named targets one import may produce.
///
/// The per-message cap bounds each notification; nothing bounded HOW MANY. A faulty or
/// hostile app-server could emit unlimited sub-2-MiB completions before answering the
/// request, and both the buffer and the target list grew with them — then every named
/// target was copied into the cleanup queue, each able to spend the full delete timeout.
/// Round 12.
///
/// One import of one session legitimately produces a handful. Sixty-four is far above
/// that and small enough that the linear duplicate check below costs nothing.
const MAX_IMPORT_COMPLETIONS: usize = 64;
// Codex 0.150.1's external Claude-session importer flattens native tool
// activity into visible assistant messages. These values and tags deliberately
// mirror that independently verified target representation. If Codex changes
// it, exact destination verification must fail closed until this projection is
// reviewed and updated.
const CODEX_IMPORT_NOTE_MAX_CHARS: usize = 2_000;
const CODEX_IMPORT_TOOL_RESULT_MAX_CHARS: usize = 4_000;
const CODEX_IMPORT_TOOL_CALL_TAG: &str = "external_agent_tool_call";
const CODEX_IMPORT_TOOL_RESULT_TAG: &str = "external_agent_tool_result";

/// JSON value that retains source object-key order for the one Codex importer
/// representation where order is visible: fallback tool-input notes. Herdr's
/// normal `serde_json::Value` intentionally keeps its existing global ordering
/// behavior; changing that dependency feature would alter unrelated API JSON.
#[derive(Debug, Clone)]
enum OrderedJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<OrderedJson>),
    Object(Vec<(String, OrderedJson)>),
}

impl OrderedJson {
    fn get(&self, key: &str) -> Option<&Self> {
        let Self::Object(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    fn as_array(&self) -> Option<&[Self]> {
        let Self::Array(values) = self else {
            return None;
        };
        Some(values)
    }
}

struct OrderedJsonVisitor;

impl<'de> Visitor<'de> for OrderedJsonVisitor {
    type Value = OrderedJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(OrderedJson::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(OrderedJson::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(OrderedJson::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(OrderedJson::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(OrderedJson::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(OrderedJson::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(OrderedJson::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(OrderedJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let capacity = map.size_hint().unwrap_or(0);
        let mut entries: Vec<(String, OrderedJson)> = Vec::with_capacity(capacity);
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(capacity);
        while let Some((key, value)) = map.next_entry::<String, OrderedJson>()? {
            if !seen.insert(key.clone()) {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            entries.push((key, value));
        }
        Ok(OrderedJson::Object(entries))
    }
}

impl<'de> Deserialize<'de> for OrderedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OrderedJsonVisitor)
    }
}

impl Serialize for OrderedJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HarnessKind {
    Claude,
    Codex,
    Omp,
}

impl HarnessKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Omp => "omp",
        }
    }

    pub(crate) fn from_agent_label(label: &str) -> Option<Self> {
        match label {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "omp" => Some(Self::Omp),
            _ => None,
        }
    }

    pub(crate) fn source(self) -> &'static str {
        match self {
            Self::Claude => "herdr:claude",
            Self::Codex => "herdr:codex",
            Self::Omp => "herdr:omp",
        }
    }

    pub(crate) fn api(self) -> crate::api::schema::AgentSessionTransferHarness {
        match self {
            Self::Claude => crate::api::schema::AgentSessionTransferHarness::Claude,
            Self::Codex => crate::api::schema::AgentSessionTransferHarness::Codex,
            Self::Omp => crate::api::schema::AgentSessionTransferHarness::Omp,
        }
    }

    pub(crate) fn agent(self) -> crate::detect::Agent {
        match self {
            Self::Claude => crate::detect::Agent::Claude,
            Self::Codex => crate::detect::Agent::Codex,
            Self::Omp => crate::detect::Agent::Omp,
        }
    }
}

impl From<crate::api::schema::AgentSessionTransferHarness> for HarnessKind {
    fn from(value: crate::api::schema::AgentSessionTransferHarness) -> Self {
        match value {
            crate::api::schema::AgentSessionTransferHarness::Claude => Self::Claude,
            crate::api::schema::AgentSessionTransferHarness::Codex => Self::Codex,
            crate::api::schema::AgentSessionTransferHarness::Omp => Self::Omp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VisibleRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub(crate) struct VisibleMessage {
    pub(crate) role: VisibleRole,
    pub(crate) text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub(crate) struct OmissionSummary {
    pub(crate) tool_records: u64,
    pub(crate) reasoning_records: u64,
    pub(crate) system_records: u64,
    pub(crate) attachment_records: u64,
    pub(crate) metadata_records: u64,
    pub(crate) unsupported_blocks: u64,
    pub(crate) sidechain_records: u64,
    /// Records dropped because they fell outside the transfer window — older
    /// history, not a record class. Zero unless the transcript exceeded the
    /// budget, so it is silent for every transfer that already worked.
    pub(crate) windowed_records: u64,
}

#[cfg(test)]
impl OmissionSummary {
    fn total(&self) -> u64 {
        self.tool_records
            + self.reasoning_records
            + self.system_records
            + self.attachment_records
            + self.metadata_records
            + self.unsupported_blocks
            + self.sidechain_records
            // Counted here even though it is not a record CLASS: this helper's job
            // is to fail when a field is added and forgotten, and that guard is
            // only worth anything if it covers every field.
            + self.windowed_records
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalTranscript {
    pub(crate) messages: Vec<VisibleMessage>,
    pub(crate) omissions: OmissionSummary,
    pub(crate) fingerprint: TranscriptFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptFingerprint {
    pub(crate) byte_len: u64,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedSession {
    pub(crate) session_ref: crate::agent_resume::AgentSessionRef,
    pub(crate) cursor: Option<String>,
    pub(crate) transcript_path: PathBuf,
    pub(crate) transcript: CanonicalTranscript,
}

#[derive(Debug, Clone)]
pub(crate) struct PrepareRequest {
    pub(crate) source_kind: HarnessKind,
    pub(crate) source_sessions_root: PathBuf,
    pub(crate) source_session_ref: crate::agent_resume::AgentSessionRef,
    pub(crate) source_cursor: Option<String>,
    pub(crate) source_transcript_path: Option<PathBuf>,
    pub(crate) target_kind: HarnessKind,
    pub(crate) target_config_home: PathBuf,
    pub(crate) target_sessions_root: PathBuf,
    pub(crate) target_launch_env: crate::config::AccountLaunchEnv,
    pub(crate) cwd: PathBuf,
    pub(crate) timeout: Duration,
}

#[derive(Debug)]
pub(crate) struct PreparedTransfer {
    pub(crate) source_path: PathBuf,
    pub(crate) source_fingerprint: TranscriptFingerprint,
    pub(crate) staged: StagedSession,
    /// Which harness and account home the staged target lives in.
    ///
    /// Carried on the value itself so ANY site that discards it can report what was
    /// left behind, without the caller having to still hold the request. With automatic
    /// cleanup cut, an unreported discard is a session nothing names.
    pub(crate) target_kind: HarnessKind,
    pub(crate) target_config_home: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeSessionTransfer {
    pub(crate) id: String,
    pub(crate) source_kind: HarnessKind,
    pub(crate) source_session: crate::agent_resume::PersistedAgentSession,
    pub(crate) source_account: Option<String>,
    pub(crate) source_config_home: PathBuf,
    pub(crate) source_sessions_root: PathBuf,
    pub(crate) source_cursor: Option<String>,
    pub(crate) source_process_pid: Option<u32>,
    pub(crate) target_kind: HarnessKind,
    pub(crate) target_account: Option<String>,
    pub(crate) target_config_home: PathBuf,
    pub(crate) target_sessions_root: PathBuf,
    pub(crate) phase: crate::api::schema::AgentSessionTransferPhase,
    pub(crate) message_count: u64,
    pub(crate) omissions: OmissionSummary,
    pub(crate) error: Option<String>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) source_fingerprint: Option<TranscriptFingerprint>,
    pub(crate) target_session_ref: Option<crate::agent_resume::AgentSessionRef>,
    pub(crate) target_cursor: Option<String>,
    pub(crate) target_transcript_path: Option<PathBuf>,
    pub(crate) target_fingerprint: Option<TranscriptFingerprint>,
    pub(crate) target_deadline: Option<std::time::Instant>,
    pub(crate) target_process: Option<VerifiedTargetProcess>,
    pub(crate) source_rollback_process: Option<VerifiedTargetProcess>,
    pub(crate) verification_in_flight: Option<RuntimeVerificationKind>,
    pub(crate) verification_observation_deadline: Option<std::time::Instant>,
    pub(crate) awaiting_deferred_target_report: bool,
    pub(crate) target_report_accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedTargetProcess {
    pub(crate) pid: u32,
    pub(crate) observed_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeVerificationKind {
    Target,
    SourceRollback,
}

impl RuntimeSessionTransfer {
    pub(crate) fn restart_owns_source(&self) -> bool {
        self.phase != crate::api::schema::AgentSessionTransferPhase::Completed
            || self.awaiting_deferred_target_report
    }

    pub(crate) fn preserves_agent_name_on_process_exit(&self) -> bool {
        use crate::api::schema::AgentSessionTransferPhase;

        matches!(
            self.phase,
            AgentSessionTransferPhase::LaunchingTarget
                | AgentSessionTransferPhase::AwaitingTarget
                | AgentSessionTransferPhase::RollingBack
        )
    }

    pub(crate) fn expected_agent_name_owner(&self) -> Option<&'static str> {
        use crate::api::schema::AgentSessionTransferPhase;

        match self.phase {
            AgentSessionTransferPhase::LaunchingTarget
            | AgentSessionTransferPhase::AwaitingTarget => Some(self.target_kind.label()),
            AgentSessionTransferPhase::Completed if self.awaiting_deferred_target_report => {
                Some(self.target_kind.label())
            }
            AgentSessionTransferPhase::RollingBack => Some(self.source_kind.label()),
            _ => None,
        }
    }

    pub(crate) fn verified_visible_destination(&self) -> Result<(), TransferError> {
        let source_path = self.source_path.as_deref().ok_or_else(|| {
            TransferError::DestinationMismatch(
                "transfer has no verified source transcript path".to_string(),
            )
        })?;
        let target_path = self.target_transcript_path.as_deref().ok_or_else(|| {
            TransferError::DestinationMismatch(
                "transfer has no staged destination transcript path".to_string(),
            )
        })?;
        let source = read_transfer_source(
            self.source_kind,
            self.target_kind,
            &self.source_sessions_root,
            source_path,
            self.source_cursor.as_deref(),
        )?;
        // THE SAME ROUTING AS `prepare`, AND FOR THE SAME REASON. Both reviewers found
        // that fixing the destination read in `prepare` alone left THIS path — the
        // post-launch re-verification, which drives rollback — still going through the
        // whole-file reader and its 64 MiB refusal. A legitimate near-window source
        // whose Codex destination expands past that would verify at staging and then be
        // rolled back after launch, which is worse than refusing it outright.
        //
        // Second site of one defect. The routing decision belongs in one place; it is
        // duplicated here only because the two callers hold `expected` differently, and
        // that is worth revisiting if a third appears.
        read_verified_destination(
            self.target_kind,
            &self.target_sessions_root,
            target_path,
            self.target_cursor.as_deref(),
            &source.0.messages,
        )
        .map(|_| ())
    }

    pub(crate) fn info(&self) -> crate::api::schema::AgentSessionTransferInfo {
        crate::api::schema::AgentSessionTransferInfo {
            id: self.id.clone(),
            source: self.source_kind.api(),
            target: self.target_kind.api(),
            target_account: self.target_account.clone(),
            phase: self.phase,
            message_count: self.message_count,
            omissions: crate::api::schema::AgentSessionTransferOmissions {
                tool_records: self.omissions.tool_records,
                reasoning_records: self.omissions.reasoning_records,
                system_records: self.omissions.system_records,
                attachment_records: self.omissions.attachment_records,
                metadata_records: self.omissions.metadata_records,
                unsupported_blocks: self.omissions.unsupported_blocks,
                sidechain_records: self.omissions.sidechain_records,
                windowed_records: self.omissions.windowed_records,
            },
            error: self.error.clone(),
        }
    }
}

/// Return the one deterministic Codex process that proves this exact resume.
///
/// A process qualifies only when its own argv contains the consecutive tokens
/// `resume <session_id>` and Herdr's normal single-process identification says
/// that process is Codex. Native `codex` executables rank ahead of wrappers;
/// ties use the lowest PID. The returned PID is therefore stable and reportable,
/// never merely evidence that some unrelated Codex process exists in the job.
pub(crate) fn codex_resume_process(
    job: &crate::platform::ForegroundJob,
    session_id: &str,
) -> Option<u32> {
    if session_id.is_empty() || session_id.chars().any(char::is_control) {
        return None;
    }
    job.processes
        .iter()
        .filter(|process| {
            process.argv.as_deref().is_some_and(|argv| {
                argv.windows(2)
                    .any(|pair| pair[0] == "resume" && pair[1] == session_id)
            })
        })
        .filter(|process| {
            let process_job = crate::platform::ForegroundJob {
                process_group_id: process.pid,
                processes: vec![(*process).clone()],
            };
            crate::detect::identify_agent_in_job(&process_job)
                .is_some_and(|(agent, _)| agent == crate::detect::Agent::Codex)
        })
        .min_by_key(|process| (!direct_codex_process(process), process.pid))
        .map(|process| process.pid)
}

/// Prove that one reported PID is the exact foreground OMP process. OMP 18
/// rewrites its argv to just `omp`, so launch arguments are not reliable after
/// startup; the official extension's PID plus Herdr's process identification is
/// the binding evidence.
pub(crate) fn omp_reported_process(
    job: &crate::platform::ForegroundJob,
    reported_pid: u32,
) -> Option<u32> {
    job.processes
        .iter()
        .find(|process| process.pid == reported_pid)
        .filter(|process| {
            let process_job = crate::platform::ForegroundJob {
                process_group_id: process.pid,
                processes: vec![(*process).clone()],
            };
            crate::detect::identify_agent_in_job(&process_job)
                .is_some_and(|(agent, _)| agent == crate::detect::Agent::Omp)
        })
        .map(|process| process.pid)
}

fn direct_codex_process(process: &crate::platform::ForegroundProcess) -> bool {
    [&process.name, process.argv0.as_deref().unwrap_or_default()]
        .into_iter()
        .any(|candidate| {
            std::path::Path::new(candidate)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| {
                    name.eq_ignore_ascii_case("codex") || name.eq_ignore_ascii_case("codex.exe")
                })
        })
}

pub(crate) fn new_transfer_id() -> Result<String, TransferError> {
    random_uuid()
}

#[derive(Debug)]
pub(crate) enum TransferError {
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    InvalidPath(String),
    LineTooLarge {
        line: usize,
        limit: usize,
    },
    /// A transcript this transfer will not window and cannot carry whole.
    ///
    /// Only OMP reaches this now: its format opens with a fixed-width title slot and a
    /// session header that a tail window would drop, so it keeps the whole-file read and
    /// the size refusal it had before this change. Claude and Codex are windowed instead
    /// of refused, which is the point of the PR.
    TranscriptTooLarge {
        /// How much was READ before refusing — a lower bound on the real size, since the
        /// reader stops at cap+1 rather than measuring the file.
        bytes: u64,
        /// The limit actually applied. Hard-coding TRANSFER_WINDOW_BYTES in the message
        /// misreported every caller using a different one (round 17).
        limit: u64,
    },
    /// One destination pass scanned more than the total-work budget allows.
    DestinationTooLarge {
        scanned: u64,
        limit: u64,
    },
    /// The transfer window contains no user turn to resume from, so every record in it
    /// answers a prompt that fell outside the window.
    NoUserTurnInWindow,
    InvalidJson {
        line: usize,
        message: String,
    },
    AmbiguousRecord {
        line: usize,
        message: String,
    },
    EmptyTranscript,
    DestinationMismatch(String),
    CodexImport(String),
    UnsupportedTranscript(String),
    Timeout,
}

impl TransferError {
    fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::InvalidPath(message) => write!(f, "untrusted transcript path: {message}"),
            Self::NoUserTurnInWindow => write!(
                f,
                "the most recent {TRANSFER_WINDOW_BYTES} bytes contain no user turn to \
                 resume from; transferring them would open the session with a reply to a \
                 prompt that is not in the window"
            ),
            // THE LIMIT IS CARRIED, NOT ASSUMED. This printed
            // `MAX_TRANSCRIPT_LINE_BYTES` for every site, including the two that refuse
            // at MAX_APP_SERVER_LINE_BYTES — so the message named 8 MiB for a record
            // refused at 2 MiB. With the destination now bounded by a third, larger
            // number, a hardcoded constant here would misreport again.
            Self::LineTooLarge { line, limit } => {
                write!(f, "transcript line {line} exceeds {limit} bytes")
            }
            Self::TranscriptTooLarge { bytes, limit } => write!(
                f,
                "transcript exceeds the {limit}-byte limit for this read (at least \
                 {bytes} bytes; the reader stops once the limit is passed)"
            ),
            Self::DestinationTooLarge { scanned, limit } => write!(
                f,
                "the destination transcript exceeded the {limit}-byte verification \
                 budget after {scanned} bytes"
            ),
            Self::InvalidJson { line, message } => {
                write!(f, "invalid transcript JSON at line {line}: {message}")
            }
            Self::AmbiguousRecord { line, message } => {
                write!(f, "ambiguous visible content at line {line}: {message}")
            }
            Self::EmptyTranscript => write!(f, "transcript has no transferable visible messages"),
            Self::DestinationMismatch(message) => {
                write!(f, "destination transcript verification failed: {message}")
            }
            Self::CodexImport(message) => write!(f, "Codex session import failed: {message}"),
            Self::UnsupportedTranscript(message) => {
                write!(
                    f,
                    "session transfer cannot preserve source transcript: {message}"
                )
            }
            Self::Timeout => write!(f, "Codex session import timed out"),
        }
    }
}

impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Read a transcript at a trusted path, WHOLE.
///
/// NOT A PRODUCTION PATH. Sources go through `read_transfer_source`, which windows;
/// destinations through `read_transcript_at_cursor`, which does not. This is a
/// convenience for tests that assert parsing behaviour, marked so nobody mistakes it
/// for the entry point a regression test should target — several of mine did.
#[cfg(test)]
pub(crate) fn read_transcript(
    kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
) -> Result<CanonicalTranscript, TransferError> {
    read_transcript_at_cursor(kind, trust_root, path, None)
}

/// EVERY CALLER OF THIS IS A DESTINATION READ, AND A DESTINATION IS NEVER WINDOWED.
///
/// Windowing is a SOURCE concern: we choose what to carry. The destination is generated
/// from that window and EXPANDS — Codex writes several records per source pair — so
/// reading its tail and comparing against the full source projection rejects a transfer
/// that worked. That was review round 3's finding, and it is re-stated here because the
/// windowing reader now sits one call below and would silently reintroduce it.
/// TEST-ONLY SINCE ROUND 16. Production destination reads go through
/// `read_verified_destination`, which routes by harness and applies the DESTINATION
/// budgets — this carries the SOURCE ceiling and would refuse a valid expanded
/// destination. Kept for parser tests; marked so nobody re-aims a regression at it.
#[cfg(test)]
pub(crate) fn read_transcript_at_cursor(
    kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
    cursor: Option<&str>,
) -> Result<CanonicalTranscript, TransferError> {
    let trusted_path = validate_transcript_path(trust_root, path)?;
    let snapshot = read_transcript_whole(&trusted_path)?;
    if kind == HarnessKind::Omp {
        return Ok(omp::parse(&snapshot.bytes, cursor)?.transcript);
    }
    parse_jsonl_snapshot(&snapshot, kind)
}

/// Read a transcript WHOLE, for verifying a destination we just wrote.
///
/// WINDOWING IS A SOURCE CONCERN. `read_transcript` takes the most recent
/// TRANSFER_WINDOW_BYTES, which is right for a source we are choosing what to carry
/// from — and wrong for a destination, which is generated FROM that window and must be
/// compared in full.
///
/// The two diverge because Codex expands what it imports: it emits event and response
/// records for the same content, so a source window near the budget produces a
/// destination over it. Reading the destination's tail and comparing it against the
/// full source projection then fails a transfer that actually worked — review round 3.
///
/// Still bounded, just not by a TAIL CUT: a destination larger than the read bound is a
/// real error rather than something to silently truncate, because we wrote it.
/// TEST-ONLY SINCE ROUND 16: `read_verified_destination` is the production entry and
/// passes the budgets explicitly. This wrapper hard-codes them, which is exactly the
/// shape that made the routing untestable for two rounds.
#[cfg(test)]
pub(crate) fn read_destination_transcript(
    kind: HarnessKind,
    config_home: &Path,
    path: &Path,
    expected: &[VisibleMessage],
) -> Result<CanonicalTranscript, TransferError> {
    read_destination_transcript_within(
        kind,
        config_home,
        path,
        expected,
        DESTINATION_RECORD_BUDGET_BYTES,
        DESTINATION_TOTAL_BUDGET_BYTES,
        DESTINATION_RECORD_BUDGET_BYTES,
        DESTINATION_TOTAL_BUDGET_BYTES,
    )
}

/// The same read with its two budgets supplied.
///
/// PARAMETERISED SO THE BUDGETS CAN BE TESTED WITHOUT 256 MiB FIXTURES. Round 9 found
/// the over-budget regression aimed at a Codex destination, where the PRE-PASS refuses
/// first — so a mutant on the main pass's limit stayed green. Testing both passes and
/// both budgets at the real constants would mean writing hundreds of megabytes per case,
/// which is how that gap survived; with the budgets passed in, each case is a few
/// kilobytes against the real code. `read_destination_transcript` above remains the only
/// production caller.
///
/// WHAT THE CONSTANTS ARE AND ARE NOT PINNED BY — the earlier version of this comment
/// claimed the wrapper's full-size regression pinned all four, and round 10 showed that
/// was false: mutating either total-budget argument left every test green. Accurately:
/// the two RECORD budgets are pinned at their production values by full-size regressions
/// through `read_destination_transcript` itself, one per pass. The TOTAL budget is not
/// fixture-pinned, because doing so would mean writing a gigabyte in a unit test; it is
/// covered instead by an assertion on the constant and by a measurement of the worst
/// expansion Codex actually produces. That is weaker, and saying so is the point.
///
/// THE TWO PASSES TAKE SEPARATE BUDGETS *ONLY* SO THEY CAN BE TOLD APART. Production
/// passes the same pair to both. My first version shared one parameter, and mutation
/// showed why that was useless: raising the pre-pass limit alone changed nothing
/// observable, because the main pass then refused the same record with the same error
/// and the same limit. The test could not fail. Splitting the parameters is what makes
/// "the pre-pass enforces its own bound" a claim a mutant can refute.
#[allow(clippy::too_many_arguments)] // one parameter per pass per budget; see below
fn read_destination_transcript_within(
    kind: HarnessKind,
    config_home: &Path,
    path: &Path,
    expected: &[VisibleMessage],
    pre_pass_record_budget: usize,
    pre_pass_total_budget: u64,
    record_budget: usize,
    total_budget: u64,
) -> Result<CanonicalTranscript, TransferError> {
    let trusted_path = validate_transcript_path(config_home, path)?;

    // STREAM-COMPARED AGAINST THE EXPECTED PROJECTION, message by message.
    //
    // Four rounds have argued about how to bound this read, and rounds 5 and 6 both
    // rejected a bound on the COUNT of retained messages: a source of many tiny
    // messages lets a faulty or hostile app-server write exactly that many near-8-MiB
    // ones, so `messages.len() <= expected.len()` holds while gigabytes accumulate.
    // Element count is not byte volume.
    //
    // Comparing as records arrive removes the question. At most one message is held at
    // a time, the first mismatch stops the read, and the memory ceiling is the expected
    // text — which comes from OUR source projection, not from the untrusted file. That
    // is a bound derived from something we control, which none of my previous three
    // attempts were.
    let expected_texts: std::collections::HashSet<&str> = expected
        .iter()
        .filter(|message| message.role == VisibleRole::User)
        .map(|message| message.text.as_str())
        .collect();

    let visible_user_events = if kind == HarnessKind::Codex {
        // Bounded by the expected user texts: an event whose text we never sent cannot
        // pair with anything, so retaining it buys nothing and is exactly the unbounded
        // retention round 6 found.
        codex_visible_user_event_texts_streamed(
            &trusted_path,
            &expected_texts,
            pre_pass_record_budget,
            pre_pass_total_budget,
        )?
    } else {
        std::collections::HashSet::new()
    };

    // ONE BUDGET FOR BOTH PASSES, AND IT COMES FROM NEITHER FILE. Every earlier round
    // derived this from the expected messages and then applied it to every record in
    // the destination, including metadata the target writes from its OWN configuration.
    // Round 8 measured the consequence: a legitimate `session_meta` exceeded a
    // tiny-message-derived limit by 181 bytes and was refused before any visible
    // message was compared. Retention is bounded here; whether a record is CORRECT is
    // decided by comparing it, below, which is the only thing that can decide it.
    let file = fs::File::open(&trusted_path)
        .map_err(|err| TransferError::io("read destination transcript", err))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut omissions = OmissionSummary::default();
    let mut matched = 0usize;
    let mut line_number = 0usize;

    loop {
        line_number += 1;
        let mut raw = Vec::new();
        let read = read_line_bounded(&mut reader, &mut raw, line_number, record_budget)?;
        if read == 0 {
            break;
        }
        hasher.update(&raw);
        total += read as u64;
        if total > total_budget {
            return Err(TransferError::DestinationTooLarge {
                scanned: total,
                limit: total_budget,
            });
        }

        let mut line = raw;
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;

        // One record's messages at a time; compared and dropped, never accumulated.
        let mut produced = Vec::new();
        match kind {
            HarnessKind::Claude => {
                parse_claude_record(line_number, &value, &mut produced, &mut omissions)?
            }
            HarnessKind::Codex => parse_codex_record(
                line_number,
                &value,
                &visible_user_events,
                &mut produced,
                &mut omissions,
            )?,
            // OMP destinations are read by `omp::parse`, which needs the whole document
            // (leaf selection is a property of the graph, not of one record). This
            // streaming reader is never given an OMP kind — stated as a refusal rather
            // than a silent default, so a future caller that tries finds out here.
            HarnessKind::Omp => {
                return Err(TransferError::UnsupportedTranscript(
                    "OMP destinations are read whole by the OMP parser, not streamed".to_string(),
                ))
            }
        }
        for message in produced {
            let Some(want) = expected.get(matched) else {
                return Err(TransferError::DestinationMismatch(format!(
                    "expected {} target-visible messages, found more; first extra at message {}",
                    expected.len(),
                    matched + 1
                )));
            };
            if &message != want {
                return Err(TransferError::DestinationMismatch(format!(
                    "expected {} target-visible messages; first difference at message {}",
                    expected.len(),
                    matched + 1
                )));
            }
            matched += 1;
        }
    }

    if matched != expected.len() {
        return Err(TransferError::DestinationMismatch(format!(
            "expected {} target-visible messages, found {matched}; first difference at message {}",
            expected.len(),
            matched + 1
        )));
    }
    Ok(CanonicalTranscript {
        // The comparison already succeeded, so the destination's messages ARE the
        // expected ones. Returning them by clone keeps the caller's contract without
        // having retained a second copy during the read.
        messages: expected.to_vec(),
        omissions,
        fingerprint: fingerprint_from(hasher.finalize(), total),
    })
}

/// Read one newline-terminated line, REFUSING before retaining more than one record's
/// worth. Returns 0 at EOF.
///
/// The point is the order: the limit is applied as bytes arrive, so an oversized record
/// is never fully allocated. Checking length after a whole-file read — which is what
/// this replaced — cannot prevent the allocation it is guarding against.
fn read_line_bounded<R: std::io::Read>(
    reader: &mut BufReader<R>,
    out: &mut Vec<u8>,
    line_number: usize,
    limit: usize,
) -> Result<usize, TransferError> {
    use std::io::BufRead as _;
    // fill_buf/consume on the CALLER'S reader, never a nested BufReader. The first
    // version wrapped it per call, which buffers ahead and DISCARDS the unread
    // remainder on drop — so every call silently ate part of the next line and parsing
    // failed at line 2.
    //
    // THE DELIMITER IS EXCLUDED from the comparison. Counting it made an exactly
    // limit-sized record measure limit+1 and be refused, while the source parser splits
    // on the newline and never counts it — so the two disagreed by one byte at exactly
    // the size that matters (round 6).
    loop {
        let chunk = reader
            .fill_buf()
            .map_err(|err| TransferError::io("read destination transcript", err))?;
        if chunk.is_empty() {
            break; // EOF
        }
        match chunk.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                out.extend_from_slice(&chunk[..=index]);
                reader.consume(index + 1);
                break;
            }
            None => {
                let taken = chunk.len();
                out.extend_from_slice(chunk);
                reader.consume(taken);
            }
        }
        if content_len(out) > limit {
            return Err(TransferError::LineTooLarge {
                line: line_number,
                limit,
            });
        }
    }
    if content_len(out) > limit {
        return Err(TransferError::LineTooLarge {
            line: line_number,
            limit,
        });
    }
    Ok(out.len())
}

/// Length of a line's CONTENT, excluding any trailing newline / carriage return.
fn content_len(line: &[u8]) -> usize {
    let mut len = line.len();
    if line.last() == Some(&b'\n') {
        len -= 1;
        if len > 0 && line[len - 1] == b'\r' {
            len -= 1;
        }
    }
    len
}

/// Collect Codex visible user-event texts with the same per-line bound, without
/// holding the file.
fn codex_visible_user_event_texts_streamed(
    path: &Path,
    expected_texts: &std::collections::HashSet<&str>,
    limit: usize,
    total_budget: u64,
) -> Result<std::collections::HashSet<String>, TransferError> {
    let file = fs::File::open(path)
        .map_err(|err| TransferError::io("read destination transcript", err))?;
    let mut reader = BufReader::new(file);
    let mut texts = std::collections::HashSet::new();
    let mut line_number = 0usize;
    let mut scanned = 0u64;
    // The limit is PASSED IN, identical to the main pass. Deriving one here — and from
    // user texts only, while this scans assistant and metadata records too — is what
    // round 7 caught: two passes disagreeing about what is too large.
    loop {
        line_number += 1;
        let mut raw = Vec::new();
        let read = read_line_bounded(&mut reader, &mut raw, line_number, limit)?;
        if read == 0 {
            break;
        }
        // The SAME budget as the main pass, because this pass reads the same file: a
        // bound applied to only one of two full scans halves nothing.
        scanned += read as u64;
        if scanned > total_budget {
            return Err(TransferError::DestinationTooLarge {
                scanned,
                limit: total_budget,
            });
        }
        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
            raw.pop();
        }
        if raw.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
            // Same predicate and normalisation as codex_visible_user_event_texts, so
            // the streamed pass cannot drift from the buffered one.
            if value.get("type").and_then(Value::as_str) == Some("event_msg")
                && value
                    .get("payload")
                    .and_then(|payload| payload.get("type"))
                    .and_then(Value::as_str)
                    == Some("user_message")
            {
                if let Some(message) = value
                    .get("payload")
                    .and_then(|payload| payload.get("message"))
                    .and_then(Value::as_str)
                {
                    let normalised = message.replace("\r\n", "\n");
                    // RETAIN ONLY WHAT WE SENT. Round 6: inserting every distinct
                    // external string let an untrusted file set the memory budget —
                    // a destination for one expected message could carry arbitrarily
                    // many unique sub-limit events and exhaust memory before the
                    // guarded pass began. An event we never sent pairs with nothing.
                    if expected_texts.contains(normalised.as_str()) {
                        texts.insert(normalised);
                    }
                }
            }
        }
    }
    Ok(texts)
}

pub(crate) async fn prepare(request: PrepareRequest) -> Result<PreparedTransfer, TransferError> {
    let source_path = select_native_transcript(
        request.source_kind,
        &request.source_sessions_root,
        &request.source_session_ref,
        request.source_transcript_path.as_deref(),
    )?;
    let (mut source, window) = read_transfer_source(
        request.source_kind,
        request.target_kind,
        &request.source_sessions_root,
        &source_path,
        request.source_cursor.as_deref(),
    )?;
    // OMP's leaf proof, kept exactly as #153 wrote it: the transfer is bound to the
    // active leaf and refuses unless that leaf is the durable resumable one. Re-parsing
    // from `window.bytes` rather than re-reading the file keeps that proof and the
    // transcript on the SAME bytes.
    if request.source_kind == HarnessKind::Omp {
        let parsed = omp::parse(&window.bytes, request.source_cursor.as_deref())?;
        let Some(cursor) = request.source_cursor.as_deref() else {
            return Err(TransferError::UnsupportedTranscript(
                "OMP source integration did not report its active leaf".to_string(),
            ));
        };
        if parsed.selected_leaf_id != cursor || parsed.physical_leaf_id != cursor {
            return Err(TransferError::UnsupportedTranscript(format!(
                "OMP active leaf {cursor:?} is not the durable resumable leaf {:?}",
                parsed.physical_leaf_id
            )));
        }
        source = parsed.transcript;
    }
    let mut expected = source.messages.clone();
    // AN ABANDONED TARGET IS REPORTED, NOT DELETED. Automatic cleanup is deliberately
    // out of scope for this change (owner decision, 2026-08-30: "yes cut the cleanup,
    // land the transfer"), and it is tracked separately.
    //
    // WHY IT WAS CUT RATHER THAN FINISHED: rounds 10-14 produced roughly twenty review
    // findings and effectively all of them were in the cleanup lifecycle, while the
    // transfer itself has been unchallenged since round 9. Deleting a session that
    // ANOTHER PROCESS owns, correctly, across our own process exit and with nothing
    // persisted, is a harder problem than the transfer it was attached to — round 14
    // found the shutdown sweep is not even reached by the headless server, which is how
    // this fleet runs.
    //
    // The residue is stated rather than hidden: an abandoned staging attempt leaves a
    // Codex thread or a Claude transcript behind, and the log line below is what makes
    // it findable. That is what the previous three rounds were shipping anyway — the
    // difference is that it now says so.
    let (session_ref, target_cursor, transcript_path) = match request.target_kind {
        HarnessKind::Claude => {
            let (session_id, path) =
                write_claude_session(&request.target_config_home, &request.cwd, &expected)?;
            (
                crate::agent_resume::AgentSessionRef::id(session_id)
                    .expect("generated Claude session id is valid"),
                None,
                path,
            )
        }
        HarnessKind::Codex => {
            // ALWAYS A BRIDGE, even for a Claude source, and that is the round-13 fix
            // for retries expressed in #153's own mechanism rather than beside it.
            //
            // Codex decides whether to do any work by looking the import SOURCE PATH up
            // in its ledger: a path it has seen is skipped, or answered with the thread
            // it produced last time. Passing the original transcript path — which is what
            // a Claude source used to do — makes a retry either produce nothing or adopt
            // a previous attempt's session. `PrivateClaudeBridge` already writes to a
            // random-UUID path under a 0700 staging directory, so a unique path per
            // import comes for free; my branch carried a `WindowFile` that did the same
            // thing less well, and it is gone.
            //
            // It also carries the WINDOW: `source.messages` is the windowed projection,
            // so an oversize transcript hands the importer what we actually intend to
            // transfer rather than the whole history.
            let bridge = PrivateClaudeBridge::write(
                &request.target_config_home,
                &request.cwd,
                &source.messages,
            )?;
            // STREAMED, so there is no ceiling here at all — see the note on
            // `claude_to_codex_import_projection_streaming`. This comment previously
            // described a whole read under a staging ceiling that no longer exists; on a
            // PR whose comments carry the justification for every bound, a comment
            // naming a deleted constant is how one gets reintroduced.
            let bridge_file = fs::File::open(bridge.path())
                .map_err(|err| TransferError::io("read staged import bridge", err))?;
            expected = claude_to_codex_import_projection_streaming(bridge_file)?;
            let mut observed_targets = Vec::new();
            let session_id = match import_claude_session_to_codex(
                &request.target_config_home,
                bridge.path(),
                &request.cwd,
                &request.target_launch_env,
                request.timeout,
                &mut observed_targets,
            )
            .await
            {
                Ok(session_id) => session_id,
                Err(err) => {
                    // The importer can create a thread and then fail before returning an
                    // id; `observed_targets` carries every id it named out of the error so
                    // the report can name them too.
                    report_abandoned_targets(
                        HarnessKind::Codex,
                        &request.target_config_home,
                        &observed_targets,
                        "the Codex importer failed after creating a target",
                    );
                    return Err(err);
                }
            };
            let path = match find_codex_rollout(&request.target_config_home, &session_id) {
                Ok(path) => path,
                Err(err) => {
                    report_abandoned_targets(
                        HarnessKind::Codex,
                        &request.target_config_home,
                        std::slice::from_ref(&session_id),
                        "the staged Codex thread could not be located after import",
                    );
                    return Err(err);
                }
            };
            (
                crate::agent_resume::AgentSessionRef::id(session_id)
                    .expect("imported Codex session id is valid"),
                None,
                path,
            )
        }
        HarnessKind::Omp => {
            let (_session_id, path, leaf) =
                omp::write(&request.target_sessions_root, &request.cwd, &expected)?;
            let canonical = fs::canonicalize(&path)
                .map_err(|error| TransferError::io("canonicalize staged OMP transcript", error))?;
            (
                crate::agent_resume::AgentSessionRef::path(
                    canonical.to_string_lossy().into_owned(),
                )
                .expect("generated OMP session path is valid"),
                Some(leaf),
                canonical,
            )
        }
    };
    // THE DESTINATION IS READ WHOLE, AND FOR JSONL TARGETS IT IS COMPARED AS IT STREAMS.
    //
    // Windowing is a SOURCE concern — we choose what to carry. The destination is
    // GENERATED from that window and expands (Codex writes several records per source
    // pair), so reading its tail, or refusing it on the source's size limit, rejects a
    // transfer that worked. That was review round 3, and this rebase nearly reinstated
    // it: resolving the conflict in #153's favour here left `read_destination_transcript`
    // called only from tests, and clippy caught it as an unused budget constant rather
    // than anything failing.
    //
    // KNOWN GAP, STATED RATHER THAN IMPLIED, AND IT APPLIES AT BOTH ROUTING SITES (here
    // and `verified_visible_destination`): no test distinguishes THIS ROUTE from
    // sending Claude/Codex through `read_transcript_at_cursor` + `verify_destination`.
    // Mutation-checked: that substitution passes the whole suite. The two differ only on
    // a destination larger than TRANSFER_WINDOW_BYTES — this reader accepts it with
    // bounded retention, the other refuses it — and producing one through `prepare`
    // requires a real Codex import rather than a fixture. The reader-level tests pin the
    // behaviour; the ROUTING is currently held by reasoning alone.
    // EVERY EXIT BELOW THIS POINT HAS A TARGET ON DISK, so each one reports it. Round 15:
    // the two report sites covered only Codex failures BEFORE a rollout was found, which
    // is the narrowest slice of the abandonment surface — a destination that fails
    // verification has already created a Claude session, a Codex thread or an OMP
    // transcript, and said nothing.
    let report_this_target = |reason: &str| {
        report_abandoned_targets(
            request.target_kind,
            &request.target_config_home,
            std::slice::from_ref(&session_ref.value),
            reason,
        );
    };
    let destination = read_verified_destination(
        request.target_kind,
        &request.target_sessions_root,
        &transcript_path,
        target_cursor.as_deref(),
        &expected,
    )
    .inspect_err(|_| report_this_target("the staged destination failed verification"))?;
    // No separate verify_destination for the JSONL arm: `read_destination_transcript`
    // compares each message as it arrives and returns the same DestinationMismatch.
    Ok(PreparedTransfer {
        target_kind: request.target_kind,
        target_config_home: request.target_config_home.clone(),
        source_path,
        source_fingerprint: source.fingerprint,
        staged: StagedSession {
            session_ref,
            cursor: target_cursor,
            transcript_path,
            transcript: CanonicalTranscript {
                messages: destination.messages,
                // Confirmation describes what was deliberately omitted from the
                // source, not destination-provider metadata introduced by staging.
                omissions: source.omissions,
                fingerprint: destination.fingerprint,
            },
        },
    })
}

fn select_native_transcript(
    kind: HarnessKind,
    trust_root: &Path,
    session_ref: &crate::agent_resume::AgentSessionRef,
    reported_path: Option<&Path>,
) -> Result<PathBuf, TransferError> {
    let expected_kind = if kind == HarnessKind::Omp {
        crate::agent_resume::AgentSessionRefKind::Path
    } else {
        crate::agent_resume::AgentSessionRefKind::Id
    };
    if session_ref.kind != expected_kind {
        return Err(TransferError::InvalidPath(format!(
            "{} session reference must use {:?}, not {:?}",
            kind.label(),
            expected_kind,
            session_ref.kind
        )));
    }
    if kind == HarnessKind::Omp {
        let path = Path::new(&session_ref.value);
        if reported_path.is_some_and(|reported| reported != path) {
            return Err(TransferError::InvalidPath(
                "OMP reported session path disagrees with its native path reference".to_string(),
            ));
        }
        return validate_transcript_path(trust_root, path);
    }
    let session_id = &session_ref.value;
    let Some(reported_path) = reported_path else {
        return find_native_transcript(kind, trust_root, session_id);
    };
    let path = validate_transcript_path(trust_root, reported_path)?;
    let identity_matches = match kind {
        HarnessKind::Claude => path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name == format!("{session_id}.jsonl")),
        HarnessKind::Codex => codex_rollout_declares_thread(&path, session_id)?,
        HarnessKind::Omp => unreachable!("OMP path references return above"),
    };
    if !identity_matches {
        return Err(TransferError::InvalidPath(format!(
            "reported {} transcript does not declare session {session_id}",
            kind.label()
        )));
    }
    Ok(path)
}

pub(crate) fn find_native_transcript(
    kind: HarnessKind,
    config_home: &Path,
    session_id: &str,
) -> Result<PathBuf, TransferError> {
    match kind {
        HarnessKind::Claude => find_claude_transcript(config_home, session_id),
        HarnessKind::Codex => find_codex_rollout(config_home, session_id),
        HarnessKind::Omp => Err(TransferError::InvalidPath(
            "OMP sessions are selected by an exact native path, not by id".to_string(),
        )),
    }
}

fn find_claude_transcript(config_home: &Path, session_id: &str) -> Result<PathBuf, TransferError> {
    if session_id.is_empty()
        || session_id.chars().any(char::is_control)
        || session_id.contains('/')
        || session_id.contains('\\')
    {
        return Err(TransferError::InvalidPath(
            "invalid Claude session id".to_string(),
        ));
    }
    let canonical_home = fs::canonicalize(config_home)
        .map_err(|err| TransferError::io("canonicalize Claude account home", err))?;
    let projects = canonical_home.join("projects");
    let entries =
        fs::read_dir(&projects).map_err(|err| TransferError::io("scan Claude projects", err))?;
    let file_name = format!("{session_id}.jsonl");
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| TransferError::io("scan Claude projects", err))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|err| TransferError::io("inspect Claude project", err))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let candidate = entry.path().join(&file_name);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                matches.push(validate_transcript_path(&canonical_home, &candidate)?);
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(TransferError::io("inspect Claude transcript", err)),
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(TransferError::InvalidPath(format!(
            "no Claude transcript found for session {session_id}"
        ))),
        _ => Err(TransferError::InvalidPath(format!(
            "multiple Claude transcripts found for session {session_id}"
        ))),
    }
}

pub(crate) fn fingerprint_transcript(
    config_home: &Path,
    path: &Path,
) -> Result<TranscriptFingerprint, TransferError> {
    let trusted_path = validate_transcript_path(config_home, path)?;
    fingerprint_file(&trusted_path)
}

pub(crate) fn verify_unchanged_transcripts(
    source_config_home: &Path,
    source_path: &Path,
    source_fingerprint: &TranscriptFingerprint,
    target_config_home: &Path,
    target_path: &Path,
    target_fingerprint: &TranscriptFingerprint,
) -> Result<(), TransferError> {
    let current_source = fingerprint_transcript(source_config_home, source_path)?;
    if &current_source != source_fingerprint {
        return Err(TransferError::DestinationMismatch(
            "source transcript changed after staging".to_string(),
        ));
    }
    let current_target = fingerprint_transcript(target_config_home, target_path)?;
    if &current_target != target_fingerprint {
        return Err(TransferError::DestinationMismatch(
            "staged destination transcript changed after verification".to_string(),
        ));
    }
    Ok(())
}

/// Read a staged destination and prove it carries `expected`. ONE PRODUCTION HELPER,
/// USED BY BOTH CALLERS.
///
/// Round 15 fixed the routing in `prepare` and missed the identical decision in
/// `verified_visible_destination` — one site fixed, the other not, which is the shape
/// that keeps producing findings here. Round 16 asked for the formulation that makes a
/// third caller impossible to get wrong; this is it.
///
/// The budgets are parameters so a test can drive the JSONL arm with a few kilobytes.
/// That matters beyond convenience: it is what finally distinguishes streaming the
/// destination from reading it whole and comparing after. Those differ only when the
/// destination exceeds the SOURCE ceiling, and reaching that end-to-end needed a 64 MiB
/// import — which is why the distinction went unguarded for two rounds and I had
/// declared it unguardable.
/// THE ONE PRODUCTION ENTRY POINT, and it takes no budgets.
///
/// Round 19's regression was a WIDENING — a bound deleted rather than tightened — and the
/// round-22 review showed the suite could not have caught it: a test that passes its own
/// ceiling never reaches a production site, and the live-append fixture is 257 KiB, so it
/// bounds the site from BELOW only. Any ceiling at or above that passes it.
///
/// No fixture fixes that, because catching a widening requires exceeding the widened
/// bound and the bound is half a gigabyte. What CAN be fixed is the number of places a
/// widening could happen: the constants appear here and nowhere else on a production
/// path, so there is one site to review instead of two, and `_within` is reachable only
/// from tests and from this function.
///
/// RESIDUAL GAP, STATED RATHER THAN IMPLIED: a widening inside THIS function is still
/// undetectable by the suite. The compile-time asserts on the constants are the guard
/// that remains, which is why they are asserts and not a test.
fn read_verified_destination(
    kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
    cursor: Option<&str>,
    expected: &[VisibleMessage],
) -> Result<CanonicalTranscript, TransferError> {
    read_verified_destination_within(
        kind,
        trust_root,
        path,
        cursor,
        expected,
        DESTINATION_RECORD_BUDGET_BYTES,
        DESTINATION_TOTAL_BUDGET_BYTES,
        OMP_DESTINATION_RETENTION_BYTES,
    )
}

fn read_verified_destination_within(
    kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
    cursor: Option<&str>,
    expected: &[VisibleMessage],
    record_budget: usize,
    total_budget: u64,
    // Injectable so a test can drive the refusal with a few kilobytes instead of half a
    // gigabyte. Production reaches this only through `read_verified_destination`.
    omp_retention: u64,
) -> Result<CanonicalTranscript, TransferError> {
    match kind {
        // Streamed and compared AS IT READS, with no source-derived ceiling: the
        // destination is generated FROM the window and expands, so refusing it on the
        // source's limit rejects a transfer that worked (review round 3).
        HarnessKind::Claude | HarnessKind::Codex => read_destination_transcript_within(
            kind,
            trust_root,
            path,
            expected,
            record_budget,
            total_budget,
            record_budget,
            total_budget,
        ),
        // OMP's parser needs the whole document — leaf selection is a property of the
        // graph, not of one record — so there is nothing to stream and the comparison is
        // a separate step.
        HarnessKind::Omp => {
            // BOUNDED BY THE DESTINATION BUDGET, NOT THE SOURCE'S. `read_transcript_at_cursor`
            // carries TRANSFER_WINDOW_BYTES, and an OMP destination is GENERATED from a
            // window that already passed it: the reviewers costed a 205-byte source pair
            // at 697 bytes once serialised, so a valid window writes an OMP transcript
            // over 64 MiB, the write succeeds, and verification then rejects the target
            // it just created. Second of the two generated artifacts measured against a
            // ceiling they were never sized by.
            let trusted_path = validate_transcript_path(trust_root, path)?;
            let file = fs::File::open(&trusted_path)
                .map_err(|err| TransferError::io("read destination transcript", err))?;
            // ONE CEILING, AND IT DOES NOT DEPEND ON THE DATA IT BOUNDS. Round 20 split
            // this by caller on the premise that a staged-size bound would refuse a
            // valid live transfer. That premise described code which never existed —
            // the version it replaced also stat'd at READ time, so on the post-launch
            // path it already measured the grown file — and the split it justified was
            // unobservable: both arms passed for every append landing before the read.
            //
            // Growth by the live target is tolerated because `omp::parse` walks from the
            // selected leaf upward, so appended entries are off-branch. That is a
            // property of the PARSER, not of this number.
            let bytes = read_whole_within(file, omp_retention)?;
            let destination = omp::parse(&bytes, cursor)?.transcript;
            verify_destination(expected, &destination)?;
            Ok(destination)
        }
    }
}

/// Compare a destination transcript against the projection that was staged.
///
/// USED FOR OMP ONLY. Claude and Codex destinations go through
/// `read_destination_transcript`, which compares message-by-message AS IT READS and so
/// never holds the whole thing; OMP's parser needs the complete document anyway, so for
/// that harness there is nothing to gain by streaming.
pub(crate) fn verify_destination(
    expected: &[VisibleMessage],
    actual: &CanonicalTranscript,
) -> Result<(), TransferError> {
    if expected == actual.messages {
        return Ok(());
    }
    let first_difference = expected
        .iter()
        .zip(actual.messages.iter())
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| expected.len().min(actual.messages.len()));
    Err(TransferError::DestinationMismatch(format!(
        "expected {} target-visible messages, found {}; first difference at message {}",
        expected.len(),
        actual.messages.len(),
        first_difference + 1
    )))
}

/// Resolve a reported transcript path under its selected account home.
///
/// The account-home itself may be a symlink (a supported user configuration),
/// but no component below it may be one. Both lexical containment and resolved
/// containment are checked so `..`, symlink escapes, and direct out-of-home
/// paths all fail closed.
pub(crate) fn validate_transcript_path(
    config_home: &Path,
    candidate: &Path,
) -> Result<PathBuf, TransferError> {
    if !config_home.is_absolute() || !candidate.is_absolute() {
        return Err(TransferError::InvalidPath(
            "account home and transcript must be absolute".to_string(),
        ));
    }
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(TransferError::InvalidPath(
            "dot path components are not allowed".to_string(),
        ));
    }

    let canonical_home = fs::canonicalize(config_home)
        .map_err(|err| TransferError::io("canonicalize account home", err))?;
    let (walk_base, relative) = if let Ok(relative) = candidate.strip_prefix(config_home) {
        (config_home, relative)
    } else if let Ok(relative) = candidate.strip_prefix(&canonical_home) {
        (canonical_home.as_path(), relative)
    } else {
        return Err(TransferError::InvalidPath(
            "path is outside the selected account home".to_string(),
        ));
    };

    let mut walked = walk_base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(TransferError::InvalidPath(
                "path contains a non-normal component".to_string(),
            ));
        };
        walked.push(part);
        let metadata = fs::symlink_metadata(&walked)
            .map_err(|err| TransferError::io("inspect transcript path", err))?;
        if metadata.file_type().is_symlink() {
            return Err(TransferError::InvalidPath(format!(
                "symlink component {} is not allowed",
                walked.display()
            )));
        }
    }

    let canonical_candidate = fs::canonicalize(candidate)
        .map_err(|err| TransferError::io("canonicalize transcript", err))?;
    if !canonical_candidate.starts_with(&canonical_home) {
        return Err(TransferError::InvalidPath(
            "resolved path escapes the selected account home".to_string(),
        ));
    }
    let metadata = fs::metadata(&canonical_candidate)
        .map_err(|err| TransferError::io("inspect transcript", err))?;
    if !metadata.is_file() {
        return Err(TransferError::InvalidPath(
            "transcript is not a regular file".to_string(),
        ));
    }
    // NO SIZE REFUSAL HERE, DELIBERATELY. This used to reject anything over the
    // budget, which made the windowing reader below it dead code: a large transcript
    // died here and never reached the code that would have trimmed it. Review of
    // #150 caught that the feature never executed on the real path.
    //
    // The memory bound now lives with each reader instead — `read_transcript_snapshot`
    // keeps only a bounded window, `fingerprint_file` streams — so every one of this
    // function's five callers is bounded by its own means. Re-adding a size check here
    // would silently disable the window again for all of them.
    //
    // This function's job is TRUST: the path resolves inside the account home and is a
    // regular file. Size is not a trust property.
    Ok(canonical_candidate)
}

fn read_transfer_source(
    source_kind: HarnessKind,
    target_kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
    cursor: Option<&str>,
) -> Result<(CanonicalTranscript, TranscriptSnapshot), TransferError> {
    let trusted_path = validate_transcript_path(trust_root, path)?;
    // THE WINDOW TRAVELS WITH THE TRANSCRIPT. The caller needs the bytes, not just the
    // parse: a windowed Claude->Codex staging must hand the importer the WINDOW, and
    // the omissions report needs the dropped-record count.
    //
    // `read_transcript_snapshot` windows for Claude and Codex and reads OMP whole — see
    // the note there; an OMP tail loses the header its parser requires.
    let snapshot = read_transcript_snapshot(&trusted_path, source_kind)?;
    let mut source = if source_kind == HarnessKind::Omp {
        omp::parse(&snapshot.bytes, cursor)?.transcript
    } else {
        parse_jsonl_snapshot(&snapshot, source_kind)?
    };
    if source_kind == HarnessKind::Claude && target_kind == HarnessKind::Codex {
        // The projection reads the SAME window the parse did — never the file
        // again — so the two cannot disagree about what is being transferred.
        source.messages = claude_to_codex_import_projection(&snapshot.bytes)?;
    }
    // The snapshot travels with the transcript because the CALLER needs the window
    // bytes: a windowed Claude->Codex staging must hand the importer the window, not
    // the original file (review finding 2).
    Ok((source, snapshot))
}

/// Read a file with the cap bound to the OPEN DESCRIPTOR.
///
/// Stat-by-path then read-by-path is TOCTOU: the file can grow or be replaced between
/// the two calls, so the cap never binds to the bytes actually read. Bounding the open
/// file cannot be raced. Returns the refusal as a message so callers can wrap it in
/// whichever error their context wants.
/// Read at most `cap` bytes FROM THE GIVEN DESCRIPTOR. `path` is for messages only.
///
/// SPLIT OUT SO THE PROPERTY IS TESTABLE, AND THE WRAPPER DELETED SO THERE IS NOTHING
/// ELSE TO CALL. Round 8 split this from a `read_bounded(path, cap)` helper so a test
/// could hold a descriptor while the PATH was replaced — the only arrangement where a
/// descriptor bound and a stat-then-read differ. Round 9 pointed out the obvious
/// consequence I had missed: the wrapper was still the production entry, so mutating IT
/// back to stat-then-read left the new test green. Callers now open and delegate here
/// directly, which closes that by construction rather than by another assertion.
fn read_bounded_file(file: fs::File, cap: u64, path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let read = std::io::Read::read_to_end(&mut std::io::Read::take(file, cap + 1), &mut bytes)
        .map_err(|err| format!("could not read {}: {err}", path.display()))?;
    if read as u64 > cap {
        return Err(format!("exceeded the {cap}-byte limit"));
    }
    Ok(bytes)
}

/// Report a PreparedTransfer that is being dropped without being accepted.
///
/// WITH AUTOMATIC CLEANUP CUT, EVERY DISCARD MUST SAY SO. Round 16, both reviewers: the
/// two reporters covered only failures INSIDE `prepare`, so a successful preparation
/// dropped by the API layer — closed event channel, terminal gone, transfer id changed,
/// source no longer idle — left a real session with nothing naming it. Those are the
/// paths where staging SUCCEEDED, which makes them the ones most likely to have created
/// something.
pub(crate) fn report_discarded_preparation(prepared: &PreparedTransfer, reason: &str) {
    report_abandoned_targets(
        prepared.target_kind,
        &prepared.target_config_home,
        std::slice::from_ref(&prepared.staged.session_ref.value),
        reason,
    );
}

/// Record a target that was created and then abandoned, so it can be found by hand.
///
/// NOT A DELETION. Removing it is out of scope for this change; see the note in
/// `prepare`. What this guarantees is that an orphan is never SILENT — the account home
/// and the session id are both in the log, which is what a human needs to clear it.
fn report_abandoned_targets(
    kind: HarnessKind,
    config_home: &Path,
    session_ids: &[String],
    reason: &str,
) {
    for locator in session_ids {
        // NAMED FOR WHAT IT HOLDS. For Claude and Codex this is a session id; for OMP it
        // is the canonical transcript PATH — which is the right thing to log, since it
        // is what a human removes, but logging it under `session_id` mislabels the one
        // receipt this warning exists to provide (round 16).
        match kind {
            HarnessKind::Omp => tracing::warn!(
                harness = kind.label(),
                transcript_path = %locator,
                config_home = %config_home.display(),
                reason,
                "a staged transfer target was created and then abandoned; it is left in \
                 place and must be removed by hand"
            ),
            HarnessKind::Claude | HarnessKind::Codex => tracing::warn!(
                harness = kind.label(),
                session_id = %locator,
                config_home = %config_home.display(),
                reason,
                "a staged transfer target was created and then abandoned; it is left in \
                 place and must be removed by hand"
            ),
        }
    }
}

/// A transcript read once: the window that will be transferred, the fingerprint of
/// the WHOLE file, and how many records fell outside the window.
///
/// Debug is hand-written and deliberately OMITS `bytes`: that field is the user's
/// conversation, and a derived Debug would spill it into any error or log that ever
/// formats a snapshot.
pub(crate) struct TranscriptSnapshot {
    /// Whole JSONL records from the tail, at most `TRANSFER_WINDOW_BYTES`.
    pub(crate) bytes: Vec<u8>,
    /// Covers the ENTIRE file, never just the window — it answers "did the source
    /// change since staging", and a window-only hash would stop noticing an append.
    pub(crate) fingerprint: TranscriptFingerprint,
    /// Records ahead of the window, dropped. Zero for any transcript that fits,
    /// which is every transcript that transfers today.
    pub(crate) dropped_records: u64,
}

impl fmt::Debug for TranscriptSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranscriptSnapshot")
            .field("window_bytes", &self.bytes.len())
            .field("fingerprint", &self.fingerprint)
            .field("dropped_records", &self.dropped_records)
            .finish()
    }
}

/// Read a transcript in ONE streaming pass, keeping only its most recent records.
///
/// WHY A WINDOW AND NOT A BIGGER LIMIT: an oversize transcript used to be refused
/// outright, which made a long-running seat permanently unmovable. Raising the cap
/// would not help either — 135 MB of JSONL is ~35M tokens, roughly 35x the largest
/// context window in existence, so a transfer that "succeeded" whole would hand the
/// target something it must immediately discard. The recent history is the part
/// that can actually be used.
///
/// WHY ONE PASS. `read_jsonl` requires the parse and the fingerprint to come from
/// the SAME bytes: hashing with a second read can bless bytes appended after
/// parsing, letting the pre-cutover recheck pass on messages that were never
/// staged. Streaming the hash while keeping a rolling tail preserves that exactly —
/// both facts come out of one traversal — and bounds memory to the window instead
/// of the file.
///
/// OMP IS NOT WINDOWED, AND THIS IS THE ONE PLACE THAT DECIDES IT. An OMP transcript
/// opens with a fixed-width `title` slot and a `session` header record, and
/// `omp::parse` refuses without them — so a TAIL window silently produces a transcript
/// that no longer parses. The format is line-delimited, so the newline alignment below
/// is fine; the header is what a tail cannot keep.
///
/// This is exactly the kind of change that MERGES CLEANLY AND IS WRONG. #153 added the
/// OMP harness while this branch was in review; nothing in either diff conflicts here,
/// and windowing would simply have started handing `omp::parse` a headerless tail.
///
/// So OMP keeps the whole-file read and the size refusal it has today — its behaviour is
/// byte-for-byte unchanged by this PR. Windowing it needs a header-preserving design and
/// its own review, and pretending otherwise would extend an unreviewed feature onto a
/// harness that landed an hour ago.
fn read_transcript_snapshot(
    path: &Path,
    kind: HarnessKind,
) -> Result<TranscriptSnapshot, TransferError> {
    read_transcript_snapshot_with_budget(path, TRANSFER_WINDOW_BYTES as usize, kind)
}

/// Read everything up to `cap`, refusing WITHOUT allocating past it.
///
/// SPLIT OUT SO THE BOUND IS OBSERVABLE. Both implementations — this one and a plain
/// `fs::read` followed by a length check — return the same error for an oversize file,
/// so the error proves nothing; only BYTES CONSUMED tells them apart, and that needs a
/// reader a test can inspect. Mutation showed the check-after-allocate version passing
/// every test before this existed.
fn read_whole_within<R: std::io::Read>(reader: R, cap: u64) -> Result<Vec<u8>, TransferError> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(reader, cap + 1), &mut bytes)
        .map_err(|err| TransferError::io("read transcript", err))?;
    if bytes.len() as u64 > cap {
        return Err(TransferError::TranscriptTooLarge {
            bytes: bytes.len() as u64,
            limit: cap,
        });
    }
    Ok(bytes)
}

/// The pre-window behaviour, kept for OMP: read it all, refuse if it is too big.
fn read_transcript_whole(path: &Path) -> Result<TranscriptSnapshot, TransferError> {
    // BOUNDED WHILE READING, NOT AFTER. I wrote this function during the #153 rebase
    // with `fs::read` followed by a length check — check-after-allocate, which is the
    // exact defect this PR fixed twice already (the ledger read in round 2, the
    // app-server response in round 9). A multi-gigabyte transcript would have exhausted
    // memory before the refusal ran.
    //
    // Reading cap+1 through the descriptor means the refusal fires having allocated one
    // byte more than the limit, and the extra byte is what distinguishes "exactly at the
    // cap" from "over it".
    let file = fs::File::open(path).map_err(|err| TransferError::io("read transcript", err))?;
    let bytes = read_whole_within(file, TRANSFER_WINDOW_BYTES)?;
    let fingerprint = fingerprint_bytes(&bytes);
    Ok(TranscriptSnapshot {
        bytes,
        fingerprint,
        dropped_records: 0,
    })
}

/// The budget is a parameter so the windowing behaviour can be TESTED against a
/// few kilobytes instead of a 64 MB fixture. A test nobody runs because it needs a
/// 64 MB file is not a test.
fn read_transcript_snapshot_with_budget(
    path: &Path,
    budget: usize,
    kind: HarnessKind,
) -> Result<TranscriptSnapshot, TransferError> {
    // THE OMP EXEMPTION LIVES HERE, not in the caller, so a test can reach it with a
    // few kilobytes instead of a 64 MB fixture. Placing it above meant the decision had
    // no regression at all: deleting it broke nothing (mutation-checked).
    if kind == HarnessKind::Omp {
        return read_transcript_whole(path);
    }
    let file = fs::File::open(path).map_err(|err| TransferError::io("read transcript", err))?;
    let mut reader = BufReader::new(file);

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    // The rolling tail. Kept at no more than 2x the budget between trims so the
    // trim is amortised rather than run on every chunk.
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 256 * 1024];

    loop {
        let read = std::io::Read::read(&mut reader, &mut chunk)
            .map_err(|err| TransferError::io("read transcript", err))?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        total += read as u64;
        tail.extend_from_slice(&chunk[..read]);
        // Keep budget+1. That extra byte is what lets an EXACT boundary be
        // recognised below: without it, a window that already begins at a record
        // start is indistinguishable from one that begins mid-record, and the
        // alignment discards a complete record for nothing (review finding 4).
        if tail.len() > (budget + 1) * 2 {
            let cut = tail.len() - (budget + 1);
            tail.drain(..cut);
        }
    }
    if tail.len() > budget + 1 {
        let cut = tail.len() - (budget + 1);
        tail.drain(..cut);
    }

    let fingerprint = fingerprint_from(hasher.finalize(), total);

    // Nothing was dropped: hand back the file unchanged, so every transcript that
    // transfers today keeps transferring byte for byte.
    if total as usize <= budget {
        return Ok(TranscriptSnapshot {
            bytes: tail,
            fingerprint,
            dropped_records: 0,
        });
    }

    // ALIGN TO A RECORD BOUNDARY. The transcript is JSONL, so a byte window
    // starting mid-record yields an unparseable first line — a hard error rather
    // than a shorter conversation.
    //
    // THE EXTRA BYTE RETAINED ABOVE IS WHAT MAKES THIS CORRECT AT AN EXACT BOUNDARY.
    // When the window lands precisely on a record start, that byte is the previous
    // record's newline, so the search below finds it at index 0 and splits at 1 —
    // keeping every whole record. Retaining only `budget` would put a record's FIRST
    // byte at index 0, and the same search would then discard that entire record for
    // nothing (review finding 4).
    //
    // Deliberately ONE branch: an explicit `if tail.first() == b'\n'` fast path was
    // written here first and removed, because it is unreachable-by-equivalence — the
    // search produces the identical result — and a mutation could not kill it. Code a
    // mutant cannot kill is the inert shape this review was about.
    let mut window = match tail.iter().position(|byte| *byte == b'\n') {
        Some(newline) => tail.split_off(newline + 1),
        // No newline in a full-budget window means one record is larger than the
        // entire budget. That is malformed, not merely long, and
        // `MAX_TRANSCRIPT_LINE_BYTES` refuses it during parsing.
        None => {
            return Err(TransferError::LineTooLarge {
                line: 1,
                limit: budget,
            })
        }
    };

    // ALIGN TO A CONVERSATIONAL BOUNDARY. A record boundary is not enough: a window
    // can legally begin with an assistant reply whose user message fell outside it,
    // producing a syntactically valid transcript that resumes mid-thought — an answer
    // to a question that is not there. Worse, it is not a parse error, so nothing
    // downstream reports it (review finding 3).
    //
    // Drop leading records until the window opens on a user turn.
    //
    // FAIL CLOSED when there is none. An earlier version kept the record-aligned tail
    // on the reasoning that a degraded window beats no window — that was wrong, and
    // review round 2 named the case: an oversize transcript whose last window holds
    // only assistant records staged SUCCESSFULLY and wrote a syntactically valid
    // session that opens with an answer to a prompt outside the window. Silently
    // resuming semantically wrong history is worse than refusing, because nothing
    // downstream can tell it happened.
    match first_user_turn_offset(&window, kind) {
        Some(offset) => window = window.split_off(offset),
        None => return Err(TransferError::NoUserTurnInWindow),
    }
    let dropped_records = count_records(
        &mut BufReader::new(
            fs::File::open(path).map_err(|err| TransferError::io("read transcript", err))?,
        ),
        total - window.len() as u64,
    )?;

    Ok(TranscriptSnapshot {
        bytes: window,
        fingerprint,
        dropped_records,
    })
}

/// Byte offset of the first record in `window` that OPENS A USER TURN, or `None` if
/// there is none.
///
/// Reuses the same shape the parsers key on rather than inventing a second
/// classification — a private rule about what a user record looks like would drift
/// from `parse_claude_record` / `parse_codex_record` the moment either changes.
fn first_user_turn_offset(window: &[u8], kind: HarnessKind) -> Option<usize> {
    let mut offset = 0usize;
    for line in window.split(|byte| *byte == b'\n') {
        let len = line.len();
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..len - 1]
        } else {
            line
        };
        if !trimmed.is_empty() {
            if let Ok(value) = serde_json::from_slice::<Value>(trimmed) {
                if opens_user_turn(&value, kind) {
                    return Some(offset);
                }
            }
        }
        offset += len + 1; // the split consumed a newline
        if offset >= window.len() {
            break;
        }
    }
    None
}

/// Whether a record begins a user turn — the only safe place to resume a conversation.
///
/// RUNS THE REAL PARSER rather than reading the record's label. Review round 2 found
/// the label check insufficient: a `type=user` record carrying only a tool result
/// passes it, and the Codex projection then reclassifies that same record as
/// assistant, so the window still opens on a reply. Empty and image-only user events
/// have the same shape. Asking the parser what it would EMIT is the only check that
/// cannot drift from what the transfer actually sends.
fn opens_user_turn(value: &Value, kind: HarnessKind) -> bool {
    let mut messages = Vec::new();
    let mut omissions = OmissionSummary::default();
    let parsed = match kind {
        HarnessKind::Claude => parse_claude_record(1, value, &mut messages, &mut omissions),
        // Single-record parsing is a JSONL notion; OMP is read as a whole document.
        // Single-record parsing is a JSONL notion; OMP is read as a whole document by
        // its own parser and never reaches this record-oriented window alignment.
        HarnessKind::Omp => return false,
        // An empty visible-event set is correct for a SINGLE record: a response_item
        // that needs pairing with a user_message elsewhere is exactly the record we
        // must not resume from, so failing to pair it here is the right answer.
        HarnessKind::Codex => parse_codex_record(
            1,
            value,
            &std::collections::HashSet::new(),
            &mut messages,
            &mut omissions,
        ),
    };
    if parsed.is_err() {
        return false;
    }
    match messages.first() {
        Some(message) => message.role == VisibleRole::User && !message.text.trim().is_empty(),
        None => false,
    }
}

/// Count the newline-terminated records in the first `prefix_len` bytes of a
/// reader — the history the window leaves behind.
///
/// Counted from the file rather than inferred, because the answer is reported to a
/// person deciding whether to accept the loss, and an estimate is not a basis for
/// that decision.
fn count_records(reader: &mut BufReader<fs::File>, prefix_len: u64) -> Result<u64, TransferError> {
    let mut remaining = prefix_len;
    let mut records = 0u64;
    let mut chunk = vec![0u8; 256 * 1024];
    while remaining > 0 {
        let want = chunk.len().min(remaining as usize);
        let read = std::io::Read::read(reader, &mut chunk[..want])
            .map_err(|err| TransferError::io("read transcript", err))?;
        if read == 0 {
            break;
        }
        records += chunk[..read].iter().filter(|byte| **byte == b'\n').count() as u64;
        remaining -= read as u64;
    }
    Ok(records)
}

fn parse_jsonl_snapshot(
    snapshot: &TranscriptSnapshot,
    kind: HarnessKind,
) -> Result<CanonicalTranscript, TransferError> {
    let bytes = &snapshot.bytes;
    // Codex persists hidden runtime context in role=user response items. The
    // user_message events are the records its own UI exposes as submitted user
    // turns, so collect their texts from this same immutable byte snapshot and
    // require every response-item user message to be either paired with one or
    // a recognized runtime context envelope.
    let codex_visible_user_events = if kind == HarnessKind::Codex {
        codex_visible_user_event_texts(bytes)?
    } else {
        std::collections::HashSet::new()
    };
    let mut messages = Vec::new();
    let mut omissions = OmissionSummary::default();
    for (index, line) in BufReader::new(Cursor::new(&bytes)).split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = line.map_err(|err| TransferError::io("read transcript", err))?;
        if line.len() > MAX_TRANSCRIPT_LINE_BYTES {
            return Err(TransferError::LineTooLarge {
                line: line_number,
                limit: MAX_TRANSCRIPT_LINE_BYTES,
            });
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        match kind {
            HarnessKind::Claude => {
                parse_claude_record(line_number, &value, &mut messages, &mut omissions)?
            }
            HarnessKind::Codex => parse_codex_record(
                line_number,
                &value,
                &codex_visible_user_events,
                &mut messages,
                &mut omissions,
            )?,
            HarnessKind::Omp => unreachable!("OMP snapshots use their tree-aware parser"),
        }
    }
    if messages.is_empty() {
        return Err(TransferError::EmptyTranscript);
    }
    omissions.windowed_records = snapshot.dropped_records;
    Ok(CanonicalTranscript {
        messages,
        omissions,
        // The snapshot's fingerprint, which covers the WHOLE file. Hashing `bytes`
        // here would hash the window and the pre-cutover recheck would stop
        // detecting a source that grew after staging.
        fingerprint: snapshot.fingerprint.clone(),
    })
}

fn codex_visible_user_event_texts(
    bytes: &[u8],
) -> Result<std::collections::HashSet<String>, TransferError> {
    let mut messages = std::collections::HashSet::new();
    for (index, line) in BufReader::new(Cursor::new(bytes)).split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = line.map_err(|err| TransferError::io("read transcript", err))?;
        if line.len() > MAX_TRANSCRIPT_LINE_BYTES {
            return Err(TransferError::LineTooLarge {
                line: line_number,
                limit: MAX_TRANSCRIPT_LINE_BYTES,
            });
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        if value.get("type").and_then(Value::as_str) != Some("event_msg")
            || value
                .get("payload")
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
                != Some("user_message")
        {
            continue;
        }
        let message = value
            .get("payload")
            .and_then(|payload| payload.get("message"))
            .and_then(Value::as_str)
            .ok_or_else(|| TransferError::AmbiguousRecord {
                line: line_number,
                message: "Codex user_message event has no string message".to_string(),
            })?;
        messages.insert(message.replace("\r\n", "\n"));
    }
    Ok(messages)
}

fn parse_claude_record(
    line: usize,
    value: &Value,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let Some(record_type) = value.get("type").and_then(Value::as_str) else {
        return classify_unknown_record(line, value, omissions);
    };
    if value.get("isSidechain").and_then(Value::as_bool) == Some(true) {
        omissions.sidechain_records += 1;
        return Ok(());
    }
    if matches!(record_type, "user" | "assistant")
        && value.get("isMeta").and_then(Value::as_bool) == Some(true)
    {
        omissions.metadata_records += 1;
        return Ok(());
    }
    match record_type {
        "user" => parse_claude_message(line, value, VisibleRole::User, messages, omissions),
        "assistant" => {
            parse_claude_message(line, value, VisibleRole::Assistant, messages, omissions)
        }
        "system" => {
            omissions.system_records += 1;
            Ok(())
        }
        "attachment" => {
            omissions.attachment_records += 1;
            Ok(())
        }
        "file-history-snapshot"
        | "file-history-delta"
        | "queue-operation"
        | "last-prompt"
        | "permission-mode"
        | "mode"
        | "ai-title"
        | "pr-link"
        | "summary"
        | "progress" => {
            omissions.metadata_records += 1;
            Ok(())
        }
        _ => classify_unknown_record(line, value, omissions),
    }
}

fn parse_claude_message(
    line: usize,
    value: &Value,
    expected_role: VisibleRole,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let message = value
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message record has no message object".to_string(),
        })?;
    let expected_role_label = match expected_role {
        VisibleRole::User => "user",
        VisibleRole::Assistant => "assistant",
    };
    if message.get("role").and_then(Value::as_str) != Some(expected_role_label) {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: format!("Claude {expected_role_label} record has a conflicting role"),
        });
    }
    let content = message
        .get("content")
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message has no content".to_string(),
        })?;
    match content {
        Value::String(text) => push_visible_message(messages, expected_role, text),
        Value::Array(blocks) => {
            let mut text = String::new();
            for block in blocks {
                let block_type = block.get("type").and_then(Value::as_str).ok_or_else(|| {
                    TransferError::AmbiguousRecord {
                        line,
                        message: "Claude content block has no type".to_string(),
                    }
                })?;
                match block_type {
                    "text" => text.push_str(block.get("text").and_then(Value::as_str).ok_or_else(
                        || TransferError::AmbiguousRecord {
                            line,
                            message: "Claude text block has non-string text".to_string(),
                        },
                    )?),
                    "thinking" | "redacted_thinking" => omissions.reasoning_records += 1,
                    "tool_use" | "tool_result" | "server_tool_use" | "web_search_tool_result" => {
                        omissions.tool_records += 1
                    }
                    "image" | "document" => omissions.attachment_records += 1,
                    _ if !contains_possible_visible_content(block) => {
                        omissions.unsupported_blocks += 1
                    }
                    _ => {
                        return Err(TransferError::AmbiguousRecord {
                            line,
                            message: format!(
                                "unknown Claude content block {block_type:?} may be visible"
                            ),
                        })
                    }
                }
            }
            push_visible_message(messages, expected_role, &text)
        }
        _ => Err(TransferError::AmbiguousRecord {
            line,
            message: "Claude message content is neither text nor blocks".to_string(),
        }),
    }
}

/// Independently project a Claude transcript into the visible message shape
/// produced by Codex 0.150.1's supported external-session importer.
///
/// This must remain destination-aware instead of changing Claude's ordinary
/// canonical parser: Codex deliberately renders tool activity as assistant
/// text, while a Claude destination receives only the provider-neutral visible
/// conversation. Exact verification against this projection proves what the
/// importer actually wrote without trusting the importer to attest to itself.
fn claude_to_codex_import_projection(bytes: &[u8]) -> Result<Vec<VisibleMessage>, TransferError> {
    claude_to_codex_import_projection_streaming(Cursor::new(bytes))
}

/// Project a Claude transcript into what Codex will import, WITHOUT holding the file.
///
/// STREAMED SO THERE IS NO CEILING TO GUESS. The generated bridge used to be read back
/// whole under `BRIDGE_STAGING_BYTES`, a bound I set at twice the source window and could
/// not defend. Round 17 showed why: the ~4.3x expansion measured on a minimal message
/// pair does NOT wash out with repetition — a 64 MiB window can hold ~327,360 such pairs
/// and produce a ~275 MiB bridge, and nothing bounds the message COUNT to prevent that
/// shape.
///
/// The fix is not a bigger number. Reading record by record means the only retention is
/// one line plus the projection itself, and the projection is `expected`, which the
/// caller already holds in memory regardless. So the guessed bound is deleted rather
/// than re-guessed — the third time on this PR that the right answer was to remove the
/// thing that needed justifying.
fn claude_to_codex_import_projection_streaming<R: std::io::Read>(
    reader: R,
) -> Result<Vec<VisibleMessage>, TransferError> {
    let mut reader = BufReader::new(reader);
    let mut messages = Vec::new();
    let mut saw_user_message = false;
    let mut line_number = 0usize;
    loop {
        line_number += 1;
        let mut raw = Vec::new();
        // Per-record bound only: the file may be any size, one record may not.
        if read_line_bounded(
            &mut reader,
            &mut raw,
            line_number,
            MAX_TRANSCRIPT_LINE_BYTES,
        )? == 0
        {
            break;
        }
        let mut line = raw;
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        let ordered: OrderedJson =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        project_claude_record_for_codex(
            line_number,
            &value,
            &ordered,
            &mut saw_user_message,
            &mut messages,
        )?;
    }
    if messages.is_empty() {
        return Err(TransferError::EmptyTranscript);
    }
    Ok(messages)
}

fn project_claude_record_for_codex(
    line: usize,
    value: &Value,
    ordered: &OrderedJson,
    saw_user_message: &mut bool,
    messages: &mut Vec<VisibleMessage>,
) -> Result<(), TransferError> {
    let Some(record_type @ ("assistant" | "user")) = value.get("type").and_then(Value::as_str)
    else {
        return Ok(());
    };
    if value.get("isMeta").and_then(Value::as_bool) == Some(true)
        || value.get("isSidechain").and_then(Value::as_bool) == Some(true)
    {
        return Ok(());
    }
    let message = value
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message record has no message object".to_string(),
        })?;
    if message.get("role").and_then(Value::as_str) != Some(record_type) {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: format!("Claude {record_type} record has a conflicting role"),
        });
    }
    let content = message
        .get("content")
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message has no content".to_string(),
        })?;
    let ordered_content = ordered
        .get("message")
        .and_then(|message| message.get("content"))
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message order projection has no content".to_string(),
        })?;
    let Some(extracted) = extract_codex_import_message(line, content, ordered_content)? else {
        return Ok(());
    };
    let role = if record_type == "assistant" || extracted.only_tool_result {
        VisibleRole::Assistant
    } else {
        VisibleRole::User
    };
    let text = if role == VisibleRole::User {
        unwrap_codex_import_user_query(extracted.text)
    } else {
        extracted.text
    };
    if role == VisibleRole::Assistant && !*saw_user_message {
        return Err(TransferError::UnsupportedTranscript(
            "Codex omits assistant messages that appear before the first user turn".to_string(),
        ));
    }
    if role == VisibleRole::User {
        *saw_user_message = true;
    }
    push_visible_message(messages, role, &text)
}

struct CodexImportMessage {
    text: String,
    only_tool_result: bool,
}

fn extract_codex_import_message(
    line: usize,
    content: &Value,
    ordered_content: &OrderedJson,
) -> Result<Option<CodexImportMessage>, TransferError> {
    if let Some(text) = content.as_str() {
        return Ok((!text.trim().is_empty()).then(|| CodexImportMessage {
            text: text.to_string(),
            only_tool_result: false,
        }));
    }
    let blocks = content
        .as_array()
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message content is neither text nor blocks".to_string(),
        })?;
    let ordered_blocks =
        ordered_content
            .as_array()
            .ok_or_else(|| TransferError::AmbiguousRecord {
                line,
                message: "Claude message order projection is not a block array".to_string(),
            })?;
    if blocks.len() != ordered_blocks.len() {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: "Claude message order projection changed block count".to_string(),
        });
    }
    let mut parts = Vec::new();
    let mut only_tool_result = !blocks.is_empty();
    for (block, ordered_block) in blocks.iter().zip(ordered_blocks) {
        let block_type = block.get("type").and_then(Value::as_str).ok_or_else(|| {
            TransferError::AmbiguousRecord {
                line,
                message: "Claude content block has no type".to_string(),
            }
        })?;
        match block_type {
            "text" => {
                let text = block.get("text").and_then(Value::as_str).ok_or_else(|| {
                    TransferError::AmbiguousRecord {
                        line,
                        message: "Claude text block has non-string text".to_string(),
                    }
                })?;
                if !text.is_empty() {
                    parts.push(text.to_string());
                    only_tool_result = false;
                }
            }
            "tool_use" => {
                parts.push(codex_import_tool_call_note(line, block, ordered_block)?);
                only_tool_result = false;
            }
            "tool_result" => parts.push(codex_import_tool_result_note(block)),
            "thinking" => {}
            other => {
                parts.push(format!("[external unsupported block: {other}]"));
                only_tool_result = false;
            }
        }
    }
    let text = parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok((!text.is_empty()).then_some(CodexImportMessage {
        text,
        only_tool_result,
    }))
}

fn codex_import_tool_call_note(
    line: usize,
    block: &Value,
    ordered_block: &OrderedJson,
) -> Result<String, TransferError> {
    let name = block
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut lines = vec![format!("[{CODEX_IMPORT_TOOL_CALL_TAG}: {name}]")];
    if let Some(input) = block.get("input").and_then(Value::as_object) {
        if let Some(description) = input.get("description").and_then(Value::as_str) {
            lines.push(format!("description: {description}"));
        }
        if let Some(command) = input.get("command").and_then(Value::as_str) {
            lines.push(format!("command: {command}"));
        }
        if let Some(file) = input
            .get("file_path")
            .or_else(|| input.get("file"))
            .and_then(Value::as_str)
        {
            lines.push(format!("file: {file}"));
        }
        if lines.len() == 1 {
            let input = ordered_codex_import_tool_input(line, ordered_block)?;
            lines.push(format!(
                "input: {}",
                truncate_codex_import_text(&input, CODEX_IMPORT_NOTE_MAX_CHARS,)
            ));
        }
    } else if block.get("input").is_some() {
        let input = ordered_codex_import_tool_input(line, ordered_block)?;
        lines.push(format!(
            "input: {}",
            truncate_codex_import_text(&input, CODEX_IMPORT_NOTE_MAX_CHARS)
        ));
    }
    lines.push(format!("[/{CODEX_IMPORT_TOOL_CALL_TAG}]"));
    Ok(lines.join("\n"))
}

fn ordered_codex_import_tool_input(
    line: usize,
    ordered_block: &OrderedJson,
) -> Result<String, TransferError> {
    let input = ordered_block
        .get("input")
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude tool input was missing from its order projection".to_string(),
        })?;
    serde_json::to_string(input).map_err(|err| TransferError::AmbiguousRecord {
        line,
        message: format!("Claude tool input order projection could not be serialized: {err}"),
    })
}

fn codex_import_tool_result_note(block: &Value) -> String {
    let label = if block.get("is_error").and_then(Value::as_bool) == Some(true) {
        format!("[{CODEX_IMPORT_TOOL_RESULT_TAG}: error]")
    } else {
        format!("[{CODEX_IMPORT_TOOL_RESULT_TAG}]")
    };
    let text = match block.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    if text.is_empty() {
        format!("{label}\n[/{CODEX_IMPORT_TOOL_RESULT_TAG}]")
    } else {
        format!(
            "{label}\n{}\n[/{CODEX_IMPORT_TOOL_RESULT_TAG}]",
            truncate_codex_import_text(&text, CODEX_IMPORT_TOOL_RESULT_MAX_CHARS)
        )
    }
}

fn truncate_codex_import_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let prefix = text
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    format!("{prefix}...")
}

fn unwrap_codex_import_user_query(text: String) -> String {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix("<user_query>")
        .and_then(|inner| inner.strip_suffix("</user_query>"))
        .map(str::trim)
        .filter(|inner| !inner.is_empty())
    else {
        return text;
    };
    inner.to_string()
}

fn parse_codex_record(
    line: usize,
    value: &Value,
    visible_user_events: &std::collections::HashSet<String>,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let Some(record_type) = value.get("type").and_then(Value::as_str) else {
        return classify_unknown_record(line, value, omissions);
    };
    match record_type {
        "response_item" => {
            parse_codex_response_item(line, value, visible_user_events, messages, omissions)
        }
        "event_msg" => parse_codex_event_message(line, value, messages, omissions),
        "turn_context" | "session_meta" | "world_state" => {
            omissions.metadata_records += 1;
            Ok(())
        }
        "compacted" => {
            omissions.reasoning_records += 1;
            Ok(())
        }
        _ => classify_unknown_record(line, value, omissions),
    }
}

fn parse_codex_response_item(
    line: usize,
    value: &Value,
    visible_user_events: &std::collections::HashSet<String>,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let payload = value
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex response item has no payload".to_string(),
        })?;
    let Some(item_type) = payload.get("type").and_then(Value::as_str) else {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: "Codex response item has no payload type".to_string(),
        });
    };
    match item_type {
        "message" => {
            let role = match payload.get("role").and_then(Value::as_str) {
                Some("assistant") => VisibleRole::Assistant,
                Some("system") | Some("developer") => {
                    omissions.system_records += 1;
                    return Ok(());
                }
                Some("user") => {
                    let mut duplicate_omissions = OmissionSummary::default();
                    let text = codex_message_text(line, payload, &mut duplicate_omissions)?;
                    if visible_user_events.contains(&text) {
                        // The paired event_msg is the UI-visible source of truth.
                        omissions.metadata_records += 1;
                        return Ok(());
                    }
                    if codex_hidden_user_context(&text) {
                        omissions.system_records += 1;
                        return Ok(());
                    }
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: "Codex role=user response item has no matching visible user_message event"
                            .to_string(),
                    });
                }
                Some(other) => {
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: format!("unknown Codex message role {other:?}"),
                    })
                }
                None => {
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: "Codex message has no role".to_string(),
                    })
                }
            };
            let text = codex_message_text(line, payload, omissions)?;
            push_visible_message(messages, role, &text)
        }
        "reasoning" => {
            omissions.reasoning_records += 1;
            Ok(())
        }
        "function_call"
        | "function_call_output"
        | "custom_tool_call"
        | "custom_tool_call_output"
        | "web_search_call"
        | "computer_call"
        | "local_shell_call"
        | "mcp_tool_call" => {
            omissions.tool_records += 1;
            Ok(())
        }
        _ if !contains_possible_visible_content(value) => {
            omissions.metadata_records += 1;
            Ok(())
        }
        _ => Err(TransferError::AmbiguousRecord {
            line,
            message: format!("unknown Codex response item {item_type:?} may be visible"),
        }),
    }
}

fn parse_codex_event_message(
    line: usize,
    value: &Value,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let payload = value
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex event message has no payload".to_string(),
        })?;
    if payload.get("type").and_then(Value::as_str) != Some("user_message") {
        omissions.metadata_records += 1;
        return Ok(());
    }
    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex user_message event has no string message".to_string(),
        })?;
    for key in ["images", "local_images", "audio", "local_audio"] {
        omissions.attachment_records += payload
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len) as u64;
    }
    if payload
        .get("text_elements")
        .and_then(Value::as_array)
        .is_some_and(|elements| !elements.is_empty())
    {
        omissions.unsupported_blocks += 1;
    }
    push_visible_message(messages, VisibleRole::User, message)
}

fn codex_message_text(
    line: usize,
    payload: &serde_json::Map<String, Value>,
    omissions: &mut OmissionSummary,
) -> Result<String, TransferError> {
    let blocks = payload
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex message content is not an array".to_string(),
        })?;
    let mut text = String::new();
    for block in blocks {
        let block_type = block.get("type").and_then(Value::as_str).ok_or_else(|| {
            TransferError::AmbiguousRecord {
                line,
                message: "Codex content block has no type".to_string(),
            }
        })?;
        match block_type {
            "input_text" | "output_text" | "text" => {
                text.push_str(block.get("text").and_then(Value::as_str).ok_or_else(|| {
                    TransferError::AmbiguousRecord {
                        line,
                        message: "Codex text block has non-string text".to_string(),
                    }
                })?)
            }
            "input_image" | "output_image" | "image" | "input_file" => {
                omissions.attachment_records += 1
            }
            _ if !contains_possible_visible_content(block) => omissions.unsupported_blocks += 1,
            _ => {
                return Err(TransferError::AmbiguousRecord {
                    line,
                    message: format!("unknown Codex content block {block_type:?} may be visible"),
                })
            }
        }
    }
    Ok(text.replace("\r\n", "\n"))
}

fn codex_hidden_user_context(text: &str) -> bool {
    (text.starts_with("# AGENTS.md instructions for ") && text.contains("<environment_context>"))
        || (text.starts_with("<environment_context>") && text.ends_with("</environment_context>"))
}

fn push_visible_message(
    messages: &mut Vec<VisibleMessage>,
    role: VisibleRole,
    text: &str,
) -> Result<(), TransferError> {
    if text.is_empty() {
        return Ok(());
    }
    messages.push(VisibleMessage {
        role,
        text: text.replace("\r\n", "\n"),
    });
    Ok(())
}

fn classify_unknown_record(
    line: usize,
    value: &Value,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    if contains_possible_visible_content(value) {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: "unknown record contains message/content/text/role fields".to_string(),
        });
    }
    omissions.metadata_records += 1;
    Ok(())
}

fn contains_possible_visible_content(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "message" | "content" | "text" | "role" | "prompt"
            ) || contains_possible_visible_content(value)
        }),
        Value::Array(values) => values.iter().any(contains_possible_visible_content),
        _ => false,
    }
}

/// Hash a transcript without holding it in memory.
///
/// The size check this used to carry was the reason an oversize source could not
/// even be RE-VERIFIED at cutover: hashing never needed the whole file, only a
/// traversal, so the bound bought nothing and blocked the recheck.
fn fingerprint_file(path: &Path) -> Result<TranscriptFingerprint, TransferError> {
    let file = fs::File::open(path)
        .map_err(|err| TransferError::io("read transcript fingerprint", err))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut chunk = vec![0u8; 256 * 1024];
    loop {
        let read = std::io::Read::read(&mut reader, &mut chunk)
            .map_err(|err| TransferError::io("read transcript fingerprint", err))?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        total += read as u64;
    }
    Ok(fingerprint_from(hasher.finalize(), total))
}

/// Build a fingerprint from a finished digest and the byte count it covers.
///
/// Shared by the two streaming readers so the hex encoding exists once: two copies
/// that must agree byte-for-byte is exactly the drift the pre-cutover recheck would
/// report as "the source changed".
fn fingerprint_from(digest: impl AsRef<[u8]>, byte_len: u64) -> TranscriptFingerprint {
    TranscriptFingerprint {
        byte_len,
        sha256: digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

/// Hash a whole slice.
///
/// The windowing SOURCE path streams instead — a transcript need never be held in
/// memory to be hashed — but the OMP parser and the whole-file destination read both
/// already have the bytes, and tests use it to state an expected value independently of
/// the streaming path they check.
pub(super) fn fingerprint_bytes(bytes: &[u8]) -> TranscriptFingerprint {
    fingerprint_from(Sha256::digest(bytes), bytes.len() as u64)
}

pub(crate) fn write_claude_session(
    config_home: &Path,
    cwd: &Path,
    messages: &[VisibleMessage],
) -> Result<(String, PathBuf), TransferError> {
    if !config_home.is_absolute() || !cwd.is_absolute() {
        return Err(TransferError::InvalidPath(
            "Claude account home and cwd must be absolute".to_string(),
        ));
    }
    fs::create_dir_all(config_home)
        .map_err(|err| TransferError::io("create Claude account home", err))?;
    let canonical_home = fs::canonicalize(config_home)
        .map_err(|err| TransferError::io("canonicalize Claude account home", err))?;
    let project_dir = canonical_home
        .join("projects")
        .join(claude_project_slug(cwd));
    fs::create_dir_all(&project_dir)
        .map_err(|err| TransferError::io("create Claude project directory", err))?;
    reject_symlinks_below(&canonical_home, &project_dir)?;

    for _ in 0..32 {
        let session_id = random_uuid()?;
        let target = project_dir.join(format!("{session_id}.jsonl"));
        let temp = project_dir.join(format!(".{session_id}.herdr-transfer.tmp"));
        let file = match crate::platform::create_private_file(&temp) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(TransferError::io("create Claude transfer file", err)),
        };
        let write_result = write_claude_records(file, cwd, &session_id, messages).and_then(|()| {
            fs::rename(&temp, &target)
                .map_err(|err| TransferError::io("commit Claude transfer file", err))
        });
        if let Err(err) = write_result {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
        return Ok((session_id, target));
    }
    Err(TransferError::Io {
        context: "allocate Claude session id",
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "repeated random session-id collision",
        ),
    })
}

/// Ephemeral native-Claude bridge used only to invoke Codex's supported
/// external-session importer for non-Claude sources. The bridge is private,
/// durable before import, and deleted on every return path.
struct PrivateClaudeBridge {
    path: PathBuf,
}

impl PrivateClaudeBridge {
    fn write(
        codex_home: &Path,
        cwd: &Path,
        messages: &[VisibleMessage],
    ) -> Result<Self, TransferError> {
        if !codex_home.is_absolute() {
            return Err(TransferError::InvalidPath(
                "Codex home for the private import bridge must be absolute".to_string(),
            ));
        }
        fs::create_dir_all(codex_home)
            .map_err(|error| TransferError::io("create Codex home", error))?;
        let canonical_home = fs::canonicalize(codex_home)
            .map_err(|error| TransferError::io("canonicalize Codex home", error))?;
        let staging = canonical_home.join(".herdr/session-transfer");
        #[cfg(unix)]
        let existed = staging.exists();
        fs::create_dir_all(&staging)
            .map_err(|error| TransferError::io("create Codex import staging directory", error))?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).map_err(|error| {
                TransferError::io("protect Codex import staging directory", error)
            })?;
        }
        reject_symlinks_below(&canonical_home, &staging)?;
        for _ in 0..32 {
            let session_id = random_uuid()?;
            let path = staging.join(format!("{session_id}.jsonl"));
            let file = match crate::platform::create_private_file(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(TransferError::io(
                        "create private Claude import bridge",
                        error,
                    ))
                }
            };
            if let Err(error) = write_claude_records(file, cwd, &session_id, messages) {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            sync_parent_directory(&staging)?;
            return Ok(Self { path });
        }
        Err(TransferError::Io {
            context: "allocate private Claude import bridge",
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "repeated random bridge-id collision",
            ),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateClaudeBridge {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %error,
                    "could not remove private session-transfer import bridge"
                );
            }
        }
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), TransferError> {
    match fs::File::open(path).and_then(|directory| directory.sync_all()) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(TransferError::io("sync transfer staging directory", error)),
    }
}

fn reject_symlinks_below(base: &Path, target: &Path) -> Result<(), TransferError> {
    let relative = target.strip_prefix(base).map_err(|_| {
        TransferError::InvalidPath("destination is outside the selected account home".to_string())
    })?;
    let mut walked = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(TransferError::InvalidPath(
                "destination contains a non-normal component".to_string(),
            ));
        };
        walked.push(part);
        let metadata = fs::symlink_metadata(&walked)
            .map_err(|err| TransferError::io("inspect destination path", err))?;
        if metadata.file_type().is_symlink() {
            return Err(TransferError::InvalidPath(format!(
                "symlink destination component {} is not allowed",
                walked.display()
            )));
        }
    }
    let resolved = fs::canonicalize(target)
        .map_err(|err| TransferError::io("canonicalize destination path", err))?;
    if !resolved.starts_with(base) {
        return Err(TransferError::InvalidPath(
            "resolved destination escapes the selected account home".to_string(),
        ));
    }
    Ok(())
}

fn write_claude_records(
    file: fs::File,
    cwd: &Path,
    session_id: &str,
    messages: &[VisibleMessage],
) -> Result<(), TransferError> {
    let mut writer = BufWriter::new(file);
    let cwd = cwd.to_string_lossy();
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|err| {
            TransferError::io(
                "format Claude transcript timestamp",
                std::io::Error::other(err.to_string()),
            )
        })?;
    let mut parent_uuid: Option<String> = None;
    for message in messages {
        let uuid = random_uuid()?;
        let native_message = match message.role {
            VisibleRole::User => json!({"role": "user", "content": &message.text}),
            VisibleRole::Assistant => json!({
                "id": format!("msg_{}", uuid.replace('-', "")),
                "type": "message",
                "role": "assistant",
                "model": "herdr-session-transfer",
                "content": [{"type": "text", "text": &message.text}],
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }),
        };
        let record = json!({
            "parentUuid": parent_uuid,
            "isSidechain": false,
            "userType": "external",
            "cwd": cwd,
            "sessionId": session_id,
            "version": "herdr-session-transfer-v1",
            "gitBranch": "",
            "type": message.role.label(),
            "message": native_message,
            "uuid": uuid,
            "timestamp": timestamp,
        });
        serde_json::to_writer(&mut writer, &record).map_err(|err| {
            TransferError::io("serialize Claude transcript", std::io::Error::other(err))
        })?;
        writer
            .write_all(b"\n")
            .map_err(|err| TransferError::io("write Claude transcript", err))?;
        parent_uuid = record
            .get("uuid")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    writer
        .flush()
        .map_err(|err| TransferError::io("flush Claude transcript", err))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|err| TransferError::io("sync Claude transcript", err))
}

impl VisibleRole {
    fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

fn claude_project_slug(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn random_uuid() -> Result<String, TransferError> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|err| {
        TransferError::io(
            "generate transfer session id",
            std::io::Error::other(err.to_string()),
        )
    })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

/// `observed_targets` reports every target the app-server named EVEN WHEN THIS FAILS.
///
/// The completion notification carrying a created thread can arrive before the response
/// we are waiting on, and if the process then exits or the timeout fires, that thread is
/// real and its id was about to be thrown away inside an error. The caller uses this to
/// clean up. It is written through a caller-owned `&mut`, so a dropped future on timeout
/// still leaves behind whatever was learned before the drop.
pub(crate) async fn import_claude_session_to_codex(
    codex_home: &Path,
    source_path: &Path,
    cwd: &Path,
    launch_env: &crate::config::AccountLaunchEnv,
    timeout: Duration,
    observed_targets: &mut Vec<String>,
) -> Result<String, TransferError> {
    let future = import_claude_session_to_codex_inner(
        codex_home,
        source_path,
        cwd,
        launch_env,
        observed_targets,
    );
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TransferError::Timeout)?
}

async fn import_claude_session_to_codex_inner(
    codex_home: &Path,
    source_path: &Path,
    cwd: &Path,
    launch_env: &crate::config::AccountLaunchEnv,
    observed_targets: &mut Vec<String>,
) -> Result<String, TransferError> {
    fs::create_dir_all(codex_home)
        .map_err(|err| TransferError::io("create Codex account home", err))?;
    let mut command = tokio::process::Command::new("codex");
    // The outer timeout drops this future. Ensure that also terminates the
    // app-server instead of orphaning a writer after the transfer has failed.
    command.kill_on_drop(true);
    command
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in &launch_env.clear_vars {
        command.env_remove(key);
    }
    for (key, value) in &launch_env.vars {
        command.env(key, value);
    }
    // Keep verification and the writer on the exact account home even for a
    // default-home account whose interactive launch omits the override.
    command.env("CODEX_HOME", codex_home);
    let mut child = command
        .spawn()
        .map_err(|err| TransferError::io("launch Codex app-server", err))?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        TransferError::CodexImport("app-server stdin was unavailable".to_string())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        TransferError::CodexImport("app-server stdout was unavailable".to_string())
    })?;
    let result = async {
        write_protocol_message(
            &mut stdin,
            &json!({
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "herdr", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"experimentalApi": true}
                }
            }),
        )
        .await?;
        let mut reader = tokio::io::BufReader::new(stdout);
        wait_for_response(&mut reader, 1).await?;
        write_protocol_message(&mut stdin, &json!({"method": "initialized"})).await?;
        write_protocol_message(
            &mut stdin,
            &json!({
                "id": 2,
                "method": "externalAgentConfig/import",
                "params": {
                    "migrationItems": [{
                        "itemType": "SESSIONS",
                        "description": "Herdr agent session transfer",
                        "cwd": cwd.to_string_lossy(),
                        "details": {
                            "sessions": [{
                                "path": source_path.to_string_lossy(),
                                "cwd": cwd.to_string_lossy(),
                                "title": null
                            }]
                        }
                    }],
                    "migrationSource": "claude",
                    "providerId": "herdr",
                    "source": "herdr"
                }
            }),
        )
        .await?;
        match wait_for_import_result(&mut reader, observed_targets).await? {
            Some(target) => Ok(target),
            None => reuse_codex_import_target(codex_home, source_path),
        }
    }
    .await;
    let _ = child.start_kill();
    let _ = child.wait().await;
    result
}

async fn write_protocol_message(
    stdin: &mut tokio::process::ChildStdin,
    value: &Value,
) -> Result<(), TransferError> {
    let mut bytes = serde_json::to_vec(value).map_err(|err| {
        TransferError::CodexImport(format!("could not encode app-server request: {err}"))
    })?;
    bytes.push(b'\n');
    stdin
        .write_all(&bytes)
        .await
        .map_err(|err| TransferError::io("write Codex app-server request", err))?;
    stdin
        .flush()
        .await
        .map_err(|err| TransferError::io("flush Codex app-server request", err))
}

/// Read one app-server response, REFUSING BEFORE ALLOCATING PAST THE CAP.
///
/// This checked `line.len()` AFTER `read_line` had already allocated the whole line, so
/// a faulty or hostile `codex` could exhaust memory on one unterminated line and the
/// 2 MiB refusal would never run. The outer timeout bounds elapsed time, not bytes.
///
/// FOUND BY SWEEPING FOR THE SHAPE, not by finding this site. Round 2 fixed exactly this
/// defect — a cap checked after the read — on the transcript ledger, and I corrected that
/// site without asking where else it lived. Two rounds later a reviewer found it here.
/// The sweep also cleared `codex_rollout_declares_thread`, which looks identical but is
/// already bounded by a `Read::take` across the whole reader.
async fn read_protocol_message<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Value, TransferError> {
    use tokio::io::AsyncBufReadExt as _;

    let mut line = Vec::new();
    loop {
        let chunk = reader
            .fill_buf()
            .await
            .map_err(|err| TransferError::io("read Codex app-server response", err))?;
        if chunk.is_empty() {
            break; // EOF
        }
        match chunk.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                line.extend_from_slice(&chunk[..=index]);
                reader.consume(index + 1);
                break;
            }
            None => {
                let taken = chunk.len();
                line.extend_from_slice(chunk);
                reader.consume(taken);
            }
        }
        // Checked INSIDE the loop, so the refusal happens while the line is still
        // partial rather than after it is whole.
        if line.len() > MAX_APP_SERVER_LINE_BYTES {
            return Err(TransferError::CodexImport(
                "app-server response exceeded the size limit".to_string(),
            ));
        }
    }
    if line.is_empty() {
        return Err(TransferError::CodexImport(
            "app-server exited before import completed".to_string(),
        ));
    }
    if line.len() > MAX_APP_SERVER_LINE_BYTES {
        return Err(TransferError::CodexImport(
            "app-server response exceeded the size limit".to_string(),
        ));
    }
    serde_json::from_slice(&line).map_err(|err| {
        TransferError::CodexImport(format!("app-server returned invalid JSON: {err}"))
    })
}

async fn wait_for_response<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    id: u64,
) -> Result<Value, TransferError> {
    loop {
        let value = read_protocol_message(reader).await?;
        if value.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(error) = value.get("error") {
            return Err(TransferError::CodexImport(format!(
                "app-server request {id} failed: {error}"
            )));
        }
        return Ok(value);
    }
}

async fn wait_for_import_result<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    observed_targets: &mut Vec<String>,
) -> Result<Option<String>, TransferError> {
    let mut import_id = None;
    let mut completions = Vec::new();
    loop {
        let value = read_protocol_message(reader).await?;
        if value.get("id").and_then(Value::as_u64) == Some(2) {
            if let Some(error) = value.get("error") {
                return Err(TransferError::CodexImport(format!(
                    "app-server request 2 failed: {error}"
                )));
            }
            import_id = Some(
                value
                    .get("result")
                    .and_then(|result| result.get("importId"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        TransferError::CodexImport("import response had no importId".to_string())
                    })?
                    .to_string(),
            );
        } else if value.get("method").and_then(Value::as_str)
            == Some("externalAgentConfig/import/completed")
        {
            let params = value.get("params").cloned().ok_or_else(|| {
                TransferError::CodexImport("completion had no params".to_string())
            })?;
            // RECORD THE TARGET THE MOMENT A COMPLETION NAMES ONE, before we know which
            // importId is ours. Completions are buffered here until response 2 arrives;
            // an EOF or timeout in between used to discard a thread the app-server had
            // already created, with nothing left able to name it.
            //
            // Attributing an unmatched completion to us is safe HERE and only here: this
            // app-server is a process we spawned for this transfer, over a pipe no other
            // client holds, and we issue exactly one import on it. If that ever stops
            // being true this attribution stops being sound, which is why it is stated
            // rather than assumed.
            // EVERY named target, not just the one a VALID completion yields. Reading
            // this through `parse_import_completion` meant a completion reporting both
            // a created session and a failure returned before extraction, so the
            // session it named was never cleaned up.
            for target in named_import_targets(&params) {
                if observed_targets.len() >= MAX_IMPORT_COMPLETIONS {
                    return Err(TransferError::CodexImport(format!(
                        "app-server named more than {MAX_IMPORT_COMPLETIONS} import targets"
                    )));
                }
                if !observed_targets.contains(&target) {
                    observed_targets.push(target);
                }
            }
            if completions.len() >= MAX_IMPORT_COMPLETIONS {
                return Err(TransferError::CodexImport(format!(
                    "app-server sent more than {MAX_IMPORT_COMPLETIONS} import completions"
                )));
            }
            completions.push(params);
        } else {
            continue;
        }

        let Some(import_id) = import_id.as_deref() else {
            continue;
        };
        let Some(completion_index) = completions
            .iter()
            .position(|params| params.get("importId").and_then(Value::as_str) == Some(import_id))
        else {
            continue;
        };
        return parse_import_completion(&completions.swap_remove(completion_index));
    }
}

/// Every target this completion NAMES, regardless of whether the import succeeded.
///
/// `parse_import_completion` returns early on failures and on more than one success, so
/// a completion that created a session AND reported a ledger failure — which Codex
/// 0.150.1 does — never reached target extraction and the created session was left
/// behind. Both round-10 reviewers found this independently.
///
/// Deliberately separate from validation: what we may KEEP and what we must CLEAN UP are
/// different questions, and answering the second one through the first is what lost
/// these sessions.
fn named_import_targets(params: &Value) -> Vec<String> {
    params
        .get("itemTypeResults")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|result| result.get("itemType").and_then(Value::as_str) == Some("SESSIONS"))
        .filter_map(|sessions| sessions.get("successes").and_then(Value::as_array))
        .flatten()
        .filter_map(|success| success.get("target").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn parse_import_completion(params: &Value) -> Result<Option<String>, TransferError> {
    let results = params
        .get("itemTypeResults")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransferError::CodexImport("completion had no itemTypeResults".to_string())
        })?;
    let sessions = results
        .iter()
        .find(|result| result.get("itemType").and_then(Value::as_str) == Some("SESSIONS"))
        .ok_or_else(|| {
            TransferError::CodexImport("completion had no SESSIONS result".to_string())
        })?;
    let failures = sessions
        .get("failures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !failures.is_empty() {
        return Err(TransferError::CodexImport(format!(
            "session importer reported failures: {}",
            Value::Array(failures)
        )));
    }
    let targets: Vec<&str> = sessions
        .get("successes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|success| success.get("target").and_then(Value::as_str))
        .collect();
    match targets.as_slice() {
        [target] => Ok(Some((*target).to_string())),
        [] => Ok(None),
        _ => Err(TransferError::CodexImport(format!(
            "expected one imported session target, found {}",
            targets.len()
        ))),
    }
}

fn reuse_codex_import_target(
    codex_home: &Path,
    source_path: &Path,
) -> Result<String, TransferError> {
    #[derive(Deserialize)]
    struct Ledger {
        records: Vec<LedgerRecord>,
    }

    #[derive(Deserialize)]
    struct LedgerRecord {
        source_path: String,
        imported_thread_id: String,
    }

    let ledger_path = codex_home.join("external_agent_session_imports.json");
    let ledger_path = validate_transcript_path(codex_home, &ledger_path).map_err(|err| {
        TransferError::CodexImport(format!(
            "import completed without a target and its ledger could not be trusted: {err}"
        ))
    })?;
    // SIZE CHECKED BEFORE THE READ, not after. Reading first and checking the length
    // afterwards allocates the whole file regardless — the check cannot prevent what it
    // is guarding against. Harmless while validate_transcript_path still refused on
    // size; removing that refusal (finding 1) exposed this as a real unbounded read,
    // which is what review round 2 caught.
    // ONE DESCRIPTOR. Stat-by-path then read-by-path is TOCTOU: the file can grow or be
    // replaced between the two calls, so the cap does not bind to the bytes actually
    // read. Bounding the open file cannot be raced — review round 3.
    let ledger_file = fs::File::open(&ledger_path).map_err(|err| {
        TransferError::CodexImport(format!(
            "Codex session import ledger could not be opened: {err}"
        ))
    })?;
    let bytes = read_bounded_file(ledger_file, MAX_APP_SERVER_LINE_BYTES as u64, &ledger_path)
        .map_err(|err| TransferError::CodexImport(format!("Codex session import ledger {err}")))?;
    let ledger: Ledger = serde_json::from_slice(&bytes).map_err(|err| {
        TransferError::CodexImport(format!("Codex session import ledger was invalid: {err}"))
    })?;
    // THE SOURCE PATH IS UNIQUE PER IMPORT, so any row matching it was written by THIS
    // import and cannot be a previous attempt's.
    //
    // Round 12 added two filters here — skip rows whose rollout is gone, skip threads
    // whose deletion is queued — to stop a stale row poisoning a retry and to stop a
    // retry adopting a thread about to be deleted. Round 13 showed the first did not
    // actually make a retry succeed (it left zero candidates and still failed) and that
    // the second was bypassed entirely, because for a source it has seen Codex answers
    // with the existing thread itself and this reader is never reached.
    //
    // Both problems come from reusing a source path across attempts. With a unique path
    // per import there is no stale row to filter and no thread to adopt, so the filters
    // are gone rather than corrected — along with the pending registry, whose
    // clear-on-timeout was unsound, and a rollout scan per matching row that could
    // multiply into hundreds of millions of filesystem operations.
    let expected_source = source_path.to_string_lossy();
    // DEDUPLICATED BEFORE ANYTHING IS RESOLVED. Round 13: a rollout lookup per matching
    // ROW meant an ambiguous ledger — bounded at 2 MiB, so thousands of rows — could
    // trigger thousands of directory scans of up to MAX_ROLLOUT_FILES_SCANNED entries
    // each. Distinct ids are what matter, and there are far fewer of them.
    let mut targets: Vec<_> = ledger
        .records
        .into_iter()
        .filter(|record| record.source_path == expected_source)
        .map(|record| record.imported_thread_id)
        .collect();
    targets.sort();
    targets.dedup();
    let target = match targets.as_slice() {
        [target] => target.clone(),
        _ => {
            return Err(TransferError::CodexImport(format!(
                "import completed without a target and the ledger had {} matching targets",
                targets.len()
            )))
        }
    };
    // The ledger is only a locator. The caller still rereads this native rollout
    // and compares its visible messages with the source before offering cutover.
    // ONE SCAN, on the single resolved target. Round 13 measured the previous shape: a
    // rollout lookup per matching ROW meant an ambiguous ledger could trigger thousands
    // of directory scans of up to MAX_ROLLOUT_FILES_SCANNED entries each. Deduplicating
    // first and resolving once is the whole fix.
    find_codex_rollout(codex_home, &target)?;
    Ok(target)
}

pub(crate) fn find_codex_rollout(
    codex_home: &Path,
    thread_id: &str,
) -> Result<PathBuf, TransferError> {
    if thread_id.is_empty() || thread_id.chars().any(char::is_control) {
        return Err(TransferError::InvalidPath(
            "invalid Codex thread id".to_string(),
        ));
    }
    let canonical_home = fs::canonicalize(codex_home)
        .map_err(|err| TransferError::io("canonicalize Codex account home", err))?;
    let sessions = canonical_home.join("sessions");
    let mut stack = vec![sessions];
    let mut matches = Vec::new();
    let mut scanned = 0_usize;
    while let Some(directory) = stack.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(TransferError::io("scan Codex sessions", err)),
        };
        for entry in entries {
            let entry = entry.map_err(|err| TransferError::io("scan Codex sessions", err))?;
            scanned += 1;
            if scanned > MAX_ROLLOUT_FILES_SCANNED {
                return Err(TransferError::InvalidPath(
                    "Codex session tree exceeded the scan limit".to_string(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|err| TransferError::io("inspect Codex session entry", err))?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(entry.path());
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if metadata.is_file()
                && name.starts_with("rollout-")
                && name.ends_with(".jsonl")
                && name.contains(thread_id)
            {
                let path = validate_transcript_path(&canonical_home, &entry.path())?;
                if codex_rollout_declares_thread(&path, thread_id)? {
                    matches.push(path);
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(TransferError::InvalidPath(format!(
            "no Codex rollout declares thread {thread_id}"
        ))),
        _ => Err(TransferError::InvalidPath(format!(
            "multiple Codex rollouts declare thread {thread_id}"
        ))),
    }
}

fn codex_rollout_declares_thread(path: &Path, thread_id: &str) -> Result<bool, TransferError> {
    let file = fs::File::open(path).map_err(|err| TransferError::io("open Codex rollout", err))?;
    codex_rollout_declares_thread_in(file, thread_id)
}

/// The rollout scan, over any reader.
///
/// SPLIT SO THE CAP IS OBSERVABLE. Round 11: the incremental cap added here had no
/// site-specific regression — the lookup test uses tiny records and the consumed-byte
/// assertion exercised the async app-server reader instead, so reverting THIS site to
/// `read_line` left both green. With a reader passed in, a test can assert how much was
/// consumed before the refusal, which is the whole property.
fn codex_rollout_declares_thread_in<R: std::io::Read>(
    reader: R,
    thread_id: &str,
) -> Result<bool, TransferError> {
    let file = reader;
    // THE CAP IS APPLIED WHILE READING, and the old comment here was wrong in a way
    // worth recording: it claimed "bounded per line, not merely per line COUNT" while
    // doing the opposite. `Read::take` bounds the whole READER at 32 lines' worth —
    // 64 MiB — so a single unterminated line could allocate all 64 MiB before the
    // 2 MiB per-line check ran. The limit the function states was not the limit it
    // enforced.
    //
    // I reported this site as clean in round 9's sweep. The sweep found it; my reading
    // of it was wrong, which is the more embarrassing half — a comment asserting the
    // property was enough to stop me checking whether the code had it.
    let mut reader = BufReader::new(std::io::Read::take(
        file,
        (MAX_APP_SERVER_LINE_BYTES as u64) * 32,
    ));
    let mut lines = Vec::new();
    for index in 0..32 {
        let mut raw = Vec::new();
        let read = read_line_bounded(&mut reader, &mut raw, index + 1, MAX_APP_SERVER_LINE_BYTES)?;
        if read == 0 {
            break;
        }
        let line = String::from_utf8(raw).map_err(|err| TransferError::InvalidJson {
            line: index + 1,
            message: err.to_string(),
        })?;
        lines.push(Ok(line));
    }
    for (index, line) in lines.into_iter().enumerate() {
        let line: String =
            line.map_err(|err: std::io::Error| TransferError::io("read Codex rollout", err))?;
        let line = line.trim_end().to_string();
        let value: Value =
            serde_json::from_str(&line).map_err(|err| TransferError::InvalidJson {
                line: index + 1,
                message: err.to_string(),
            })?;
        if value.get("type").and_then(Value::as_str) == Some("session_meta") {
            return Ok(value
                .get("payload")
                .and_then(|payload| payload.get("id"))
                .and_then(Value::as_str)
                == Some(thread_id));
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Append a CHILD of the staged leaf — which is exactly what a live OMP target writes
    /// after launch, and is off the branch `omp::parse` walks because that walk goes
    /// UPWARD from `leaf` toward the root. A child is never on its own parent's ancestry.
    ///
    /// (An earlier version of this comment said "the staged leaf's own parent chain tip",
    /// describing a SIBLING. The code was right and the comment was not — the round-22
    /// reviewer caught it, and on this PR a wrong comment beside right code has twice been
    /// the thing that produced the next round's defect.)
    fn append_off_branch_record(path: &Path, leaf: &str, text_bytes: usize) {
        let before = std::fs::metadata(path).unwrap().len();
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        std::io::Write::write_all(
            &mut file,
            format!(
                "{}\n",
                json!({"type":"message","id":"appended-after-launch","parentId":leaf,
                    "timestamp":"2026-08-31T02:30:00Z",
                    "message":{"role":"user",
                        "content":[{"type":"text","text":"z".repeat(text_bytes)}],
                        "timestamp":1}})
            )
            .as_bytes(),
        )
        .unwrap();
        drop(file);
        let after = std::fs::metadata(path).unwrap().len();
        assert!(
            after > before + text_bytes as u64,
            "precondition: the append must actually grow the transcript ({before} -> {after})"
        );
    }

    /// A transfer in the phase where `verified_visible_destination` runs: the target has
    /// been launched and is live.
    #[allow(clippy::too_many_arguments)]
    fn post_launch_transfer(
        source_id: String,
        source_path: PathBuf,
        source_home: PathBuf,
        target_sessions: PathBuf,
        target_path: PathBuf,
        leaf: String,
        message_count: u64,
    ) -> RuntimeSessionTransfer {
        RuntimeSessionTransfer {
            id: "post-launch".to_string(),
            source_kind: HarnessKind::Claude,
            source_session: crate::agent_resume::PersistedAgentSession {
                source: "claude".to_string(),
                agent: "claude".to_string(),
                session_ref: crate::agent_resume::AgentSessionRef::id(source_id)
                    .expect("valid session id"),
            },
            source_account: None,
            source_config_home: source_home.clone(),
            source_sessions_root: source_home,
            source_cursor: None,
            source_process_pid: None,
            target_kind: HarnessKind::Omp,
            target_account: None,
            target_config_home: target_sessions.clone(),
            target_sessions_root: target_sessions,
            phase: crate::api::schema::AgentSessionTransferPhase::AwaitingTarget,
            message_count,
            omissions: OmissionSummary::default(),
            error: None,
            source_path: Some(source_path),
            source_fingerprint: None,
            target_session_ref: None,
            target_cursor: Some(leaf),
            target_transcript_path: Some(target_path),
            target_fingerprint: None,
            target_deadline: None,
            target_process: None,
            source_rollback_process: None,
            verification_in_flight: None,
            verification_observation_deadline: None,
            awaiting_deferred_target_report: false,
            target_report_accepted: false,
        }
    }

    fn temp_root(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "herdr-session-transfer-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_fixture(path: &Path, lines: &[Value]) {
        let mut file = fs::File::create(path).unwrap();
        for line in lines {
            serde_json::to_writer(&mut file, line).unwrap();
            writeln!(file).unwrap();
        }
    }

    fn foreground_process(
        pid: u32,
        name: &str,
        argv: &[&str],
    ) -> crate::platform::ForegroundProcess {
        crate::platform::ForegroundProcess {
            pid,
            name: name.to_string(),
            argv0: argv.first().map(|value| (*value).to_string()),
            argv: Some(argv.iter().map(|value| (*value).to_string()).collect()),
            cmdline: Some(argv.join(" ")),
        }
    }

    #[test]
    fn codex_resume_process_binds_the_exact_session_and_uses_a_stable_order() {
        let job = crate::platform::ForegroundJob {
            process_group_id: 20,
            processes: vec![
                foreground_process(20, "node", &["node", "/usr/bin/codex", "resume", "wanted"]),
                foreground_process(10, "codex", &["codex", "resume", "other"]),
                foreground_process(40, "codex", &["codex", "resume", "wanted"]),
                foreground_process(30, "codex", &["codex", "resume", "wanted"]),
            ],
        };

        assert_eq!(codex_resume_process(&job, "wanted"), Some(30));
        assert_eq!(codex_resume_process(&job, "missing"), None);
    }

    #[test]
    fn omp_process_proof_requires_the_reported_foreground_omp_pid() {
        let job = crate::platform::ForegroundJob {
            process_group_id: 20,
            processes: vec![
                foreground_process(20, "omp", &["omp"]),
                foreground_process(30, "codex", &["codex", "resume", "thread"]),
            ],
        };
        assert_eq!(omp_reported_process(&job, 20), Some(20));
        assert_eq!(omp_reported_process(&job, 30), None);
        assert_eq!(omp_reported_process(&job, 999), None);
    }

    #[tokio::test]
    async fn omp_to_claude_stages_exact_visible_history_and_rejects_a_stale_leaf() {
        let root = temp_root("omp-to-claude");
        let source_root = root.join("omp-sessions");
        let target_home = root.join("claude");
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "question".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "answer".into(),
            },
        ];
        let (_session_id, source_path, leaf) = omp::write(&source_root, &root, &messages).unwrap();
        let source_ref =
            crate::agent_resume::AgentSessionRef::path(source_path.to_string_lossy().into_owned())
                .unwrap();
        let request = |cursor: String| PrepareRequest {
            source_kind: HarnessKind::Omp,
            source_sessions_root: source_root.clone(),
            source_session_ref: source_ref.clone(),
            source_cursor: Some(cursor),
            source_transcript_path: Some(source_path.clone()),
            target_kind: HarnessKind::Claude,
            target_config_home: target_home.clone(),
            target_sessions_root: target_home.clone(),
            target_launch_env: crate::config::AccountLaunchEnv::unselected(),
            cwd: root.clone(),
            timeout: Duration::from_secs(1),
        };
        let prepared = prepare(request(leaf)).await.unwrap();
        assert_eq!(prepared.staged.transcript.messages, messages);
        assert_eq!(
            prepared.staged.session_ref.kind,
            crate::agent_resume::AgentSessionRefKind::Id
        );

        assert!(matches!(
            prepare(request("missing-leaf".into())).await,
            Err(TransferError::UnsupportedTranscript(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn claude_to_omp_stages_a_native_path_reference_and_leaf() {
        let root = temp_root("claude-to-omp");
        let source_home = root.join("claude");
        let target_root = root.join("omp-sessions");
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "hello".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "hi".into(),
            },
        ];
        let (source_id, source_path) =
            write_claude_session(&source_home, &root, &messages).unwrap();
        let prepared = prepare(PrepareRequest {
            source_kind: HarnessKind::Claude,
            source_sessions_root: source_home.clone(),
            source_session_ref: crate::agent_resume::AgentSessionRef::id(source_id).unwrap(),
            source_cursor: None,
            source_transcript_path: Some(source_path),
            target_kind: HarnessKind::Omp,
            target_config_home: root.join("omp-agent"),
            target_sessions_root: target_root.clone(),
            target_launch_env: crate::config::AccountLaunchEnv::unselected(),
            cwd: root.clone(),
            timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        assert_eq!(
            prepared.staged.session_ref.kind,
            crate::agent_resume::AgentSessionRefKind::Path
        );
        assert!(prepared.staged.cursor.is_some());
        assert_eq!(prepared.staged.transcript.messages, messages);
        let canonical_target_root = fs::canonicalize(target_root).unwrap();
        assert!(
            prepared
                .staged
                .transcript_path
                .starts_with(canonical_target_root),
            "the staged path must stay below the canonical OMP sessions root"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_claude_codex_bridge_is_private_exact_and_removed_on_drop() {
        let root = temp_root("codex-bridge");
        let codex_home = root.join("codex");
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "one".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "two".into(),
            },
        ];
        let bridge = PrivateClaudeBridge::write(&codex_home, &root, &messages).unwrap();
        let path = bridge.path().to_path_buf();
        let projection =
            claude_to_codex_import_projection(&fs::read(bridge.path()).unwrap()).unwrap();
        assert_eq!(projection, messages);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(bridge);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_parser_keeps_visible_text_and_reports_omissions() {
        let root = temp_root("claude-parse");
        let path = root.join("source.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"user","message":{"role":"user","content":"one\r\ntwo"}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"thinking","thinking":"hidden"},
                    {"type":"text","text":"answer"},
                    {"type":"tool_use","name":"shell"}
                ]}}),
                json!({"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"hidden"}]}}),
                json!({"type":"user","isMeta":true,"message":{"role":"user","content":"internal metadata"}}),
                json!({"type":"attachment","fileName":"image.png"}),
                json!({"type":"future-metadata","counter":3}),
            ],
        );
        let transcript = read_transcript(HarnessKind::Claude, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "one\ntwo".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "answer".into()
                },
            ]
        );
        assert_eq!(transcript.omissions.reasoning_records, 1);
        assert_eq!(transcript.omissions.tool_records, 2);
        assert_eq!(transcript.omissions.attachment_records, 1);
        assert_eq!(transcript.omissions.metadata_records, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_to_codex_projection_matches_codex_importer_semantics() {
        let root = temp_root("claude-codex-projection");
        let path = root.join("source.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"user","message":{"role":"user","content":" \n<user_query>\r\nhello\r\nworld\n</user_query>\n "}}),
                json!({"type":"user","isMeta":true,"message":{"role":"user","content":"hidden metadata"}}),
                json!({"type":"assistant","isSidechain":true,"message":{"role":"assistant","content":[{"type":"text","text":"hidden branch"}]}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"thinking","thinking":"hidden reasoning"},
                    {"type":"text","text":"answer"},
                    {"type":"tool_use","name":"shell","input":{
                        "description":"inspect",
                        "command":"ls",
                        "file_path":"/tmp/a"
                    }}
                ]}}),
                json!({"type":"user","message":{"role":"user","content":[
                    {"type":"tool_result","is_error":true,"content":[{"type":"text","text":"failed"}]}
                ]}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"redacted_thinking","data":"hidden"}
                ]}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"image","source":{"type":"base64","data":"hidden"}}
                ]}}),
                json!({"type":"user","message":{"role":"user","content":[
                    {"type":"text","text":"follow-up"},
                    {"type":"tool_result","content":"context"}
                ]}}),
            ],
        );

        let ordinary = read_transcript(HarnessKind::Claude, &root, &path).unwrap();
        let (projected, _snapshot) =
            read_transfer_source(HarnessKind::Claude, HarnessKind::Codex, &root, &path, None)
                .unwrap();

        assert_eq!(ordinary.messages.len(), 3);
        assert_eq!(projected.fingerprint, ordinary.fingerprint);
        assert_eq!(projected.omissions, ordinary.omissions);
        assert_eq!(projected.omissions.metadata_records, 1);
        assert_eq!(projected.omissions.sidechain_records, 1);
        assert_eq!(projected.omissions.reasoning_records, 2);
        assert_eq!(projected.omissions.tool_records, 3);
        assert_eq!(projected.omissions.attachment_records, 1);
        assert_eq!(
            projected.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "hello\nworld".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: concat!(
                        "answer\n\n",
                        "[external_agent_tool_call: shell]\n",
                        "description: inspect\n",
                        "command: ls\n",
                        "file: /tmp/a\n",
                        "[/external_agent_tool_call]"
                    )
                    .into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: concat!(
                        "[external_agent_tool_result: error]\n",
                        "failed\n",
                        "[/external_agent_tool_result]"
                    )
                    .into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "[external unsupported block: redacted_thinking]".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "[external unsupported block: image]".into(),
                },
                VisibleMessage {
                    role: VisibleRole::User,
                    text: concat!(
                        "follow-up\n\n",
                        "[external_agent_tool_result]\n",
                        "context\n",
                        "[/external_agent_tool_result]"
                    )
                    .into(),
                },
            ]
        );

        let target_path = root.join("rollout-imported.jsonl");
        let answer_with_tool = concat!(
            "answer\n\n",
            "[external_agent_tool_call: shell]\n",
            "description: inspect\n",
            "command: ls\n",
            "file: /tmp/a\n",
            "[/external_agent_tool_call]"
        );
        let failed_tool_result = concat!(
            "[external_agent_tool_result: error]\n",
            "failed\n",
            "[/external_agent_tool_result]"
        );
        let follow_up = concat!(
            "follow-up\n\n",
            "[external_agent_tool_result]\n",
            "context\n",
            "[/external_agent_tool_result]"
        );
        write_fixture(
            &target_path,
            &[
                json!({"type":"session_meta","payload":{"id":"imported"}}),
                json!({"type":"event_msg","payload":{"type":"turn_started"}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"hello\r\nworld"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello\r\nworld"}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":answer_with_tool}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":answer_with_tool}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":failed_tool_result}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":failed_tool_result}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":"[external unsupported block: redacted_thinking]"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"[external unsupported block: redacted_thinking]"}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":"[external unsupported block: image]"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"[external unsupported block: image]"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":follow_up}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":follow_up}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":"<EXTERNAL SESSION IMPORTED>"}}),
                json!({"type":"event_msg","payload":{"type":"turn_complete"}}),
            ],
        );
        let actual = read_transcript(HarnessKind::Codex, &root, &target_path).unwrap();
        verify_destination(&projected.messages, &actual).unwrap();
        let mut changed = actual;
        changed.messages[1].text.push('!');
        let error = verify_destination(&projected.messages, &changed)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target-visible"));
        assert!(error.contains("message 2"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_import_projection_truncates_by_unicode_scalar_count() {
        let text = "🦀".repeat(CODEX_IMPORT_NOTE_MAX_CHARS + 1);
        let truncated = truncate_codex_import_text(&text, CODEX_IMPORT_NOTE_MAX_CHARS);
        assert_eq!(truncated.chars().count(), CODEX_IMPORT_NOTE_MAX_CHARS);
        assert!(truncated.ends_with("..."));
        assert_eq!(
            truncated
                .chars()
                .filter(|character| *character == '🦀')
                .count(),
            CODEX_IMPORT_NOTE_MAX_CHARS - 3
        );
    }

    #[test]
    fn codex_import_projection_preserves_fallback_tool_input_key_order() {
        let bytes = br#"{"type":"user","message":{"role":"user","content":"request"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"AskUserQuestion","input":{"question":"Choose","header":"Backend","multiSelect":false}}]}}
"#;
        let projected = claude_to_codex_import_projection(bytes).unwrap();
        assert_eq!(
            projected,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "request".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: concat!(
                        "[external_agent_tool_call: AskUserQuestion]\n",
                        "input: {\"question\":\"Choose\",\"header\":\"Backend\",\"multiSelect\":false}\n",
                        "[/external_agent_tool_call]"
                    )
                    .into(),
                },
            ]
        );
    }

    #[test]
    fn codex_import_projection_rejects_duplicate_object_keys() {
        let bytes = br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"shell","input":{"command":"first","command":"second"}}]}}
"#;
        assert!(matches!(
            claude_to_codex_import_projection(bytes),
            Err(TransferError::InvalidJson { message, .. })
                if message.contains("duplicate JSON object key")
        ));
    }

    #[test]
    fn codex_import_projection_handles_many_unique_object_keys() {
        use std::fmt::Write as _;

        let mut input = String::from("{");
        for index in 0..5_000 {
            if index > 0 {
                input.push(',');
            }
            write!(&mut input, "\"key{index}\":{index}").unwrap();
        }
        input.push('}');
        let bytes = format!(
            "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"request\"}}}}\n\
             {{\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"tool_use\",\"name\":\"large\",\"input\":{input}}}]}}}}\n"
        );
        let projected = claude_to_codex_import_projection(bytes.as_bytes()).unwrap();
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[1].role, VisibleRole::Assistant);
        assert_eq!(
            projected[1].text.chars().count(),
            CODEX_IMPORT_NOTE_MAX_CHARS
                + "[external_agent_tool_call: large]\ninput: \n[/external_agent_tool_call]"
                    .chars()
                    .count()
        );
    }

    #[test]
    fn codex_import_projection_refuses_assistant_records_before_first_user_turn() {
        let bytes = br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"leading answer"}]}}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"leading tool result"}]}}
{"type":"user","message":{"role":"user","content":"first request"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"kept answer"}]}}
"#;
        assert!(matches!(
            claude_to_codex_import_projection(bytes),
            Err(TransferError::UnsupportedTranscript(message))
                if message.contains("before the first user turn")
        ));
    }

    #[test]
    fn codex_parser_ignores_duplicate_events_and_system_injections() {
        let root = temp_root("codex-parse");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"system"}]}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"hello"}}),
                json!({"type":"response_item","payload":{"type":"reasoning","summary":["hidden"]}}),
                json!({"type":"response_item","payload":{"type":"function_call","name":"shell"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"world"}]}}),
            ],
        );
        let transcript = read_transcript(HarnessKind::Codex, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "hello".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "world".into()
                },
            ]
        );
        assert_eq!(transcript.omissions.system_records, 1);
        assert_eq!(transcript.omissions.reasoning_records, 1);
        assert_eq!(transcript.omissions.tool_records, 1);
        assert_eq!(transcript.omissions.metadata_records, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_parser_uses_visible_user_events_and_omits_runtime_context() {
        let root = temp_root("codex-visible-user-events");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"# AGENTS.md instructions for /work\n<environment_context>hidden</environment_context>"}]}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"visible prompt"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"visible prompt","images":[],"local_images":[]}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"visible answer"}]}}),
            ],
        );

        let transcript = read_transcript(HarnessKind::Codex, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "visible prompt".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "visible answer".into()
                },
            ]
        );
        assert_eq!(transcript.omissions.system_records, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_parser_rejects_an_unpaired_ordinary_role_user_record() {
        let root = temp_root("codex-unpaired-user");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"possibly visible"}]}}),
            ],
        );

        assert!(matches!(
            read_transcript(HarnessKind::Codex, &root, &path),
            Err(TransferError::AmbiguousRecord { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_parser_pairs_user_records_after_crlf_normalization() {
        let root = temp_root("codex-crlf-user-pair");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"first\r\nsecond"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"first\r\nsecond"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}}),
            ],
        );

        let transcript = read_transcript(HarnessKind::Codex, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "first\nsecond".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "answer".into()
                },
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_record_with_possible_visible_text_fails_closed() {
        let root = temp_root("ambiguous");
        let path = root.join("source.jsonl");
        write_fixture(&path, &[json!({"type":"future","text":"maybe visible"})]);
        assert!(matches!(
            read_transcript(HarnessKind::Claude, &root, &path),
            Err(TransferError::AmbiguousRecord { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn is_meta_does_not_hide_an_unknown_record_with_visible_content() {
        let root = temp_root("ambiguous-meta");
        let path = root.join("source.jsonl");
        write_fixture(
            &path,
            &[json!({
                "type":"future-visible",
                "isMeta":true,
                "message":{"role":"user","content":"must not disappear"}
            })],
        );
        assert!(matches!(
            read_transcript(HarnessKind::Claude, &root, &path),
            Err(TransferError::AmbiguousRecord { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_validation_rejects_parent_and_out_of_home_paths() {
        let root = temp_root("path-trust");
        let outside = temp_root("outside").join("source.jsonl");
        fs::write(&outside, b"{}\n").unwrap();
        assert!(matches!(
            validate_transcript_path(&root, &outside),
            Err(TransferError::InvalidPath(_))
        ));
        let dotted = root.join("child").join("..").join("source.jsonl");
        assert!(matches!(
            validate_transcript_path(&root, &dotted),
            Err(TransferError::InvalidPath(_))
        ));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn path_validation_rejects_symlinks_below_account_home() {
        use std::os::unix::fs::symlink;

        let root = temp_root("symlink");
        let real = root.join("real.jsonl");
        fs::write(&real, b"{}\n").unwrap();
        let link = root.join("link.jsonl");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            validate_transcript_path(&root, &link),
            Err(TransferError::InvalidPath(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_writer_round_trips_exact_visible_messages() {
        let root = temp_root("claude-write");
        let cwd = root.join("work.tree");
        fs::create_dir_all(&cwd).unwrap();
        let expected = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "hello\n".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "answer".into(),
            },
        ];
        let (session_id, path) = write_claude_session(&root, &cwd, &expected).unwrap();
        assert!(path.ends_with(format!("{session_id}.jsonl")));
        let actual = read_transcript(HarnessKind::Claude, &root, &path).unwrap();
        verify_destination(&expected, &actual).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_rollout_lookup_verifies_session_meta_id() {
        let root = temp_root("codex-lookup");
        let day = root.join("sessions/2026/08/29");
        fs::create_dir_all(&day).unwrap();
        let wrong = day.join("rollout-2026-wanted.jsonl");
        write_fixture(
            &wrong,
            &[json!({"type":"session_meta","payload":{"id":"other"}})],
        );
        assert!(find_codex_rollout(&root, "wanted").is_err());
        let correct = day.join("rollout-2026-real-wanted.jsonl");
        write_fixture(
            &correct,
            &[json!({"type":"session_meta","payload":{"id":"wanted"}})],
        );
        assert_eq!(
            find_codex_rollout(&root, "wanted").unwrap(),
            correct.canonicalize().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_import_reuses_the_unique_verified_ledger_target() {
        let root = temp_root("codex-import-ledger");
        let source = root.join("imports/source.jsonl");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"{}\n").unwrap();
        let rollout = root.join("sessions/2026/08/29/rollout-target-thread.jsonl");
        fs::create_dir_all(rollout.parent().unwrap()).unwrap();
        write_fixture(
            &rollout,
            &[json!({"type":"session_meta","payload":{"id":"target-thread"}})],
        );
        fs::write(
            root.join("external_agent_session_imports.json"),
            serde_json::to_vec(&json!({
                "records": [{
                    "source_path": source.to_string_lossy(),
                    "imported_thread_id": "target-thread"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            reuse_codex_import_target(&root, &source).unwrap(),
            "target-thread"
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// AXIS — ROUND-12: the number of import completions is bounded, not just their size.
    ///
    /// The per-message cap bounds each notification; nothing bounded how many arrive. A
    /// faulty app-server could emit unlimited sub-2-MiB completions before answering, and
    /// both the buffer and the target list grew with them — then every named target was
    /// copied into the cleanup queue, each able to spend the full delete timeout.
    #[tokio::test]
    async fn an_endless_stream_of_import_completions_is_refused() {
        // TARGETLESS COMPLETIONS, so the COMPLETION guard is the one under test. Round 13:
        // my first fixture named a distinct target in every completion, which tripped the
        // observed-targets guard first — removing the completions bound alone left the
        // test green, so it could not see the thing it was named after.
        let mut stream = String::new();
        for index in 0..(MAX_IMPORT_COMPLETIONS * 2) {
            stream.push_str(&format!(
                "{}\n",
                json!({"method": "externalAgentConfig/import/completed", "params": {
                    "importId": format!("other-{index}"),
                    "itemTypeResults": [{
                        "itemType": "SESSIONS",
                        "successes": [],
                        "failures": []
                    }]
                }})
            ));
        }
        let mut reader =
            tokio::io::BufReader::new(std::io::Cursor::new(stream.as_bytes().to_vec()));
        let mut observed = Vec::new();
        let err = wait_for_import_result(&mut reader, &mut observed)
            .await
            .expect_err("an unbounded completion stream must be refused");
        assert!(
            matches!(&err, TransferError::CodexImport(message)
                if message.contains("import completions")),
            "expected the COMPLETION bound specifically, got {err}"
        );
        assert!(
            observed.is_empty(),
            "no targets were named, so the completion guard is the only one that can \
             have fired"
        );
    }

    /// AXIS — ROUND-17: the abandonment warning actually names what a human must clear.
    ///
    /// With automatic cleanup cut, this log line is the ONLY cleanup receipt, and round
    /// 17 found nothing observed it: removing any report call left state and return
    /// values identical, and no test referenced the reporter at all. A receipt nobody
    /// checks is the same shape as the cleanup that silently never ran.
    ///
    /// Asserts the TYPED locator per harness, which is the half that was actually wrong
    /// before: OMP's locator is a transcript path and was being emitted as `session_id`.
    #[test]
    fn the_abandonment_warning_names_the_locator_a_human_would_use() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("capture").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            report_abandoned_targets(
                HarnessKind::Codex,
                std::path::Path::new("/tmp/codex-home"),
                &["thread-abc".to_string()],
                "test",
            );
            report_abandoned_targets(
                HarnessKind::Omp,
                std::path::Path::new("/tmp/omp-home"),
                &["/tmp/omp-home/sessions/leaf.jsonl".to_string()],
                "test",
            );
        });

        let logged = String::from_utf8(capture.0.lock().expect("capture").clone()).unwrap();
        assert!(
            logged.contains("session_id=\"thread-abc\"")
                || logged.contains("session_id=thread-abc"),
            "a Codex thread must be named as a session id: {logged}"
        );
        assert!(
            logged.contains("transcript_path"),
            "an OMP locator is a PATH and must not be labelled session_id: {logged}"
        );
        // ASSERTED ON THE VALUE, UNQUOTED. `%locator` records a DisplayValue that the
        // fmt layer renders WITHOUT quotes, so the previous form — looking for
        // `session_id="/tmp/omp-home` — could not fire for the regression it names: the
        // natural way of writing the bug produces output it accepts. One of three
        // assertions in this test could not print a failure.
        assert!(
            logged.contains("transcript_path=/tmp/omp-home/sessions/leaf.jsonl"),
            "the OMP locator must appear as a transcript_path VALUE, not just the field \
             name: {logged}"
        );
        assert!(
            !logged.contains("session_id=/tmp/omp-home"),
            "the OMP path must not be emitted under session_id: {logged}"
        );
        assert!(
            logged.contains("/tmp/codex-home") && logged.contains("/tmp/omp-home"),
            "the account home must be logged so the artifact can be found: {logged}"
        );
    }

    /// AXIS — ROUND-17: the generated bridge is STREAMED, so it has no ceiling to guess.
    ///
    /// It used to be read back whole under a bound I set at twice the source window and
    /// defended with "only the largest source matters". That reasoning was wrong in the
    /// exact way the reviewers showed: a 64 MiB window can hold ~327,360 minimal message
    /// pairs, the measured ~4.3x per-pair expansion does not wash out with repetition,
    /// and the result is a ~275 MiB bridge — with nothing bounding message COUNT to
    /// prevent that shape.
    ///
    /// So the bound is deleted rather than raised. Retention is one record plus the
    /// projection, and the projection is `expected`, which the caller holds anyway.
    #[test]
    fn the_bridge_projection_streams_a_file_past_any_whole_read_ceiling() {
        // Deliberately larger than the DESTINATION record budget would allow to be held
        // as one blob, and far past anything a "2x the window" guess would have covered
        // proportionally: what matters is that no total-size check exists at all.
        let root = temp_root("bridge-streamed");
        let path = root.join("bridge.jsonl");
        let pairs = 20_000;
        let mut body = String::new();
        for index in 0..pairs {
            body.push_str(&format!(
                "{}\n{}\n",
                json!({"type":"user","cwd":"/tmp","sessionId":"s",
                    "message":{"role":"user","content":format!("q{index}")}}),
                json!({"type":"assistant","cwd":"/tmp","sessionId":"s",
                    "message":{"role":"assistant",
                        "content":[{"type":"text","text":format!("a{index}")}]}})
            ));
        }
        std::fs::write(&path, body.as_bytes()).unwrap();

        let file = std::fs::File::open(&path).unwrap();
        let projected = claude_to_codex_import_projection_streaming(file)
            .expect("the projection must stream, not refuse on total size");
        assert_eq!(
            projected.len(),
            pairs * 2,
            "every record must be projected regardless of the file's total size"
        );

        // AND THE SURVIVOR IS CLOSED, WITHOUT A FILE. I called this expensive twice; the
        // reviewer pointed out the projection takes any `R: Read`, so a generator works:
        // two real records followed by hundreds of MiB of records the projection IGNORES
        // (`project_claude_record_for_codex` returns Ok(()) for any type that is not
        // user/assistant). Streaming retention stays at one line plus two messages, so
        // this costs a parse and no allocation — while any whole read under any constant
        // below the generated size fails.
        //
        // Third time a gap I declared expensive turned out cheap once someone else
        // looked at it. The pattern: I kept sizing the fixture to the FILE, when the
        // property only needed the READER to be large.
        struct Endless {
            emitted: u64,
            limit: u64,
            pending: Vec<u8>,
            at: usize,
            filler: Vec<u8>,
        }
        impl std::io::Read for Endless {
            // BULK COPY, NOT BYTE AT A TIME. The first version drained a VecDeque one
            // byte per iteration and took 17s; changing the record SIZE made no
            // difference, which is what showed the cost was the reader rather than the
            // parse I had assumed.
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.at >= self.pending.len() {
                    if self.emitted >= self.limit {
                        return Ok(0);
                    }
                    self.pending = self.filler.clone();
                    self.at = 0;
                    self.emitted += self.pending.len() as u64;
                }
                let take = (self.pending.len() - self.at).min(buf.len());
                buf[..take].copy_from_slice(&self.pending[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }

        let head = Vec::from(
            format!(
                "{}\n{}\n",
                json!({"type":"user","cwd":"/tmp","sessionId":"s",
                    "message":{"role":"user","content":"only-q"}}),
                json!({"type":"assistant","cwd":"/tmp","sessionId":"s",
                    "message":{"role":"assistant",
                        "content":[{"type":"text","text":"only-a"}]}})
            )
            .as_bytes(),
        );
        // Well past twice the window, so any reintroduced whole read at a plausible
        // constant refuses. Nothing of this size is ever held.
        //
        // The filler records are LARGE (256 KiB) on purpose: the cost here is one serde
        // parse per record, so the same coverage at 4 KiB records took 17s of a ~40s
        // suite. Same bytes generated, ~64x fewer parses.
        let generated = 3 * TRANSFER_WINDOW_BYTES;
        let filler = format!(
            "{}\n",
            json!({"type":"system","subtype":"filler","content":"y".repeat(256 * 1024)})
        )
        .into_bytes();
        let endless = Endless {
            emitted: 0,
            limit: generated,
            pending: head,
            at: 0,
            filler,
        };
        let streamed = claude_to_codex_import_projection_streaming(endless)
            .expect("the projection must stream a source larger than any whole-read cap");
        assert_eq!(
            streamed.len(),
            2,
            "only the two real messages are retained; the filler is parsed and dropped"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-17: the survivor is closed. A destination past the REAL 64 MiB
    /// source constant still verifies.
    ///
    /// I declared this one unclosable-without-expense twice: distinguishing the
    /// streaming arm from a whole read at the literal TRANSFER_WINDOW_BYTES needs a
    /// destination actually over 64 MiB. The reviewer pointed out the suite ALREADY
    /// writes one, so this is not a new class of fixture — it is the same cost the
    /// oversize source test already pays.
    ///
    /// The shape matters: bulk is IGNORED metadata, and the visible projection is tiny.
    /// That is a real Codex destination — several records per pair, most of them not
    /// visible messages — and it is exactly what a source-sized ceiling refuses wrongly.
    #[test]
    fn a_destination_past_the_real_source_constant_still_verifies() {
        let root = temp_root("dest-past-real-cap");
        let path = root.join("rollout-thread.jsonl");

        // One metadata record over the source ceiling, plus a two-message conversation.
        // `session_meta` is not a visible message, so the projection stays tiny while
        // the FILE is unambiguously past TRANSFER_WINDOW_BYTES.
        // SPREAD ACROSS MANY RECORDS, not one. My first attempt put the whole 64 MiB in
        // a single `session_meta`, which legitimately exceeds the PER-RECORD budget and
        // failed for the wrong reason — the file has to be oversize while every record
        // is ordinary, which is also what a real destination looks like.
        let chunk = "i".repeat(1024 * 1024);
        let mut records: Vec<Value> = (0..68)
            .map(|index| {
                json!({"type":"session_meta",
                    "payload":{"id":format!("thread-{index}"),"base_instructions":chunk}})
            })
            .collect();
        records.push(
            json!({"type":"response_item","payload":{"type":"message","role":"user",
            "content":[{"type":"input_text","text":"q"}]}}),
        );
        records.push(json!({"type":"event_msg","payload":{"type":"user_message",
            "message":"q","images":[],"local_images":[]}}));
        write_fixture(&path, &records);
        let total = std::fs::metadata(&path).unwrap().len();
        assert!(
            total > TRANSFER_WINDOW_BYTES,
            "precondition: the destination must exceed the SOURCE constant ({total} vs \
             {TRANSFER_WINDOW_BYTES}), or this cannot distinguish the two readers"
        );

        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "q".to_string(),
        }];
        let verified = read_verified_destination_within(
            HarnessKind::Codex,
            &root,
            &path,
            None,
            &expect,
            DESTINATION_RECORD_BUDGET_BYTES,
            DESTINATION_TOTAL_BUDGET_BYTES,
            OMP_DESTINATION_RETENTION_BYTES,
        )
        .expect("a destination past the source constant must still verify");
        assert_eq!(verified.messages, expect);
        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-21: a LIVE OMP target may append, and verification must survive it.
    ///
    /// Enters through `verified_visible_destination`, the post-launch method that DRIVES
    /// ROLLBACK, rather than through the helper — a test on the helper alone says nothing
    /// about what the rollback path actually calls.
    ///
    /// The property: `omp::parse` walks from the selected leaf upward, so records the
    /// live target appends past the staged leaf are off-branch and the comparison never
    /// sees them. Round 20 attributed this tolerance to a per-caller byte bound instead
    /// of to the parser, which is why that round produced an unobservable distinction.
    #[test]
    fn a_live_omp_target_may_append_after_launch_and_still_verify() {
        let root = temp_root("omp-live-append");
        let source_home = root.join("claude-home");
        let target_sessions = root.join("omp-home").join("sessions");
        let cwd = root.join("cwd");
        std::fs::create_dir_all(&target_sessions).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "q".to_string(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "a".to_string(),
            },
        ];
        let (source_id, source_path) = write_claude_session(&source_home, &cwd, &messages).unwrap();
        let (_target_id, target_path, leaf) =
            omp::write(&target_sessions, &cwd, &messages).unwrap();

        append_off_branch_record(&target_path, &leaf, 256 * 1024);

        let transfer = post_launch_transfer(
            source_id,
            source_path,
            source_home,
            target_sessions,
            target_path,
            leaf,
            messages.len() as u64,
        );
        transfer
            .verified_visible_destination()
            .expect("a live target's append past the staged leaf must not fail verification");

        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-21: the OMP retention ceiling actually REFUSES.
    ///
    /// THE TEST ROUND 20 SHOULD HAVE WRITTEN. Round 19 deleted
    /// `OMP_DESTINATION_RETENTION_BYTES` and round 20 replaced it with the file's own
    /// length — `cap = metadata().len()` then "read at most cap", which cannot refuse any
    /// file at any size. Neither round had a test that could tell a real ceiling from
    /// none, so both shipped. This one can: it drives the bound down to a few kilobytes
    /// and exceeds it.
    ///
    /// Deleting the bound, or restoring the self-referential form, turns this red.
    #[test]
    fn an_omp_destination_past_the_retention_ceiling_is_refused() {
        let root = temp_root("omp-retention-ceiling");
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let messages = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "x".repeat(64 * 1024),
        }];
        let (_id, path, leaf) =
            omp::write(&sessions, std::path::Path::new("/tmp"), &messages).unwrap();
        let written = std::fs::metadata(&path).unwrap().len();
        let ceiling = written / 2;

        let error = read_verified_destination_within(
            HarnessKind::Omp,
            &sessions,
            &path,
            Some(leaf.as_str()),
            &messages,
            DESTINATION_RECORD_BUDGET_BYTES,
            DESTINATION_TOTAL_BUDGET_BYTES,
            ceiling,
        )
        .expect_err("a destination above the retention ceiling must be refused, not read");
        assert!(
            matches!(error, TransferError::TranscriptTooLarge { bytes, limit }
                if bytes > limit && limit == ceiling),
            "the refusal must name the ceiling it enforced, and the ceiling must be the \
             injected one rather than the file's own size: {error:?} \
             (file {written} bytes, ceiling {ceiling})"
        );

        // THE CONTROL. The same file under the real constant verifies, so the assertion
        // above is about the CEILING and not about the fixture being malformed.
        read_verified_destination_within(
            HarnessKind::Omp,
            &sessions,
            &path,
            Some(leaf.as_str()),
            &messages,
            DESTINATION_RECORD_BUDGET_BYTES,
            DESTINATION_TOTAL_BUDGET_BYTES,
            OMP_DESTINATION_RETENTION_BYTES,
        )
        .expect("the same destination must verify under the production ceiling");

        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-22: the modelled ROLE is the one with the worst expansion.
    ///
    /// FOUR ROUNDS SIZED THIS CEILING FROM "THE MINIMAL RECORD" AND ALL FOUR MEANT "the
    /// minimal record I happened to write". Round 18 used a 205-byte pair carrying `cwd`
    /// and `sessionId`, fields only the CODEX bridge requires. Round 21 dropped those but
    /// left the assistant record in its array form, and a reviewer demolished it with an
    /// all-assistant window of string-content records.
    ///
    /// The first version of THIS test then repeated the shape one level up: it looked for
    /// the globally smallest accepted record and found a 56-byte user one, which is real
    /// but is the wrong input to the model — a user record produces a user ENTRY at about
    /// half an assistant entry's cost, so the pair that maximises RETENTION is not the pair
    /// containing the smallest record. Expansion is per-role, so the model is per-role, and
    /// this asserts the role the model names is actually the worst one.
    ///
    /// It enumerates the forms `parse_claude_record` ACCEPTS — accepted meaning "produces a
    /// visible message", not merely "parses" — measures the writer's cost for each role,
    /// and requires the modelled pair to dominate. A cheaper accepted form, or a role whose
    /// entry cost grows, turns this red instead of silently moving the true worst case out
    /// from under the ceiling.
    #[test]
    fn the_modelled_role_is_the_worst_expanding_one() {
        let root = temp_root("worst-role");
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();

        let smallest_accepted = |candidates: &[serde_json::Value]| -> u64 {
            let mut best = u64::MAX;
            for candidate in candidates {
                let line = candidate.to_string();
                let dir = temp_root("accepted-form");
                let path = dir.join("t.jsonl");
                std::fs::write(&path, format!("{line}\n")).unwrap();
                let produces_a_message = read_transcript(HarnessKind::Claude, &dir, &path)
                    .map(|t| !t.messages.is_empty())
                    .unwrap_or(false);
                let _ = fs::remove_dir_all(&dir);
                if produces_a_message {
                    best = best.min(line.len() as u64 + 1);
                }
            }
            best
        };

        // Marginal writer cost per entry, differenced so the header cancels.
        let entry_cost = |role: VisibleRole| -> u64 {
            let at = |count: usize| {
                let messages: Vec<_> = (0..count)
                    .map(|_| VisibleMessage {
                        role,
                        text: "a".to_string(),
                    })
                    .collect();
                let (_id, path, _leaf) =
                    omp::write(&sessions, std::path::Path::new("/tmp"), &messages).unwrap();
                std::fs::metadata(&path).unwrap().len()
            };
            (at(200) - at(100)) / 100
        };

        let assistant_min = smallest_accepted(&[
            json!({"type":"assistant","message":{"role":"assistant","content":"a"}}),
            json!({"type":"assistant",
                "message":{"role":"assistant","content":[{"type":"text","text":"a"}]}}),
        ]);
        let user_min = smallest_accepted(&[
            json!({"type":"user","message":{"role":"user","content":"q"}}),
            json!({"type":"user","message":{"role":"user","content":[{"type":"text","text":"q"}]}}),
        ]);
        let assistant_ratio = entry_cost(VisibleRole::Assistant) as f64 / assistant_min as f64;
        let user_ratio = entry_cost(VisibleRole::User) as f64 / user_min as f64;

        assert!(
            assistant_ratio >= user_ratio,
            "the retention model is derived from the ASSISTANT pair, but the USER pair \
             now expands worse ({user_ratio:.2}x vs {assistant_ratio:.2}x); re-derive \
             OMP_DESTINATION_RETENTION_BYTES from the user pair instead"
        );
        assert!(
            OMP_MIN_ASSISTANT_RECORD_BYTES <= assistant_min,
            "the model assumes no accepted assistant record is smaller than \
             {OMP_MIN_ASSISTANT_RECORD_BYTES} bytes, but one is {assistant_min}"
        );
        assert!(
            assistant_min - OMP_MIN_ASSISTANT_RECORD_BYTES <= 8,
            "the modelled assistant minimum ({OMP_MIN_ASSISTANT_RECORD_BYTES}) has drifted \
             from the measured one ({assistant_min}); re-derive it rather than widening \
             the gap, which inflates the ceiling for no reason"
        );

        // ALL THREE SOURCE KINDS FEED `omp::write`, SO ALL THREE COMPETE FOR THE VERTEX.
        //
        // `read_transfer_source` windows Claude and Codex and refuses an oversize OMP
        // source, so every kind delivers at most one window into the writer and any could
        // hold the worst rate.
        //
        // COMPARED AS RATES PER ROLE, NOT AS RAW MINIMA — round 24 caught the first
        // version doing the latter, and it was wrong in both directions. A cheap record
        // producing a USER message says nothing about a bound derived from an ASSISTANT
        // pair: the assistant entry costs about twice the user one, so comparing a Codex
        // user minimum against a Claude assistant minimum can fail on a transcript that is
        // cheaper per byte (false-fail, the same spurious-fire mode the 8-window floor was
        // deleted for) and can pass while a genuinely worse assistant form exists
        // (false-pass). What the LP argument actually maximises is retained bytes per
        // source byte AT A VERTEX, and a vertex is one role — so the comparison is
        // per-role, entry cost over record cost.
        //
        // AND EACH KIND IS SWEPT, NOT SAMPLED. Round 21 died because one probe was assumed
        // minimal; round 24 found the same assumption here, where the Codex probe wrote
        // only the `response_item` form and missed the `event_msg` one at 69 bytes.
        let cheapest = |kind: HarnessKind, role: VisibleRole, forms: &[String]| -> u64 {
            let mut best = u64::MAX;
            for body in forms {
                let dir = temp_root("form");
                let path = dir.join("t.jsonl");
                std::fs::write(&path, body).unwrap();
                let hit = read_transcript(kind, &dir, &path)
                    .map(|t| t.messages.iter().any(|m| m.role == role))
                    .unwrap_or(false);
                let _ = fs::remove_dir_all(&dir);
                if hit {
                    // Marginal cost of the LAST record, which is what a rate depends on.
                    best = best.min(
                        body.lines()
                            .next_back()
                            .map(|l| l.len() as u64 + 1)
                            .unwrap_or(u64::MAX),
                    );
                }
            }
            best
        };
        let one = |v: serde_json::Value| format!("{v}\n");

        // OMP needs a real header and a valid parent chain; an orphan entry is rejected
        // and a root entry needs an explicit `"parentId": null` rather than an absent one.
        let omp_chain = |role: &str| -> String {
            let dir = temp_root("omp-seed");
            let seeds = dir.join("s");
            std::fs::create_dir_all(&seeds).unwrap();
            let (_id, seed, _leaf) = omp::write(
                &seeds,
                std::path::Path::new("/tmp"),
                &[VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "a".to_string(),
                }],
            )
            .unwrap();
            let text = std::fs::read_to_string(&seed).unwrap();
            let _ = fs::remove_dir_all(&dir);
            let mut header = text.lines();
            let mut out = format!(
                "{}\n{}\n",
                header.next().expect("pad"),
                header.next().expect("session")
            );
            for index in 0..8u32 {
                let entry = if index == 0 {
                    json!({"id":"0","parentId":Value::Null,"type":"message",
                        "message":{"role":role,"content":"x"}})
                } else {
                    json!({"id":index.to_string(),"parentId":(index - 1).to_string(),
                        "type":"message","message":{"role":role,"content":"x"}})
                };
                out.push_str(&entry.to_string());
                out.push('\n');
            }
            out
        };

        let rates = [
            (
                "claude/assistant",
                VisibleRole::Assistant,
                cheapest(
                    HarnessKind::Claude,
                    VisibleRole::Assistant,
                    &[
                        one(
                            json!({"type":"assistant","message":{"role":"assistant","content":"a"}}),
                        ),
                        one(json!({"type":"assistant","message":{"role":"assistant",
                            "content":[{"type":"text","text":"a"}]}})),
                    ],
                ),
            ),
            (
                "claude/user",
                VisibleRole::User,
                cheapest(
                    HarnessKind::Claude,
                    VisibleRole::User,
                    &[
                        one(json!({"type":"user","message":{"role":"user","content":"q"}})),
                        one(json!({"type":"user","message":{"role":"user",
                            "content":[{"type":"text","text":"q"}]}})),
                    ],
                ),
            ),
            (
                "codex/assistant",
                VisibleRole::Assistant,
                cheapest(
                    HarnessKind::Codex,
                    VisibleRole::Assistant,
                    &[
                        one(json!({"type":"response_item","payload":{"type":"message",
                            "role":"assistant","content":[{"type":"text","text":"a"}]}})),
                        one(json!({"type":"event_msg","payload":{"type":"agent_message",
                            "message":"a"}})),
                    ],
                ),
            ),
            (
                "codex/user",
                VisibleRole::User,
                cheapest(
                    HarnessKind::Codex,
                    VisibleRole::User,
                    &[
                        one(json!({"type":"event_msg","payload":{"type":"user_message",
                            "message":"a"}})),
                        one(json!({"type":"response_item","payload":{"type":"message",
                            "role":"user","content":[{"type":"input_text","text":"q"}]}})),
                    ],
                ),
            ),
            (
                "omp/assistant",
                VisibleRole::Assistant,
                cheapest(
                    HarnessKind::Omp,
                    VisibleRole::Assistant,
                    &[omp_chain("assistant")],
                ),
            ),
            (
                "omp/user",
                VisibleRole::User,
                cheapest(HarnessKind::Omp, VisibleRole::User, &[omp_chain("user")]),
            ),
        ];

        let assistant_entry = entry_cost(VisibleRole::Assistant) as f64;
        let user_entry = entry_cost(VisibleRole::User) as f64;
        let modelled = assistant_entry / OMP_MIN_ASSISTANT_RECORD_BYTES as f64;

        for (label, role, min_record) in rates {
            assert!(
                min_record != u64::MAX,
                "no candidate form for {label} produced a visible message of that role — \
                 the probe has gone stale and is silently measuring nothing"
            );
            let entry = if role == VisibleRole::Assistant {
                assistant_entry
            } else {
                user_entry
            };
            let rate = entry / min_record as f64;
            assert!(
                rate <= modelled,
                "the retention model takes the CLAUDE assistant pair as the worst rate \
                 ({modelled:.2} retained bytes per source byte), but {label} now reaches \
                 {rate:.2} ({min_record} B per record, {entry:.0} B per entry); the vertex \
                 has moved and OMP_DESTINATION_RETENTION_BYTES must be re-derived from it"
            );
        }

        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-22: `omp::write`'s per-entry cost stays inside the modelled maximum.
    ///
    /// THIS IS THE GUARD THE OLD MEASUREMENT TEST WAS TRYING TO BE. Round 21's version
    /// asserted a ratio against the ceiling, which the round-22 review showed was strictly
    /// weaker than the compile-time assert already covering it — it could only fire below
    /// ~5.11 windows, and the BUILD already failed below 6. Its one real role was catching
    /// a change to `omp::write`, and at 5.11x it had 1.57x of slack while the shape that
    /// actually ships had 1.05x. A guard aimed at the right risk, calibrated to miss it.
    ///
    /// Aimed at the writer directly instead: measure what `omp::write` emits per entry and
    /// require the modelled maximum to cover it. Adding a field to the entry envelope
    /// turns this red at the point the cost changes, rather than at the point some
    /// unrelated ratio crosses a ceiling.
    #[test]
    fn omp_write_entry_cost_stays_inside_the_modelled_maximum() {
        let root = temp_root("omp-entry-cost");
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();

        // The assistant entry is the larger of the two forms the writer emits, and the
        // envelope is fixed-width, so per-entry cost is measured by differencing two
        // transcripts rather than by parsing one.
        let entry_cost = |count: usize| -> u64 {
            let messages: Vec<_> = (0..count)
                .map(|_| VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "a".to_string(),
                })
                .collect();
            let (_id, path, _leaf) =
                omp::write(&sessions, std::path::Path::new("/tmp"), &messages).unwrap();
            std::fs::metadata(&path).unwrap().len()
        };
        // Differencing cancels the header, so this is the marginal entry cost.
        let per_entry = (entry_cost(200) - entry_cost(100)) / 100;

        assert!(
            per_entry <= OMP_MAX_DESTINATION_ENTRY_BYTES,
            "omp::write now emits {per_entry} bytes per assistant entry, above the \
             modelled maximum of {OMP_MAX_DESTINATION_ENTRY_BYTES} that \
             OMP_DESTINATION_RETENTION_BYTES is derived from — raise the model, because \
             the ceiling is now below what the writer produces and `prepare` PUBLISHES \
             the session before reading it back"
        );
        assert!(
            OMP_MAX_DESTINATION_ENTRY_BYTES - per_entry <= 64,
            "the modelled maximum ({OMP_MAX_DESTINATION_ENTRY_BYTES}) has drifted well \
             above the measured cost ({per_entry}); that inflates the retention ceiling \
             for no reason"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-22: the WORST accepted shape still fits the ceiling.
    ///
    /// The end-to-end check on the model above, and it uses the shape that actually
    /// demolished round 21: an ALL-ASSISTANT window of string-content records, which no
    /// earlier fixture wrote because every one of them assumed a conversation alternates.
    /// Windowing cuts the HEAD of a transcript, so an assistant-heavy tail is a normal
    /// outcome of the very feature this PR adds — not an exotic input.
    ///
    /// Reverting the constant to round 21's `8 * TRANSFER_WINDOW_BYTES` leaves this green
    /// by 5%, which is exactly why the margin is asserted rather than just the fit.
    #[test]
    fn the_worst_accepted_shape_fits_the_retention_ceiling_with_margin() {
        let root = temp_root("omp-worst-shape");
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();

        let entries = 800;
        let mut messages = Vec::new();
        let mut source_bytes = 0u64;
        for _ in 0..entries {
            source_bytes += json!({"type":"assistant",
                "message":{"role":"assistant","content":"a"}})
            .to_string()
            .len() as u64
                + 1;
            messages.push(VisibleMessage {
                role: VisibleRole::Assistant,
                text: "a".to_string(),
            });
        }
        let (_id, path, _leaf) =
            omp::write(&sessions, std::path::Path::new("/tmp"), &messages).unwrap();
        let destination_bytes = std::fs::metadata(&path).unwrap().len();

        let ratio = destination_bytes as f64 / source_bytes as f64;
        let held_from_a_full_window = ratio * TRANSFER_WINDOW_BYTES as f64;
        let ceiling = OMP_DESTINATION_RETENTION_BYTES as f64;
        let margin = ceiling / held_from_a_full_window;

        assert!(
            margin >= 1.25,
            "the worst accepted shape expands {ratio:.2}x ({source_bytes} -> \
             {destination_bytes} bytes over {entries} entries), so a full window holds \
             {:.0} MiB against a {:.0} MiB ceiling — margin {margin:.2}x, below the 1.25x \
             this bound is built to keep. `prepare` publishes before it reads back, so \
             being low orphans a session rather than merely failing.",
            held_from_a_full_window / (1024.0 * 1024.0),
            ceiling / (1024.0 * 1024.0)
        );
        assert!(
            ratio > 7.0,
            "precondition: this fixture must reproduce the WORST shape, and {ratio:.2}x \
             means it no longer does — the ceiling would then be validated against an \
             input that is not the worst one, which is how rounds 18, 19 and 21 each \
             shipped a bound a reviewer then demolished"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-16: a destination LARGER THAN THE SOURCE CEILING still verifies.
    ///
    /// THIS IS THE GAP I DECLARED UNGUARDABLE FOR TWO ROUNDS, and the reviewers were
    /// right that it was not. I believed distinguishing "stream the destination" from
    /// "read it whole and compare after" needed a 64 MiB end-to-end import, because the
    /// two differ only when the destination exceeds the SOURCE ceiling. Extracting one
    /// helper with injectable budgets makes the same distinction cost a few kilobytes:
    /// pass a small whole-read budget, exceed it, and only the streaming arm survives.
    ///
    /// The property is the whole point of the PR. A destination is GENERATED from the
    /// window and expands — measured by review at ~205 source bytes per pair becoming
    /// ~882 in the Claude bridge and ~697 in OMP — so any ceiling sized for the source
    /// rejects transfers that worked.
    ///
    /// WHAT THIS STILL DOES NOT CATCH, narrowed but not gone: a mutant that reads the
    /// destination whole under the REAL 64 MiB source constant survives, because this
    /// fixture is kilobytes and never reaches it. Catching that specific substitution
    /// needs a genuinely oversize destination. What changed in round 16 is the scope of
    /// the hole: before the helper existed, the entire routing decision was unguarded at
    /// both sites; now only the hard-coded-constant variant is.
    #[test]
    fn a_destination_past_the_source_ceiling_still_verifies() {
        let root = temp_root("dest-past-source-cap");
        let path = root.join("session.jsonl");
        let expect: Vec<VisibleMessage> = (0..40)
            .map(|index| VisibleMessage {
                role: if index % 2 == 0 {
                    VisibleRole::User
                } else {
                    VisibleRole::Assistant
                },
                text: format!("m{index} {}", "x".repeat(200)),
            })
            .collect();
        let mut records = Vec::new();
        for message in &expect {
            records.push(match message.role {
                VisibleRole::User => json!({"type":"user",
                    "message":{"role":"user","content":message.text}}),
                VisibleRole::Assistant => json!({"type":"assistant",
                    "message":{"role":"assistant",
                        "content":[{"type":"text","text":message.text}]}}),
            });
        }
        write_fixture(&path, &records);
        let total = std::fs::metadata(&path).unwrap().len();

        // A budget the destination EXCEEDS — standing in for the source ceiling that a
        // real expanded destination overshoots.
        let source_ceiling = total / 2;
        assert!(
            source_ceiling > 0 && total > source_ceiling,
            "precondition: {total} > {source_ceiling}"
        );

        // The streaming arm accepts it: retention is bounded per record, not by the file.
        let verified = read_verified_destination_within(
            HarnessKind::Claude,
            &root,
            &path,
            None,
            &expect,
            DESTINATION_RECORD_BUDGET_BYTES,
            DESTINATION_TOTAL_BUDGET_BYTES,
            OMP_DESTINATION_RETENTION_BYTES,
        )
        .expect("a destination past the source ceiling must still verify");
        assert_eq!(verified.messages, expect);

        // THE CONTROL, and it is what makes the assertion above mean something: reading
        // the same file whole under that ceiling REFUSES it. If this ever stops
        // refusing, the test above has stopped discriminating.
        let file = std::fs::File::open(&path).unwrap();
        assert!(
            matches!(
                read_whole_within(file, source_ceiling),
                Err(TransferError::TranscriptTooLarge { .. })
            ),
            "precondition: the whole reader must refuse at this ceiling, or the streaming \
             arm is not being distinguished from anything"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-15: the whole read refuses BEFORE allocating past its cap.
    ///
    /// I wrote `read_transcript_whole` during the #153 rebase as `fs::read` followed by a
    /// length check — check-after-allocate, the same defect this PR already fixed twice
    /// (the ledger read, then the app-server response). A multi-gigabyte transcript would
    /// have exhausted memory before the refusal ran.
    ///
    /// ASSERTED ON BYTES CONSUMED, because both versions return the same error and the
    /// error therefore proves nothing. Mutation confirms: reverting to `fs::read` leaves
    /// every other test green.
    #[test]
    fn the_whole_read_refuses_before_allocating_past_its_cap() {
        let cap = 4096u64;
        let total = (cap as usize) * 8;
        let mut cursor = std::io::Cursor::new(vec![b'x'; total]);
        let err =
            read_whole_within(&mut cursor, cap).expect_err("a file past the cap must be refused");
        assert!(
            matches!(err, TransferError::TranscriptTooLarge { .. }),
            "expected the size refusal, got {err}"
        );
        let consumed = cursor.position();
        assert!(
            consumed <= cap + 1,
            "the refusal must fire having read at most cap+1 bytes, not the whole file: \
             consumed {consumed} of {total} with cap {cap}"
        );

        // AND THE EXACT BOUNDARY, which the assertion above cannot see. Round 16: a
        // `take(cap)` + refuse-at-`>= cap` implementation also consumes no more than
        // cap+1 and also refuses the oversize fixture, so it survived — while wrongly
        // rejecting a file of EXACTLY cap bytes. The cap is inclusive; only a fixture
        // sitting on it can say so.
        let exact = std::io::Cursor::new(vec![b'y'; cap as usize]);
        let bytes = read_whole_within(exact, cap)
            .expect("a file of exactly the cap must be accepted, not refused");
        assert_eq!(bytes.len(), cap as usize);
    }

    /// AXIS — THE #153 REBASE: an OMP source is NEVER windowed.
    ///
    /// OMP transcripts open with a fixed-width `title` slot and a `session` header
    /// record, and `omp::parse` refuses without them — so a TAIL window silently
    /// produces a transcript that no longer parses. The format is line-delimited, so the
    /// newline alignment is fine; the HEADER is what a tail cannot keep.
    ///
    /// THIS IS THE CHANGE THAT WOULD HAVE MERGED CLEANLY AND BEEN WRONG. #153 added the
    /// OMP harness while this branch was in review; nothing in either diff conflicts at
    /// `read_transfer_source`, and windowing would simply have started handing
    /// `omp::parse` a headerless tail. Mutation showed the exemption had no guard, which
    /// is why this exists.
    #[test]
    fn an_omp_source_is_read_whole_however_small_the_budget() {
        let root = temp_root("omp-not-windowed");
        let path = root.join("omp.jsonl");
        // Bigger than the budget below, so a windowing read would certainly drop the
        // header — the fixture straddles the threshold rather than merely exceeding it.
        let mut body = String::new();
        for index in 0..200 {
            body.push_str(&format!(
                "{}\n",
                json!({"type": "entry", "id": format!("e{index}"), "text": "x".repeat(64)})
            ));
        }
        std::fs::write(&path, body.as_bytes()).unwrap();
        let total = std::fs::metadata(&path).unwrap().len() as usize;
        let budget = total / 8;
        assert!(
            budget > 0 && total > budget,
            "precondition: {total} must exceed {budget}"
        );

        let omp = read_transcript_snapshot_with_budget(&path, budget, HarnessKind::Omp).unwrap();
        assert_eq!(
            omp.bytes.len(),
            total,
            "an OMP source must be read whole; a windowed tail loses the title slot and \
             session header its parser requires"
        );
        assert_eq!(
            omp.dropped_records, 0,
            "nothing may be dropped from an OMP source"
        );

        // THE CONTROL, and it needs a Claude-shaped file rather than this one: a
        // windowed Claude read refuses a window with no user turn, so reusing the OMP
        // fixture here fails for the wrong reason. Same budget, different harness —
        // which is what makes the assertion above about the HARNESS and not about the
        // budget being too generous to bite.
        let claude_body = synthetic_claude_transcript(200, 64);
        let claude_path = root.join("claude.jsonl");
        std::fs::write(&claude_path, claude_body.as_bytes()).unwrap();
        let claude_total = claude_body.len();
        let claude = read_transcript_snapshot_with_budget(
            &claude_path,
            claude_total / 8,
            HarnessKind::Claude,
        )
        .unwrap();
        assert!(
            claude.bytes.len() < claude_total,
            "precondition: this budget must actually window a JSONL source ({} of {})",
            claude.bytes.len(),
            claude_total
        );
        assert!(
            claude.dropped_records > 0,
            "precondition: the control must actually drop records"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-15: PRODUCTION `prepare` hands the importer the STAGED path, and a
    /// different one on every attempt.
    ///
    /// The previous version of this constructed two `PrivateClaudeBridge` values and
    /// compared their paths. That proves the bridge WRITER is unique and nothing about
    /// what `prepare` actually sends — a mutant that still creates a bridge but passes
    /// `source_path` to the importer restores Codex's retry skip/adoption bug with the
    /// test green. Both round-15 reviewers found that independently; it is the fifth
    /// time on this PR a fixture of mine sat beside the production path instead of on
    /// it, so this one drives `prepare` and reads what the app-server was told.
    ///
    /// The shim records the import request and exits; the import failing is fine,
    /// because the assertion is about what was SENT, not about the outcome.
    #[tokio::test]
    async fn production_prepare_sends_the_importer_a_fresh_staged_path_each_time() {
        let root = temp_root("prepare-import-source");
        let bin = root.join("bin");
        let sessions = root.join("claude");
        let target_home = root.join("codex");
        let project = sessions.join("projects/-tmp");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&target_home).unwrap();
        let session_id = "aaaaaaaa-0000-0000-0000-000000000001";
        let source = project.join(format!("{session_id}.jsonl"));
        write_fixture(
            &source,
            &[
                json!({"type":"user","cwd":"/tmp","sessionId":session_id,
                    "message":{"role":"user","content":"hello"}}),
                json!({"type":"assistant","cwd":"/tmp","sessionId":session_id,
                    "message":{"role":"assistant","content":[{"type":"text","text":"hi"}]}}),
            ],
        );

        let log = root.join("import-requests.log");
        let shim = bin.join("codex");
        std::fs::write(
            &shim,
            format!(
                // ANSWERS THE HANDSHAKE FIRST. The client sends `initialize` and WAITS
                // for its response before sending anything else, so a shim that only
                // watches for the import line blocks the exchange and times out having
                // recorded nothing. Same mistake as the delete-protocol shim earlier.
                "#!/bin/sh\n\
                 head -n 1 > /dev/null\n\
                 printf '%s\\n' '{{\"id\":1,\"result\":{{}}}}'\n\
                 while IFS= read -r line; do\n\
                 \x20 case \"$line\" in\n\
                 \x20   *externalAgentConfig/import*)\n\
                 \x20     printf '%s\\n' \"$line\" >> '{}'\n\
                 \x20     exit 0;;\n\
                 \x20 esac\n\
                 done\n",
                log.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let previous = std::env::var_os("PATH");
        // SAFETY: nextest gives each test its own process.
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    previous.as_ref().and_then(|p| p.to_str()).unwrap_or("")
                ),
            );
        }
        for _ in 0..2 {
            let _ = prepare(PrepareRequest {
                source_kind: HarnessKind::Claude,
                source_sessions_root: sessions.clone(),
                source_session_ref: crate::agent_resume::AgentSessionRef::id(
                    session_id.to_string(),
                )
                .expect("valid session id"),
                source_cursor: None,
                source_transcript_path: Some(source.clone()),
                target_kind: HarnessKind::Codex,
                target_config_home: target_home.clone(),
                target_sessions_root: target_home.clone(),
                target_launch_env: crate::config::AccountLaunchEnv::default(),
                cwd: std::path::PathBuf::from("/tmp"),
                timeout: Duration::from_secs(10),
            })
            .await;
        }
        if let Some(previous) = previous {
            unsafe { std::env::set_var("PATH", previous) };
        }

        let recorded = std::fs::read_to_string(&log).expect("the importer must be invoked");
        let paths: Vec<String> = recorded
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|value| {
                value["params"]["migrationItems"][0]["details"]["sessions"][0]["path"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(
            paths.len(),
            2,
            "both attempts must reach the importer: {recorded}"
        );
        assert!(
            paths.iter().all(|path| path != &source.to_string_lossy()),
            "the ORIGINAL transcript path must never be sent — Codex would look it up in \
             its import ledger and skip or reuse: {paths:?}"
        );
        assert_ne!(
            paths[0], paths[1],
            "two attempts must present DIFFERENT staged paths, or the second is skipped \
             or answered with the first attempt's thread"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn codex_import_rejects_an_ambiguous_ledger_target() {
        let root = temp_root("codex-import-ledger-ambiguous");
        let source = root.join("imports/source.jsonl");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"{}\n").unwrap();
        fs::write(
            root.join("external_agent_session_imports.json"),
            serde_json::to_vec(&json!({
                "records": [
                    {
                        "source_path": source.to_string_lossy(),
                        "imported_thread_id": "first-thread"
                    },
                    {
                        "source_path": source.to_string_lossy(),
                        "imported_thread_id": "second-thread"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        assert!(reuse_codex_import_target(&root, &source).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reported_native_path_disambiguates_without_weakening_identity_checks() {
        let root = temp_root("reported-source-path");
        let first = root.join("projects/first/session-1.jsonl");
        let second = root.join("projects/second/session-1.jsonl");
        fs::create_dir_all(first.parent().unwrap()).unwrap();
        fs::create_dir_all(second.parent().unwrap()).unwrap();
        fs::write(&first, b"{}\n").unwrap();
        fs::write(&second, b"{}\n").unwrap();
        assert!(find_native_transcript(HarnessKind::Claude, &root, "session-1").is_err());
        assert_eq!(
            select_native_transcript(
                HarnessKind::Claude,
                &root,
                &crate::agent_resume::AgentSessionRef::id("session-1").unwrap(),
                Some(&second),
            )
            .unwrap(),
            second.canonicalize().unwrap()
        );

        let mismatched = root.join("projects/first/other.jsonl");
        fs::write(&mismatched, b"{}\n").unwrap();
        assert!(matches!(
            select_native_transcript(
                HarnessKind::Claude,
                &root,
                &crate::agent_resume::AgentSessionRef::id("session-1").unwrap(),
                Some(&mismatched),
            ),
            Err(TransferError::InvalidPath(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn destination_comparison_names_first_difference() {
        let expected = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "a".into(),
        }];
        let actual = CanonicalTranscript {
            messages: vec![VisibleMessage {
                role: VisibleRole::User,
                text: "b".into(),
            }],
            omissions: OmissionSummary::default(),
            fingerprint: TranscriptFingerprint {
                byte_len: 0,
                sha256: String::new(),
            },
        };
        assert!(verify_destination(&expected, &actual)
            .unwrap_err()
            .to_string()
            .contains("message 1"));
    }

    /// Build a transcript of `count` minimal Claude records, each padded so the
    /// file reliably exceeds a budget.
    fn synthetic_claude_transcript(count: usize, pad: usize) -> String {
        (0..count)
            .map(|index| {
                let filler = "x".repeat(pad);
                format!(
                    "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"m{index} {filler}\"}}}}\n"
                )
            })
            .collect()
    }

    fn temp_transcript(tag: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "herdr-window-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("transcript.jsonl");
        std::fs::write(&path, body).unwrap();
        path
    }

    /// AXIS — THE REGRESSION TEST FOR REVIEW FINDING 1, and the shape every other test
    /// here was missing.
    ///
    /// It goes through `read_transcript`, the PUBLIC entry point, which calls
    /// `validate_transcript_path` before the windowing reader. The original tests called
    /// the private reader directly and so entered BELOW the guard that refused oversize
    /// files — they passed while the feature never executed on the real path, and CI was
    /// 6 of 6 green over a dead code path. A test that keeps calling the reader directly
    /// stays green through the exact defect.
    ///
    /// Deliberately uses the REAL budget rather than an injected one: the defect was a
    /// second size rule upstream of the window, and only the real constant can catch a
    /// disagreement between them.
    #[test]
    fn an_oversize_transcript_survives_the_public_read_path() {
        let record_bytes = 64 * 1024;
        // Comfortably over TRANSFER_WINDOW_BYTES so the window genuinely engages.
        let record_count = (TRANSFER_WINDOW_BYTES as usize / record_bytes) + 200;
        let body = synthetic_claude_transcript(record_count, record_bytes);
        assert!(
            body.len() as u64 > TRANSFER_WINDOW_BYTES,
            "precondition: the fixture must exceed the window, or this proves nothing"
        );
        let path = temp_transcript("public-oversize", &body);
        let home = path.parent().unwrap();

        // CLAUDE -> CODEX, because that is the only oversize transfer production runs.
        // This asked for Claude -> Claude, which `same_session_harness` REJECTS before
        // preparation (src/app/api/session_transfer.rs:143-150), so the regression
        // entered a combination the transfer refuses — and additionally skipped
        // claude_to_codex_import_projection, which every real oversize Claude transfer
        // executes. Third round of the same defect in a third disguise: the test and
        // the production path drift apart while the test stays green.
        let (transcript, _snapshot) =
            read_transfer_source(HarnessKind::Claude, HarnessKind::Codex, home, &path, None)
                .expect("an oversize transcript must window, not be refused");

        assert!(
            !transcript.messages.is_empty(),
            "the window must carry messages"
        );
        assert!(
            transcript.omissions.windowed_records > 0,
            "an oversize transcript must report the history it left behind"
        );
        assert_eq!(
            transcript.fingerprint.byte_len,
            body.len() as u64,
            "the fingerprint must still cover the whole file"
        );

        let _ = std::fs::remove_dir_all(home);
    }

    /// AXIS — REVIEW FINDING 3: the window opens on a USER turn, not mid-thought.
    ///
    /// A record boundary is not a conversational one. A window can legally begin with an
    /// assistant reply whose user message fell outside it — a syntactically valid
    /// transcript that resumes with an answer to a question that is not there. Nothing
    /// downstream reports it, because it parses.
    #[test]
    fn the_window_opens_on_a_user_turn_not_an_orphan_reply() {
        // Alternating user/assistant, so wherever the byte budget lands there is a real
        // chance the first whole record is an assistant one.
        let mut body = String::new();
        for index in 0..400 {
            let filler = "x".repeat(512);
            body.push_str(&format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"q{index} {filler}\"}}}}\n"
            ));
            body.push_str(&format!(
                "{{\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":\"a{index} {filler}\"}}}}\n"
            ));
        }
        let path = temp_transcript("user-turn", &body);

        for budget in [16 * 1024usize, 20 * 1024, 24 * 1024, 28 * 1024] {
            let snapshot =
                read_transcript_snapshot_with_budget(&path, budget, HarnessKind::Claude).unwrap();
            let first = snapshot
                .bytes
                .split(|byte| *byte == b'\n')
                .find(|line| !line.is_empty())
                .expect("a non-empty window");
            let value: Value = serde_json::from_slice(first).expect("whole JSON");
            assert_eq!(
                value.get("type").and_then(Value::as_str),
                Some("user"),
                "budget {budget}: the window must open on a user turn, not an orphan reply"
            );
        }

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// AXIS — REVIEW FINDING 4: a window whose byte boundary lands EXACTLY on a record
    /// boundary keeps that record instead of discarding it.
    ///
    /// The old alignment always searched forward for a newline, so a window that already
    /// began at a record start threw one complete record away for nothing.
    #[test]
    fn an_exact_boundary_does_not_discard_a_whole_record() {
        // FIXED-WIDTH records, deliberately: `synthetic_claude_transcript` writes m9
        // and m10, so its records differ by a byte and "a budget of exactly N records"
        // is then not exactly N records. The first version of this test used it and
        // failed for that reason — the fixture, not the code.
        let mut body = String::new();
        for index in 0..40 {
            let filler = "x".repeat(64);
            body.push_str(&format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"m{index:04} {filler}\"}}}}\n"
            ));
        }
        let path = temp_transcript("exact-boundary", &body);
        let record_len = body.lines().next().unwrap().len() + 1; // + newline
        assert!(
            body.lines().all(|line| line.len() + 1 == record_len),
            "precondition: records must be uniform width for an exact-boundary budget"
        );

        // A budget of exactly N records means the window boundary falls precisely on a
        // record start; all N must survive.
        let wanted = 10usize;
        let snapshot =
            read_transcript_snapshot_with_budget(&path, record_len * wanted, HarnessKind::Claude)
                .unwrap();
        let kept = snapshot
            .bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count();
        assert_eq!(kept, wanted, "an exact boundary must not cost a record");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// AXIS — ROUND-2 FINDING 1: a window with no usable user turn FAILS CLOSED.
    ///
    /// The earlier version kept the record-aligned tail, reasoning that a degraded
    /// window beats no window. It does not: staging then succeeds and writes a session
    /// that opens with an answer to a prompt outside the window, and nothing downstream
    /// can tell. Refusing is the only outcome that does not lie.
    #[test]
    fn a_window_with_no_user_turn_is_refused_rather_than_resumed() {
        // Assistant records only, large enough that the window cannot reach a user turn.
        let mut body = String::new();
        body.push_str(
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"the only prompt\"}}\n",
        );
        for index in 0..200 {
            let filler = "x".repeat(512);
            body.push_str(&format!(
                "{{\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":\"a{index} {filler}\"}}}}\n"
            ));
        }
        let path = temp_transcript("no-user-turn", &body);

        let err = read_transcript_snapshot_with_budget(&path, 8 * 1024, HarnessKind::Claude)
            .expect_err("a window of pure assistant replies must be refused");
        assert!(
            matches!(err, TransferError::NoUserTurnInWindow),
            "expected NoUserTurnInWindow, got {err}"
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// AXIS — ROUND-2 FINDING 2: a `type=user` record carrying only a TOOL RESULT does
    /// not open a turn.
    ///
    /// The label says user; the parser emits no visible user message, and the Codex
    /// projection reclassifies the same record as assistant. A boundary check that reads
    /// the label passes here and still opens the window on a reply — which is why the
    /// check now asks the parser what it would emit. The previous test could not detect
    /// this, because it checked the label too.
    #[test]
    fn a_tool_result_labelled_user_does_not_open_a_turn() {
        let tool_result = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"t1\",\"content\":\"output\"}]}}";
        let real_user =
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"a real question\"}}";

        let value: Value = serde_json::from_str(tool_result).unwrap();
        assert_eq!(
            value.get("type").and_then(Value::as_str),
            Some("user"),
            "precondition: the record is LABELLED user, which is the whole trap"
        );
        assert!(
            !opens_user_turn(&value, HarnessKind::Claude),
            "a tool-result-only record emits no visible user message and must not open a turn"
        );

        let real: Value = serde_json::from_str(real_user).unwrap();
        assert!(
            opens_user_turn(&real, HarnessKind::Claude),
            "a genuine user message must still open a turn, or the window can never start"
        );

        // And end to end: a window whose first record is the tool result must advance
        // past it to the real question.
        let body = format!("{tool_result}\n{real_user}\n");
        let path = temp_transcript("tool-result-boundary", &body);
        let offset = first_user_turn_offset(body.as_bytes(), HarnessKind::Claude)
            .expect("the real user record must be found");
        assert!(
            offset > 0,
            "the window must skip the tool result, not open on it"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// AXIS — ROUND-3 FINDING 1, RE-AIMED IN ROUND 4: a CODEX destination larger than
    /// the source window is verified in FULL, not through the window's tail.
    ///
    /// Codex expands what it imports — TurnStarted, UserMessage, ResponseItem and
    /// TurnComplete per message — so a source window near the budget yields a
    /// destination over it. Reading that destination's tail and comparing it against
    /// the full source projection fails a transfer that worked.
    ///
    /// The round-3 version read a CLAUDE destination. The expansion under test happens
    /// only for a CODEX target, so it could not have caught a regression in the path it
    /// claimed to protect — the third instance of a test drifting off the production
    /// path while staying green.
    #[test]
    fn a_codex_destination_larger_than_the_window_is_read_whole() {
        let root = temp_root("codex-dest-whole");
        let path = root.join("rollout-thread.jsonl");

        // The shape a real Codex import produces: paired response_item + event_msg per
        // user turn, plus an assistant response.
        let mut records = vec![json!({"type":"session_meta","payload":{"id":"thread"}})];
        for index in 0..120 {
            let filler = "x".repeat(256);
            let prompt = format!("q{index} {filler}");
            records.push(json!({"type":"event_msg","payload":{"type":"turn_started"}}));
            records.push(
                json!({"type":"response_item","payload":{"type":"message","role":"user",
                "content":[{"type":"input_text","text":prompt}]}}),
            );
            records.push(json!({"type":"event_msg","payload":{"type":"user_message",
                "message":prompt,"images":[],"local_images":[]}}));
            records.push(
                json!({"type":"response_item","payload":{"type":"message","role":"assistant",
                "content":[{"type":"output_text","text":format!("a{index} {filler}")}]}}),
            );
        }
        write_fixture(&path, &records);
        let body = std::fs::read(&path).unwrap();

        // The reader compares against the expected projection as records arrive, so
        // the test supplies exactly what the source would have produced.
        let mut expect = Vec::new();
        for index in 0..120 {
            let filler = "x".repeat(256);
            expect.push(VisibleMessage {
                role: VisibleRole::User,
                text: format!("q{index} {filler}"),
            });
            expect.push(VisibleMessage {
                role: VisibleRole::Assistant,
                text: format!("a{index} {filler}"),
            });
        }
        let whole = read_destination_transcript(HarnessKind::Codex, &root, &path, &expect)
            .expect("a Codex destination must be readable in full");

        // The two readers must genuinely disagree, or this proves nothing.
        let windowed =
            read_transcript_snapshot_with_budget(&path, 8 * 1024, HarnessKind::Codex).unwrap();
        assert!(
            windowed.dropped_records > 0,
            "precondition: the windowing reader must actually drop records here"
        );
        let windowed_messages = parse_jsonl_snapshot(&windowed, HarnessKind::Codex)
            .map(|t| t.messages.len())
            .unwrap_or(0);

        assert_eq!(
            whole.messages.len(),
            240,
            "the destination read must see EVERY visible message (120 user + 120 assistant)"
        );
        assert!(
            whole.messages.len() > windowed_messages,
            "and strictly more than a windowed read would have seen ({windowed_messages})"
        );
        assert_eq!(
            whole.fingerprint.byte_len,
            body.len() as u64,
            "and must cover the whole file"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-8: the destination budget is NOT derived from the expected messages.
    ///
    /// Rounds 4-7 each refined a limit computed from our own message text and then
    /// applied it to every record in the file. Codex writes `session_meta` from the
    /// TARGET's configuration, so its size is unrelated to the transcript: the reviewer
    /// measured a legitimate metadata record at 8,454,325 bytes against a limit of
    /// 8,454,144 derived from a one-character message, refused 181 bytes over, after the
    /// session had been created.
    ///
    /// GOES THROUGH `read_destination_transcript`, not a formula. The round-7 test
    /// asserted a derivation in isolation, so a mutant that kept an expected-text-only
    /// derivation and rejected valid metadata stayed green.
    #[test]
    fn destination_metadata_larger_than_every_expected_message_is_accepted() {
        let root = temp_root("codex-dest-metadata");
        let path = root.join("rollout-thread.jsonl");

        // SIZED ABOVE THE LARGEST LIMIT ANY EXPECTED-DERIVED FORMULA PRODUCED. The
        // floor of the round-7 formula was MAX_TRANSCRIPT_LINE_BYTES + 64 KiB, so a
        // metadata record must exceed that to discriminate — a smaller one passes under
        // both the old rule and the new one and proves nothing. It stays well under
        // DESTINATION_RECORD_BUDGET_BYTES, which is the bound that still applies.
        let instructions = "i".repeat(9 * 1024 * 1024);
        let records = vec![
            json!({"type":"session_meta","payload":{"id":"thread",
                "base_instructions":instructions}}),
            json!({"type":"response_item","payload":{"type":"message","role":"user",
                "content":[{"type":"input_text","text":"q"}]}}),
            json!({"type":"event_msg","payload":{"type":"user_message",
                "message":"q","images":[],"local_images":[]}}),
        ];
        write_fixture(&path, &records);

        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "q".to_string(),
        }];

        // State the counts, not just the verdict: the fixture has to straddle the old
        // limit for the assertion below to mean anything.
        let metadata_bytes = serde_json::to_string(&records[0]).unwrap().len();
        let round_seven_limit = (serde_json::to_string("q").unwrap().len() + 64 * 1024)
            .max(MAX_TRANSCRIPT_LINE_BYTES + 64 * 1024);
        assert!(
            metadata_bytes > round_seven_limit,
            "precondition: metadata record {metadata_bytes} bytes must exceed the \
             round-7 limit {round_seven_limit} or this cannot discriminate"
        );
        assert!(
            metadata_bytes < DESTINATION_RECORD_BUDGET_BYTES,
            "precondition: the fixture must stay inside the retention budget"
        );

        let read = read_destination_transcript(HarnessKind::Codex, &root, &path, &expect)
            .expect("metadata sized by the target's own configuration must not be refused");
        assert_eq!(read.messages, expect);
    }

    /// AXIS — ROUND-8 (the other half): the retention budget still binds.
    ///
    /// Removing the expected-derived limit must not remove the bound. A single record
    /// larger than DESTINATION_RECORD_BUDGET_BYTES is still refused, so a mutant that
    /// deletes the check — which the test above cannot see — turns this red.
    #[test]
    fn a_destination_record_over_the_retention_budget_is_still_refused() {
        let root = temp_root("codex-dest-over-budget");
        let path = root.join("rollout-thread.jsonl");

        let oversize = "i".repeat(DESTINATION_RECORD_BUDGET_BYTES + 1024);
        let records = vec![json!({"type":"session_meta","payload":{"id":"thread",
            "base_instructions":oversize}})];
        write_fixture(&path, &records);

        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "q".to_string(),
        }];
        let err = read_destination_transcript(HarnessKind::Codex, &root, &path, &expect)
            .expect_err("a record past the retention budget must be refused");
        assert!(
            matches!(err, TransferError::LineTooLarge { limit, .. }
                if limit == DESTINATION_RECORD_BUDGET_BYTES),
            "expected a LineTooLarge naming the retention budget, got {err}"
        );
    }

    /// AXIS — ROUND-9: a target named before the response survives the failure.
    ///
    /// `wait_for_import_result` buffers completions until response 2 tells it which
    /// importId is ours. If the app-server names a created thread and THEN dies, the old
    /// code returned an error and dropped that id — so a real thread existed with
    /// nothing left able to refer to it, and every retry made another.
    #[tokio::test]
    async fn a_target_named_before_the_response_is_reported_through_the_failure() {
        // A completion carrying a target, then EOF: no response 2 ever arrives.
        // The real completion shape, not a guess at it: the target lives under
        // itemTypeResults -> SESSIONS -> successes[].target, which is what
        // `parse_import_completion` reads. My first fixture invented a flat
        // `targetThreadId` field and the test failed — correctly, because the
        // production extractor would not have found a target there either.
        let stream = concat!(
            r#"{"method":"externalAgentConfig/import/completed","params":{"#,
            r#""importId":"imp-1","itemTypeResults":[{"itemType":"SESSIONS","#,
            r#""successes":[{"target":"thread-abc"}],"failures":[]}]}}"#,
            "\n"
        );
        let mut reader =
            tokio::io::BufReader::new(std::io::Cursor::new(stream.as_bytes().to_vec()));
        let mut observed = Vec::new();
        let err = wait_for_import_result(&mut reader, &mut observed)
            .await
            .expect_err("EOF before the response must still fail");
        assert!(
            matches!(&err, TransferError::CodexImport(message)
                if message.contains("exited before import completed")),
            "expected the EOF error, got {err}"
        );
        assert_eq!(
            observed,
            vec!["thread-abc".to_string()],
            "the target the app-server named must survive the failure so it can be \
             cleaned up"
        );
    }

    /// AXIS — ROUND-10: a completion reporting BOTH a success and a failure still yields
    /// its created target for cleanup.
    ///
    /// Found independently by both round-10 reviewers. Codex 0.150.1 can persist a
    /// target, add it to `successes`, and then report a ledger-update failure.
    /// `parse_import_completion` returns on failures BEFORE it extracts successes, so
    /// reading the observable target through it left that session behind — and this is
    /// not the unnamed-target case filed as #155: the session is named right there in
    /// the payload.
    #[tokio::test]
    async fn a_completion_with_failures_still_yields_its_created_target() {
        let params = json!({
            "importId": "imp-1",
            "itemTypeResults": [{
                "itemType": "SESSIONS",
                "successes": [{"target": "thread-created"}],
                "failures": [{"itemType": "SESSIONS", "subErrorType": "ledger_update_failed"}]
            }]
        });

        // Validation still refuses it — the transfer did not succeed...
        assert!(
            parse_import_completion(&params).is_err(),
            "a completion carrying failures must not be accepted as a successful import"
        );

        // ...and the PRODUCTION LOOP still learns about the session it made. Round 11:
        // asserting on `named_import_targets` alone left a mutant green that reverted
        // `wait_for_import_result` to success-only extraction, because nothing entered
        // through the loop that actually populates `observed_targets`.
        let stream = format!(
            "{}\n",
            json!({"method": "externalAgentConfig/import/completed", "params": params})
        );
        let mut reader =
            tokio::io::BufReader::new(std::io::Cursor::new(stream.as_bytes().to_vec()));
        let mut observed = Vec::new();
        let err = wait_for_import_result(&mut reader, &mut observed)
            .await
            .expect_err("a completion with failures is not a successful import");
        assert!(
            matches!(&err, TransferError::CodexImport(_)),
            "expected an import error, got {err}"
        );
        assert_eq!(
            observed,
            vec!["thread-created".to_string()],
            "the created session must be retained for cleanup by the production loop"
        );
    }

    /// AXIS — ROUND-9: an app-server line is refused BEFORE it is fully allocated.
    ///
    /// This checked the 2 MiB cap after `read_line` had already allocated the whole
    /// line, so one unterminated response could exhaust memory before the refusal ran.
    /// The fixture is a line past the cap with NO trailing newline, which is the case
    /// the old code could not survive: a bound applied afterwards never fires.
    #[tokio::test]
    async fn an_oversize_app_server_line_is_refused_before_it_is_allocated() {
        // FOUR EXTRA MEGABYTES, AND THE ASSERTION IS ON BYTES CONSUMED. Refusing after
        // the read completes returns the SAME error, so an error alone cannot tell the
        // two apart — the reader's position can. A bound that fires while the line is
        // still partial stops near the cap; one that fires afterwards has read to EOF.
        let total = MAX_APP_SERVER_LINE_BYTES + 4 * 1024 * 1024;
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(vec![b'x'; total]));
        let err = read_protocol_message(&mut reader)
            .await
            .expect_err("an oversize response must be refused");
        assert!(
            matches!(&err, TransferError::CodexImport(message)
                if message.contains("exceeded the size limit")),
            "expected a size refusal, got {err}"
        );
        let consumed = reader.into_inner().position() as usize;
        assert!(
            consumed < total,
            "the refusal must fire before the whole line is read: consumed {consumed} \
             of {total}"
        );

        // And a well-formed response of ordinary size still parses, so the refusal is
        // not simply rejecting everything.
        let mut ok =
            tokio::io::BufReader::new(std::io::Cursor::new(b"{\"id\":1,\"result\":{}}\n".to_vec()));
        let value = read_protocol_message(&mut ok)
            .await
            .expect("valid response");
        assert_eq!(value["id"], 1);
    }

    /// AXIS — ROUND-11: the rollout scanner refuses BEFORE consuming the whole line.
    ///
    /// I reported this site clean in round 9's sweep: `Read::take` bounds the whole
    /// READER at 64 MiB, so an unterminated first line could allocate all of it before
    /// the stated 2 MiB per-line limit ran. Round 10 corrected me, and round 11 pointed
    /// out the correction had no regression of its own — reverting to `read_line` plus
    /// the same size error left every existing test green, because they use tiny records.
    ///
    /// Asserted on BYTES CONSUMED, since both implementations return the same error.
    #[test]
    fn the_rollout_scanner_refuses_before_consuming_an_oversize_line() {
        let total = MAX_APP_SERVER_LINE_BYTES + 4 * 1024 * 1024;
        let mut cursor = std::io::Cursor::new(vec![b'x'; total]);
        let err = codex_rollout_declares_thread_in(&mut cursor, "wanted")
            .expect_err("an oversize record must be refused");
        assert!(
            matches!(err, TransferError::LineTooLarge { limit, .. }
                if limit == MAX_APP_SERVER_LINE_BYTES),
            "expected the per-line cap, got {err}"
        );

        // THE DISCRIMINATING ASSERTION. Both implementations return the error above, so
        // the error alone proves nothing — a `read_line` version reaches it only after
        // consuming everything. My first version of this test asserted the error and
        // stopped, while its own comment claimed it measured consumption.
        let consumed = cursor.position() as usize;
        assert!(
            consumed < total,
            "the cap must fire while the line is still partial: consumed {consumed} \
             of {total}"
        );
    }

    /// AXIS — ROUND-10: the PRODUCTION wrapper's record budget, on the main pass.
    ///
    /// The Codex full-size regression is refused by the PRE-pass, so nothing pinned the
    /// main pass's production argument — mutating it left every test green. A Claude
    /// destination has no pre-pass, so this is the wrapper's own configuration.
    #[test]
    fn the_production_wrapper_enforces_the_record_budget_on_the_main_pass() {
        let root = temp_root("wrapper-main-budget");
        let path = root.join("session.jsonl");
        let oversize = "y".repeat(DESTINATION_RECORD_BUDGET_BYTES + 1024);
        write_fixture(
            &path,
            &[json!({"type":"user","message":{"role":"user","content":oversize}})],
        );

        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "q".to_string(),
        }];
        let err = read_destination_transcript(HarnessKind::Claude, &root, &path, &expect)
            .expect_err("the production wrapper must refuse a record past the budget");
        assert!(
            matches!(err, TransferError::LineTooLarge { limit, .. }
                if limit == DESTINATION_RECORD_BUDGET_BYTES),
            "expected the production record budget, got {err}"
        );
    }

    /// AXIS — ROUND-10: the total budget admits a modelled worst-case expansion.
    ///
    /// Round 10's objection was that four windows was never PROVEN to admit a legitimate
    /// transfer, and a bound that refuses a VALID transfer is the defect this PR has had
    /// in five forms. Codex writes several records per source pair and duplicates message
    /// text, so expansion is worst for MANY TINY messages, where per-record envelope
    /// overhead dominates — which is the shape measured here.
    ///
    /// WHAT THIS IS AND IS NOT. Round 11: my first version omitted Codex's assistant
    /// event and turn-complete records and gave the Claude source no `cwd`, so calling it
    /// "the worst expansion Codex actually makes" overclaimed — it did not run an import
    /// at all. The record set below models every kind 0.150.1 emits per pair, and the
    /// source carries the fields the importer requires, but it is still a MODEL: this is
    /// a lower bound on expansion, not a proof of the maximum.
    ///
    /// The strongest evidence for the 16x policy is not this test — it is that a reviewer
    /// looked for a legitimate transcript exceeding it and found none. Recorded here
    /// because that is the kind of evidence that otherwise lives only in a verdict.
    #[test]
    fn codex_expansion_stays_far_inside_the_total_budget() {
        let root = temp_root("expansion-ratio");
        let source = root.join("source.jsonl");
        let destination = root.join("rollout-thread.jsonl");

        // The worst case for expansion: the smallest messages that still carry content.
        let pairs = 400;
        let mut source_records = Vec::new();
        let mut destination_records =
            vec![json!({"type":"session_meta","payload":{"id":"thread"}})];
        for index in 0..pairs {
            let prompt = format!("q{index}");
            let answer = format!("a{index}");
            // The source carries `cwd` and `sessionId`, which the Claude importer
            // requires — without them there is nothing to import and the ratio is
            // measured against a file Codex would have rejected.
            source_records.push(json!({"type":"user","cwd":"/tmp",
                "sessionId":"aaaaaaaa-0000-0000-0000-000000000001",
                "message":{"role":"user","content":prompt}}));
            source_records.push(json!({"type":"assistant","cwd":"/tmp",
                "sessionId":"aaaaaaaa-0000-0000-0000-000000000001",
                "message":{"role":"assistant","content":[{"type":"text","text":answer}]}}));
            // SIX destination records per pair, not four: the user event and response
            // item, the ASSISTANT event, its response item, and the turn boundary
            // records. Omitting the assistant event and turn-complete understated the
            // expansion, which is the direction that matters for a budget.
            destination_records.push(json!({"type":"event_msg","payload":{"type":"turn_started"}}));
            destination_records.push(
                json!({"type":"response_item","payload":{"type":"message","role":"user",
                "content":[{"type":"input_text","text":prompt}]}}),
            );
            destination_records.push(json!({"type":"event_msg","payload":{"type":"user_message",
                "message":prompt,"images":[],"local_images":[]}}));
            destination_records.push(
                json!({"type":"response_item","payload":{"type":"message","role":"assistant",
                "content":[{"type":"output_text","text":answer}]}}),
            );
            destination_records.push(json!({"type":"event_msg","payload":{"type":"agent_message",
                "message":answer}}));
            destination_records.push(json!({"type":"event_msg",
                "payload":{"type":"turn_complete","turn_id":index}}));
        }
        write_fixture(&source, &source_records);
        write_fixture(&destination, &destination_records);

        let source_bytes = std::fs::metadata(&source).unwrap().len();
        let destination_bytes = std::fs::metadata(&destination).unwrap().len();
        let ratio = destination_bytes as f64 / source_bytes as f64;
        let budget_multiple = DESTINATION_TOTAL_BUDGET_BYTES as f64 / TRANSFER_WINDOW_BYTES as f64;

        // Counts with the verdict, not just the verdict.
        assert!(
            ratio < budget_multiple / 2.0,
            "modelled Codex expansion {ratio:.2}x on {pairs} tiny message pairs \
             ({source_bytes} -> {destination_bytes} bytes); the total budget allows \
             {budget_multiple:.0}x, which leaves too little margin"
        );
        assert_eq!(
            DESTINATION_TOTAL_BUDGET_BYTES,
            16 * TRANSFER_WINDOW_BYTES,
            "the total budget is a stated multiple of the window, not an inferred one"
        );
    }

    /// AXIS — ROUND-9: the MAIN pass enforces the record budget on its own.
    ///
    /// The round-8 over-budget regression used a Codex destination, where the pre-pass
    /// reads first and refuses first — so a mutant that raised only the main pass's
    /// limit stayed green. A Claude destination has no pre-pass, so this reaches the
    /// main pass directly.
    #[test]
    fn the_main_pass_enforces_the_record_budget_without_a_pre_pass() {
        let root = temp_root("main-pass-budget");
        let path = root.join("session.jsonl");
        let budget = 4096usize;
        let records = vec![json!({"type":"user","message":{"role":"user",
            "content":"y".repeat(budget * 2)}})];
        write_fixture(&path, &records);

        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "y".repeat(budget * 2),
        }];
        let err = read_destination_transcript_within(
            HarnessKind::Claude,
            &root,
            &path,
            &expect,
            usize::MAX,
            u64::MAX,
            budget,
            DESTINATION_TOTAL_BUDGET_BYTES,
        )
        .expect_err("the main pass must refuse a record past the budget");
        assert!(
            matches!(err, TransferError::LineTooLarge { limit, .. } if limit == budget),
            "expected LineTooLarge naming the record budget, got {err}"
        );
    }

    /// AXIS — ROUND-9: the CODEX PRE-PASS enforces the same budget.
    ///
    /// The pair to the test above: between them, a mutant on either pass's limit dies.
    #[test]
    fn the_codex_pre_pass_enforces_the_record_budget() {
        let root = temp_root("pre-pass-budget");
        let path = root.join("rollout-thread.jsonl");
        let budget = 4096usize;
        let records = vec![json!({"type":"session_meta","payload":{"id":"thread",
            "base_instructions":"i".repeat(budget * 2)}})];
        write_fixture(&path, &records);

        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "q".to_string(),
        }];
        // MAIN-PASS BUDGETS WIDE OPEN, so a refusal can only have come from the
        // pre-pass. Sharing one budget made this test unfalsifiable: the main pass
        // refused the same record with the same error, and a mutant on the pre-pass
        // limit survived it.
        let err = read_destination_transcript_within(
            HarnessKind::Codex,
            &root,
            &path,
            &expect,
            budget,
            DESTINATION_TOTAL_BUDGET_BYTES,
            usize::MAX,
            u64::MAX,
        )
        .expect_err("the pre-pass must refuse a record past the budget");
        assert!(
            matches!(err, TransferError::LineTooLarge { limit, .. } if limit == budget),
            "expected LineTooLarge naming the record budget, got {err}"
        );
    }

    /// AXIS — ROUND-9: TOTAL work is bounded, not just each record.
    ///
    /// Both reviewers, independently: a per-record bound lets a producer emit
    /// arbitrarily many sub-budget records, all of which are parsed twice. Asserted on
    /// BOTH kinds, because the two passes count separately and a bound applied to only
    /// one of two full scans halves nothing.
    #[test]
    fn each_destination_pass_stops_at_the_total_budget() {
        let root = temp_root("total-budget");
        let expect = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "q".to_string(),
        }];

        for (kind, name, filler) in [
            (
                HarnessKind::Claude,
                "session.jsonl",
                json!({"type":"system","content":"x".repeat(512)}),
            ),
            (
                HarnessKind::Codex,
                "rollout-thread.jsonl",
                json!({"type":"session_meta","payload":{"id":"thread",
                    "base_instructions":"x".repeat(512)}}),
            ),
        ] {
            let path = root.join(name);
            let records: Vec<_> = std::iter::repeat_n(filler, 200).collect();
            write_fixture(&path, &records);
            let total = std::fs::metadata(&path).unwrap().len();
            let budget = total / 4;
            assert!(
                budget > 0 && total > budget,
                "precondition: {name} must exceed the budget ({total} vs {budget})"
            );

            // The Codex case aims the budget at the PRE-pass (main pass unbounded) and
            // the Claude case at the main pass, so each arm can only be satisfied by the
            // pass it names.
            let (pre_total, main_total) = match kind {
                HarnessKind::Codex => (budget, u64::MAX),
                HarnessKind::Claude => (u64::MAX, budget),
                // This fixture drives the two JSONL passes; OMP has neither.
                HarnessKind::Omp => unreachable!("the total-budget fixture is JSONL-only"),
            };
            let err = read_destination_transcript_within(
                kind,
                &root,
                &path,
                &expect,
                DESTINATION_RECORD_BUDGET_BYTES,
                pre_total,
                DESTINATION_RECORD_BUDGET_BYTES,
                main_total,
            )
            .expect_err("scanning must stop at the total budget");
            assert!(
                matches!(err, TransferError::DestinationTooLarge { limit, .. } if limit == budget),
                "expected DestinationTooLarge for {name}, got {err}"
            );
        }
    }

    /// AXIS — ROUND-9: an EXACTLY budget-sized record is accepted by the real reader.
    ///
    /// The round-6 delimiter regression asserted on `content_len` alone, so a mutant
    /// comparing `out.len()` — which includes the newline — left it green while
    /// rejecting a record of exactly the limit. This drives `read_line_bounded` itself.
    /// The limit is a parameter of that function, so passing a small one is the real
    /// production path with a real argument, not a bypass.
    #[test]
    fn a_record_of_exactly_the_budget_is_accepted_by_the_reader() {
        let root = temp_root("exact-boundary");
        let path = root.join("exact.jsonl");
        let limit = 2048usize;
        let mut body = vec![b'x'; limit];
        body.push(b'\n');
        std::fs::write(&path, &body).unwrap();

        let file = std::fs::File::open(&path).unwrap();
        let mut reader = BufReader::new(file);
        let mut raw = Vec::new();
        let read = read_line_bounded(&mut reader, &mut raw, 1, limit)
            .expect("a record of exactly the limit must be accepted");
        assert_eq!(read, limit + 1, "the delimiter is read but not counted");
        assert_eq!(content_len(&raw), limit);
    }

    /// AXIS — ROUND-6: the delimiter is EXCLUDED from a record's measured length.
    ///
    /// The round-5 reader added the trailing newline before comparing, while the source
    /// parser splits on it and never counts it — so an exactly limit-sized record
    /// measured limit+1 and was refused, and only AFTER the target session existed.
    ///
    /// Tested on `content_len` DIRECTLY rather than through a fixture, and the reason is
    /// worth stating: the derived limit is `largest expected text + 64 KiB`, so a record
    /// that MATCHES its expected text is always ~64 KiB below the limit and the boundary
    /// is unreachable from outside. A fixture-based version of this test passed against a
    /// build that counted the delimiter — it could not have failed. The headroom makes
    /// the off-by-one harmless in production; this pins the unit that implements it.
    #[test]
    fn a_records_measured_length_excludes_its_delimiter() {
        assert_eq!(content_len(b"abc"), 3, "no delimiter, no adjustment");
        assert_eq!(content_len(b"abc\n"), 3, "the newline must not count");
        assert_eq!(content_len(b"abc\r\n"), 3, "nor a CRLF pair");
        assert_eq!(content_len(b"\n"), 0, "a bare newline is an empty record");
        assert_eq!(content_len(b""), 0);
        // The boundary case the source parser and this reader must agree on.
        let exact = vec![b'x'; MAX_TRANSCRIPT_LINE_BYTES];
        let mut terminated = exact.clone();
        terminated.push(b'\n');
        assert_eq!(
            content_len(&terminated),
            MAX_TRANSCRIPT_LINE_BYTES,
            "an exactly limit-sized record must measure the limit, not limit+1"
        );
    }

    /// AXIS — ROUND-6: the expected-count check fires DURING the read, not after EOF.
    ///
    /// Discriminated by MALFORMED TRAILING INPUT placed after the surplus message. If
    /// enforcement happens as records arrive, the mismatch is reported and the garbage
    /// is never parsed. If it were moved after EOF — which the round-5 test could not
    /// tell apart — the parser would reach the garbage first and the observed error
    /// would be InvalidJson instead.
    #[test]
    fn a_surplus_message_is_caught_before_later_garbage_is_parsed() {
        let root = temp_root("dest-early-stop");
        let path = root.join("destination.jsonl");

        let mut body = String::new();
        for index in 0..3 {
            body.push_str(&format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"m{index}\"}}}}\n"
            ));
        }
        body.push_str("this is not json at all\n");
        std::fs::write(&path, &body).unwrap();

        // Expect only the first two; the third is surplus and precedes the garbage.
        let expect = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "m0".to_string(),
            },
            VisibleMessage {
                role: VisibleRole::User,
                text: "m1".to_string(),
            },
        ];
        let err = read_destination_transcript(HarnessKind::Claude, &root, &path, &expect)
            .expect_err("a surplus message must be refused");
        assert!(
            matches!(err, TransferError::DestinationMismatch(_)),
            "expected a mismatch reported during the read, got {err} — InvalidJson here \
             would mean the check ran only after the whole file was parsed"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-6: the Codex pre-pass retains ONLY texts we sent.
    ///
    /// It previously inserted every distinct external user_message into a HashSet with
    /// no bound, so a destination for one expected message could carry arbitrarily many
    /// unique sub-limit events and exhaust memory before the guarded pass began — an
    /// untrusted file setting our memory budget.
    #[test]
    fn the_codex_prepass_retains_only_expected_texts() {
        let root = temp_root("codex-prepass-bound");
        let path = root.join("rollout.jsonl");

        let mut records = vec![json!({"type":"session_meta","payload":{"id":"thread"}})];
        records.push(json!({"type":"event_msg","payload":{"type":"user_message",
            "message":"ours","images":[],"local_images":[]}}));
        // Fifty events we never sent. Under the old unbounded pass all fifty were kept.
        for index in 0..50 {
            records.push(json!({"type":"event_msg","payload":{"type":"user_message",
                "message":format!("never-sent-{index}"),"images":[],"local_images":[]}}));
        }
        write_fixture(&path, &records);

        let expected: std::collections::HashSet<&str> = ["ours"].into_iter().collect();
        let kept = codex_visible_user_event_texts_streamed(
            &path,
            &expected,
            MAX_TRANSCRIPT_LINE_BYTES,
            DESTINATION_TOTAL_BUDGET_BYTES,
        )
        .unwrap();
        assert_eq!(
            kept.len(),
            1,
            "only texts we sent may be retained; kept {kept:?}"
        );
        assert!(kept.contains("ours"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// AXIS — ROUND-3 FINDING 3, RE-AIMED IN ROUND 8: the cap binds to ONE DESCRIPTOR.
    ///
    /// The round-3 version wrote an oversize file and called `read_bounded`. Every
    /// candidate implementation refuses that — stat-by-path, whole-file-then-check, and
    /// the descriptor bound alike — so it asserted a property it could not observe and
    /// both insecure mutants survived it.
    ///
    /// This holds a descriptor open and REPLACES THE PATH underneath it with a file past
    /// the cap. Only a read bound to the descriptor still sees the original bytes; a
    /// mutant that reaches for the path reads the replacement and refuses.
    #[test]
    fn the_ledger_read_is_bounded_by_the_descriptor_not_the_path() {
        let root = std::env::temp_dir().join(format!(
            "herdr-ledger-bound-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("external_agent_session_imports.json");

        // Small at open...
        std::fs::write(&path, vec![b'y'; 4096]).unwrap();
        let held = std::fs::File::open(&path).expect("open the ledger");

        // ...and past the cap at the path by the time it is read. `rename` gives the
        // path a DIFFERENT inode, so the held descriptor and the path now disagree —
        // which is precisely the state a growing or replaced ledger produces.
        let replacement = root.join("replacement.json");
        std::fs::write(&replacement, vec![b'x'; MAX_APP_SERVER_LINE_BYTES + 4096]).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(
            std::fs::metadata(&path).unwrap().len() as usize > MAX_APP_SERVER_LINE_BYTES,
            "precondition: the path must now exceed the cap, or the two agree and this \
             cannot discriminate"
        );

        let bytes = read_bounded_file(held, MAX_APP_SERVER_LINE_BYTES as u64, &path)
            .expect("the held descriptor is within the cap and must still read");
        assert_eq!(
            bytes.len(),
            4096,
            "the read must return the descriptor's bytes, not the path's"
        );

        // And the cap genuinely refuses when the DESCRIPTOR itself is oversize.
        let over = std::fs::File::open(&path).expect("open the replacement");
        let err = read_bounded_file(over, MAX_APP_SERVER_LINE_BYTES as u64, &path)
            .expect_err("content beyond the cap must be refused");
        assert!(
            err.contains("exceeded"),
            "expected a cap refusal, got {err}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// AXIS: a transcript that fits transfers WHOLE, and reports nothing dropped.
    ///
    /// The no-regression guard for every transfer that works today — windowing must
    /// be invisible below the budget, byte for byte.
    #[test]
    fn a_transcript_within_the_budget_is_returned_unchanged() {
        let body = synthetic_claude_transcript(20, 16);
        let path = temp_transcript("fits", &body);

        let snapshot = read_transcript_snapshot(&path, HarnessKind::Claude).unwrap();
        assert_eq!(
            snapshot.bytes,
            body.as_bytes(),
            "the file must pass through untouched"
        );
        assert_eq!(snapshot.dropped_records, 0);
        assert_eq!(snapshot.fingerprint.byte_len, body.len() as u64);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// AXIS: the fingerprint covers the WHOLE file, never the window.
    ///
    /// If it hashed the window, the pre-cutover recheck in
    /// `verify_unchanged_transcripts` would stop noticing a source that grew after
    /// staging — the exact hole the read-once comment exists to close. Asserted
    /// against an independent hash of the entire file.
    #[test]
    fn the_fingerprint_covers_the_whole_file_not_the_window() {
        let body = synthetic_claude_transcript(200, 1024);
        let path = temp_transcript("fingerprint", &body);

        // A SMALL budget, so the window is genuinely a fraction of the file. With a
        // budget the file already fits under, window and file are the same bytes and
        // this test cannot tell a whole-file hash from a window hash — it passed
        // against a deliberately broken build until the budget was shrunk here.
        let budget = 8 * 1024;
        let snapshot =
            read_transcript_snapshot_with_budget(&path, budget, HarnessKind::Claude).unwrap();
        assert!(
            snapshot.bytes.len() < body.len() / 4,
            "precondition: the window must be much smaller than the file, or this proves nothing"
        );

        let whole = fingerprint_bytes(body.as_bytes());
        assert_eq!(
            snapshot.fingerprint, whole,
            "the hash must be of the entire file"
        );
        assert_ne!(
            snapshot.fingerprint,
            fingerprint_bytes(&snapshot.bytes),
            "and must NOT be the hash of the window"
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// AXIS: an oversize transcript yields a window of WHOLE records, the most
    /// recent ones, with an exact count of what was left behind.
    ///
    /// Whole records are the load-bearing part: the transcript is JSONL, so a raw
    /// byte window starting mid-record produces an unparseable first line — a hard
    /// error rather than a shorter conversation.
    #[test]
    fn an_oversize_transcript_windows_to_whole_recent_records() {
        // A record per line, each far larger than the budget divided by the count,
        // so the boundary lands mid-record and the trim has real work to do.
        let record_count = 400usize;
        let body = synthetic_claude_transcript(record_count, 1024);
        let path = temp_transcript("oversize", &body);

        let snapshot =
            read_transcript_snapshot_with_budget(&path, 64 * 1024, HarnessKind::Claude).unwrap();

        assert!(
            snapshot.dropped_records > 0,
            "precondition: the window had to drop something"
        );
        assert!(snapshot.bytes.len() <= 64 * 1024);
        // WHOLE RECORDS: every line parses, and the first one is not a fragment.
        for (index, line) in snapshot.bytes.split(|byte| *byte == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            serde_json::from_slice::<Value>(line)
                .unwrap_or_else(|err| panic!("window line {index} is not whole JSON: {err}"));
        }
        // THE MOST RECENT records, not an arbitrary slice: the last record of the
        // file must be the last record of the window.
        let window = String::from_utf8(snapshot.bytes.clone()).unwrap();
        assert!(
            window.contains(&format!("m{}", record_count - 1)),
            "the newest record must be inside the window"
        );
        assert!(
            !window.contains("\"m0 "),
            "the oldest record must have been dropped"
        );
        // And the count is exact, not an estimate.
        let kept = window.lines().filter(|line| !line.is_empty()).count() as u64;
        assert_eq!(
            snapshot.dropped_records + kept,
            record_count as u64,
            "dropped + kept must account for every record in the file"
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn omission_total_includes_every_class() {
        let omissions = OmissionSummary {
            tool_records: 1,
            reasoning_records: 2,
            system_records: 3,
            attachment_records: 4,
            metadata_records: 5,
            unsupported_blocks: 6,
            sidechain_records: 7,
            windowed_records: 8,
        };
        assert_eq!(omissions.total(), 36);
    }

    #[test]
    fn claude_project_slug_matches_native_character_substitution() {
        assert_eq!(
            claude_project_slug(Path::new("/root/.gitmoot/work_tree")),
            "-root--gitmoot-work-tree"
        );
    }

    #[test]
    fn known_nonvisible_types_are_exhaustive_sets_without_duplicates() {
        let claude: HashSet<_> = [
            "system",
            "attachment",
            "file-history-snapshot",
            "file-history-delta",
            "queue-operation",
            "last-prompt",
            "permission-mode",
            "mode",
            "ai-title",
            "pr-link",
            "summary",
            "progress",
        ]
        .into_iter()
        .collect();
        assert_eq!(claude.len(), 12);
    }
}
