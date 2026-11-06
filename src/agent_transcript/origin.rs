//! Which user turns came from someone other than the owner.
//!
//! herdr remembers a digest of every brokered `agent.prompt` that was not the
//! owner's (scripts, the CLI, gitmoot, other agents, guests). A transcript user
//! turn whose text equals one of those, matched oldest first and in order, is
//! marked `origin: "other"`. Nothing is guessed from the text itself.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Non-owner prompts a pane remembers; the oldest is forgotten first.
pub(crate) const OTHER_PROMPT_LIMIT: usize = 200;

/// How much earlier than herdr's submit stamp omp may stamp the user line.
/// Both clocks are the host's; this only absorbs rounding and write order.
const CLOCK_SLACK_MS: u64 = 5_000;

/// One remembered non-owner prompt: a digest of its text, never the text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OtherPrompt {
    /// Hex SHA-256 of the prompt text with line endings unified and the
    /// surrounding whitespace trimmed.
    pub(crate) sha256: String,
    /// When herdr queued the prompt, in milliseconds since the Unix epoch.
    pub(crate) submitted_unix_ms: u64,
}

impl OtherPrompt {
    pub(crate) fn new(text: &str, submitted_unix_ms: u64) -> Self {
        Self {
            sha256: text_digest(text),
            submitted_unix_ms,
        }
    }
}

/// Exact text identity, tolerant only of `\r\n` and surrounding whitespace,
/// which the terminal and omp may change on the way into the session file.
pub(super) fn text_digest(text: &str) -> String {
    let normalized = text.replace("\r\n", "\n");
    format!("{:x}", Sha256::digest(normalized.trim().as_bytes()))
}

/// A user turn on the branch, in file order.
pub(super) struct UserTurn {
    pub(super) id: String,
    pub(super) ts_ms: u64,
    pub(super) sha256: String,
}

/// The ids of the user turns the prompts produced. Each prompt, oldest first,
/// takes the first unclaimed user turn after the previous match that has the
/// same text and was not written before the prompt was queued.
pub(super) fn matched_turns(prompts: &[OtherPrompt], turns: &[UserTurn]) -> HashSet<String> {
    let mut matched = HashSet::new();
    let mut cursor = 0;
    for prompt in prompts {
        let found = turns[cursor..].iter().position(|turn| {
            turn.sha256 == prompt.sha256
                && turn.ts_ms.saturating_add(CLOCK_SLACK_MS) >= prompt.submitted_unix_ms
        });
        if let Some(offset) = found {
            matched.insert(turns[cursor + offset].id.clone());
            cursor += offset + 1;
        }
    }
    matched
}

/// The earliest moment a matching user turn can carry.
pub(super) fn earliest_turn_ms(prompts: &[OtherPrompt]) -> Option<u64> {
    prompts
        .iter()
        .map(|prompt| prompt.submitted_unix_ms.saturating_sub(CLOCK_SLACK_MS))
        .min()
}
