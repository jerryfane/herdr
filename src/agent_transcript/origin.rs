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

/// How long after herdr queued a prompt its user line may still appear.
/// `agent.prompt` refuses blocked panes, so omp takes the prompt at once when
/// idle, or queues it behind the running turn. Ten minutes covers a follow-up
/// queued behind an ordinary turn; past it a remembered prompt that never
/// produced an entry cannot claim the owner's later message with the same
/// text. A turn queued longer stays unmarked (shown as the owner's), which is
/// the safe side for owner-only navigation.
const MAX_DELIVERY_MS: u64 = 10 * 60 * 1_000;

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
/// takes one unclaimed user turn after the previous match with the same text:
/// the first one written at or after the prompt was queued and within
/// [`MAX_DELIVERY_MS`], else (clocks and write order are not exact) the latest
/// one inside the [`CLOCK_SLACK_MS`] before it. A post-submission entry always
/// wins, so an identical owner message just before the prompt is never taken.
pub(super) fn matched_turns(prompts: &[OtherPrompt], turns: &[UserTurn]) -> HashSet<String> {
    let mut matched = HashSet::new();
    let mut cursor = 0;
    for prompt in prompts {
        let submitted = prompt.submitted_unix_ms;
        let same_text = |turn: &&UserTurn| turn.sha256 == prompt.sha256;
        let candidates = || turns[cursor..].iter().enumerate();
        let after = candidates().find(|(_, turn)| {
            same_text(turn)
                && turn.ts_ms >= submitted
                && turn.ts_ms <= submitted.saturating_add(MAX_DELIVERY_MS)
        });
        let found = after.or_else(|| {
            candidates().rfind(|(_, turn)| {
                same_text(turn)
                    && turn.ts_ms < submitted
                    && turn.ts_ms.saturating_add(CLOCK_SLACK_MS) >= submitted
            })
        });
        if let Some((offset, turn)) = found {
            matched.insert(turn.id.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(id: &str, ts_ms: u64, text: &str) -> UserTurn {
        UserTurn {
            id: id.into(),
            ts_ms,
            sha256: text_digest(text),
        }
    }

    fn ids(matched: HashSet<String>) -> Vec<String> {
        let mut ids: Vec<_> = matched.into_iter().collect();
        ids.sort();
        ids
    }

    #[test]
    fn a_post_submission_entry_wins_over_an_owner_entry_inside_the_slack() {
        // The owner typed "continue" at 9.0 s; automation queued the same
        // text at 10.0 s and omp wrote it at 10.1 s.
        let turns = [
            turn("owner-before", 9_000, "continue"),
            turn("script-actual", 10_100, "continue"),
        ];
        let prompts = [OtherPrompt::new("continue", 10_000)];
        assert_eq!(ids(matched_turns(&prompts, &turns)), ["script-actual"]);
    }

    #[test]
    fn the_backwards_slack_applies_only_without_a_later_entry() {
        let turns = [
            turn("early", 4_000, "continue"),
            turn("stamped-early", 9_500, "continue"),
        ];
        let prompts = [OtherPrompt::new("continue", 10_000)];
        assert_eq!(ids(matched_turns(&prompts, &turns)), ["stamped-early"]);
    }

    #[test]
    fn a_stale_prompt_cannot_claim_a_much_later_owner_entry() {
        let turns = [turn(
            "owner-later",
            10_000 + MAX_DELIVERY_MS + 1,
            "continue",
        )];
        let prompts = [OtherPrompt::new("continue", 10_000)];
        assert!(matched_turns(&prompts, &turns).is_empty());
    }
}
