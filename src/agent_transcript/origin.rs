//! Which user turns came from someone other than the owner.
//!
//! herdr remembers a digest of every brokered `agent.prompt` that was not the
//! owner's (scripts, the CLI, gitmoot, other agents, guests). A transcript user
//! turn whose text equals one of those, matched oldest first and in order, is
//! marked `origin: "other"`. Nothing is guessed from the text itself.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

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

/// Non-owner prompts whose submission has not reported yet. Each reports
/// within its submit delay or deadline, so this bound is reached only when a
/// pane is not taking input; `agent.prompt` then refuses new non-owner prompts
/// (`too_many_pending_prompts`) rather than send one it cannot track.
pub(crate) const PENDING_PROMPT_LIMIT: usize = 64;

/// What one admitted prompt's submission reported: `true` once its Enter was
/// written, `false` when it failed. Set once, by the submission alone.
type Outcome = Arc<OnceLock<bool>>;

/// The submission's handle on its record. [`Self::delivered`] reports the
/// prompt written; dropping it without that reports failure, so every path
/// that does not deliver (a refused or failed write, a closed actor, an error
/// before the write) resolves the record.
#[derive(Debug)]
pub(crate) struct PromptOutcome(Outcome);

impl PromptOutcome {
    pub(crate) fn delivered(self) {
        let _ = self.0.set(true);
    }
}

impl Drop for PromptOutcome {
    fn drop(&mut self) {
        let _ = self.0.set(false);
    }
}

/// `agent.prompt` refused a non-owner prompt: too many are still submitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TooManyPendingPrompts;

#[derive(Debug, Clone)]
struct PromptRecord {
    prompt: OtherPrompt,
    outcome: Outcome,
    /// Seen delivered by [`OtherPromptLog::prune`], so a save keeps it.
    counted: bool,
}

/// A pane's brokered non-owner prompts, in admission order: one record each,
/// created when `agent.prompt` admits the prompt (before anything is written)
/// and resolved only by that submission's own outcome. Failed records are
/// dropped; at most [`OTHER_PROMPT_LIMIT`] delivered ones are kept.
#[derive(Debug, Clone, Default)]
pub(crate) struct OtherPromptLog {
    records: Vec<PromptRecord>,
}

impl OtherPromptLog {
    /// Delivered prompts saved with the pane.
    pub(crate) fn restored(prompts: impl IntoIterator<Item = OtherPrompt>) -> Self {
        let records = prompts
            .into_iter()
            .map(|prompt| PromptRecord {
                prompt,
                outcome: Arc::new(OnceLock::from(true)),
                counted: true,
            })
            .collect();
        Self { records }
    }

    /// Admit a prompt about to be submitted, or refuse it while
    /// [`PENDING_PROMPT_LIMIT`] are unresolved.
    pub(crate) fn admit(
        &mut self,
        text: &str,
        submitted_unix_ms: u64,
    ) -> Result<PromptOutcome, TooManyPendingPrompts> {
        self.prune();
        let pending = self
            .records
            .iter()
            .filter(|record| record.outcome.get().is_none())
            .count();
        if pending >= PENDING_PROMPT_LIMIT {
            return Err(TooManyPendingPrompts);
        }
        let outcome = Outcome::default();
        self.records.push(PromptRecord {
            prompt: OtherPrompt::new(text, submitted_unix_ms),
            outcome: Arc::clone(&outcome),
            counted: false,
        });
        Ok(PromptOutcome(outcome))
    }

    /// Drop failed records and the oldest delivered ones past the limit.
    /// Returns whether the delivered set (what a save keeps) changed.
    pub(crate) fn prune(&mut self) -> bool {
        let mut changed = false;
        self.records
            .retain_mut(|record| match record.outcome.get() {
                Some(false) => false,
                Some(true) => {
                    changed |= !record.counted;
                    record.counted = true;
                    true
                }
                None => true,
            });
        let mut excess = self
            .records
            .iter()
            .filter(|record| record.counted)
            .count()
            .saturating_sub(OTHER_PROMPT_LIMIT);
        if excess > 0 {
            changed = true;
            self.records.retain(|record| {
                let drop = record.counted && excess > 0;
                excess -= usize::from(drop);
                !drop
            });
        }
        changed
    }

    /// The delivered prompts, oldest first, at most [`OTHER_PROMPT_LIMIT`]:
    /// one pass, each record read once.
    pub(crate) fn delivered(&self) -> Vec<OtherPrompt> {
        let mut delivered: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.outcome.get() == Some(&true))
            .map(|record| record.prompt.clone())
            .collect();
        let excess = delivered.len().saturating_sub(OTHER_PROMPT_LIMIT);
        delivered.drain(..excess);
        delivered
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
}

/// Identifies a list of delivered prompts, so a transcript cursor can tell
/// whether the prompts it was served with have changed since.
pub(super) fn fingerprint(prompts: &[OtherPrompt]) -> u64 {
    let mut hasher = Sha256::new();
    for prompt in prompts {
        hasher.update(prompt.sha256.as_bytes());
        hasher.update(prompt.submitted_unix_ms.to_le_bytes());
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"))
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
    fn a_record_counts_once_its_own_submission_reports_delivered() {
        let mut log = OtherPromptLog::default();
        let outcome = log.admit("continue", 1).unwrap();
        assert!(log.delivered().is_empty(), "pending until reported");
        outcome.delivered();
        assert_eq!(log.delivered(), [OtherPrompt::new("continue", 1)]);
        assert!(log.prune(), "now saved");
        assert_eq!(log.len(), 1, "one record per prompt");
    }

    #[test]
    fn a_failed_submission_removes_its_record() {
        let mut log = OtherPromptLog::default();
        drop(log.admit("continue", 1).unwrap());
        assert!(log.delivered().is_empty());
        assert!(!log.prune());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn overlapping_prompts_are_all_kept_and_excess_ones_refused() {
        let mut log = OtherPromptLog::default();
        let outcomes: Vec<_> = (0..PENDING_PROMPT_LIMIT as u64)
            .map(|n| log.admit(&format!("prompt-{n}"), n).unwrap())
            .collect();
        assert_eq!(
            log.admit("one more", 99).unwrap_err(),
            TooManyPendingPrompts
        );
        for outcome in outcomes {
            outcome.delivered();
        }
        assert_eq!(log.delivered().len(), PENDING_PROMPT_LIMIT);
        assert!(log.admit("now room", 100).is_ok());
    }

    #[test]
    fn only_the_newest_delivered_prompts_are_kept() {
        let mut log = OtherPromptLog::restored(
            (0..OTHER_PROMPT_LIMIT as u64).map(|n| OtherPrompt::new(&format!("old-{n}"), n)),
        );
        let pending = log.admit("pending", 500).unwrap();
        log.admit("newest", 600).unwrap().delivered();
        assert!(log.prune());
        let delivered = log.delivered();
        assert_eq!(delivered.len(), OTHER_PROMPT_LIMIT);
        assert_eq!(delivered[0], OtherPrompt::new("old-1", 1));
        assert_eq!(delivered.last(), Some(&OtherPrompt::new("newest", 600)));
        pending.delivered();
        assert_eq!(log.delivered().len(), OTHER_PROMPT_LIMIT);
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
