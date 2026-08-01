use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposerInputSource {
    Human,
    Api,
    AgentPrompt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComposerWrite {
    pub(crate) attempt_id: String,
    pub(crate) source: ComposerInputSource,
    /// Detection content sequence immediately before the write. A visual frame
    /// at this sequence cannot yet corroborate the new input.
    pub(crate) baseline_content_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposerRegionObservation {
    Empty,
    Text,
    Missing,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposerCursorObservation {
    Draft,
    Suggestion,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposerStyleObservation {
    // Reserved for a future theme-independent style role. Production reports
    // Unavailable today; tests pin that style can only downgrade confidence.
    #[allow(dead_code)]
    Neutral,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ComposerVisualObservation {
    pub(crate) region: ComposerRegionObservation,
    pub(crate) cursor: ComposerCursorObservation,
    pub(crate) style: ComposerStyleObservation,
    pub(crate) frame_stable: bool,
    pub(crate) content_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposerAssessmentState {
    // Reserved until Herdr has durable proof that an attributed draft was
    // observed and subsequently cleared.
    #[allow(dead_code)]
    Empty,
    DraftPresent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComposerAssessment {
    pub(crate) state: ComposerAssessmentState,
    pub(crate) attempt_id: Option<String>,
    pub(crate) source: Option<ComposerInputSource>,
    pub(crate) visual: ComposerVisualObservation,
}

/// What a delayed agent-prompt submission learned when its moment arrived.
///
/// Both facts matter and they are not opposites. `abandoned` means the guard
/// refused to write because the pane changed hands, so text is stranded in a
/// composer with no turn. `submitted` means the key was written, so the
/// composer emptied — and therefore any text seen there afterwards belongs to
/// someone else, which is what stops a spent prompt from being credited with a
/// human's keystrokes.
#[derive(Debug, Default)]
pub struct PromptSubmitWatch {
    pub abandoned: std::sync::atomic::AtomicBool,
    pub submitted: std::sync::atomic::AtomicBool,
    /// The pane's turn counter at the moment the prompt was written.
    ///
    /// `submitted` says only that the key reached the PTY, which is NOT proof a
    /// turn began — herdr#18 is exactly the case where the key was written and
    /// the draft stranded anyway. Retiring on `submitted` alone therefore erases
    /// attribution from a genuinely stranded prompt, which trades one wrong
    /// answer for another. A turn counter that has since advanced is positive
    /// evidence the composer really did empty.
    pub turn_at_write: std::sync::atomic::AtomicU64,
}

pub(crate) fn fresh_composer_attempt_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("cmp-{clock:016x}-{sequence:08x}")
}

pub(crate) fn assess_composer(
    write: Option<&ComposerWrite>,
    visual: ComposerVisualObservation,
) -> ComposerAssessment {
    let source = write.map(|write| write.source);
    let attempt_id = write.map(|write| write.attempt_id.clone());

    // Provenance is volatile across daemon restart and live handoff. Its
    // absence therefore means "we do not know", even when cursor geometry
    // resembles a hosted suggestion. Missing regions, incoherent frames, and
    // style tripwires are likewise deliberately loud.
    if write.is_none()
        || !visual.frame_stable
        || matches!(
            visual.region,
            ComposerRegionObservation::Missing | ComposerRegionObservation::Unavailable
        )
        || visual.style == ComposerStyleObservation::Conflict
        || visual.cursor == ComposerCursorObservation::Conflict
        || write.is_some_and(|write| visual.content_seq <= write.baseline_content_seq)
    {
        return ComposerAssessment {
            state: ComposerAssessmentState::Unknown,
            attempt_id,
            source,
            visual,
        };
    }

    let state = match (write, visual.region, visual.cursor) {
        (Some(_), ComposerRegionObservation::Text, ComposerCursorObservation::Draft) => {
            ComposerAssessmentState::DraftPresent
        }
        // An empty frame cannot distinguish a tagged write that has not echoed
        // from an observed draft that later cleared. The prompt wait keeps that
        // history request-locally; a standalone snapshot must stay unknown.
        (Some(_), ComposerRegionObservation::Empty, _) => ComposerAssessmentState::Unknown,
        // Provenance is the mechanism, but a visual cursor contradiction or a
        // missing corroborating cursor is uncertainty, not permission to guess.
        _ => ComposerAssessmentState::Unknown,
    };
    ComposerAssessment {
        state,
        attempt_id,
        source,
        visual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visual(
        region: ComposerRegionObservation,
        cursor: ComposerCursorObservation,
    ) -> ComposerVisualObservation {
        ComposerVisualObservation {
            region,
            cursor,
            style: ComposerStyleObservation::Neutral,
            frame_stable: true,
            content_seq: 2,
        }
    }

    fn write() -> ComposerWrite {
        ComposerWrite {
            attempt_id: "attempt-7".into(),
            source: ComposerInputSource::AgentPrompt,
            baseline_content_seq: 1,
        }
    }

    #[test]
    fn writer_provenance_and_cursor_report_unsent_draft_with_attempt() {
        let assessment = assess_composer(
            Some(&write()),
            visual(
                ComposerRegionObservation::Text,
                ComposerCursorObservation::Draft,
            ),
        );
        assert_eq!(assessment.state, ComposerAssessmentState::DraftPresent);
        assert_eq!(assessment.attempt_id.as_deref(), Some("attempt-7"));
    }

    #[test]
    fn composer_content_without_writer_provenance_is_unknown() {
        let assessment = assess_composer(
            None,
            visual(
                ComposerRegionObservation::Text,
                ComposerCursorObservation::Suggestion,
            ),
        );
        assert_eq!(assessment.state, ComposerAssessmentState::Unknown);
    }

    #[test]
    fn pending_write_with_empty_region_stays_unknown_after_unrelated_output() {
        let assessment = assess_composer(
            Some(&write()),
            visual(
                ComposerRegionObservation::Empty,
                ComposerCursorObservation::Unavailable,
            ),
        );
        assert_eq!(assessment.state, ComposerAssessmentState::Unknown);
    }

    #[test]
    fn missing_region_is_unknown() {
        let observed = ComposerVisualObservation {
            region: ComposerRegionObservation::Missing,
            ..visual(
                ComposerRegionObservation::Text,
                ComposerCursorObservation::Draft,
            )
        };
        assert_eq!(
            assess_composer(Some(&write()), observed).state,
            ComposerAssessmentState::Unknown
        );
    }

    #[test]
    fn mid_repaint_frame_is_unknown() {
        let observed = ComposerVisualObservation {
            frame_stable: false,
            ..visual(
                ComposerRegionObservation::Text,
                ComposerCursorObservation::Draft,
            )
        };
        assert_eq!(
            assess_composer(Some(&write()), observed).state,
            ComposerAssessmentState::Unknown
        );
    }

    #[test]
    fn conflicting_signals_are_unknown() {
        let observed = ComposerVisualObservation {
            cursor: ComposerCursorObservation::Conflict,
            ..visual(
                ComposerRegionObservation::Text,
                ComposerCursorObservation::Draft,
            )
        };
        assert_eq!(
            assess_composer(Some(&write()), observed).state,
            ComposerAssessmentState::Unknown
        );
    }

    #[test]
    fn pre_redraw_frame_is_unknown() {
        let observed = ComposerVisualObservation {
            content_seq: 1,
            ..visual(
                ComposerRegionObservation::Text,
                ComposerCursorObservation::Draft,
            )
        };
        assert_eq!(
            assess_composer(Some(&write()), observed).state,
            ComposerAssessmentState::Unknown
        );
    }

    #[test]
    fn style_alone_never_establishes_either_confident_verdict() {
        for write in [None, Some(&write())] {
            let assessment = assess_composer(
                write,
                ComposerVisualObservation {
                    style: ComposerStyleObservation::Conflict,
                    ..visual(
                        ComposerRegionObservation::Text,
                        ComposerCursorObservation::Unavailable,
                    )
                },
            );
            assert_eq!(assessment.state, ComposerAssessmentState::Unknown);
        }
    }
}
