mod composer;
mod id;
mod runtime;
mod runtime_registry;
pub mod state;
mod title;

pub(crate) use composer::{
    assess_composer, ComposerAssessment, ComposerAssessmentState, ComposerCursorObservation,
    ComposerInputSource, ComposerRegionObservation, ComposerStyleObservation,
    ComposerVisualObservation, ComposerWrite, PromptSubmitWatch,
};
pub use id::TerminalId;
pub use runtime::TerminalRuntime;
pub(crate) use runtime_registry::TerminalRuntimeRegistry;
pub use state::{
    AgentMetadataReport, EffectivePresentation, EffectiveStateChange, TerminalState,
    TerminalStateMutation, TurnOutcome,
};
pub(crate) use state::{TurnCounterResetPath, TurnRecord, TurnReplayError};
pub(crate) use title::stripped_terminal_title;
