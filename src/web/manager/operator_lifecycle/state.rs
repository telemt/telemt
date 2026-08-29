use std::time::Instant;

use tokio_util::sync::CancellationToken;

use super::{OperatorDrainStatus, OperatorLifecycleState};

/// Exact live-work counts sampled while an operator drain is active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WorkCounts {
    /// Live WEB sessions.
    pub(super) sessions: usize,
    /// Live logical streams.
    pub(super) streams: usize,
    /// Live session-owned WebSockets.
    pub(super) websockets: usize,
}

impl WorkCounts {
    /// Returns whether every tracked work class reached zero.
    pub(super) fn is_zero(self) -> bool {
        self.sessions == 0 && self.streams == 0 && self.websockets == 0
    }
}

/// Single active drain identity and cancellation authority.
pub(super) struct ActiveDrain {
    /// Process-local operation sequence.
    pub(super) sequence: u64,
    /// Cancellation token owned by resume or terminal shutdown.
    pub(super) cancellation: CancellationToken,
}

/// Mutex-protected lifecycle state used for atomic transitions.
pub(super) struct OperatorLifecycleInner {
    /// Current reversible lifecycle state.
    pub(super) state: OperatorLifecycleState,
    /// Monotonic transition epoch.
    pub(super) epoch: u64,
    /// Monotonic transition timestamp.
    pub(super) since: Instant,
    /// Whether terminal process shutdown closed the state machine.
    pub(super) terminal: bool,
    /// Currently active drain, if any.
    pub(super) active: Option<ActiveDrain>,
    /// Active or retained latest drain status.
    pub(super) drain: Option<OperatorDrainStatus>,
}

/// Lock-free read snapshot published after lifecycle mutations.
#[derive(Clone)]
pub(super) struct OperatorSnapshot {
    /// Current reversible lifecycle state.
    pub(super) state: OperatorLifecycleState,
    /// Monotonic transition epoch.
    pub(super) epoch: u64,
    /// Monotonic transition timestamp.
    pub(super) since: Instant,
    /// Whether terminal process shutdown closed the state machine.
    pub(super) terminal: bool,
    /// Active or retained latest drain status.
    pub(super) drain: Option<OperatorDrainStatus>,
}
