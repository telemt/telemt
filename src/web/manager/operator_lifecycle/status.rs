use serde::Serialize;

/// Reversible operator lifecycle state independent from terminal WEB shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperatorLifecycleState {
    /// Operator admission is open subject to config and generation policy.
    Running,
    /// New WEB work is paused without closing existing work.
    Paused,
    /// Existing WEB work is completing before the absolute deadline.
    Draining,
    /// The deadline fired and close signals were sent to remaining sessions.
    ForceClosing,
    /// Every tracked WEB session, stream, and WebSocket completed.
    Drained,
}

/// Current or retained drain-operation phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperatorDrainState {
    /// Existing work is inside its graceful completion interval.
    Draining,
    /// Forced session closure was signalled and zero is not confirmed yet.
    ForceClosing,
    /// The operation reached confirmed zero.
    Completed,
    /// Explicit resume or terminal process shutdown cancelled the waiter.
    Cancelled,
}

/// Terminal result retained for the latest drain operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperatorDrainOutcome {
    /// All tracked work completed before forced closure was committed.
    Graceful,
    /// Tracked work reached zero after the deadline forced session closure.
    Forced,
    /// The drain waiter was cancelled before confirmed zero.
    Cancelled,
}

/// API-visible status for the active or latest process-local drain.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct OperatorDrainStatus {
    /// Opaque process-fenced drain identifier.
    pub(crate) operation_id: String,
    /// Current operation phase.
    pub(crate) state: OperatorDrainState,
    /// Terminal outcome when the operation no longer waits for zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outcome: Option<OperatorDrainOutcome>,
    /// Frozen relative deadline accepted from the API.
    pub(crate) timeout_secs: u64,
    /// Wall-clock projection retained only for operator correlation.
    pub(crate) started_epoch_millis: u64,
    /// Wall-clock projection of the monotonic deadline.
    pub(crate) deadline_epoch_millis: u64,
    /// Wall-clock completion or cancellation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) completed_epoch_millis: Option<u64>,
    /// Most recent exact live-session sample.
    pub(crate) remaining_sessions: usize,
    /// Most recent exact logical-stream ownership sample.
    pub(crate) remaining_streams: usize,
    /// Most recent exact session-owned WebSocket sample.
    pub(crate) remaining_websockets: usize,
    /// Whether the deadline won and committed the forced-close snapshot.
    pub(crate) force_close_signalled: bool,
}

/// API-visible snapshot of reversible WEB operator lifecycle state.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct OperatorLifecycleStatus {
    /// Stable process-local state machine value.
    pub(crate) state: OperatorLifecycleState,
    /// Monotonic state-transition epoch independent from config revision.
    pub(crate) epoch: u64,
    /// Monotonic age of the current state.
    pub(crate) age_ms: u64,
    /// Whether the operator-owned admission fence is open.
    pub(crate) admission_open: bool,
    /// Operator and effective config admission conjunction.
    pub(crate) effective_new_work_admission: bool,
    /// Active or latest drain retained until replacement or process restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) drain: Option<OperatorDrainStatus>,
}
