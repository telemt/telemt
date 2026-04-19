use std::time::Instant;

use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum PressureState {
    Normal = 0,
    Pressured = 1,
    Shedding = 2,
    Saturated = 3,
}

impl PressureState {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Default for PressureState {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowPressureClass {
    Healthy,
    Bursty,
    Backpressured,
    Standing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandingQueueState {
    Transient,
    Standing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowSchedulerState {
    Idle,
    Active,
    Backpressured,
    Penalized,
    SheddingCandidate,
}

#[derive(Debug, Clone)]
pub(crate) struct QueuedFrame {
    pub(crate) conn_id: u64,
    pub(crate) flags: u32,
    pub(crate) data: Bytes,
    pub(crate) enqueued_at: Instant,
}

impl QueuedFrame {
    #[inline]
    pub(crate) fn queued_bytes(&self) -> u64 {
        self.data.len() as u64
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FlowFairnessState {
    pub(crate) _flow_id: u64,
    pub(crate) _worker_id: u16,
    pub(crate) pending_bytes: u64,
    pub(crate) deficit_bytes: i64,
    pub(crate) queue_started_at: Option<Instant>,
    pub(crate) last_drain_at: Option<Instant>,
    pub(crate) recent_drain_bytes: u64,
    pub(crate) consecutive_stalls: u8,
    pub(crate) consecutive_skips: u8,
    pub(crate) penalty_score: u16,
    pub(crate) pressure_class: FlowPressureClass,
    pub(crate) standing_state: StandingQueueState,
    pub(crate) scheduler_state: FlowSchedulerState,
    pub(crate) bucket_id: usize,
    pub(crate) weight_quanta: u8,
    pub(crate) in_active_ring: bool,
}

impl FlowFairnessState {
    pub(crate) fn new(flow_id: u64, worker_id: u16, bucket_id: usize, weight_quanta: u8) -> Self {
        Self {
            _flow_id: flow_id,
            _worker_id: worker_id,
            pending_bytes: 0,
            deficit_bytes: 0,
            queue_started_at: None,
            last_drain_at: None,
            recent_drain_bytes: 0,
            consecutive_stalls: 0,
            consecutive_skips: 0,
            penalty_score: 0,
            pressure_class: FlowPressureClass::Healthy,
            standing_state: StandingQueueState::Transient,
            scheduler_state: FlowSchedulerState::Idle,
            bucket_id,
            weight_quanta: weight_quanta.max(1),
            in_active_ring: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionDecision {
    Admit,
    RejectWorkerCap,
    RejectFlowCap,
    RejectBucketCap,
    RejectSaturated,
    RejectStandingFlow,
}

#[derive(Debug, Clone)]
pub(crate) enum SchedulerDecision {
    Idle,
    Dispatch(DispatchCandidate),
}

#[derive(Debug, Clone)]
pub(crate) struct DispatchCandidate {
    pub(crate) frame: QueuedFrame,
    pub(crate) pressure_state: PressureState,
    pub(crate) flow_class: FlowPressureClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchFeedback {
    Routed,
    QueueFull,
    ChannelClosed,
    NoConn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchAction {
    Continue,
    CloseFlow,
}
