use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use serde::Serialize;

/// Stable operational rejection reason recorded at the decision point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebRejectionReason {
    /// Ordinary accepted HTTP connection slots were exhausted.
    HttpConnectionCapacity,
    /// Concurrent HTTP request handler slots were exhausted.
    HttpHandlerCapacity,
    /// Primary long-poll slots were exhausted.
    LanePollCapacity,
    /// Auxiliary lane-open wait slots were exhausted.
    LaneAuxPollCapacity,
    /// Concurrent collected-body reader slots were exhausted.
    BodyReaderCapacity,
    /// Process-wide collected-body bytes were exhausted.
    BodyBytesCapacity,
    /// Bootstrap credential quota or identifier space was exhausted.
    BootstrapCapacity,
    /// Bootstrap issuance rate policy rejected the operation.
    BootstrapRate,
    /// Live session quota or identifier space was exhausted.
    SessionCapacity,
    /// Session creation rate policy rejected the operation.
    SessionRate,
    /// One session reached its logical-stream ceiling.
    StreamSessionCapacity,
    /// Global or profile logical-stream capacity was exhausted.
    StreamCapacity,
    /// Logical-stream creation rate policy rejected the operation.
    StreamRate,
    /// No synthetic source port remained for the exact relay tuple.
    StreamTupleExhausted,
    /// Concurrent inner-handshake slots were exhausted.
    StreamHandshakeCapacity,
    /// The active relay generation had no connection permit.
    GenerationConnectionCapacity,
    /// One session reached its queued data ceiling.
    QueueSessionCapacity,
    /// The process-wide queued data ceiling was exhausted.
    QueueGlobalCapacity,
    /// Process-wide WebSocket connection slots were exhausted.
    WebSocketConnectionCapacity,
    /// Shared WebSocket byte capacity was exhausted.
    WebSocketBytesCapacity,
    /// Bounded WebSocket replacement capacity was exhausted.
    WebSocketEvictionCapacity,
    /// Effective WEB configuration disabled new work.
    ConfigDisabled,
    /// Effective user policy disabled new work.
    UserDisabled,
    /// Operator admission was paused.
    OperatorPaused,
    /// Operator admission was gracefully draining.
    OperatorDraining,
    /// Operator drain had committed forced close signals.
    OperatorForceClosing,
    /// Operator drain had reached confirmed zero.
    OperatorDrained,
    /// The active relay generation closed new admission.
    GenerationAdmissionClosed,
    /// The active relay generation could not own a new task.
    GenerationScopeClosed,
    /// Terminal runtime closure rejected the operation.
    RuntimeClosed,
    /// A bounded operation could not acquire or complete its deadline.
    Deadline,
    /// Concurrent ownership rejected the operation.
    Concurrent,
}

impl WebRejectionReason {
    /// Complete fixed rejection set in stable metric order.
    pub(crate) const ALL: [Self; 32] = [
        Self::HttpConnectionCapacity,
        Self::HttpHandlerCapacity,
        Self::LanePollCapacity,
        Self::LaneAuxPollCapacity,
        Self::BodyReaderCapacity,
        Self::BodyBytesCapacity,
        Self::BootstrapCapacity,
        Self::BootstrapRate,
        Self::SessionCapacity,
        Self::SessionRate,
        Self::StreamSessionCapacity,
        Self::StreamCapacity,
        Self::StreamRate,
        Self::StreamTupleExhausted,
        Self::StreamHandshakeCapacity,
        Self::GenerationConnectionCapacity,
        Self::QueueSessionCapacity,
        Self::QueueGlobalCapacity,
        Self::WebSocketConnectionCapacity,
        Self::WebSocketBytesCapacity,
        Self::WebSocketEvictionCapacity,
        Self::ConfigDisabled,
        Self::UserDisabled,
        Self::OperatorPaused,
        Self::OperatorDraining,
        Self::OperatorForceClosing,
        Self::OperatorDrained,
        Self::GenerationAdmissionClosed,
        Self::GenerationScopeClosed,
        Self::RuntimeClosed,
        Self::Deadline,
        Self::Concurrent,
    ];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HttpConnectionCapacity => "http_connection_capacity",
            Self::HttpHandlerCapacity => "http_handler_capacity",
            Self::LanePollCapacity => "lane_poll_capacity",
            Self::LaneAuxPollCapacity => "lane_aux_poll_capacity",
            Self::BodyReaderCapacity => "body_reader_capacity",
            Self::BodyBytesCapacity => "body_bytes_capacity",
            Self::BootstrapCapacity => "bootstrap_capacity",
            Self::BootstrapRate => "bootstrap_rate",
            Self::SessionCapacity => "session_capacity",
            Self::SessionRate => "session_rate",
            Self::StreamSessionCapacity => "stream_session_capacity",
            Self::StreamCapacity => "stream_capacity",
            Self::StreamRate => "stream_rate",
            Self::StreamTupleExhausted => "stream_tuple_exhausted",
            Self::StreamHandshakeCapacity => "stream_handshake_capacity",
            Self::GenerationConnectionCapacity => "generation_connection_capacity",
            Self::QueueSessionCapacity => "queue_session_capacity",
            Self::QueueGlobalCapacity => "queue_global_capacity",
            Self::WebSocketConnectionCapacity => "websocket_connection_capacity",
            Self::WebSocketBytesCapacity => "websocket_bytes_capacity",
            Self::WebSocketEvictionCapacity => "websocket_eviction_capacity",
            Self::ConfigDisabled => "config_disabled",
            Self::UserDisabled => "user_disabled",
            Self::OperatorPaused => "operator_paused",
            Self::OperatorDraining => "operator_draining",
            Self::OperatorForceClosing => "operator_force_closing",
            Self::OperatorDrained => "operator_drained",
            Self::GenerationAdmissionClosed => "generation_admission_closed",
            Self::GenerationScopeClosed => "generation_scope_closed",
            Self::RuntimeClosed => "runtime_closed",
            Self::Deadline => "deadline",
            Self::Concurrent => "concurrent",
        }
    }
}

/// Terminal result for one accepted socket that found normal HTTP capacity exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebHttpConnectionOverloadOutcome {
    /// Legacy policy closed the accepted socket immediately.
    Dropped,
    /// Bounded waiting acquired ordinary connection capacity.
    WaitAdmitted,
    /// Bounded waiting expired and emitted the retryable response.
    WaitTimeout503,
    /// Immediate response policy emitted the retryable response.
    Responded503,
    /// The bounded overload socket pool was already full.
    OverflowCapacityDrop,
    /// Writing or closing the retryable response failed.
    ResponseErrorDrop,
    /// Listener or process shutdown cancelled overload handling.
    ShutdownDrop,
}

impl WebHttpConnectionOverloadOutcome {
    /// Complete fixed accepted-socket outcome set in stable metric order.
    pub(crate) const ALL: [Self; 7] = [
        Self::Dropped,
        Self::WaitAdmitted,
        Self::WaitTimeout503,
        Self::Responded503,
        Self::OverflowCapacityDrop,
        Self::ResponseErrorDrop,
        Self::ShutdownDrop,
    ];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dropped => "dropped",
            Self::WaitAdmitted => "wait_admitted",
            Self::WaitTimeout503 => "wait_timeout_503",
            Self::Responded503 => "responded_503",
            Self::OverflowCapacityDrop => "overflow_capacity_drop",
            Self::ResponseErrorDrop => "response_error_drop",
            Self::ShutdownDrop => "shutdown_drop",
        }
    }
}

/// Passive outcome for one plain-HTTP decoy upstream request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebDecoyUpstreamOutcome {
    /// The internal decoy origin produced a response head.
    Success,
    /// The request activity plane could not grant a deadline lease.
    DeadlineExhausted,
    /// The configured origin actively refused the TCP connection.
    ConnectRefused,
    /// The bounded TCP connect phase timed out.
    ConnectTimeout,
    /// The TCP connect failed for another I/O reason.
    ConnectError,
    /// The bounded HTTP client handshake timed out.
    HttpHandshakeTimeout,
    /// The HTTP client handshake failed.
    HttpHandshakeError,
    /// The origin did not produce a response head before the deadline.
    ResponseHeadTimeout,
    /// URI preparation or the HTTP request failed.
    RequestError,
}

impl WebDecoyUpstreamOutcome {
    /// Complete fixed decoy-origin outcome set in stable metric order.
    pub(crate) const ALL: [Self; 9] = [
        Self::Success,
        Self::DeadlineExhausted,
        Self::ConnectRefused,
        Self::ConnectTimeout,
        Self::ConnectError,
        Self::HttpHandshakeTimeout,
        Self::HttpHandshakeError,
        Self::ResponseHeadTimeout,
        Self::RequestError,
    ];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::DeadlineExhausted => "deadline_exhausted",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectError => "connect_error",
            Self::HttpHandshakeTimeout => "http_handshake_timeout",
            Self::HttpHandshakeError => "http_handshake_error",
            Self::ResponseHeadTimeout => "response_head_timeout",
            Self::RequestError => "request_error",
        }
    }
}

/// API-safe typed rejection counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebRejectionCounter {
    /// Stable closed-set rejection token.
    pub(crate) reason: &'static str,
    /// Monotonic process-lifetime count.
    pub(crate) total: u64,
}

/// API-safe typed outcome counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebOutcomeCounter {
    /// Stable closed-set outcome token.
    pub(crate) outcome: &'static str,
    /// Monotonic process-lifetime count.
    pub(crate) total: u64,
}

/// Existing aggregate WEB totals retained with their original semantics.
#[derive(Clone, Copy)]
pub(crate) struct WebAggregateSnapshot {
    /// Created session incarnations.
    pub(crate) sessions_created: u64,
    /// Closed session incarnations.
    pub(crate) sessions_closed: u64,
    /// Admitted logical streams.
    pub(crate) streams_opened: u64,
    /// Rejected logical streams covered by the legacy aggregate.
    pub(crate) streams_rejected: u64,
    /// Accepted carrier uplink payload bytes.
    pub(crate) bytes_up: u64,
    /// Emitted carrier downlink payload bytes.
    pub(crate) bytes_down: u64,
    /// Legacy aggregate capacity-hit count.
    pub(crate) limit_hits: u64,
}

/// Process-owned operational counters shared by ingress, API, and metrics.
pub(crate) struct WebTelemetry {
    started: Instant,
    live_acceptors: AtomicUsize,
    accepted: AtomicU64,
    accept_errors: AtomicU64,
    rejections: [AtomicU64; WebRejectionReason::ALL.len()],
    overload_outcomes: [AtomicU64; WebHttpConnectionOverloadOutcome::ALL.len()],
    decoy_outcomes: [AtomicU64; WebDecoyUpstreamOutcome::ALL.len()],
    last_decoy_outcome: AtomicUsize,
    last_decoy_elapsed_ms: AtomicU64,
    sessions_created: AtomicU64,
    sessions_closed: AtomicU64,
    streams_opened: AtomicU64,
    streams_rejected: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    limit_hits: AtomicU64,
}

impl WebTelemetry {
    /// Creates zeroed process-lifetime WEB telemetry.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            live_acceptors: AtomicUsize::new(0),
            accepted: AtomicU64::new(0),
            accept_errors: AtomicU64::new(0),
            rejections: std::array::from_fn(|_| AtomicU64::new(0)),
            overload_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            decoy_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            last_decoy_outcome: AtomicUsize::new(usize::MAX),
            last_decoy_elapsed_ms: AtomicU64::new(0),
            sessions_created: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            streams_rejected: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            limit_hits: AtomicU64::new(0),
        })
    }

    /// Registers one live accept loop before its task can be cancelled unpolled.
    pub(crate) fn acceptor_guard(self: &Arc<Self>) -> WebAcceptorGuard {
        self.live_acceptors.fetch_add(1, Ordering::AcqRel);
        WebAcceptorGuard {
            telemetry: Arc::clone(self),
        }
    }

    /// Returns currently registered WEB accept loops.
    pub(crate) fn live_acceptors(&self) -> usize {
        self.live_acceptors.load(Ordering::Acquire)
    }

    /// Records one successfully accepted WEB socket.
    pub(crate) fn record_accept(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns successfully accepted WEB sockets.
    pub(crate) fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Records one WEB listener `accept` error.
    pub(crate) fn record_accept_error(&self) {
        self.accept_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns WEB listener `accept` errors.
    pub(crate) fn accept_errors(&self) -> u64 {
        self.accept_errors.load(Ordering::Relaxed)
    }

    /// Records one operational rejection at its admission decision point.
    pub(crate) fn record_rejection(&self, reason: WebRejectionReason) {
        self.rejections[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed rejection counter.
    pub(crate) fn rejection_total(&self, reason: WebRejectionReason) -> u64 {
        self.rejections[reason as usize].load(Ordering::Relaxed)
    }

    /// Captures the complete fixed rejection set for API serialization.
    pub(crate) fn rejection_counters(&self) -> Vec<WebRejectionCounter> {
        WebRejectionReason::ALL
            .into_iter()
            .map(|reason| WebRejectionCounter {
                reason: reason.as_str(),
                total: self.rejection_total(reason),
            })
            .collect()
    }

    /// Records one terminal accepted-socket overload outcome.
    pub(crate) fn record_overload(&self, outcome: WebHttpConnectionOverloadOutcome) {
        self.overload_outcomes[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed accepted-socket overload counter.
    pub(crate) fn overload_total(&self, outcome: WebHttpConnectionOverloadOutcome) -> u64 {
        self.overload_outcomes[outcome as usize].load(Ordering::Relaxed)
    }

    /// Captures the complete fixed overload outcome set for API serialization.
    pub(crate) fn overload_counters(&self) -> Vec<WebOutcomeCounter> {
        WebHttpConnectionOverloadOutcome::ALL
            .into_iter()
            .map(|outcome| WebOutcomeCounter {
                outcome: outcome.as_str(),
                total: self.overload_total(outcome),
            })
            .collect()
    }

    /// Records one internal plain-HTTP decoy origin outcome.
    pub(crate) fn record_decoy(&self, outcome: WebDecoyUpstreamOutcome) {
        self.decoy_outcomes[outcome as usize].fetch_add(1, Ordering::Relaxed);
        let elapsed_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.last_decoy_elapsed_ms
            .store(elapsed_ms.saturating_add(1), Ordering::Relaxed);
        self.last_decoy_outcome
            .store(outcome as usize, Ordering::Release);
    }

    /// Returns one fixed internal decoy origin counter.
    pub(crate) fn decoy_total(&self, outcome: WebDecoyUpstreamOutcome) -> u64 {
        self.decoy_outcomes[outcome as usize].load(Ordering::Relaxed)
    }

    /// Captures the complete fixed decoy outcome set for API serialization.
    pub(crate) fn decoy_counters(&self) -> Vec<WebOutcomeCounter> {
        WebDecoyUpstreamOutcome::ALL
            .into_iter()
            .map(|outcome| WebOutcomeCounter {
                outcome: outcome.as_str(),
                total: self.decoy_total(outcome),
            })
            .collect()
    }

    /// Returns the last decoy outcome and its monotonic age in milliseconds.
    pub(crate) fn last_decoy(&self) -> Option<(&'static str, u64)> {
        let raw = self.last_decoy_outcome.load(Ordering::Acquire);
        let outcome = WebDecoyUpstreamOutcome::ALL.get(raw).copied()?;
        let recorded = self.last_decoy_elapsed_ms.load(Ordering::Relaxed);
        let now = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        Some((
            outcome.as_str(),
            now.saturating_sub(recorded.saturating_sub(1)),
        ))
    }

    /// Records one created session incarnation.
    pub(crate) fn record_session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one closed session incarnation.
    pub(crate) fn record_session_closed(&self) {
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one admitted logical stream.
    pub(crate) fn record_stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one logical stream in the legacy rejection aggregate.
    pub(crate) fn record_stream_rejected(&self) {
        self.streams_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds accepted carrier uplink payload bytes.
    pub(crate) fn record_up(&self, bytes: usize) {
        self.bytes_up.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Adds emitted carrier downlink payload bytes.
    pub(crate) fn record_down(&self, bytes: usize) {
        self.bytes_down.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Records one legacy aggregate capacity hit.
    pub(crate) fn record_limit_hit(&self) {
        self.limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Captures legacy process-owned aggregate totals.
    pub(crate) fn aggregates(&self) -> WebAggregateSnapshot {
        WebAggregateSnapshot {
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_closed: self.sessions_closed.load(Ordering::Relaxed),
            streams_opened: self.streams_opened.load(Ordering::Relaxed),
            streams_rejected: self.streams_rejected.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            limit_hits: self.limit_hits.load(Ordering::Relaxed),
        }
    }
}

/// Cancellation-safe live-acceptor registration.
pub(crate) struct WebAcceptorGuard {
    telemetry: Arc<WebTelemetry>,
}

impl Drop for WebAcceptorGuard {
    fn drop(&mut self) {
        self.telemetry.live_acceptors.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_counter_sets_and_acceptor_guard_are_exact() {
        let telemetry = WebTelemetry::new();
        let guard = telemetry.acceptor_guard();
        assert_eq!(telemetry.live_acceptors(), 1);
        telemetry.record_rejection(WebRejectionReason::HttpConnectionCapacity);
        telemetry.record_overload(WebHttpConnectionOverloadOutcome::Dropped);
        telemetry.record_decoy(WebDecoyUpstreamOutcome::ConnectRefused);
        assert_eq!(
            telemetry.rejection_counters().len(),
            WebRejectionReason::ALL.len()
        );
        assert_eq!(
            telemetry.overload_counters().len(),
            WebHttpConnectionOverloadOutcome::ALL.len()
        );
        assert_eq!(
            telemetry.decoy_counters().len(),
            WebDecoyUpstreamOutcome::ALL.len()
        );
        assert_eq!(
            telemetry.rejection_total(WebRejectionReason::HttpConnectionCapacity),
            1
        );
        assert_eq!(
            telemetry.last_decoy().map(|value| value.0),
            Some("connect_refused")
        );
        drop(guard);
        assert_eq!(telemetry.live_acceptors(), 0);
    }
}
