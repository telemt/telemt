use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{WebCarrier, WebLimitsConfig};
use crate::maestro::generation::RuntimeGeneration;
use crate::web::telemetry::{WebRejectionReason, WebTelemetry};
use crate::web::trace::WebTraceStore;

// Credential maps, quotas, and token-bucket helpers remain private to the manager.
mod state;
// Carrier attempt metadata remains explicit and independent from HTTP parsing.
mod negotiation;
// Bounded process-local carrier evidence is isolated from session registries.
#[path = "manager/carrier_learning.rs"]
mod learning;
// Bootstrap credentials and idempotent session creation are isolated from queue accounting.
mod credentials;
// First-session admission and bounded carrier replacement share one state machine.
mod session_creation;
// Session admission remains separate from stream tuple ownership.
mod session_admission;
// Carrier commit, health, and conflict echoes share one outcome publication path.
mod carrier_outcome;
// Stream admission and synthetic tuple ownership are process-scoped.
mod admission;
// Shutdown and expiry work remain outside request-path coordination.
mod lifecycle;
pub(crate) use lifecycle::WebShutdownOutcome;
// Reversible operator admission stays independent from terminal process shutdown.
mod operator_lifecycle;
pub(crate) use operator_lifecycle::{
    OperatorLifecycleError, OperatorLifecycleState, OperatorLifecycleStatus,
};
// Queue and WebSocket allocations share one process-owned data-plane budget.
mod budget;
// WebSocket admission, replacement, and liveness are process-scoped.
mod websocket;
// Bounded read-only snapshots and opaque session references serve the API.
mod status;
pub(crate) use status::{
    SessionDetail, SessionFilter, SessionListRequest, SessionRefError, WebRuntimeStatus,
};
// Fixed-cardinality capacity snapshots serve API and Prometheus observability.
mod observability;
pub(crate) use observability::{WebCapacityResourceStatus, WebCapacitySnapshot};
// Asynchronous bounded close operations isolate mutation lifecycle from HTTP requests.
mod control;
pub(crate) use budget::WebSocketBudgetLease;
use budget::{WebDataBudget, WebSocketBudgetClass};
pub(crate) use control::{CloseOperationSelector, ControlError};
pub(crate) use negotiation::{
    CarrierCapabilities, CarrierClientClass, CarrierFailure, CarrierLearningContext, CarrierRequest,
};
use state::{ManagerState, StreamAdmissionState};
pub(crate) use websocket::{WebSocketConnection, WebSocketKind};

const TOKEN_BYTES: usize = 32;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

/// Stable hash key used for bootstrap and session credentials.
pub(crate) type TokenHash = [u8; TOKEN_BYTES];
/// Stable non-allocating key used for per-profile quotas.
pub(crate) type ProfileKey = [u8; TOKEN_BYTES];

/// Stable failure category for accepted-socket capacity admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpConnectionAdmissionError {
    /// The bounded connection plane currently has no free permit.
    AtCapacity,
    /// Terminal runtime shutdown closed the connection plane.
    Closed,
}

/// WEB manager operation failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagerError {
    /// Credential, hostname, or ownership validation failed.
    Authentication,
    /// Bounded queue capacity is temporarily unavailable.
    Backpressure,
    /// A configured admission or rate ceiling was reached.
    Limit,
    /// Carrier framing or sequencing violated the protocol.
    Protocol,
    /// The operation conflicts with another in-flight operation.
    Concurrent,
    /// An authenticated attempt chain is already committed.
    Committed,
    /// The process or session has stopped accepting work.
    Closed,
    /// Operator pause or drain temporarily rejects new WEB work.
    AdmissionPaused,
}

impl ManagerError {
    /// Returns the stable non-sensitive failure token used by WEB diagnostics.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Backpressure => "backpressure",
            Self::Limit => "limit",
            Self::Protocol => "protocol",
            Self::Concurrent => "concurrent",
            Self::Committed => "committed",
            Self::Closed => "closed",
            Self::AdmissionPaused => "admission_paused",
        }
    }
}

/// Successful idempotent session creation result.
pub(crate) struct CreateResult {
    /// Opaque bearer token for the created or replayed session.
    pub(crate) token: String,
    /// Carrier frozen into the created or replayed session.
    pub(crate) carrier: WebCarrier,
    /// One-based carrier attempt echoed only for negotiated sessions.
    pub(crate) attempt: Option<u8>,
    /// Effective frozen candidate count on the first automatic response.
    pub(crate) candidate_count: Option<u8>,
    /// Cumulative final chain deadline on the first automatic response.
    pub(crate) deadline_secs: Option<u64>,
    /// Actual attempt-chain phase echoed for automatic sessions.
    pub(crate) carrier_state: Option<&'static str>,
}

/// Authenticated non-secret attempt-chain metadata returned with a conflict.
pub(crate) struct CarrierEcho {
    /// Carrier frozen into the current committed attempt.
    pub(crate) carrier: WebCarrier,
    /// One-based current attempt.
    pub(crate) attempt: u8,
    /// Frozen supported candidate count.
    pub(crate) candidate_count: u8,
    /// Frozen cumulative final deadline.
    pub(crate) deadline_secs: u64,
    /// Actual current chain phase.
    pub(crate) state: &'static str,
}

/// Successful bridge bootstrap issuance result.
pub(crate) struct BootstrapResult {
    /// Opaque one-use bootstrap credential.
    pub(crate) token: String,
    /// Process-unique non-secret trace identifier.
    pub(crate) trace_session_id: u64,
}

/// Process-owned bounded WEB credential, session, and memory coordinator.
pub(crate) struct WebProcessRuntime {
    runtime_instance: Arc<str>,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    trace: Arc<WebTraceStore>,
    limits: WebLimitsConfig,
    state: Mutex<ManagerState>,
    stream_admission: Mutex<StreamAdmissionState>,
    learning: Mutex<learning::CarrierLearning>,
    http_connections: Arc<Semaphore>,
    http_overload_connections: Arc<Semaphore>,
    http_handlers: Arc<Semaphore>,
    lane_polls: Arc<Semaphore>,
    lane_aux_polls: Arc<Semaphore>,
    body_readers: Arc<Semaphore>,
    body_bytes: Arc<Semaphore>,
    stream_handshakes: Arc<Semaphore>,
    websocket_connections: Arc<Semaphore>,
    websockets: Mutex<websocket::WebSocketRegistry>,
    websocket_next_id: AtomicU64,
    websocket_clock: std::time::Instant,
    websocket_notify: Arc<Notify>,
    operator_lifecycle: operator_lifecycle::OperatorLifecycle,
    data_budget: Arc<WebDataBudget>,
    control_operations: Mutex<control::ControlOperationRegistry>,
    next_control_operation_id: AtomicU64,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    telemetry: Arc<WebTelemetry>,
}

impl WebProcessRuntime {
    /// Starts one process-scoped manager using immutable allocation ceilings.
    #[cfg(test)]
    pub(crate) fn start(active_runtime: Arc<ArcSwap<RuntimeGeneration>>) -> Arc<Self> {
        let config = active_runtime.load().config();
        let trace = WebTraceStore::new(config.web.debug.clone(), &config.web.limits);
        Self::start_with_trace(active_runtime, trace, WebTelemetry::new())
    }

    /// Starts one process-scoped manager with a shared API-visible trace store.
    pub(crate) fn start_with_trace(
        active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
        trace: Arc<WebTraceStore>,
        telemetry: Arc<WebTelemetry>,
    ) -> Arc<Self> {
        let initial_generation = active_runtime.load_full();
        let config = initial_generation.config();
        trace.apply_policy(initial_generation.id, &config.web.debug);
        let limits = config.web.limits.clone();
        let learning_capacity = limits.max_carrier_learning_entries;
        let mut carrier_learning = learning::CarrierLearning::new(learning_capacity);
        let _ = carrier_learning.apply_policy(
            std::time::Instant::now(),
            config.web.carrier_negotiation_enabled() && config.web.carrier_learning,
            config.web.carrier_negotiation_aggressiveness,
            Duration::from_secs(config.web.timeouts.carrier_learning_secs),
        );
        let websocket_connections = limits
            .max_http_connections
            .saturating_sub(limits.websocket_http_connection_reserve);
        let lane_poll_limit = limits.max_http_handlers / 2;
        let lane_aux_poll_limit = (lane_poll_limit / 2).max(1);
        let runtime_instance: Arc<str> = Arc::from(format!("{:032x}", rand::random::<u128>()));
        let runtime = Arc::new(Self {
            operator_lifecycle: operator_lifecycle::OperatorLifecycle::new(Arc::clone(
                &runtime_instance,
            )),
            runtime_instance,
            active_runtime,
            trace,
            http_connections: Arc::new(Semaphore::new(limits.max_http_connections)),
            http_overload_connections: Arc::new(Semaphore::new(
                limits.max_http_overload_connections,
            )),
            http_handlers: Arc::new(Semaphore::new(limits.max_http_handlers)),
            lane_polls: Arc::new(Semaphore::new(lane_poll_limit)),
            lane_aux_polls: Arc::new(Semaphore::new(lane_aux_poll_limit)),
            body_readers: Arc::new(Semaphore::new(limits.max_body_readers)),
            body_bytes: Arc::new(Semaphore::new(limits.max_body_bytes_global)),
            stream_handshakes: Arc::new(Semaphore::new(limits.max_stream_handshakes)),
            websocket_connections: Arc::new(Semaphore::new(websocket_connections)),
            websockets: Mutex::new(websocket::WebSocketRegistry::default()),
            websocket_next_id: AtomicU64::new(1),
            websocket_clock: std::time::Instant::now(),
            websocket_notify: Arc::new(Notify::new()),
            data_budget: WebDataBudget::new(limits.clone()),
            control_operations: Mutex::new(control::ControlOperationRegistry::default()),
            next_control_operation_id: AtomicU64::new(1),
            limits,
            state: Mutex::new(ManagerState::new(initial_generation.id, config.web.enabled)),
            stream_admission: Mutex::new(StreamAdmissionState::default()),
            learning: Mutex::new(carrier_learning),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            telemetry,
        });
        let weak = Arc::downgrade(&runtime);
        let shutdown = runtime.shutdown.clone();
        runtime.tasks.spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let Some(runtime) = weak.upgrade() else {
                            break;
                        };
                        let generation = runtime.active_generation();
                        let policy = generation.config().web.debug.clone();
                        runtime
                            .trace
                            .apply_policy(generation.id, &policy);
                        runtime.cleanup();
                    }
                }
            }
        });
        runtime
    }

    /// Loads the currently active generation without retaining older generations.
    pub(crate) fn active_generation(&self) -> Arc<RuntimeGeneration> {
        self.active_runtime.load_full()
    }

    /// Returns the random process-instance fence used by control-plane references.
    pub(crate) fn runtime_instance(&self) -> &str {
        &self.runtime_instance
    }

    /// Returns the process-owned WEB debug trace store.
    pub(crate) fn trace(&self) -> &Arc<WebTraceStore> {
        &self.trace
    }

    /// Returns the process-owned operational telemetry handle.
    pub(crate) fn telemetry(&self) -> &Arc<WebTelemetry> {
        &self.telemetry
    }

    /// Returns whether terminal process shutdown has started.
    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    /// Reserves one accepted HTTP connection.
    pub(crate) fn try_http_connection(
        &self,
    ) -> Result<OwnedSemaphorePermit, HttpConnectionAdmissionError> {
        match Arc::clone(&self.http_connections).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) => {
                self.record_limit_hit();
                Err(HttpConnectionAdmissionError::AtCapacity)
            }
            Err(TryAcquireError::Closed) => Err(HttpConnectionAdmissionError::Closed),
        }
    }

    /// Waits for one accepted HTTP connection slot after bounded overload admission.
    pub(crate) async fn acquire_http_connection(
        &self,
    ) -> Result<OwnedSemaphorePermit, HttpConnectionAdmissionError> {
        Arc::clone(&self.http_connections)
            .acquire_owned()
            .await
            .map_err(|_| HttpConnectionAdmissionError::Closed)
    }

    /// Reserves one accepted socket outside ordinary HTTP connection capacity.
    pub(crate) fn try_http_overload_connection(
        &self,
    ) -> Result<OwnedSemaphorePermit, HttpConnectionAdmissionError> {
        match Arc::clone(&self.http_overload_connections).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) => Err(HttpConnectionAdmissionError::AtCapacity),
            Err(TryAcquireError::Closed) => Err(HttpConnectionAdmissionError::Closed),
        }
    }

    /// Reserves one concurrently executing HTTP request handler.
    pub(crate) fn try_http_handler(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.http_handlers).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::HttpHandlerCapacity);
        }
        permit
    }

    /// Reserves one parked lane poll without exhausting all HTTP handlers.
    pub(crate) fn try_lane_poll(&self, auxiliary: bool) -> Option<OwnedSemaphorePermit> {
        let slots = if auxiliary {
            &self.lane_aux_polls
        } else {
            &self.lane_polls
        };
        let permit = Arc::clone(slots).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_limit_hit();
            self.telemetry.record_rejection(if auxiliary {
                WebRejectionReason::LaneAuxPollCapacity
            } else {
                WebRejectionReason::LanePollCapacity
            });
        }
        permit
    }

    /// Reserves one logical stream in the inner MTProxy handshake phase.
    pub(crate) fn try_stream_handshake(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.stream_handshakes).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_stream_rejected_reason(WebRejectionReason::StreamHandshakeCapacity);
        }
        permit
    }

    /// Spawns one process-owned auxiliary task with shutdown cancellation.
    pub(crate) fn spawn_auxiliary<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.shutdown.is_cancelled() {
            drop(future);
            return;
        }
        let shutdown = self.shutdown.clone();
        let tracked = self.tasks.track_future(async move {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {}
                _ = future => {}
            }
        });
        if self.shutdown.is_cancelled() {
            drop(tracked);
            return;
        }
        drop(tokio::spawn(tracked));
    }

    /// Reserves one body reader and its declared bounded body allocation.
    pub(crate) fn try_body_budget(
        &self,
        bytes: usize,
    ) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let Some(bytes) = u32::try_from(bytes).ok() else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyBytesCapacity);
            return None;
        };
        let Some(reader) = Arc::clone(&self.body_readers).try_acquire_owned().ok() else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyReaderCapacity);
            return None;
        };
        let Some(body) = Arc::clone(&self.body_bytes)
            .try_acquire_many_owned(bytes)
            .ok()
        else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyBytesCapacity);
            return None;
        };
        Some((reader, body))
    }

    /// Reserves transient bytes while one downlink batch replaces queued frames.
    pub(crate) fn try_downlink_staging_budget(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        let bytes = u32::try_from(bytes).ok()?;
        let permit = Arc::clone(&self.body_bytes)
            .try_acquire_many_owned(bytes)
            .ok();
        if permit.is_none() {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyBytesCapacity);
        }
        permit
    }

    /// Reserves bounded process-wide queue capacity for data or control traffic.
    pub(crate) fn try_reserve_pending(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
        downlink: bool,
    ) -> bool {
        if !self
            .data_budget
            .try_reserve_queue(owner, bytes, items, control, downlink)
        {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::QueueGlobalCapacity);
            return false;
        }
        true
    }

    /// Releases process-wide queue capacity and wakes blocked relay writers.
    pub(crate) fn release_pending(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
    ) {
        self.data_budget.release_queue(owner, bytes, items, control);
    }

    /// Returns the shared notification source for global queue capacity changes.
    pub(crate) fn budget_notify(&self) -> Arc<Notify> {
        self.data_budget.notify()
    }

    /// Reserves fixed WebSocket driver memory below the admission watermark.
    pub(crate) fn try_websocket_base_budget(
        &self,
        owner: ProfileKey,
        bytes: usize,
    ) -> Option<WebSocketBudgetLease> {
        self.data_budget
            .try_reserve_websocket(owner, bytes, WebSocketBudgetClass::Base)
    }

    /// Reserves one transient WebSocket message below the eviction watermark.
    pub(crate) fn try_websocket_data_budget(
        &self,
        owner: ProfileKey,
        bytes: usize,
    ) -> Option<WebSocketBudgetLease> {
        self.data_budget
            .try_reserve_websocket(owner, bytes, WebSocketBudgetClass::Data)
    }

    /// Admits one WebSocket with dead-first, then owner-local bounded replacement.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_websocket(
        self: &Arc<Self>,
        owner: ProfileKey,
        session_id: u64,
        session_hash: TokenHash,
        client_ip: IpAddr,
        kind: WebSocketKind,
        base_bytes: usize,
        liveness_interval: Duration,
        eviction_timeout: Duration,
        parent_cancellation: CancellationToken,
    ) -> Result<WebSocketConnection, ManagerError> {
        websocket::admit(
            self,
            owner,
            session_id,
            session_hash,
            client_ip,
            kind,
            base_bytes,
            liveness_interval,
            eviction_timeout,
            parent_cancellation,
        )
        .await
    }

    /// Accounts one successfully committed carrier uplink body.
    pub(crate) fn record_up(&self, bytes: usize) {
        self.telemetry.record_up(bytes);
    }

    /// Accounts one emitted carrier downlink body.
    pub(crate) fn record_down(&self, bytes: usize) {
        self.telemetry.record_down(bytes);
    }

    fn record_limit_hit(&self) {
        self.telemetry.record_limit_hit();
    }
}
