use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize};
use std::task::Waker;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config::{WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebTimeoutsConfig};
use crate::proxy::user_admission::UserSessionRegistration;
use crate::web::frame::FrameType;
use crate::web::manager::{
    CarrierClientClass, CarrierLearningContext, ProfileKey, TokenHash, WebProcessRuntime,
};

// Backend tasks own generation admission and authenticated MTProxy relay lifetimes.
mod backend;
// Deferred callbacks preserve the session-state lock as a callback-free boundary.
mod effects;
use effects::DeferredSessionEffects;
// Activity clocks separate authenticated peer leases from diagnostic progress.
mod activity;
use activity::SessionActivity;
// Shared state helpers own queue accounting and bounded tombstone updates.
mod state;
use state::{inbound_queue_cost, insert_carrier_lane, remember_closed};
// Downlink queues own cursor replay, flow control, and memory reservations.
mod downlink;
// Response ownership keeps detached batches charged until the last body clone drops.
mod resident;
// Read-only control-plane snapshots stay isolated from carrier operations.
mod status;
pub(crate) use status::WebSessionStatus;
// Lane carrier state isolates request sequencing and downlink replay per logical stream.
mod lanes;
// Lane batch staging transfers queue ownership without escaping process budgets.
mod lane_downlink;
// Lane uplink creation remains transactional across validation and queue reservations.
mod lane_uplink;
// WebSocket carrier state owns pre-OPEN lane reservations and failure isolation.
mod websocket;
pub(crate) use websocket::WebSocketLaneReservation;
pub(crate) use websocket::WebSocketProbeReservation;
// Carrier commit and health evidence share one session-locked state machine.
mod negotiation;
use negotiation::CarrierHealthPublicationState;
// Session closure and carrier-attempt transitions share one cancellation boundary.
mod lifecycle;
use lifecycle::SessionNegotiationPhase;
pub(crate) use lifecycle::{SessionCloseOutcome, SessionCloseReason};
// Uplink batches own exactly-once sequencing and client-frame validation.
mod uplink;
// HTTP conveyor ownership bounds reordered requests without changing native frames.
mod conveyor;
pub(crate) use conveyor::{ConveyorError, conveyor_waiter_limit};
// Logical stream polling owns cancellation-safe waker registration.
mod stream_io;

/// Conservative allocator and container overhead charged to every queued item.
pub(crate) const QUEUE_ITEM_COST: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingClass {
    Uplink,
    Downlink,
    Control,
}

struct InboundChunk {
    bytes: Bytes,
    offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamIdentity {
    pub(crate) id: u32,
    pub(crate) instance: u64,
}

/// Exact server-local identity of one carrier-lane incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierLaneIdentity {
    /// Numeric lane identifier carried on the wire.
    pub(crate) lane_id: u32,
    /// Monotonic server-local incarnation of that numeric lane.
    pub(crate) instance: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WebSocketLaneClaim {
    lane: CarrierLaneIdentity,
    peer_port: u16,
    connection_id: Option<u64>,
}

struct StreamState {
    instance: u64,
    inbound: VecDeque<InboundChunk>,
    receive_window: u32,
    send_credit: u64,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct QueuedFrame {
    encoded: BytesMut,
    frame_type: FrameType,
    stream_id: u32,
    control: bool,
    cost: usize,
}

struct DownBatch {
    body: Bytes,
    lease: Arc<resident::PendingResponseLease>,
    base_cursor: u64,
    next_cursor: u64,
    data_bytes: usize,
    data_items: usize,
    control_bytes: usize,
    control_items: usize,
    carrier_health_eligible: bool,
}

struct CarrierLane {
    instance: u64,
    pending_bytes: usize,
    pending_items: usize,
    resident: Arc<resident::ResidentCounters>,
    pending_frames: VecDeque<QueuedFrame>,
    pending_windows: HashMap<u32, usize>,
    unacked: Option<DownBatch>,
    down_cursor: u64,
    down_epoch: u64,
    last_up_sequence: u64,
    last_up_digest: TokenHash,
    up_active: bool,
    notify: Arc<Notify>,
}

impl CarrierLane {
    fn new(instance: u64) -> Self {
        Self {
            instance,
            pending_bytes: 0,
            pending_items: 0,
            resident: Arc::new(resident::ResidentCounters::default()),
            pending_frames: VecDeque::new(),
            pending_windows: HashMap::new(),
            unacked: None,
            down_cursor: 0,
            down_epoch: 0,
            last_up_sequence: 0,
            last_up_digest: [0; 32],
            up_active: false,
            notify: Arc::new(Notify::new()),
        }
    }
}

struct SessionState {
    conveyor: conveyor::ConveyorState,
    streams: HashMap<u32, StreamState>,
    closing_streams: HashMap<u32, u64>,
    next_stream_instance: u64,
    active_peer_ports: HashSet<u16>,
    closed_streams: HashSet<u32>,
    closed_order: VecDeque<u32>,
    pending_frames: VecDeque<QueuedFrame>,
    pending_windows: HashMap<u32, usize>,
    unacked: Option<DownBatch>,
    down_cursor: u64,
    down_epoch: u64,
    last_up_sequence: u64,
    last_up_digest: TokenHash,
    carrier_lanes: HashMap<u32, CarrierLane>,
    lane_open_waits: usize,
    next_lane_instance: u64,
    websocket_lane_reservations: HashMap<u32, WebSocketLaneClaim>,
    pending_bytes: usize,
    pending_items: usize,
    pending_control_bytes: usize,
    pending_control_items: usize,
    activity: SessionActivity,
    negotiation_phase: SessionNegotiationPhase,
    carrier_health_due_at: Option<Instant>,
    carrier_health_activity_at: Option<Instant>,
    carrier_health_uplink: bool,
    carrier_health_downlink: bool,
    carrier_commit_published: bool,
    recovery_committed: bool,
    websocket_carrier_active: bool,
    websocket_commit_ack_pending: bool,
    websocket_commit_ack_owner: Option<u64>,
    websocket_commit_ack_written: bool,
    websocket_probe_claimed: bool,
    close_requested: Option<SessionCloseReason>,
    closed: bool,
}

/// One bounded WEB carrier session containing logical MTProxy streams.
pub(crate) struct WebSession {
    manager: std::sync::Weak<WebProcessRuntime>,
    token_hash: TokenHash,
    client_ip: IpAddr,
    trace_session_id: u64,
    generation_id: u64,
    profile: Arc<WebRuntimeProfile>,
    profile_key: ProfileKey,
    selected_carrier: WebCarrier,
    carrier_attempt: u8,
    bootstrap_hash: TokenHash,
    carrier_deadline_at: Option<Instant>,
    carrier_class: CarrierClientClass,
    learning_context: Option<CarrierLearningContext>,
    automatic_carrier: bool,
    recovery: bool,
    created_at: Instant,
    limits: WebLimitsConfig,
    timeouts: WebTimeoutsConfig,
    _user_registration: Option<UserSessionRegistration>,
    state: Mutex<SessionState>,
    carrier_health_publication: AtomicU8,
    close_complete: AtomicBool,
    close_notify: Notify,
    down_notify: Arc<Notify>,
    lane_open_notify: Arc<Notify>,
    cancel: CancellationToken,
    tasks_live: AtomicUsize,
    tasks_done: Arc<Notify>,
    resident: Arc<resident::ResidentCounters>,
    finished: AtomicBool,
    up_active: AtomicBool,
}

/// One successful downlink poll result.
pub(crate) struct PollResult {
    /// Encoded downlink frame batch, or an empty long-poll result.
    pub(crate) body: Bytes,
    /// Cursor the client must present on its next downlink request.
    pub(crate) next_cursor: u64,
    /// Indicates that a drained non-zero lane no longer needs polling.
    pub(crate) lane_closed: bool,
}

impl WebSession {
    #[allow(clippy::too_many_arguments)]
    /// Creates one carrier session with immutable ownership and allocation policy.
    pub(crate) fn new(
        manager: std::sync::Weak<WebProcessRuntime>,
        token_hash: TokenHash,
        client_ip: IpAddr,
        trace_session_id: u64,
        profile: Arc<WebRuntimeProfile>,
        profile_key: ProfileKey,
        selected_carrier: WebCarrier,
        carrier_attempt: u8,
        bootstrap_hash: TokenHash,
        carrier_deadline_at: Option<Instant>,
        carrier_class: CarrierClientClass,
        learning_context: Option<CarrierLearningContext>,
        automatic_carrier: bool,
        recovery: bool,
        limits: WebLimitsConfig,
        timeouts: WebTimeoutsConfig,
        user_registration: Option<UserSessionRegistration>,
    ) -> Arc<Self> {
        let generation_id = manager
            .upgrade()
            .map_or(0, |manager| manager.active_generation().id);
        Self::new_for_generation(
            manager,
            token_hash,
            client_ip,
            trace_session_id,
            generation_id,
            profile,
            profile_key,
            selected_carrier,
            carrier_attempt,
            bootstrap_hash,
            carrier_deadline_at,
            carrier_class,
            learning_context,
            automatic_carrier,
            recovery,
            limits,
            timeouts,
            user_registration,
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates one carrier session with the issuing generation captured explicitly.
    pub(crate) fn new_for_generation(
        manager: std::sync::Weak<WebProcessRuntime>,
        token_hash: TokenHash,
        client_ip: IpAddr,
        trace_session_id: u64,
        generation_id: u64,
        profile: Arc<WebRuntimeProfile>,
        profile_key: ProfileKey,
        selected_carrier: WebCarrier,
        carrier_attempt: u8,
        bootstrap_hash: TokenHash,
        carrier_deadline_at: Option<Instant>,
        carrier_class: CarrierClientClass,
        learning_context: Option<CarrierLearningContext>,
        automatic_carrier: bool,
        recovery: bool,
        limits: WebLimitsConfig,
        timeouts: WebTimeoutsConfig,
        user_registration: Option<UserSessionRegistration>,
    ) -> Arc<Self> {
        let created_at = Instant::now();
        let cancel = user_registration
            .as_ref()
            .map(UserSessionRegistration::token)
            .unwrap_or_default();
        let mut carrier_lanes = HashMap::new();
        let mut next_lane_instance = 1;
        if selected_carrier == WebCarrier::HttpsLanes {
            carrier_lanes.insert(0, CarrierLane::new(next_lane_instance));
            next_lane_instance += 1;
        }
        Arc::new(Self {
            manager,
            token_hash,
            client_ip,
            trace_session_id,
            generation_id,
            profile,
            profile_key,
            selected_carrier,
            carrier_attempt,
            bootstrap_hash,
            carrier_deadline_at,
            carrier_class,
            learning_context,
            automatic_carrier,
            recovery,
            created_at,
            limits,
            timeouts,
            _user_registration: user_registration,
            state: Mutex::new(SessionState {
                conveyor: conveyor::ConveyorState::default(),
                streams: HashMap::new(),
                closing_streams: HashMap::new(),
                next_stream_instance: 1,
                active_peer_ports: HashSet::new(),
                closed_streams: HashSet::new(),
                closed_order: VecDeque::new(),
                pending_frames: VecDeque::new(),
                pending_windows: HashMap::new(),
                unacked: None,
                down_cursor: 0,
                down_epoch: 0,
                last_up_sequence: 0,
                last_up_digest: [0; 32],
                carrier_lanes,
                lane_open_waits: 0,
                next_lane_instance,
                websocket_lane_reservations: HashMap::new(),
                pending_bytes: 0,
                pending_items: 0,
                pending_control_bytes: 0,
                pending_control_items: 0,
                activity: SessionActivity::new(created_at),
                negotiation_phase: SessionNegotiationPhase::Uncommitted,
                carrier_health_due_at: None,
                carrier_health_activity_at: None,
                carrier_health_uplink: false,
                carrier_health_downlink: false,
                carrier_commit_published: false,
                recovery_committed: false,
                websocket_carrier_active: false,
                websocket_commit_ack_pending: false,
                websocket_commit_ack_owner: None,
                websocket_commit_ack_written: false,
                websocket_probe_claimed: false,
                close_requested: None,
                closed: false,
            }),
            carrier_health_publication: AtomicU8::new(
                CarrierHealthPublicationState::Awaiting as u8,
            ),
            close_complete: AtomicBool::new(false),
            close_notify: Notify::new(),
            down_notify: Arc::new(Notify::new()),
            lane_open_notify: Arc::new(Notify::new()),
            cancel,
            tasks_live: AtomicUsize::new(0),
            tasks_done: Arc::new(Notify::new()),
            resident: Arc::new(resident::ResidentCounters::default()),
            finished: AtomicBool::new(false),
            up_active: AtomicBool::new(false),
        })
    }

    /// Returns the stable hashed token identity without exposing the credential.
    pub(crate) fn token_hash(&self) -> TokenHash {
        self.token_hash
    }

    /// Checks the canonical virtual host that owns this bearer session.
    pub(crate) fn matches_host(&self, host: &str) -> bool {
        self.profile.host == host
    }

    /// Returns the immutable carrier selected when this session was created.
    pub(crate) fn carrier(&self) -> WebCarrier {
        self.selected_carrier
    }

    /// Returns the stable quota owner without exposing profile credentials.
    pub(crate) fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// Returns the issuing generation retained by this frozen carrier chain.
    pub(crate) fn generation_id(&self) -> u64 {
        self.generation_id
    }

    /// Returns whether this session still belongs to its issuing runtime generation.
    pub(crate) fn current_generation_matches(&self) -> bool {
        self.manager
            .upgrade()
            .is_some_and(|manager| manager.active_generation().id == self.generation_id)
    }

    /// Returns the process-unique non-secret trace identifier.
    pub(crate) fn trace_session_id(&self) -> u64 {
        self.trace_session_id
    }

    /// Returns the immutable carrier-attempt incarnation number.
    pub(crate) fn carrier_attempt(&self) -> u8 {
        self.carrier_attempt
    }

    /// Creates a child cancellation boundary for one owned carrier task.
    pub(crate) fn carrier_cancellation(&self) -> CancellationToken {
        self.cancel.child_token()
    }

    /// Returns a cloned non-secret identity only for enabled debug capture.
    pub(crate) fn trace_identity(&self) -> crate::web::trace::TraceIdentity {
        crate::web::trace::TraceIdentity::from_profile(self.trace_session_id, &self.profile)
    }

    /// Records one typed lifecycle event without exposing session credentials.
    pub(super) fn trace_lifecycle(
        &self,
        event: crate::web::trace::TraceLifecycleEvent,
        stream_id: Option<u32>,
        reason: Option<&'static str>,
    ) {
        if let Some(manager) = self.manager.upgrade() {
            manager.trace().record_profile_lifecycle(
                self.client_ip,
                Some(self.trace_session_id),
                &self.profile,
                event,
                stream_id,
                reason,
            );
        }
    }

    /// Returns the immutable limits frozen when this carrier chain was created.
    pub(crate) fn limits(&self) -> &WebLimitsConfig {
        &self.limits
    }

    /// Returns the immutable timeouts frozen when this carrier chain was created.
    pub(crate) fn timeouts(&self) -> &WebTimeoutsConfig {
        &self.timeouts
    }
}
