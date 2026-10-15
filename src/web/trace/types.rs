use std::net::IpAddr;

/// WEB HTTP route classification retained by the debug trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceRoute {
    /// Routing has not completed yet.
    Unknown,
    /// Ordinary static or upstream fallback traffic.
    Decoy,
    /// Authenticated bridge page issuance.
    Bridge,
    /// Bootstrap-to-session exchange.
    Session,
    /// Carrier uplink exchange.
    Uplink,
    /// Carrier downlink exchange.
    Downlink,
    /// WebSocket upgrade handshake.
    Websocket,
    /// Authenticated generated-bridge diagnostic report.
    Diagnostic,
}

impl TraceRoute {
    /// Returns the stable status-page label.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Decoy => "decoy",
            Self::Bridge => "bridge",
            Self::Session => "session",
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
            Self::Websocket => "websocket",
            Self::Diagnostic => "diagnostic",
        }
    }
}

/// Direction of captured HTTP body or carrier frame data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceDirection {
    /// Client-to-server data.
    Request,
    /// Server-to-client data.
    Response,
}

impl TraceDirection {
    /// Returns the stable status-page label.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// Terminal observation state of one HTTP body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceBodyState {
    /// The body completed normally.
    Complete,
    /// Body polling returned an error.
    Error,
    /// The body was dropped before a terminal poll.
    Aborted,
}

impl TraceBodyState {
    /// Returns the stable status-page label.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Error => "error",
            Self::Aborted => "aborted",
        }
    }
}

/// One sanitized HTTP header.
#[derive(Debug)]
pub(crate) struct TraceHeader {
    /// Lowercase header name.
    pub(crate) name: String,
    /// Allowlisted value, or `None` when only the name may be retained.
    pub(crate) value: Option<String>,
}

/// One bounded HTTP body observation.
#[derive(Debug)]
pub(crate) struct TraceBodySnapshot {
    /// Total bytes observed on the wire-facing Hyper body.
    pub(crate) observed_bytes: u64,
    /// Retained prefix or full bounded body bytes.
    pub(crate) captured: Vec<u8>,
    /// Indicates that bytes were omitted by policy or capacity.
    pub(crate) truncated: bool,
    /// Terminal body state.
    pub(crate) state: TraceBodyState,
}

/// One parsed carrier frame without payload retention.
#[derive(Debug)]
pub(crate) struct TraceFrame {
    /// HTTP body direction containing the frame.
    pub(crate) direction: TraceDirection,
    /// Stable protocol frame type, when the header parsed.
    pub(crate) frame_type: Option<&'static str>,
    /// Logical stream or lane identifier.
    pub(crate) stream_id: Option<u32>,
    /// Frame payload length.
    pub(crate) payload_len: Option<usize>,
    /// Decoded non-zero WINDOW delta.
    pub(crate) window_delta: Option<u32>,
    /// Closed parse or shape error category.
    pub(crate) parse_error: Option<&'static str>,
}

/// Request lifecycle timing points measured from service entry.
#[derive(Debug, Default)]
pub(crate) struct TraceTimings {
    /// Request body terminal poll time.
    pub(crate) request_body_us: Option<u64>,
    /// Handler response-ready time.
    pub(crate) response_ready_us: Option<u64>,
    /// Response body terminal poll or drop time.
    pub(crate) response_body_us: Option<u64>,
}

/// Stable non-secret WEB trace identity.
#[derive(Clone, Debug, Default)]
pub(crate) struct TraceIdentity {
    /// Process-unique monotonic WEB session identifier.
    pub(crate) session_id: Option<u64>,
    /// Exact access user name.
    pub(crate) user: Option<String>,
    /// Domain-separated client-secret fingerprint.
    pub(crate) key_fingerprint: Option<String>,
}

impl TraceIdentity {
    /// Builds a non-secret identity from one validated runtime profile.
    pub(crate) fn from_profile(
        session_id: u64,
        profile: &crate::config::WebRuntimeProfile,
    ) -> Self {
        Self::from_optional_profile(Some(session_id), profile)
    }

    /// Builds a profile identity when admission failed before session allocation.
    pub(crate) fn from_optional_profile(
        session_id: Option<u64>,
        profile: &crate::config::WebRuntimeProfile,
    ) -> Self {
        Self {
            session_id,
            user: Some(profile.shared.user.clone()),
            key_fingerprint: Some(profile.shared.key_fingerprint.clone()),
        }
    }
}

/// Complete request-to-response WEB HTTP trace.
#[derive(Debug)]
pub(crate) struct TraceHttpRecord {
    /// HTTP method.
    pub(crate) method: String,
    /// URI path without query material.
    pub(crate) path: String,
    /// Final route classification.
    pub(crate) route: TraceRoute,
    /// Sanitized request headers.
    pub(crate) request_headers: Vec<TraceHeader>,
    /// Sanitized response headers.
    pub(crate) response_headers: Vec<TraceHeader>,
    /// Request body observation when enabled by policy.
    pub(crate) request_body: Option<TraceBodySnapshot>,
    /// Response status when a response head was produced.
    pub(crate) status: Option<u16>,
    /// Response body observation when enabled by policy.
    pub(crate) response_body: Option<TraceBodySnapshot>,
    /// Parsed carrier frame metadata.
    pub(crate) frames: Vec<TraceFrame>,
    /// Monotonic request timing points.
    pub(crate) timings: Option<TraceTimings>,
}

/// Stable non-secret metadata retained across one WebSocket connection.
#[derive(Clone, Debug)]
pub(crate) struct TraceWebSocketContext {
    /// Process-unique connection identifier.
    pub(crate) connection_id: u64,
    /// Direct listener peer address.
    pub(crate) peer_ip: IpAddr,
    /// Trusted effective client address.
    pub(crate) effective_ip: IpAddr,
    /// Bounded user-agent copied only while debugging is enabled.
    pub(crate) user_agent: Option<String>,
    /// Session and profile identity without credentials.
    pub(crate) identity: TraceIdentity,
    /// Logical lane identifier for websocket-lanes.
    pub(crate) lane_id: Option<u32>,
}

/// One bounded ordered WebSocket message observation.
#[derive(Debug)]
pub(crate) struct TraceWebSocketRecord {
    /// Wire direction of this message.
    pub(crate) direction: TraceDirection,
    /// Closed RFC 6455 message category.
    pub(crate) message_type: &'static str,
    /// Total payload bytes observed.
    pub(crate) payload_bytes: usize,
    /// Policy-bounded message body observation.
    pub(crate) body: Option<TraceBodySnapshot>,
    /// Parsed carrier frames for binary messages.
    pub(crate) frames: Vec<TraceFrame>,
    /// Message processing or write duration when timing capture is enabled.
    pub(crate) duration_us: Option<u64>,
    /// Process-unique owning WebSocket connection.
    pub(crate) connection_id: u64,
    /// Logical lane identifier for websocket-lanes.
    pub(crate) lane_id: Option<u32>,
}

/// WEB lifecycle event category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceLifecycleEvent {
    /// A bridge bootstrap was issued.
    BridgeIssued,
    /// A generated bridge reported one fixed diagnostic event.
    BridgeDiagnostic,
    /// Bootstrap or bridge admission was rejected.
    BootstrapRejected,
    /// A session request was classified for legacy or automatic negotiation.
    CarrierClassified,
    /// One carrier candidate was selected for an attempt.
    CarrierSelected,
    /// A provisional carrier was reported failed by the bridge.
    CarrierFailed,
    /// An uncommitted carrier session was atomically superseded.
    CarrierSuperseded,
    /// Bidirectional carrier evidence made replacement unsafe.
    CarrierCommitted,
    /// A committed carrier survived its configured health interval.
    CarrierHealthy,
    /// A new session was created.
    SessionCreated,
    /// An idempotent session creation was replayed.
    SessionReplayed,
    /// Session creation was rejected.
    SessionRejected,
    /// A session closed.
    SessionClosed,
    /// A logical stream was admitted.
    StreamAdmitted,
    /// A logical stream was rejected.
    StreamRejected,
    /// A logical stream delivered its first inner byte.
    StreamFirstByte,
    /// An admitted logical stream released its relay and tuple ownership.
    StreamClosed,
    /// The inner MTProxy handshake succeeded.
    HandshakeSucceeded,
    /// The inner MTProxy handshake timed out.
    HandshakeTimeout,
    /// The inner MTProxy handshake failed on I/O.
    HandshakeIo,
    /// The inner MTProxy handshake was rejected.
    HandshakeRejected,
    /// Authenticated relay started.
    RelayStarted,
    /// Authenticated relay ended.
    RelayEnded,
}

impl TraceLifecycleEvent {
    /// Returns the stable status-page label.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BridgeIssued => "bridge_issued",
            Self::BridgeDiagnostic => "bridge_diagnostic",
            Self::BootstrapRejected => "bootstrap_rejected",
            Self::CarrierClassified => "carrier_classified",
            Self::CarrierSelected => "carrier_selected",
            Self::CarrierFailed => "carrier_failed",
            Self::CarrierSuperseded => "carrier_superseded",
            Self::CarrierCommitted => "carrier_committed",
            Self::CarrierHealthy => "carrier_healthy",
            Self::SessionCreated => "session_created",
            Self::SessionReplayed => "session_replayed",
            Self::SessionRejected => "session_rejected",
            Self::SessionClosed => "session_closed",
            Self::StreamAdmitted => "stream_admitted",
            Self::StreamRejected => "stream_rejected",
            Self::StreamFirstByte => "stream_first_byte",
            Self::StreamClosed => "stream_closed",
            Self::HandshakeSucceeded => "handshake_succeeded",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::HandshakeIo => "handshake_io",
            Self::HandshakeRejected => "handshake_rejected",
            Self::RelayStarted => "relay_started",
            Self::RelayEnded => "relay_ended",
        }
    }
}

/// Non-sensitive carrier-negotiation fields attached to lifecycle records.
#[derive(Debug)]
pub(crate) struct TraceCarrierDetail {
    /// Stable client classification; never a raw User-Agent.
    pub(crate) client_class: &'static str,
    /// Candidate associated with the lifecycle transition.
    pub(crate) carrier: crate::config::WebCarrier,
    /// One-based candidate attempt.
    pub(crate) attempt: u8,
    /// Weighted learning scores indexed by the canonical carrier order.
    pub(crate) scores: [i16; 4],
}

/// Optional non-secret context for one lifecycle transition.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TraceLifecycleContext {
    /// Monotonic peer inactivity preceding the transition.
    pub(crate) peer_gap_ms: Option<u64>,
    /// Previous logical session replaced by this transition.
    pub(crate) predecessor_session_id: Option<u64>,
}

/// One typed WEB lifecycle observation.
#[derive(Debug)]
pub(crate) struct TraceLifecycleRecord {
    /// Closed event category.
    pub(crate) event: TraceLifecycleEvent,
    /// Logical stream identifier when applicable.
    pub(crate) stream_id: Option<u32>,
    /// Terminal outcome or rejection reason.
    pub(crate) reason: Option<&'static str>,
    /// Carrier negotiation detail when this is a carrier lifecycle event.
    pub(crate) carrier: Option<TraceCarrierDetail>,
    /// Optional monotonic peer inactivity preceding the transition.
    pub(crate) peer_gap_ms: Option<u64>,
    /// Optional logical predecessor for a recovered session incarnation.
    pub(crate) predecessor_session_id: Option<u64>,
}

/// Trace record payload variant.
#[derive(Debug)]
pub(crate) enum TraceRecordKind {
    /// HTTP request-to-response exchange.
    Http(TraceHttpRecord),
    /// One ordered WebSocket message.
    Websocket(TraceWebSocketRecord),
    /// Session or stream lifecycle event.
    Lifecycle(TraceLifecycleRecord),
}

/// Common stored WEB trace record.
#[derive(Debug)]
pub(crate) struct TraceRecord {
    /// Process-unique monotonic record sequence.
    pub(crate) seq: u64,
    /// Event completion time in Unix epoch milliseconds.
    pub(crate) epoch_millis: u64,
    /// Direct TCP peer accepted by the WEB listener.
    pub(crate) peer_ip: Option<IpAddr>,
    /// Trusted effective client identity.
    pub(crate) effective_ip: Option<IpAddr>,
    /// Bounded user-agent value retained for filtering.
    pub(crate) user_agent: Option<String>,
    /// Non-secret WEB identity.
    pub(crate) identity: TraceIdentity,
    /// Typed record payload.
    pub(crate) kind: TraceRecordKind,
}
