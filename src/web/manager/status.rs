use std::net::IpAddr;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;

use super::WebProcessRuntime;
use crate::config::{
    WebCarrier, WebCarrierNegotiationAggressiveness, WebDebugConfig, WebLimitsConfig,
};
use crate::web::session::WebSessionStatus;

const SESSION_REF_VERSION: &str = "ws1";
const MAX_SESSION_SCAN: usize = 1000;

/// Current usage of one process-owned semaphore.
#[derive(Clone, Serialize)]
struct PermitStatus {
    used: usize,
    available: usize,
    capacity: usize,
    closed: bool,
}

/// Short-lock manager registry counts.
#[derive(Clone, Serialize)]
struct ManagerStatus {
    issuance_enabled: bool,
    issuance_generation: u64,
    shutdown: bool,
    bootstraps: usize,
    sessions: usize,
    closed_tokens: usize,
    closed_sessions: usize,
    client_ips: usize,
    profiles: usize,
}

/// Logical-stream admission counters.
#[derive(Clone, Serialize)]
struct StreamStatus {
    live: usize,
    profiles: usize,
    closed: bool,
}

/// Shared queue and WebSocket byte-budget counters.
#[derive(Clone, Serialize)]
struct BudgetStatus {
    queue_bytes: usize,
    queue_items: usize,
    control_bytes: usize,
    control_items: usize,
    websocket_bytes: usize,
    high_water_bytes: usize,
    owners: usize,
    closed: bool,
}

/// Process WebSocket registry counters.
#[derive(Clone, Serialize)]
struct WebSocketStatus {
    entries: usize,
    claims: usize,
    evictions_in_flight: usize,
    closed: bool,
}

/// Process-local carrier-learning summary.
#[derive(Clone, Serialize)]
struct LearningStatus {
    enabled: bool,
    aggressiveness: WebCarrierNegotiationAggressiveness,
    epoch: Option<u64>,
    entries: usize,
    capacity: usize,
    lifetime_secs: u64,
    age_ms: u64,
}

/// Effective trace policy and bounded ring counters.
#[derive(Clone, Serialize)]
struct DebugStatus {
    policy: WebDebugConfig,
    policy_generation: u64,
    epoch: u64,
    records: usize,
    records_capacity: usize,
    used_bytes: usize,
    bytes_capacity: usize,
    contention_drops: u64,
    evictions: u64,
    byte_truncations: u64,
    earliest_seq: Option<u64>,
    latest_seq: Option<u64>,
}

/// One non-blocking multi-plane WEB runtime snapshot.
#[derive(Clone, Serialize)]
pub(crate) struct WebRuntimeStatus {
    runtime_instance: String,
    generation_id: u64,
    limits: WebLimitsConfig,
    manager: Option<ManagerStatus>,
    streams: Option<StreamStatus>,
    budget: Option<BudgetStatus>,
    websockets: Option<WebSocketStatus>,
    learning: Option<LearningStatus>,
    debug: Option<DebugStatus>,
    permits: Vec<(&'static str, PermitStatus)>,
    auxiliary_tasks: usize,
    session_incarnations_created: u64,
    session_incarnations_closed: u64,
    streams_opened: u64,
    streams_rejected: u64,
    bytes_up: u64,
    bytes_down: u64,
    limit_hits: u64,
    partial: Vec<&'static str>,
}

/// Strict bounded filters for session enumeration and bulk close.
#[derive(Clone, Default)]
pub(crate) struct SessionFilter {
    /// Exact process-local logical session identifier.
    pub(crate) trace_session_id: Option<u64>,
    /// Exact forwarded client address.
    pub(crate) client_ip: Option<IpAddr>,
    /// Exact canonical virtual host.
    pub(crate) host: Option<String>,
    /// Exact configured user label.
    pub(crate) user: Option<String>,
    /// Exact non-secret User-Agent identifier.
    pub(crate) user_agent_id: Option<[u8; 16]>,
    /// Exact non-secret profile-key fingerprint.
    pub(crate) key_id: Option<String>,
    /// Exact current carrier.
    pub(crate) carrier: Option<WebCarrier>,
    /// Exact point-in-time lifecycle token.
    pub(crate) state: Option<String>,
}

impl SessionFilter {
    /// Returns whether the selector would match every live session.
    pub(crate) fn is_empty(&self) -> bool {
        self.trace_session_id.is_none()
            && self.client_ip.is_none()
            && self.host.is_none()
            && self.user.is_none()
            && self.user_agent_id.is_none()
            && self.key_id.is_none()
            && self.carrier.is_none()
            && self.state.is_none()
    }
}

/// Validated bounded list request.
pub(crate) struct SessionListRequest {
    /// Maximum returned rows.
    pub(crate) limit: usize,
    /// Exclusive ordered logical-session cursor.
    pub(crate) cursor: Option<u64>,
    /// Exact bounded filters.
    pub(crate) filter: SessionFilter,
}

/// One API-safe session row with optional User-Agent metadata.
#[derive(Clone, Serialize)]
pub(crate) struct SessionRow {
    /// Opaque process-fenced logical-session reference.
    pub(crate) session_ref: String,
    /// Bounded sanitized User-Agent display value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent_id: Option<String>,
    #[serde(flatten)]
    status: WebSessionStatus,
}

/// Bounded session page and continuation metadata.
#[derive(Clone, Serialize)]
pub(crate) struct SessionPage {
    /// Ordered live-session rows captured without blocking.
    pub(crate) sessions: Vec<SessionRow>,
    next_cursor: Option<String>,
    scanned: usize,
    scan_truncated: bool,
    partial_sessions: usize,
    partial: Vec<&'static str>,
}

/// Exact detail lookup outcome.
pub(crate) enum SessionDetail {
    /// One exact live-session snapshot.
    Active(Box<SessionRow>),
    /// One bounded retained closed-session tombstone.
    Gone { attempt: u8 },
    /// A required short lock was contended.
    Busy,
    /// Neither a live session nor a retained tombstone exists.
    NotFound,
}

struct Candidate {
    trace_session_id: u64,
    session: Arc<crate::web::session::WebSession>,
    user_agent: Option<Arc<str>>,
    user_agent_id: Option<[u8; 16]>,
}

impl WebProcessRuntime {
    /// Captures every independent plane without blocking on a contended lock.
    pub(crate) fn try_status(&self) -> WebRuntimeStatus {
        let generation_id = self.active_generation().id;
        let mut partial = Vec::new();
        let manager = self.state.try_lock().map(|state| ManagerStatus {
            issuance_enabled: state.issuance_enabled,
            issuance_generation: state.issuance_generation,
            shutdown: state.closed,
            bootstraps: state.bootstraps.len(),
            sessions: state.sessions.len(),
            closed_tokens: state.closed_tokens.len(),
            closed_sessions: state.closed_sessions.len(),
            client_ips: state.sessions_per_ip.len(),
            profiles: state.sessions_per_profile.len(),
        });
        if manager.is_none() {
            partial.push("manager");
        }
        let streams = self.stream_admission.try_lock().map(|state| StreamStatus {
            live: state.streams_live,
            profiles: state.streams_per_profile.len(),
            closed: state.closed,
        });
        if streams.is_none() {
            partial.push("streams");
        }
        let budget = self.data_budget.try_snapshot().map(|status| BudgetStatus {
            queue_bytes: status.queue_bytes,
            queue_items: status.queue_items,
            control_bytes: status.queue_control_bytes,
            control_items: status.queue_control_items,
            websocket_bytes: status.websocket_bytes,
            high_water_bytes: status.high_water_bytes,
            owners: status.owners,
            closed: status.closed,
        });
        if budget.is_none() {
            partial.push("budget");
        }
        let websockets = self.websockets.try_lock().map(|registry| {
            let status = registry.status();
            WebSocketStatus {
                entries: status.entries,
                claims: status.claims,
                evictions_in_flight: status.evictions_in_flight,
                closed: status.closed,
            }
        });
        if websockets.is_none() {
            partial.push("websockets");
        }
        let learning = self
            .try_carrier_learning_status()
            .map(|status| LearningStatus {
                enabled: status.enabled,
                aggressiveness: status.aggressiveness,
                epoch: status.epoch,
                entries: status.entries,
                capacity: status.capacity,
                lifetime_secs: status.lifetime_secs,
                age_ms: status.age_ms,
            });
        if learning.is_none() {
            partial.push("learning");
        }
        let debug = self.trace.try_status().map(|status| DebugStatus {
            policy: status.policy.as_ref().clone(),
            policy_generation: status.policy_generation,
            epoch: status.epoch,
            records: status.records,
            records_capacity: status.records_capacity,
            used_bytes: status.used_bytes,
            bytes_capacity: status.bytes_capacity,
            contention_drops: status.contention_drops,
            evictions: status.evictions,
            byte_truncations: status.byte_truncations,
            earliest_seq: status.earliest_seq,
            latest_seq: status.latest_seq,
        });
        if debug.is_none() {
            partial.push("debug");
        }
        let websocket_capacity = self
            .limits
            .max_http_connections
            .saturating_sub(self.limits.websocket_http_connection_reserve);
        let aggregates = self.telemetry.aggregates();
        WebRuntimeStatus {
            runtime_instance: self.runtime_instance().to_string(),
            generation_id,
            limits: self.limits.clone(),
            manager,
            streams,
            budget,
            websockets,
            learning,
            debug,
            permits: vec![
                (
                    "http_connections",
                    permits(&self.http_connections, self.limits.max_http_connections),
                ),
                (
                    "http_overload_connections",
                    permits(
                        &self.http_overload_connections,
                        self.limits.max_http_overload_connections,
                    ),
                ),
                (
                    "http_handlers",
                    permits(&self.http_handlers, self.limits.max_http_handlers),
                ),
                (
                    "lane_polls",
                    permits(&self.lane_polls, self.limits.max_http_handlers / 2),
                ),
                (
                    "lane_aux_polls",
                    permits(
                        &self.lane_aux_polls,
                        (self.limits.max_http_handlers / 4).max(1),
                    ),
                ),
                (
                    "body_readers",
                    permits(&self.body_readers, self.limits.max_body_readers),
                ),
                (
                    "body_bytes",
                    permits(&self.body_bytes, self.limits.max_body_bytes_global),
                ),
                (
                    "stream_handshakes",
                    permits(&self.stream_handshakes, self.limits.max_stream_handshakes),
                ),
                (
                    "websocket_connections",
                    permits(&self.websocket_connections, websocket_capacity),
                ),
            ],
            auxiliary_tasks: self.tasks.len(),
            session_incarnations_created: aggregates.sessions_created,
            session_incarnations_closed: aggregates.sessions_closed,
            streams_opened: aggregates.streams_opened,
            streams_rejected: aggregates.streams_rejected,
            bytes_up: aggregates.bytes_up,
            bytes_down: aggregates.bytes_down,
            limit_hits: aggregates.limit_hits,
            partial,
        }
    }

    /// Formats an opaque process-fenced session reference.
    pub(crate) fn session_ref(&self, trace_session_id: u64) -> String {
        format!(
            "{SESSION_REF_VERSION}.{}.{trace_session_id:016x}",
            self.runtime_instance()
        )
    }

    /// Parses an exact reference and distinguishes stale process instances.
    pub(crate) fn parse_session_ref(&self, value: &str) -> Result<u64, SessionRefError> {
        let mut parts = value.split('.');
        let version = parts.next();
        let instance = parts.next();
        let id = parts.next();
        if version != Some(SESSION_REF_VERSION) || parts.next().is_some() {
            return Err(SessionRefError::Invalid);
        }
        if !instance.is_some_and(|instance| {
            instance.len() == 32
                && instance
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(SessionRefError::Invalid);
        }
        let id = id
            .filter(|id| {
                id.len() == 16
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .and_then(|id| u64::from_str_radix(id, 16).ok())
            .filter(|id| *id != 0)
            .ok_or(SessionRefError::Invalid)?;
        if instance != Some(self.runtime_instance()) {
            return Err(SessionRefError::StaleInstance);
        }
        Ok(id)
    }

    /// Lists live sessions under an ordered bounded scan.
    pub(crate) fn list_sessions(&self, request: SessionListRequest) -> SessionPage {
        let Some(state) = self.state.try_lock() else {
            return SessionPage {
                sessions: Vec::new(),
                next_cursor: request.cursor.map(|id| self.session_ref(id)),
                scanned: 0,
                scan_truncated: false,
                partial_sessions: 0,
                partial: vec!["manager"],
            };
        };
        let mut candidates = Vec::with_capacity(request.limit);
        let mut scanned = 0usize;
        let mut last_scanned = request.cursor;
        for (&trace_session_id, index) in state
            .session_index
            .range((request.cursor.map_or(Unbounded, Excluded), Unbounded))
        {
            if scanned >= MAX_SESSION_SCAN || candidates.len() >= request.limit {
                break;
            }
            scanned += 1;
            last_scanned = Some(trace_session_id);
            let Some(session) = state.sessions.get(&index.session_hash).cloned() else {
                continue;
            };
            if !immutable_matches(&session, index, &request.filter) {
                continue;
            }
            candidates.push(Candidate {
                trace_session_id,
                session,
                user_agent: index.user_agent.clone(),
                user_agent_id: index.user_agent_id,
            });
        }
        drop(state);
        let mut rows = Vec::with_capacity(candidates.len());
        let mut partial_sessions = 0usize;
        let now = Instant::now();
        for candidate in candidates {
            let Some(status) = candidate.session.try_status(now) else {
                partial_sessions += 1;
                continue;
            };
            if request
                .filter
                .state
                .as_deref()
                .is_some_and(|expected| expected != status.state)
            {
                continue;
            }
            rows.push(self.row(candidate, status));
        }
        let scan_truncated = scanned >= MAX_SESSION_SCAN;
        SessionPage {
            sessions: rows,
            next_cursor: (scan_truncated || scanned >= request.limit)
                .then(|| last_scanned.map(|id| self.session_ref(id)))
                .flatten(),
            scanned,
            scan_truncated,
            partial_sessions,
            partial: Vec::new(),
        }
    }

    /// Resolves one active or recently closed logical session.
    pub(crate) fn session_detail(&self, trace_session_id: u64) -> SessionDetail {
        let Some(state) = self.state.try_lock() else {
            return SessionDetail::Busy;
        };
        if let Some(index) = state.session_index.get(&trace_session_id) {
            let Some(session) = state.sessions.get(&index.session_hash).cloned() else {
                return SessionDetail::Busy;
            };
            let candidate = Candidate {
                trace_session_id,
                session,
                user_agent: index.user_agent.clone(),
                user_agent_id: index.user_agent_id,
            };
            drop(state);
            return candidate
                .session
                .try_status(Instant::now())
                .map(|status| SessionDetail::Active(Box::new(self.row(candidate, status))))
                .unwrap_or(SessionDetail::Busy);
        }
        let closed = state
            .closed_sessions
            .get(&trace_session_id)
            .map(|closed| closed.attempt);
        closed.map_or(SessionDetail::NotFound, |attempt| SessionDetail::Gone {
            attempt,
        })
    }

    fn row(&self, candidate: Candidate, status: WebSessionStatus) -> SessionRow {
        SessionRow {
            session_ref: self.session_ref(candidate.trace_session_id),
            user_agent: candidate.user_agent.map(|value| value.to_string()),
            user_agent_id: candidate.user_agent_id.map(hex::encode),
            status,
        }
    }
}

// Opaque session references and immutable filter matching.
mod reference;
pub(crate) use reference::SessionRefError;
pub(super) use reference::immutable_matches;
use reference::permits;
