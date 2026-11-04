use std::time::Instant;

use serde::Serialize;

use super::{CarrierHealthPublicationState, SessionNegotiationPhase, WebSession};
use crate::config::WebCarrier;

/// One bounded point-in-time session snapshot without bearer identity.
#[derive(Clone, Serialize)]
pub(crate) struct WebSessionStatus {
    /// Stable trace identifier within this process.
    pub(crate) trace_session_id: u64,
    /// Forwarded client address frozen at session creation.
    pub(crate) client_ip: std::net::IpAddr,
    /// Canonical WEB virtual host.
    pub(crate) host: String,
    /// Configured non-secret user label.
    pub(crate) user: String,
    /// Non-secret configured key fingerprint.
    pub(crate) key_id: String,
    /// Current carrier incarnation.
    pub(crate) carrier: WebCarrier,
    /// One-based carrier attempt.
    pub(crate) attempt: u8,
    /// Stable client classification token.
    pub(crate) client_class: &'static str,
    /// Whether server-side carrier negotiation owns this chain.
    pub(crate) automatic: bool,
    /// Current session lifecycle token.
    pub(crate) state: &'static str,
    /// Current manager-confirmed health publication phase.
    pub(crate) health_publication: &'static str,
    /// Live logical streams.
    pub(crate) streams: usize,
    /// Stream relay tasks that have not exited.
    pub(crate) tasks: usize,
    /// Carrier lanes currently retained.
    pub(crate) lanes: usize,
    /// Lane OPEN polls currently waiting.
    pub(crate) lane_open_waits: usize,
    /// WebSocket lane slots reserved before ownership transfer.
    pub(crate) websocket_lane_reservations: usize,
    /// Whether the multiplexed WebSocket carrier is active.
    pub(crate) websocket_active: bool,
    /// Queued and response-resident bytes charged to this session.
    pub(crate) pending_bytes: usize,
    /// Queued and response-resident items charged to this session.
    pub(crate) pending_items: usize,
    /// Control bytes included in the pending total.
    pub(crate) control_bytes: usize,
    /// Control items included in the pending total.
    pub(crate) control_items: usize,
    /// Monotonic age since session creation.
    pub(crate) age_ms: u64,
    /// Monotonic age since the latest peer or carrier progress.
    pub(crate) idle_ms: u64,
    /// Monotonic age since the latest validated peer operation.
    pub(crate) peer_idle_ms: u64,
    /// Session-frozen authenticated peer inactivity allowance.
    pub(crate) reconnect_grace_ms: u64,
    /// Remaining time before peer inactivity makes the session eligible for cleanup.
    pub(crate) peer_deadline_remaining_ms: u64,
    /// Remaining automatic negotiation deadline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) negotiation_remaining_ms: Option<u64>,
}

impl WebSession {
    /// Captures one short-lock session snapshot or reports lock contention.
    pub(crate) fn try_status(&self, now: Instant) -> Option<WebSessionStatus> {
        let state = self.state.try_lock()?;
        let resident = self.resident.snapshot();
        let state_name = if state.closed {
            "closed"
        } else if state.close_requested.is_some() {
            "closing"
        } else if self.carrier_health_publication_state()
            == CarrierHealthPublicationState::Published
        {
            "healthy"
        } else {
            match state.negotiation_phase {
                SessionNegotiationPhase::Uncommitted => "provisional",
                SessionNegotiationPhase::Replacing => "replacing",
                SessionNegotiationPhase::Committed => "committed",
                SessionNegotiationPhase::Superseded => "superseded",
            }
        };
        Some(WebSessionStatus {
            trace_session_id: self.trace_session_id,
            client_ip: self.client_ip,
            host: self.profile.host.clone(),
            user: self.profile.shared.user.clone(),
            key_id: self.profile.shared.key_fingerprint.clone(),
            carrier: self.selected_carrier,
            attempt: self.carrier_attempt,
            client_class: self.carrier_class.as_str(),
            automatic: self.automatic_carrier,
            state: state_name,
            health_publication: match self.carrier_health_publication_state() {
                CarrierHealthPublicationState::Awaiting => "awaiting",
                CarrierHealthPublicationState::Publishing => "publishing",
                CarrierHealthPublicationState::Published => "published",
                CarrierHealthPublicationState::Rejected => "rejected",
            },
            streams: state.streams.len(),
            tasks: self.tasks_live(),
            lanes: state.carrier_lanes.len(),
            lane_open_waits: state.lane_open_waits,
            websocket_lane_reservations: state.websocket_lane_reservations.len(),
            websocket_active: state.websocket_carrier_active,
            pending_bytes: state.pending_bytes.saturating_add(resident.bytes()),
            pending_items: state.pending_items.saturating_add(resident.items()),
            control_bytes: state
                .pending_control_bytes
                .saturating_add(resident.control_bytes),
            control_items: state
                .pending_control_items
                .saturating_add(resident.control_items),
            age_ms: millis(now.saturating_duration_since(self.created_at)),
            idle_ms: millis(state.activity.progress_idle(now)),
            peer_idle_ms: millis(state.activity.peer_idle(now)),
            reconnect_grace_ms: self.timeouts.reconnect_grace_secs.saturating_mul(1_000),
            peer_deadline_remaining_ms: self
                .timeouts
                .reconnect_grace_secs
                .saturating_mul(1_000)
                .saturating_sub(millis(state.activity.peer_idle(now))),
            negotiation_remaining_ms: self
                .carrier_deadline_at
                .map(|deadline| millis(deadline.saturating_duration_since(now))),
        })
    }

    /// Returns the forwarded client address frozen at session creation.
    pub(crate) fn client_ip(&self) -> std::net::IpAddr {
        self.client_ip
    }

    /// Returns the canonical profile host frozen into this session.
    pub(crate) fn profile_host(&self) -> &str {
        &self.profile.host
    }

    /// Returns the configured non-secret user label.
    pub(crate) fn profile_user(&self) -> &str {
        &self.profile.shared.user
    }

    /// Returns the configured non-secret key fingerprint.
    pub(crate) fn key_id(&self) -> &str {
        &self.profile.shared.key_fingerprint
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
