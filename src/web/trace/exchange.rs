use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use zeroize::Zeroizing;

use super::sanitize::{
    bounded_text, capture_limit, frame_error_name, frame_type_name, request_dynamic_bytes,
    response_dynamic_bytes, sanitized_headers, scrub_body, sensitive_values,
};
use super::store::{WebTraceStore, epoch_millis};
use super::types::{
    TraceBodySnapshot, TraceBodyState, TraceDirection, TraceFrame, TraceHeader, TraceHttpRecord,
    TraceIdentity, TraceRecord, TraceRecordKind, TraceRoute, TraceTimings,
};
use crate::config::{WebDebugBodyCapture, WebDebugConfig, WebLimitsConfig, WebRuntimeProfile};
use crate::web::frame::{self, FrameType};

const USER_AGENT_MAX_BYTES: usize = 512;

#[derive(Default)]
struct BodyCapture {
    observed_bytes: u64,
    captured: Vec<u8>,
    truncated: bool,
    state: Option<TraceBodyState>,
}

struct ExchangeState {
    phase: ExchangePhase,
    reserved: usize,
    method: String,
    path: String,
    route: TraceRoute,
    peer_ip: IpAddr,
    effective_ip: Option<IpAddr>,
    user_agent: Option<String>,
    identity: TraceIdentity,
    request_headers: Vec<TraceHeader>,
    response_headers: Vec<TraceHeader>,
    request_body: BodyCapture,
    response_body: BodyCapture,
    status: Option<u16>,
    frames: Vec<TraceFrame>,
    timings: TraceTimings,
    redactions: Vec<Zeroizing<Vec<u8>>>,
    body_capture_blocked: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExchangePhase {
    Open,
    Committed,
}

/// One in-flight request-to-response capture with process-wide byte leases.
pub(crate) struct HttpTraceExchange {
    store: Arc<WebTraceStore>,
    epoch: u64,
    policy: Arc<WebDebugConfig>,
    started: Instant,
    started_epoch_millis: u64,
    state: Mutex<ExchangeState>,
}

impl HttpTraceExchange {
    /// Creates one enabled exchange after the store reserved its base record lease.
    pub(super) fn new<B>(
        store: Arc<WebTraceStore>,
        epoch: u64,
        policy: Arc<WebDebugConfig>,
        request: &hyper::Request<B>,
        peer_ip: IpAddr,
        base_reservation: usize,
    ) -> Arc<Self> {
        let started = Instant::now();
        let started_epoch_millis = epoch_millis();
        let dynamic = request_dynamic_bytes(request, &policy);
        let dynamic_reserved = store.try_reserve(dynamic);
        let (mut method, mut path, mut user_agent, request_headers, redactions) =
            if dynamic_reserved {
                (
                    request.method().as_str().to_string(),
                    request.uri().path().to_string(),
                    request
                        .headers()
                        .get(hyper::header::USER_AGENT)
                        .map(|value| bounded_text(value.as_bytes(), USER_AGENT_MAX_BYTES)),
                    if policy.capture_headers {
                        sanitized_headers(request.headers(), store.wildcard_redaction)
                    } else {
                        Vec::new()
                    },
                    sensitive_values(request.headers(), request.uri().query()),
                )
            } else {
                (
                    bounded_text(request.method().as_str().as_bytes(), 32),
                    bounded_text(request.uri().path().as_bytes(), 512),
                    None,
                    Vec::new(),
                    Vec::new(),
                )
            };
        if store.wildcard_redaction {
            super::wildcard::scrub_text(
                &mut method,
                !dynamic_reserved && request.method().as_str().len() > 32,
            );
            super::wildcard::scrub_text(
                &mut path,
                !dynamic_reserved && request.uri().path().len() > 512,
            );
            if let Some(user_agent) = &mut user_agent {
                let truncated = request
                    .headers()
                    .get(hyper::header::USER_AGENT)
                    .is_some_and(|value| value.len() > USER_AGENT_MAX_BYTES);
                super::wildcard::scrub_text(user_agent, truncated);
            }
        }
        Arc::new(Self {
            store,
            epoch,
            policy,
            started,
            started_epoch_millis,
            state: Mutex::new(ExchangeState {
                phase: ExchangePhase::Open,
                reserved: base_reservation + if dynamic_reserved { dynamic } else { 0 },
                method,
                path,
                route: TraceRoute::Unknown,
                peer_ip,
                effective_ip: None,
                user_agent,
                identity: TraceIdentity::default(),
                request_headers,
                response_headers: Vec::new(),
                request_body: BodyCapture::default(),
                response_body: BodyCapture::default(),
                status: None,
                frames: Vec::new(),
                timings: TraceTimings::default(),
                redactions,
                body_capture_blocked: !dynamic_reserved,
            }),
        })
    }

    /// Sets the final request route before body polling or decoy forwarding.
    pub(crate) fn set_route(&self, route: TraceRoute) {
        let mut state = self.state.lock();
        if state.phase == ExchangePhase::Open {
            state.route = route;
        }
    }

    /// Sets the trusted effective client address after proxy-header validation.
    pub(crate) fn set_effective_ip(&self, client_ip: IpAddr) {
        let mut state = self.state.lock();
        if state.phase == ExchangePhase::Open {
            state.effective_ip = Some(client_ip);
        }
    }

    /// Binds non-secret profile and process session identity.
    pub(crate) fn bind_profile(&self, profile: &WebRuntimeProfile, session_id: u64) {
        let dynamic = profile
            .shared
            .user
            .len()
            .saturating_add(profile.shared.key_fingerprint.len());
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open {
            return;
        }
        state.identity.session_id = Some(session_id);
        if self.reserve_locked(&mut state, dynamic) {
            state.identity.user = Some(profile.shared.user.clone());
            state.identity.key_fingerprint = Some(profile.shared.key_fingerprint.clone());
        }
    }

    /// Binds an already resolved non-secret session identity.
    pub(crate) fn bind_identity(&self, identity: TraceIdentity) {
        let dynamic = identity
            .user
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(identity.key_fingerprint.as_ref().map_or(0, String::len));
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open {
            return;
        }
        state.identity.session_id = identity.session_id;
        if self.reserve_locked(&mut state, dynamic) {
            state.identity.user = identity.user;
            state.identity.key_fingerprint = identity.key_fingerprint;
        }
    }

    /// Registers an ephemeral credential for body scrubbing before commit.
    pub(crate) fn register_redaction(&self, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open {
            return;
        }
        if !self.reserve_locked(&mut state, value.len()) {
            Self::block_body_capture_locked(&mut state);
            return;
        }
        state.redactions.push(Zeroizing::new(value.to_vec()));
    }

    /// Captures response status and sanitized headers at handler completion.
    pub(crate) fn response_ready<B>(&self, response: &hyper::Response<B>) {
        let dynamic = response_dynamic_bytes(response, &self.policy);
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open {
            return;
        }
        let reserved = self.reserve_locked(&mut state, dynamic);
        state.status = Some(response.status().as_u16());
        if self.policy.capture_headers && reserved {
            state.response_headers =
                sanitized_headers(response.headers(), self.store.wildcard_redaction);
        }
        if reserved {
            state
                .redactions
                .extend(sensitive_values(response.headers(), None));
        } else if dynamic != 0 {
            state.body_capture_blocked = true;
            state.request_body.captured.clear();
            state.response_body.captured.clear();
            state.request_body.truncated = true;
            state.response_body.truncated = true;
        }
        if self.policy.capture_timings {
            state.timings.response_ready_us = Some(self.elapsed_us());
        }
    }

    /// Appends one body data frame without changing the proxied bytes.
    pub(crate) fn body_data(&self, direction: TraceDirection, data: &[u8]) {
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open {
            return;
        }
        let route = state.route;
        let body_capture_blocked = state.body_capture_blocked;
        {
            let body = selected_body(&mut state, direction);
            body.observed_bytes = body
                .observed_bytes
                .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        }
        if data.is_empty() {
            return;
        }
        if body_capture_blocked {
            let body = selected_body(&mut state, direction);
            body.truncated |= !data.is_empty();
            return;
        }
        let Some(limit) = capture_limit(&self.policy, route, self.store.max_carrier_body_bytes())
        else {
            return;
        };
        let body = selected_body(&mut state, direction);
        if body.captured.len() >= limit {
            if !data.is_empty() && !body.truncated {
                self.store.record_truncation();
            }
            body.truncated |= !data.is_empty();
            return;
        }
        let needs_reservation = body.captured.capacity() == 0;
        if needs_reservation {
            if !self.reserve_locked(&mut state, limit) {
                let body = selected_body(&mut state, direction);
                body.truncated = true;
                return;
            }
            let body = selected_body(&mut state, direction);
            body.captured = Vec::with_capacity(limit);
        }
        let body = selected_body(&mut state, direction);
        let take = data.len().min(limit - body.captured.len());
        body.captured.extend_from_slice(&data[..take]);
        if take < data.len() {
            if !body.truncated {
                self.store.record_truncation();
            }
            body.truncated = true;
        }
    }

    /// Marks one request or response body terminal state.
    pub(crate) fn body_finished(&self, direction: TraceDirection, terminal: TraceBodyState) {
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open {
            return;
        }
        let body = match direction {
            TraceDirection::Request => &mut state.request_body,
            TraceDirection::Response => &mut state.response_body,
        };
        if body.state.is_none() {
            body.state = Some(terminal);
        }
        if self.policy.capture_timings {
            match direction {
                TraceDirection::Request => state.timings.request_body_us = Some(self.elapsed_us()),
                TraceDirection::Response => {
                    state.timings.response_body_us = Some(self.elapsed_us())
                }
            }
        }
        drop(state);
        if direction == TraceDirection::Response {
            self.commit();
        }
    }

    /// Attaches parsed carrier frame metadata from one complete bounded body.
    pub(crate) fn record_frames(
        &self,
        direction: TraceDirection,
        body: &[u8],
        limits: &WebLimitsConfig,
    ) {
        if !self.policy.capture_frames {
            return;
        }
        let estimated_frames = body
            .len()
            .div_ceil(frame::HEADER_BYTES)
            .clamp(1, limits.max_frames_per_body);
        let reservation = estimated_frames.saturating_mul(std::mem::size_of::<TraceFrame>());
        let mut state = self.state.lock();
        if state.phase != ExchangePhase::Open || !self.reserve_locked(&mut state, reservation) {
            return;
        }
        let frames = match frame::parse_all(body, limits) {
            Ok(frames) => frames
                .into_iter()
                .map(|frame| TraceFrame {
                    direction,
                    frame_type: Some(frame_type_name(frame.frame_type)),
                    stream_id: Some(frame.stream_id),
                    payload_len: Some(frame.payload.len()),
                    window_delta: (frame.frame_type == FrameType::Window)
                        .then(|| frame::window_amount(frame.payload).ok())
                        .flatten(),
                    parse_error: None,
                })
                .collect::<Vec<_>>(),
            Err(error) => vec![TraceFrame {
                direction,
                frame_type: None,
                stream_id: None,
                payload_len: None,
                window_delta: None,
                parse_error: Some(frame_error_name(error)),
            }],
        };
        state.frames.extend(frames);
    }

    /// Commits once after response body consumption or drop.
    pub(crate) fn commit(&self) {
        let (record, reserved) = {
            let mut state = self.state.lock();
            if state.phase != ExchangePhase::Open {
                return;
            }
            state.phase = ExchangePhase::Committed;
            let reserved = state.reserved;
            (self.build_record_locked(&mut state), reserved)
        };
        if !self.store.try_commit(record, reserved, self.epoch) {
            self.store.release(reserved);
        }
    }

    fn reserve_locked(&self, state: &mut ExchangeState, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        if self.store.try_reserve(bytes) {
            state.reserved = state.reserved.saturating_add(bytes);
            true
        } else {
            false
        }
    }

    fn block_body_capture_locked(state: &mut ExchangeState) {
        state.body_capture_blocked = true;
        state.request_body.captured.clear();
        state.response_body.captured.clear();
        state.request_body.truncated = true;
        state.response_body.truncated = true;
    }

    fn build_record_locked(&self, state: &mut ExchangeState) -> TraceRecord {
        let redactions = std::mem::take(&mut state.redactions);
        scrub_body(&mut state.request_body.captured, &redactions);
        scrub_body(&mut state.response_body.captured, &redactions);
        if self.store.wildcard_redaction {
            super::wildcard::scrub_bytes(
                &mut state.request_body.captured,
                state.request_body.truncated
                    || state.request_body.state != Some(TraceBodyState::Complete),
            );
            super::wildcard::scrub_bytes(
                &mut state.response_body.captured,
                state.response_body.truncated
                    || state.response_body.state != Some(TraceBodyState::Complete),
            );
        }
        let request_body = body_snapshot(&self.policy, &mut state.request_body);
        let response_body = body_snapshot(&self.policy, &mut state.response_body);
        TraceRecord {
            seq: self.store.next_record_seq(),
            epoch_millis: self.started_epoch_millis,
            peer_ip: Some(state.peer_ip),
            effective_ip: state.effective_ip,
            user_agent: state.user_agent.take(),
            identity: std::mem::take(&mut state.identity),
            kind: TraceRecordKind::Http(TraceHttpRecord {
                method: std::mem::take(&mut state.method),
                path: std::mem::take(&mut state.path),
                route: state.route,
                request_headers: std::mem::take(&mut state.request_headers),
                response_headers: std::mem::take(&mut state.response_headers),
                request_body,
                status: state.status,
                response_body,
                frames: std::mem::take(&mut state.frames),
                timings: self
                    .policy
                    .capture_timings
                    .then(|| std::mem::take(&mut state.timings)),
            }),
        }
    }

    fn elapsed_us(&self) -> u64 {
        self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }
}

impl Drop for HttpTraceExchange {
    fn drop(&mut self) {
        if self.state.get_mut().phase == ExchangePhase::Open {
            self.body_finished(TraceDirection::Request, TraceBodyState::Aborted);
            self.body_finished(TraceDirection::Response, TraceBodyState::Aborted);
        }
    }
}

fn body_snapshot(policy: &WebDebugConfig, body: &mut BodyCapture) -> Option<TraceBodySnapshot> {
    (policy.body_capture != WebDebugBodyCapture::Off).then(|| TraceBodySnapshot {
        observed_bytes: body.observed_bytes,
        captured: std::mem::take(&mut body.captured),
        truncated: body.truncated,
        state: body.state.unwrap_or(TraceBodyState::Aborted),
    })
}

fn selected_body(state: &mut ExchangeState, direction: TraceDirection) -> &mut BodyCapture {
    match direction {
        TraceDirection::Request => &mut state.request_body,
        TraceDirection::Response => &mut state.response_body,
    }
}

#[cfg(test)]
mod tests;
