use std::net::IpAddr;
use std::sync::atomic::Ordering;

use crate::config::WebDebugBodyCapture;
use crate::web::frame::{self, FrameType};

use super::super::types::{
    TraceBodySnapshot, TraceBodyState, TraceDirection, TraceFrame, TraceIdentity, TraceRecord,
    TraceRecordKind, TraceWebSocketContext, TraceWebSocketRecord,
};
use super::{BASE_RECORD_RESERVATION, WebTraceStore, epoch_millis};

impl WebTraceStore {
    /// Builds connection metadata only while WebSocket debugging is enabled.
    pub(crate) fn websocket_context<B, F>(
        &self,
        request: &hyper::Request<B>,
        peer_ip: IpAddr,
        effective_ip: IpAddr,
        connection_id: u64,
        lane_id: Option<u32>,
        identity: F,
    ) -> Option<TraceWebSocketContext>
    where
        F: FnOnce() -> TraceIdentity,
    {
        if !self.enabled.load(Ordering::Acquire) || !self.policy.load().enabled {
            return None;
        }
        let mut user_agent = request
            .headers()
            .get(hyper::header::USER_AGENT)
            .map(|value| super::super::sanitize::bounded_text(value.as_bytes(), 512));
        if self.wildcard_redaction
            && let Some(text) = &mut user_agent
        {
            let truncated = request
                .headers()
                .get(hyper::header::USER_AGENT)
                .is_some_and(|value| value.len() > 512);
            super::super::wildcard::scrub_text(text, truncated);
        }
        Some(TraceWebSocketContext {
            connection_id,
            peer_ip,
            effective_ip,
            user_agent,
            identity: identity(),
            lane_id,
        })
    }

    /// Records one policy-bounded WebSocket message without retaining credentials.
    pub(crate) fn record_websocket_message(
        &self,
        context: &TraceWebSocketContext,
        direction: TraceDirection,
        message_type: &'static str,
        payload: &[u8],
        duration_us: u64,
    ) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        let policy = self.policy.load_full();
        if !policy.enabled {
            return;
        }
        let capture_limit = super::super::sanitize::capture_limit(
            &policy,
            super::super::types::TraceRoute::Websocket,
            self.max_carrier_body_bytes,
        )
        .unwrap_or(0);
        let capture_bytes = payload.len().min(capture_limit);
        let frame_reservation = if policy.capture_frames {
            payload
                .len()
                .div_ceil(frame::HEADER_BYTES)
                .clamp(1, self.frame_limits.max_frames_per_body)
                .saturating_mul(std::mem::size_of::<TraceFrame>())
        } else {
            0
        };
        let identity_bytes = context
            .identity
            .user
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(
                context
                    .identity
                    .key_fingerprint
                    .as_ref()
                    .map_or(0, String::len),
            );
        let reservation = BASE_RECORD_RESERVATION
            .saturating_add(identity_bytes)
            .saturating_add(context.user_agent.as_ref().map_or(0, String::len))
            .saturating_add(capture_bytes)
            .saturating_add(frame_reservation);
        if !self.try_reserve_record(reservation) {
            return;
        }
        let mut body =
            (policy.body_capture != WebDebugBodyCapture::Off).then(|| TraceBodySnapshot {
                observed_bytes: payload.len() as u64,
                captured: payload[..capture_bytes].to_vec(),
                truncated: capture_limit != 0 && capture_bytes < payload.len(),
                state: TraceBodyState::Complete,
            });
        if self.wildcard_redaction
            && let Some(body) = &mut body
        {
            super::super::wildcard::scrub_bytes(&mut body.captured, body.truncated);
        }
        let frames = if policy.capture_frames && message_type == "binary" {
            websocket_frames(direction, payload, &self.frame_limits)
        } else {
            Vec::new()
        };
        let record = TraceRecord {
            seq: self.next_record_seq(),
            epoch_millis: epoch_millis(),
            peer_ip: Some(context.peer_ip),
            effective_ip: Some(context.effective_ip),
            user_agent: context.user_agent.clone(),
            identity: context.identity.clone(),
            kind: TraceRecordKind::Websocket(TraceWebSocketRecord {
                direction,
                message_type,
                payload_bytes: payload.len(),
                body,
                frames,
                duration_us: policy.capture_timings.then_some(duration_us),
                connection_id: context.connection_id,
                lane_id: context.lane_id,
            }),
        };
        if !self.try_commit(record, reservation, epoch) {
            self.release(reservation);
        }
    }
}

fn websocket_frames(
    direction: TraceDirection,
    payload: &[u8],
    limits: &crate::config::WebLimitsConfig,
) -> Vec<TraceFrame> {
    match frame::parse_all(payload, limits) {
        Ok(frames) => frames
            .into_iter()
            .map(|value| TraceFrame {
                direction,
                frame_type: Some(super::super::sanitize::frame_type_name(value.frame_type)),
                stream_id: Some(value.stream_id),
                payload_len: Some(value.payload.len()),
                window_delta: (value.frame_type == FrameType::Window)
                    .then(|| frame::window_amount(value.payload).ok())
                    .flatten(),
                parse_error: None,
            })
            .collect(),
        Err(error) => vec![TraceFrame {
            direction,
            frame_type: None,
            stream_id: None,
            payload_len: None,
            window_delta: None,
            parse_error: Some(super::super::sanitize::frame_error_name(error)),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{WebDebugConfig, WebLimitsConfig};
    use crate::web::frame::FrameType;

    #[test]
    fn websocket_message_capture_retains_bounded_identity_body_timing_and_frames() {
        let policy = WebDebugConfig {
            enabled: true,
            capture_frames: true,
            capture_timings: true,
            body_capture: WebDebugBodyCapture::Full,
            ..Default::default()
        };
        let limits = WebLimitsConfig {
            debug_records_capacity: 4,
            debug_bytes_global: 64 * 1024,
            ..Default::default()
        };
        let store = WebTraceStore::new(policy, &limits);
        let request = hyper::Request::builder()
            .header(hyper::header::USER_AGENT, "trace-client")
            .body(())
            .unwrap();
        let context = store
            .websocket_context(
                &request,
                "127.0.0.1".parse().unwrap(),
                "192.0.2.10".parse().unwrap(),
                17,
                Some(7),
                || TraceIdentity {
                    session_id: Some(42),
                    user: Some("alice".to_string()),
                    key_fingerprint: Some("0123456789abcdef".to_string()),
                },
            )
            .unwrap();
        let payload = crate::web::frame::encode(FrameType::Pong, 0, &[]);
        store.record_websocket_message(&context, TraceDirection::Request, "binary", &payload, 123);

        let records = store.snapshot_matching(|_| true);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].record.user_agent.as_deref(),
            Some("trace-client")
        );
        let TraceRecordKind::Websocket(message) = &records[0].record.kind else {
            panic!("expected WebSocket trace");
        };
        assert_eq!(message.connection_id, 17);
        assert_eq!(message.lane_id, Some(7));
        assert_eq!(message.duration_us, Some(123));
        assert_eq!(
            message.body.as_ref().unwrap().captured.as_slice(),
            payload.as_ref()
        );
        assert_eq!(message.frames.len(), 1);
        assert_eq!(message.frames[0].frame_type, Some("PONG"));
    }
}
