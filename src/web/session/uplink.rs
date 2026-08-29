use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::backend::StreamCompletion;
use super::{
    InboundChunk, PendingClass, QUEUE_ITEM_COST, SessionState, StreamIdentity, StreamState,
    WebSession, inbound_queue_cost,
};
use crate::web::frame::{self, Frame, FrameType};
use crate::web::manager::{ManagerError, TokenHash};

#[derive(Clone, Copy, Default)]
pub(super) struct AppliedProgress {
    pub(super) accepted_open: bool,
    pub(super) accepted_data: bool,
}

impl AppliedProgress {
    pub(super) fn any(self) -> bool {
        self.accepted_open || self.accepted_data
    }
}

impl WebSession {
    /// Applies one exactly-once uplink batch.
    pub(crate) fn process_up(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
    ) -> Result<u64, ManagerError> {
        let (acknowledged, progressed) = self.process_up_inner(sequence, body)?;
        if self.automatic_carrier && !progressed && !self.is_carrier_committed() {
            return Err(ManagerError::Backpressure);
        }
        Ok(acknowledged)
    }

    /// Applies one WebSocket uplink batch and reports actual carrier progress.
    pub(crate) fn process_websocket_multiplex(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
    ) -> Result<bool, ManagerError> {
        self.process_up_inner(sequence, body)
            .map(|(_, progress)| progress)
    }

    fn process_up_inner(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
    ) -> Result<(u64, bool), ManagerError> {
        if !self.carrier().is_multiplexed() {
            return Err(ManagerError::Protocol);
        }
        if self
            .up_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ManagerError::Concurrent);
        }
        let _uplink = UplinkGuard(&self.up_active);
        let frames = match frame::parse_all(body, &self.limits) {
            Ok(frames) => frames,
            Err(_) => {
                self.close();
                return Err(ManagerError::Protocol);
            }
        };
        if frames
            .iter()
            .copied()
            .any(|value| frame::validate_client_shape(value).is_err())
        {
            self.close();
            return Err(ManagerError::Protocol);
        }
        let digest: TokenHash = Sha256::digest(body).into();
        let mut opened = Vec::new();
        let mut committed = false;
        let mut healthy = false;
        let result = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            self.ensure_carrier_active_locked(&state)?;
            state.last_activity = Instant::now();
            if sequence == state.last_up_sequence && sequence != 0 {
                return if bool::from(state.last_up_digest.ct_eq(&digest)) {
                    Ok((sequence, false))
                } else {
                    drop(state);
                    self.close();
                    Err(ManagerError::Protocol)
                };
            }
            if sequence == 0 || sequence != state.last_up_sequence.saturating_add(1) {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            }
            if !validate_batch(&state, &frames) {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            }
            let (reserve_bytes, reserve_items) = inbound_reservation(&state, &frames);
            if !self.reserve_locked(
                &mut state,
                reserve_bytes,
                reserve_items,
                PendingClass::Uplink,
            ) {
                return Err(ManagerError::Backpressure);
            }
            let mut unused_bytes = reserve_bytes;
            let mut unused_items = reserve_items;
            let mut progress = AppliedProgress::default();
            let applied = self.apply_batch_locked(
                &mut state,
                &frames,
                &mut opened,
                &mut None,
                &mut unused_bytes,
                &mut unused_items,
                &mut progress,
            );
            self.release_locked(&mut state, unused_bytes, unused_items, false);
            if !applied {
                Err(ManagerError::Closed)
            } else {
                state.last_up_sequence = sequence;
                state.last_up_digest = digest;
                (committed, healthy) = self.record_uplink_progress_locked(&mut state, progress);
                Ok((sequence, progress.any()))
            }
        };
        if matches!(result, Err(ManagerError::Backpressure)) {
            return result;
        }
        if result.is_err() {
            self.close();
            drop(opened);
            return result;
        }
        if committed {
            self.finish_carrier_commit();
        }
        if healthy {
            self.finish_carrier_health();
        }
        for completion in opened {
            self.spawn_stream(completion, false);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.record_up(body.len());
        }
        result
    }

    // Batch application keeps every transactional accumulator explicit.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_batch_locked(
        self: &Arc<Self>,
        state: &mut SessionState,
        frames: &[Frame<'_>],
        opened: &mut Vec<StreamCompletion>,
        reserved_open: &mut Option<(u32, u16)>,
        unused_bytes: &mut usize,
        unused_items: &mut usize,
        progress: &mut AppliedProgress,
    ) -> bool {
        for value in frames {
            if value.stream_id == 0 {
                continue;
            }
            let was_closed = state.closed_streams.contains(&value.stream_id)
                || state.closing_streams.contains_key(&value.stream_id);
            match value.frame_type {
                FrameType::Open => {
                    let Some(stream) = next_stream_identity(state, value.stream_id) else {
                        return false;
                    };
                    let peer_port = match reserved_open.take() {
                        Some((reserved_stream_id, peer_port))
                            if reserved_stream_id == value.stream_id =>
                        {
                            peer_port
                        }
                        Some(reserved) => {
                            *reserved_open = Some(reserved);
                            return false;
                        }
                        None => {
                            let Some(peer_port) = self.reserve_stream_locked(state) else {
                                self.remember_closed_locked(state, value.stream_id);
                                if !self.queue_control_locked(
                                    state,
                                    FrameType::Close,
                                    value.stream_id,
                                    &[],
                                ) {
                                    return false;
                                }
                                continue;
                            };
                            peer_port
                        }
                    };
                    state.streams.insert(
                        value.stream_id,
                        StreamState {
                            instance: stream.instance,
                            inbound: VecDeque::new(),
                            receive_window: frame::INITIAL_STREAM_WINDOW,
                            send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                            read_waker: None,
                            write_waker: None,
                        },
                    );
                    progress.accepted_open = true;
                    opened.push(self.own_stream_task(stream, peer_port));
                }
                FrameType::Data if !was_closed => {
                    let Some(stream) = state.streams.get_mut(&value.stream_id) else {
                        return false;
                    };
                    stream.receive_window -= value.payload.len() as u32;
                    stream.inbound.push_back(InboundChunk {
                        bytes: Bytes::copy_from_slice(value.payload),
                        offset: 0,
                    });
                    progress.accepted_data = true;
                    *unused_bytes =
                        unused_bytes.saturating_sub(value.payload.len() + QUEUE_ITEM_COST);
                    *unused_items = unused_items.saturating_sub(1);
                    if let Some(waker) = stream.read_waker.take() {
                        waker.wake();
                    }
                }
                FrameType::Window if !was_closed => {
                    let Some(stream) = state.streams.get_mut(&value.stream_id) else {
                        return false;
                    };
                    let amount = frame::window_amount(value.payload).unwrap_or(0);
                    stream.send_credit = stream
                        .send_credit
                        .saturating_add(u64::from(amount))
                        .min(u64::from(u32::MAX));
                    if let Some(waker) = stream.write_waker.take() {
                        waker.wake();
                    }
                }
                FrameType::Close if !was_closed => {
                    let Some(stream) = state.streams.remove(&value.stream_id) else {
                        return false;
                    };
                    state
                        .closing_streams
                        .insert(value.stream_id, stream.instance);
                    let (bytes, items) = inbound_queue_cost(&stream.inbound);
                    self.release_locked(state, bytes, items, false);
                    self.remember_closed_locked(state, value.stream_id);
                    if let Some(waker) = stream.read_waker {
                        waker.wake();
                    }
                    if let Some(waker) = stream.write_waker {
                        waker.wake();
                    }
                }
                FrameType::Data | FrameType::Window | FrameType::Close => {}
                _ => return false,
            }
        }
        true
    }

    fn reserve_stream_locked(&self, state: &mut SessionState) -> Option<u16> {
        let manager = self.manager.upgrade()?;
        if state.active_peer_ports.len() >= self.profile.max_streams_per_session {
            manager.record_stream_rejected_reason(
                crate::web::telemetry::WebRejectionReason::StreamSessionCapacity,
            );
            return None;
        }
        let peer_port = manager
            .try_acquire_stream(
                self.profile_key,
                self.profile.max_streams,
                self.client_ip,
                self.profile.public_addr,
            )
            .ok()?;
        if state.active_peer_ports.insert(peer_port) {
            return Some(peer_port);
        }
        manager.release_stream(
            self.profile_key,
            self.client_ip,
            self.profile.public_addr,
            peer_port,
        );
        None
    }
}

fn next_stream_identity(state: &mut SessionState, stream_id: u32) -> Option<StreamIdentity> {
    let instance = state.next_stream_instance;
    state.next_stream_instance = instance.checked_add(1)?;
    Some(StreamIdentity {
        id: stream_id,
        instance,
    })
}

struct UplinkGuard<'a>(&'a AtomicBool);

impl Drop for UplinkGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) fn validate_batch(state: &SessionState, frames: &[Frame<'_>]) -> bool {
    let mut live = state
        .streams
        .iter()
        .map(|(id, stream)| (*id, (stream.receive_window, stream.send_credit)))
        .collect::<HashMap<_, _>>();
    let mut closed = HashSet::new();
    for value in frames {
        if value.stream_id == 0 {
            if value.frame_type != FrameType::Pong {
                return false;
            }
            continue;
        }
        let was_closed = state.closed_streams.contains(&value.stream_id)
            || state.closing_streams.contains_key(&value.stream_id)
            || closed.contains(&value.stream_id);
        match value.frame_type {
            FrameType::Open => {
                if live.contains_key(&value.stream_id) || was_closed {
                    return false;
                }
                live.insert(
                    value.stream_id,
                    (
                        frame::INITIAL_STREAM_WINDOW,
                        u64::from(frame::INITIAL_STREAM_WINDOW),
                    ),
                );
            }
            FrameType::Data if !was_closed => {
                let Some((receive_window, send_credit)) = live.get_mut(&value.stream_id) else {
                    return false;
                };
                let Ok(payload_len) = u32::try_from(value.payload.len()) else {
                    return false;
                };
                if payload_len > *receive_window {
                    return false;
                }
                *receive_window -= payload_len;
                let _ = send_credit;
            }
            FrameType::Window if !was_closed => {
                let Some((_, send_credit)) = live.get_mut(&value.stream_id) else {
                    return false;
                };
                let Ok(amount) = frame::window_amount(value.payload) else {
                    return false;
                };
                *send_credit = send_credit
                    .saturating_add(u64::from(amount))
                    .min(u64::from(u32::MAX));
            }
            FrameType::Close if !was_closed => {
                if live.remove(&value.stream_id).is_none() {
                    return false;
                }
                closed.insert(value.stream_id);
            }
            FrameType::Data | FrameType::Window | FrameType::Close => {}
            _ => return false,
        }
    }
    true
}

pub(super) fn inbound_reservation(state: &SessionState, frames: &[Frame<'_>]) -> (usize, usize) {
    let mut live = state.streams.keys().copied().collect::<HashSet<_>>();
    let mut bytes = 0usize;
    let mut items = 0usize;
    for value in frames {
        match value.frame_type {
            FrameType::Open => {
                live.insert(value.stream_id);
            }
            FrameType::Data if live.contains(&value.stream_id) => {
                bytes = bytes.saturating_add(value.payload.len() + QUEUE_ITEM_COST);
                items = items.saturating_add(1);
            }
            FrameType::Close => {
                live.remove(&value.stream_id);
            }
            _ => {}
        }
    }
    (bytes, items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    use crate::config::{
        WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
    };
    use crate::web::manager::WebProcessRuntime;

    fn session() -> Arc<WebSession> {
        session_with_automatic(false)
    }

    fn session_with_automatic(automatic: bool) -> Arc<WebSession> {
        let profile = Arc::new(WebRuntimeProfile {
            host: "proxy.example.com".to_string(),
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::Https,
            carrier_negotiation_enabled: false,
            carrier_learning: true,
            carriers: Arc::from([WebCarrier::Https]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            capability: [0; 32],
            key_fingerprint: "0000000000000000".to_string(),
            max_sessions: 1,
            max_streams: 1,
            max_streams_per_session: 1,
        });
        WebSession::new(
            std::sync::Weak::<WebProcessRuntime>::new(),
            [1; 32],
            "192.0.2.10".parse().unwrap(),
            1,
            profile,
            [2; 32],
            WebCarrier::Https,
            1,
            [3; 32],
            None,
            if automatic {
                crate::web::manager::CarrierClientClass::Bridge
            } else {
                crate::web::manager::CarrierClientClass::Legacy
            },
            None,
            automatic,
            WebLimitsConfig::default(),
            WebTimeoutsConfig::default(),
        )
    }

    #[test]
    fn uplink_retry_commits_only_one_exact_body() {
        let session = session();
        let first = frame::encode(FrameType::Pong, 0, &[1, 2, 3]);
        assert_eq!(session.process_up(1, &first), Ok(1));
        assert_eq!(session.process_up(1, &first), Ok(1));

        let changed = frame::encode(FrameType::Pong, 0, &[1, 2, 4]);
        assert_eq!(session.process_up(1, &changed), Err(ManagerError::Protocol));
        assert!(session.state.lock().closed);
    }

    #[test]
    fn concurrent_uplink_does_not_commit_sequence() {
        let session = session();
        let body = frame::encode(FrameType::Pong, 0, &[]);
        session.up_active.store(true, Ordering::Release);
        assert_eq!(session.process_up(1, &body), Err(ManagerError::Concurrent));
        assert_eq!(session.state.lock().last_up_sequence, 0);
        session.up_active.store(false, Ordering::Release);
        assert_eq!(session.process_up(1, &body), Ok(1));
    }

    #[test]
    fn backpressured_uplink_does_not_commit_or_close() {
        let session = session();
        {
            let mut state = session.state.lock();
            state.streams.insert(
                1,
                StreamState {
                    instance: 1,
                    inbound: VecDeque::new(),
                    receive_window: frame::INITIAL_STREAM_WINDOW,
                    send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                    read_waker: None,
                    write_waker: None,
                },
            );
            state.pending_bytes = session.limits.pending_bytes_per_session;
        }
        let body = frame::encode(FrameType::Data, 1, &[1]);

        assert_eq!(
            session.process_up(1, &body),
            Err(ManagerError::Backpressure)
        );
        let state = session.state.lock();
        assert!(!state.closed);
        assert_eq!(state.last_up_sequence, 0);
        assert!(state.streams.get(&1).unwrap().inbound.is_empty());
    }

    #[test]
    fn uplink_gap_is_fatal() {
        let session = session();
        let body = frame::encode(FrameType::Pong, 0, &[]);
        assert_eq!(session.process_up(2, &body), Err(ManagerError::Protocol));
        assert!(session.state.lock().closed);
    }

    #[test]
    fn automatic_uplink_does_not_ack_a_batch_without_real_progress() {
        let session = session_with_automatic(true);
        let body = frame::encode(FrameType::Pong, 0, &[]);

        assert_eq!(
            session.process_up(1, &body),
            Err(ManagerError::Backpressure)
        );
        assert!(!session.is_carrier_committed());
        assert!(!session.state.lock().closed);
    }
}
