use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::uplink::{AppliedProgress, inbound_reservation, validate_batch};
use super::{
    DeferredSessionEffects, PendingClass, SessionCloseReason, WebSession, insert_carrier_lane,
};
use crate::config::WebCarrier;
use crate::web::frame::{self, Frame, FrameType};
use crate::web::manager::{ManagerError, TokenHash};
use crate::web::telemetry::WebSessionLifecycleObservation;

impl WebSession {
    /// Applies one exactly-once uplink batch to an independent HTTPS lane.
    pub(crate) fn process_up_lane(
        self: &Arc<Self>,
        lane_id: u32,
        sequence: u64,
        body: &[u8],
    ) -> Result<u64, ManagerError> {
        self.process_up_lane_inner(lane_id, sequence, body, None)
    }

    /// Applies one lane batch only while its optional conveyor claim still owns the turn.
    pub(super) fn process_up_lane_inner(
        self: &Arc<Self>,
        lane_id: u32,
        sequence: u64,
        body: &[u8],
        claim: Option<(&super::conveyor::ConveyorClaim, TokenHash)>,
    ) -> Result<u64, ManagerError> {
        if self.carrier() != WebCarrier::HttpsLanes || lane_id > frame::MAX_STREAM_ID {
            return Err(ManagerError::Protocol);
        }
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let frames = match frame::parse_all(body, &self.limits) {
            Ok(frames) => frames,
            Err(_) => {
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
        };
        if frames
            .iter()
            .copied()
            .any(|value| value.stream_id != lane_id || frame::validate_client_shape(value).is_err())
        {
            self.close(SessionCloseReason::Protocol);
            return Err(ManagerError::Protocol);
        }
        let digest: TokenHash =
            claim.map_or_else(|| Sha256::digest(body).into(), |(_, digest)| digest);
        let mut opened = Vec::new();
        let mut committed = false;
        let mut healthy = None;
        let mut effects = DeferredSessionEffects::new();
        let result = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            self.ensure_carrier_active_locked(&state)?;
            if let Some((claim, _)) = claim {
                claim.validate_locked(&state, &digest)?;
            }
            let new_lane = !state.carrier_lanes.contains_key(&lane_id);
            if new_lane {
                if claim.is_none()
                    && lane_id != 0
                    && frames
                        .first()
                        .is_some_and(|value| value.frame_type != FrameType::Open)
                    && only_late_frames(&frames)
                {
                    self.touch_peer_locked(
                        &mut state,
                        Instant::now(),
                        WebSessionLifecycleObservation::HttpActivityAfterGap,
                    );
                    return if self.automatic_carrier
                        && state.negotiation_phase != super::SessionNegotiationPhase::Committed
                    {
                        Err(ManagerError::Backpressure)
                    } else {
                        Ok(sequence)
                    };
                }
                if lane_id == 0
                    || frames
                        .first()
                        .is_none_or(|value| value.frame_type != FrameType::Open)
                {
                    drop(state);
                    self.close(SessionCloseReason::Protocol);
                    return Err(ManagerError::Protocol);
                }
                let lane_limit = self
                    .profile
                    .shared
                    .max_streams_per_session
                    .saturating_add(self.limits.max_tombstones_per_session)
                    .saturating_add(1);
                if state.carrier_lanes.len() >= lane_limit {
                    return Err(ManagerError::Limit);
                }
            }
            let (last_sequence, last_digest, up_active) = state
                .carrier_lanes
                .get(&lane_id)
                .map_or((0, [0; 32], false), |lane| {
                    (lane.last_up_sequence, lane.last_up_digest, lane.up_active)
                });
            if sequence == last_sequence && sequence != 0 {
                return if bool::from(last_digest.ct_eq(&digest)) {
                    self.touch_peer_locked(
                        &mut state,
                        Instant::now(),
                        WebSessionLifecycleObservation::HttpActivityAfterGap,
                    );
                    Ok(sequence)
                } else {
                    drop(state);
                    self.close(SessionCloseReason::Protocol);
                    Err(ManagerError::Protocol)
                };
            }
            if sequence == 0 || sequence != last_sequence.saturating_add(1) {
                drop(state);
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
            if up_active {
                return Err(ManagerError::Concurrent);
            }
            if !validate_batch(&state, &frames) {
                drop(state);
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
            self.touch_peer_locked(
                &mut state,
                Instant::now(),
                WebSessionLifecycleObservation::HttpActivityAfterGap,
            );
            let (reserve_bytes, reserve_items) = inbound_reservation(&state, &frames);
            if !self.reserve_locked(
                &mut state,
                reserve_bytes,
                reserve_items,
                PendingClass::Uplink,
            ) {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
                return Err(ManagerError::Backpressure);
            }
            if new_lane && insert_carrier_lane(&mut state, lane_id).is_none() {
                self.release_locked(
                    &mut state,
                    &mut effects,
                    reserve_bytes,
                    reserve_items,
                    false,
                );
                drop(state);
                effects.finish();
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
            let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                self.release_locked(
                    &mut state,
                    &mut effects,
                    reserve_bytes,
                    reserve_items,
                    false,
                );
                drop(state);
                effects.finish();
                return Err(ManagerError::Closed);
            };
            lane.up_active = true;
            let mut unused_bytes = reserve_bytes;
            let mut unused_items = reserve_items;
            let mut progress = AppliedProgress::default();
            let applied = self.apply_batch_locked(
                &mut state,
                &frames,
                &mut effects,
                &mut opened,
                &mut None,
                &mut unused_bytes,
                &mut unused_items,
                &mut progress,
            );
            self.release_locked(&mut state, &mut effects, unused_bytes, unused_items, false);
            if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                lane.up_active = false;
                if applied {
                    lane.last_up_sequence = sequence;
                    lane.last_up_digest = digest;
                }
            }
            if applied {
                state.conveyor.commit(Some(lane_id), sequence, digest);
                (committed, healthy) = self.record_uplink_progress_locked(&mut state, progress);
            }
            applied.then_some(sequence).ok_or(ManagerError::Closed)
        };
        effects.finish();
        if matches!(result, Err(ManagerError::Backpressure)) {
            return result;
        }
        if matches!(result, Err(ManagerError::Closed)) && self.close_if_cancelled() {
            drop(opened);
            return result;
        }
        if result.is_err() {
            self.close(SessionCloseReason::Protocol);
            drop(opened);
            return result;
        }
        if self.automatic_carrier && !self.is_carrier_committed() {
            self.lane_open_notify.notify_waiters();
            return Err(ManagerError::Backpressure);
        }
        if committed {
            self.finish_carrier_commit();
        }
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
        self.lane_open_notify.notify_waiters();
        for completion in opened {
            self.spawn_stream(completion, false);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.record_up(body.len());
        }
        result
    }
}

fn only_late_frames(frames: &[Frame<'_>]) -> bool {
    frames.iter().all(|value| {
        matches!(
            value.frame_type,
            FrameType::Data | FrameType::Window | FrameType::Close
        )
    })
}
