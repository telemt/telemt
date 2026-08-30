use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::OwnedSemaphorePermit;

use super::lane_downlink::take_lane_down_batch;
use super::{
    CarrierLaneIdentity, PendingClass, PollResult, QUEUE_ITEM_COST, QueuedFrame, SessionState,
    WebSession, remember_closed,
};
use crate::web::frame::{self, FrameType};
use crate::web::manager::ManagerError;

impl WebSession {
    /// Polls one lane with independent cursor replay and newest-poll-wins semantics.
    pub(crate) async fn poll_down_lane(
        &self,
        lane_id: u32,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        self.poll_down_lane_inner(lane_id, None, cursor).await
    }

    /// Polls only the exact lane incarnation owned by one WebSocket driver.
    pub(crate) async fn poll_down_websocket_lane(
        &self,
        lane: CarrierLaneIdentity,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        self.poll_down_lane_inner(lane.lane_id, Some(lane.instance), cursor)
            .await
    }

    async fn poll_down_lane_inner(
        &self,
        lane_id: u32,
        expected_instance: Option<u64>,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        if !self.carrier().uses_lanes() || lane_id > frame::MAX_STREAM_ID {
            return Err(ManagerError::Protocol);
        }
        let lane_ready = if let Some(expected_instance) = expected_instance {
            let state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            state
                .carrier_lanes
                .get(&lane_id)
                .is_some_and(|lane| lane.instance == expected_instance)
        } else {
            self.wait_for_lane_open(lane_id, cursor).await?
        };
        if !lane_ready {
            return Ok(PollResult {
                body: Bytes::new(),
                next_cursor: cursor,
                lane_closed: expected_instance.is_some(),
            });
        }
        let (instance, epoch, notify, healthy) = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            state.last_activity = Instant::now();
            let acknowledged = {
                let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                };
                if expected_instance.is_some_and(|instance| lane.instance != instance) {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                }
                if let Some(unacked) = &lane.unacked {
                    if cursor == unacked.base_cursor {
                        return Ok(PollResult {
                            body: unacked.body.clone(),
                            next_cursor: unacked.next_cursor,
                            lane_closed: false,
                        });
                    }
                    if cursor != unacked.next_cursor {
                        drop(state);
                        self.close();
                        return Err(ManagerError::Protocol);
                    }
                    lane.unacked.take()
                } else {
                    if cursor != lane.down_cursor {
                        drop(state);
                        self.close();
                        return Err(ManagerError::Protocol);
                    }
                    None
                }
            };
            if let Some(batch) = acknowledged {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.pending_bytes = lane.pending_bytes.saturating_sub(batch.data_bytes);
                    lane.pending_items = lane.pending_items.saturating_sub(batch.data_items);
                }
                batch.lease.detach();
                self.release_local_locked(&mut state, batch.data_bytes, batch.data_items, false);
                self.release_local_locked(
                    &mut state,
                    batch.control_bytes,
                    batch.control_items,
                    true,
                );
                state.carrier_health_downlink |= batch.carrier_health_eligible;
                if batch.carrier_health_eligible {
                    state.carrier_health_activity_at = Some(Instant::now());
                }
                if let Some(stream) = state.streams.get_mut(&lane_id)
                    && let Some(waker) = stream.write_waker.take()
                {
                    waker.wake();
                }
            }
            let lane = state
                .carrier_lanes
                .get_mut(&lane_id)
                .ok_or(ManagerError::Protocol)?;
            let Some(epoch) = lane.down_epoch.checked_add(1) else {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            };
            lane.down_epoch = epoch;
            let instance = lane.instance;
            let notify = Arc::clone(&lane.notify);
            let healthy = self.carrier_health_ready_locked(&mut state, Instant::now());
            (instance, epoch, notify, healthy)
        };
        if healthy {
            self.finish_carrier_health();
        }
        notify.notify_waiters();

        let deadline = Duration::from_secs(self.timeouts.long_poll_secs);
        let poll = async {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut state = self.state.lock();
                    if state.closed {
                        return Err(ManagerError::Closed);
                    }
                    let carrier_health_eligible = lane_id != 0
                        && state.negotiation_phase == super::SessionNegotiationPhase::Committed;
                    let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    };
                    if lane.instance != instance {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                    if lane.down_epoch != epoch {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: false,
                        });
                    }
                    if !lane.pending_frames.is_empty() {
                        let batch = match take_lane_down_batch(
                            self,
                            &self.limits,
                            lane,
                            cursor,
                            carrier_health_eligible,
                        ) {
                            Ok(batch) => batch,
                            Err(ManagerError::Backpressure) => {
                                return Err(ManagerError::Backpressure);
                            }
                            Err(error) => {
                                drop(state);
                                self.close();
                                return Err(error);
                            }
                        };
                        let result = PollResult {
                            body: batch.body.clone(),
                            next_cursor: batch.next_cursor,
                            lane_closed: false,
                        };
                        lane.unacked = Some(batch);
                        drop(state);
                        if let Some(manager) = self.manager.upgrade() {
                            manager.record_down(result.body.len());
                        }
                        return Ok(result);
                    }
                    if lane_id != 0
                        && !state.streams.contains_key(&lane_id)
                        && state.closed_streams.contains(&lane_id)
                    {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                }
                notified.await;
            }
        };
        match tokio::time::timeout(deadline, poll).await {
            Ok(result) => result,
            Err(_) => {
                let mut state = self.state.lock();
                if state.closed {
                    return Err(ManagerError::Closed);
                }
                if !state.carrier_lanes.contains_key(&lane_id) {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                }
                if lane_id != 0
                    && !state.streams.contains_key(&lane_id)
                    && state.closed_streams.contains(&lane_id)
                {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                }
                if let Some(lane) = state.carrier_lanes.get(&lane_id) {
                    if lane.instance != instance {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                    if lane.down_epoch == epoch {
                        state.last_activity = Instant::now();
                    }
                }
                Ok(PollResult {
                    body: Bytes::new(),
                    next_cursor: cursor,
                    lane_closed: false,
                })
            }
        }
    }

    async fn wait_for_lane_open(&self, lane_id: u32, cursor: u64) -> Result<bool, ManagerError> {
        let wait = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            if state.carrier_lanes.contains_key(&lane_id) {
                return Ok(true);
            }
            if cursor != 0 || lane_id == 0 {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            }
            if state.closed_streams.contains(&lane_id)
                || state.closing_streams.contains_key(&lane_id)
            {
                return Ok(true);
            }
            if state.lane_open_waits >= self.limits.max_lane_open_waits_per_session {
                return Err(ManagerError::Limit);
            }
            let Some(manager) = self.manager.upgrade() else {
                return Err(ManagerError::Closed);
            };
            let Some(auxiliary) = manager.try_lane_poll(true) else {
                return Err(ManagerError::Limit);
            };
            state.lane_open_waits += 1;
            LaneOpenWaitGuard {
                session: self,
                _auxiliary: auxiliary,
            }
        };
        let deadline = Duration::from_secs(self.timeouts.lane_open_wait_secs);
        let opened = tokio::time::timeout(deadline, async {
            loop {
                let notified = self.lane_open_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let state = self.state.lock();
                    if state.closed {
                        return Err(ManagerError::Closed);
                    }
                    if state.carrier_lanes.contains_key(&lane_id)
                        || state.closed_streams.contains(&lane_id)
                        || state.closing_streams.contains_key(&lane_id)
                    {
                        return Ok(true);
                    }
                }
                notified.await;
            }
        })
        .await;
        drop(wait);
        match opened {
            Ok(result) => result,
            Err(_) => {
                let state = self.state.lock();
                if state.closed {
                    Err(ManagerError::Closed)
                } else {
                    Ok(state.carrier_lanes.contains_key(&lane_id)
                        || state.closed_streams.contains(&lane_id)
                        || state.closing_streams.contains_key(&lane_id))
                }
            }
        }
    }

    pub(super) fn queue_lane_frame_locked(
        &self,
        state: &mut SessionState,
        frame_type: FrameType,
        stream_id: u32,
        payload: &[u8],
        control: bool,
    ) -> bool {
        if !state.carrier_lanes.contains_key(&stream_id) {
            return false;
        }
        if frame_type == FrameType::Window {
            let coalesced = state.carrier_lanes.get(&stream_id).and_then(|lane| {
                let index = lane.pending_windows.get(&stream_id).copied()?;
                let queued = lane.pending_frames.get(index)?;
                let previous = u32::from_be_bytes(
                    queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                previous
                    .checked_add(frame::window_amount(payload).unwrap_or(0))
                    .map(|total| (index, total))
            });
            if let Some((index, total)) = coalesced
                && let Some(lane) = state.carrier_lanes.get_mut(&stream_id)
                && let Some(queued) = lane.pending_frames.get_mut(index)
            {
                queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                    .copy_from_slice(&total.to_be_bytes());
                lane.notify.notify_waiters();
                return true;
            }
        }
        let can_coalesce = frame_type == FrameType::Data
            && state
                .carrier_lanes
                .get(&stream_id)
                .and_then(|lane| lane.pending_frames.back())
                .is_some_and(|last| {
                    last.frame_type == FrameType::Data
                        && last.stream_id == stream_id
                        && last.encoded.len() - frame::HEADER_BYTES + payload.len()
                            <= self.limits.max_frame_payload_bytes
                });
        if can_coalesce {
            if state.carrier_lanes.get(&stream_id).is_none_or(|lane| {
                let resident = lane.resident.snapshot();
                payload.len() > self.limits.pending_bytes_per_lane
                    || lane.pending_bytes.saturating_add(resident.data_bytes)
                        > self
                            .limits
                            .pending_bytes_per_lane
                            .saturating_sub(payload.len())
            }) {
                return false;
            }
            if !self.reserve_locked(state, payload.len(), 0, PendingClass::Downlink) {
                return false;
            }
            let Some(lane) = state.carrier_lanes.get_mut(&stream_id) else {
                self.release_locked(state, payload.len(), 0, false);
                return false;
            };
            let Some(last) = lane.pending_frames.back_mut() else {
                self.release_locked(state, payload.len(), 0, false);
                return false;
            };
            last.encoded.extend_from_slice(payload);
            last.cost += payload.len();
            let payload_len = (last.encoded.len() - frame::HEADER_BYTES) as u32;
            last.encoded[4..8].copy_from_slice(&payload_len.to_be_bytes());
            lane.pending_bytes += payload.len();
            lane.notify.notify_waiters();
            return true;
        }
        let cost = frame::HEADER_BYTES + payload.len() + QUEUE_ITEM_COST;
        let class = if control {
            PendingClass::Control
        } else {
            PendingClass::Downlink
        };
        if !control
            && state.carrier_lanes.get(&stream_id).is_none_or(|lane| {
                let resident = lane.resident.snapshot();
                cost > self.limits.pending_bytes_per_lane
                    || lane.pending_bytes.saturating_add(resident.data_bytes)
                        > self.limits.pending_bytes_per_lane.saturating_sub(cost)
                    || lane.pending_items.saturating_add(resident.data_items)
                        >= self.limits.pending_items_per_lane
            })
        {
            return false;
        }
        if !self.reserve_locked(state, cost, 1, class) {
            return false;
        }
        let mut encoded = BytesMut::with_capacity(frame::HEADER_BYTES + payload.len());
        encoded.put_u8(frame_type as u8);
        encoded.put_u8((stream_id >> 16) as u8);
        encoded.put_u8((stream_id >> 8) as u8);
        encoded.put_u8(stream_id as u8);
        encoded.put_u32(payload.len() as u32);
        encoded.extend_from_slice(payload);
        let Some(lane) = state.carrier_lanes.get_mut(&stream_id) else {
            self.release_locked(state, cost, 1, control);
            return false;
        };
        let index = lane.pending_frames.len();
        lane.pending_frames.push_back(QueuedFrame {
            encoded,
            frame_type,
            stream_id,
            control,
            cost,
        });
        if !control {
            lane.pending_bytes += cost;
            lane.pending_items += 1;
        }
        if frame_type == FrameType::Window {
            lane.pending_windows.insert(stream_id, index);
        }
        lane.notify.notify_waiters();
        true
    }

    pub(super) fn remember_closed_locked(&self, state: &mut SessionState, stream_id: u32) {
        let evicted = remember_closed(state, stream_id, self.limits.max_tombstones_per_session);
        if !self.carrier().uses_lanes() {
            return;
        }
        if let Some(evicted) = evicted {
            self.release_lane_locked(state, evicted);
        }
        if let Some(lane) = state.carrier_lanes.get(&stream_id) {
            lane.notify.notify_waiters();
        }
    }

    pub(super) fn release_lane_locked(&self, state: &mut SessionState, lane_id: u32) {
        let Some(mut lane) = state.carrier_lanes.remove(&lane_id) else {
            return;
        };
        lane.notify.notify_waiters();
        let mut data_bytes = 0usize;
        let mut data_items = 0usize;
        let mut control_bytes = 0usize;
        let mut control_items = 0usize;
        for queued in lane.pending_frames.drain(..) {
            if queued.control {
                control_bytes = control_bytes.saturating_add(queued.cost);
                control_items = control_items.saturating_add(1);
            } else {
                data_bytes = data_bytes.saturating_add(queued.cost);
                data_items = data_items.saturating_add(1);
            }
        }
        if let Some(batch) = lane.unacked.take() {
            batch.lease.detach();
            self.release_local_locked(state, batch.data_bytes, batch.data_items, false);
            self.release_local_locked(state, batch.control_bytes, batch.control_items, true);
        }
        self.release_locked(state, data_bytes, data_items, false);
        self.release_locked(state, control_bytes, control_items, true);
        self.lane_open_notify.notify_waiters();
    }
}

struct LaneOpenWaitGuard<'a> {
    session: &'a WebSession,
    _auxiliary: OwnedSemaphorePermit,
}

impl Drop for LaneOpenWaitGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.session.state.lock();
        state.lane_open_waits = state.lane_open_waits.saturating_sub(1);
    }
}

// Lane-specific protocol, replay, and lifecycle tests.
#[cfg(test)]
mod tests;
