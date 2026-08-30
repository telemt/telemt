use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{SessionNegotiationPhase, WebSession};

struct ReleasedQueues {
    data_bytes: usize,
    data_items: usize,
    control_bytes: usize,
    control_items: usize,
}

/// Deferred queue release after manager publication linearizes a supersede.
#[must_use]
pub(crate) struct CarrierSupersedeCompletion<'a> {
    session: &'a WebSession,
    released: ReleasedQueues,
}

impl CarrierSupersedeCompletion<'_> {
    /// Releases process budgets and signals cancellation after manager locks are dropped.
    pub(crate) fn finish(self) {
        self.session.finish_close(self.released, true);
    }
}

impl WebSession {
    /// Closes carrier state while relay tasks retain their admission until exit.
    pub(crate) fn close(&self) {
        let Some(released) = self.begin_close(false, None) else {
            return;
        };
        self.finish_close(released, false);
    }

    /// Atomically prevents first-frame commit while one successor is prepared.
    pub(crate) fn begin_carrier_supersede(&self) -> bool {
        let mut state = self.state.lock();
        if state.closed || state.close_requested {
            return false;
        }
        match state.negotiation_phase {
            SessionNegotiationPhase::Uncommitted => {
                state.negotiation_phase = SessionNegotiationPhase::Replacing;
                true
            }
            SessionNegotiationPhase::Replacing
            | SessionNegotiationPhase::Committed
            | SessionNegotiationPhase::Superseded => false,
        }
    }

    /// Restores an uncommitted attempt after successor admission failed.
    pub(crate) fn cancel_carrier_supersede(&self) {
        let close_requested = {
            let mut state = self.state.lock();
            if !state.closed && state.negotiation_phase == SessionNegotiationPhase::Replacing {
                state.negotiation_phase = SessionNegotiationPhase::Uncommitted;
            }
            state.close_requested
        };
        if close_requested {
            self.close();
        }
    }

    /// Linearizes manager publication against close requests on the old token.
    pub(crate) fn prepare_carrier_supersede(&self) -> Option<CarrierSupersedeCompletion<'_>> {
        let released = self.begin_close(true, None)?;
        Some(CarrierSupersedeCompletion {
            session: self,
            released,
        })
    }

    /// Waits for all logical-stream tasks after admission has closed.
    pub(crate) async fn wait(&self) {
        loop {
            let notified = self.tasks_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.tasks_live.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Returns the current number of registered logical-stream tasks.
    pub(crate) fn tasks_live(&self) -> usize {
        self.tasks_live.load(Ordering::Acquire)
    }

    /// Atomically closes a session only when reconnect grace is still due.
    pub(crate) fn close_if_due(&self, now: Instant) -> bool {
        let healthy = {
            let mut state = self.state.lock();
            self.carrier_health_ready_locked(&mut state, now)
        };
        if healthy {
            self.finish_carrier_health();
        }
        let Some(released) = self.begin_close(false, Some(now)) else {
            return false;
        };
        self.finish_close(released, false);
        true
    }

    fn begin_close(&self, superseded: bool, idle_now: Option<Instant>) -> Option<ReleasedQueues> {
        let mut state = self.state.lock();
        if state.closed
            || (superseded
                && (state.negotiation_phase != SessionNegotiationPhase::Replacing
                    || state.close_requested))
        {
            return None;
        }
        if let Some(now) = idle_now
            && (state.negotiation_phase == SessionNegotiationPhase::Replacing
                || now.saturating_duration_since(state.last_activity)
                    < Duration::from_secs(self.timeouts.reconnect_grace_secs))
        {
            return None;
        }
        if !superseded && state.negotiation_phase == SessionNegotiationPhase::Replacing {
            state.close_requested = true;
            return None;
        }
        state.closed = true;
        if superseded {
            state.negotiation_phase = SessionNegotiationPhase::Superseded;
        }
        for stream in state.streams.values_mut() {
            if let Some(waker) = stream.read_waker.take() {
                waker.wake();
            }
            if let Some(waker) = stream.write_waker.take() {
                waker.wake();
            }
        }
        state.streams.clear();
        state.pending_frames.clear();
        state.pending_windows.clear();
        if let Some(batch) = state.unacked.take() {
            batch.lease.detach();
            self.release_local_locked(&mut state, batch.data_bytes, batch.data_items, false);
            self.release_local_locked(&mut state, batch.control_bytes, batch.control_items, true);
        }
        let mut lane_data_bytes = 0usize;
        let mut lane_data_items = 0usize;
        let mut lane_control_bytes = 0usize;
        let mut lane_control_items = 0usize;
        for lane in state.carrier_lanes.values_mut() {
            lane.notify.notify_waiters();
            if let Some(batch) = lane.unacked.take() {
                batch.lease.detach();
                lane_data_bytes = lane_data_bytes.saturating_add(batch.data_bytes);
                lane_data_items = lane_data_items.saturating_add(batch.data_items);
                lane_control_bytes = lane_control_bytes.saturating_add(batch.control_bytes);
                lane_control_items = lane_control_items.saturating_add(batch.control_items);
            }
        }
        self.release_local_locked(&mut state, lane_data_bytes, lane_data_items, false);
        self.release_local_locked(&mut state, lane_control_bytes, lane_control_items, true);
        state.carrier_lanes.clear();
        let control_bytes = state.pending_control_bytes;
        let control_items = state.pending_control_items;
        let data_bytes = state.pending_bytes.saturating_sub(control_bytes);
        let data_items = state.pending_items.saturating_sub(control_items);
        state.pending_bytes = 0;
        state.pending_items = 0;
        state.pending_control_bytes = 0;
        state.pending_control_items = 0;
        Some(ReleasedQueues {
            data_bytes,
            data_items,
            control_bytes,
            control_items,
        })
    }

    fn finish_close(&self, released: ReleasedQueues, superseded: bool) {
        self.cancel.cancel();
        if self.carrier().is_multiplexed() {
            self.down_notify.notify_waiters();
        }
        if self.carrier().uses_lanes() {
            self.lane_open_notify.notify_waiters();
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.release_pending(
                self.profile_key,
                released.data_bytes,
                released.data_items,
                false,
            );
            manager.release_pending(
                self.profile_key,
                released.control_bytes,
                released.control_items,
                true,
            );
            if !self.finished.swap(true, Ordering::AcqRel) {
                self.trace_lifecycle(
                    crate::web::trace::TraceLifecycleEvent::SessionClosed,
                    None,
                    Some(if superseded { "superseded" } else { "closed" }),
                );
                if !superseded {
                    manager.session_finished(
                        self.token_hash,
                        self.client_ip,
                        self.profile_key,
                        &self.profile.host,
                        Duration::from_secs(self.timeouts.bootstrap_lifetime_secs),
                    );
                }
            }
        }
    }
}
