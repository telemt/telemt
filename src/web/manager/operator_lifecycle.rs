use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;

use super::WebProcessRuntime;

// Serialized state-machine values stay separate from synchronization mechanics.
mod status;
pub(crate) use status::{
    OperatorDrainOutcome, OperatorDrainState, OperatorDrainStatus, OperatorLifecycleState,
    OperatorLifecycleStatus,
};
// Mutable and published lifecycle state storage.
mod state;
use state::{ActiveDrain, OperatorLifecycleInner, OperatorSnapshot, WorkCounts};

const OPERATOR_ADMISSION_CLOSED: usize = 1 << (usize::BITS - 1);
const OPERATOR_REGISTRATION_COUNT: usize = OPERATOR_ADMISSION_CLOSED - 1;
const DRAIN_REF_VERSION: &str = "wd1";

/// Stable operator-control rejection category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperatorLifecycleError {
    /// Process shutdown terminally closed the command gate.
    Closed,
    /// One drain already owns the single active operation slot.
    OperationInProgress,
}

struct OperatorAdmission {
    state: AtomicUsize,
    registrations_drained: Notify,
}

pub(super) struct OperatorRegistration<'a> {
    admission: &'a OperatorAdmission,
}

impl OperatorAdmission {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            registrations_drained: Notify::new(),
        }
    }

    fn try_register(&self) -> Option<OperatorRegistration<'_>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & OPERATOR_ADMISSION_CLOSED != 0
                || state & OPERATOR_REGISTRATION_COUNT == OPERATOR_REGISTRATION_COUNT
            {
                return None;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(OperatorRegistration { admission: self }),
                Err(observed) => state = observed,
            }
        }
    }

    fn close(&self) {
        self.state
            .fetch_or(OPERATOR_ADMISSION_CLOSED, Ordering::AcqRel);
    }

    fn reopen(&self) {
        self.state
            .fetch_and(!OPERATOR_ADMISSION_CLOSED, Ordering::AcqRel);
    }

    fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & OPERATOR_ADMISSION_CLOSED != 0
    }

    async fn wait_for_registrations(&self) {
        loop {
            let notified = self.registrations_drained.notified();
            if self.state.load(Ordering::Acquire) & OPERATOR_REGISTRATION_COUNT == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for OperatorRegistration<'_> {
    fn drop(&mut self) {
        let previous = self.admission.state.fetch_sub(1, Ordering::AcqRel);
        if previous & OPERATOR_REGISTRATION_COUNT == 1 {
            self.admission.registrations_drained.notify_waiters();
        }
    }
}

pub(super) struct OperatorLifecycle {
    runtime_instance: Arc<str>,
    admission: OperatorAdmission,
    commands: AsyncMutex<()>,
    inner: Mutex<OperatorLifecycleInner>,
    published: ArcSwap<OperatorSnapshot>,
    work_changed: Notify,
    next_operation_id: AtomicU64,
}

impl OperatorLifecycle {
    pub(super) fn new(runtime_instance: Arc<str>) -> Self {
        let since = Instant::now();
        let snapshot = OperatorSnapshot {
            state: OperatorLifecycleState::Running,
            epoch: 0,
            since,
            terminal: false,
            drain: None,
        };
        Self {
            runtime_instance,
            admission: OperatorAdmission::new(),
            commands: AsyncMutex::new(()),
            inner: Mutex::new(OperatorLifecycleInner {
                state: snapshot.state,
                epoch: snapshot.epoch,
                since,
                terminal: false,
                active: None,
                drain: None,
            }),
            published: ArcSwap::from_pointee(snapshot),
            work_changed: Notify::new(),
            next_operation_id: AtomicU64::new(1),
        }
    }

    pub(super) fn try_register(&self) -> Option<OperatorRegistration<'_>> {
        self.admission.try_register()
    }

    pub(super) fn notify_work_changed(&self) {
        if self.admission.is_closed() {
            self.work_changed.notify_waiters();
        }
    }

    pub(super) fn status(&self, config_enabled: bool) -> OperatorLifecycleStatus {
        let snapshot = self.published.load();
        let admission_open =
            !snapshot.terminal && snapshot.state == OperatorLifecycleState::Running;
        OperatorLifecycleStatus {
            state: snapshot.state,
            epoch: snapshot.epoch,
            age_ms: millis(Instant::now().saturating_duration_since(snapshot.since)),
            admission_open,
            effective_new_work_admission: admission_open && config_enabled,
            drain: snapshot.drain.clone(),
        }
    }

    fn is_terminal(&self) -> bool {
        self.published.load().terminal
    }

    fn rejection_reason(&self) -> crate::web::telemetry::WebRejectionReason {
        let inner = self.inner.lock();
        if inner.terminal {
            return crate::web::telemetry::WebRejectionReason::RuntimeClosed;
        }
        match inner.state {
            OperatorLifecycleState::Paused => {
                crate::web::telemetry::WebRejectionReason::OperatorPaused
            }
            OperatorLifecycleState::Draining => {
                crate::web::telemetry::WebRejectionReason::OperatorDraining
            }
            OperatorLifecycleState::ForceClosing => {
                crate::web::telemetry::WebRejectionReason::OperatorForceClosing
            }
            OperatorLifecycleState::Drained => {
                crate::web::telemetry::WebRejectionReason::OperatorDrained
            }
            OperatorLifecycleState::Running => {
                crate::web::telemetry::WebRejectionReason::RuntimeClosed
            }
        }
    }

    fn publish_locked(&self, inner: &OperatorLifecycleInner) {
        self.published.store(Arc::new(OperatorSnapshot {
            state: inner.state,
            epoch: inner.epoch,
            since: inner.since,
            terminal: inner.terminal,
            drain: inner.drain.clone(),
        }));
    }

    fn transition_locked(&self, inner: &mut OperatorLifecycleInner, state: OperatorLifecycleState) {
        if inner.state != state {
            inner.state = state;
            inner.epoch = inner.epoch.saturating_add(1);
            inner.since = Instant::now();
        }
    }

    fn update_counts(&self, sequence: u64, counts: WorkCounts) -> bool {
        let mut inner = self.inner.lock();
        if inner
            .active
            .as_ref()
            .is_none_or(|active| active.sequence != sequence)
        {
            return false;
        }
        let Some(drain) = inner.drain.as_mut() else {
            return false;
        };
        if drain.remaining_sessions != counts.sessions
            || drain.remaining_streams != counts.streams
            || drain.remaining_websockets != counts.websockets
        {
            drain.remaining_sessions = counts.sessions;
            drain.remaining_streams = counts.streams;
            drain.remaining_websockets = counts.websockets;
            self.publish_locked(&inner);
        }
        true
    }

    fn commit_force(&self, sequence: u64, counts: WorkCounts) -> bool {
        let mut inner = self.inner.lock();
        if inner
            .active
            .as_ref()
            .is_none_or(|active| active.sequence != sequence)
        {
            return false;
        }
        self.transition_locked(&mut inner, OperatorLifecycleState::ForceClosing);
        let Some(drain) = inner.drain.as_mut() else {
            return false;
        };
        drain.state = OperatorDrainState::ForceClosing;
        drain.remaining_sessions = counts.sessions;
        drain.remaining_streams = counts.streams;
        drain.remaining_websockets = counts.websockets;
        drain.force_close_signalled = true;
        self.publish_locked(&inner);
        true
    }

    fn complete(&self, sequence: u64, forced: bool) {
        let mut inner = self.inner.lock();
        if inner
            .active
            .as_ref()
            .is_none_or(|active| active.sequence != sequence)
        {
            return;
        }
        inner.active = None;
        self.transition_locked(&mut inner, OperatorLifecycleState::Drained);
        if let Some(drain) = inner.drain.as_mut() {
            drain.state = OperatorDrainState::Completed;
            drain.outcome = Some(if forced {
                OperatorDrainOutcome::Forced
            } else {
                OperatorDrainOutcome::Graceful
            });
            drain.completed_epoch_millis = Some(crate::web::trace::store_epoch_millis());
            drain.remaining_sessions = 0;
            drain.remaining_streams = 0;
            drain.remaining_websockets = 0;
        }
        self.publish_locked(&inner);
    }

    fn close_terminal(&self) {
        let mut inner = self.inner.lock();
        self.admission.close();
        if inner.terminal {
            return;
        }
        inner.terminal = true;
        if let Some(active) = inner.active.take() {
            active.cancellation.cancel();
            if let Some(drain) = inner.drain.as_mut() {
                drain.state = OperatorDrainState::Cancelled;
                drain.outcome = Some(OperatorDrainOutcome::Cancelled);
                drain.completed_epoch_millis = Some(crate::web::trace::store_epoch_millis());
            }
        }
        self.publish_locked(&inner);
        self.work_changed.notify_waiters();
    }
}

impl WebProcessRuntime {
    /// Returns the current lock-free operator lifecycle snapshot.
    pub(crate) fn operator_lifecycle_status(&self) -> OperatorLifecycleStatus {
        let config_enabled = self.active_generation().config().web.enabled;
        self.operator_lifecycle.status(config_enabled)
    }

    /// Pauses new WEB work after every pre-cutover admission section completes.
    pub(crate) async fn pause_operator(
        self: &Arc<Self>,
    ) -> Result<OperatorLifecycleStatus, OperatorLifecycleError> {
        let _command = self.operator_lifecycle.commands.lock().await;
        {
            let mut inner = self.operator_lifecycle.inner.lock();
            if inner.terminal || self.shutdown.is_cancelled() {
                return Err(OperatorLifecycleError::Closed);
            }
            self.operator_lifecycle.admission.close();
            if matches!(
                inner.state,
                OperatorLifecycleState::Running | OperatorLifecycleState::Drained
            ) {
                self.operator_lifecycle
                    .transition_locked(&mut inner, OperatorLifecycleState::Paused);
            }
            self.operator_lifecycle.publish_locked(&inner);
        }
        self.operator_lifecycle
            .admission
            .wait_for_registrations()
            .await;
        if self.shutdown.is_cancelled() || self.operator_lifecycle.is_terminal() {
            return Err(OperatorLifecycleError::Closed);
        }
        Ok(self.operator_lifecycle_status())
    }

    /// Starts one asynchronous graceful WEB drain under an absolute deadline.
    pub(crate) async fn drain_operator(
        self: &Arc<Self>,
        timeout: Duration,
    ) -> Result<OperatorLifecycleStatus, OperatorLifecycleError> {
        let _command = self.operator_lifecycle.commands.lock().await;
        let sequence = self
            .operator_lifecycle
            .next_operation_id
            .fetch_add(1, Ordering::Relaxed);
        let cancellation = CancellationToken::new();
        let started = TokioInstant::now();
        let deadline = started + timeout;
        let started_epoch_millis = crate::web::trace::store_epoch_millis();
        {
            let mut inner = self.operator_lifecycle.inner.lock();
            if inner.terminal || self.shutdown.is_cancelled() {
                return Err(OperatorLifecycleError::Closed);
            }
            if inner.active.is_some()
                || matches!(
                    inner.state,
                    OperatorLifecycleState::Draining | OperatorLifecycleState::ForceClosing
                )
            {
                return Err(OperatorLifecycleError::OperationInProgress);
            }
            self.operator_lifecycle.admission.close();
            inner.active = Some(ActiveDrain {
                sequence,
                cancellation: cancellation.clone(),
            });
            inner.drain = Some(OperatorDrainStatus {
                operation_id: format!(
                    "{DRAIN_REF_VERSION}.{}.{sequence:016x}",
                    self.operator_lifecycle.runtime_instance
                ),
                state: OperatorDrainState::Draining,
                outcome: None,
                timeout_secs: timeout.as_secs(),
                started_epoch_millis,
                deadline_epoch_millis: started_epoch_millis
                    .saturating_add(timeout.as_millis().min(u128::from(u64::MAX)) as u64),
                completed_epoch_millis: None,
                remaining_sessions: 0,
                remaining_streams: 0,
                remaining_websockets: 0,
                force_close_signalled: false,
            });
            self.operator_lifecycle
                .transition_locked(&mut inner, OperatorLifecycleState::Draining);
            self.operator_lifecycle.publish_locked(&inner);
        }
        self.operator_lifecycle
            .admission
            .wait_for_registrations()
            .await;
        if self.shutdown.is_cancelled() || self.operator_lifecycle.is_terminal() {
            return Err(OperatorLifecycleError::Closed);
        }
        let counts = self.operator_work_counts();
        if !self.operator_lifecycle.update_counts(sequence, counts) {
            return Err(OperatorLifecycleError::Closed);
        }
        let runtime = Arc::clone(self);
        self.spawn_auxiliary(async move {
            runtime
                .run_operator_drain(sequence, deadline, cancellation)
                .await;
        });
        Ok(self.operator_lifecycle_status())
    }

    /// Resumes operator admission and invalidates any active drain waiter.
    pub(crate) async fn resume_operator(
        self: &Arc<Self>,
    ) -> Result<OperatorLifecycleStatus, OperatorLifecycleError> {
        let _command = self.operator_lifecycle.commands.lock().await;
        let counts = self.operator_work_counts();
        let mut inner = self.operator_lifecycle.inner.lock();
        if inner.terminal || self.shutdown.is_cancelled() {
            return Err(OperatorLifecycleError::Closed);
        }
        if let Some(active) = inner.active.take() {
            active.cancellation.cancel();
            if let Some(drain) = inner.drain.as_mut() {
                drain.state = OperatorDrainState::Cancelled;
                drain.outcome = Some(OperatorDrainOutcome::Cancelled);
                drain.completed_epoch_millis = Some(crate::web::trace::store_epoch_millis());
                drain.remaining_sessions = counts.sessions;
                drain.remaining_streams = counts.streams;
                drain.remaining_websockets = counts.websockets;
            }
        }
        self.operator_lifecycle
            .transition_locked(&mut inner, OperatorLifecycleState::Running);
        self.operator_lifecycle.admission.reopen();
        self.operator_lifecycle.publish_locked(&inner);
        drop(inner);
        self.operator_lifecycle.work_changed.notify_waiters();
        Ok(self.operator_lifecycle_status())
    }

    pub(super) fn try_operator_admission(
        &self,
    ) -> Result<OperatorRegistration<'_>, super::ManagerError> {
        match self.operator_lifecycle.try_register() {
            Some(registration) => Ok(registration),
            None => {
                self.telemetry
                    .record_rejection(self.operator_lifecycle.rejection_reason());
                Err(super::ManagerError::AdmissionPaused)
            }
        }
    }

    pub(super) fn notify_operator_work_changed(&self) {
        self.operator_lifecycle.notify_work_changed();
    }

    pub(super) fn close_operator_lifecycle(&self) {
        self.operator_lifecycle.close_terminal();
    }

    fn operator_work_counts(&self) -> WorkCounts {
        let sessions = self.state.lock().sessions.len();
        let streams = self.stream_admission.lock().streams_live;
        let websockets = self.websockets.lock().status().entries;
        WorkCounts {
            sessions,
            streams,
            websockets,
        }
    }

    async fn run_operator_drain(
        self: Arc<Self>,
        sequence: u64,
        deadline: TokioInstant,
        cancellation: CancellationToken,
    ) {
        let mut forced = false;
        loop {
            let notified = self.operator_lifecycle.work_changed.notified();
            let counts = self.operator_work_counts();
            if !self.operator_lifecycle.update_counts(sequence, counts) {
                return;
            }
            if counts.is_zero() {
                self.operator_lifecycle.complete(sequence, forced);
                return;
            }
            if forced {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return,
                    _ = notified => {}
                }
                continue;
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return,
                _ = notified => {},
                _ = tokio::time::sleep_until(deadline) => {
                    let counts = self.operator_work_counts();
                    if counts.is_zero() {
                        self.operator_lifecycle.complete(sequence, false);
                        return;
                    }
                    // Freeze the close set while admission is still closed. If resume
                    // wins the following epoch check, this snapshot is discarded.
                    let sessions = self
                        .state
                        .lock()
                        .sessions
                        .values()
                        .cloned()
                        .collect::<Vec<_>>();
                    if !self.operator_lifecycle.commit_force(sequence, counts) {
                        return;
                    }
                    forced = true;
                    for session in sessions {
                        session.close();
                    }
                }
            }
        }
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
#[path = "operator_lifecycle/tests.rs"]
mod tests;
