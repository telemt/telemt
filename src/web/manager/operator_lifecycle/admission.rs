use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

use super::OperatorLifecycleState;

const OPERATOR_ADMISSION_CLOSED: usize = 1 << (usize::BITS - 1);
const OPERATOR_REJECTION_BITS: u32 = 3;
const OPERATOR_REJECTION_SHIFT: u32 = usize::BITS - 1 - OPERATOR_REJECTION_BITS;
const OPERATOR_REJECTION_MASK: usize =
    ((1usize << OPERATOR_REJECTION_BITS) - 1) << OPERATOR_REJECTION_SHIFT;
const OPERATOR_REGISTRATION_COUNT: usize = (1usize << OPERATOR_REJECTION_SHIFT) - 1;

#[derive(Clone, Copy)]
#[repr(usize)]
/// Stable rejection encoded into the closed admission-fence word.
pub(super) enum OperatorAdmissionRejection {
    /// Operator pause closed admission.
    Paused = 1,
    /// Graceful drain closed admission.
    Draining = 2,
    /// Deadline-triggered forced closure remains in progress.
    ForceClosing = 3,
    /// The latest drain reached confirmed zero.
    Drained = 4,
    /// Terminal process shutdown closed admission.
    RuntimeClosed = 5,
}

impl OperatorAdmissionRejection {
    /// Maps a closed lifecycle state to its admission rejection.
    pub(super) fn for_state(state: OperatorLifecycleState) -> Self {
        match state {
            OperatorLifecycleState::Paused => Self::Paused,
            OperatorLifecycleState::Draining => Self::Draining,
            OperatorLifecycleState::ForceClosing => Self::ForceClosing,
            OperatorLifecycleState::Drained => Self::Drained,
            OperatorLifecycleState::Running => Self::RuntimeClosed,
        }
    }

    fn from_admission_state(state: usize) -> Self {
        match (state & OPERATOR_REJECTION_MASK) >> OPERATOR_REJECTION_SHIFT {
            value if value == Self::Paused as usize => Self::Paused,
            value if value == Self::Draining as usize => Self::Draining,
            value if value == Self::ForceClosing as usize => Self::ForceClosing,
            value if value == Self::Drained as usize => Self::Drained,
            _ => Self::RuntimeClosed,
        }
    }

    fn telemetry_reason(self) -> crate::web::telemetry::WebRejectionReason {
        match self {
            Self::Paused => crate::web::telemetry::WebRejectionReason::OperatorPaused,
            Self::Draining => crate::web::telemetry::WebRejectionReason::OperatorDraining,
            Self::ForceClosing => {
                crate::web::telemetry::WebRejectionReason::OperatorForceClosing
            }
            Self::Drained => crate::web::telemetry::WebRejectionReason::OperatorDrained,
            Self::RuntimeClosed => crate::web::telemetry::WebRejectionReason::RuntimeClosed,
        }
    }
}

/// Lock-free admission fence with bounded pre-cutover registration tracking.
pub(super) struct OperatorAdmission {
    state: AtomicUsize,
    registrations_drained: Notify,
}

/// RAII ownership of one synchronous pre-cutover admission section.
pub(in crate::web::manager) struct OperatorRegistration<'a> {
    admission: &'a OperatorAdmission,
}

impl OperatorAdmission {
    /// Creates an open admission fence.
    pub(super) fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            registrations_drained: Notify::new(),
        }
    }

    /// Registers one pre-cutover section or returns its stable rejection reason.
    pub(super) fn try_register(
        &self,
    ) -> Result<OperatorRegistration<'_>, crate::web::telemetry::WebRejectionReason> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & OPERATOR_ADMISSION_CLOSED != 0 {
                return Err(
                    OperatorAdmissionRejection::from_admission_state(state).telemetry_reason(),
                );
            }
            if state & OPERATOR_REGISTRATION_COUNT == OPERATOR_REGISTRATION_COUNT {
                return Err(crate::web::telemetry::WebRejectionReason::Concurrent);
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(OperatorRegistration { admission: self }),
                Err(observed) => state = observed,
            }
        }
    }

    /// Atomically closes admission while preserving active registration count.
    pub(super) fn close(&self, reason: OperatorAdmissionRejection) {
        let reason = (reason as usize) << OPERATOR_REJECTION_SHIFT;
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            let next = (state & OPERATOR_REGISTRATION_COUNT)
                | OPERATOR_ADMISSION_CLOSED
                | reason;
            match self.state.compare_exchange_weak(
                state,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => state = observed,
            }
        }
    }

    /// Reopens admission without altering active registration ownership.
    pub(super) fn reopen(&self) {
        self.state.fetch_and(
            !(OPERATOR_ADMISSION_CLOSED | OPERATOR_REJECTION_MASK),
            Ordering::AcqRel,
        );
    }

    /// Returns whether the admission fence is closed.
    pub(super) fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & OPERATOR_ADMISSION_CLOSED != 0
    }

    /// Waits until every pre-cutover registration has been released.
    pub(super) async fn wait_for_registrations(&self) {
        loop {
            let notified = self.registrations_drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
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
