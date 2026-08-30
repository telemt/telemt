use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const CONTROL_TASK_ADMISSION_CLOSED: usize = 1 << (usize::BITS - 1);
const CONTROL_TASK_REGISTRATION_COUNT: usize = CONTROL_TASK_ADMISSION_CLOSED - 1;

struct ControlTaskAdmission {
    state: AtomicUsize,
    registrations_drained: Notify,
}

struct ControlTaskRegistration<'a> {
    admission: &'a ControlTaskAdmission,
}

impl ControlTaskAdmission {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            registrations_drained: Notify::new(),
        }
    }

    fn try_register(&self) -> Option<ControlTaskRegistration<'_>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & CONTROL_TASK_ADMISSION_CLOSED != 0
                || state & CONTROL_TASK_REGISTRATION_COUNT == CONTROL_TASK_REGISTRATION_COUNT
            {
                return None;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ControlTaskRegistration { admission: self }),
                Err(observed) => state = observed,
            }
        }
    }

    fn close(&self) {
        self.state
            .fetch_or(CONTROL_TASK_ADMISSION_CLOSED, Ordering::AcqRel);
    }

    async fn wait_for_registrations(&self) {
        loop {
            let notified = self.registrations_drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.load(Ordering::Acquire) & CONTROL_TASK_REGISTRATION_COUNT == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for ControlTaskRegistration<'_> {
    fn drop(&mut self) {
        let previous = self.admission.state.fetch_sub(1, Ordering::AcqRel);
        if previous & CONTROL_TASK_REGISTRATION_COUNT == 1 {
            self.admission.registrations_drained.notify_waiters();
        }
    }
}

struct ProcessControlPlaneInner {
    admission: ControlTaskAdmission,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    shutdown_completed: AtomicBool,
}

/// Process-owned cancellation and join scope for API, metrics, and signal tasks.
#[derive(Clone)]
pub(crate) struct ProcessControlPlane {
    inner: Arc<ProcessControlPlaneInner>,
}

impl ProcessControlPlane {
    /// Creates an open process control-plane scope.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ProcessControlPlaneInner {
                admission: ControlTaskAdmission::new(),
                cancellation: CancellationToken::new(),
                tasks: TaskTracker::new(),
                shutdown_completed: AtomicBool::new(false),
            }),
        }
    }

    /// Registers a cancellable process control-plane task before it can be unpolled.
    pub(crate) fn spawn<F>(&self, future: F) -> Result<(), F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(registration) = self.inner.admission.try_register() else {
            return Err(future);
        };
        let cancellation = self.inner.cancellation.clone();
        self.inner.tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {}
                _ = future => {}
            }
        });
        drop(registration);
        Ok(())
    }

    /// Closes task admission, cancels all owned work, and joins it within the deadline.
    pub(crate) async fn shutdown(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        self.inner.admission.close();
        self.inner.cancellation.cancel();
        self.inner.tasks.close();
        if self.inner.shutdown_completed.load(Ordering::Acquire) {
            return true;
        }
        let registrations_stopped =
            tokio::time::timeout_at(deadline, self.inner.admission.wait_for_registrations())
                .await
                .is_ok();
        let tasks_stopped = tokio::time::timeout_at(deadline, self.inner.tasks.wait())
            .await
            .is_ok();
        let outcome = registrations_stopped && tasks_stopped;
        if outcome {
            self.inner.shutdown_completed.store(true, Ordering::Release);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn shutdown_cancels_owned_tasks_and_rejects_late_registration() {
        struct DropSignal(Arc<AtomicBool>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let scope = ProcessControlPlane::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let drop_signal = DropSignal(dropped.clone());
        assert!(
            scope
                .spawn(async move {
                    let _drop_signal = drop_signal;
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );

        assert!(scope.shutdown(Duration::from_secs(1)).await);
        assert!(dropped.load(Ordering::Acquire));
        assert!(scope.spawn(async {}).is_err());
    }

    #[tokio::test]
    async fn concurrent_shutdown_callers_wait_for_completion() {
        let scope = ProcessControlPlane::new();
        let registration = scope.inner.admission.try_register().unwrap();
        let first_scope = scope.clone();
        let first = tokio::spawn(async move { first_scope.shutdown(Duration::from_secs(1)).await });
        tokio::task::yield_now().await;
        let second_scope = scope.clone();
        let second =
            tokio::spawn(async move { second_scope.shutdown(Duration::from_secs(1)).await });

        tokio::task::yield_now().await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        drop(registration);

        assert!(first.await.unwrap());
        assert!(second.await.unwrap());
    }

    #[tokio::test]
    async fn cancelled_shutdown_caller_cannot_orphan_the_control_plane() {
        let scope = ProcessControlPlane::new();
        let registration = scope.inner.admission.try_register().unwrap();
        let first_scope = scope.clone();
        let first =
            tokio::spawn(async move { first_scope.shutdown(Duration::from_secs(30)).await });
        tokio::task::yield_now().await;

        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(scope.spawn(async {}).is_err());
        drop(registration);

        assert!(scope.shutdown(Duration::from_secs(1)).await);
    }
}
