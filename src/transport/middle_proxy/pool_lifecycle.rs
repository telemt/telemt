use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::pool::MePool;
use super::registry::ConnLease;

const ME_TASK_ADMISSION_CLOSED: usize = 1 << (usize::BITS - 1);
const ME_TASK_REGISTRATION_COUNT: usize = ME_TASK_ADMISSION_CLOSED - 1;

struct MeTaskAdmission {
    state: AtomicUsize,
    registrations_drained: Notify,
}

/// RAII ownership of one ME task-publication section.
pub(super) struct MeTaskRegistration<'a> {
    admission: &'a MeTaskAdmission,
}

impl MeTaskAdmission {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            registrations_drained: Notify::new(),
        }
    }

    fn try_register(&self) -> Option<MeTaskRegistration<'_>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & ME_TASK_ADMISSION_CLOSED != 0
                || state & ME_TASK_REGISTRATION_COUNT == ME_TASK_REGISTRATION_COUNT
            {
                return None;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(MeTaskRegistration { admission: self }),
                Err(observed) => state = observed,
            }
        }
    }

    fn close(&self) {
        self.state
            .fetch_or(ME_TASK_ADMISSION_CLOSED, Ordering::AcqRel);
    }

    async fn wait_for_registrations(&self) {
        loop {
            let notified = self.registrations_drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.load(Ordering::Acquire) & ME_TASK_REGISTRATION_COUNT == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for MeTaskRegistration<'_> {
    fn drop(&mut self) {
        let previous = self.admission.state.fetch_sub(1, Ordering::AcqRel);
        if previous & ME_TASK_REGISTRATION_COUNT == 1 {
            self.admission.registrations_drained.notify_waiters();
        }
    }
}

/// Pool-owned admission, cancellation, and join authority for ME tasks.
pub(super) struct MePoolLifecycle {
    admission: MeTaskAdmission,
    producer_cancel: CancellationToken,
    producer_tasks: TaskTracker,
    writer_tasks: TaskTracker,
    cleanup_cancel: CancellationToken,
    cleanup_tasks: TaskTracker,
    cleanup_started: AtomicBool,
    shutdown_started: AtomicBool,
}

impl MePoolLifecycle {
    /// Creates an open ME task lifecycle.
    pub(super) fn new() -> Self {
        Self {
            admission: MeTaskAdmission::new(),
            producer_cancel: CancellationToken::new(),
            producer_tasks: TaskTracker::new(),
            writer_tasks: TaskTracker::new(),
            cleanup_cancel: CancellationToken::new(),
            cleanup_tasks: TaskTracker::new(),
            cleanup_started: AtomicBool::new(false),
            shutdown_started: AtomicBool::new(false),
        }
    }

    /// Registers one task-publication section while lifecycle admission is open.
    pub(super) fn try_register(&self) -> Option<MeTaskRegistration<'_>> {
        self.admission.try_register()
    }

    /// Registers and spawns one cancellation-aware ME producer.
    pub(super) fn spawn_producer<F>(&self, future: F) -> Result<(), F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(registration) = self.try_register() else {
            return Err(future);
        };
        self.spawn_registered_producer(registration, future);
        Ok(())
    }

    /// Spawns a producer after its caller published cancellation cleanup ownership.
    pub(super) fn spawn_registered_producer<F>(
        &self,
        registration: MeTaskRegistration<'_>,
        future: F,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancel = self.producer_cancel.clone();
        self.producer_tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = future => {}
            }
        });
        drop(registration);
    }

    /// Spawns a writer after its caller completed task registration.
    pub(super) fn spawn_registered_writer<F>(&self, registration: MeTaskRegistration<'_>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.writer_tasks.spawn(future);
        drop(registration);
    }

    fn start_cleanup_worker(&self, pool: &Arc<MePool>) -> bool {
        let Some(registration) = self.try_register() else {
            return false;
        };
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return true;
        }
        let Some(mut cleanup_rx) = pool.registry.take_cleanup_receiver() else {
            self.cleanup_started.store(false, Ordering::Release);
            return false;
        };
        let registry = Arc::clone(&pool.registry);
        let cancel = self.cleanup_cancel.clone();
        self.cleanup_tasks.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    cleanup = cleanup_rx.recv() => {
                        let Some(conn_id) = cleanup else {
                            return;
                        };
                        registry.unregister(conn_id).await;
                    }
                    _ = cancel.cancelled() => {
                        while let Ok(conn_id) = cleanup_rx.try_recv() {
                            registry.unregister(conn_id).await;
                        }
                        return;
                    }
                }
            }
        });
        drop(registration);
        true
    }

    /// Idempotently closes task admission and cancels ME producers.
    pub(super) fn begin_shutdown(&self) {
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.admission.close();
        self.producer_cancel.cancel();
    }

    async fn wait_until<F>(deadline: tokio::time::Instant, future: F) -> bool
    where
        F: Future<Output = ()>,
    {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        tokio::time::timeout_at(deadline, future).await.is_ok()
    }

    /// Joins producers, writers, and cleanup ownership under one deadline.
    pub(super) async fn shutdown_pool(&self, pool: &Arc<MePool>, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        self.begin_shutdown();
        pool.set_runtime_ready(false);

        let registrations_stopped =
            Self::wait_until(deadline, self.admission.wait_for_registrations()).await;

        self.producer_tasks.close();
        let producers_stopped = Self::wait_until(deadline, self.producer_tasks.wait()).await;

        let close_signals_sent = if tokio::time::Instant::now() < deadline {
            tokio::time::timeout_at(deadline, pool.shutdown_send_close_conn_all())
                .await
                .is_ok()
        } else {
            false
        };

        let writers = pool.writers.snapshot();
        for writer in writers.iter() {
            writer.cancel.cancel();
        }
        self.writer_tasks.close();
        let writers_stopped = Self::wait_until(deadline, self.writer_tasks.wait()).await;

        self.cleanup_cancel.cancel();
        self.cleanup_tasks.close();
        let cleanup_stopped = Self::wait_until(deadline, self.cleanup_tasks.wait()).await;

        registrations_stopped
            && producers_stopped
            && close_signals_sent
            && writers_stopped
            && cleanup_stopped
    }
}

impl MePool {
    /// Registers one cancellation-safe client route in the bounded cleanup plane.
    pub(crate) async fn register_connection(
        self: &Arc<Self>,
    ) -> Option<(ConnLease, mpsc::Receiver<super::MeResponse>)> {
        if !self.lifecycle.start_cleanup_worker(self) {
            return None;
        }
        let registration = self.lifecycle.try_register()?;
        let registered = tokio::select! {
            biased;
            _ = self.lifecycle.producer_cancel.cancelled() => None,
            registered = self.registry.register_leased() => registered,
        };
        drop(registration);
        registered
    }

    /// Closes ME task admission and joins pool-owned producers and writers.
    pub(crate) async fn shutdown_until(self: &Arc<Self>, timeout: Duration) -> bool {
        self.lifecycle.shutdown_pool(self, timeout).await
    }

    /// Terminally closes ME task admission without waiting for asynchronous teardown.
    pub(crate) fn begin_shutdown(&self) {
        self.lifecycle.begin_shutdown();
        self.set_runtime_ready(false);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::MePoolLifecycle;

    #[tokio::test]
    async fn shutdown_fence_rejects_late_producer_registration() {
        struct DropSignal(Arc<AtomicBool>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let lifecycle = Arc::new(MePoolLifecycle::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let drop_signal = DropSignal(dropped.clone());
        let spawned = lifecycle.spawn_producer(async move {
            let _drop_signal = drop_signal;
            std::future::pending::<()>().await;
        });
        assert!(spawned.is_ok());

        lifecycle.begin_shutdown();
        lifecycle.producer_tasks.close();
        tokio::time::timeout(Duration::from_secs(1), lifecycle.producer_tasks.wait())
            .await
            .unwrap();

        assert!(dropped.load(Ordering::Acquire));
        assert!(lifecycle.spawn_producer(async {}).is_err());
    }
}
