use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, RwLock, Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::proxy::authenticated::ClientRuntimeDeps;
#[cfg(test)]
use crate::proxy::route_mode::RelayRouteMode;
use crate::proxy::route_mode::RouteRuntimeController;
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::tls_front::TlsFrontCache;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

const SESSION_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const BACKGROUND_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_ADMISSION_CLOSED: usize = 1 << (usize::BITS - 1);
const SESSION_REGISTRATION_COUNT: usize = SESSION_ADMISSION_CLOSED - 1;

struct SessionAdmission {
    state: AtomicUsize,
    registrations_drained: Notify,
}

struct SessionRegistration<'a> {
    admission: &'a SessionAdmission,
}

impl SessionAdmission {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            registrations_drained: Notify::new(),
        }
    }

    fn try_register(&self) -> Option<SessionRegistration<'_>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & SESSION_ADMISSION_CLOSED != 0
                || state & SESSION_REGISTRATION_COUNT == SESSION_REGISTRATION_COUNT
            {
                return None;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(SessionRegistration { admission: self }),
                Err(observed) => state = observed,
            }
        }
    }

    fn close(&self) {
        self.state
            .fetch_or(SESSION_ADMISSION_CLOSED, Ordering::AcqRel);
    }

    fn reopen(&self) {
        self.state
            .fetch_and(!SESSION_ADMISSION_CLOSED, Ordering::AcqRel);
    }

    async fn wait_for_registrations(&self) {
        loop {
            let notified = self.registrations_drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.load(Ordering::Acquire) & SESSION_REGISTRATION_COUNT == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for SessionRegistration<'_> {
    fn drop(&mut self) {
        let previous = self.admission.state.fetch_sub(1, Ordering::AcqRel);
        if previous & SESSION_REGISTRATION_COUNT == 1 {
            self.admission.registrations_drained.notify_waiters();
        }
    }
}

/// Process-visible control-plane receivers for one active runtime generation.
#[derive(Clone)]
pub(crate) struct RuntimeWatchState {
    pub(crate) generation_id: u64,
    pub(crate) config_rx: watch::Receiver<Arc<ProxyConfig>>,
    pub(crate) admission_rx: watch::Receiver<bool>,
}

/// Cancellation and join ownership for one generation's background tasks.
#[derive(Clone)]
pub(crate) struct RuntimeTaskScope {
    tracker: TaskTracker,
    cancel: CancellationToken,
    admission: Arc<SessionAdmission>,
}

impl RuntimeTaskScope {
    /// Creates an open generation-owned task scope.
    pub(crate) fn new() -> Self {
        Self {
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
            admission: Arc::new(SessionAdmission::new()),
        }
    }

    /// Spawns one task that is cancelled when the generation stops.
    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(_registration) = self.admission.try_register() else {
            return;
        };
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = future => {}
            }
        });
    }

    /// Returns the cancellation signal shared by generation-owned controllers.
    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Cancels the scope and waits within the bounded background-task budget.
    pub(crate) async fn stop(&self) {
        self.admission.close();
        self.admission.wait_for_registrations().await;
        self.cancel.cancel();
        self.tracker.close();
        let _ = tokio::time::timeout(BACKGROUND_STOP_TIMEOUT, self.tracker.wait()).await;
    }
}

/// Runtime-owned data plane and control-plane dependencies for one generation.
pub(crate) struct RuntimeGeneration {
    pub(crate) id: u64,
    pub(crate) config_rx: watch::Receiver<Arc<ProxyConfig>>,
    pub(crate) admission_rx: watch::Receiver<bool>,
    pub(crate) stats: Arc<Stats>,
    pub(crate) upstream_manager: Arc<UpstreamManager>,
    pub(crate) replay_checker: Arc<ReplayChecker>,
    pub(crate) buffer_pool: Arc<BufferPool>,
    pub(crate) rng: Arc<SecureRandom>,
    pub(crate) me_pool: Option<Arc<MePool>>,
    pub(crate) me_pool_runtime: Arc<RwLock<Option<Arc<MePool>>>>,
    pub(crate) route_runtime: Arc<RouteRuntimeController>,
    pub(crate) tls_cache: Option<Arc<TlsFrontCache>>,
    pub(crate) ip_tracker: Arc<UserIpTracker>,
    pub(crate) beobachten: Arc<BeobachtenStore>,
    pub(crate) proxy_shared: Arc<ProxySharedState>,
    pub(crate) max_connections: Arc<Semaphore>,
    background_tasks: RuntimeTaskScope,
    sessions: TaskTracker,
    session_cancel: CancellationToken,
    session_admission: SessionAdmission,
}

impl RuntimeGeneration {
    #[allow(clippy::too_many_arguments)]
    /// Builds one fully owned runtime generation.
    pub(crate) fn new(
        id: u64,
        config_rx: watch::Receiver<Arc<ProxyConfig>>,
        admission_rx: watch::Receiver<bool>,
        stats: Arc<Stats>,
        upstream_manager: Arc<UpstreamManager>,
        replay_checker: Arc<ReplayChecker>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        me_pool: Option<Arc<MePool>>,
        me_pool_runtime: Arc<RwLock<Option<Arc<MePool>>>>,
        route_runtime: Arc<RouteRuntimeController>,
        tls_cache: Option<Arc<TlsFrontCache>>,
        ip_tracker: Arc<UserIpTracker>,
        beobachten: Arc<BeobachtenStore>,
        proxy_shared: Arc<ProxySharedState>,
        max_connections: Arc<Semaphore>,
        background_tasks: RuntimeTaskScope,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            config_rx,
            admission_rx,
            stats,
            upstream_manager,
            replay_checker,
            buffer_pool,
            rng,
            me_pool,
            me_pool_runtime,
            route_runtime,
            tls_cache,
            ip_tracker,
            beobachten,
            proxy_shared,
            max_connections,
            background_tasks,
            sessions: TaskTracker::new(),
            session_cancel: CancellationToken::new(),
            session_admission: SessionAdmission::new(),
        })
    }

    /// Returns the latest hot-reloaded configuration for this generation.
    pub(crate) fn config(&self) -> Arc<ProxyConfig> {
        self.config_rx.borrow().clone()
    }

    /// Returns receivers used by process-scoped observers of this generation.
    pub(crate) fn watch_state(&self) -> RuntimeWatchState {
        RuntimeWatchState {
            generation_id: self.id,
            config_rx: self.config_rx.clone(),
            admission_rx: self.admission_rx.clone(),
        }
    }

    /// Returns the initial or asynchronously published Middle-End pool.
    pub(crate) async fn current_me_pool(&self) -> Option<Arc<MePool>> {
        if let Some(pool) = &self.me_pool {
            return Some(pool.clone());
        }
        self.me_pool_runtime.read().await.clone()
    }

    /// Pins all dependencies required by a client stream without retaining the generation.
    pub(crate) fn client_runtime_deps(&self) -> ClientRuntimeDeps {
        ClientRuntimeDeps {
            config: self.config(),
            stats: Arc::clone(&self.stats),
            upstream_manager: Arc::clone(&self.upstream_manager),
            buffer_pool: Arc::clone(&self.buffer_pool),
            rng: Arc::clone(&self.rng),
            me_pool: self.me_pool.clone(),
            me_pool_runtime: Some(Arc::clone(&self.me_pool_runtime)),
            route_runtime: Arc::clone(&self.route_runtime),
            ip_tracker: Arc::clone(&self.ip_tracker),
            shared: Arc::clone(&self.proxy_shared),
        }
    }

    /// Registers a session only while admission remains open.
    pub(crate) fn spawn_session<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.try_spawn_session(future).is_ok()
    }

    /// Registers one session or returns its unpolled future to the caller.
    pub(crate) fn try_spawn_session<F>(&self, future: F) -> Result<(), F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(_registration) = self.session_admission.try_register() else {
            return Err(future);
        };
        let cancel = self.session_cancel.clone();
        self.sessions.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = future => {}
            }
        });
        Ok(())
    }

    /// Closes admission while preserving already registered sessions.
    pub(crate) fn stop_accepting_sessions(&self) {
        self.session_admission.close();
    }

    /// Waits for registered sessions and cancels them when the deadline expires.
    pub(crate) async fn drain_sessions(&self, timeout: Duration) -> bool {
        self.stop_accepting_sessions();
        self.session_admission.wait_for_registrations().await;
        self.sessions.close();
        if tokio::time::timeout(timeout, self.sessions.wait())
            .await
            .is_ok()
        {
            return true;
        }
        self.stop_sessions().await;
        false
    }

    /// Cancels all sessions and waits within the bounded session-stop budget.
    pub(crate) async fn stop_sessions(&self) {
        self.stop_accepting_sessions();
        self.session_admission.wait_for_registrations().await;
        self.session_cancel.cancel();
        self.sessions.close();
        let _ = tokio::time::timeout(SESSION_STOP_TIMEOUT, self.sessions.wait()).await;
    }

    /// Stops all background tasks owned by this generation.
    pub(crate) async fn stop_background_tasks(&self) {
        self.background_tasks.stop().await;
    }

    /// Terminally stops the generation's Middle-End task and writer scope.
    pub(crate) async fn stop_middle_end(&self, timeout: Duration) -> bool {
        let Some(pool) = self.current_me_pool().await else {
            return true;
        };
        pool.shutdown_until(timeout).await
    }
}

impl Drop for RuntimeGeneration {
    fn drop(&mut self) {
        if let Some(pool) = self.me_pool.as_ref() {
            pool.begin_shutdown();
        }
        if let Ok(pool) = self.me_pool_runtime.try_read()
            && let Some(pool) = pool.as_ref()
        {
            pool.begin_shutdown();
        }
    }
}

#[cfg(test)]
/// Builds a lightweight runtime generation without network startup tasks.
pub(crate) fn test_runtime_generation(id: u64, config: ProxyConfig) -> Arc<RuntimeGeneration> {
    let (_admission_tx, admission_rx) = watch::channel(true);
    test_runtime_generation_with_admission(id, config, admission_rx)
}

#[cfg(test)]
/// Builds a lightweight runtime generation with a controllable admission gate.
pub(crate) fn test_runtime_generation_with_admission(
    id: u64,
    config: ProxyConfig,
    admission_rx: watch::Receiver<bool>,
) -> Arc<RuntimeGeneration> {
    let (config_tx, config_rx) = watch::channel(Arc::new(config.clone()));
    let stats = Arc::new(Stats::new());
    let upstream_manager = Arc::new(UpstreamManager::new(
        config.upstreams,
        config.general.upstream_connect_retry_attempts,
        config.general.upstream_connect_retry_backoff_ms,
        config.general.upstream_connect_budget_ms,
        config.general.tg_connect,
        config.general.upstream_unhealthy_fail_threshold,
        config.general.upstream_connect_failfast_hard_errors,
        stats.clone(),
    ));
    let _config_tx = config_tx;
    RuntimeGeneration::new(
        id,
        config_rx,
        admission_rx,
        stats,
        upstream_manager,
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::with_config(4096, 16)),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RwLock::new(None)),
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        ProxySharedState::new(),
        Arc::new(Semaphore::new(64)),
        RuntimeTaskScope::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn stop_sessions_cancels_tracked_future() {
        let generation = test_runtime_generation(1, ProxyConfig::default());
        let started = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(tokio::sync::Notify::new());
        let started_task = started.clone();
        let dropped_task = dropped.clone();
        assert!(generation.spawn_session(async move {
            struct DropSignal(Arc<tokio::sync::Notify>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.notify_one();
                }
            }
            let _drop_signal = DropSignal(dropped_task);
            started_task.notify_one();
            std::future::pending::<()>().await;
        }));
        started.notified().await;

        generation.stop_sessions().await;

        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .unwrap();
        assert!(!generation.spawn_session(async {}));
    }

    #[tokio::test]
    async fn runtime_task_scope_joins_cancelled_background_task() {
        struct DropSignal(Arc<AtomicUsize>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        let scope = RuntimeTaskScope::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        let drop_signal = DropSignal(dropped.clone());
        scope.spawn(async move {
            let _drop_signal = drop_signal;
            std::future::pending::<()>().await;
        });
        tokio::time::timeout(Duration::from_secs(1), scope.stop())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::Acquire), 1);

        let late_drop_signal = DropSignal(dropped.clone());
        scope.spawn(async move {
            let _late_drop_signal = late_drop_signal;
        });
        assert_eq!(dropped.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn session_admission_waits_for_registration_started_before_cutover() {
        let admission = Arc::new(SessionAdmission::new());
        let registration = admission.try_register().unwrap();
        admission.close();
        assert!(admission.try_register().is_none());

        let wait_admission = admission.clone();
        let waiter = tokio::spawn(async move {
            wait_admission.wait_for_registrations().await;
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(registration);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();

        admission.reopen();
        assert!(admission.try_register().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cutover_never_leaves_late_session_registrations() {
        const ATTEMPTS: usize = 10_000;

        let admission = Arc::new(SessionAdmission::new());
        let tracker = TaskTracker::new();
        let cancel = CancellationToken::new();
        let start = Arc::new(Barrier::new(ATTEMPTS + 1));
        let live = Arc::new(AtomicUsize::new(0));
        let mut attempts = tokio::task::JoinSet::new();

        for _ in 0..ATTEMPTS {
            let admission = admission.clone();
            let tracker = tracker.clone();
            let cancel = cancel.clone();
            let start = start.clone();
            let live = live.clone();
            attempts.spawn(async move {
                start.wait().await;
                let Some(_registration) = admission.try_register() else {
                    return;
                };
                tracker.spawn(async move {
                    live.fetch_add(1, Ordering::AcqRel);
                    cancel.cancelled().await;
                    live.fetch_sub(1, Ordering::AcqRel);
                });
            });
        }

        start.wait().await;
        admission.close();
        admission.wait_for_registrations().await;
        tracker.close();
        cancel.cancel();
        while attempts.join_next().await.is_some() {}
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();

        assert_eq!(live.load(Ordering::Acquire), 0);
        assert!(admission.try_register().is_none());
    }
}
