use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{RwLock, Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
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

/// Cancellation and join ownership for one generation's background tasks.
#[derive(Clone)]
pub(crate) struct RuntimeTaskScope {
    tracker: TaskTracker,
    cancel: CancellationToken,
}

impl RuntimeTaskScope {
    pub(crate) fn new() -> Self {
        Self {
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
        }
    }

    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = future => {}
            }
        });
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub(crate) async fn stop(&self) {
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
    accepting_sessions: AtomicBool,
}

impl RuntimeGeneration {
    #[allow(clippy::too_many_arguments)]
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
            accepting_sessions: AtomicBool::new(true),
        })
    }

    pub(crate) fn config(&self) -> Arc<ProxyConfig> {
        self.config_rx.borrow().clone()
    }

    pub(crate) async fn current_me_pool(&self) -> Option<Arc<MePool>> {
        if let Some(pool) = &self.me_pool {
            return Some(pool.clone());
        }
        self.me_pool_runtime.read().await.clone()
    }

    pub(crate) fn spawn_session<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !self.accepting_sessions.load(Ordering::Acquire) {
            return false;
        }
        let cancel = self.session_cancel.clone();
        self.sessions.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = future => {}
            }
        });
        true
    }

    pub(crate) fn stop_accepting_sessions(&self) {
        self.accepting_sessions.store(false, Ordering::Release);
    }

    pub(crate) fn resume_accepting_sessions(&self) {
        self.accepting_sessions.store(true, Ordering::Release);
    }

    pub(crate) async fn drain_sessions(&self, timeout: Duration) -> bool {
        self.stop_accepting_sessions();
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

    pub(crate) async fn stop_sessions(&self) {
        self.stop_accepting_sessions();
        self.session_cancel.cancel();
        self.sessions.close();
        let _ = tokio::time::timeout(SESSION_STOP_TIMEOUT, self.sessions.wait()).await;
    }

    pub(crate) async fn stop_background_tasks(&self) {
        self.background_tasks.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_sessions_cancels_tracked_future() {
        let tracker = TaskTracker::new();
        let cancel = CancellationToken::new();
        let child_cancel = cancel.clone();
        tracker.spawn(async move {
            child_cancel.cancelled().await;
        });
        cancel.cancel();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn runtime_task_scope_joins_cancelled_background_task() {
        let scope = RuntimeTaskScope::new();
        scope.spawn(std::future::pending());
        tokio::time::timeout(Duration::from_secs(1), scope.stop())
            .await
            .unwrap();
    }
}
