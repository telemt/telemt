use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::watch;

use super::manager::WebProcessRuntime;
use super::telemetry::WebTelemetry;

/// Process-owned WEB ingress lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WebRuntimeLifecycle {
    /// Listener orchestration has not completed.
    Starting,
    /// This process has no WEB listener.
    NoWebListener,
    /// WEB admission and request handling are active.
    Running,
    /// WEB admission is closed while owned work drains.
    Draining,
    /// All WEB ingress work drained within the deadline.
    Drained,
    /// The bounded shutdown deadline expired.
    DeadlineExceeded,
}

impl WebRuntimeLifecycle {
    /// Complete fixed lifecycle set used by one-hot metrics.
    pub(crate) const ALL: [Self; 6] = [
        Self::Starting,
        Self::NoWebListener,
        Self::Running,
        Self::Draining,
        Self::Drained,
        Self::DeadlineExceeded,
    ];

    /// Returns the stable API token for this lifecycle state.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::NoWebListener => "no_web_listener",
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Drained => "drained",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }
}

/// One immutable lifecycle publication consumed by the control plane.
#[derive(Clone)]
pub(crate) struct WebRuntimePublication {
    /// Monotonic process-local lifecycle transition number.
    pub(crate) epoch: u64,
    /// Current lifecycle state.
    pub(crate) lifecycle: WebRuntimeLifecycle,
    /// Monotonic transition time used only for relative age.
    pub(crate) since: Instant,
    /// Actual WEB listener addresses frozen for this process.
    pub(crate) listeners: Arc<[SocketAddr]>,
    /// Weak runtime access that never extends data-plane ownership.
    pub(crate) runtime: Weak<WebProcessRuntime>,
    /// Process-owned counters that remain readable after runtime release.
    pub(crate) telemetry: Arc<WebTelemetry>,
}

/// Single-writer process lifecycle publisher for WEB ingress.
#[derive(Clone)]
pub(crate) struct WebRuntimeControl {
    epoch: Arc<AtomicU64>,
    telemetry: Arc<WebTelemetry>,
    tx: watch::Sender<WebRuntimePublication>,
}

impl WebRuntimeControl {
    /// Creates the process channel in the pre-listener `starting` state.
    pub(crate) fn new() -> Self {
        let telemetry = WebTelemetry::new();
        let publication = WebRuntimePublication {
            epoch: 1,
            lifecycle: WebRuntimeLifecycle::Starting,
            since: Instant::now(),
            listeners: Arc::from([]),
            runtime: Weak::new(),
            telemetry: Arc::clone(&telemetry),
        };
        let (tx, _rx) = watch::channel(publication);
        Self {
            epoch: Arc::new(AtomicU64::new(1)),
            telemetry,
            tx,
        }
    }

    /// Subscribes without transferring runtime ownership to the receiver.
    pub(crate) fn subscribe(&self) -> watch::Receiver<WebRuntimePublication> {
        self.tx.subscribe()
    }

    /// Returns the shared process-owned WEB telemetry handle.
    pub(crate) fn telemetry(&self) -> Arc<WebTelemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Publishes one lifecycle transition and optional weak runtime reference.
    pub(crate) fn publish(
        &self,
        lifecycle: WebRuntimeLifecycle,
        listeners: Arc<[SocketAddr]>,
        runtime: Weak<WebProcessRuntime>,
    ) {
        let epoch = self.epoch.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        self.tx.send_replace(WebRuntimePublication {
            epoch,
            lifecycle,
            since: Instant::now(),
            listeners,
            runtime,
            telemetry: Arc::clone(&self.telemetry),
        });
    }
}

impl Default for WebRuntimeControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_is_monotonic_and_does_not_require_a_runtime_owner() {
        let control = WebRuntimeControl::new();
        let receiver = control.subscribe();
        control.publish(
            WebRuntimeLifecycle::NoWebListener,
            Arc::from([]),
            Weak::new(),
        );

        let publication = receiver.borrow().clone();
        assert_eq!(publication.epoch, 2);
        assert_eq!(publication.lifecycle, WebRuntimeLifecycle::NoWebListener);
        assert!(publication.runtime.upgrade().is_none());
    }

    #[tokio::test]
    async fn publication_keeps_only_weak_runtime_ownership() {
        let generation = crate::maestro::generation::test_runtime_generation(
            1,
            crate::config::ProxyConfig::default(),
        );
        let runtime =
            WebProcessRuntime::start(Arc::new(arc_swap::ArcSwap::from(generation.clone())));
        let strong_before = Arc::strong_count(&runtime);
        let control = WebRuntimeControl::new();
        control.publish(
            WebRuntimeLifecycle::Running,
            Arc::from([]),
            Arc::downgrade(&runtime),
        );

        assert_eq!(Arc::strong_count(&runtime), strong_before);
        runtime.shutdown().await;
        drop(runtime);
        assert!(control.subscribe().borrow().runtime.upgrade().is_none());
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
