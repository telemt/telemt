use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::maestro::generation::RuntimeWatchState;

mod command;
mod iptables;
mod model;
mod nftables;
mod pf;

use self::command::has_firewall_privileges;
use self::model::{SynLimitNamespace, synlimit_namespace, synlimit_targets};

static ACTIVE_SYNLIMIT_NAMESPACE: Mutex<Option<SynLimitNamespace>> = Mutex::new(None);

/// Process-owned lifecycle handle for the SYN limiter reconciler.
pub(crate) struct SynlimitController {
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl SynlimitController {
    /// Stops config observation after any in-flight reconcile completes.
    pub(crate) async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.join.await;
    }
}

/// Spawns the process-scoped SYN limiter reconciler for active generations.
pub(crate) fn spawn_synlimit_controller(
    runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
) -> SynlimitController {
    let shutdown = CancellationToken::new();
    let join = tokio::spawn(watch_active_runtime_configs(
        runtime_watch_rx,
        shutdown.clone(),
        |_generation_id, cfg| async move {
            reconcile_synlimit_rules(&cfg).await;
        },
    ));
    SynlimitController { shutdown, join }
}

async fn watch_active_runtime_configs<F, Fut>(
    mut runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
    shutdown: CancellationToken,
    mut on_config: F,
) where
    F: FnMut(u64, Arc<ProxyConfig>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut current = loop {
        if let Some(state) = runtime_watch_rx.borrow().clone() {
            break state;
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            changed = runtime_watch_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    };
    if shutdown.is_cancelled() {
        return;
    }
    let initial_config = current.config_rx.borrow().clone();
    on_config(current.generation_id, initial_config).await;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            changed = runtime_watch_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let Some(next) = runtime_watch_rx.borrow().clone() else {
                    continue;
                };
                if next.generation_id != current.generation_id {
                    current = next;
                    let config = current.config_rx.borrow().clone();
                    on_config(current.generation_id, config).await;
                }
            }
            changed = current.config_rx.changed() => {
                if changed.is_err() {
                        let Some(next) = wait_for_new_runtime(
                            &mut runtime_watch_rx,
                            current.generation_id,
                            &shutdown,
                        ).await else {
                        break;
                    };
                    current = next;
                    let config = current.config_rx.borrow().clone();
                    on_config(current.generation_id, config).await;
                    continue;
                }
                let active_generation_id = runtime_watch_rx
                    .borrow()
                    .as_ref()
                    .map(|state| state.generation_id);
                if active_generation_id == Some(current.generation_id) {
                    let cfg = current.config_rx.borrow_and_update().clone();
                    on_config(current.generation_id, cfg).await;
                }
            }
        }
    }
}

async fn wait_for_new_runtime(
    runtime_watch_rx: &mut watch::Receiver<Option<RuntimeWatchState>>,
    previous_generation_id: u64,
    shutdown: &CancellationToken,
) -> Option<RuntimeWatchState> {
    loop {
        if let Some(state) = runtime_watch_rx.borrow().clone()
            && state.generation_id != previous_generation_id
        {
            return Some(state);
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return None,
            changed = runtime_watch_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            }
        }
    }
}

pub(crate) async fn reconcile_synlimit_rules(cfg: &ProxyConfig) {
    let targets = synlimit_targets(cfg);
    let namespace = synlimit_namespace(&targets);
    if let Some(previous_namespace) = set_active_synlimit_namespace(namespace.clone()) {
        match clear_synlimit_rules_for_namespace(&previous_namespace).await {
            Ok(true) => {
                warn!("Removed previous SYN limiter namespace before reconcile");
            }
            Ok(false) => {}
            Err(error) => {
                warn!(error = %error, "Failed to clear previous SYN limiter namespace before reconcile");
            }
        }
    }

    if targets.is_empty() {
        return;
    }
    let Some(namespace) = namespace else {
        return;
    };
    if !has_firewall_privileges() {
        warn!("SYN limiter configured but firewall privileges are not available; rules not applied");
        return;
    }

    match clear_synlimit_rules_for_namespace(&namespace).await {
        Ok(true) => {
            warn!("Removed stale SYN limiter rules left by a previous run before reconcile");
        }
        Ok(false) => {}
        Err(error) => {
            warn!(error = %error, "Failed to clear stale SYN limiter rules before reconcile");
        }
    }

    if targets.has_iptables_targets() {
        if let Err(error) = iptables::apply_synlimit_rules(&targets, &namespace).await {
            warn!(error = %error, "Failed to apply iptables SYN limiter rules");
        }
    }
    if targets.has_nft_targets() {
        if let Err(error) = nftables::apply_synlimit_rules(&targets, &namespace).await {
            warn!(error = %error, "Failed to apply nftables SYN limiter rules");
        }
    }
    if targets.has_pf_targets() {
        if let Err(error) = pf::apply_synlimit_rules(&targets, &namespace).await {
            warn!(error = %error, "Failed to apply PF SYN limiter rules");
        }
    }
}

pub(crate) async fn clear_synlimit_rules_all_backends() -> Result<bool, String> {
    let Some(namespace) = take_active_synlimit_namespace() else {
        return Ok(false);
    };
    clear_synlimit_rules_for_namespace(&namespace).await
}

async fn clear_synlimit_rules_for_namespace(namespace: &SynLimitNamespace) -> Result<bool, String> {
    if !has_firewall_privileges() {
        return Ok(false);
    }

    let mut errors = Vec::new();
    let mut removed = false;
    match nftables::clear_rules_all_families(namespace).await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match iptables::clear_rules_for_binary("iptables", namespace).await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match iptables::clear_rules_for_binary("ip6tables", namespace).await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match pf::clear_rules(namespace).await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }

    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join("; "))
    }
}

fn set_active_synlimit_namespace(next: Option<SynLimitNamespace>) -> Option<SynLimitNamespace> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(mut active) => {
            if *active == next {
                None
            } else {
                std::mem::replace(&mut *active, next)
            }
        }
        Err(error) => {
            warn!(error = %error, "Failed to update active SYN limiter namespace");
            None
        }
    }
}

fn take_active_synlimit_namespace() -> Option<SynLimitNamespace> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(mut active) => active.take(),
        Err(error) => {
            warn!(error = %error, "Failed to read active SYN limiter namespace");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{Notify, mpsc};

    fn runtime_state(
        generation_id: u64,
        max_connections: u32,
    ) -> (
        RuntimeWatchState,
        watch::Sender<Arc<ProxyConfig>>,
        watch::Sender<bool>,
    ) {
        let mut config = ProxyConfig::default();
        config.server.max_connections = max_connections;
        let (config_tx, config_rx) = watch::channel(Arc::new(config));
        let (admission_tx, admission_rx) = watch::channel(true);
        (
            RuntimeWatchState {
                generation_id,
                config_rx,
                admission_rx,
            },
            config_tx,
            admission_tx,
        )
    }

    #[tokio::test]
    async fn config_watcher_ignores_retired_generation_updates() {
        let (initial, initial_config_tx, _initial_admission_tx) = runtime_state(1, 10);
        let (runtime_tx, runtime_rx) = watch::channel(Some(initial));
        let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
        let watcher = tokio::spawn(watch_active_runtime_configs(
            runtime_rx,
            CancellationToken::new(),
            move |generation_id, cfg| {
                let observed_tx = observed_tx.clone();
                async move {
                    let _ = observed_tx.send((generation_id, cfg.server.max_connections));
                }
            },
        ));

        assert_eq!(observed_rx.recv().await, Some((1, 10)));
        let (next, next_config_tx, _next_admission_tx) = runtime_state(2, 20);
        runtime_tx.send_replace(Some(next));
        assert_eq!(observed_rx.recv().await, Some((2, 20)));

        let mut stale = ProxyConfig::default();
        stale.server.max_connections = 30;
        initial_config_tx.send_replace(Arc::new(stale));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), observed_rx.recv())
                .await
                .is_err()
        );

        let mut active = ProxyConfig::default();
        active.server.max_connections = 40;
        next_config_tx.send_replace(Arc::new(active));
        assert_eq!(observed_rx.recv().await, Some((2, 40)));

        watcher.abort();
    }

    #[tokio::test]
    async fn shutdown_waits_for_inflight_reconcile_and_stops_future_updates() {
        let (initial, config_tx, _admission_tx) = runtime_state(1, 10);
        let (_runtime_tx, runtime_rx) = watch::channel(Some(initial));
        let shutdown = CancellationToken::new();
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let started_callback = started.clone();
        let release_callback = release.clone();
        let calls_callback = calls.clone();
        let watcher_shutdown = shutdown.clone();
        let watcher = tokio::spawn(watch_active_runtime_configs(
            runtime_rx,
            watcher_shutdown,
            move |_generation_id, _cfg| {
                let started = started_callback.clone();
                let release = release_callback.clone();
                let calls = calls_callback.clone();
                async move {
                    calls.fetch_add(1, Ordering::AcqRel);
                    started.notify_one();
                    release.notified().await;
                }
            },
        ));
        started.notified().await;

        shutdown.cancel();
        tokio::task::yield_now().await;
        assert!(!watcher.is_finished());
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), watcher)
            .await
            .unwrap()
            .unwrap();

        drop(_runtime_tx);
        let mut updated = ProxyConfig::default();
        updated.server.max_connections = 20;
        assert!(config_tx.send(Arc::new(updated)).is_err());
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn shutdown_before_start_skips_initial_reconcile() {
        let (initial, _config_tx, _admission_tx) = runtime_state(1, 10);
        let (_runtime_tx, runtime_rx) = watch::channel(Some(initial));
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_callback = calls.clone();

        watch_active_runtime_configs(runtime_rx, shutdown, move |_generation_id, _cfg| {
            let calls = calls_callback.clone();
            async move {
                calls.fetch_add(1, Ordering::AcqRel);
            }
        })
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
}
