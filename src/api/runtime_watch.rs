use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use crate::config::ProxyConfig;

use super::ApiRuntimeState;
use super::events::ApiEventStore;

pub(super) fn spawn_runtime_watchers(
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    admission_rx: watch::Receiver<bool>,
    runtime_state: Arc<ApiRuntimeState>,
    runtime_events: Arc<ApiEventStore>,
) {
    let mut config_rx_reload = config_rx;
    let runtime_state_reload = runtime_state.clone();
    let runtime_events_reload = runtime_events.clone();
    tokio::spawn(async move {
        loop {
            if config_rx_reload.changed().await.is_err() {
                break;
            }
            runtime_state_reload
                .config_reload_count
                .fetch_add(1, Ordering::Relaxed);
            runtime_state_reload
                .last_config_reload_epoch_secs
                .store(now_epoch_secs(), Ordering::Relaxed);
            runtime_events_reload.record("config.reload.applied", "config receiver updated");
        }
    });

    let mut admission_rx_watch = admission_rx;
    tokio::spawn(async move {
        runtime_state
            .admission_open
            .store(*admission_rx_watch.borrow(), Ordering::Relaxed);
        runtime_events.record(
            "admission.state",
            format!("accepting_new_connections={}", *admission_rx_watch.borrow()),
        );
        loop {
            if admission_rx_watch.changed().await.is_err() {
                break;
            }
            let admission_open = *admission_rx_watch.borrow();
            runtime_state
                .admission_open
                .store(admission_open, Ordering::Relaxed);
            runtime_events.record(
                "admission.state",
                format!("accepting_new_connections={}", admission_open),
            );
        }
    });
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
