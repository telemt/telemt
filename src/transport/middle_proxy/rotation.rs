use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;

use super::MePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeReinitTrigger {
    Periodic,
    MapChanged,
}

impl MeReinitTrigger {
    fn as_str(self) -> &'static str {
        match self {
            MeReinitTrigger::Periodic => "periodic",
            MeReinitTrigger::MapChanged => "map-change",
        }
    }
}

pub fn enqueue_reinit_trigger(
    tx: &mpsc::Sender<MeReinitTrigger>,
    trigger: MeReinitTrigger,
) {
    match tx.try_send(trigger) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            debug!(trigger = trigger.as_str(), "ME reinit trigger dropped (queue full)");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!(trigger = trigger.as_str(), "ME reinit trigger dropped (scheduler closed)");
        }
    }
}

pub async fn me_reinit_scheduler(
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    mut trigger_rx: mpsc::Receiver<MeReinitTrigger>,
) {
    info!("ME reinit scheduler started");
    loop {
        let Some(first_trigger) = trigger_rx.recv().await else {
            warn!("ME reinit scheduler stopped: trigger channel closed");
            break;
        };

        let mut map_change_seen = matches!(first_trigger, MeReinitTrigger::MapChanged);
        let mut periodic_seen = matches!(first_trigger, MeReinitTrigger::Periodic);
        let cfg = config_rx.borrow().clone();
        let coalesce_window = Duration::from_millis(cfg.general.me_reinit_coalesce_window_ms);
        if !coalesce_window.is_zero() {
            let deadline = tokio::time::Instant::now() + coalesce_window;
            loop {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                match tokio::time::timeout(deadline - now, trigger_rx.recv()).await {
                    Ok(Some(next)) => {
                        if next == MeReinitTrigger::MapChanged {
                            map_change_seen = true;
                        } else {
                            periodic_seen = true;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }

        let reason = if map_change_seen && periodic_seen {
            "map-change+periodic"
        } else if map_change_seen {
            "map-change"
        } else {
            "periodic"
        };

        if cfg.general.me_reinit_singleflight {
            debug!(reason, "ME reinit scheduled (single-flight)");
            pool.zero_downtime_reinit_periodic(rng.as_ref()).await;
        } else {
            debug!(reason, "ME reinit scheduled (concurrent mode)");
            let pool_clone = pool.clone();
            let rng_clone = rng.clone();
            tokio::spawn(async move {
                pool_clone
                    .zero_downtime_reinit_periodic(rng_clone.as_ref())
                    .await;
            });
        }

    }
}

/// Periodically enqueue reinitialization triggers for ME generations.
pub async fn me_rotation_task(
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
    reinit_tx: mpsc::Sender<MeReinitTrigger>,
) {
    let mut interval_secs = config_rx
        .borrow()
        .general
        .effective_me_reinit_every_secs()
        .max(1);
    let mut interval = Duration::from_secs(interval_secs);
    let mut next_tick = tokio::time::Instant::now() + interval;

    info!(interval_secs, "ME periodic reinit task started");

    loop {
        let sleep = tokio::time::sleep_until(next_tick);
        tokio::pin!(sleep);

        tokio::select! {
            _ = &mut sleep => {
                enqueue_reinit_trigger(&reinit_tx, MeReinitTrigger::Periodic);
                let refreshed_secs = config_rx
                    .borrow()
                    .general
                    .effective_me_reinit_every_secs()
                    .max(1);
                if refreshed_secs != interval_secs {
                    info!(
                        old_me_reinit_every_secs = interval_secs,
                        new_me_reinit_every_secs = refreshed_secs,
                        "ME periodic reinit interval changed"
                    );
                    interval_secs = refreshed_secs;
                    interval = Duration::from_secs(interval_secs);
                }
                next_tick = tokio::time::Instant::now() + interval;
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    warn!("ME periodic reinit task stopped: config channel closed");
                    break;
                }
                let new_secs = config_rx
                    .borrow()
                    .general
                    .effective_me_reinit_every_secs()
                    .max(1);
                if new_secs == interval_secs {
                    continue;
                }

                if new_secs < interval_secs {
                    info!(
                        old_me_reinit_every_secs = interval_secs,
                        new_me_reinit_every_secs = new_secs,
                        "ME periodic reinit interval decreased, running immediate reinit"
                    );
                    interval_secs = new_secs;
                    interval = Duration::from_secs(interval_secs);
                    enqueue_reinit_trigger(&reinit_tx, MeReinitTrigger::Periodic);
                    next_tick = tokio::time::Instant::now() + interval;
                } else {
                    info!(
                        old_me_reinit_every_secs = interval_secs,
                        new_me_reinit_every_secs = new_secs,
                        "ME periodic reinit interval increased"
                    );
                    interval_secs = new_secs;
                    interval = Duration::from_secs(interval_secs);
                    next_tick = tokio::time::Instant::now() + interval;
                }
            }
        }
    }
}
