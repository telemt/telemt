use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
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

pub fn enqueue_reinit_trigger(tx: &mpsc::Sender<MeReinitTrigger>, trigger: MeReinitTrigger) {
    match tx.try_send(trigger) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            debug!(
                trigger = trigger.as_str(),
                "ME reinit trigger dropped (queue full)"
            );
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!(
                trigger = trigger.as_str(),
                "ME reinit trigger dropped (scheduler closed)"
            );
        }
    }
}

const REINIT_TRIGGER_PERIODIC: u8 = 1;
const REINIT_TRIGGER_MAP_CHANGED: u8 = 2;

struct ReinitInflightGuard {
    pool: Arc<MePool>,
}

impl Drop for ReinitInflightGuard {
    fn drop(&mut self) {
        self.pool
            .reinit
            .scheduler_inflight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn effective_reinit_concurrency(config: &ProxyConfig) -> usize {
    if config.general.me_reinit_singleflight {
        1
    } else {
        config.general.me_reinit_max_concurrency.clamp(1, 8)
    }
}

fn trigger_bit(trigger: MeReinitTrigger) -> u8 {
    match trigger {
        MeReinitTrigger::Periodic => REINIT_TRIGGER_PERIODIC,
        MeReinitTrigger::MapChanged => REINIT_TRIGGER_MAP_CHANGED,
    }
}

fn trigger_reason(pending: u8) -> &'static str {
    match pending {
        REINIT_TRIGGER_PERIODIC => "periodic",
        REINIT_TRIGGER_MAP_CHANGED => "map-change",
        _ => "map-change+periodic",
    }
}

pub async fn me_reinit_scheduler(
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    mut trigger_rx: mpsc::Receiver<MeReinitTrigger>,
    me_ready_tx: watch::Sender<u64>,
) {
    info!("ME reinit scheduler started");
    let mut tasks = JoinSet::<bool>::new();
    let mut pending = 0u8;
    let mut pending_deadline = None;
    let mut trigger_channel_open = true;

    loop {
        let cfg = config_rx.borrow().clone();
        let max_concurrency = effective_reinit_concurrency(&cfg);
        pool.reinit
            .max_concurrency_effective
            .store(max_concurrency, std::sync::atomic::Ordering::Release);

        let pending_ready = pending != 0
            && pending_deadline.is_none_or(|deadline| deadline <= tokio::time::Instant::now());
        if pending_ready && tasks.len() < max_concurrency {
            let reason = trigger_reason(pending);
            pending = 0;
            pending_deadline = None;
            debug!(reason, max_concurrency, "ME reinit scheduled");
            let pool_clone = pool.clone();
            let rng_clone = rng.clone();
            pool.reinit
                .scheduler_inflight
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let inflight = ReinitInflightGuard {
                pool: Arc::clone(&pool_clone),
            };
            tasks.spawn(async move {
                let _inflight = inflight;
                pool_clone
                    .zero_downtime_reinit_periodic(rng_clone.as_ref())
                    .await
            });
            continue;
        }

        if !trigger_channel_open && pending == 0 && tasks.is_empty() {
            warn!("ME reinit scheduler stopped: trigger channel closed");
            return;
        }

        let timer_enabled = pending != 0 && tasks.len() < max_concurrency;
        tokio::select! {
            trigger = trigger_rx.recv(), if trigger_channel_open => {
                match trigger {
                    Some(trigger) => {
                        if pending == 0 {
                            pending_deadline = Some(
                                tokio::time::Instant::now()
                                    + Duration::from_millis(
                                        cfg.general.me_reinit_coalesce_window_ms,
                                    ),
                            );
                        }
                        pending |= trigger_bit(trigger);
                    }
                    None => trigger_channel_open = false,
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(true)) => {
                        me_ready_tx.send_modify(|version| {
                            *version = version.saturating_add(1);
                        });
                    }
                    Some(Ok(false)) => {}
                    Some(Err(error)) => {
                        warn!(error = %error, "ME reinit task failed");
                    }
                    None => {}
                }
            }
            _ = async {
                if let Some(deadline) = pending_deadline {
                    tokio::time::sleep_until(deadline).await;
                }
            }, if timer_enabled => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ProxyConfig;

    #[test]
    fn effective_concurrency_is_one_for_singleflight_and_bounded_otherwise() {
        let mut config = ProxyConfig::default();
        config.general.me_reinit_singleflight = true;
        config.general.me_reinit_max_concurrency = 8;
        assert_eq!(super::effective_reinit_concurrency(&config), 1);

        config.general.me_reinit_singleflight = false;
        config.general.me_reinit_max_concurrency = 2;
        assert_eq!(super::effective_reinit_concurrency(&config), 2);
        config.general.me_reinit_max_concurrency = usize::MAX;
        assert_eq!(super::effective_reinit_concurrency(&config), 8);
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
