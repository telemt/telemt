use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;

use super::MePool;

/// Periodically reinitialize ME generations and swap them after full warmup.
pub async fn me_rotation_task(
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
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
                pool.zero_downtime_reinit_periodic(rng.as_ref()).await;
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
                    pool.zero_downtime_reinit_periodic(rng.as_ref()).await;
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
