use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tracing::{info, warn};

use crate::crypto::SecureRandom;

use super::MePool;

/// Periodically refresh ME connections to avoid long-lived degradation.
pub async fn me_rotation_task(pool: Arc<MePool>, rng: Arc<SecureRandom>, interval: Duration) {
    let interval = interval.max(Duration::from_secs(600));
    loop {
        tokio::time::sleep(interval).await;

        let candidate = {
            let ws = pool.writers.read().await;
            if ws.is_empty() {
                None
            } else {
                let idx = (pool.rr.load(std::sync::atomic::Ordering::Relaxed) as usize) % ws.len();
                ws.get(idx).cloned()
            }
        };

        let Some(w) = candidate else {
            continue;
        };

        info!(addr = %w.addr, writer_id = w.id, "Rotating ME connection");
        match pool.connect_one(w.addr, rng.as_ref()).await {
            Ok(()) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let ws = pool.writers.read().await;
                let new_alive = ws.iter().any(|nw|
                    nw.id != w.id && nw.addr == w.addr && !nw.degraded.load(Ordering::Relaxed) && !nw.draining.load(Ordering::Relaxed)
                );
                drop(ws);
                if new_alive {
                    pool.mark_writer_draining(w.id).await;
                } else {
                    warn!(addr = %w.addr, writer_id = w.id, "New writer died, keeping old");
                }
            }
            Err(e) => {
                warn!(addr = %w.addr, writer_id = w.id, error = %e, "ME rotation connect failed");
            }
        }
    }
}
