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
                // Remove old writer after new one is up.
                pool.remove_writer_and_reroute(w.id).await;
            }
            Err(e) => {
                warn!(addr = %w.addr, writer_id = w.id, error = %e, "ME rotation connect failed");
            }
        }
    }
}
