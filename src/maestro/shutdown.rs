use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::signal;
use tracing::{error, info, warn};

use crate::transport::middle_proxy::MePool;

use super::helpers::{format_uptime, unit_label};

pub(crate) async fn wait_for_shutdown(process_started_at: Instant, me_pool: Option<Arc<MePool>>) {
    match signal::ctrl_c().await {
        Ok(()) => {
            let shutdown_started_at = Instant::now();
            info!("Shutting down...");
            let uptime_secs = process_started_at.elapsed().as_secs();
            info!("Uptime: {}", format_uptime(uptime_secs));
            if let Some(pool) = &me_pool {
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    pool.shutdown_send_close_conn_all(),
                )
                .await
                {
                    Ok(total) => {
                        info!(
                            close_conn_sent = total,
                            "ME shutdown: RPC_CLOSE_CONN broadcast completed"
                        );
                    }
                    Err(_) => {
                        warn!("ME shutdown: RPC_CLOSE_CONN broadcast timed out");
                    }
                }
            }
            let shutdown_secs = shutdown_started_at.elapsed().as_secs();
            info!(
                "Shutdown completed successfully in {} {}.",
                shutdown_secs,
                unit_label(shutdown_secs, "second", "seconds")
            );
        }
        Err(e) => error!("Signal error: {}", e),
    }
}
