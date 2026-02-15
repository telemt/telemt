use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;

use super::MePool;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, min_connections: usize) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let current = pool.connection_count();
        if current < min_connections {
            warn!(
                current,
                min = min_connections,
                "ME pool below minimum, reconnecting..."
            );
            let map = pool.proxy_map_v4.read().await.clone();
            for (_dc, addrs) in map.iter() {
                for &(ip, port) in addrs {
                    let needed = min_connections.saturating_sub(pool.connection_count());
                    if needed == 0 {
                        break;
                    }
                    let addr = SocketAddr::new(ip, port);
                    match pool.connect_one(addr, &rng).await {
                        Ok(()) => info!(%addr, "ME reconnected"),
                        Err(e) => debug!(%addr, error = %e, "ME reconnect failed"),
                    }
                }
            }
        }
    }
}
