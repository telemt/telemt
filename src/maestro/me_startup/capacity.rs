/// Returns the cleanup reservation budget for simultaneously admitted ME clients.
pub(super) fn me_connection_cleanup_capacity(max_connections: u32) -> usize {
    if max_connections == 0 {
        // Match frontend admission; adding headroom here would exceed Tokio's limit.
        tokio::sync::Semaphore::MAX_PERMITS
    } else {
        (max_connections as usize)
            .saturating_add(128)
            .min(tokio::sync::Semaphore::MAX_PERMITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Semaphore;
    use crate::transport::middle_proxy::{ConnRegistry, MeResponse};

    #[test]
    fn me_cleanup_capacity_preserves_zero_and_finite_limits() {
        for (configured, expected) in [
            (0, Semaphore::MAX_PERMITS),
            (1, 129),
            (128, 256),
            (10_000, 10_128),
            (u32::MAX, (u32::MAX as usize).saturating_add(128).min(Semaphore::MAX_PERMITS)),
        ] {
            let capacity = me_connection_cleanup_capacity(configured);
            assert_eq!(capacity, expected);
            assert!(capacity > 0 && capacity <= Semaphore::MAX_PERMITS);
        }
    }

    #[tokio::test]
    async fn me_cleanup_capacity_zero_admits_512_simultaneous_leased_routes() {
        let registry = Arc::new(ConnRegistry::with_route_and_cleanup_capacity(
            8, me_connection_cleanup_capacity(0),
        ));
        let mut clients = Vec::new();
        for index in 0..512 {
            let client = tokio::time::timeout(Duration::from_secs(1), registry.register_leased())
                .await.unwrap_or_else(|_| panic!("registration {} blocked", index + 1))
                .unwrap();
            clients.push(client);
        }
        for (lease, mut receiver) in clients {
            registry.route_nowait(lease.conn_id(), MeResponse::Ack(1)).await;
            assert!(matches!(receiver.try_recv(), Ok(MeResponse::Ack(1))));
            lease.unregister().await;
        }
        // All reservation capacity must remain reusable after explicit cleanup.
        let (lease, _) = registry.register_leased().await.unwrap();
        lease.unregister().await;
    }
}
