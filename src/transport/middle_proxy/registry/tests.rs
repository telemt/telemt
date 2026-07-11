use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Semaphore;

use super::{ConnMeta, ConnRegistry, RouteResult};
use crate::transport::middle_proxy::MeResponse;

fn writer_byte_budget() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(2049))
}

#[tokio::test]
async fn writer_activity_snapshot_tracks_writer_and_dc_load() {
    let registry = ConnRegistry::new();

    let (conn_a, _rx_a) = registry.register().await;
    let (conn_b, _rx_b) = registry.register().await;
    let (conn_c, _rx_c) = registry.register().await;
    let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
    let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
    registry
        .register_writer(10, writer_tx_a.clone(), writer_byte_budget())
        .await;
    registry
        .register_writer(20, writer_tx_b.clone(), writer_byte_budget())
        .await;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    assert!(
        registry
            .bind_writer(
                conn_a,
                10,
                ConnMeta {
                    target_dc: 2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );
    assert!(
        registry
            .bind_writer(
                conn_b,
                10,
                ConnMeta {
                    target_dc: -2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );
    assert!(
        registry
            .bind_writer(
                conn_c,
                20,
                ConnMeta {
                    target_dc: 4,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );

    let snapshot = registry.writer_activity_snapshot().await;
    assert_eq!(snapshot.bound_clients_by_writer.get(&10), Some(&2));
    assert_eq!(snapshot.bound_clients_by_writer.get(&20), Some(&1));
    assert_eq!(snapshot.active_sessions_by_target_dc.get(&2), Some(&1));
    assert_eq!(snapshot.active_sessions_by_target_dc.get(&-2), Some(&1));
    assert_eq!(snapshot.active_sessions_by_target_dc.get(&4), Some(&1));
}

#[tokio::test]
async fn route_data_is_bounded_by_byte_permits_before_channel_capacity() {
    let registry = ConnRegistry::with_route_byte_permits_for_tests(4, 1);
    let (conn_id, mut rx) = registry.register().await;
    let routed = registry
        .route_nowait(
            conn_id,
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xAA]),
                route_permit: None,
            },
        )
        .await;
    assert!(matches!(routed, RouteResult::Routed));

    let blocked = registry
        .route_nowait(
            conn_id,
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xBB]),
                route_permit: None,
            },
        )
        .await;
    assert!(
        matches!(blocked, RouteResult::QueueFullHigh),
        "byte budget must reject data before count capacity is exhausted"
    );

    drop(rx.recv().await);

    let routed_after_drain = registry
        .route_nowait(
            conn_id,
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xCC]),
                route_permit: None,
            },
        )
        .await;
    assert!(
        matches!(routed_after_drain, RouteResult::Routed),
        "receiving queued data must release byte permits"
    );
}

#[tokio::test]
async fn bind_writer_rebinds_conn_atomically() {
    let registry = ConnRegistry::new();
    let (conn_id, _rx) = registry.register().await;
    let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
    let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
    registry
        .register_writer(10, writer_tx_a, writer_byte_budget())
        .await;
    registry
        .register_writer(20, writer_tx_b, writer_byte_budget())
        .await;

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let first_our_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let second_our_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 443);

    assert!(
        registry
            .bind_writer(
                conn_id,
                10,
                ConnMeta {
                    target_dc: 2,
                    client_addr,
                    our_addr: first_our_addr,
                    proto_flags: 1,
                },
            )
            .await
    );
    assert!(
        registry
            .bind_writer(
                conn_id,
                20,
                ConnMeta {
                    target_dc: 2,
                    client_addr,
                    our_addr: second_our_addr,
                    proto_flags: 2,
                },
            )
            .await
    );

    let writer = registry.get_writer(conn_id).await.expect("writer binding");
    assert_eq!(writer.writer_id, 20);

    let meta = registry.get_meta(conn_id).await.expect("conn meta");
    assert_eq!(meta.our_addr, second_our_addr);
    assert_eq!(meta.proto_flags, 2);

    let snapshot = registry.writer_activity_snapshot().await;
    assert_eq!(snapshot.bound_clients_by_writer.get(&10), Some(&0));
    assert_eq!(snapshot.bound_clients_by_writer.get(&20), Some(&1));
    assert!(
        registry
            .writer_idle_since_snapshot()
            .await
            .contains_key(&10)
    );
}

#[tokio::test]
async fn writer_lost_does_not_drop_rebound_conn() {
    let registry = ConnRegistry::new();
    let (conn_id, _rx) = registry.register().await;
    let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
    let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
    registry
        .register_writer(10, writer_tx_a, writer_byte_budget())
        .await;
    registry
        .register_writer(20, writer_tx_b, writer_byte_budget())
        .await;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    assert!(
        registry
            .bind_writer(
                conn_id,
                10,
                ConnMeta {
                    target_dc: 2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );
    assert!(
        registry
            .bind_writer(
                conn_id,
                20,
                ConnMeta {
                    target_dc: 2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 1,
                },
            )
            .await
    );

    let lost = registry.writer_lost(10).await;
    assert!(lost.is_empty());
    assert_eq!(
        registry
            .get_writer(conn_id)
            .await
            .expect("writer")
            .writer_id,
        20
    );

    let removed_writer = registry.unregister(conn_id).await;
    assert_eq!(removed_writer, Some(20));
    assert!(registry.is_writer_empty(20).await);
}

#[tokio::test]
async fn bind_writer_rejects_unregistered_writer() {
    let registry = ConnRegistry::new();
    let (conn_id, _rx) = registry.register().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

    assert!(
        !registry
            .bind_writer(
                conn_id,
                10,
                ConnMeta {
                    target_dc: 2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );
    assert!(registry.get_writer(conn_id).await.is_none());
}

#[tokio::test]
async fn non_empty_writer_ids_returns_only_writers_with_bound_clients() {
    let registry = ConnRegistry::new();
    let (conn_id, _rx) = registry.register().await;
    let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
    let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
    registry
        .register_writer(10, writer_tx_a, writer_byte_budget())
        .await;
    registry
        .register_writer(20, writer_tx_b, writer_byte_budget())
        .await;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    assert!(
        registry
            .bind_writer(
                conn_id,
                10,
                ConnMeta {
                    target_dc: 2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );

    let non_empty = registry.non_empty_writer_ids(&[10, 20, 30]).await;
    assert!(non_empty.contains(&10));
    assert!(!non_empty.contains(&20));
    assert!(!non_empty.contains(&30));
}
