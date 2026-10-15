use super::*;
use std::time::Duration;

use crate::crypto::{AesCtr, SecureRandom};
use crate::error::{ProxyError, Result};
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::middle_relay::handle_via_middle_proxy_with_conntrack;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::{ConntrackClosePolicy, ProxySharedState};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::MeResponse;
use crate::transport::middle_proxy::admission_test_support::unregistered_writer;
use crate::transport::middle_proxy::registry::RouteResult;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio_util::task::AbortOnDropHandle;

fn spawn_relay(pool: Arc<MePool>) -> (DuplexStream, Arc<Stats>, AbortOnDropHandle<Result<()>>) {
    let stats = Arc::new(Stats::new());
    let quota = stats.current_user_quota_handle("test");
    let (server, client) = tokio::io::duplex(1024);
    let (reader, writer) = tokio::io::split(server);
    let route = RouteRuntimeController::new(RelayRouteMode::Middle);
    let success = HandshakeSuccess {
        user: "test".into(),
        dc_idx: 5,
        proto_tag: crate::protocol::constants::ProtoTag::Intermediate,
        dec_key: [0; 32],
        dec_iv: 0,
        enc_key: [0; 32],
        enc_iv: 0,
        peer: "192.0.2.10:12345".parse().unwrap(),
        is_tls: false,
    };
    let task = AbortOnDropHandle::new(tokio::spawn(handle_via_middle_proxy_with_conntrack(
        CryptoReader::new(reader, AesCtr::new(&[0; 32], 0)),
        CryptoWriter::new(writer, AesCtr::new(&[0; 32], 0), 4096),
        success,
        pool,
        stats.clone(),
        Arc::new(crate::config::ProxyConfig::default()),
        Arc::new(BufferPool::new()),
        "203.0.113.10:443".parse().unwrap(),
        Arc::new(SecureRandom::new()),
        route.subscribe(),
        route.snapshot(),
        1,
        CancellationToken::new(),
        ProxySharedState::new(),
        ConntrackClosePolicy::Suppress,
        quota,
    )));
    (client, stats, task)
}

async fn send_client_frame(client: &mut DuplexStream) {
    let payload = AesCtr::new(&[0; 32], 0).encrypt(&[4, 0, 0, 0, 1, 2, 3, 4]);
    client.write_all(&payload).await.unwrap();
}

#[tokio::test]
async fn unavailable_dc_sender_error_closes_an_idle_client_relay() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(HashMap::from([(5, vec![(addr.ip(), addr.port())])]), None)
        .await;
    pool.route_runtime.me_route_no_writer_mode.store(
        crate::config::MeRouteNoWriterMode::AsyncRecoveryFailfast.as_u8(),
        std::sync::atomic::Ordering::Relaxed,
    );
    let (mut client, stats, mut task) = spawn_relay(pool.clone());
    send_client_frame(&mut client).await;
    let result = tokio::time::timeout(Duration::from_secs(2), &mut task)
        .await
        .expect("ME sender failure must not wait for more client input")
        .expect("relay must not panic while consuming the completed sender");
    assert!(
        matches!(result, Err(ProxyError::Proxy(ref message))
        if message == "No ME writer available in failfast window"),
        "unexpected result: {result:?}"
    );
    assert!(pool.registry.active_conn_ids().await.is_empty());
    assert_eq!(stats.get_current_connections_me(), 0);
    drop(client);
}

async fn downstream_completion_closes_idle_client(close: bool) {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(HashMap::from([(5, vec![(addr.ip(), addr.port())])]), None)
        .await;
    let (writer, mut commands) = unregistered_writer(
        &pool,
        1,
        5,
        addr,
        pool.current_generation(),
        WriterContour::Active,
    );
    let byte_budget = writer.byte_budget.clone();
    let full_budget = byte_budget.available_permits();
    pool.registry
        .register_writer(writer.id, writer.tx.clone(), writer.byte_budget.clone())
        .await;
    pool.writers.write().await.push(writer);
    let (mut client, stats, mut task) = spawn_relay(pool.clone());
    send_client_frame(&mut client).await;
    let command = tokio::time::timeout(Duration::from_secs(2), commands.recv())
        .await
        .expect("client request must reach the registered ME writer")
        .expect("writer command channel must remain open");
    drop(command);
    let ids = pool.registry.active_conn_ids().await;
    assert_eq!(ids.len(), 1);
    let conn_id = ids[0];
    assert!(pool.registry.get_writer(conn_id).await.is_some());
    if close {
        assert_eq!(
            pool.registry.route(conn_id, MeResponse::Close).await,
            RouteResult::Routed
        );
    } else {
        assert_eq!(pool.registry.unregister(conn_id).await, Some(1));
    }
    let result = tokio::time::timeout(Duration::from_secs(2), &mut task)
        .await
        .expect("completed ME writer must close an idle client relay")
        .expect("relay must not poll a completed ME writer twice");
    if close {
        assert!(result.is_ok(), "ME close must complete cleanly: {result:?}");
    } else {
        assert!(
            matches!(result, Err(ProxyError::MiddleConnectionLost)),
            "unexpected result: {result:?}"
        );
    }
    assert_eq!(
        pool.registry.route(conn_id, MeResponse::Ack(0)).await,
        RouteResult::NoConn
    );
    assert!(pool.registry.get_writer(conn_id).await.is_none());
    assert_eq!(stats.get_current_connections_me(), 0);
    assert_eq!(byte_budget.available_permits(), full_budget);
    drop(client);
}

#[tokio::test]
async fn downstream_close_finishes_an_idle_client_relay_without_double_polling() {
    downstream_completion_closes_idle_client(true).await;
}

#[tokio::test]
async fn downstream_channel_error_finishes_an_idle_client_relay_without_double_polling() {
    downstream_completion_closes_idle_client(false).await;
}
