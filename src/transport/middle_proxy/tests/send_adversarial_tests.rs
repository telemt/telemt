use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::pool::{MePool, MeWriter, WriterContour};
use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::stats::Stats;

async fn make_pool() -> (Arc<MePool>, Arc<SecureRandom>) {
    let general = GeneralConfig {
        me_route_no_writer_mode: MeRouteNoWriterMode::AsyncRecoveryFailfast,
        me_route_no_writer_wait_ms: 50,
        me_writer_pick_mode: MeWriterPickMode::SortedRr,
        me_deterministic_writer_sort: true,
        ..GeneralConfig::default()
    };

    let rng = Arc::new(SecureRandom::new());
    let pool = MePool::new(
        None,
        vec![1u8; 32],
        None,
        false,
        None,
        Vec::new(),
        false,
        Vec::new(),
        1,
        None,
        12,
        1200,
        HashMap::new(),
        HashMap::new(),
        None,
        NetworkDecision::default(),
        None,
        rng.clone(),
        Arc::new(Stats::default()),
        general.me_keepalive_enabled,
        general.me_keepalive_interval_secs,
        general.me_keepalive_jitter_secs,
        general.me_keepalive_payload_random,
        general.rpc_proxy_req_every,
        general.me_warmup_stagger_enabled,
        general.me_warmup_step_delay_ms,
        general.me_warmup_step_jitter_ms,
        general.me_reconnect_max_concurrent_per_dc,
        general.me_reconnect_backoff_base_ms,
        general.me_reconnect_backoff_cap_ms,
        general.me_reconnect_fast_retry_count,
        general.me_single_endpoint_shadow_writers,
        general.me_single_endpoint_outage_mode_enabled,
        general.me_single_endpoint_outage_disable_quarantine,
        general.me_single_endpoint_outage_backoff_min_ms,
        general.me_single_endpoint_outage_backoff_max_ms,
        general.me_single_endpoint_shadow_rotate_every_secs,
        general.me_floor_mode,
        general.me_adaptive_floor_idle_secs,
        general.me_adaptive_floor_min_writers_single_endpoint,
        general.me_adaptive_floor_min_writers_multi_endpoint,
        general.me_adaptive_floor_recover_grace_secs,
        general.me_adaptive_floor_writers_per_core_total,
        general.me_adaptive_floor_cpu_cores_override,
        general.me_adaptive_floor_max_extra_writers_single_per_core,
        general.me_adaptive_floor_max_extra_writers_multi_per_core,
        general.me_adaptive_floor_max_active_writers_per_core,
        general.me_adaptive_floor_max_warm_writers_per_core,
        general.me_adaptive_floor_max_active_writers_global,
        general.me_adaptive_floor_max_warm_writers_global,
        general.hardswap,
        general.me_pool_drain_ttl_secs,
        general.me_instadrain,
        general.me_pool_drain_threshold,
        general.me_pool_drain_soft_evict_enabled,
        general.me_pool_drain_soft_evict_grace_secs,
        general.me_pool_drain_soft_evict_per_writer,
        general.me_pool_drain_soft_evict_budget_per_core,
        general.me_pool_drain_soft_evict_cooldown_ms,
        general.effective_me_pool_force_close_secs(),
        general.me_pool_min_fresh_ratio,
        general.me_hardswap_warmup_delay_min_ms,
        general.me_hardswap_warmup_delay_max_ms,
        general.me_hardswap_warmup_extra_passes,
        general.me_hardswap_warmup_pass_backoff_base_ms,
        general.me_bind_stale_mode,
        general.me_bind_stale_ttl_secs,
        general.me_secret_atomic_snapshot,
        general.me_deterministic_writer_sort,
        general.me_writer_pick_mode,
        general.me_writer_pick_sample_size,
        MeSocksKdfPolicy::default(),
        general.me_writer_cmd_channel_capacity,
        general.me_writer_byte_budget_bytes,
        general.me_route_channel_capacity,
        general.me_route_backpressure_enabled,
        general.me_route_fairshare_enabled,
        general.me_route_backpressure_base_timeout_ms,
        general.me_route_backpressure_high_timeout_ms,
        general.me_route_backpressure_high_watermark_pct,
        general.me_reader_route_data_wait_ms,
        general.me_health_interval_ms_unhealthy,
        general.me_health_interval_ms_healthy,
        general.me_warn_rate_limit_ms,
        general.me_route_no_writer_mode,
        general.me_route_no_writer_wait_ms,
        general.me_route_hybrid_max_wait_ms,
        general.me_route_blocking_send_timeout_ms,
        general.me_route_inline_recovery_attempts,
        general.me_route_inline_recovery_wait_ms,
    );

    (pool, rng)
}

async fn insert_writer(
    pool: &Arc<MePool>,
    writer_id: u64,
    writer_dc: i32,
    addr: SocketAddr,
    register_in_registry: bool,
) -> mpsc::Receiver<WriterCommand> {
    let (tx, rx) = mpsc::channel::<WriterCommand>(8);
    let byte_budget = pool.new_writer_byte_budget();
    let writer = MeWriter {
        id: writer_id,
        addr,
        source_ip: addr.ip(),
        writer_dc,
        generation: pool.current_generation(),
        contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
        created_at: Instant::now(),
        tx: tx.clone(),
        byte_budget: byte_budget.clone(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };

    pool.writers.write().await.push(writer);
    {
        let mut map = pool.proxy_map_v4.write().await;
        map.entry(writer_dc)
            .or_insert_with(Vec::new)
            .push((addr.ip(), addr.port()));
    }
    pool.rebuild_endpoint_dc_map().await;
    if register_in_registry {
        pool.registry
            .register_writer(writer_id, tx, byte_budget)
            .await;
    }
    rx
}

async fn recv_data_count(rx: &mut mpsc::Receiver<WriterCommand>, budget: Duration) -> usize {
    let start = Instant::now();
    let mut data_count = 0usize;
    while Instant::now().duration_since(start) < budget {
        let remaining = budget.saturating_sub(Instant::now().duration_since(start));
        match tokio::time::timeout(remaining.min(Duration::from_millis(10)), rx.recv()).await {
            Ok(Some(WriterCommand::Data { .. })) => data_count += 1,
            Ok(Some(WriterCommand::DataAndFlush(_))) => data_count += 1,
            Ok(Some(WriterCommand::ProxyReq(_))) => data_count += 1,
            Ok(Some(WriterCommand::ControlAndFlush(_))) => data_count += 1,
            Ok(Some(WriterCommand::Close)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    data_count
}

async fn recv_first_data_payload(
    rx: &mut mpsc::Receiver<WriterCommand>,
    budget: Duration,
) -> Option<Vec<u8>> {
    let start = Instant::now();
    while Instant::now().duration_since(start) < budget {
        let remaining = budget.saturating_sub(Instant::now().duration_since(start));
        match tokio::time::timeout(remaining.min(Duration::from_millis(10)), rx.recv()).await {
            Ok(Some(WriterCommand::Data { payload, .. })) => return Some(payload.to_vec()),
            Ok(Some(WriterCommand::DataAndFlush(payload))) => return Some(payload.to_vec()),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    None
}

fn proxy_req_our_addr_from_payload(payload: &[u8]) -> SocketAddr {
    const CLIENT_ADDR_WIRE_LEN: usize = 20;
    const OUR_ADDR_OFFSET: usize = 4 + 4 + 8 + CLIENT_ADDR_WIRE_LEN;

    let our_addr = &payload[OUR_ADDR_OFFSET..OUR_ADDR_OFFSET + CLIENT_ADDR_WIRE_LEN];
    let ip = Ipv4Addr::new(our_addr[12], our_addr[13], our_addr[14], our_addr[15]);
    let port = u32::from_le_bytes([our_addr[16], our_addr[17], our_addr[18], our_addr[19]]);
    SocketAddr::new(
        IpAddr::V4(ip),
        u16::try_from(port).expect("test port must fit u16"),
    )
}

#[tokio::test]
async fn send_proxy_req_does_not_replay_when_first_bind_commit_fails() {
    let (pool, _rng) = make_pool().await;
    pool.rr.store(0, Ordering::Relaxed);

    let (conn_id, _rx) = pool.registry.register().await;
    let mut stale_rx = insert_writer(
        &pool,
        10,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 443),
        false,
    )
    .await;
    let mut live_rx = insert_writer(
        &pool,
        11,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)), 443),
        true,
    )
    .await;

    let result = pool
        .send_proxy_req(
            conn_id,
            2,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            b"hello",
            0,
            None,
            None,
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(
        recv_data_count(&mut stale_rx, Duration::from_millis(50)).await,
        0
    );
    assert_eq!(
        recv_data_count(&mut live_rx, Duration::from_millis(50)).await,
        1
    );

    let bound = pool.registry.get_writer(conn_id).await;
    assert!(bound.is_some());
    assert_eq!(bound.expect("writer should be bound").writer_id, 11);
}

#[tokio::test]
async fn send_proxy_req_prunes_iterative_stale_bind_failures_without_data_replay() {
    let (pool, _rng) = make_pool().await;
    pool.rr.store(0, Ordering::Relaxed);

    let (conn_id, _rx) = pool.registry.register().await;

    let mut stale_rx_1 = insert_writer(
        &pool,
        21,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 21)), 443),
        false,
    )
    .await;
    let mut stale_rx_2 = insert_writer(
        &pool,
        22,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 22)), 443),
        false,
    )
    .await;
    let mut live_rx = insert_writer(
        &pool,
        23,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 23)), 443),
        true,
    )
    .await;

    let result = pool
        .send_proxy_req(
            conn_id,
            2,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            b"storm",
            0,
            None,
            None,
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(
        recv_data_count(&mut stale_rx_1, Duration::from_millis(50)).await,
        0
    );
    assert_eq!(
        recv_data_count(&mut stale_rx_2, Duration::from_millis(50)).await,
        0
    );
    assert_eq!(
        recv_data_count(&mut live_rx, Duration::from_millis(50)).await,
        1
    );

    let writers = pool.writers.read().await;
    let writer_ids = writers.iter().map(|w| w.id).collect::<Vec<_>>();
    drop(writers);
    assert_eq!(writer_ids, vec![23]);
}

#[tokio::test]
async fn send_proxy_req_uses_writer_source_ip_when_advertised_our_addr_differs() {
    let (pool, _rng) = make_pool().await;
    pool.rr.store(0, Ordering::Relaxed);

    let (conn_id, _rx) = pool.registry.register().await;
    let mut live_rx = insert_writer(
        &pool,
        31,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 31)), 443),
        true,
    )
    .await;

    {
        let mut writers = pool.writers.write().await;
        let writer = writers
            .iter_mut()
            .find(|writer| writer.id == 31)
            .expect("test writer must exist");
        writer.source_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
    }

    let our_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 8443);
    let result = pool
        .send_proxy_req(
            conn_id,
            2,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 30002),
            our_addr,
            b"route",
            0,
            None,
            None,
        )
        .await;

    assert!(result.is_ok());
    let payload = recv_first_data_payload(&mut live_rx, Duration::from_millis(50))
        .await
        .expect("writer must receive routed payload");
    assert_eq!(
        proxy_req_our_addr_from_payload(&payload),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31)), our_addr.port())
    );
}

#[tokio::test]
async fn send_proxy_req_blocking_fallback_uses_writer_source_ip() {
    let (pool, _rng) = make_pool().await;
    pool.rr.store(0, Ordering::Relaxed);

    let (conn_id, _rx) = pool.registry.register().await;
    let mut live_rx = insert_writer(
        &pool,
        32,
        2,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 32)), 443),
        true,
    )
    .await;
    let source_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 32));

    let tx = {
        let mut writers = pool.writers.write().await;
        let writer = writers
            .iter_mut()
            .find(|writer| writer.id == 32)
            .expect("test writer must exist");
        writer.source_ip = source_ip;
        writer.tx.clone()
    };
    for _ in 0..8 {
        tx.try_send(WriterCommand::Close)
            .expect("test writer channel must accept preload");
    }

    let our_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 9443);
    let pool_for_send = pool.clone();
    let send_task = tokio::spawn(async move {
        pool_for_send
            .send_proxy_req(
                conn_id,
                2,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 30003),
                our_addr,
                b"blocking",
                0,
                None,
                None,
            )
            .await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(matches!(live_rx.recv().await, Some(WriterCommand::Close)));

    let result = send_task.await.expect("send task must not panic");
    assert!(result.is_ok());
    let payload = recv_first_data_payload(&mut live_rx, Duration::from_millis(50))
        .await
        .expect("writer must receive blocking fallback payload");
    assert_eq!(
        proxy_req_our_addr_from_payload(&payload),
        SocketAddr::new(source_ip, our_addr.port())
    );
}
