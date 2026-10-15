use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::network::probe::NetworkDecision;
use crate::transport::middle_proxy::codec::WriterCommand;
use crate::transport::middle_proxy::pool::{MePool, MeWriter, WriterContour};
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;

// End-to-end relay lifecycle checks use the isolated pool fixtures.
#[path = "relay_lifecycle_tests.rs"]
mod relay_lifecycle_tests;

fn writer(pool: &Arc<MePool>, id: u64, dc: i32, addr: SocketAddr) -> MeWriter {
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    MeWriter {
        id,
        addr,
        source_ip: addr.ip(),
        writer_dc: dc,
        generation: pool.current_generation(),
        contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
        created_at: Instant::now(),
        tx,
        byte_budget: pool.new_writer_byte_budget(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    }
}

#[tokio::test]
async fn dual_family_status_reports_each_family_floor() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        effective_prefer: 4,
        effective_multipath: false,
        ..NetworkDecision::default()
    })
    .await;
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(v4.ip(), v4.port())])]),
        Some(HashMap::from([(2, vec![(v6.ip(), v6.port())])])),
    )
    .await;
    let required_per_family = pool.required_writers_for_dc(1);
    let mut writers = pool.writers.write().await;
    for (group, dc) in [2, -2].into_iter().enumerate() {
        for offset in 0..required_per_family {
            writers.push(writer(&pool, (group as u64 * 100) + offset as u64, dc, v4));
        }
    }
    drop(writers);

    let snapshot = pool.api_status_snapshot().await;

    assert_eq!(snapshot.required_writers, required_per_family * 4);
    assert_eq!(snapshot.alive_writers, required_per_family * 2);
    assert_eq!(snapshot.coverage_pct, 50.0);
    for dc in snapshot.dcs {
        assert_eq!(dc.required_writers, required_per_family * 2);
        assert_eq!(dc.alive_writers, required_per_family);
        assert_eq!(dc.coverage_pct, 50.0);
    }
    assert!(!pool.admission_ready_full_floor().await);
}

#[tokio::test]
async fn unavailable_dc_does_not_close_healthy_me_admission() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(addr.ip(), addr.port())]),
            (5, vec![(addr.ip(), addr.port())]),
        ]),
        None,
    )
    .await;
    assert!(!pool.admission_ready_conditional_cast().await);
    let healthy = writer(&pool, 1, 2, addr);
    let draining = healthy.draining.clone();
    let contour = healthy.contour.clone();
    pool.writers.write().await.push(healthy);

    assert!(pool.admission_ready_conditional_cast().await);
    assert!(!pool.admission_ready_full_floor().await);
    draining.store(true, std::sync::atomic::Ordering::Release);
    assert!(!pool.admission_ready_conditional_cast().await);
    draining.store(false, std::sync::atomic::Ordering::Release);
    contour.store(
        WriterContour::Warm.as_u8(),
        std::sync::atomic::Ordering::Release,
    );
    assert!(!pool.admission_ready_conditional_cast().await);
    contour.store(
        WriterContour::Active.as_u8(),
        std::sync::atomic::Ordering::Release,
    );
    pool.writers.write().await[0].generation += 1;
    assert!(!pool.admission_ready_conditional_cast().await);
}

#[tokio::test]
async fn partial_startup_finishes_and_keeps_unavailable_dc_in_map() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_addr = listener.local_addr().unwrap();
    drop(listener);
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(addr.ip(), addr.port())]),
            (5, vec![(unavailable_addr.ip(), unavailable_addr.port())]),
        ]),
        None,
    )
    .await;
    let required = pool.required_writers_for_dc(1);
    for (group, dc) in [2, -2].into_iter().enumerate() {
        for offset in 0..required {
            pool.writers.write().await.push(writer(
                &pool,
                (group * required + offset) as u64,
                dc,
                addr,
            ));
        }
    }
    let rng = Arc::new(crate::crypto::SecureRandom::new());
    tokio::time::timeout(std::time::Duration::from_secs(5), pool.init(12, &rng))
        .await
        .expect("partial ME startup must finish")
        .expect("working DCs must start without waiting for a failed DC");
    assert!(pool.endpoint_snapshot.load().map_v4.contains_key(&5));
    assert!(pool.admission_ready_conditional_cast().await);
}

#[tokio::test(start_paused = true)]
async fn partial_dc_outage_does_not_suppress_working_ipv4() {
    use crate::transport::middle_proxy::admission_test_support::unregistered_writer;
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(addr.ip(), addr.port())]),
            (5, vec![(addr.ip(), addr.port())]),
        ]),
        None,
    )
    .await;
    let mut receivers = Vec::new();
    let required = pool.required_writers_for_dc(1);
    for (group, dc) in [2, -2].into_iter().enumerate() {
        for offset in 0..required {
            let (healthy, receiver) = unregistered_writer(
                &pool,
                (group * required + offset) as u64,
                dc,
                addr,
                pool.current_generation(),
                WriterContour::Active,
            );
            receivers.push(receiver);
            pool.writers.write().await.push(healthy);
        }
    }
    observe_health_ticks(pool.clone()).await;
    assert!(
        !pool.is_family_temporarily_suppressed(
            crate::network::IpFamily::V4,
            MePool::now_epoch_secs(),
        )
    );
    drop(receivers);
}

async fn observe_health_ticks(pool: Arc<MePool>) {
    let monitor = tokio::spawn(crate::transport::middle_proxy::health::me_health_monitor(
        pool,
        Arc::new(crate::crypto::SecureRandom::new()),
        12,
    ));
    for _ in 0..20 {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    monitor.abort();
    let _ = monitor.await;
}

#[tokio::test(start_paused = true)]
async fn complete_family_outage_still_suppresses_ipv4() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    observe_health_ticks(pool.clone()).await;
    assert!(pool.family_fail_streak(crate::network::IpFamily::V4) >= 5);
    assert!(
        pool.is_family_temporarily_suppressed(
            crate::network::IpFamily::V4,
            MePool::now_epoch_secs(),
        )
    );
    assert!(!pool.admission_ready_conditional_cast().await);
}

#[tokio::test(start_paused = true)]
async fn empty_enabled_family_is_not_suppressed() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    assert!(pool.endpoint_snapshot.load().map_v4.is_empty());
    observe_health_ticks(pool.clone()).await;
    assert_eq!(pool.family_fail_streak(crate::network::IpFamily::V4), 0);
    assert!(
        !pool.is_family_temporarily_suppressed(
            crate::network::IpFamily::V4,
            MePool::now_epoch_secs(),
        )
    );
    assert!(!pool.admission_ready_conditional_cast().await);
}

#[tokio::test(start_paused = true)]
async fn disabled_family_with_configured_endpoints_is_not_suppressed() {
    let pool = make_pool_with_decision(NetworkDecision::default()).await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    observe_health_ticks(pool.clone()).await;
    assert_eq!(pool.family_fail_streak(crate::network::IpFamily::V4), 0);
    assert!(
        !pool.is_family_temporarily_suppressed(
            crate::network::IpFamily::V4,
            MePool::now_epoch_secs(),
        )
    );
    assert!(!pool.admission_ready_conditional_cast().await);
}

#[tokio::test]
async fn partial_admission_accepts_a_negative_only_signed_dc_writer() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    pool.writers.write().await.push(writer(&pool, 1, -2, addr));
    assert!(pool.admission_ready_conditional_cast().await);
    assert!(!pool.admission_ready_full_floor().await);
    pool.writers.write().await[0].writer_dc = -5;
    assert!(!pool.admission_ready_conditional_cast().await);
}

#[tokio::test]
async fn partial_admission_accepts_only_an_alternate_family_writer() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        effective_prefer: 4,
        ..NetworkDecision::default()
    })
    .await;
    let v4: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let v6: SocketAddr = "[::1]:1".parse().unwrap();
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(v4.ip(), v4.port())])]),
        Some(HashMap::from([(2, vec![(v6.ip(), v6.port())])])),
    )
    .await;
    pool.writers.write().await.push(writer(&pool, 1, 2, v6));
    assert!(pool.admission_ready_conditional_cast().await);
    assert!(!pool.admission_ready_full_floor().await);
}
