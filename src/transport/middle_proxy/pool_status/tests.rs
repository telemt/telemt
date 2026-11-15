use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::network::probe::NetworkDecision;
use crate::transport::middle_proxy::codec::WriterCommand;
use crate::transport::middle_proxy::pool::{MePool, MeWriter, WriterContour};
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;

fn writer(
    pool: &Arc<MePool>,
    id: u64,
    dc: i32,
    addr: SocketAddr,
) -> (MeWriter, mpsc::Receiver<WriterCommand>) {
    let (tx, rx) = mpsc::channel::<WriterCommand>(8);
    (
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
        },
        rx,
    )
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
    let mut receivers = Vec::new();
    let mut writers = pool.writers.write().await;
    for (group, dc) in [2, -2].into_iter().enumerate() {
        for offset in 0..required_per_family {
            let (writer, receiver) = writer(&pool, (group as u64 * 100) + offset as u64, dc, v4);
            writers.push(writer);
            receivers.push(receiver);
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
async fn conditional_admission_accepts_any_live_signed_dc_route() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        effective_prefer: 4,
        ..NetworkDecision::default()
    })
    .await;
    let dc2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 2)), 443);
    let dc5 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 5, 5)), 443);
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(dc2.ip(), dc2.port())]),
            (5, vec![(dc5.ip(), dc5.port())]),
        ]),
        None,
    )
    .await;

    assert!(!pool.admission_ready_conditional_cast().await);
    let (live, _receiver) = writer(&pool, 1, 2, dc2);
    pool.writers.write().await.push(live);
    assert!(pool.admission_ready_conditional_cast().await);
    assert!(!pool.admission_ready_full_floor().await);

    pool.writers.write().await.clear();
    let (orphan, _receiver) = writer(&pool, 2, 9, dc2);
    pool.writers.write().await.push(orphan);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    pool.update_proxy_maps(HashMap::from([(-2, vec![(dc2.ip(), dc2.port())])]), None)
        .await;
    let (positive_route, _receiver) = writer(&pool, 3, 2, dc2);
    pool.writers.write().await.push(positive_route);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let (negative_route, _receiver) = writer(&pool, 4, -2, dc2);
    pool.writers.write().await.push(negative_route);
    assert!(pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(dc2.ip(), dc2.port())]),
            (5, vec![(dc5.ip(), dc5.port())]),
        ]),
        None,
    )
    .await;
    let old_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 22)), 443);
    let (old_dc_writer, _receiver) = writer(&pool, 5, 2, old_endpoint);
    pool.writers.write().await.push(old_dc_writer);
    assert!(pool.admission_ready_conditional_cast().await);
    let replacement = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22)), 443);
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(replacement.ip(), replacement.port())]),
            (5, vec![(dc5.ip(), dc5.port())]),
        ]),
        None,
    )
    .await;
    assert!(pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let other_family = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    let (disabled, _receiver) = writer(&pool, 6, 2, other_family);
    pool.writers.write().await.push(disabled);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let (warm, _receiver) = writer(&pool, 7, 2, replacement);
    warm.contour
        .store(WriterContour::Warm.as_u8(), Ordering::Relaxed);
    pool.writers.write().await.push(warm);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let (draining, _receiver) = writer(&pool, 8, 2, replacement);
    draining.draining.store(true, Ordering::Relaxed);
    pool.writers.write().await.push(draining);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let (mut stale, _receiver) = writer(&pool, 9, 2, replacement);
    stale.generation = pool.current_generation().saturating_sub(1);
    pool.writers.write().await.push(stale);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let (closed, receiver) = writer(&pool, 10, 2, replacement);
    drop(receiver);
    pool.writers.write().await.push(closed);
    assert!(!pool.admission_ready_conditional_cast().await);

    pool.writers.write().await.clear();
    let (cancelled, _receiver) = writer(&pool, 11, 2, replacement);
    cancelled.cancel.cancel();
    pool.writers.write().await.push(cancelled);
    assert!(!pool.admission_ready_conditional_cast().await);
}
