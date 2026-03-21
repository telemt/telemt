use super::*;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Barrier;
use tokio::time::Instant;

#[test]
fn quota_lock_same_user_returns_same_arc_instance() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let a = quota_user_lock("quota-lock-same-user");
    let b = quota_user_lock("quota-lock-same-user");
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn quota_lock_parallel_same_user_reuses_single_lock() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let user = "quota-lock-parallel-same";
    let mut handles = Vec::new();

    for _ in 0..64 {
        handles.push(std::thread::spawn(move || quota_user_lock(user)));
    }

    let first = handles
        .remove(0)
        .join()
        .expect("thread must return lock handle");

    for handle in handles {
        let got = handle.join().expect("thread must return lock handle");
        assert!(Arc::ptr_eq(&first, &got));
    }
}

#[test]
fn quota_lock_unique_users_materialize_distinct_entries() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);

    map.clear();

    let base = format!("quota-lock-distinct-{}", std::process::id());
    let users: Vec<String> = (0..(QUOTA_USER_LOCKS_MAX / 2))
        .map(|idx| format!("{base}-{idx}"))
        .collect();

    for user in &users {
        let _ = quota_user_lock(user);
    }

    for user in &users {
        assert!(map.get(user).is_some(), "lock cache must contain entry for {user}");
    }
}

#[test]
fn quota_lock_unique_churn_stress_keeps_all_inserted_keys_addressable() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);

    map.clear();

    let base = format!("quota-lock-churn-{}", std::process::id());
    for idx in 0..(QUOTA_USER_LOCKS_MAX + 256) {
        let _ = quota_user_lock(&format!("{base}-{idx}"));
    }

    assert!(
        map.len() <= QUOTA_USER_LOCKS_MAX,
        "quota lock cache must stay bounded under unique-user churn"
    );
}

#[test]
fn quota_lock_saturation_returns_stable_overflow_lock_without_cache_growth() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let prefix = format!("quota-held-{}", std::process::id());
    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("{prefix}-{idx}")));
    }

    assert_eq!(
        map.len(),
        QUOTA_USER_LOCKS_MAX,
        "cache must be saturated for overflow check"
    );

    let overflow_user = format!("quota-overflow-{}", std::process::id());
    let overflow_a = quota_user_lock(&overflow_user);
    let overflow_b = quota_user_lock(&overflow_user);

    assert_eq!(
        map.len(),
        QUOTA_USER_LOCKS_MAX,
        "overflow path must not grow lock cache"
    );
    assert!(
        map.get(&overflow_user).is_none(),
        "overflow user lock must stay outside bounded cache under saturation"
    );
    assert!(
        Arc::ptr_eq(&overflow_a, &overflow_b),
        "overflow user must receive stable striped overflow lock while saturated"
    );

    drop(retained);
}

#[test]
fn quota_lock_reclaims_unreferenced_entries_before_ephemeral_fallback() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    // Saturate with retained strong references first so parallel tests cannot
    // reclaim our fixture entries before we validate the reclaim path.
    let prefix = format!("quota-reclaim-drop-{}", std::process::id());
    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("{prefix}-{idx}")));
    }

    drop(retained);

    let overflow_user = format!("quota-reclaim-overflow-{}", std::process::id());
    let overflow = quota_user_lock(&overflow_user);

    assert!(
        map.get(&overflow_user).is_some(),
        "after reclaiming stale entries, overflow user should become cacheable"
    );
    assert!(
        Arc::strong_count(&overflow) >= 2,
        "cacheable overflow lock should be held by both map and caller"
    );
}

#[test]
fn quota_lock_saturated_same_user_must_not_return_distinct_locks() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("quota-saturated-held-{}-{idx}", std::process::id())));
    }

    let overflow_user = format!("quota-saturated-same-user-{}", std::process::id());
    let a = quota_user_lock(&overflow_user);
    let b = quota_user_lock(&overflow_user);

    assert!(
        Arc::ptr_eq(&a, &b),
        "same user must not receive distinct locks under saturation because that enables quota race bypass"
    );

    drop(retained);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_lock_saturation_concurrent_same_user_never_overshoots_quota() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("quota-saturated-race-held-{}-{idx}", std::process::id())));
    }

    let stats = Arc::new(Stats::new());
    let user = format!("quota-saturated-race-user-{}", std::process::id());
    let gate = Arc::new(Barrier::new(2));

    let worker = |label: u8, stats: Arc<Stats>, user: String, gate: Arc<Barrier>| {
        tokio::spawn(async move {
            let counters = Arc::new(SharedCounters::new());
            let quota_exceeded = Arc::new(AtomicBool::new(false));
            let mut io = StatsIo::new(
                tokio::io::sink(),
                counters,
                Arc::clone(&stats),
                user,
                Some(1),
                quota_exceeded,
                Instant::now(),
            );
            gate.wait().await;
            io.write_all(&[label]).await
        })
    };

    let one = worker(0x11, Arc::clone(&stats), user.clone(), Arc::clone(&gate));
    let two = worker(0x22, Arc::clone(&stats), user.clone(), Arc::clone(&gate));

    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = one.await.expect("task one must not panic");
        let _ = two.await.expect("task two must not panic");
    })
    .await
    .expect("quota race workers must complete");

    assert!(
        stats.get_user_total_octets(&user) <= 1,
        "saturated lock path must never overshoot quota for same user"
    );

    drop(retained);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_lock_saturation_stress_same_user_never_overshoots_quota() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("quota-saturated-stress-held-{}-{idx}", std::process::id())));
    }

    for round in 0..128u32 {
        let stats = Arc::new(Stats::new());
        let user = format!("quota-saturated-stress-user-{}-{round}", std::process::id());
        let gate = Arc::new(Barrier::new(2));

        let one = {
            let stats = Arc::clone(&stats);
            let user = user.clone();
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                let counters = Arc::new(SharedCounters::new());
                let quota_exceeded = Arc::new(AtomicBool::new(false));
                let mut io = StatsIo::new(
                    tokio::io::sink(),
                    counters,
                    Arc::clone(&stats),
                    user,
                    Some(1),
                    quota_exceeded,
                    Instant::now(),
                );
                gate.wait().await;
                io.write_all(&[0x31]).await
            })
        };

        let two = {
            let stats = Arc::clone(&stats);
            let user = user.clone();
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                let counters = Arc::new(SharedCounters::new());
                let quota_exceeded = Arc::new(AtomicBool::new(false));
                let mut io = StatsIo::new(
                    tokio::io::sink(),
                    counters,
                    Arc::clone(&stats),
                    user,
                    Some(1),
                    quota_exceeded,
                    Instant::now(),
                );
                gate.wait().await;
                io.write_all(&[0x32]).await
            })
        };

        let _ = one.await.expect("stress task one must not panic");
        let _ = two.await.expect("stress task two must not panic");

        assert!(
            stats.get_user_total_octets(&user) <= 1,
            "round {round}: saturated path must not overshoot quota"
        );
    }

    drop(retained);
}

#[test]
fn quota_error_classifier_accepts_internal_quota_sentinel_only() {
    let err = quota_io_error();
    assert!(is_quota_io_error(&err));
}

#[test]
fn quota_error_classifier_rejects_plain_permission_denied() {
    let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
    assert!(!is_quota_io_error(&err));
}

#[test]
fn quota_lock_test_scope_recovers_after_guard_poison() {
    let poison_result = std::thread::spawn(|| {
        let _guard = super::quota_user_lock_test_scope();
        panic!("intentional test-only guard poison");
    })
    .join();
    assert!(poison_result.is_err(), "poison setup thread must panic");

    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let a = quota_user_lock("quota-lock-poison-recovery-user");
    let b = quota_user_lock("quota-lock-poison-recovery-user");
    assert!(Arc::ptr_eq(&a, &b));
}

#[tokio::test]
async fn quota_lock_integration_zero_quota_cuts_off_without_forwarding() {
    let stats = Arc::new(Stats::new());
    let user = "quota-zero-user";

    let (mut client_peer, relay_client) = duplex(2048);
    let (relay_server, mut server_peer) = duplex(2048);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        512,
        512,
        user,
        Arc::clone(&stats),
        Some(0),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(b"x")
        .await
        .expect("client write must succeed");

    let mut probe = [0u8; 1];
    let forwarded = tokio::time::timeout(Duration::from_millis(80), server_peer.read(&mut probe)).await;
    if let Ok(Ok(n)) = forwarded {
        assert_eq!(n, 0, "zero quota path must not forward payload bytes");
    }

    let result = tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate under zero quota")
        .expect("relay task must not panic");
    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
}

#[tokio::test]
async fn quota_lock_integration_no_quota_relays_both_directions_under_burst() {
    let stats = Arc::new(Stats::new());

    let (mut client_peer, relay_client) = duplex(8192);
    let (relay_server, mut server_peer) = duplex(8192);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        "quota-none-burst-user",
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    let c2s = vec![0xA5; 2048];
    let s2c = vec![0x5A; 1536];

    client_peer.write_all(&c2s).await.expect("client burst write must succeed");
    let mut got_c2s = vec![0u8; c2s.len()];
    server_peer.read_exact(&mut got_c2s).await.expect("server must receive c2s burst");
    assert_eq!(got_c2s, c2s);

    server_peer.write_all(&s2c).await.expect("server burst write must succeed");
    let mut got_s2c = vec![0u8; s2c.len()];
    client_peer.read_exact(&mut got_s2c).await.expect("client must receive s2c burst");
    assert_eq!(got_s2c, s2c);

    drop(client_peer);
    drop(server_peer);

    let done = tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate after peers close")
        .expect("relay task must not panic");
    assert!(done.is_ok());
}
