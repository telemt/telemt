use super::*;
use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::crypto::AesCtr;
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter, PooledBuffer};
use crate::transport::middle_proxy::MePool;
use bytes::Bytes;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::duplex;
use tokio::sync::Barrier;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_pooled_payload(data: &[u8]) -> PooledBuffer {
    let pool = Arc::new(BufferPool::with_config(data.len().max(1), 4));
    let mut payload = pool.get();
    payload.resize(data.len(), 0);
    payload[..data.len()].copy_from_slice(data);
    payload
}

fn make_pooled_payload_from(pool: &Arc<BufferPool>, data: &[u8]) -> PooledBuffer {
    let mut payload = pool.get();
    payload.resize(data.len(), 0);
    payload[..data.len()].copy_from_slice(data);
    payload
}

#[test]
fn should_yield_sender_only_on_budget_with_backlog() {
    assert!(!should_yield_c2me_sender(0, true));
    assert!(!should_yield_c2me_sender(
        C2ME_SENDER_FAIRNESS_BUDGET - 1,
        true
    ));
    assert!(!should_yield_c2me_sender(
        C2ME_SENDER_FAIRNESS_BUDGET,
        false
    ));
    assert!(should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, true));
}

#[tokio::test]
async fn enqueue_c2me_command_uses_try_send_fast_path() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(2);
    enqueue_c2me_command(
        &tx,
        C2MeCommand::Data {
            payload: make_pooled_payload(&[1, 2, 3]),
            flags: 0,
        },
    )
    .await
    .unwrap();

    let recv = timeout(TokioDuration::from_millis(50), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[1, 2, 3]);
            assert_eq!(flags, 0);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[tokio::test]
async fn enqueue_c2me_command_falls_back_to_send_when_queue_is_full() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[9]),
        flags: 9,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let producer = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: make_pooled_payload(&[7, 7]),
                flags: 7,
            },
        )
        .await
        .unwrap();
    });

    let _ = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap();
    producer.await.unwrap();

    let recv = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[7, 7]);
            assert_eq!(flags, 7);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[tokio::test]
async fn enqueue_c2me_command_closed_channel_recycles_payload() {
    let pool = Arc::new(BufferPool::with_config(64, 4));
    let payload = make_pooled_payload_from(&pool, &[1, 2, 3, 4]);
    let (tx, rx) = mpsc::channel::<C2MeCommand>(1);
    drop(rx);

    let result = enqueue_c2me_command(&tx, C2MeCommand::Data { payload, flags: 0 }).await;

    assert!(result.is_err(), "closed queue must fail enqueue");
    drop(result);
    assert!(
        pool.stats().pooled >= 1,
        "payload must return to pool when enqueue fails on closed channel"
    );
}

#[tokio::test]
async fn enqueue_c2me_command_full_then_closed_recycles_waiting_payload() {
    let pool = Arc::new(BufferPool::with_config(64, 4));
    let (tx, rx) = mpsc::channel::<C2MeCommand>(1);

    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload_from(&pool, &[9]),
        flags: 1,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let pool2 = pool.clone();
    let blocked_send = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: make_pooled_payload_from(&pool2, &[7, 7, 7]),
                flags: 2,
            },
        )
        .await
    });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;
    drop(rx);

    let result = timeout(TokioDuration::from_secs(1), blocked_send)
        .await
        .expect("blocked send task must finish")
        .expect("blocked send task must not panic");

    assert!(
        result.is_err(),
        "closing receiver while sender is blocked must fail enqueue"
    );
    drop(result);
    assert!(
        pool.stats().pooled >= 2,
        "both queued and blocked payloads must return to pool after channel close"
    );
}

#[tokio::test]
async fn enqueue_c2me_command_full_queue_times_out_without_receiver_progress() {
    let (tx, _rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[1]),
        flags: 0,
    })
    .await
    .unwrap();

    let started = Instant::now();
    let result = enqueue_c2me_command(
        &tx,
        C2MeCommand::Data {
            payload: make_pooled_payload(&[2, 2]),
            flags: 1,
        },
    )
    .await;

    assert!(
        result.is_err(),
        "enqueue must fail when queue stays full beyond bounded timeout"
    );
    assert!(
        started.elapsed() < TokioDuration::from_millis(400),
        "full-queue timeout must resolve promptly"
    );
}

#[test]
fn desync_dedup_cache_is_bounded() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(
            should_emit_full_desync(key, false, now),
            "unique keys up to cap must be tracked"
        );
    }

    assert!(
        should_emit_full_desync(u64::MAX, false, now),
        "new key above cap must emit once after bounded eviction for forensic visibility"
    );

    assert!(
        !should_emit_full_desync(u64::MAX, false, now),
        "already tracked key inside dedup window must stay suppressed"
    );
}

#[test]
fn quota_user_lock_cache_reuses_entry_for_same_user() {
    let _guard = super::quota_user_lock_test_scope();

    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let a = quota_user_lock("quota-user-a");
    let b = quota_user_lock("quota-user-a");
    assert!(Arc::ptr_eq(&a, &b), "same user must reuse same quota lock");
}

#[test]
fn quota_user_lock_cache_is_bounded_under_unique_churn() {
    let _guard = super::quota_user_lock_test_scope();

    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    for idx in 0..(QUOTA_USER_LOCKS_MAX + 128) {
        let user = format!("quota-user-{idx}");
        let lock = quota_user_lock(&user);
        drop(lock);
    }

    assert!(
        map.len() <= QUOTA_USER_LOCKS_MAX,
        "quota lock cache must stay within configured bound"
    );
}

#[test]
fn quota_user_lock_cache_saturation_returns_stable_overflow_lock_without_growth() {
    let _guard = super::quota_user_lock_test_scope();

    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    for attempt in 0..8u32 {
        map.clear();

        let prefix = format!("quota-held-user-{}-{attempt}", std::process::id());
        let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
        for idx in 0..QUOTA_USER_LOCKS_MAX {
            let user = format!("{prefix}-{idx}");
            retained.push(quota_user_lock(&user));
        }

        if map.len() != QUOTA_USER_LOCKS_MAX {
            drop(retained);
            continue;
        }

        let overflow_user = format!("quota-overflow-user-{}-{attempt}", std::process::id());
        let overflow_a = quota_user_lock(&overflow_user);
        let overflow_b = quota_user_lock(&overflow_user);

        assert_eq!(
            map.len(),
            QUOTA_USER_LOCKS_MAX,
            "overflow acquisition must not grow cache past hard limit"
        );
        assert!(
            map.get(&overflow_user).is_none(),
            "overflow path should not cache new user lock when map is saturated and all entries are retained"
        );
        assert!(
            Arc::ptr_eq(&overflow_a, &overflow_b),
            "overflow user lock should use deterministic striping under saturation"
        );

        drop(retained);
        return;
    }

    panic!("unable to observe stable saturated lock-cache precondition after bounded retries");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_quota_race_under_lock_cache_saturation_still_allows_only_one_winner() {
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        let user = format!("quota-saturated-user-{idx}");
        retained.push(quota_user_lock(&user));
    }

    assert_eq!(
        map.len(),
        QUOTA_USER_LOCKS_MAX,
        "precondition: cache must be saturated for overflow-user race test"
    );

    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);
    let user = "gap-t04-saturated-lock-race-user";
    let barrier = Arc::new(Barrier::new(2));

    let one = run_quota_race_attempt(&stats, &bytes_me2c, user, 0x55, 9101, barrier.clone());
    let two = run_quota_race_attempt(&stats, &bytes_me2c, user, 0x66, 9102, barrier);
    let (r1, r2) = tokio::join!(one, two);

    assert!(
        matches!(r1, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. }))
            && matches!(r2, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. })),
        "both racers must resolve cleanly without unexpected errors"
    );
    assert!(
        matches!(r1, Err(ProxyError::DataQuotaExceeded { .. }))
            || matches!(r2, Err(ProxyError::DataQuotaExceeded { .. })),
        "at least one racer must be quota-rejected even when lock cache is saturated"
    );
    assert_eq!(
        stats.get_user_total_octets(user),
        1,
        "saturated lock cache must not permit double-success quota overshoot"
    );

    drop(retained);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_quota_race_under_lock_cache_saturation_never_allows_double_success() {
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        let user = format!("quota-saturated-stress-holder-{idx}");
        retained.push(quota_user_lock(&user));
    }

    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    for round in 0..128u64 {
        let user = format!("gap-t04-saturated-race-round-{round}");
        let barrier = Arc::new(Barrier::new(2));

        let one = run_quota_race_attempt(
            &stats,
            &bytes_me2c,
            &user,
            0x71,
            12_000 + round,
            barrier.clone(),
        );
        let two = run_quota_race_attempt(&stats, &bytes_me2c, &user, 0x72, 13_000 + round, barrier);

        let (r1, r2) = tokio::join!(one, two);
        assert!(
            matches!(r1, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. }))
                && matches!(r2, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. })),
            "round {round}: racers must resolve cleanly"
        );
        assert!(
            matches!(r1, Err(ProxyError::DataQuotaExceeded { .. }))
                || matches!(r2, Err(ProxyError::DataQuotaExceeded { .. })),
            "round {round}: at least one racer must be quota-rejected"
        );
        assert_eq!(
            stats.get_user_total_octets(&user),
            1,
            "round {round}: saturated cache must still enforce exactly one forwarded byte"
        );
    }

    drop(retained);
}

#[test]
fn adversarial_forensics_trace_id_should_not_alias_conn_id() {
    let now = Instant::now();
    let trace_id = 0x1122_3344_5566_7788;
    let conn_id = 0x8877_6655_4433_2211;
    let state = RelayForensicsState {
        trace_id,
        conn_id,
        user: "trace-user".to_string(),
        peer: "198.51.100.17:443".parse().unwrap(),
        peer_hash: 0x8877_6655_4433_2211,
        started_at: now,
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    };

    assert_ne!(
        state.trace_id, state.conn_id,
        "security expectation: trace correlation should be independent of connection identity"
    );
    assert_eq!(state.trace_id, trace_id);
    assert_eq!(state.conn_id, conn_id);
}

#[tokio::test]
async fn abridged_ack_uses_big_endian_confirm_bytes_after_decryption() {
    let (mut writer_side, reader_side) = duplex(8);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(reader_side, AesCtr::new(&key, iv), 8 * 1024);

    write_client_ack(&mut writer, ProtoTag::Abridged, 0x11_22_33_44)
        .await
        .expect("ack write must succeed");

    let mut observed = [0u8; 4];
    writer_side
        .read_exact(&mut observed)
        .await
        .expect("ack bytes must be readable");
    let mut decryptor = AesCtr::new(&key, iv);
    let decrypted = decryptor.decrypt(&observed);

    assert_eq!(
        decrypted,
        0x11_22_33_44u32.to_be_bytes(),
        "abridged ACK should encode confirm bytes in big-endian order"
    );
}

#[test]
fn desync_dedup_full_cache_churn_stays_suppressed() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(should_emit_full_desync(key, false, now));
    }

    for offset in 0..2048u64 {
        let emitted = should_emit_full_desync(u64::MAX - offset, false, now);
        if offset == 0 {
            assert!(
                emitted,
                "first full-cache newcomer should emit for forensic visibility"
            );
        } else {
            assert!(
                !emitted,
                "full-cache newcomer churn inside emit interval must stay suppressed"
            );
        }
    }
}

#[test]
fn dedup_hash_is_stable_for_same_input_within_process() {
    let sample = (
        "scope_user",
        hash_ip("198.51.100.7".parse().unwrap()),
        ProtoTag::Secure,
    );
    let first = hash_value(&sample);
    let second = hash_value(&sample);
    assert_eq!(
        first, second,
        "dedup hash must be stable within a process for cache lookups"
    );
}

#[test]
fn dedup_hash_resists_simple_collision_bursts_for_peer_ip_space() {
    let mut seen = HashSet::new();

    for octet in 1u16..=2048 {
        let third = ((octet / 256) & 0xff) as u8;
        let fourth = (octet & 0xff) as u8;
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, third, fourth));
        let key = hash_value(&(
            "scope_user",
            hash_ip(ip),
            ProtoTag::Secure,
            DESYNC_ERROR_CLASS,
        ));
        seen.insert(key);
    }

    assert_eq!(
        seen.len(),
        2048,
        "adversarial peer-IP burst should not collapse dedup keys via trivial collisions"
    );
}

#[test]
fn light_fuzz_dedup_hash_collision_rate_stays_negligible() {
    let mut rng = StdRng::seed_from_u64(0x9E37_79B9_A1B2_C3D4);
    let mut seen = HashSet::new();
    let samples = 8192usize;

    for _ in 0..samples {
        let user_seed: u64 = rng.random();
        let peer_seed: u64 = rng.random();
        let proto = if (peer_seed & 1) == 0 {
            ProtoTag::Secure
        } else {
            ProtoTag::Intermediate
        };
        let key = hash_value(&(user_seed, peer_seed, proto, DESYNC_ERROR_CLASS));
        seen.insert(key);
    }

    let collisions = samples - seen.len();
    assert!(
        collisions <= 1,
        "light fuzz collision count should remain negligible for 64-bit dedup keys"
    );
}

#[test]
fn stress_desync_dedup_churn_keeps_cache_hard_bounded() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    let total = DESYNC_DEDUP_MAX_ENTRIES + 8192;

    let mut emitted_count = 0usize;
    for key in 0..total as u64 {
        let emitted = should_emit_full_desync(key, false, now);
        if emitted {
            emitted_count += 1;
        }
    }

    assert_eq!(
        emitted_count,
        DESYNC_DEDUP_MAX_ENTRIES + 1,
        "after capacity is reached, same-tick newcomer churn must be rate-limited"
    );

    let len = DESYNC_DEDUP
        .get()
        .expect("dedup cache must be initialized by stress run")
        .len();
    assert!(
        len <= DESYNC_DEDUP_MAX_ENTRIES,
        "dedup cache must stay bounded under stress churn"
    );
}

#[test]
fn full_cache_newcomer_emission_is_rate_limited_but_periodic() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();

    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    // Same-tick newcomer storm: only the first should emit full forensic record.
    let mut burst_emits = 0usize;
    for i in 0..1024u64 {
        if should_emit_full_desync(10_000_000 + i, false, base_now) {
            burst_emits += 1;
        }
    }
    assert_eq!(
        burst_emits, 1,
        "full-cache newcomer burst must be bounded to a single full emit per interval"
    );

    // After each interval elapses, one newcomer may emit again.
    for step in 1..=6u64 {
        let t = base_now + DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL * step as u32;
        assert!(
            should_emit_full_desync(20_000_000 + step, false, t),
            "full-cache newcomer should re-emit once interval has elapsed"
        );
        assert!(
            !should_emit_full_desync(30_000_000 + step, false, t),
            "additional newcomers in the same interval tick must remain suppressed"
        );
    }
}

#[test]
fn full_cache_mode_override_emits_every_event() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for i in 0..10_000u64 {
        assert!(
            should_emit_full_desync(100_000_000 + i, true, now),
            "desync_all_full override must bypass dedup and rate-limit suppression"
        );
    }
}

#[test]
fn report_desync_stats_follow_rate_limited_full_cache_policy() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    let stats = Stats::new();
    let mut state = make_forensics_state();
    state.started_at = base_now;

    for i in 0..128u64 {
        state.peer_hash = 0xABC0_0000_0000_0000u64 ^ i;
        let _ = report_desync_frame_too_large(
            &state,
            ProtoTag::Secure,
            3,
            1024,
            4096,
            Some([0x16, 0x03, 0x03, 0x00]),
            &stats,
        );
    }

    assert_eq!(
        stats.get_desync_total(),
        128,
        "every detected desync must increment total counter"
    );
    assert_eq!(
        stats.get_desync_full_logged(),
        1,
        "same-interval full-cache newcomer storm must allow only one full forensic emit"
    );
    assert_eq!(
        stats.get_desync_suppressed(),
        127,
        "remaining same-interval full-cache newcomer events must be suppressed"
    );

    // After one full interval in real wall clock, a newcomer should emit again.
    thread::sleep(DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL + TokioDuration::from_millis(20));
    state.peer_hash = 0xDEAD_BEEF_DEAD_BEEFu64;
    let _ = report_desync_frame_too_large(
        &state,
        ProtoTag::Secure,
        4,
        1024,
        4097,
        Some([0x16, 0x03, 0x03, 0x01]),
        &stats,
    );

    assert_eq!(
        stats.get_desync_full_logged(),
        2,
        "full forensic emission must recover after rate-limit interval"
    );
}

#[test]
fn concurrent_full_cache_newcomer_storm_is_single_emit_per_interval() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    let emits = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for worker_id in 0..32u64 {
        let emits = Arc::clone(&emits);
        workers.push(thread::spawn(move || {
            for i in 0..512u64 {
                let key = 0x7000_0000_0000_0000u64 ^ (worker_id << 20) ^ i;
                if should_emit_full_desync(key, false, base_now) {
                    emits.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("worker thread must not panic");
    }

    assert_eq!(
        emits.load(Ordering::Relaxed),
        1,
        "concurrent same-interval full-cache storm must allow only one full forensic emit"
    );
}

#[test]
fn light_fuzz_full_cache_rate_limit_oracle_matches_model() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    let mut rng = StdRng::seed_from_u64(0xD15EA5E5_F00DBAAD);
    let mut model_last_emit: Option<Instant> = None;

    for i in 0..4096u64 {
        let jitter_ms: u64 = rng.random_range(0..=3000);
        let t = base_now + TokioDuration::from_millis(jitter_ms);
        let key = 0x55AA_0000_0000_0000u64 ^ i ^ rng.random::<u64>();
        let actual = should_emit_full_desync(key, false, t);

        let expected = match model_last_emit {
            None => {
                model_last_emit = Some(t);
                true
            }
            Some(last) => {
                match t.checked_duration_since(last) {
                    Some(elapsed) if elapsed >= DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL => {
                        model_last_emit = Some(t);
                        true
                    }
                    Some(_) => false,
                    None => {
                        // Match production fail-open behavior for non-monotonic synthetic input.
                        model_last_emit = Some(t);
                        true
                    }
                }
            }
        };

        assert_eq!(
            actual, expected,
            "full-cache rate-limit gate diverged from reference model under light fuzz"
        );
    }
}

#[test]
fn full_cache_gate_lock_poison_is_fail_closed_without_panic() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    // Poison the full-cache gate lock intentionally.
    let gate = DESYNC_FULL_CACHE_LAST_EMIT_AT.get_or_init(|| Mutex::new(None));
    let _ = std::panic::catch_unwind(|| {
        let _lock = gate
            .lock()
            .expect("gate lock must be lockable before poison");
        panic!("intentional gate poison for fail-closed regression");
    });

    let emitted = should_emit_full_desync(0xFACE_0000_0000_0001, false, base_now);
    assert!(
        !emitted,
        "poisoned full-cache gate must fail-closed (suppress) instead of panic or fail-open"
    );
    assert!(
        dedup.len() <= DESYNC_DEDUP_MAX_ENTRIES,
        "dedup cache must remain bounded even when gate lock is poisoned"
    );
}

#[test]
fn full_cache_non_monotonic_time_emits_and_resets_gate_safely() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    // First event seeds the gate.
    assert!(should_emit_full_desync(
        0xABCD_0000_0000_0001,
        false,
        base_now + TokioDuration::from_millis(900)
    ));

    // Synthetic earlier timestamp must not panic; it should fail-open and reset gate.
    assert!(should_emit_full_desync(
        0xABCD_0000_0000_0002,
        false,
        base_now + TokioDuration::from_millis(100)
    ));

    // Same instant again remains suppressed after reset.
    assert!(!should_emit_full_desync(
        0xABCD_0000_0000_0003,
        false,
        base_now + TokioDuration::from_millis(100)
    ));
}

#[test]
fn desync_dedup_full_cache_inserts_new_key_with_bounded_single_key_churn() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let base_now = Instant::now();

    // Fill with fresh entries so stale-pruning does not apply.
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        dedup.insert(key, base_now - TokioDuration::from_millis(10));
    }

    let before_keys: std::collections::HashSet<u64> = dedup.iter().map(|e| *e.key()).collect();

    let newcomer_key = u64::MAX;
    let emitted = should_emit_full_desync(newcomer_key, false, base_now);
    assert!(
        emitted,
        "new entry under full fresh cache must emit after bounded eviction"
    );
    assert!(
        dedup.get(&newcomer_key).is_some(),
        "new key must be inserted after bounded eviction"
    );

    let after_keys: std::collections::HashSet<u64> = dedup.iter().map(|e| *e.key()).collect();
    let removed_count = before_keys.difference(&after_keys).count();
    let added_count = after_keys.difference(&before_keys).count();

    assert_eq!(
        removed_count, 1,
        "full-cache insertion must evict exactly one prior key"
    );
    assert_eq!(
        added_count, 1,
        "full-cache insertion must add exactly one newcomer key"
    );
    assert!(
        dedup.len() <= DESYNC_DEDUP_MAX_ENTRIES,
        "dedup cache must remain hard-bounded after full-cache churn"
    );
}

#[test]
fn light_fuzz_desync_dedup_temporal_gate_behavior_is_stable() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let key = 0xC0DE_CAFE_u64;
    let start = Instant::now();

    assert!(
        should_emit_full_desync(key, false, start),
        "first event for key must emit full forensic record"
    );

    // Deterministic pseudo-random time deltas around dedup window edge.
    let mut s: u64 = 0x1234_5678_9ABC_DEF0;
    for _ in 0..2048 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;

        let delta_ms = s % (DESYNC_DEDUP_WINDOW.as_millis() as u64 * 2 + 1);
        let now = start + TokioDuration::from_millis(delta_ms);
        let emitted = should_emit_full_desync(key, false, now);

        if delta_ms < DESYNC_DEDUP_WINDOW.as_millis() as u64 {
            assert!(
                !emitted,
                "events inside dedup window must remain suppressed"
            );
        } else {
            // Once window elapsed for this key, at least one sample should re-emit and refresh.
            if emitted {
                return;
            }
        }
    }

    panic!("expected at least one post-window sample to re-emit forensic record");
}

fn make_forensics_state() -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 1,
        conn_id: 2,
        user: "test-user".to_string(),
        peer: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        peer_hash: 3,
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

fn make_crypto_reader<R>(reader: R) -> CryptoReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

async fn make_me_pool_for_abort_test(stats: Arc<Stats>) -> Arc<MePool> {
    let general = GeneralConfig::default();

    MePool::new(
        None,
        vec![1u8; 32],
        None,
        false,
        None,
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
        Arc::new(SecureRandom::new()),
        stats,
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
        MeWriterPickMode::default(),
        general.me_writer_pick_sample_size,
        MeSocksKdfPolicy::default(),
        general.me_writer_cmd_channel_capacity,
        general.me_route_channel_capacity,
        general.me_route_backpressure_base_timeout_ms,
        general.me_route_backpressure_high_timeout_ms,
        general.me_route_backpressure_high_watermark_pct,
        general.me_reader_route_data_wait_ms,
        general.me_health_interval_ms_unhealthy,
        general.me_health_interval_ms_healthy,
        general.me_warn_rate_limit_ms,
        MeRouteNoWriterMode::default(),
        general.me_route_no_writer_wait_ms,
        general.me_route_inline_recovery_attempts,
        general.me_route_inline_recovery_wait_ms,
    )
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

#[tokio::test]
async fn read_client_payload_times_out_on_header_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled header read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_times_out_on_payload_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, mut writer) = duplex(1024);
    let encrypted_len = encrypt_for_reader(&[8, 0, 0, 0]);
    writer.write_all(&encrypted_len).await.unwrap();

    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled payload body read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_large_intermediate_frame_is_exact() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(262_144);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload_len = buffer_pool.buffer_size().saturating_mul(3).max(65_537);
    let mut plaintext = Vec::with_capacity(4 + payload_len);
    plaintext.extend_from_slice(&(payload_len as u32).to_le_bytes());
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_mul(31)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        payload_len + 16,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(
        frame.len(),
        payload_len,
        "payload size must match wire length"
    );
    for (idx, byte) in frame.iter().enumerate() {
        assert_eq!(*byte, (idx as u8).wrapping_mul(31));
    }
    assert_eq!(frame_counter, 1, "exactly one frame must be counted");
}

#[tokio::test]
async fn read_client_payload_secure_strips_tail_padding_bytes() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [0x11u8, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
    let tail = [0xeeu8, 0xff, 0x99];
    let wire_len = payload.len() + tail.len();

    let mut plaintext = Vec::with_capacity(4 + wire_len);
    plaintext.extend_from_slice(&(wire_len as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    plaintext.extend_from_slice(&tail);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("secure payload read must succeed")
    .expect("secure frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(frame_counter, 1, "one secure frame must be counted");
}

#[tokio::test]
async fn read_client_payload_secure_rejects_wire_len_below_4() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let mut plaintext = Vec::with_capacity(7);
    plaintext.extend_from_slice(&3u32.to_le_bytes());
    plaintext.extend_from_slice(&[1u8, 2, 3]);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Proxy(ref msg)) if msg.contains("Frame too small: 3")),
        "secure wire length below 4 must be fail-closed by the frame-too-small guard"
    );
}

#[tokio::test]
async fn read_client_payload_intermediate_skips_zero_len_frame() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [7u8, 6, 5, 4, 3, 2, 1, 0];
    let mut plaintext = Vec::with_capacity(4 + 4 + payload.len());
    plaintext.extend_from_slice(&0u32.to_le_bytes());
    plaintext.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("intermediate payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(frame_counter, 1, "zero-length frame must be skipped");
}

#[tokio::test]
async fn read_client_payload_abridged_extended_len_sets_quickack() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload_len = 4 * 130;
    let len_words = (payload_len / 4) as u32;
    let mut plaintext = Vec::with_capacity(1 + 3 + payload_len);
    plaintext.push(0xff | 0x80);
    let lw = len_words.to_le_bytes();
    plaintext.extend_from_slice(&lw[..3]);
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_add(17)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Abridged,
        payload_len + 16,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("abridged payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(
        quickack,
        "quickack bit must be propagated from abridged header"
    );
    assert_eq!(frame.len(), payload_len);
    assert_eq!(frame_counter, 1, "one abridged frame must be counted");
}

#[tokio::test]
async fn read_client_payload_returns_buffer_to_pool_after_emit() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let pool = Arc::new(BufferPool::with_config(64, 8));
    pool.preallocate(1);
    assert_eq!(pool.stats().pooled, 1, "precondition: one pooled buffer");

    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    // Force growth beyond default pool buffer size to catch ownership-take regressions.
    let payload_len = 257usize;
    let mut plaintext = Vec::with_capacity(4 + payload_len);
    plaintext.extend_from_slice(&(payload_len as u32).to_le_bytes());
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_mul(13)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let _ = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        payload_len + 8,
        TokioDuration::from_secs(1),
        &pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    assert_eq!(frame_counter, 1);
    let pool_stats = pool.stats();
    assert!(
        pool_stats.pooled >= 1,
        "emitted payload buffer must be returned to pool to avoid pool drain"
    );
}

#[tokio::test]
async fn read_client_payload_keeps_pool_buffer_checked_out_until_frame_drop() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let pool = Arc::new(BufferPool::with_config(64, 2));
    pool.preallocate(1);
    assert_eq!(
        pool.stats().pooled,
        1,
        "one pooled buffer must be available"
    );

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [0x41u8, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];
    let mut plaintext = Vec::with_capacity(4 + payload.len());
    plaintext.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let (frame, quickack) = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_secs(1),
        &pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    assert!(!quickack);
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(
        pool.stats().pooled,
        0,
        "buffer must stay checked out while frame payload is alive"
    );

    drop(frame);
    assert!(
        pool.stats().pooled >= 1,
        "buffer must return to pool only after frame drop"
    );
}

#[tokio::test]
async fn enqueue_c2me_close_unblocks_after_queue_drain() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[0x41]),
        flags: 0,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let close_task =
        tokio::spawn(async move { enqueue_c2me_command(&tx2, C2MeCommand::Close).await });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;

    let first = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .expect("first queued item must be present");
    assert!(matches!(first, C2MeCommand::Data { .. }));

    close_task
        .await
        .unwrap()
        .expect("close enqueue must succeed after drain");

    let second = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .expect("close command must follow after queue drain");
    assert!(matches!(second, C2MeCommand::Close));
}

#[tokio::test]
async fn enqueue_c2me_close_full_then_receiver_drop_fails_cleanly() {
    let (tx, rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[0x42]),
        flags: 0,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let close_task =
        tokio::spawn(async move { enqueue_c2me_command(&tx2, C2MeCommand::Close).await });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;
    drop(rx);

    let result = timeout(TokioDuration::from_secs(1), close_task)
        .await
        .expect("close task must finish")
        .expect("close task must not panic");
    assert!(
        result.is_err(),
        "close enqueue must fail cleanly when receiver is dropped under pressure"
    );
}

#[tokio::test]
async fn process_me_writer_response_ack_obeys_flush_policy() {
    let (writer_side, _reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    let immediate = process_me_writer_response(
        MeResponse::Ack(0x11223344),
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "user",
        None,
        &bytes_me2c,
        77,
        true,
        false,
    )
    .await
    .expect("ack response must be processed");

    assert!(matches!(
        immediate,
        MeWriterResponseOutcome::Continue {
            frames: 1,
            bytes: 4,
            flush_immediately: true,
        }
    ));

    let delayed = process_me_writer_response(
        MeResponse::Ack(0x55667788),
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "user",
        None,
        &bytes_me2c,
        77,
        false,
        false,
    )
    .await
    .expect("ack response must be processed");

    assert!(matches!(
        delayed,
        MeWriterResponseOutcome::Continue {
            frames: 1,
            bytes: 4,
            flush_immediately: false,
        }
    ));
}

#[tokio::test]
async fn process_me_writer_response_data_updates_byte_accounting() {
    let (writer_side, _reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    let payload = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let outcome = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from(payload.clone()),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "user",
        None,
        &bytes_me2c,
        88,
        false,
        false,
    )
    .await
    .expect("data response must be processed");

    assert!(matches!(
        outcome,
        MeWriterResponseOutcome::Continue {
            frames: 1,
            bytes,
            flush_immediately: false,
        } if bytes == payload.len()
    ));
    assert_eq!(
        bytes_me2c.load(std::sync::atomic::Ordering::Relaxed),
        payload.len() as u64,
        "ME->C byte accounting must increase by emitted payload size"
    );
}

#[tokio::test]
async fn process_me_writer_response_data_enforces_live_user_quota() {
    let (writer_side, mut reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    stats.add_user_octets_from("quota-user", 10);

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from(vec![1u8, 2, 3, 4]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "quota-user",
        Some(12),
        &bytes_me2c,
        89,
        false,
        false,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::DataQuotaExceeded { user }) if user == "quota-user"),
        "ME->client runtime path must terminate when live user quota is crossed"
    );

    let mut raw = [0u8; 1];
    assert!(
        timeout(TokioDuration::from_millis(100), reader_side.read(&mut raw))
            .await
            .is_err(),
        "quota exhaustion must not write any ciphertext to the client stream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_me_writer_response_concurrent_same_user_quota_does_not_overshoot_limit() {
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);
    let user = "quota-race-user";

    let (writer_side_a, _reader_side_a) = duplex(1024);
    let (writer_side_b, _reader_side_b) = duplex(1024);
    let mut writer_a = make_crypto_writer(writer_side_a);
    let mut writer_b = make_crypto_writer(writer_side_b);
    let mut frame_buf_a = Vec::new();
    let mut frame_buf_b = Vec::new();
    let rng_a = SecureRandom::new();
    let rng_b = SecureRandom::new();

    let fut_a = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[0x11]),
        },
        &mut writer_a,
        ProtoTag::Intermediate,
        &rng_a,
        &mut frame_buf_a,
        &stats,
        user,
        Some(1),
        &bytes_me2c,
        91,
        false,
        false,
    );
    let fut_b = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[0x22]),
        },
        &mut writer_b,
        ProtoTag::Intermediate,
        &rng_b,
        &mut frame_buf_b,
        &stats,
        user,
        Some(1),
        &bytes_me2c,
        92,
        false,
        false,
    );

    let (result_a, result_b) = tokio::join!(fut_a, fut_b);

    assert!(
        matches!(result_a, Err(ProxyError::DataQuotaExceeded { ref user }) if user == "quota-race-user")
            || matches!(result_a, Ok(_)),
        "concurrent quota test must complete without panicking"
    );
    assert!(
        matches!(result_b, Err(ProxyError::DataQuotaExceeded { ref user }) if user == "quota-race-user")
            || matches!(result_b, Ok(_)),
        "concurrent quota test must complete without panicking"
    );
    assert!(
        stats.get_user_total_octets(user) <= 1,
        "same-user concurrent middle-relay responses must not overshoot the configured quota"
    );
}

#[tokio::test]
async fn process_me_writer_response_data_does_not_forward_partial_payload_when_remaining_quota_is_smaller_than_message()
 {
    let (writer_side, mut reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    stats.add_user_octets_to("partial-quota-user", 3);

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from(vec![1u8, 2, 3, 4]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "partial-quota-user",
        Some(4),
        &bytes_me2c,
        90,
        false,
        false,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::DataQuotaExceeded { user }) if user == "partial-quota-user"),
        "ME->client runtime path must reject oversized payloads before writing"
    );

    let mut raw = [0u8; 1];
    assert!(
        timeout(TokioDuration::from_millis(100), reader_side.read(&mut raw))
            .await
            .is_err(),
        "oversized payloads must not leak any partial ciphertext to the client stream"
    );
}

#[tokio::test]
async fn middle_relay_abort_midflight_releases_route_gauge() {
    let stats = Arc::new(Stats::new());
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());

    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let crypto_reader = make_crypto_reader(server_reader);
    let crypto_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "abort-middle-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50001".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_middle_proxy(
        crypto_reader,
        crypto_writer,
        success,
        me_pool,
        stats.clone(),
        config,
        buffer_pool,
        "127.0.0.1:443".parse().unwrap(),
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xdecafbad,
    ));

    let started = tokio::time::timeout(TokioDuration::from_secs(2), async {
        loop {
            if stats.get_current_connections_me() == 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        started.is_ok(),
        "middle relay must increment route gauge before abort"
    );

    relay_task.abort();
    let joined = relay_task.await;
    assert!(
        joined.is_err(),
        "aborted middle relay task must return join error"
    );

    tokio::time::sleep(TokioDuration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "route gauge must be released when middle relay task is aborted mid-flight"
    );

    drop(client_side);
}

#[tokio::test]
async fn middle_relay_cutover_midflight_releases_route_gauge() {
    let stats = Arc::new(Stats::new());
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());

    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let crypto_reader = make_crypto_reader(server_reader);
    let crypto_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "cutover-middle-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50003".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_middle_proxy(
        crypto_reader,
        crypto_writer,
        success,
        me_pool,
        stats.clone(),
        config,
        buffer_pool,
        "127.0.0.1:443".parse().unwrap(),
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xfeed_beef,
    ));

    tokio::time::timeout(TokioDuration::from_secs(2), async {
        loop {
            if stats.get_current_connections_me() == 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("middle relay must increment route gauge before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Direct).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(TokioDuration::from_secs(6), relay_task)
        .await
        .expect("middle relay must terminate after cutover")
        .expect("middle relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover should terminate middle relay session"
    );
    assert!(
        matches!(
            relay_result,
            Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
        ),
        "client-visible cutover error must stay generic and avoid route-internal metadata"
    );

    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "route gauge must be released when middle relay exits on cutover"
    );

    drop(client_side);
}

async fn run_quota_race_attempt(
    stats: &Stats,
    bytes_me2c: &AtomicU64,
    user: &str,
    payload: u8,
    conn_id: u64,
    barrier: Arc<Barrier>,
) -> Result<MeWriterResponseOutcome> {
    let (writer_side, _reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    barrier.wait().await;
    process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from(vec![payload]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        stats,
        user,
        Some(1),
        bytes_me2c,
        conn_id,
        false,
        false,
    )
    .await
}

#[tokio::test]
async fn abridged_max_extended_length_fails_closed_without_panic_or_partial_read() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(256);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let plaintext = vec![0x7f, 0xff, 0xff, 0xff];
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Abridged,
        4096,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        result.is_err(),
        "oversized abridged length must fail closed"
    );
    assert_eq!(
        frame_counter, 0,
        "oversized frame must not be counted as accepted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deterministic_quota_race_exactly_one_succeeds_and_one_is_rejected() {
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);
    let user = "gap-t04-race-user";
    let barrier = Arc::new(Barrier::new(2));

    let f1 = run_quota_race_attempt(&stats, &bytes_me2c, user, 0x11, 5001, barrier.clone());
    let f2 = run_quota_race_attempt(&stats, &bytes_me2c, user, 0x22, 5002, barrier);

    let (r1, r2) = tokio::join!(f1, f2);

    assert!(
        matches!(r1, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. })),
        "first racer must either finish or fail closed on quota"
    );
    assert!(
        matches!(r2, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. })),
        "second racer must either finish or fail closed on quota"
    );
    assert!(
        matches!(r1, Err(ProxyError::DataQuotaExceeded { .. }))
            || matches!(r2, Err(ProxyError::DataQuotaExceeded { .. })),
        "at least one racer must be quota-rejected"
    );
    assert_eq!(
        stats.get_user_total_octets(user),
        1,
        "same-user race must forward/account exactly one payload byte"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_quota_race_bursts_never_allow_double_success_per_round() {
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    for round in 0..128u64 {
        let user = format!("gap-t04-race-burst-{round}");
        let barrier = Arc::new(Barrier::new(2));

        let one = run_quota_race_attempt(
            &stats,
            &bytes_me2c,
            &user,
            0x33,
            6000 + round,
            barrier.clone(),
        );
        let two = run_quota_race_attempt(&stats, &bytes_me2c, &user, 0x44, 7000 + round, barrier);

        let (r1, r2) = tokio::join!(one, two);
        assert!(
            matches!(r1, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. }))
                && matches!(r2, Ok(_) | Err(ProxyError::DataQuotaExceeded { .. })),
            "round {round}: racers must resolve cleanly without unexpected errors"
        );
        assert!(
            matches!(r1, Err(ProxyError::DataQuotaExceeded { .. }))
                || matches!(r2, Err(ProxyError::DataQuotaExceeded { .. })),
            "round {round}: at least one racer must be quota-rejected"
        );
        assert_eq!(
            stats.get_user_total_octets(&user),
            1,
            "round {round}: same-user total octets must remain exactly 1 (single forwarded winner)"
        );
    }
}

#[tokio::test]
async fn middle_relay_cutover_storm_multi_session_keeps_generic_errors_and_releases_gauge() {
    let session_count = 6usize;
    let stats = Arc::new(Stats::new());
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());

    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));
    let route_snapshot = route_runtime.snapshot();

    let mut relay_tasks = Vec::with_capacity(session_count);
    let mut client_sides = Vec::with_capacity(session_count);

    for idx in 0..session_count {
        let (server_side, client_side) = duplex(64 * 1024);
        client_sides.push(client_side);
        let (server_reader, server_writer) = tokio::io::split(server_side);
        let crypto_reader = make_crypto_reader(server_reader);
        let crypto_writer = make_crypto_writer(server_writer);

        let success = HandshakeSuccess {
            user: format!("cutover-storm-middle-user-{idx}"),
            dc_idx: 2,
            proto_tag: ProtoTag::Intermediate,
            dec_key: [0u8; 32],
            dec_iv: 0,
            enc_key: [0u8; 32],
            enc_iv: 0,
            peer: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                52000 + idx as u16,
            ),
            is_tls: false,
        };

        relay_tasks.push(tokio::spawn(handle_via_middle_proxy(
            crypto_reader,
            crypto_writer,
            success,
            me_pool.clone(),
            stats.clone(),
            config.clone(),
            buffer_pool.clone(),
            "127.0.0.1:443".parse().unwrap(),
            rng.clone(),
            route_runtime.subscribe(),
            route_snapshot,
            0xB000_0000 + idx as u64,
        )));
    }

    tokio::time::timeout(TokioDuration::from_secs(4), async {
        loop {
            if stats.get_current_connections_me() == session_count as u64 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("all middle sessions must become active before cutover storm");

    let route_runtime_flipper = route_runtime.clone();
    let flipper = tokio::spawn(async move {
        for step in 0..64u32 {
            let mode = if (step & 1) == 0 {
                RelayRouteMode::Direct
            } else {
                RelayRouteMode::Middle
            };
            let _ = route_runtime_flipper.set_mode(mode);
            tokio::time::sleep(TokioDuration::from_millis(15)).await;
        }
    });

    for relay_task in relay_tasks {
        let relay_result = tokio::time::timeout(TokioDuration::from_secs(10), relay_task)
            .await
            .expect("middle relay task must finish under cutover storm")
            .expect("middle relay task must not panic");

        assert!(
            matches!(
                relay_result,
                Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
            ),
            "storm-cutover termination must remain generic for all middle sessions"
        );
    }

    flipper.abort();
    let _ = flipper.await;

    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "middle route gauge must return to zero after cutover storm"
    );

    drop(client_sides);
}

#[tokio::test]
async fn secure_padding_distribution_in_relay_writer() {
    timeout(TokioDuration::from_secs(10), async {
        let (mut client_side, relay_side) = duplex(512 * 1024);
        let key = [0u8; 32];
        let iv = 0u128;
        let mut writer = CryptoWriter::new(relay_side, AesCtr::new(&key, iv), 8 * 1024);
        let rng = Arc::new(SecureRandom::new());
        let mut frame_buf = Vec::new();
        let mut decryptor = AesCtr::new(&key, iv);

        let mut padding_counts = [0usize; 4];
        let iterations = 180usize;
        let payload = vec![0xAAu8; 100]; // 4-byte aligned

        for _ in 0..iterations {
            write_client_payload(
                &mut writer,
                ProtoTag::Secure,
                0,
                &payload,
                &rng,
                &mut frame_buf,
            )
            .await
            .expect("payload write must succeed");
            writer
                .flush()
                .await
                .expect("writer flush must complete so encrypted frame becomes readable");

            let mut len_buf = [0u8; 4];
            client_side
                .read_exact(&mut len_buf)
                .await
                .expect("must read encrypted secure length");
            let decrypted_len_bytes = decryptor.decrypt(&len_buf);
            let decrypted_len_bytes: [u8; 4] = decrypted_len_bytes
                .try_into()
                .expect("decrypted length must be 4 bytes");
            let wire_len = (u32::from_le_bytes(decrypted_len_bytes) & 0x7fff_ffff) as usize;

            assert!(
                wire_len >= payload.len(),
                "wire length must include at least payload bytes"
            );
            let padding_len = wire_len - payload.len();
            assert!(padding_len >= 1 && padding_len <= 3);
            padding_counts[padding_len] += 1;

            // Drain and decrypt frame bytes so CTR state stays aligned across writes.
            let mut trash = vec![0u8; wire_len];
            client_side
                .read_exact(&mut trash)
                .await
                .expect("must read encrypted secure frame body");
            let _ = decryptor.decrypt(&trash);
        }

        for p in 1..=3 {
            let count = padding_counts[p];
            assert!(
                count > iterations / 8,
                "padding length {p} is under-represented ({count}/{iterations})"
            );
        }
    })
    .await
    .expect("secure padding distribution test exceeded runtime budget");
}

#[tokio::test]
async fn negative_middle_end_connection_lost_during_relay_exits_on_client_eof() {
    let (client_reader_side, client_writer_side) = duplex(1024);
    let (_relay_reader_side, relay_writer_side) = duplex(1024);

    let key = [0u8; 32];
    let iv = 0u128;
    let crypto_reader = CryptoReader::new(client_reader_side, AesCtr::new(&key, iv));
    let crypto_writer = CryptoWriter::new(relay_writer_side, AesCtr::new(&key, iv), 1024);

    let stats = Arc::new(Stats::new());
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::with_config(1024, 1));
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = RouteRuntimeController::new(RelayRouteMode::Middle);

    // Create an ME pool.
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;

    // ConnRegistry ids are monotonic; reserve one id so we can predict the
    // next session conn_id and close it deterministically without relying on
    // writer-bound views such as active_conn_ids().
    let (probe_conn_id, probe_rx) = me_pool.registry().register().await;
    drop(probe_rx);
    me_pool.registry().unregister(probe_conn_id).await;
    let target_conn_id = probe_conn_id.wrapping_add(1);

    let success = HandshakeSuccess {
        user: "test-user".to_string(),
        peer: "127.0.0.1:12345".parse().unwrap(),
        dc_idx: 1,
        proto_tag: ProtoTag::Intermediate,
        enc_key: key,
        enc_iv: iv,
        dec_key: key,
        dec_iv: iv,
        is_tls: false,
    };

    let session_task = tokio::spawn(handle_via_middle_proxy(
        crypto_reader,
        crypto_writer,
        success,
        me_pool.clone(),
        stats.clone(),
        config.clone(),
        buffer_pool.clone(),
        "127.0.0.1:443".parse().unwrap(),
        rng.clone(),
        route_runtime.subscribe(),
        route_runtime.snapshot(),
        0x1234_5678,
    ));

    // Wait until session startup is visible, then unregister the predicted
    // conn_id to close the per-session ME response channel.
    timeout(TokioDuration::from_millis(500), async {
        loop {
            if stats.get_current_connections_me() >= 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("ME session must start before channel close simulation");

    me_pool.registry().unregister(target_conn_id).await;

    drop(client_writer_side);

    let result = timeout(TokioDuration::from_secs(2), session_task)
        .await
        .expect("Session task must terminate after ME drop and client EOF")
        .expect("Session task must not panic");

    assert!(
        result.is_ok(),
        "Session should complete cleanly after ME drop when client closes, got: {:?}",
        result
    );
}

#[tokio::test]
async fn adversarial_middle_end_drop_plus_cutover_returns_generic_route_switch() {
    let (client_reader_side, _client_writer_side) = duplex(1024);
    let (_relay_reader_side, relay_writer_side) = duplex(1024);

    let key = [0u8; 32];
    let iv = 0u128;
    let crypto_reader = CryptoReader::new(client_reader_side, AesCtr::new(&key, iv));
    let crypto_writer = CryptoWriter::new(relay_writer_side, AesCtr::new(&key, iv), 1024);

    let stats = Arc::new(Stats::new());
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::with_config(1024, 1));
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));

    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;

    // Predict the next conn_id so we can force-drop its ME channel deterministically.
    let (probe_conn_id, probe_rx) = me_pool.registry().register().await;
    drop(probe_rx);
    me_pool.registry().unregister(probe_conn_id).await;
    let target_conn_id = probe_conn_id.wrapping_add(1);

    let success = HandshakeSuccess {
        user: "test-user-cutover".to_string(),
        peer: "127.0.0.1:12345".parse().unwrap(),
        dc_idx: 1,
        proto_tag: ProtoTag::Intermediate,
        enc_key: key,
        enc_iv: iv,
        dec_key: key,
        dec_iv: iv,
        is_tls: false,
    };

    let runtime_clone = route_runtime.clone();
    let session_task = tokio::spawn(handle_via_middle_proxy(
        crypto_reader,
        crypto_writer,
        success,
        me_pool.clone(),
        stats.clone(),
        config,
        buffer_pool,
        "127.0.0.1:443".parse().unwrap(),
        rng,
        runtime_clone.subscribe(),
        runtime_clone.snapshot(),
        0xC001_CAFE,
    ));

    timeout(TokioDuration::from_millis(500), async {
        loop {
            if stats.get_current_connections_me() >= 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("ME session must start before race trigger");

    // Race ME channel drop with route cutover and assert generic client-visible outcome.
    me_pool.registry().unregister(target_conn_id).await;
    assert!(
        route_runtime.set_mode(RelayRouteMode::Direct).is_some(),
        "cutover must advance generation"
    );

    let relay_result = timeout(TokioDuration::from_secs(6), session_task)
        .await
        .expect("session must terminate under ME-drop + cutover race")
        .expect("session task must not panic");

    assert!(
        matches!(
            relay_result,
            Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
        ),
        "race outcome must remain generic and not leak ME internals, got: {:?}",
        relay_result
    );
}

#[tokio::test]
async fn stress_middle_end_drop_with_client_eof_never_hangs_across_burst() {
    let stats = Arc::new(Stats::new());
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;

    for round in 0..32u64 {
        let (client_reader_side, client_writer_side) = duplex(1024);
        let (_relay_reader_side, relay_writer_side) = duplex(1024);

        let key = [0u8; 32];
        let iv = 0u128;
        let crypto_reader = CryptoReader::new(client_reader_side, AesCtr::new(&key, iv));
        let crypto_writer = CryptoWriter::new(relay_writer_side, AesCtr::new(&key, iv), 1024);

        let config = Arc::new(ProxyConfig::default());
        let buffer_pool = Arc::new(BufferPool::with_config(1024, 1));
        let rng = Arc::new(SecureRandom::new());
        let route_runtime = RouteRuntimeController::new(RelayRouteMode::Middle);

        let (probe_conn_id, probe_rx) = me_pool.registry().register().await;
        drop(probe_rx);
        me_pool.registry().unregister(probe_conn_id).await;
        let target_conn_id = probe_conn_id.wrapping_add(1);

        let success = HandshakeSuccess {
            user: format!("stress-me-drop-eof-{round}"),
            peer: "127.0.0.1:12345".parse().unwrap(),
            dc_idx: 1,
            proto_tag: ProtoTag::Intermediate,
            enc_key: key,
            enc_iv: iv,
            dec_key: key,
            dec_iv: iv,
            is_tls: false,
        };

        let session_task = tokio::spawn(handle_via_middle_proxy(
            crypto_reader,
            crypto_writer,
            success,
            me_pool.clone(),
            stats.clone(),
            config,
            buffer_pool,
            "127.0.0.1:443".parse().unwrap(),
            rng,
            route_runtime.subscribe(),
            route_runtime.snapshot(),
            0xD00D_0000 + round,
        ));

        timeout(TokioDuration::from_millis(500), async {
            loop {
                if stats.get_current_connections_me() >= 1 {
                    break;
                }
                tokio::time::sleep(TokioDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("session must start before forced drop in burst round");

        me_pool.registry().unregister(target_conn_id).await;
        drop(client_writer_side);

        let result = timeout(TokioDuration::from_secs(2), session_task)
            .await
            .expect("burst round session must terminate quickly")
            .expect("burst round session must not panic");

        assert!(
            result.is_ok(),
            "burst round {round}: expected clean shutdown after ME drop + EOF, got: {:?}",
            result
        );
    }
}
