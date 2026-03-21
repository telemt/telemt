use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio::io::duplex;
use tokio::time::{Duration as TokioDuration, Instant as TokioInstant, timeout};

fn make_crypto_reader<T>(reader: T) -> CryptoReader<T>
where
    T: AsyncRead + Unpin + Send + 'static,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

fn make_forensics(conn_id: u64, started_at: Instant) -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 0xA000_0000 + conn_id,
        conn_id,
        user: format!("idle-test-user-{conn_id}"),
        peer: "127.0.0.1:50000".parse().expect("peer parse must succeed"),
        peer_hash: hash_ip("127.0.0.1".parse().expect("ip parse must succeed")),
        started_at,
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

fn make_idle_policy(soft_ms: u64, hard_ms: u64, grace_ms: u64) -> RelayClientIdlePolicy {
    RelayClientIdlePolicy {
        enabled: true,
        soft_idle: Duration::from_millis(soft_ms),
        hard_idle: Duration::from_millis(hard_ms),
        grace_after_downstream_activity: Duration::from_millis(grace_ms),
        legacy_frame_read_timeout: Duration::from_millis(hard_ms),
    }
}

fn idle_pressure_test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

fn acquire_idle_pressure_test_lock() -> std::sync::MutexGuard<'static, ()> {
    match idle_pressure_test_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[tokio::test]
async fn idle_policy_soft_mark_then_hard_close_increments_reason_counters() {
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(1, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_idle_policy(40, 120, 0);
    let last_downstream_activity_ms = AtomicU64::new(0);

    let start = TokioInstant::now();
    let result = timeout(
        TokioDuration::from_secs(2),
        read_client_payload_with_idle_policy(
            &mut crypto_reader,
            ProtoTag::Intermediate,
            1024,
            &buffer_pool,
            &forensics,
            &mut frame_counter,
            &stats,
            &idle_policy,
            &mut idle_state,
            &last_downstream_activity_ms,
            session_started_at,
        ),
    )
    .await
    .expect("idle test must complete");

    assert!(matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut));
    let err_text = match result {
        Err(ProxyError::Io(ref e)) => e.to_string(),
        _ => String::new(),
    };
    assert!(
        err_text.contains("middle-relay hard idle timeout"),
        "hard close must expose a clear timeout reason"
    );
    assert!(
        start.elapsed() >= TokioDuration::from_millis(80),
        "hard timeout must not trigger before idle deadline window"
    );
    assert_eq!(stats.get_relay_idle_soft_mark_total(), 1);
    assert_eq!(stats.get_relay_idle_hard_close_total(), 1);
}

#[tokio::test]
async fn idle_policy_downstream_activity_grace_extends_hard_deadline() {
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(2, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_idle_policy(30, 60, 100);
    let last_downstream_activity_ms = AtomicU64::new(20);

    let start = TokioInstant::now();
    let result = timeout(
        TokioDuration::from_secs(2),
        read_client_payload_with_idle_policy(
            &mut crypto_reader,
            ProtoTag::Intermediate,
            1024,
            &buffer_pool,
            &forensics,
            &mut frame_counter,
            &stats,
            &idle_policy,
            &mut idle_state,
            &last_downstream_activity_ms,
            session_started_at,
        ),
    )
    .await
    .expect("grace test must complete");

    assert!(matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut));
    assert!(
        start.elapsed() >= TokioDuration::from_millis(100),
        "recent downstream activity must extend hard idle deadline"
    );
}

#[tokio::test]
async fn relay_idle_policy_disabled_keeps_legacy_timeout_behavior() {
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics(3, Instant::now());
    let mut frame_counter = 0u64;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        Duration::from_millis(60),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut));
    let err_text = match result {
        Err(ProxyError::Io(ref e)) => e.to_string(),
        _ => String::new(),
    };
    assert!(
        err_text.contains("middle-relay client frame read timeout"),
        "legacy mode must keep expected timeout reason"
    );
    assert_eq!(stats.get_relay_idle_soft_mark_total(), 0);
    assert_eq!(stats.get_relay_idle_hard_close_total(), 0);
}

#[tokio::test]
async fn adversarial_partial_frame_trickle_cannot_bypass_hard_idle_close() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(4, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_idle_policy(30, 90, 0);
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(12);
    plaintext.extend_from_slice(&8u32.to_le_bytes());
    plaintext.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted[..1])
        .await
        .expect("must write a single trickle byte");

    let result = timeout(
        TokioDuration::from_secs(2),
        read_client_payload_with_idle_policy(
            &mut crypto_reader,
            ProtoTag::Intermediate,
            1024,
            &buffer_pool,
            &forensics,
            &mut frame_counter,
            &stats,
            &idle_policy,
            &mut idle_state,
            &last_downstream_activity_ms,
            session_started_at,
        ),
    )
    .await
    .expect("partial frame trickle test must complete");

    assert!(matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut));
    assert_eq!(frame_counter, 0, "partial trickle must not count as a valid frame");
}

#[tokio::test]
async fn successful_client_frame_resets_soft_idle_mark() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(5, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    idle_state.soft_idle_marked = true;
    let idle_policy = make_idle_policy(200, 300, 0);
    let last_downstream_activity_ms = AtomicU64::new(0);

    let payload = [9u8, 8, 7, 6, 5, 4, 3, 2];
    let mut plaintext = Vec::with_capacity(4 + payload.len());
    plaintext.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted)
        .await
        .expect("must write full encrypted frame");

    let read = read_client_payload_with_idle_policy(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await
    .expect("frame read must succeed")
    .expect("frame must be returned");

    assert_eq!(read.0.as_ref(), &payload);
    assert_eq!(frame_counter, 1);
    assert!(
        !idle_state.soft_idle_marked,
        "a valid client frame must clear soft-idle mark"
    );
}

#[tokio::test]
async fn protocol_desync_small_frame_updates_reason_counter() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics(6, Instant::now());
    let mut frame_counter = 0u64;

    let mut plaintext = Vec::with_capacity(7);
    plaintext.extend_from_slice(&3u32.to_le_bytes());
    plaintext.extend_from_slice(&[1u8, 2, 3]);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.expect("must write frame");

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

    assert!(matches!(result, Err(ProxyError::Proxy(ref msg)) if msg.contains("Frame too small")));
    assert_eq!(stats.get_relay_protocol_desync_close_total(), 1);
}

#[tokio::test]
async fn stress_many_idle_sessions_fail_closed_without_hang() {
    let mut tasks = Vec::with_capacity(24);

    for idx in 0..24u64 {
        tasks.push(tokio::spawn(async move {
            let (reader, _writer) = duplex(256);
            let mut crypto_reader = make_crypto_reader(reader);
            let buffer_pool = Arc::new(BufferPool::new());
            let stats = Stats::new();
            let session_started_at = Instant::now();
            let forensics = make_forensics(100 + idx, session_started_at);
            let mut frame_counter = 0u64;
            let mut idle_state = RelayClientIdleState::new(session_started_at);
            let idle_policy = make_idle_policy(20, 50, 10);
            let last_downstream_activity_ms = AtomicU64::new(0);

            let result = timeout(
                TokioDuration::from_secs(2),
                read_client_payload_with_idle_policy(
                    &mut crypto_reader,
                    ProtoTag::Intermediate,
                    1024,
                    &buffer_pool,
                    &forensics,
                    &mut frame_counter,
                    &stats,
                    &idle_policy,
                    &mut idle_state,
                    &last_downstream_activity_ms,
                    session_started_at,
                ),
            )
            .await
            .expect("stress task must complete");

            assert!(matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut));
            assert_eq!(stats.get_relay_idle_hard_close_total(), 1);
            assert_eq!(frame_counter, 0);
        }));
    }

    for task in tasks {
        task.await.expect("stress task must not panic");
    }
}

#[test]
fn pressure_evicts_oldest_idle_candidate_with_deterministic_ordering() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    assert!(mark_relay_idle_candidate(10));
    assert!(mark_relay_idle_candidate(11));
    assert_eq!(oldest_relay_idle_candidate(), Some(10));

    note_relay_pressure_event();

    let mut seen_for_newer = 0u64;
    assert!(
        !maybe_evict_idle_candidate_on_pressure(11, &mut seen_for_newer, &stats),
        "newer idle candidate must not be evicted while older candidate exists"
    );
    assert_eq!(oldest_relay_idle_candidate(), Some(10));

    let mut seen_for_oldest = 0u64;
    assert!(
        maybe_evict_idle_candidate_on_pressure(10, &mut seen_for_oldest, &stats),
        "oldest idle candidate must be evicted first under pressure"
    );
    assert_eq!(oldest_relay_idle_candidate(), Some(11));
    assert_eq!(stats.get_relay_pressure_evict_total(), 1);

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn pressure_does_not_evict_without_new_pressure_signal() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    assert!(mark_relay_idle_candidate(21));
    let mut seen = relay_pressure_event_seq();

    assert!(
        !maybe_evict_idle_candidate_on_pressure(21, &mut seen, &stats),
        "without new pressure signal, candidate must stay"
    );
    assert_eq!(stats.get_relay_pressure_evict_total(), 0);
    assert_eq!(oldest_relay_idle_candidate(), Some(21));

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn stress_pressure_eviction_preserves_fifo_across_many_candidates() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    let mut seen_per_conn = std::collections::HashMap::new();
    for conn_id in 1000u64..1064u64 {
        assert!(mark_relay_idle_candidate(conn_id));
        seen_per_conn.insert(conn_id, 0u64);
    }

    for expected in 1000u64..1064u64 {
        note_relay_pressure_event();

        let mut seen = *seen_per_conn
            .get(&expected)
            .expect("per-conn pressure cursor must exist");
        assert!(
            maybe_evict_idle_candidate_on_pressure(expected, &mut seen, &stats),
            "expected conn_id {expected} must be evicted next by deterministic FIFO ordering"
        );
        seen_per_conn.insert(expected, seen);

        let next = if expected == 1063 {
            None
        } else {
            Some(expected + 1)
        };
        assert_eq!(oldest_relay_idle_candidate(), next);
    }

    assert_eq!(stats.get_relay_pressure_evict_total(), 64);
    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_single_pressure_event_must_not_evict_more_than_one_candidate() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    assert!(mark_relay_idle_candidate(301));
    assert!(mark_relay_idle_candidate(302));
    assert!(mark_relay_idle_candidate(303));

    let mut seen_301 = 0u64;
    let mut seen_302 = 0u64;
    let mut seen_303 = 0u64;

    // Single pressure event should authorize at most one eviction globally.
    note_relay_pressure_event();

    let evicted_301 = maybe_evict_idle_candidate_on_pressure(301, &mut seen_301, &stats);
    let evicted_302 = maybe_evict_idle_candidate_on_pressure(302, &mut seen_302, &stats);
    let evicted_303 = maybe_evict_idle_candidate_on_pressure(303, &mut seen_303, &stats);

    let evicted_total = [evicted_301, evicted_302, evicted_303]
        .iter()
        .filter(|value| **value)
        .count();

    assert_eq!(
        evicted_total, 1,
        "single pressure event must not cascade-evict multiple idle candidates"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_pressure_counter_must_track_global_budget_not_per_session_cursor() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    assert!(mark_relay_idle_candidate(401));
    assert!(mark_relay_idle_candidate(402));

    let mut seen_oldest = 0u64;
    let mut seen_next = 0u64;

    note_relay_pressure_event();

    assert!(
        maybe_evict_idle_candidate_on_pressure(401, &mut seen_oldest, &stats),
        "oldest candidate must consume pressure budget first"
    );

    assert!(
        !maybe_evict_idle_candidate_on_pressure(402, &mut seen_next, &stats),
        "next candidate must not consume the same pressure budget"
    );

    assert_eq!(
        stats.get_relay_pressure_evict_total(),
        1,
        "single pressure budget must produce exactly one eviction"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_stale_pressure_before_idle_mark_must_not_trigger_eviction() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    // Pressure happened before any idle candidate existed.
    note_relay_pressure_event();
    assert!(mark_relay_idle_candidate(501));

    let mut seen = 0u64;
    assert!(
        !maybe_evict_idle_candidate_on_pressure(501, &mut seen, &stats),
        "stale pressure (before soft-idle mark) must not evict newly marked candidate"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_stale_pressure_must_not_evict_any_of_newly_marked_batch() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    note_relay_pressure_event();
    assert!(mark_relay_idle_candidate(511));
    assert!(mark_relay_idle_candidate(512));
    assert!(mark_relay_idle_candidate(513));

    let mut seen_511 = 0u64;
    let mut seen_512 = 0u64;
    let mut seen_513 = 0u64;

    let evicted = [
        maybe_evict_idle_candidate_on_pressure(511, &mut seen_511, &stats),
        maybe_evict_idle_candidate_on_pressure(512, &mut seen_512, &stats),
        maybe_evict_idle_candidate_on_pressure(513, &mut seen_513, &stats),
    ]
    .iter()
    .filter(|value| **value)
    .count();

    assert_eq!(
        evicted, 0,
        "stale pressure event must not evict any candidate from a newly marked batch"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_stale_pressure_seen_without_candidates_must_be_globally_invalidated() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    note_relay_pressure_event();

    // Session A observed pressure while there were no candidates.
    let mut seen_a = 0u64;
    assert!(
        !maybe_evict_idle_candidate_on_pressure(999_001, &mut seen_a, &stats),
        "no candidate existed, so no eviction is possible"
    );

    // Candidate appears later; Session B must not be able to consume stale pressure.
    assert!(mark_relay_idle_candidate(521));
    let mut seen_b = 0u64;
    assert!(
        !maybe_evict_idle_candidate_on_pressure(521, &mut seen_b, &stats),
        "once pressure is observed with empty candidate set, it must not be replayed later"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_stale_pressure_must_not_survive_candidate_churn() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();
    let stats = Stats::new();

    note_relay_pressure_event();
    assert!(mark_relay_idle_candidate(531));
    clear_relay_idle_candidate(531);
    assert!(mark_relay_idle_candidate(532));

    let mut seen = 0u64;
    assert!(
        !maybe_evict_idle_candidate_on_pressure(532, &mut seen, &stats),
        "stale pressure must not survive clear+remark churn cycles"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_pressure_seq_saturation_must_not_disable_future_pressure_accounting() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();

    {
        let mut guard = relay_idle_candidate_registry()
            .lock()
            .expect("registry lock must be available");
        guard.pressure_event_seq = u64::MAX;
        guard.pressure_consumed_seq = u64::MAX - 1;
    }

    // A new pressure event should still be representable; saturating at MAX creates a permanent lockout.
    note_relay_pressure_event();
    let after = relay_pressure_event_seq();
    assert_ne!(
        after,
        u64::MAX,
        "pressure sequence saturation must not permanently freeze event progression"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn blackhat_pressure_seq_saturation_must_not_break_multiple_distinct_events() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();

    {
        let mut guard = relay_idle_candidate_registry()
            .lock()
            .expect("registry lock must be available");
        guard.pressure_event_seq = u64::MAX;
        guard.pressure_consumed_seq = u64::MAX;
    }

    note_relay_pressure_event();
    let first = relay_pressure_event_seq();
    note_relay_pressure_event();
    let second = relay_pressure_event_seq();

    assert!(
        second > first,
        "distinct pressure events must remain distinguishable even at sequence boundary"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_race_single_pressure_event_allows_at_most_one_eviction_under_parallel_claims() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();

    let stats = Arc::new(Stats::new());
    let sessions = 16usize;
    let rounds = 200usize;
    let conn_ids: Vec<u64> = (10_000u64..10_000u64 + sessions as u64).collect();
    let mut seen_per_session = vec![0u64; sessions];

    for conn_id in &conn_ids {
        assert!(mark_relay_idle_candidate(*conn_id));
    }

    for round in 0..rounds {
        note_relay_pressure_event();

        let mut joins = Vec::with_capacity(sessions);
        for (idx, conn_id) in conn_ids.iter().enumerate() {
            let mut seen = seen_per_session[idx];
            let conn_id = *conn_id;
            let stats = stats.clone();
            joins.push(tokio::spawn(async move {
                let evicted = maybe_evict_idle_candidate_on_pressure(conn_id, &mut seen, stats.as_ref());
                (idx, conn_id, seen, evicted)
            }));
        }

        let mut evicted_this_round = 0usize;
        let mut evicted_conn = None;
        for join in joins {
            let (idx, conn_id, seen, evicted) = join.await.expect("race task must not panic");
            seen_per_session[idx] = seen;
            if evicted {
                evicted_this_round += 1;
                evicted_conn = Some(conn_id);
            }
        }

        assert!(
            evicted_this_round <= 1,
            "round {round}: one pressure event must never produce more than one eviction"
        );
        if let Some(conn) = evicted_conn {
            assert!(
                mark_relay_idle_candidate(conn),
                "round {round}: evicted conn must be re-markable as idle candidate"
            );
        }
    }

    assert!(
        stats.get_relay_pressure_evict_total() <= rounds as u64,
        "eviction total must never exceed number of pressure events"
    );
    assert!(
        stats.get_relay_pressure_evict_total() > 0,
        "parallel race must still observe at least one successful eviction"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_race_burst_pressure_with_churn_preserves_empty_set_invalidation_and_budget() {
    let _guard = acquire_idle_pressure_test_lock();
    clear_relay_idle_pressure_state_for_testing();

    let stats = Arc::new(Stats::new());
    let sessions = 12usize;
    let rounds = 120usize;
    let conn_ids: Vec<u64> = (20_000u64..20_000u64 + sessions as u64).collect();
    let mut seen_per_session = vec![0u64; sessions];

    for conn_id in &conn_ids {
        assert!(mark_relay_idle_candidate(*conn_id));
    }

    let mut expected_total_evictions = 0u64;

    for round in 0..rounds {
        let empty_phase = round % 5 == 0;
        if empty_phase {
            for conn_id in &conn_ids {
                clear_relay_idle_candidate(*conn_id);
            }
        }

        note_relay_pressure_event();

        let mut joins = Vec::with_capacity(sessions);
        for (idx, conn_id) in conn_ids.iter().enumerate() {
            let mut seen = seen_per_session[idx];
            let conn_id = *conn_id;
            let stats = stats.clone();
            joins.push(tokio::spawn(async move {
                let evicted = maybe_evict_idle_candidate_on_pressure(conn_id, &mut seen, stats.as_ref());
                (idx, conn_id, seen, evicted)
            }));
        }

        let mut evicted_this_round = 0usize;
        let mut evicted_conn = None;
        for join in joins {
            let (idx, conn_id, seen, evicted) = join.await.expect("burst race task must not panic");
            seen_per_session[idx] = seen;
            if evicted {
                evicted_this_round += 1;
                evicted_conn = Some(conn_id);
            }
        }

        if empty_phase {
            assert_eq!(
                evicted_this_round, 0,
                "round {round}: empty candidate phase must not allow stale-pressure eviction"
            );
            for conn_id in &conn_ids {
                assert!(mark_relay_idle_candidate(*conn_id));
            }
        } else {
            assert!(
                evicted_this_round <= 1,
                "round {round}: pressure budget must cap at one eviction"
            );
            if let Some(conn_id) = evicted_conn {
                expected_total_evictions = expected_total_evictions.saturating_add(1);
                assert!(mark_relay_idle_candidate(conn_id));
            }
        }
    }

    assert_eq!(
        stats.get_relay_pressure_evict_total(),
        expected_total_evictions,
        "global pressure eviction counter must match observed per-round successful consumes"
    );

    clear_relay_idle_pressure_state_for_testing();
}
