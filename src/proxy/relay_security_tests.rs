use super::relay_bidirectional;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::task::Waker;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

#[derive(Default)]
struct WakeCounter {
    wakes: AtomicUsize,
}

impl std::task::Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn quota_lock_contention_does_not_self_wake_pending_writer() {
    let stats = Arc::new(Stats::new());
    let user = "quota-lock-contention-user";

    let lock = super::quota_user_lock(user);
    let _held_lock = lock
        .try_lock()
        .expect("test must hold the per-user quota lock before polling writer");

    let counters = Arc::new(super::SharedCounters::new());
    let quota_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut io = super::StatsIo::new(
        tokio::io::sink(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        quota_exceeded,
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x11]);
    assert!(poll.is_pending(), "writer must remain pending while lock is contended");
    assert_eq!(
        wake_counter.wakes.load(Ordering::Relaxed),
        0,
        "contended quota lock must not self-wake immediately and spin the executor"
    );
}

#[tokio::test]
async fn quota_lock_contention_writer_schedules_single_deferred_wake_until_lock_acquired() {
    let stats = Arc::new(Stats::new());
    let user = "quota-lock-writer-liveness-user";

    let lock = super::quota_user_lock(user);
    let held_lock = lock
        .try_lock()
        .expect("test must hold the per-user quota lock before polling writer");

    let counters = Arc::new(super::SharedCounters::new());
    let quota_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut io = super::StatsIo::new(
        tokio::io::sink(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        quota_exceeded,
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0x11]);
    assert!(first.is_pending(), "writer must remain pending while lock is contended");
    assert_eq!(
        wake_counter.wakes.load(Ordering::Relaxed),
        0,
        "deferred wake must not fire synchronously"
    );

    timeout(Duration::from_millis(50), async {
        loop {
            if wake_counter.wakes.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("contended writer must schedule a deferred wake in bounded time");
    let wakes_after_first_yield = wake_counter.wakes.load(Ordering::Relaxed);
    assert!(
        wakes_after_first_yield >= 1,
        "contended writer must schedule at least one deferred wake for liveness"
    );

    let second = Pin::new(&mut io).poll_write(&mut cx, &[0x22]);
    assert!(second.is_pending(), "writer remains pending while lock is still held");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        wake_counter.wakes.load(Ordering::Relaxed),
        wakes_after_first_yield,
        "writer contention should not schedule unbounded wake storms before lock acquisition"
    );

    drop(held_lock);
    let released = Pin::new(&mut io).poll_write(&mut cx, &[0x33]);
    assert!(released.is_ready(), "writer must make progress once quota lock is released");
}

#[tokio::test]
async fn quota_lock_contention_read_path_schedules_deferred_wake_for_liveness() {
    let stats = Arc::new(Stats::new());
    let user = "quota-lock-read-liveness-user";

    let lock = super::quota_user_lock(user);
    let held_lock = lock
        .try_lock()
        .expect("test must hold the per-user quota lock before polling reader");

    let counters = Arc::new(super::SharedCounters::new());
    let quota_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut io = super::StatsIo::new(
        tokio::io::empty(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        quota_exceeded,
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 1];
    let mut buf = ReadBuf::new(&mut storage);

    let first = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
    assert!(first.is_pending(), "reader must remain pending while lock is contended");
    assert_eq!(
        wake_counter.wakes.load(Ordering::Relaxed),
        0,
        "read contention wake must not fire synchronously"
    );

    timeout(Duration::from_millis(50), async {
        loop {
            if wake_counter.wakes.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("read contention must schedule a deferred wake in bounded time");

    drop(held_lock);
    let mut buf_after_release = ReadBuf::new(&mut storage);
    let released = Pin::new(&mut io).poll_read(&mut cx, &mut buf_after_release);
    assert!(released.is_ready(), "reader must make progress once quota lock is released");
}

#[tokio::test]
async fn relay_bidirectional_enforces_live_user_quota() {
    let stats = Arc::new(Stats::new());
    let user = "quota-user";
    stats.add_user_octets_from(user, 6);

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        Some(8),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(&[0x10, 0x20, 0x30, 0x40])
        .await
        .expect("client write must succeed");

    let mut forwarded = [0u8; 4];
    let _ = timeout(
        Duration::from_millis(200),
        server_peer.read_exact(&mut forwarded),
    )
    .await;

    let relay_result = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay task must finish under quota cutoff")
        .expect("relay task must not panic");

    assert!(
        matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == "quota-user"),
        "relay must surface a typed quota error once live quota is exceeded"
    );
}

#[tokio::test]
async fn relay_bidirectional_does_not_forward_server_bytes_after_quota_is_exhausted() {
    let stats = Arc::new(Stats::new());
    let quota_user = "quota-exhausted-user";
    stats.add_user_octets_from(quota_user, 1);

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        quota_user,
        Arc::clone(&stats),
        Some(1),
        Arc::new(BufferPool::new()),
    ));

    server_peer
        .write_all(&[0xde, 0xad, 0xbe, 0xef])
        .await
        .expect("server write must succeed");

    let mut observed = [0u8; 4];
    let forwarded = timeout(
        Duration::from_millis(200),
        client_peer.read_exact(&mut observed),
    )
    .await;

    let relay_result = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay task must finish under quota cutoff")
        .expect("relay task must not panic");

    assert!(
        !matches!(forwarded, Ok(Ok(n)) if n == observed.len()),
        "no full server payload should be forwarded once quota is already exhausted"
    );
    assert!(
        matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == quota_user),
        "relay must still terminate with a typed quota error"
    );
}

#[tokio::test]
async fn relay_bidirectional_does_not_leak_partial_server_payload_when_remaining_quota_is_smaller_than_write() {
    let stats = Arc::new(Stats::new());
    let quota_user = "partial-leak-user";
    stats.add_user_octets_from(quota_user, 3);

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        quota_user,
        Arc::clone(&stats),
        Some(4),
        Arc::new(BufferPool::new()),
    ));

    server_peer
        .write_all(&[0x11, 0x22, 0x33, 0x44])
        .await
        .expect("server write must succeed");

    let mut observed = [0u8; 8];
    let forwarded = timeout(Duration::from_millis(200), client_peer.read(&mut observed)).await;

    let relay_result = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay task must finish under quota cutoff")
        .expect("relay task must not panic");

    assert!(
        !matches!(forwarded, Ok(Ok(n)) if n > 0),
        "quota exhaustion must not leak any partial server payload when remaining quota is smaller than the write"
    );
    assert!(
        matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == quota_user),
        "relay must still terminate with a typed quota error"
    );
}

#[tokio::test]
async fn relay_bidirectional_zero_quota_remains_fail_closed_for_server_payloads_under_stress() {
    let stats = Arc::new(Stats::new());
    let quota_user = "zero-quota-user";

    for payload_len in [1usize, 16, 512, 4096] {
        let (mut client_peer, relay_client) = duplex(4096);
        let (relay_server, mut server_peer) = duplex(4096);

        let (client_reader, client_writer) = tokio::io::split(relay_client);
        let (server_reader, server_writer) = tokio::io::split(relay_server);

        let relay_task = tokio::spawn(relay_bidirectional(
            client_reader,
            client_writer,
            server_reader,
            server_writer,
            1024,
            1024,
            quota_user,
            Arc::clone(&stats),
            Some(0),
            Arc::new(BufferPool::new()),
        ));

        let payload = vec![0x7f; payload_len];
        let _ = server_peer.write_all(&payload).await;

        let mut observed = vec![0u8; payload_len];
        let forwarded = timeout(Duration::from_millis(200), client_peer.read(&mut observed)).await;

        let relay_result = timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay task must finish under zero-quota cutoff")
            .expect("relay task must not panic");

        assert!(
            !matches!(forwarded, Ok(Ok(n)) if n > 0),
            "zero quota must not forward any server bytes for payload_len={payload_len}"
        );
        assert!(
            matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == quota_user),
            "zero quota must terminate with the typed quota error for payload_len={payload_len}"
        );
    }
}

#[tokio::test]
async fn relay_bidirectional_allows_exact_server_payload_at_quota_boundary() {
    let stats = Arc::new(Stats::new());
    let quota_user = "exact-boundary-user";

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        quota_user,
        Arc::clone(&stats),
        Some(4),
        Arc::new(BufferPool::new()),
    ));

    server_peer
        .write_all(&[0x91, 0x92, 0x93, 0x94])
        .await
        .expect("server write must succeed at exact quota boundary");

    let mut observed = [0u8; 4];
    client_peer
        .read_exact(&mut observed)
        .await
        .expect("client must receive the full payload at the exact quota boundary");
    assert_eq!(observed, [0x91, 0x92, 0x93, 0x94]);

    let relay_result = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay task must finish after exact boundary delivery")
        .expect("relay task must not panic");

    assert!(
        matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == quota_user),
        "relay must close with a typed quota error after reaching the exact boundary"
    );
}

#[tokio::test]
async fn relay_bidirectional_does_not_forward_client_bytes_after_quota_is_exhausted() {
    let stats = Arc::new(Stats::new());
    let quota_user = "client-exhausted-user";
    stats.add_user_octets_from(quota_user, 1);

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        quota_user,
        Arc::clone(&stats),
        Some(1),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(&[0x51, 0x52, 0x53, 0x54])
        .await
        .expect("client write must succeed even when quota is already exhausted");

    let mut observed = [0u8; 4];
    let forwarded = timeout(
        Duration::from_millis(200),
        server_peer.read_exact(&mut observed),
    )
    .await;

    let relay_result = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay task must finish under quota cutoff")
        .expect("relay task must not panic");

    assert!(
        !matches!(forwarded, Ok(Ok(n)) if n == observed.len()),
        "client payload must not be fully forwarded once quota is already exhausted"
    );
    assert!(
        matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == quota_user),
        "relay must still terminate with a typed quota error"
    );
}

#[tokio::test]
async fn relay_bidirectional_server_bytes_remain_blocked_even_under_multiple_payload_sizes() {
    let stats = Arc::new(Stats::new());
    let quota_user = "quota-fuzz-user";
    stats.add_user_octets_from(quota_user, 2);

    for payload_len in [1usize, 32, 1024, 8192] {
        let (mut client_peer, relay_client) = duplex(4096);
        let (relay_server, mut server_peer) = duplex(4096);

        let (client_reader, client_writer) = tokio::io::split(relay_client);
        let (server_reader, server_writer) = tokio::io::split(relay_server);

        let relay_task = tokio::spawn(relay_bidirectional(
            client_reader,
            client_writer,
            server_reader,
            server_writer,
            1024,
            1024,
            quota_user,
            Arc::clone(&stats),
            Some(2),
            Arc::new(BufferPool::new()),
        ));

        let payload = vec![0xaa; payload_len];
        let _ = server_peer.write_all(&payload).await;

        let mut observed = vec![0u8; payload_len];
        let forwarded = timeout(
            Duration::from_millis(200),
            client_peer.read_exact(&mut observed),
        )
        .await;

        let relay_result = timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay task must finish under quota cutoff")
            .expect("relay task must not panic");

        assert!(
            !matches!(forwarded, Ok(Ok(n)) if n == payload_len),
            "quota exhaustion must block full server-to-client forwarding for payload_len={payload_len}"
        );
        assert!(
            matches!(relay_result, Err(ProxyError::DataQuotaExceeded { ref user }) if user == quota_user),
            "relay must keep returning the typed quota error for payload_len={payload_len}"
        );
    }
}

#[tokio::test]
async fn relay_bidirectional_terminates_on_activity_timeout() {
    tokio::time::pause();
    let stats = Arc::new(Stats::new());
    let user = "timeout-user";

    let (client_peer, relay_client) = duplex(4096);
    let (relay_server, server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        None, // No quota
        Arc::new(BufferPool::new()),
    ));

    // Wait past the activity timeout threshold (1800 seconds) + buffer
    tokio::time::sleep(Duration::from_secs(1805)).await;
    
    // Resume time to process timeouts
    tokio::time::resume();

    let relay_result = timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay task must finish inside bounded timeout due to inactivity cutoff")
        .expect("relay task must not panic");

    assert!(
        relay_result.is_ok(),
        "relay should complete successfully on scheduled inactivity timeout"
    );
    
    // Verify client/server sockets are closed
    drop(client_peer);
    drop(server_peer);
}

#[tokio::test]
async fn relay_bidirectional_watchdog_resists_premature_execution() {
    tokio::time::pause();
    let stats = Arc::new(Stats::new());
    let user = "activity-user";

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let mut relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    // Advance by half the timeout
    tokio::time::sleep(Duration::from_secs(900)).await;

    // Provide activity
    client_peer
        .write_all(&[0xaa, 0xbb])
        .await
        .expect("client write must succeed");
    client_peer.flush().await.unwrap();

    // Advance by another half (total time since start is 1800, but since last activity is 900)
    tokio::time::sleep(Duration::from_secs(900)).await;

    tokio::time::resume();

    // Re-evaluating the task, it should NOT have timed out and still be pending
    let relay_result = timeout(Duration::from_millis(100), &mut relay_task).await;
    assert!(
        relay_result.is_err(),
        "Relay must not exit prematurely as long as activity was received before timeout"
    );
    
    // Explicitly drop sockets to cleanly shut down relay loop
    drop(client_peer);
    drop(server_peer);
    
    let completion = timeout(Duration::from_secs(1), relay_task).await
        .expect("relay task must complete securely after client disconnection")
        .expect("relay task must not panic");
    assert!(completion.is_ok(), "relay exits clean");
}

#[tokio::test]
async fn relay_bidirectional_half_closure_terminates_cleanly() {
    let stats = Arc::new(Stats::new());
    let (client_peer, relay_client) = duplex(4096);
    let (relay_server, server_peer) = duplex(4096);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader, client_writer, server_reader, server_writer, 1024, 1024, "half-close", stats, None, Arc::new(BufferPool::new()),
    ));
    
    // Half closure: drop the client completely but leave the server active.
    drop(client_peer);
    
    // Check that we don't immediately crash. Bidirectional relay stays open for the server -> client flush.
    // Eventually dropping the server cleanly closes the task.
    drop(server_peer);
    timeout(Duration::from_secs(1), relay_task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn relay_bidirectional_zero_length_noise_fuzzing() {
    let stats = Arc::new(Stats::new());
    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader, client_writer, server_reader, server_writer, 1024, 1024, "fuzz", stats, None, Arc::new(BufferPool::new()),
    ));

    // Flood with zero-length payloads (edge cases in stream framing logic sometimes loop)
    for _ in 0..100 {
        client_peer.write_all(&[]).await.unwrap();
    }
    client_peer.write_all(&[1, 2, 3]).await.unwrap();
    client_peer.flush().await.unwrap();
    
    let mut buf = [0u8; 3];
    server_peer.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, &[1, 2, 3]);
    
    drop(client_peer);
    drop(server_peer);
    timeout(Duration::from_secs(1), relay_task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn relay_bidirectional_asymmetric_backpressure() {
    let stats = Arc::new(Stats::new());
    // Give the client stream an extremely narrow throughput limit explicitly
    let (client_peer, relay_client) = duplex(1024); 
    let (relay_server, mut server_peer) = duplex(4096);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader, client_writer, server_reader, server_writer, 1024, 1024, "slowloris", stats, None, Arc::new(BufferPool::new()),
    ));

    let payload = vec![0xba; 65536]; // 64k payload
    
    // Server attempts to shove 64KB into a relay whose client pipe only holds 1KB!
    let write_res = tokio::time::timeout(Duration::from_millis(50), server_peer.write_all(&payload)).await;
    
    assert!(
        write_res.is_err(), 
        "Relay backpressure MUST halt the server writer from unbounded buffering when client stream is full!"
    );
    
    drop(client_peer);
    drop(server_peer);
    
    let completion = timeout(Duration::from_secs(1), relay_task).await.unwrap().unwrap();
    assert!(
        completion.is_ok() || completion.is_err(), 
        "Task must unwind reliably (either Ok or BrokenPipe Err) when dropped despite active backpressure locks"
    );
}

use rand::{Rng, SeedableRng, rngs::StdRng};

#[tokio::test]
async fn relay_bidirectional_light_fuzzing_temporal_jitter() {
    tokio::time::pause();
    let stats = Arc::new(Stats::new());
    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, server_peer) = duplex(4096);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let mut relay_task = tokio::spawn(relay_bidirectional(
        client_reader, client_writer, server_reader, server_writer, 1024, 1024, "fuzz-user", stats, None, Arc::new(BufferPool::new()),
    ));

    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    
    for _ in 0..10 {
        // Vary timing significantly up to 1600 seconds (limit is 1800s)
        let jitter = rng.random_range(100..1600); 
        tokio::time::sleep(Duration::from_secs(jitter)).await;
        
        client_peer.write_all(&[0x11]).await.unwrap();
        client_peer.flush().await.unwrap();
        
        // Ensure task has not died
        let res = timeout(Duration::from_millis(10), &mut relay_task).await;
        assert!(res.is_err(), "Relay must remain open indefinitely under light temporal fuzzing with active jitter pulses");
    }
    
    drop(client_peer);
    drop(server_peer);
    timeout(Duration::from_secs(1), relay_task).await.unwrap().unwrap().unwrap();
}

struct FaultyReader {
    error_once: Option<io::Error>,
}

struct TwoPartyGate {
    arrivals: AtomicUsize,
    total_bytes: AtomicUsize,
    wakers: Mutex<Vec<Waker>>,
}

impl TwoPartyGate {
    fn new() -> Self {
        Self {
            arrivals: AtomicUsize::new(0),
            total_bytes: AtomicUsize::new(0),
            wakers: Mutex::new(Vec::new()),
        }
    }

    fn arrive_or_park(&self, cx: &mut Context<'_>) -> bool {
        if self.arrivals.load(Ordering::Relaxed) >= 2 {
            return true;
        }

        let prev = self.arrivals.fetch_add(1, Ordering::AcqRel);
        if prev + 1 >= 2 {
            let mut wakers = self.wakers.lock().unwrap_or_else(|p| p.into_inner());
            for waker in wakers.drain(..) {
                waker.wake();
            }
            true
        } else {
            let mut wakers = self.wakers.lock().unwrap_or_else(|p| p.into_inner());
            wakers.push(cx.waker().clone());
            false
        }
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

struct GateWriter {
    gate: Arc<TwoPartyGate>,
    entered: bool,
}

impl GateWriter {
    fn new(gate: Arc<TwoPartyGate>) -> Self {
        Self {
            gate,
            entered: false,
        }
    }
}

impl AsyncWrite for GateWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.entered {
            self.entered = true;
        }

        if !self.gate.arrive_or_park(cx) {
            return Poll::Pending;
        }

        self.gate
            .total_bytes
            .fetch_add(buf.len(), Ordering::Relaxed);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct GateReader {
    gate: Arc<TwoPartyGate>,
    entered: bool,
    emitted: bool,
}

impl GateReader {
    fn new(gate: Arc<TwoPartyGate>) -> Self {
        Self {
            gate,
            entered: false,
            emitted: false,
        }
    }
}

impl AsyncRead for GateReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.emitted {
            return Poll::Ready(Ok(()));
        }

        if !self.entered {
            self.entered = true;
        }

        if !self.gate.arrive_or_park(cx) {
            return Poll::Pending;
        }

        buf.put_slice(&[0x42]);
        self.gate.total_bytes.fetch_add(1, Ordering::Relaxed);
        self.emitted = true;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_concurrent_quota_write_race_does_not_overshoot_limit() {
    let stats = Arc::new(Stats::new());
    let gate = Arc::new(TwoPartyGate::new());
    let user = "concurrent-quota-write".to_string();

    let writer_a = super::StatsIo::new(
        GateWriter::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        Some(1),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let writer_b = super::StatsIo::new(
        GateWriter::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        Some(1),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let task_a = tokio::spawn(async move {
        let mut w = writer_a;
        AsyncWriteExt::write_all(&mut w, &[0x01]).await
    });
    let task_b = tokio::spawn(async move {
        let mut w = writer_b;
        AsyncWriteExt::write_all(&mut w, &[0x02]).await
    });

    let (res_a, res_b) = tokio::join!(task_a, task_b);
    let _ = res_a.expect("task a must join");
    let _ = res_b.expect("task b must join");

    assert!(
        gate.total_bytes() <= 1,
        "concurrent same-user writes must not forward more than one byte under quota=1"
    );
    assert!(
        stats.get_user_total_octets(&user) <= 1,
        "concurrent same-user writes must not account over limit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_concurrent_quota_read_race_does_not_overshoot_limit() {
    let stats = Arc::new(Stats::new());
    let gate = Arc::new(TwoPartyGate::new());
    let user = "concurrent-quota-read".to_string();

    let reader_a = super::StatsIo::new(
        GateReader::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        Some(1),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let reader_b = super::StatsIo::new(
        GateReader::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        Some(1),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let task_a = tokio::spawn(async move {
        let mut r = reader_a;
        let mut one = [0u8; 1];
        AsyncReadExt::read_exact(&mut r, &mut one).await
    });
    let task_b = tokio::spawn(async move {
        let mut r = reader_b;
        let mut one = [0u8; 1];
        AsyncReadExt::read_exact(&mut r, &mut one).await
    });

    let (res_a, res_b) = tokio::join!(task_a, task_b);
    let _ = res_a.expect("task a must join");
    let _ = res_b.expect("task b must join");

    assert!(
        gate.total_bytes() <= 1,
        "concurrent same-user reads must not consume more than one byte under quota=1"
    );
    assert!(
        stats.get_user_total_octets(&user) <= 1,
        "concurrent same-user reads must not account over limit"
    );
}

#[tokio::test]
async fn stress_same_user_quota_parallel_relays_never_exceed_limit() {
    let stats = Arc::new(Stats::new());
    let user = "parallel-quota-user";

    for _ in 0..128 {
        let (mut client_peer_a, relay_client_a) = duplex(256);
        let (relay_server_a, mut server_peer_a) = duplex(256);
        let (mut client_peer_b, relay_client_b) = duplex(256);
        let (relay_server_b, mut server_peer_b) = duplex(256);

        let (client_reader_a, client_writer_a) = tokio::io::split(relay_client_a);
        let (server_reader_a, server_writer_a) = tokio::io::split(relay_server_a);
        let (client_reader_b, client_writer_b) = tokio::io::split(relay_client_b);
        let (server_reader_b, server_writer_b) = tokio::io::split(relay_server_b);

        let relay_a = tokio::spawn(relay_bidirectional(
            client_reader_a,
            client_writer_a,
            server_reader_a,
            server_writer_a,
            64,
            64,
            user,
            Arc::clone(&stats),
            Some(1),
            Arc::new(BufferPool::new()),
        ));

        let relay_b = tokio::spawn(relay_bidirectional(
            client_reader_b,
            client_writer_b,
            server_reader_b,
            server_writer_b,
            64,
            64,
            user,
            Arc::clone(&stats),
            Some(1),
            Arc::new(BufferPool::new()),
        ));

        let _ = tokio::join!(
            client_peer_a.write_all(&[0x01]),
            server_peer_a.write_all(&[0x02]),
            client_peer_b.write_all(&[0x03]),
            server_peer_b.write_all(&[0x04]),
        );

        let _ = timeout(Duration::from_millis(50), poll_fn(|cx| {
            let mut one = [0u8; 1];
            let _ = Pin::new(&mut client_peer_a).poll_read(cx, &mut ReadBuf::new(&mut one));
            Poll::Ready(())
        }))
        .await;

        drop(client_peer_a);
        drop(server_peer_a);
        drop(client_peer_b);
        drop(server_peer_b);

        let _ = timeout(Duration::from_secs(1), relay_a).await;
        let _ = timeout(Duration::from_secs(1), relay_b).await;

        assert!(
            stats.get_user_total_octets(user) <= 1,
            "parallel relays must not exceed configured quota"
        );
    }
}

impl FaultyReader {
    fn permission_denied_with_message(message: impl Into<String>) -> Self {
        Self {
            error_once: Some(io::Error::new(io::ErrorKind::PermissionDenied, message.into())),
        }
    }
}

impl AsyncRead for FaultyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(err) = self.error_once.take() {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn relay_bidirectional_does_not_misclassify_transport_permission_denied_as_quota() {
    let stats = Arc::new(Stats::new());
    let (client_peer, relay_client) = duplex(4096);
    let (client_reader, client_writer) = tokio::io::split(relay_client);

    let relay_result = relay_bidirectional(
        client_reader,
        client_writer,
        FaultyReader::permission_denied_with_message("user data quota exceeded"),
        tokio::io::sink(),
        1024,
        1024,
        "non-quota-permission-denied",
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    )
    .await;

    drop(client_peer);

    assert!(
        matches!(relay_result, Err(ProxyError::Io(ref err)) if err.kind() == io::ErrorKind::PermissionDenied),
        "non-quota transport PermissionDenied errors must remain IO errors"
    );
}

#[tokio::test]
async fn relay_bidirectional_light_fuzz_permission_denied_messages_remain_io_errors() {
    let mut rng = StdRng::seed_from_u64(0xA11CE0B5);

    for i in 0..128u64 {
        let stats = Arc::new(Stats::new());
        let (client_peer, relay_client) = duplex(1024);
        let (client_reader, client_writer) = tokio::io::split(relay_client);

        let random_len = rng.random_range(1..=48);
        let mut msg = String::with_capacity(random_len);
        for _ in 0..random_len {
            let ch = (b'a' + (rng.random::<u8>() % 26)) as char;
            msg.push(ch);
        }
        // Include the legacy quota string in a subset of fuzz cases to validate
        // collision resistance against message-based classification.
        if i % 7 == 0 {
            msg = "user data quota exceeded".to_string();
        }

        let relay_result = relay_bidirectional(
            client_reader,
            client_writer,
            FaultyReader::permission_denied_with_message(msg),
            tokio::io::sink(),
            1024,
            1024,
            "fuzz-perm-denied",
            Arc::clone(&stats),
            None,
            Arc::new(BufferPool::new()),
        )
        .await;

        drop(client_peer);

        assert!(
            matches!(relay_result, Err(ProxyError::Io(ref err)) if err.kind() == io::ErrorKind::PermissionDenied),
            "transport PermissionDenied case must stay typed as IO regardless of message content"
        );
    }
}

#[tokio::test]
async fn relay_half_close_keeps_reverse_direction_progressing() {
    let stats = Arc::new(Stats::new());
    let user = "half-close-user";

    let (client_peer, relay_client) = duplex(1024);
    let (relay_server, server_peer) = duplex(1024);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);
    let (mut cp_reader, mut cp_writer) = tokio::io::split(client_peer);
    let (mut sp_reader, mut sp_writer) = tokio::io::split(server_peer);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        8192,
        8192,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    sp_writer.write_all(&[0x10, 0x20, 0x30, 0x40]).await.unwrap();
    sp_writer.shutdown().await.unwrap();

    let mut inbound = [0u8; 4];
    cp_reader.read_exact(&mut inbound).await.unwrap();
    assert_eq!(inbound, [0x10, 0x20, 0x30, 0x40]);

    cp_writer.write_all(&[0xaa, 0xbb, 0xcc, 0xdd]).await.unwrap();
    let mut outbound = [0u8; 4];
    sp_reader.read_exact(&mut outbound).await.unwrap();
    assert_eq!(outbound, [0xaa, 0xbb, 0xcc, 0xdd]);

    relay_task.abort();
    let joined = relay_task.await;
    assert!(joined.is_err(), "aborted relay task must return join error");
}
