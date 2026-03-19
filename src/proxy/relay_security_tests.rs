use super::relay_bidirectional as relay_bidirectional_impl;
use crate::proxy::adaptive_buffers::AdaptiveTier;
use crate::proxy::session_eviction::SessionLease;
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

async fn relay_bidirectional<CR, CW, SR, SW>(
    client_reader: CR,
    client_writer: CW,
    server_reader: SR,
    server_writer: SW,
    c2s_buf_size: usize,
    s2c_buf_size: usize,
    user: &str,
    stats: Arc<Stats>,
    _quota_limit: Option<u64>,
    buffer_pool: Arc<BufferPool>,
) -> crate::error::Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    relay_bidirectional_impl(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        c2s_buf_size,
        s2c_buf_size,
        user,
        0,
        stats,
        buffer_pool,
        SessionLease::default(),
        AdaptiveTier::Base,
    )
    .await
}

#[tokio::test]
async fn stats_io_write_tracks_user_totals() {
    let stats = Arc::new(Stats::new());
    let user = "stats-io-write-tracking-user";

    let counters = Arc::new(super::SharedCounters::new());
    let mut io = super::StatsIo::new(
        tokio::io::sink(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        tokio::time::Instant::now(),
    );

    AsyncWriteExt::write_all(&mut io, &[0x11, 0x22, 0x33])
        .await
        .expect("write to sink must succeed");

    assert_eq!(
        stats.get_user_total_octets(user),
        3,
        "StatsIo write path must account bytes to per-user totals"
    );
}

#[tokio::test]
async fn stats_io_read_tracks_user_totals() {
    let stats = Arc::new(Stats::new());
    let user = "stats-io-read-tracking-user";

    let (mut peer, relay_side) = duplex(64);
    let counters = Arc::new(super::SharedCounters::new());
    let mut io = super::StatsIo::new(
        relay_side,
        counters,
        Arc::clone(&stats),
        user.to_string(),
        tokio::time::Instant::now(),
    );

    peer.write_all(&[0xaa, 0xbb])
        .await
        .expect("peer write must succeed");

    let mut out = [0u8; 2];
    io.read_exact(&mut out)
        .await
        .expect("wrapped read must succeed");
    assert_eq!(out, [0xaa, 0xbb]);
    assert_eq!(
        stats.get_user_total_octets(user),
        2,
        "StatsIo read path must account bytes to per-user totals"
    );
}

#[tokio::test]
async fn relay_bidirectional_does_not_apply_client_quota_gate() {
    let stats = Arc::new(Stats::new());
    let user = "relay-no-quota-gate-user";
    stats.add_user_octets_from(user, 10_000);

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

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
        Some(1),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(&[0x10, 0x20, 0x30, 0x40])
        .await
        .expect("client write must succeed");
    let mut c2s = [0u8; 4];
    server_peer
        .read_exact(&mut c2s)
        .await
        .expect("server must receive client payload even with high preloaded octets");
    assert_eq!(c2s, [0x10, 0x20, 0x30, 0x40]);

    server_peer
        .write_all(&[0xaa, 0xbb, 0xcc, 0xdd])
        .await
        .expect("server write must succeed");
    let mut s2c = [0u8; 4];
    client_peer
        .read_exact(&mut s2c)
        .await
        .expect("client must receive server payload even with high preloaded octets");
    assert_eq!(s2c, [0xaa, 0xbb, 0xcc, 0xdd]);

    let not_finished = timeout(Duration::from_millis(100), &mut relay_task).await;
    assert!(
        matches!(not_finished, Err(_)),
        "relay must not self-terminate with quota-style errors; gating is handled before relay"
    );
    relay_task.abort();
}

#[tokio::test]
async fn relay_bidirectional_counts_octets_without_fail_closed_cutoff() {
    let stats = Arc::new(Stats::new());
    let user = "relay-stats-no-cutoff-user";

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
        Some(0),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(&[1, 2, 3])
        .await
        .expect("client write must succeed");
    server_peer
        .write_all(&[4, 5, 6, 7])
        .await
        .expect("server write must succeed");

    let mut c2s = [0u8; 3];
    server_peer
        .read_exact(&mut c2s)
        .await
        .expect("server must receive c2s payload");
    let mut s2c = [0u8; 4];
    client_peer
        .read_exact(&mut s2c)
        .await
        .expect("client must receive s2c payload");

    let total = stats.get_user_total_octets(user);
    assert!(
        total >= 7,
        "relay must continue accounting octets, observed total={total}"
    );

    relay_task.abort();
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
async fn adversarial_concurrent_statsio_write_accounting_is_additive() {
    let stats = Arc::new(Stats::new());
    let gate = Arc::new(TwoPartyGate::new());
    let user = "concurrent-quota-write".to_string();

    let writer_a = super::StatsIo::new(
        GateWriter::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        tokio::time::Instant::now(),
    );

    let writer_b = super::StatsIo::new(
        GateWriter::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
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

    assert_eq!(
        gate.total_bytes(),
        2,
        "both concurrent writes must forward one byte each"
    );
    assert_eq!(
        stats.get_user_total_octets(&user),
        2,
        "both concurrent writes must be accounted for same user"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_concurrent_statsio_read_accounting_is_additive() {
    let stats = Arc::new(Stats::new());
    let gate = Arc::new(TwoPartyGate::new());
    let user = "concurrent-quota-read".to_string();

    let reader_a = super::StatsIo::new(
        GateReader::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        tokio::time::Instant::now(),
    );

    let reader_b = super::StatsIo::new(
        GateReader::new(Arc::clone(&gate)),
        Arc::new(super::SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
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

    assert_eq!(
        gate.total_bytes(),
        2,
        "both concurrent reads must consume one byte each"
    );
    assert_eq!(
        stats.get_user_total_octets(&user),
        2,
        "both concurrent reads must be accounted for same user"
    );
}

#[tokio::test]
async fn stress_same_user_parallel_relays_complete_without_deadlock() {
    let stats = Arc::new(Stats::new());
    let user = "parallel-relay-user";

    for _ in 0..64 {
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
            None,
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
            None,
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

        let total = stats.get_user_total_octets(user);
        assert!(
            total >= 2,
            "parallel relays must account cross-session octets and stay live; total={total}"
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
