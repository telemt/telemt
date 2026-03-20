//! Bidirectional Relay — poll-based, no head-of-line blocking
//!
//! ## What changed and why
//!
//! Previous implementation used a single-task `select! { biased; ... }` loop
//! where each branch called `write_all()`. This caused head-of-line blocking:
//! while `write_all()` waited for a slow writer (e.g. client on 3G downloading
//! media), the entire loop was blocked — the other direction couldn't make progress.
//!
//! Symptoms observed in production:
//! - Media loading at ~8 KB/s despite fast server connection
//! - Stop-and-go pattern with 50–500ms gaps between chunks
//! - `biased` select starving S→C direction
//! - Some users unable to load media at all
//!
//! ## New architecture
//!
//! Uses `tokio::io::copy_bidirectional` which polls both directions concurrently
//! in a single task via non-blocking `poll_read` / `poll_write` calls:
//!
//! Old (select! + write_all — BLOCKING):
//!
//!   loop {
//!       select! {
//!           biased;
//!           data = client.read()  => { server.write_all(data).await; }  ← BLOCKS here
//!           data = server.read()  => { client.write_all(data).await; }  ← can't run
//!       }
//!   }
//!
//! New (copy_bidirectional — CONCURRENT):
//!
//!   poll(cx) {
//!       // Both directions polled in the same poll cycle
//!       C→S: poll_read(client) → poll_write(server)   // non-blocking
//!       S→C: poll_read(server) → poll_write(client)   // non-blocking
//!       // If one writer is Pending, the other direction still progresses
//!   }
//!
//! Benefits:
//! - No head-of-line blocking: slow client download doesn't block uploads
//! - No biased starvation: fair polling of both directions
//! - Proper flush: `copy_bidirectional` calls `poll_flush` when reader stalls,
//!   so CryptoWriter's pending ciphertext is always drained (fixes "stuck at 95%")
//! - No deadlock risk: old write_all could deadlock when both TCP buffers filled;
//!   poll-based approach lets TCP flow control work correctly
//!
//! Stats tracking:
//! - `StatsIo` wraps client side, intercepts `poll_read` / `poll_write`
//! - `poll_read` on client = C→S (client sending) → `octets_from`, `msgs_from`
//! - `poll_write` on client = S→C (to client)     → `octets_to`, `msgs_to`
//! - `SharedCounters` (atomics) let the watchdog read stats without locking

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional_with_sizes,
};
use tokio::time::Instant;
use tracing::{debug, trace, warn};
use crate::error::Result;
use crate::proxy::adaptive_buffers::{
    self, AdaptiveTier, RelaySignalSample, SessionAdaptiveController, TierTransitionReason,
};
use crate::proxy::session_eviction::SessionLease;
use crate::stats::Stats;
use crate::stream::BufferPool;

// ============= Constants =============

/// Activity timeout for iOS compatibility.
///
/// iOS keeps Telegram connections alive in background for up to 30 minutes.
/// Closing earlier causes unnecessary reconnects and handshake overhead.
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(1800);

/// Watchdog check interval — also used for periodic rate logging.
///
/// 10 seconds gives responsive timeout detection (±10s accuracy)
/// without measurable overhead from atomic reads.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(10);
const ADAPTIVE_TICK: Duration = Duration::from_millis(250);

// ============= CombinedStream =============

/// Combines separate read and write halves into a single bidirectional stream.
///
/// `copy_bidirectional` requires `AsyncRead + AsyncWrite` on each side,
/// but the handshake layer produces split reader/writer pairs
/// (e.g. `CryptoReader<FakeTlsReader<OwnedReadHalf>>` + `CryptoWriter<...>`).
///
/// This wrapper reunifies them with zero overhead — each trait method
/// delegates directly to the corresponding half. No buffering, no copies.
///
/// Safety: `poll_read` only touches `reader`, `poll_write` only touches `writer`,
/// so there's no aliasing even though both are called on the same `&mut self`.
struct CombinedStream<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> CombinedStream<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for CombinedStream<R, W> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for CombinedStream<R, W> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

// ============= SharedCounters =============

/// Atomic counters shared between the relay (via StatsIo) and the watchdog task.
///
/// Using `Relaxed` ordering is sufficient because:
/// - Counters are monotonically increasing (no ABA problem)
/// - Slight staleness in watchdog reads is harmless (±10s check interval anyway)
/// - No ordering dependencies between different counters
struct SharedCounters {
    /// Bytes read from client (C→S direction)
    c2s_bytes: AtomicU64,
    /// Bytes written to client (S→C direction)
    s2c_bytes: AtomicU64,
    /// Number of poll_read completions (≈ C→S chunks)
    c2s_ops: AtomicU64,
    /// Number of poll_write completions (≈ S→C chunks)
    s2c_ops: AtomicU64,
    /// Milliseconds since relay epoch of last I/O activity
    last_activity_ms: AtomicU64,
    /// Bytes requested to write to client (S→C direction).
    s2c_requested_bytes: AtomicU64,
    /// Total write operations for S→C direction.
    s2c_write_ops: AtomicU64,
    /// Number of partial writes to client.
    s2c_partial_writes: AtomicU64,
    /// Number of times S→C poll_write returned Pending.
    s2c_pending_writes: AtomicU64,
    /// Consecutive pending writes in S→C direction.
    s2c_consecutive_pending_writes: AtomicU64,
}

impl SharedCounters {
    fn new() -> Self {
        Self {
            c2s_bytes: AtomicU64::new(0),
            s2c_bytes: AtomicU64::new(0),
            c2s_ops: AtomicU64::new(0),
            s2c_ops: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(0),
            s2c_requested_bytes: AtomicU64::new(0),
            s2c_write_ops: AtomicU64::new(0),
            s2c_partial_writes: AtomicU64::new(0),
            s2c_pending_writes: AtomicU64::new(0),
            s2c_consecutive_pending_writes: AtomicU64::new(0),
        }
    }

    /// Record activity at this instant.
    #[inline]
    fn touch(&self, now: Instant, epoch: Instant) {
        let ms = now.duration_since(epoch).as_millis() as u64;
        self.last_activity_ms.store(ms, Ordering::Relaxed);
    }

    /// How long since last recorded activity.
    fn idle_duration(&self, now: Instant, epoch: Instant) -> Duration {
        let last_ms = self.last_activity_ms.load(Ordering::Relaxed);
        let now_ms = now.duration_since(epoch).as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }
}

// ============= StatsIo =============

/// Transparent I/O wrapper that tracks per-user statistics and activity.
///
/// Wraps the **client** side of the relay. Direction mapping:
///
/// | poll method  | direction | stats updated                        |
/// |-------------|-----------|--------------------------------------|
/// | `poll_read`  | C→S       | `octets_from`, `msgs_from`, counters |
/// | `poll_write` | S→C       | `octets_to`, `msgs_to`, counters     |
///
/// Both update the shared activity timestamp for the watchdog.
///
/// Note on message counts: the original code counted one `read()`/`write_all()`
/// as one "message". Here we count `poll_read`/`poll_write` completions instead.
/// Byte counts are identical; op counts may differ slightly due to different
/// internal buffering in `copy_bidirectional`. This is fine for monitoring.
struct StatsIo<S> {
    inner: S,
    counters: Arc<SharedCounters>,
    stats: Arc<Stats>,
    user: String,
    epoch: Instant,
}

impl<S> StatsIo<S> {
    fn new(
        inner: S,
        counters: Arc<SharedCounters>,
        stats: Arc<Stats>,
        user: String,
        epoch: Instant,
    ) -> Self {
        // Mark initial activity so the watchdog doesn't fire before data flows
        counters.touch(Instant::now(), epoch);
        Self { inner, counters, stats, user, epoch }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StatsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();

        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    // C→S: client sent data
                    this.counters.c2s_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    this.counters.c2s_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats.add_user_octets_from(&this.user, n as u64);
                    this.stats.increment_user_msgs_from(&this.user);

                    trace!(user = %this.user, bytes = n, "C->S");
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.counters
            .s2c_requested_bytes
            .fetch_add(buf.len() as u64, Ordering::Relaxed);

        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.counters.s2c_write_ops.fetch_add(1, Ordering::Relaxed);
                this.counters
                    .s2c_consecutive_pending_writes
                    .store(0, Ordering::Relaxed);
                if n < buf.len() {
                    this.counters
                        .s2c_partial_writes
                        .fetch_add(1, Ordering::Relaxed);
                }
                if n > 0 {
                    // S→C: data written to client
                    this.counters.s2c_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    this.counters.s2c_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats.add_user_octets_to(&this.user, n as u64);
                    this.stats.increment_user_msgs_to(&this.user);

                    trace!(user = %this.user, bytes = n, "S->C");
                }
                Poll::Ready(Ok(n))
            }
            Poll::Pending => {
                this.counters
                    .s2c_pending_writes
                    .fetch_add(1, Ordering::Relaxed);
                this.counters
                    .s2c_consecutive_pending_writes
                    .fetch_add(1, Ordering::Relaxed);
                Poll::Pending
            }
            other => other,
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ============= Relay =============

/// Relay data bidirectionally between client and server.
///
/// Uses `tokio::io::copy_bidirectional` for concurrent, non-blocking data transfer.
///
/// ## API compatibility
///
/// The `_buffer_pool` parameter is retained for call-site compatibility.
/// Effective relay copy buffers are configured by `c2s_buf_size` / `s2c_buf_size`.
///
/// ## Guarantees preserved
///
/// - Activity timeout: 30 minutes of inactivity → clean shutdown
/// - Per-user stats: bytes and ops counted per direction
/// - Periodic rate logging: every 10 seconds when active
/// - Clean shutdown: both write sides are shut down on exit
/// - Error propagation: I/O errors are returned as `ProxyError::Io`
pub async fn relay_bidirectional<CR, CW, SR, SW>(
    client_reader: CR,
    client_writer: CW,
    server_reader: SR,
    server_writer: SW,
    c2s_buf_size: usize,
    s2c_buf_size: usize,
    user: &str,
    dc_idx: i16,
    stats: Arc<Stats>,
    _buffer_pool: Arc<BufferPool>,
    session_lease: SessionLease,
    seed_tier: AdaptiveTier,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    let epoch = Instant::now();
    let counters = Arc::new(SharedCounters::new());
    let user_owned = user.to_string();

    // ── Combine split halves into bidirectional streams ──────────────
    let client_combined = CombinedStream::new(client_reader, client_writer);
    let mut server = CombinedStream::new(server_reader, server_writer);

    // Wrap client with stats/activity tracking
    let mut client = StatsIo::new(
        client_combined,
        Arc::clone(&counters),
        Arc::clone(&stats),
        user_owned.clone(),
        epoch,
    );

    // ── Watchdog: activity timeout + periodic rate logging ──────────
    let wd_counters = Arc::clone(&counters);
    let wd_user = user_owned.clone();
    let wd_dc = dc_idx;
    let wd_stats = Arc::clone(&stats);
    let wd_session = session_lease.clone();

    let watchdog = async {
        let mut prev_c2s_log: u64 = 0;
        let mut prev_s2c_log: u64 = 0;
        let mut prev_c2s_sample: u64 = 0;
        let mut prev_s2c_requested_sample: u64 = 0;
        let mut prev_s2c_written_sample: u64 = 0;
        let mut prev_s2c_write_ops_sample: u64 = 0;
        let mut prev_s2c_partial_sample: u64 = 0;
        let mut accumulated_log = Duration::ZERO;
        let mut adaptive = SessionAdaptiveController::new(seed_tier);

        loop {
            tokio::time::sleep(ADAPTIVE_TICK).await;

            if wd_session.is_stale() {
                wd_stats.increment_reconnect_stale_close_total();
                warn!(
                    user = %wd_user,
                    dc = wd_dc,
                    "Session evicted by reconnect"
                );
                return;
            }

            let now = Instant::now();
            let idle = wd_counters.idle_duration(now, epoch);

            // ── Activity timeout ────────────────────────────────────
            if idle >= ACTIVITY_TIMEOUT {
                let c2s = wd_counters.c2s_bytes.load(Ordering::Relaxed);
                let s2c = wd_counters.s2c_bytes.load(Ordering::Relaxed);
                warn!(
                    user = %wd_user,
                    c2s_bytes = c2s,
                    s2c_bytes = s2c,
                    idle_secs = idle.as_secs(),
                    "Activity timeout"
                );
                return; // Causes select! to cancel copy_bidirectional
            }

            let c2s_total = wd_counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c_requested_total = wd_counters
                .s2c_requested_bytes
                .load(Ordering::Relaxed);
            let s2c_written_total = wd_counters.s2c_bytes.load(Ordering::Relaxed);
            let s2c_write_ops_total = wd_counters
                .s2c_write_ops
                .load(Ordering::Relaxed);
            let s2c_partial_total = wd_counters
                .s2c_partial_writes
                .load(Ordering::Relaxed);
            let consecutive_pending = wd_counters
                .s2c_consecutive_pending_writes
                .load(Ordering::Relaxed) as u32;

            let sample = RelaySignalSample {
                c2s_bytes: c2s_total.saturating_sub(prev_c2s_sample),
                s2c_requested_bytes: s2c_requested_total
                    .saturating_sub(prev_s2c_requested_sample),
                s2c_written_bytes: s2c_written_total
                    .saturating_sub(prev_s2c_written_sample),
                s2c_write_ops: s2c_write_ops_total
                    .saturating_sub(prev_s2c_write_ops_sample),
                s2c_partial_writes: s2c_partial_total
                    .saturating_sub(prev_s2c_partial_sample),
                s2c_consecutive_pending_writes: consecutive_pending,
            };

            if let Some(transition) = adaptive.observe(sample, ADAPTIVE_TICK.as_secs_f64()) {
                match transition.reason {
                    TierTransitionReason::SoftConfirmed => {
                        wd_stats.increment_relay_adaptive_promotions_total();
                    }
                    TierTransitionReason::HardPressure => {
                        wd_stats.increment_relay_adaptive_promotions_total();
                        wd_stats.increment_relay_adaptive_hard_promotions_total();
                    }
                    TierTransitionReason::QuietDemotion => {
                        wd_stats.increment_relay_adaptive_demotions_total();
                    }
                }
                adaptive_buffers::record_user_tier(&wd_user, adaptive.max_tier_seen());
                debug!(
                    user = %wd_user,
                    dc = wd_dc,
                    from_tier = transition.from.as_u8(),
                    to_tier = transition.to.as_u8(),
                    reason = ?transition.reason,
                    throughput_ema_bps = sample
                        .c2s_bytes
                        .max(sample.s2c_written_bytes)
                        .saturating_mul(8)
                        .saturating_mul(4),
                    "Adaptive relay tier transition"
                );
            }

            prev_c2s_sample = c2s_total;
            prev_s2c_requested_sample = s2c_requested_total;
            prev_s2c_written_sample = s2c_written_total;
            prev_s2c_write_ops_sample = s2c_write_ops_total;
            prev_s2c_partial_sample = s2c_partial_total;

            accumulated_log = accumulated_log.saturating_add(ADAPTIVE_TICK);
            if accumulated_log < WATCHDOG_INTERVAL {
                continue;
            }
            accumulated_log = Duration::ZERO;

            // ── Periodic rate logging ───────────────────────────────
            let c2s = wd_counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c = wd_counters.s2c_bytes.load(Ordering::Relaxed);
            let c2s_delta = c2s.saturating_sub(prev_c2s_log);
            let s2c_delta = s2c.saturating_sub(prev_s2c_log);

            if c2s_delta > 0 || s2c_delta > 0 {
                let secs = WATCHDOG_INTERVAL.as_secs_f64();
                debug!(
                    user = %wd_user,
                    c2s_kbps = (c2s_delta as f64 / secs / 1024.0) as u64,
                    s2c_kbps = (s2c_delta as f64 / secs / 1024.0) as u64,
                    c2s_total = c2s,
                    s2c_total = s2c,
                    "Relay active"
                );
            }

            prev_c2s_log = c2s;
            prev_s2c_log = s2c;
        }
    };

    // ── Run bidirectional copy + watchdog concurrently ───────────────
    //
    // copy_bidirectional polls both directions in the same poll() call:
    //   C→S: poll_read(client/StatsIo) → poll_write(server)
    //   S→C: poll_read(server)         → poll_write(client/StatsIo)
    //
    // When one direction's writer returns Pending, the other direction
    // continues — no head-of-line blocking.
    //
    // When the watchdog fires, select! drops the copy future,
    // releasing the &mut borrows on client and server.
    let copy_result = tokio::select! {
        result = copy_bidirectional_with_sizes(
            &mut client,
            &mut server,
            c2s_buf_size.max(1),
            s2c_buf_size.max(1),
        ) => Some(result),
        _ = watchdog => None, // Activity timeout — cancel relay
    };

    // ── Clean shutdown ──────────────────────────────────────────────
    // After select!, the losing future is dropped, borrows released.
    // Shut down both write sides for clean TCP FIN.
    let _ = client.shutdown().await;
    let _ = server.shutdown().await;

    // ── Final logging ───────────────────────────────────────────────
    let c2s_ops = counters.c2s_ops.load(Ordering::Relaxed);
    let s2c_ops = counters.s2c_ops.load(Ordering::Relaxed);
    let duration = epoch.elapsed();
    adaptive_buffers::record_user_tier(&user_owned, seed_tier);

    match copy_result {
        Some(Ok((c2s, s2c))) => {
            // Normal completion — one side closed the connection
            debug!(
                user = %user_owned,
                c2s_bytes = c2s,
                s2c_bytes = s2c,
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Relay finished"
            );
            Ok(())
        }
        Some(Err(e)) => {
            // I/O error in one of the directions
            let c2s = counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c = counters.s2c_bytes.load(Ordering::Relaxed);
            debug!(
                user = %user_owned,
                c2s_bytes = c2s,
                s2c_bytes = s2c,
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                error = %e,
                "Relay error"
            );
            Err(e.into())
        }
        None => {
            // Activity timeout (watchdog fired)
            let c2s = counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c = counters.s2c_bytes.load(Ordering::Relaxed);
            debug!(
                user = %user_owned,
                c2s_bytes = c2s,
                s2c_bytes = s2c,
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Relay finished (activity timeout)"
            );
            Ok(())
        }
    }
}
