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

use crate::error::{ProxyError, Result};
use crate::stats::{Stats, UserStats};
use crate::stream::BufferPool;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional_with_sizes};
use tokio::time::Instant;
use tracing::{debug, trace, warn};

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

#[inline]
fn watchdog_delta(current: u64, previous: u64) -> u64 {
    current.saturating_sub(previous)
}

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
}

impl SharedCounters {
    fn new() -> Self {
        Self {
            c2s_bytes: AtomicU64::new(0),
            s2c_bytes: AtomicU64::new(0),
            c2s_ops: AtomicU64::new(0),
            s2c_ops: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(0),
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
    user_stats: Arc<UserStats>,
    quota_limit: Option<u64>,
    quota_exceeded: Arc<AtomicBool>,
    quota_bytes_since_check: u64,
    epoch: Instant,
}

impl<S> StatsIo<S> {
    fn new(
        inner: S,
        counters: Arc<SharedCounters>,
        stats: Arc<Stats>,
        user: String,
        quota_limit: Option<u64>,
        quota_exceeded: Arc<AtomicBool>,
        epoch: Instant,
    ) -> Self {
        // Mark initial activity so the watchdog doesn't fire before data flows
        counters.touch(Instant::now(), epoch);
        let user_stats = stats.get_or_create_user_stats_handle(&user);
        Self {
            inner,
            counters,
            stats,
            user,
            user_stats,
            quota_limit,
            quota_exceeded,
            quota_bytes_since_check: 0,
            epoch,
        }
    }
}

#[derive(Debug)]
struct QuotaIoSentinel;

impl std::fmt::Display for QuotaIoSentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("user data quota exceeded")
    }
}

impl std::error::Error for QuotaIoSentinel {}

fn quota_io_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, QuotaIoSentinel)
}

fn is_quota_io_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        && err
            .get_ref()
            .and_then(|source| source.downcast_ref::<QuotaIoSentinel>())
            .is_some()
}

const QUOTA_NEAR_LIMIT_BYTES: u64 = 64 * 1024;
const QUOTA_LARGE_CHARGE_BYTES: u64 = 16 * 1024;
const QUOTA_ADAPTIVE_INTERVAL_MIN_BYTES: u64 = 4 * 1024;
const QUOTA_ADAPTIVE_INTERVAL_MAX_BYTES: u64 = 64 * 1024;

#[inline]
fn quota_adaptive_interval_bytes(remaining_before: u64) -> u64 {
    remaining_before.saturating_div(2).clamp(
        QUOTA_ADAPTIVE_INTERVAL_MIN_BYTES,
        QUOTA_ADAPTIVE_INTERVAL_MAX_BYTES,
    )
}

#[inline]
fn should_immediate_quota_check(remaining_before: u64, charge_bytes: u64) -> bool {
    remaining_before <= QUOTA_NEAR_LIMIT_BYTES || charge_bytes >= QUOTA_LARGE_CHARGE_BYTES
}

impl<S: AsyncRead + Unpin> AsyncRead for StatsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.quota_exceeded.load(Ordering::Acquire) {
            return Poll::Ready(Err(quota_io_error()));
        }

        let mut remaining_before = None;
        if let Some(limit) = this.quota_limit {
            let used_before = this.user_stats.quota_used();
            let remaining = limit.saturating_sub(used_before);
            if remaining == 0 {
                this.quota_exceeded.store(true, Ordering::Release);
                return Poll::Ready(Err(quota_io_error()));
            }
            remaining_before = Some(remaining);
        }

        let before = buf.filled().len();

        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    let n_to_charge = n as u64;

                    // C→S: client sent data
                    this.counters
                        .c2s_bytes
                        .fetch_add(n_to_charge, Ordering::Relaxed);
                    this.counters.c2s_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats
                        .add_user_octets_from_handle(this.user_stats.as_ref(), n_to_charge);
                    this.stats
                        .increment_user_msgs_from_handle(this.user_stats.as_ref());

                    if let (Some(limit), Some(remaining)) = (this.quota_limit, remaining_before) {
                        this.stats
                            .quota_charge_post_write(this.user_stats.as_ref(), n_to_charge);
                        if should_immediate_quota_check(remaining, n_to_charge) {
                            this.quota_bytes_since_check = 0;
                            if this.user_stats.quota_used() >= limit {
                                this.quota_exceeded.store(true, Ordering::Release);
                            }
                        } else {
                            this.quota_bytes_since_check =
                                this.quota_bytes_since_check.saturating_add(n_to_charge);
                            let interval = quota_adaptive_interval_bytes(remaining);
                            if this.quota_bytes_since_check >= interval {
                                this.quota_bytes_since_check = 0;
                                if this.user_stats.quota_used() >= limit {
                                    this.quota_exceeded.store(true, Ordering::Release);
                                }
                            }
                        }
                    }

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
        if this.quota_exceeded.load(Ordering::Acquire) {
            return Poll::Ready(Err(quota_io_error()));
        }

        let mut remaining_before = None;
        if let Some(limit) = this.quota_limit {
            let used_before = this.user_stats.quota_used();
            let remaining = limit.saturating_sub(used_before);
            if remaining == 0 {
                this.quota_exceeded.store(true, Ordering::Release);
                return Poll::Ready(Err(quota_io_error()));
            }
            remaining_before = Some(remaining);
        }

        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    let n_to_charge = n as u64;

                    // S→C: data written to client
                    this.counters
                        .s2c_bytes
                        .fetch_add(n_to_charge, Ordering::Relaxed);
                    this.counters.s2c_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats
                        .add_user_octets_to_handle(this.user_stats.as_ref(), n_to_charge);
                    this.stats
                        .increment_user_msgs_to_handle(this.user_stats.as_ref());

                    if let (Some(limit), Some(remaining)) = (this.quota_limit, remaining_before) {
                        this.stats
                            .quota_charge_post_write(this.user_stats.as_ref(), n_to_charge);
                        if should_immediate_quota_check(remaining, n_to_charge) {
                            this.quota_bytes_since_check = 0;
                            if this.user_stats.quota_used() >= limit {
                                this.quota_exceeded.store(true, Ordering::Release);
                            }
                        } else {
                            this.quota_bytes_since_check =
                                this.quota_bytes_since_check.saturating_add(n_to_charge);
                            let interval = quota_adaptive_interval_bytes(remaining);
                            if this.quota_bytes_since_check >= interval {
                                this.quota_bytes_since_check = 0;
                                if this.user_stats.quota_used() >= limit {
                                    this.quota_exceeded.store(true, Ordering::Release);
                                }
                            }
                        }
                    }

                    trace!(user = %this.user, bytes = n, "S->C");
                }
                Poll::Ready(Ok(n))
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
/// - Error propagation: quota exits return `ProxyError::DataQuotaExceeded`,
///   other I/O failures are returned as `ProxyError::Io`
pub async fn relay_bidirectional<CR, CW, SR, SW>(
    client_reader: CR,
    client_writer: CW,
    server_reader: SR,
    server_writer: SW,
    c2s_buf_size: usize,
    s2c_buf_size: usize,
    user: &str,
    stats: Arc<Stats>,
    quota_limit: Option<u64>,
    _buffer_pool: Arc<BufferPool>,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    let epoch = Instant::now();
    let counters = Arc::new(SharedCounters::new());
    let quota_exceeded = Arc::new(AtomicBool::new(false));
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
        quota_limit,
        Arc::clone(&quota_exceeded),
        epoch,
    );

    // ── Watchdog: activity timeout + periodic rate logging ──────────
    let wd_counters = Arc::clone(&counters);
    let wd_user = user_owned.clone();
    let wd_quota_exceeded = Arc::clone(&quota_exceeded);

    let watchdog = async {
        let mut prev_c2s: u64 = 0;
        let mut prev_s2c: u64 = 0;

        loop {
            tokio::time::sleep(WATCHDOG_INTERVAL).await;

            let now = Instant::now();
            let idle = wd_counters.idle_duration(now, epoch);

            if wd_quota_exceeded.load(Ordering::Acquire) {
                warn!(user = %wd_user, "User data quota reached, closing relay");
                return;
            }

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

            // ── Periodic rate logging ───────────────────────────────
            let c2s = wd_counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c = wd_counters.s2c_bytes.load(Ordering::Relaxed);
            let c2s_delta = watchdog_delta(c2s, prev_c2s);
            let s2c_delta = watchdog_delta(s2c, prev_s2c);

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

            prev_c2s = c2s;
            prev_s2c = s2c;
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
        Some(Err(e)) if is_quota_io_error(&e) => {
            let c2s = counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c = counters.s2c_bytes.load(Ordering::Relaxed);
            warn!(
                user = %user_owned,
                c2s_bytes = c2s,
                s2c_bytes = s2c,
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Data quota reached, closing relay"
            );
            Err(ProxyError::DataQuotaExceeded {
                user: user_owned.clone(),
            })
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

#[cfg(test)]
#[path = "tests/relay_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/relay_quota_boundary_blackhat_tests.rs"]
mod relay_quota_boundary_blackhat_tests;

#[cfg(test)]
#[path = "tests/relay_quota_model_adversarial_tests.rs"]
mod relay_quota_model_adversarial_tests;

#[cfg(test)]
#[path = "tests/relay_quota_overflow_regression_tests.rs"]
mod relay_quota_overflow_regression_tests;

#[cfg(test)]
#[path = "tests/relay_quota_extended_attack_surface_security_tests.rs"]
mod relay_quota_extended_attack_surface_security_tests;

#[cfg(test)]
#[path = "tests/relay_watchdog_delta_security_tests.rs"]
mod relay_watchdog_delta_security_tests;

#[cfg(test)]
#[path = "tests/relay_atomic_quota_invariant_tests.rs"]
mod relay_atomic_quota_invariant_tests;
