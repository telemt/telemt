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
use crate::proxy::traffic_limiter::TrafficLease;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

// ============= Constants =============

/// Activity timeout for iOS compatibility.
///
/// iOS keeps Telegram connections alive in background for up to 30 minutes.
/// Closing earlier causes unnecessary reconnects and handshake overhead.
#[allow(dead_code)]
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

mod adaptive_copy;
mod io;

pub(crate) use self::adaptive_copy::relay_direct_adaptive;

use self::io::{CombinedStream, SharedCounters, StatsIo, is_quota_io_error};
#[cfg(test)]
use self::io::{quota_adaptive_interval_bytes, should_immediate_quota_check};
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
#[allow(dead_code)]
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
    relay_bidirectional_with_activity_timeout(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        c2s_buf_size,
        s2c_buf_size,
        user,
        stats,
        quota_limit,
        _buffer_pool,
        ACTIVITY_TIMEOUT,
    )
    .await
}

pub async fn relay_bidirectional_with_activity_timeout<CR, CW, SR, SW>(
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
    activity_timeout: Duration,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    relay_bidirectional_with_activity_timeout_and_lease(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        c2s_buf_size,
        s2c_buf_size,
        user,
        stats,
        quota_limit,
        _buffer_pool,
        None,
        activity_timeout,
    )
    .await
}

pub async fn relay_bidirectional_with_activity_timeout_and_lease<CR, CW, SR, SW>(
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
    traffic_lease: Option<Arc<TrafficLease>>,
    activity_timeout: Duration,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    relay_bidirectional_with_activity_timeout_lease_cancel_inner(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        c2s_buf_size,
        s2c_buf_size,
        user,
        stats,
        quota_limit,
        _buffer_pool,
        traffic_lease,
        activity_timeout,
        None,
    )
    .await
}

#[allow(dead_code)]
pub async fn relay_bidirectional_with_activity_timeout_lease_and_cancel<CR, CW, SR, SW>(
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
    traffic_lease: Option<Arc<TrafficLease>>,
    activity_timeout: Duration,
    session_cancel: CancellationToken,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    relay_bidirectional_with_activity_timeout_lease_cancel_inner(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        c2s_buf_size,
        s2c_buf_size,
        user,
        stats,
        quota_limit,
        _buffer_pool,
        traffic_lease,
        activity_timeout,
        Some(session_cancel),
    )
    .await
}

async fn relay_bidirectional_with_activity_timeout_lease_cancel_inner<CR, CW, SR, SW>(
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
    traffic_lease: Option<Arc<TrafficLease>>,
    activity_timeout: Duration,
    session_cancel: Option<CancellationToken>,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    let activity_timeout = activity_timeout.max(Duration::from_secs(1));
    let epoch = Instant::now();
    let counters = Arc::new(SharedCounters::new());
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let user_owned = user.to_string();

    // ── Combine split halves into bidirectional streams ──────────────
    let client_combined = CombinedStream::new(client_reader, client_writer);
    let mut server = CombinedStream::new(server_reader, server_writer);

    // Wrap client with stats/activity tracking
    let mut client = StatsIo::new_with_traffic_lease(
        client_combined,
        Arc::clone(&counters),
        Arc::clone(&stats),
        user_owned.clone(),
        traffic_lease,
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
            if idle >= activity_timeout {
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
    enum RelayOutcome {
        Copy(std::io::Result<(u64, u64)>),
        ActivityTimeout,
        UserDisabled,
    }

    let cancel_wait = async move {
        match session_cancel {
            Some(token) => token.cancelled().await,
            None => pending::<()>().await,
        }
    };
    tokio::pin!(cancel_wait);

    let relay_outcome = tokio::select! {
        result = copy_bidirectional_with_sizes(
            &mut client,
            &mut server,
            c2s_buf_size.max(1),
            s2c_buf_size.max(1),
        ) => RelayOutcome::Copy(result),
        _ = watchdog => RelayOutcome::ActivityTimeout,
        _ = &mut cancel_wait => RelayOutcome::UserDisabled,
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

    match relay_outcome {
        RelayOutcome::Copy(Ok((c2s, s2c))) => {
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
        RelayOutcome::Copy(Err(e)) if is_quota_io_error(&e) => {
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
        RelayOutcome::Copy(Err(e)) => {
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
        RelayOutcome::ActivityTimeout => {
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
        RelayOutcome::UserDisabled => {
            let c2s = counters.c2s_bytes.load(Ordering::Relaxed);
            let s2c = counters.s2c_bytes.load(Ordering::Relaxed);
            debug!(
                user = %user_owned,
                c2s_bytes = c2s,
                s2c_bytes = s2c,
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Relay finished (user disabled)"
            );
            Err(ProxyError::UserDisabled {
                user: user_owned.clone(),
            })
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

#[cfg(test)]
#[path = "tests/relay_baseline_invariant_tests.rs"]
mod relay_baseline_invariant_tests;
