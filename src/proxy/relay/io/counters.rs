use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

// ============= SharedCounters =============

/// Atomic counters shared between the relay (via StatsIo) and the watchdog task.
///
/// Using `Relaxed` ordering is sufficient because:
/// - Counters are monotonically increasing (no ABA problem)
/// - Slight staleness in watchdog reads is harmless (±10s check interval anyway)
/// - No ordering dependencies between different counters
pub(in crate::proxy::relay) struct SharedCounters {
    /// Bytes read from client (C→S direction)
    pub(in crate::proxy::relay) c2s_bytes: AtomicU64,
    /// Bytes written to client (S→C direction)
    pub(in crate::proxy::relay) s2c_bytes: AtomicU64,
    /// Number of poll_read completions (≈ C→S chunks)
    pub(in crate::proxy::relay) c2s_ops: AtomicU64,
    /// Number of poll_write completions (≈ S→C chunks)
    pub(in crate::proxy::relay) s2c_ops: AtomicU64,
    /// Bytes presented to client writes, including retried pending writes.
    pub(in crate::proxy::relay) s2c_requested_bytes: AtomicU64,
    /// Successful client writes that consumed only part of the offered slice.
    pub(in crate::proxy::relay) s2c_partial_writes: AtomicU64,
    /// Consecutive pending client writes observed by the active copy loop.
    pub(in crate::proxy::relay) s2c_consecutive_pending_writes: AtomicU32,
    /// Milliseconds since relay epoch of last I/O activity
    last_activity_ms: AtomicU64,
}

impl SharedCounters {
    pub(in crate::proxy::relay) fn new() -> Self {
        Self {
            c2s_bytes: AtomicU64::new(0),
            s2c_bytes: AtomicU64::new(0),
            c2s_ops: AtomicU64::new(0),
            s2c_ops: AtomicU64::new(0),
            s2c_requested_bytes: AtomicU64::new(0),
            s2c_partial_writes: AtomicU64::new(0),
            s2c_consecutive_pending_writes: AtomicU32::new(0),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    /// Record activity at this instant.
    #[inline]
    pub(in crate::proxy::relay) fn touch(&self, now: Instant, epoch: Instant) {
        let ms = now.duration_since(epoch).as_millis() as u64;
        self.last_activity_ms.store(ms, Ordering::Relaxed);
    }

    /// How long since last recorded activity.
    pub(in crate::proxy::relay) fn idle_duration(&self, now: Instant, epoch: Instant) -> Duration {
        let last_ms = self.last_activity_ms.load(Ordering::Relaxed);
        let now_ms = now.duration_since(epoch).as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }
}
