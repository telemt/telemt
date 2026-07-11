use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;

use crate::stats::Stats;
use crate::stream::BufferPool;

use super::shared_state::ProxySharedState;

/// Accounting granularity for process-wide Direct copy-buffer reservations.
pub(crate) const DIRECT_BUFFER_UNIT_BYTES: usize = 4 * 1024;
/// Minimum client-to-DC copy-buffer capacity for one Direct session.
pub(crate) const DIRECT_BASE_C2S_BYTES: usize = 4 * 1024;
/// Minimum DC-to-client copy-buffer capacity for one Direct session.
pub(crate) const DIRECT_BASE_S2C_BYTES: usize = 8 * 1024;

const AUTO_HARD_MIN_BYTES: usize = 64 * 1024 * 1024;
const AUTO_HARD_MAX_BYTES: usize = 2 * 1024 * 1024 * 1024;
const AUTO_HARD_FALLBACK_BYTES: usize = 512 * 1024 * 1024;
const TARGET_FLOOR_MIN_BYTES: usize = 16 * 1024 * 1024;
const CONTROL_INTERVAL: Duration = Duration::from_secs(1);
const HEALTHY_RECOVERY_SAMPLES: u8 = 30;
const BUFFER_POOL_TRIM_LOW_WATERMARK: usize = 64;
const BUFFER_POOL_TRIM_HIGH_WATERMARK: usize = 128;

#[derive(Debug, Clone, Copy, Default)]
/// Lock-free observability snapshot of the Direct copy-buffer envelope.
pub(crate) struct DirectBufferBudgetSnapshot {
    /// Absolute process-wide copy-buffer ceiling.
    pub(crate) hard_limit_bytes: u64,
    /// Current pressure-adjusted promotion target.
    pub(crate) target_bytes: u64,
    /// Bytes currently covered by active session leases.
    pub(crate) reserved_bytes: u64,
    /// Effective host or cgroup memory limit.
    pub(crate) memory_total_bytes: u64,
    /// Effective host or cgroup memory headroom.
    pub(crate) memory_available_bytes: u64,
    /// Current process resident set size.
    pub(crate) process_rss_bytes: u64,
    /// Successful tier growth reservations.
    pub(crate) promotion_total: u64,
    /// Tier growth attempts rejected by the adaptive target.
    pub(crate) promotion_denied_total: u64,
    /// Sessions admitted at minimum size above the adaptive target.
    pub(crate) minimum_fallback_total: u64,
    /// Sessions rejected by the absolute ceiling.
    pub(crate) admission_rejected_total: u64,
    /// Quiet-period tier reductions.
    pub(crate) quiet_demotion_total: u64,
    /// Sustained write-pressure tier reductions.
    pub(crate) write_pressure_demotion_total: u64,
    /// Process-wide pressure tier reductions.
    pub(crate) global_pressure_demotion_total: u64,
    /// Current sessions for Base through Tier3.
    pub(crate) tier_sessions: [u64; 4],
}

#[derive(Debug, Clone, Copy, Default)]
struct SystemMemorySample {
    total_bytes: u64,
    available_bytes: u64,
    process_rss_bytes: u64,
}

/// Process-wide hard envelope and adaptive target for Direct copy buffers.
pub(crate) struct DirectBufferBudget {
    hard_limit_bytes: u64,
    target_bytes: AtomicU64,
    reserved_bytes: AtomicU64,
    pressure_generation: AtomicU64,
    pressure_tx: watch::Sender<u64>,
    memory_total_bytes: AtomicU64,
    memory_available_bytes: AtomicU64,
    process_rss_bytes: AtomicU64,
    promotion_total: AtomicU64,
    promotion_denied_total: AtomicU64,
    minimum_fallback_total: AtomicU64,
    admission_rejected_total: AtomicU64,
    quiet_demotion_total: AtomicU64,
    write_pressure_demotion_total: AtomicU64,
    global_pressure_demotion_total: AtomicU64,
    tier_sessions: [AtomicU64; 4],
}

impl DirectBufferBudget {
    /// Creates an envelope with a fixed absolute ceiling.
    pub(crate) fn new(hard_limit_bytes: usize) -> Arc<Self> {
        let hard_limit_bytes = align_down(hard_limit_bytes.max(DIRECT_BUFFER_UNIT_BYTES)) as u64;
        let (pressure_tx, _) = watch::channel(0);
        Arc::new(Self {
            hard_limit_bytes,
            target_bytes: AtomicU64::new(hard_limit_bytes),
            reserved_bytes: AtomicU64::new(0),
            pressure_generation: AtomicU64::new(0),
            pressure_tx,
            memory_total_bytes: AtomicU64::new(0),
            memory_available_bytes: AtomicU64::new(0),
            process_rss_bytes: AtomicU64::new(0),
            promotion_total: AtomicU64::new(0),
            promotion_denied_total: AtomicU64::new(0),
            minimum_fallback_total: AtomicU64::new(0),
            admission_rejected_total: AtomicU64::new(0),
            quiet_demotion_total: AtomicU64::new(0),
            write_pressure_demotion_total: AtomicU64::new(0),
            global_pressure_demotion_total: AtomicU64::new(0),
            tier_sessions: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }

    /// Returns the current pressure-adjusted reservation target.
    pub(crate) fn target_bytes(&self) -> usize {
        self.target_bytes.load(Ordering::Relaxed) as usize
    }

    /// Subscribes to target reductions that require prompt session demotion.
    pub(crate) fn subscribe_pressure(&self) -> watch::Receiver<u64> {
        self.pressure_tx.subscribe()
    }

    /// Reserves bytes against either the adaptive target or the absolute ceiling.
    pub(crate) fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
        allow_above_target: bool,
    ) -> Option<DirectBufferLease> {
        let bytes = align_up(bytes) as u64;
        let limit = if allow_above_target {
            self.hard_limit_bytes
        } else {
            self.target_bytes
                .load(Ordering::Relaxed)
                .min(self.hard_limit_bytes)
        };
        if !self.try_add_reserved(bytes, limit) {
            return None;
        }
        self.tier_sessions[0].fetch_add(1, Ordering::Relaxed);
        Some(DirectBufferLease {
            budget: Arc::clone(self),
            reserved_bytes: bytes,
            tier: 0,
        })
    }

    fn try_add_reserved(&self, bytes: u64, limit: u64) -> bool {
        let mut current = self.reserved_bytes.load(Ordering::Acquire);
        loop {
            if bytes > limit.saturating_sub(current) {
                return false;
            }
            match self.reserved_bytes.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn target_floor_bytes(&self) -> u64 {
        (self.hard_limit_bytes / 8)
            .max(TARGET_FLOOR_MIN_BYTES as u64)
            .min(self.hard_limit_bytes)
    }

    fn set_target_bytes(&self, target: u64) {
        let target = align_down(
            target
                .clamp(self.target_floor_bytes(), self.hard_limit_bytes)
                as usize,
        ) as u64;
        let previous = self.target_bytes.swap(target, Ordering::AcqRel);
        if target < previous {
            let generation = self
                .pressure_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1);
            self.pressure_tx.send_replace(generation);
        }
    }

    fn update_system_sample(&self, sample: SystemMemorySample) {
        self.memory_total_bytes
            .store(sample.total_bytes, Ordering::Relaxed);
        self.memory_available_bytes
            .store(sample.available_bytes, Ordering::Relaxed);
        self.process_rss_bytes
            .store(sample.process_rss_bytes, Ordering::Relaxed);
    }

    /// Records a session that had to bypass the adaptive target at minimum size.
    pub(crate) fn increment_minimum_fallback(&self) {
        self.minimum_fallback_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a session rejected because the absolute ceiling was exhausted.
    pub(crate) fn increment_admission_rejected(&self) {
        self.admission_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a tier reduction after sustained low throughput.
    pub(crate) fn increment_quiet_demotion(&self) {
        self.quiet_demotion_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a tier reduction after sustained partial or pending writes.
    pub(crate) fn increment_write_pressure_demotion(&self) {
        self.write_pressure_demotion_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a tier reduction requested by the process-wide controller.
    pub(crate) fn increment_global_pressure_demotion(&self) {
        self.global_pressure_demotion_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Captures all bounded metrics without allocating or locking.
    pub(crate) fn snapshot(&self) -> DirectBufferBudgetSnapshot {
        DirectBufferBudgetSnapshot {
            hard_limit_bytes: self.hard_limit_bytes,
            target_bytes: self.target_bytes.load(Ordering::Relaxed),
            reserved_bytes: self.reserved_bytes.load(Ordering::Relaxed),
            memory_total_bytes: self.memory_total_bytes.load(Ordering::Relaxed),
            memory_available_bytes: self.memory_available_bytes.load(Ordering::Relaxed),
            process_rss_bytes: self.process_rss_bytes.load(Ordering::Relaxed),
            promotion_total: self.promotion_total.load(Ordering::Relaxed),
            promotion_denied_total: self.promotion_denied_total.load(Ordering::Relaxed),
            minimum_fallback_total: self.minimum_fallback_total.load(Ordering::Relaxed),
            admission_rejected_total: self.admission_rejected_total.load(Ordering::Relaxed),
            quiet_demotion_total: self.quiet_demotion_total.load(Ordering::Relaxed),
            write_pressure_demotion_total: self
                .write_pressure_demotion_total
                .load(Ordering::Relaxed),
            global_pressure_demotion_total: self
                .global_pressure_demotion_total
                .load(Ordering::Relaxed),
            tier_sessions: std::array::from_fn(|index| {
                self.tier_sessions[index].load(Ordering::Relaxed)
            }),
        }
    }
}

/// Returns the conservative ceiling used when memory discovery is unavailable.
pub(crate) fn fallback_direct_buffer_hard_limit() -> usize {
    AUTO_HARD_FALLBACK_BYTES
}

/// RAII ownership of all copy-buffer bytes retained by one Direct session.
pub(crate) struct DirectBufferLease {
    budget: Arc<DirectBufferBudget>,
    reserved_bytes: u64,
    tier: usize,
}

impl DirectBufferLease {
    /// Returns the currently covered allocation rounded to accounting units.
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reserved_bytes as usize
    }

    /// Attempts to cover a larger tier before its buffers are resized.
    pub(crate) fn try_grow_to(&mut self, bytes: usize) -> bool {
        let bytes = align_up(bytes) as u64;
        if bytes <= self.reserved_bytes {
            return true;
        }
        let delta = bytes - self.reserved_bytes;
        let limit = self
            .budget
            .target_bytes
            .load(Ordering::Relaxed)
            .min(self.budget.hard_limit_bytes);
        if !self.budget.try_add_reserved(delta, limit) {
            self.budget
                .promotion_denied_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.reserved_bytes = bytes;
        self.budget.promotion_total.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Releases bytes only after both directional buffers report smaller coverage.
    pub(crate) fn shrink_to(&mut self, bytes: usize) {
        let bytes = align_up(bytes) as u64;
        if bytes >= self.reserved_bytes {
            return;
        }
        let released = self.reserved_bytes - bytes;
        self.reserved_bytes = bytes;
        self.budget
            .reserved_bytes
            .fetch_sub(released, Ordering::AcqRel);
    }

    /// Updates bounded per-tier session gauges for an accepted transition.
    pub(crate) fn set_tier(&mut self, tier: usize) {
        let tier = tier.min(self.budget.tier_sessions.len() - 1);
        if tier == self.tier {
            return;
        }
        decrement_saturating(&self.budget.tier_sessions[self.tier]);
        self.budget.tier_sessions[tier].fetch_add(1, Ordering::Relaxed);
        self.tier = tier;
    }
}

impl Drop for DirectBufferLease {
    fn drop(&mut self) {
        self.budget
            .reserved_bytes
            .fetch_sub(self.reserved_bytes, Ordering::AcqRel);
        decrement_saturating(&self.budget.tier_sessions[self.tier]);
    }
}

/// Resolves the startup hard ceiling from config, cgroup, and host memory.
pub(crate) async fn resolve_direct_buffer_hard_limit(configured: usize) -> usize {
    if configured != 0 {
        return align_down(configured);
    }
    let sample = read_system_memory_sample().await;
    if sample.total_bytes == 0 {
        return AUTO_HARD_FALLBACK_BYTES;
    }
    let derived = (sample.total_bytes / 4)
        .clamp(AUTO_HARD_MIN_BYTES as u64, AUTO_HARD_MAX_BYTES as u64)
        .min(sample.total_bytes);
    align_down(derived as usize).max(DIRECT_BUFFER_UNIT_BYTES)
}

/// Starts the single control-plane task for Direct budget and shared pool pressure.
pub(crate) fn spawn_direct_buffer_budget_controller(
    budget: Arc<DirectBufferBudget>,
    buffer_pool: Arc<BufferPool>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
    max_connections: u32,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CONTROL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut healthy_streak = 0u8;
        let mut previous_denied = 0u64;
        let mut previous_fallback = 0u64;
        let mut previous_rejected = 0u64;
        let pool_trim_low = buffer_pool
            .max_buffers()
            .min(BUFFER_POOL_TRIM_LOW_WATERMARK);
        let pool_trim_high = buffer_pool
            .max_buffers()
            .min(BUFFER_POOL_TRIM_HIGH_WATERMARK);
        let mut pool_trim_armed = true;

        loop {
            interval.tick().await;
            let sample = read_system_memory_sample().await;
            budget.update_system_sample(sample);

            let snapshot = budget.snapshot();
            let denied_delta = snapshot.promotion_denied_total.saturating_sub(previous_denied);
            previous_denied = snapshot.promotion_denied_total;
            let fallback_delta = snapshot
                .minimum_fallback_total
                .saturating_sub(previous_fallback);
            previous_fallback = snapshot.minimum_fallback_total;
            let rejected_delta = snapshot
                .admission_rejected_total
                .saturating_sub(previous_rejected);
            previous_rejected = snapshot.admission_rejected_total;

            let connection_pct = connection_fill_pct(stats.as_ref(), max_connections);
            let memory_available_pct = percentage(sample.available_bytes, sample.total_bytes);
            let target_utilization_pct = percentage(snapshot.reserved_bytes, snapshot.target_bytes);
            let pressure = shared.conntrack_pressure_active()
                || connection_pct.is_some_and(|value| value >= 85)
                || memory_available_pct.is_some_and(|value| value <= 15)
                || target_utilization_pct.is_some_and(|value| value >= 90)
                || denied_delta > 0
                || fallback_delta > 0
                || rejected_delta > 0;

            if !pressure {
                pool_trim_armed = true;
            } else if pool_trim_armed && buffer_pool.pooled() > pool_trim_high {
                buffer_pool.trim_to(pool_trim_low);
                pool_trim_armed = false;
            }

            let pool_snapshot = buffer_pool.stats();
            stats.set_buffer_pool_gauges(
                pool_snapshot.pooled,
                pool_snapshot.allocated,
                pool_snapshot.allocated.saturating_sub(pool_snapshot.pooled),
            );
            stats.set_buffer_pool_replaced_nonstandard_total(
                pool_snapshot.replaced_nonstandard,
            );

            let headroom_target = if sample.total_bytes == 0 {
                snapshot.hard_limit_bytes
            } else {
                snapshot
                    .reserved_bytes
                    .saturating_add(sample.available_bytes / 4)
                    .min(snapshot.hard_limit_bytes)
            };

            if pressure {
                healthy_streak = 0;
                let reduced = snapshot.target_bytes.saturating_mul(3) / 4;
                budget.set_target_bytes(reduced.min(headroom_target));
                continue;
            }

            let healthy = memory_available_pct.is_none_or(|value| value >= 30)
                && connection_pct.is_none_or(|value| value <= 70);
            if !healthy {
                healthy_streak = 0;
                if headroom_target < snapshot.target_bytes {
                    budget.set_target_bytes(headroom_target);
                }
                continue;
            }

            healthy_streak = healthy_streak.saturating_add(1);
            if healthy_streak >= HEALTHY_RECOVERY_SAMPLES {
                healthy_streak = 0;
                let increment = (snapshot.target_bytes / 16).max(4 * 1024 * 1024);
                budget.set_target_bytes(
                    snapshot
                        .target_bytes
                        .saturating_add(increment)
                        .min(headroom_target),
                );
            }
        }
    });
}

fn connection_fill_pct(stats: &Stats, max_connections: u32) -> Option<u8> {
    if max_connections == 0 {
        return None;
    }
    Some(
        ((stats
            .get_current_connections_total()
            .saturating_mul(100))
            / u64::from(max_connections))
        .min(100) as u8,
    )
}

fn percentage(value: u64, total: u64) -> Option<u8> {
    if total == 0 {
        return None;
    }
    Some(((value.saturating_mul(100)) / total).min(100) as u8)
}

async fn read_system_memory_sample() -> SystemMemorySample {
    #[cfg(target_os = "linux")]
    {
        let meminfo = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .unwrap_or_default();
        let status = tokio::fs::read_to_string("/proc/self/status")
            .await
            .unwrap_or_default();
        let host_total = parse_kib_field(&meminfo, "MemTotal:");
        let host_available = parse_kib_field(&meminfo, "MemAvailable:");
        let process_rss = parse_kib_field(&status, "VmRSS:");

        let cgroup_v2_max = read_cgroup_limit("/sys/fs/cgroup/memory.max").await;
        let cgroup_v2_current = read_u64_file("/sys/fs/cgroup/memory.current").await;
        let cgroup_v1_max = read_cgroup_limit("/sys/fs/cgroup/memory/memory.limit_in_bytes").await;
        let cgroup_v1_current =
            read_u64_file("/sys/fs/cgroup/memory/memory.usage_in_bytes").await;
        let cgroup_max = cgroup_v2_max.or(cgroup_v1_max);
        let cgroup_current = cgroup_v2_current.or(cgroup_v1_current);

        let total = match (host_total, cgroup_max) {
            (0, Some(limit)) => limit,
            (host, Some(limit)) => host.min(limit),
            (host, None) => host,
        };
        let cgroup_available = cgroup_max.zip(cgroup_current).map(|(limit, current)| {
            limit.saturating_sub(current)
        });
        let available = match (host_available, cgroup_available) {
            (0, Some(value)) => value,
            (host, Some(value)) => host.min(value),
            (host, None) => host,
        };
        return SystemMemorySample {
            total_bytes: total,
            available_bytes: available,
            process_rss_bytes: process_rss,
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        SystemMemorySample::default()
    }
}

#[cfg(target_os = "linux")]
async fn read_cgroup_limit(path: &str) -> Option<u64> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    let raw = raw.trim();
    if raw == "max" {
        return None;
    }
    let value = raw.parse::<u64>().ok()?;
    (value < (1u64 << 60)).then_some(value)
}

#[cfg(target_os = "linux")]
async fn read_u64_file(path: &str) -> Option<u64> {
    tokio::fs::read_to_string(path)
        .await
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn parse_kib_field(raw: &str, key: &str) -> u64 {
    raw.lines()
        .find_map(|line| {
            let value = line.strip_prefix(key)?.split_whitespace().next()?;
            value.parse::<u64>().ok()
        })
        .unwrap_or(0)
        .saturating_mul(1024)
}

fn align_up(bytes: usize) -> usize {
    bytes
        .div_ceil(DIRECT_BUFFER_UNIT_BYTES)
        .saturating_mul(DIRECT_BUFFER_UNIT_BYTES)
}

fn align_down(bytes: usize) -> usize {
    bytes / DIRECT_BUFFER_UNIT_BYTES * DIRECT_BUFFER_UNIT_BYTES
}

fn decrement_saturating(value: &AtomicU64) {
    let mut current = value.load(Ordering::Relaxed);
    while current != 0 {
        match value.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
#[path = "tests/direct_buffer_budget_tests.rs"]
mod tests;
