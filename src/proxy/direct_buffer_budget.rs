use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::{Mutex as ParkingMutex, MutexGuard as ParkingMutexGuard};
use tokio::sync::watch;

// Process controller and system-memory sampling remain outside data-plane accounting.
mod controller;
#[cfg(test)]
use controller::connection_fill_pct;
pub(crate) use controller::{
    resolve_direct_buffer_hard_limit, run_direct_buffer_budget_controller,
};

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
    active_controller_generation: AtomicU64,
    controller_update: ParkingMutex<()>,
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
            active_controller_generation: AtomicU64::new(0),
            controller_update: ParkingMutex::new(()),
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

    /// Transfers adaptive-target writes to the active runtime generation.
    pub(crate) fn activate_controller(&self, generation: u64) {
        let _controller_update = self.controller_update.lock();
        self.active_controller_generation
            .fetch_max(generation, Ordering::AcqRel);
    }

    fn begin_controller_update(&self, generation: u64) -> Option<ParkingMutexGuard<'_, ()>> {
        let controller_update = self.controller_update.lock();
        (self.active_controller_generation.load(Ordering::Acquire) == generation)
            .then_some(controller_update)
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
        let target =
            align_down(target.clamp(self.target_floor_bytes(), self.hard_limit_bytes) as usize)
                as u64;
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
        self.minimum_fallback_total.fetch_add(1, Ordering::Relaxed);
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
#[cfg(test)]
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
