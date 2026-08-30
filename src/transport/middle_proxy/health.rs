#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::MeFloorMode;
use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::MePool;
use super::pool::MeFamilyRuntimeState;

const JITTER_FRAC_NUM: u64 = 2; // jitter up to 50% of backoff
#[allow(dead_code)]
const MAX_CONCURRENT_PER_DC_DEFAULT: usize = 1;
const SHADOW_ROTATE_RETRY_SECS: u64 = 30;
const IDLE_REFRESH_TRIGGER_BASE_SECS: u64 = 45;
const IDLE_REFRESH_TRIGGER_JITTER_SECS: u64 = 5;
const IDLE_REFRESH_RETRY_SECS: u64 = 8;
const IDLE_REFRESH_SUCCESS_GUARD_SECS: u64 = 5;
const HEALTH_RECONNECT_BUDGET_PER_CORE: usize = 2;
const HEALTH_RECONNECT_BUDGET_PER_DC: usize = 1;
const HEALTH_RECONNECT_BUDGET_MIN: usize = 4;
const HEALTH_RECONNECT_BUDGET_MAX: usize = 128;
const FAMILY_SUPPRESS_FAIL_STREAK_THRESHOLD: u32 = 5;
const FAMILY_SUPPRESS_DURATION_SECS: u64 = 60;
const FAMILY_RECOVER_SUCCESS_STREAK_TARGET: u32 = 2;
const HEALTH_DRAIN_CLOSE_BUDGET_PER_CORE: usize = 16;
const HEALTH_DRAIN_CLOSE_BUDGET_MIN: usize = 16;
const HEALTH_DRAIN_CLOSE_BUDGET_MAX: usize = 256;
const HEALTH_DRAIN_TIMEOUT_ENFORCER_INTERVAL_SECS: u64 = 1;

#[derive(Debug, Clone)]
struct DcFloorPlanEntry {
    dc: i32,
    endpoints: Vec<SocketAddr>,
    alive: usize,
    min_required: usize,
    target_required: usize,
    max_required: usize,
    has_bound_clients: bool,
    floor_capped: bool,
}

#[derive(Debug, Clone)]
struct FamilyFloorPlan {
    by_dc: HashMap<i32, DcFloorPlanEntry>,
    active_cap_configured_total: usize,
    active_cap_effective_total: usize,
    warm_cap_configured_total: usize,
    warm_cap_effective_total: usize,
    active_writers_current: usize,
    warm_writers_current: usize,
    target_writers_total: usize,
}

#[derive(Debug)]
struct FamilyReconnectOutcome {
    key: (i32, IpFamily),
    dc: i32,
    family: IpFamily,
    required: usize,
    endpoint_count: usize,
}

struct ScheduledReconnects<'a> {
    inflight: &'a mut HashMap<(i32, IpFamily), usize>,
    keys: Vec<(i32, IpFamily)>,
}

impl ScheduledReconnects<'_> {
    fn current(&self, key: &(i32, IpFamily)) -> usize {
        self.inflight.get(key).copied().unwrap_or(0)
    }

    fn reserve(&mut self, key: (i32, IpFamily)) {
        self.keys.push(key);
        *self.inflight.entry(key).or_insert(0) += 1;
    }
}

impl Drop for ScheduledReconnects<'_> {
    fn drop(&mut self) {
        for key in self.keys.drain(..) {
            let std::collections::hash_map::Entry::Occupied(mut entry) = self.inflight.entry(key)
            else {
                continue;
            };
            let remaining = entry.get().saturating_sub(1);
            if remaining == 0 {
                entry.remove();
            } else {
                *entry.get_mut() = remaining;
            }
        }
    }
}

// Periodic family health monitor orchestration.
mod monitor;
// Draining-writer deadline enforcement.
mod drain;
// Per-family reconnect scheduling and health state.
mod family;
// Adaptive-floor planning and warning rate limits.
mod floor_plan;
// Idle-writer refresh and cap-aware swaps.
mod idle_refresh;
// Single-endpoint recovery and shadow rotation.
mod recovery;
// Independent stale draining-writer watchdog.
mod zombie_watchdog;

pub use drain::me_drain_timeout_enforcer;
pub(in crate::transport::middle_proxy) use drain::{
    health_drain_close_budget, reap_draining_writers,
};
use family::{check_family, update_family_runtime_state};
use floor_plan::{
    build_family_floor_plan, live_active_writers_for_dc_family, should_emit_rate_limited_warn,
};
use idle_refresh::{maybe_refresh_idle_writer_for_dc, maybe_swap_idle_writer_for_cap};
pub use monitor::me_health_monitor;
use recovery::{
    has_bound_clients_on_endpoint, maybe_rotate_single_endpoint_shadow,
    recover_single_endpoint_outage,
};
pub use zombie_watchdog::me_zombie_writer_watchdog;

#[cfg(test)]
mod tests;
