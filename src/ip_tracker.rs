// IP address tracking and per-user unique IP limiting.

#![allow(dead_code)]

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use crate::config::UserMaxUniqueIpsMode;

const CLEANUP_DRAIN_BATCH_LIMIT: usize = 1024;
const MAX_ACTIVE_IP_ENTRIES: u64 = 131_072;
const MAX_RECENT_IP_ENTRIES: u64 = 262_144;
const USER_IP_TRACKER_SHARDS: usize = 64;
const USER_IP_TRACKER_SHARD_MASK: usize = USER_IP_TRACKER_SHARDS - 1;

mod admission;
mod cleanup;
mod snapshot;
#[cfg(test)]
mod tests;

#[derive(Debug, Default)]
struct UserIpShard {
    active_ips: HashMap<String, HashMap<IpAddr, usize>>,
    recent_ips: HashMap<String, HashMap<IpAddr, Instant>>,
}

#[derive(Debug, Default)]
struct CleanupShard {
    queue: Mutex<HashMap<String, HashMap<IpAddr, usize>>>,
}

#[derive(Debug, Clone)]
struct UserIpLimitPolicy {
    max_ips: Arc<HashMap<String, usize>>,
    default_max_ips: usize,
    mode: UserMaxUniqueIpsMode,
    window_secs: u64,
}

impl Default for UserIpLimitPolicy {
    fn default() -> Self {
        Self {
            max_ips: Arc::new(HashMap::new()),
            default_max_ips: 0,
            mode: UserMaxUniqueIpsMode::ActiveWindow,
            window_secs: 30,
        }
    }
}

/// Tracks active and recent client IPs for per-user admission control.
#[derive(Debug, Clone)]
pub struct UserIpTracker {
    shards: Arc<Box<[RwLock<UserIpShard>]>>,
    active_entry_count: Arc<AtomicU64>,
    recent_entry_count: Arc<AtomicU64>,
    active_cap_rejects: Arc<AtomicU64>,
    recent_cap_rejects: Arc<AtomicU64>,
    cleanup_deferred_releases: Arc<AtomicU64>,
    limit_policy: Arc<ArcSwap<UserIpLimitPolicy>>,
    last_compact_epoch_secs: Arc<AtomicU64>,
    cleanup_queue_len: Arc<AtomicU64>,
    cleanup_shards: Arc<Box<[CleanupShard]>>,
    cleanup_drain_locks: Arc<Box<[AsyncMutex<()>]>>,
    #[cfg(test)]
    cleanup_queue_poison_probe: Arc<Mutex<HashMap<(String, IpAddr), usize>>>,
}

/// Point-in-time memory counters for user/IP limiter state.
#[derive(Debug, Clone, Copy)]
pub struct UserIpTrackerMemoryStats {
    /// Number of users with active IP state.
    pub active_users: usize,
    /// Number of users with recent IP state.
    pub recent_users: usize,
    /// Number of active `(user, ip)` entries.
    pub active_entries: usize,
    /// Number of recent-window `(user, ip)` entries.
    pub recent_entries: usize,
    /// Number of deferred disconnect cleanups waiting to be drained.
    pub cleanup_queue_len: usize,
    /// Number of new connections rejected by the global active-entry cap.
    pub active_cap_rejects: u64,
    /// Number of new connections rejected by the global recent-entry cap.
    pub recent_cap_rejects: u64,
    /// Number of release cleanups deferred through the cleanup queue.
    pub cleanup_deferred_releases: u64,
}

impl UserIpTracker {
    pub fn new() -> Self {
        let shards = std::iter::repeat_with(|| RwLock::new(UserIpShard::default()))
            .take(USER_IP_TRACKER_SHARDS)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let cleanup_shards = std::iter::repeat_with(CleanupShard::default)
            .take(USER_IP_TRACKER_SHARDS)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let cleanup_drain_locks = std::iter::repeat_with(|| AsyncMutex::new(()))
            .take(USER_IP_TRACKER_SHARDS)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards: Arc::new(shards),
            active_entry_count: Arc::new(AtomicU64::new(0)),
            recent_entry_count: Arc::new(AtomicU64::new(0)),
            active_cap_rejects: Arc::new(AtomicU64::new(0)),
            recent_cap_rejects: Arc::new(AtomicU64::new(0)),
            cleanup_deferred_releases: Arc::new(AtomicU64::new(0)),
            limit_policy: Arc::new(ArcSwap::from_pointee(UserIpLimitPolicy::default())),
            last_compact_epoch_secs: Arc::new(AtomicU64::new(0)),
            cleanup_queue_len: Arc::new(AtomicU64::new(0)),
            cleanup_shards: Arc::new(cleanup_shards),
            cleanup_drain_locks: Arc::new(cleanup_drain_locks),
            #[cfg(test)]
            cleanup_queue_poison_probe: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) fn shard_idx(username: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        username.hash(&mut hasher);
        (hasher.finish() as usize) & USER_IP_TRACKER_SHARD_MASK
    }

    fn limit_window(policy: &UserIpLimitPolicy) -> Duration {
        Duration::from_secs(policy.window_secs)
    }

    fn user_limit(policy: &UserIpLimitPolicy, username: &str) -> Option<usize> {
        policy
            .max_ips
            .get(username)
            .copied()
            .filter(|limit| *limit > 0)
            .or_else(|| (policy.default_max_ips > 0).then_some(policy.default_max_ips))
    }

    pub(super) fn decrement_counter(counter: &AtomicU64, amount: usize) {
        if amount == 0 {
            return;
        }
        let amount = amount as u64;
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(amount))
        });
    }

    pub(super) fn apply_active_cleanup(
        active_ips: &mut HashMap<String, HashMap<IpAddr, usize>>,
        user: &str,
        ip: IpAddr,
        pending_count: usize,
    ) -> usize {
        if pending_count == 0 {
            return 0;
        }

        let mut remove_user = false;
        let mut removed_active_entries = 0usize;
        if let Some(user_ips) = active_ips.get_mut(user) {
            if let Some(count) = user_ips.get_mut(&ip) {
                if *count > pending_count {
                    *count -= pending_count;
                } else if user_ips.remove(&ip).is_some() {
                    removed_active_entries = 1;
                }
            }
            remove_user = user_ips.is_empty();
        }
        if remove_user {
            active_ips.remove(user);
        }
        removed_active_entries
    }

    pub(super) fn try_increment_counter(counter: &AtomicU64, cap: u64) -> bool {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                (current < cap).then_some(current + 1)
            })
            .is_ok()
    }

    pub(super) fn pop_one_cleanup(
        queue: &mut HashMap<String, HashMap<IpAddr, usize>>,
    ) -> Option<(String, IpAddr, usize)> {
        let user = queue.keys().next().cloned()?;
        let ip = queue.get(&user)?.keys().next().copied()?;
        let count = queue.get_mut(&user)?.remove(&ip)?;
        let remove_user = queue
            .get(&user)
            .map(|user_queue| user_queue.is_empty())
            .unwrap_or(false);
        if remove_user {
            queue.remove(&user);
        }
        Some((user, ip, count))
    }

    #[cfg(test)]
    pub(super) fn observe_cleanup_poison_for_tests(&self) {
        match self.cleanup_queue_poison_probe.lock() {
            Ok(_) => {}
            Err(_) => {
                self.cleanup_queue_poison_probe.clear_poison();
            }
        }
    }

    #[cfg(not(test))]
    pub(super) fn observe_cleanup_poison_for_tests(&self) {}

    pub(super) fn now_epoch_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for UserIpTracker {
    fn default() -> Self {
        Self::new()
    }
}
