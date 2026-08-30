use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnetwork::IpNetwork;

use crate::config::RateLimitBps;

// Atomic per-user and per-CIDR accounting.
mod buckets;
// Immutable policy matching and sharded registries.
mod policy;
// Traffic lease accounting and cleanup.
mod lease;
// Runtime policy application and admission.
mod limiter;
// Epoch and arithmetic helpers.
mod helpers;

pub use helpers::next_refill_delay;
use helpers::{
    auto_cidr_bucket_key, bytes_per_epoch, current_epoch, decrement_atomic_saturating,
    now_epoch_secs,
};

#[cfg(test)]
mod tests;
const REGISTRY_SHARDS: usize = 64;
const FAIR_EPOCH_MS: u64 = 20;
const MAX_BORROW_CHUNK_BYTES: u64 = 32 * 1024;
const CLEANUP_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDirection {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficConsumeResult {
    pub granted: u64,
    pub blocked_user: bool,
    pub blocked_cidr: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TrafficLimiterMetricsSnapshot {
    pub user_throttle_up_total: u64,
    pub user_throttle_down_total: u64,
    pub cidr_throttle_up_total: u64,
    pub cidr_throttle_down_total: u64,
    pub user_wait_up_ms_total: u64,
    pub user_wait_down_ms_total: u64,
    pub cidr_wait_up_ms_total: u64,
    pub cidr_wait_down_ms_total: u64,
    pub user_active_leases: u64,
    pub cidr_active_leases: u64,
    pub user_policy_entries: u64,
    pub cidr_policy_entries: u64,
}

#[derive(Default)]
struct ScopeMetrics {
    throttle_up_total: AtomicU64,
    throttle_down_total: AtomicU64,
    wait_up_ms_total: AtomicU64,
    wait_down_ms_total: AtomicU64,
    active_leases: AtomicU64,
    policy_entries: AtomicU64,
}

#[derive(Default)]
struct AtomicRatePair {
    up_bps: AtomicU64,
    down_bps: AtomicU64,
}

#[derive(Default)]
struct DirectionBucket {
    epoch: AtomicU64,
    used: AtomicU64,
}

struct UserBucket {
    rates: AtomicRatePair,
    up: DirectionBucket,
    down: DirectionBucket,
    active_leases: AtomicU64,
}

#[derive(Default)]
struct CidrDirectionBucket {
    epoch: AtomicU64,
    used: AtomicU64,
    active_users: AtomicU64,
}

#[derive(Default)]
struct CidrUserDirectionState {
    epoch: AtomicU64,
    used: AtomicU64,
}

struct CidrUserShare {
    active_conns: AtomicU64,
    up: CidrUserDirectionState,
    down: CidrUserDirectionState,
}

struct CidrBucket {
    rates: AtomicRatePair,
    up: CidrDirectionBucket,
    down: CidrDirectionBucket,
    users: ShardedRegistry<CidrUserShare>,
    active_leases: AtomicU64,
}

#[derive(Clone)]
struct CidrRule {
    key: String,
    cidr: IpNetwork,
    limits: RateLimitBps,
    prefix_len: u8,
}

#[derive(Clone, Copy)]
struct CidrAutoRule {
    prefix_len: u8,
    limits: RateLimitBps,
}

enum CidrPolicyMatch<'a> {
    Explicit(&'a CidrRule),
    Auto { key: String, limits: RateLimitBps },
}

#[derive(Default)]
struct PolicySnapshot {
    user_limits: HashMap<String, RateLimitBps>,
    cidr_rules_v4: Vec<CidrRule>,
    cidr_rules_v6: Vec<CidrRule>,
    cidr_auto_rules_v4: Vec<CidrAutoRule>,
    cidr_auto_rules_v6: Vec<CidrAutoRule>,
    cidr_rule_keys: HashSet<String>,
}

struct ShardedRegistry<T> {
    shards: Box<[DashMap<String, Arc<T>>]>,
    mask: usize,
}

pub struct TrafficLease {
    limiter: Arc<TrafficLimiter>,
    user_bucket: Option<Arc<UserBucket>>,
    cidr_bucket: Option<Arc<CidrBucket>>,
    cidr_user_key: Option<String>,
    cidr_user_share: Option<Arc<CidrUserShare>>,
}

pub struct TrafficLimiter {
    policy: ArcSwap<PolicySnapshot>,
    user_buckets: ShardedRegistry<UserBucket>,
    cidr_buckets: ShardedRegistry<CidrBucket>,
    user_scope: ScopeMetrics,
    cidr_scope: ScopeMetrics,
    last_cleanup_epoch_secs: AtomicU64,
}
