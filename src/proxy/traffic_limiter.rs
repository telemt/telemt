use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnetwork::IpNetwork;

use crate::config::{CidrRateLimitKey, RateLimitBps};

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

impl ScopeMetrics {
    fn throttle(&self, direction: RateDirection) {
        match direction {
            RateDirection::Up => {
                self.throttle_up_total.fetch_add(1, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.throttle_down_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn wait_ms(&self, direction: RateDirection, wait_ms: u64) {
        match direction {
            RateDirection::Up => {
                self.wait_up_ms_total.fetch_add(wait_ms, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.wait_down_ms_total
                    .fetch_add(wait_ms, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Default)]
struct AtomicRatePair {
    up_bps: AtomicU64,
    down_bps: AtomicU64,
}

impl AtomicRatePair {
    fn set(&self, limits: RateLimitBps) {
        self.up_bps.store(limits.up_bps, Ordering::Relaxed);
        self.down_bps.store(limits.down_bps, Ordering::Relaxed);
    }

    fn get(&self, direction: RateDirection) -> u64 {
        match direction {
            RateDirection::Up => self.up_bps.load(Ordering::Relaxed),
            RateDirection::Down => self.down_bps.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct DirectionBucket {
    epoch: AtomicU64,
    used: AtomicU64,
}

impl DirectionBucket {
    fn sync_epoch(&self, epoch: u64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
        }
    }

    fn try_consume(&self, cap_bps: u64, requested: u64) -> u64 {
        if requested == 0 {
            return 0;
        }
        if cap_bps == 0 {
            return requested;
        }

        let epoch = current_epoch();
        self.sync_epoch(epoch);
        let cap_epoch = bytes_per_epoch(cap_bps);

        loop {
            let used = self.used.load(Ordering::Relaxed);
            if used >= cap_epoch {
                return 0;
            }
            let remaining = cap_epoch.saturating_sub(used);
            let grant = requested.min(remaining);
            if grant == 0 {
                return 0;
            }
            let next = used.saturating_add(grant);
            if self
                .used
                .compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return grant;
            }
        }
    }

    fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

struct UserBucket {
    rates: AtomicRatePair,
    up: DirectionBucket,
    down: DirectionBucket,
    active_leases: AtomicU64,
}

impl UserBucket {
    fn new(limits: RateLimitBps) -> Self {
        let rates = AtomicRatePair::default();
        rates.set(limits);
        Self {
            rates,
            up: DirectionBucket::default(),
            down: DirectionBucket::default(),
            active_leases: AtomicU64::new(0),
        }
    }

    fn set_rates(&self, limits: RateLimitBps) {
        self.rates.set(limits);
    }

    fn try_consume(&self, direction: RateDirection, requested: u64) -> u64 {
        let cap_bps = self.rates.get(direction);
        match direction {
            RateDirection::Up => self.up.try_consume(cap_bps, requested),
            RateDirection::Down => self.down.try_consume(cap_bps, requested),
        }
    }

    fn refund(&self, direction: RateDirection, bytes: u64) {
        match direction {
            RateDirection::Up => self.up.refund(bytes),
            RateDirection::Down => self.down.refund(bytes),
        }
    }
}

#[derive(Default)]
struct CidrDirectionBucket {
    epoch: AtomicU64,
    used: AtomicU64,
    active_users: AtomicU64,
}

impl CidrDirectionBucket {
    fn sync_epoch(&self, epoch: u64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
            self.active_users.store(0, Ordering::Relaxed);
        }
    }

    fn try_consume(
        &self,
        user_state: &CidrUserDirectionState,
        cap_epoch: u64,
        requested: u64,
    ) -> u64 {
        if requested == 0 || cap_epoch == 0 {
            return 0;
        }

        let epoch = current_epoch();
        self.sync_epoch(epoch);
        user_state.sync_epoch_and_mark_active(epoch, &self.active_users);
        let active_users = self.active_users.load(Ordering::Relaxed).max(1);
        let fair_share = cap_epoch.saturating_div(active_users).max(1);

        loop {
            let total_used = self.used.load(Ordering::Relaxed);
            if total_used >= cap_epoch {
                return 0;
            }
            let total_remaining = cap_epoch.saturating_sub(total_used);
            let user_used = user_state.used.load(Ordering::Relaxed);
            let guaranteed_remaining = fair_share.saturating_sub(user_used);

            let grant = if guaranteed_remaining > 0 {
                requested.min(guaranteed_remaining).min(total_remaining)
            } else {
                requested.min(total_remaining).min(MAX_BORROW_CHUNK_BYTES)
            };

            if grant == 0 {
                return 0;
            }

            let next_total = total_used.saturating_add(grant);
            if self
                .used
                .compare_exchange_weak(total_used, next_total, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                user_state.used.fetch_add(grant, Ordering::Relaxed);
                return grant;
            }
        }
    }

    fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

#[derive(Default)]
struct CidrUserDirectionState {
    epoch: AtomicU64,
    used: AtomicU64,
}

impl CidrUserDirectionState {
    fn sync_epoch_and_mark_active(&self, epoch: u64, active_users: &AtomicU64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
            active_users.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

struct CidrUserShare {
    active_conns: AtomicU64,
    up: CidrUserDirectionState,
    down: CidrUserDirectionState,
}

impl CidrUserShare {
    fn new() -> Self {
        Self {
            active_conns: AtomicU64::new(0),
            up: CidrUserDirectionState::default(),
            down: CidrUserDirectionState::default(),
        }
    }
}

struct CidrBucket {
    rates: AtomicRatePair,
    up: CidrDirectionBucket,
    down: CidrDirectionBucket,
    users: ShardedRegistry<CidrUserShare>,
    active_leases: AtomicU64,
}

impl CidrBucket {
    fn new(limits: RateLimitBps) -> Self {
        let rates = AtomicRatePair::default();
        rates.set(limits);
        Self {
            rates,
            up: CidrDirectionBucket::default(),
            down: CidrDirectionBucket::default(),
            users: ShardedRegistry::new(REGISTRY_SHARDS),
            active_leases: AtomicU64::new(0),
        }
    }

    fn set_rates(&self, limits: RateLimitBps) {
        self.rates.set(limits);
    }

    fn acquire_user_share(&self, user: &str) -> Arc<CidrUserShare> {
        let share = self.users.get_or_insert_with(user, CidrUserShare::new);
        share.active_conns.fetch_add(1, Ordering::Relaxed);
        share
    }

    fn release_user_share(&self, user: &str, share: &Arc<CidrUserShare>) {
        decrement_atomic_saturating(&share.active_conns, 1);
        let share_for_remove = Arc::clone(share);
        let _ = self.users.remove_if(user, |candidate| {
            Arc::ptr_eq(candidate, &share_for_remove)
                && candidate.active_conns.load(Ordering::Relaxed) == 0
        });
    }

    fn try_consume_for_user(
        &self,
        direction: RateDirection,
        share: &CidrUserShare,
        requested: u64,
    ) -> u64 {
        let cap_bps = self.rates.get(direction);
        if cap_bps == 0 {
            return requested;
        }
        let cap_epoch = bytes_per_epoch(cap_bps);
        match direction {
            RateDirection::Up => self.up.try_consume(&share.up, cap_epoch, requested),
            RateDirection::Down => self.down.try_consume(&share.down, cap_epoch, requested),
        }
    }

    fn refund_for_user(&self, direction: RateDirection, share: &CidrUserShare, bytes: u64) {
        match direction {
            RateDirection::Up => {
                self.up.refund(bytes);
                share.up.refund(bytes);
            }
            RateDirection::Down => {
                self.down.refund(bytes);
                share.down.refund(bytes);
            }
        }
    }

    fn cleanup_idle_users(&self) {
        self.users
            .retain(|_, share| share.active_conns.load(Ordering::Relaxed) > 0);
    }
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

impl PolicySnapshot {
    fn match_cidr(&self, ip: IpAddr) -> Option<CidrPolicyMatch<'_>> {
        match ip {
            IpAddr::V4(_) => self
                .cidr_rules_v4
                .iter()
                .find(|rule| rule.cidr.contains(ip)),
            IpAddr::V6(_) => self
                .cidr_rules_v6
                .iter()
                .find(|rule| rule.cidr.contains(ip)),
        }
        .map(CidrPolicyMatch::Explicit)
        .or_else(|| self.match_auto_cidr(ip))
    }

    fn match_auto_cidr(&self, ip: IpAddr) -> Option<CidrPolicyMatch<'_>> {
        let rule = match ip {
            IpAddr::V4(_) => self.cidr_auto_rules_v4.first()?,
            IpAddr::V6(_) => self.cidr_auto_rules_v6.first()?,
        };
        let key = auto_cidr_bucket_key(ip, rule.prefix_len)?;
        Some(CidrPolicyMatch::Auto {
            key,
            limits: rule.limits,
        })
    }
}

struct ShardedRegistry<T> {
    shards: Box<[DashMap<String, Arc<T>>]>,
    mask: usize,
}

impl<T> ShardedRegistry<T> {
    fn new(shards: usize) -> Self {
        let shard_count = shards.max(1).next_power_of_two();
        let mut items = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            items.push(DashMap::<String, Arc<T>>::new());
        }
        Self {
            shards: items.into_boxed_slice(),
            mask: shard_count.saturating_sub(1),
        }
    }

    fn shard_index(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    fn get_or_insert_with<F>(&self, key: &str, make: F) -> Arc<T>
    where
        F: FnOnce() -> T,
    {
        let shard = &self.shards[self.shard_index(key)];
        match shard.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => Arc::clone(entry.get()),
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                let value = Arc::new(make());
                slot.insert(Arc::clone(&value));
                value
            }
        }
    }

    fn retain<F>(&self, predicate: F)
    where
        F: Fn(&String, &Arc<T>) -> bool + Copy,
    {
        for shard in &*self.shards {
            shard.retain(|key, value| predicate(key, value));
        }
    }

    fn remove_if<F>(&self, key: &str, predicate: F) -> bool
    where
        F: Fn(&Arc<T>) -> bool,
    {
        let shard = &self.shards[self.shard_index(key)];
        let should_remove = match shard.get(key) {
            Some(entry) => predicate(entry.value()),
            None => false,
        };
        if !should_remove {
            return false;
        }
        shard.remove(key).is_some()
    }
}

pub struct TrafficLease {
    limiter: Arc<TrafficLimiter>,
    user_bucket: Option<Arc<UserBucket>>,
    cidr_bucket: Option<Arc<CidrBucket>>,
    cidr_user_key: Option<String>,
    cidr_user_share: Option<Arc<CidrUserShare>>,
}

impl TrafficLease {
    pub fn try_consume(&self, direction: RateDirection, requested: u64) -> TrafficConsumeResult {
        if requested == 0 {
            return TrafficConsumeResult {
                granted: 0,
                blocked_user: false,
                blocked_cidr: false,
            };
        }

        let mut granted = requested;
        if let Some(user_bucket) = self.user_bucket.as_ref() {
            let user_granted = user_bucket.try_consume(direction, granted);
            if user_granted == 0 {
                self.limiter.observe_throttle(direction, true, false);
                return TrafficConsumeResult {
                    granted: 0,
                    blocked_user: true,
                    blocked_cidr: false,
                };
            }
            granted = user_granted;
        }

        if let (Some(cidr_bucket), Some(cidr_user_share)) =
            (self.cidr_bucket.as_ref(), self.cidr_user_share.as_ref())
        {
            let cidr_granted =
                cidr_bucket.try_consume_for_user(direction, cidr_user_share, granted);
            if cidr_granted < granted
                && let Some(user_bucket) = self.user_bucket.as_ref()
            {
                user_bucket.refund(direction, granted.saturating_sub(cidr_granted));
            }
            if cidr_granted == 0 {
                self.limiter.observe_throttle(direction, false, true);
                return TrafficConsumeResult {
                    granted: 0,
                    blocked_user: false,
                    blocked_cidr: true,
                };
            }
            granted = cidr_granted;
        }

        TrafficConsumeResult {
            granted,
            blocked_user: false,
            blocked_cidr: false,
        }
    }

    pub fn refund(&self, direction: RateDirection, bytes: u64) {
        if bytes == 0 {
            return;
        }

        if let Some(user_bucket) = self.user_bucket.as_ref() {
            user_bucket.refund(direction, bytes);
        }
        if let (Some(cidr_bucket), Some(cidr_user_share)) =
            (self.cidr_bucket.as_ref(), self.cidr_user_share.as_ref())
        {
            cidr_bucket.refund_for_user(direction, cidr_user_share, bytes);
        }
    }

    pub fn observe_wait_ms(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
        wait_ms: u64,
    ) {
        if wait_ms == 0 {
            return;
        }
        self.limiter
            .observe_wait(direction, blocked_user, blocked_cidr, wait_ms);
    }
}

impl Drop for TrafficLease {
    fn drop(&mut self) {
        if let Some(bucket) = self.user_bucket.as_ref() {
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.user_scope.active_leases, 1);
        }

        if let Some(bucket) = self.cidr_bucket.as_ref() {
            if let (Some(user_key), Some(share)) =
                (self.cidr_user_key.as_ref(), self.cidr_user_share.as_ref())
            {
                bucket.release_user_share(user_key, share);
            }
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.cidr_scope.active_leases, 1);
        }
    }
}

pub struct TrafficLimiter {
    policy: ArcSwap<PolicySnapshot>,
    user_buckets: ShardedRegistry<UserBucket>,
    cidr_buckets: ShardedRegistry<CidrBucket>,
    user_scope: ScopeMetrics,
    cidr_scope: ScopeMetrics,
    last_cleanup_epoch_secs: AtomicU64,
}

impl TrafficLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            policy: ArcSwap::from_pointee(PolicySnapshot::default()),
            user_buckets: ShardedRegistry::new(REGISTRY_SHARDS),
            cidr_buckets: ShardedRegistry::new(REGISTRY_SHARDS),
            user_scope: ScopeMetrics::default(),
            cidr_scope: ScopeMetrics::default(),
            last_cleanup_epoch_secs: AtomicU64::new(0),
        })
    }

    pub fn apply_policy(
        &self,
        user_limits: HashMap<String, RateLimitBps>,
        cidr_limits: HashMap<CidrRateLimitKey, RateLimitBps>,
    ) {
        let filtered_users = user_limits
            .into_iter()
            .filter(|(_, limit)| limit.up_bps > 0 || limit.down_bps > 0)
            .collect::<HashMap<_, _>>();

        let mut cidr_rules_v4 = Vec::new();
        let mut cidr_rules_v6 = Vec::new();
        let mut cidr_auto_rules_v4 = Vec::new();
        let mut cidr_auto_rules_v6 = Vec::new();
        let mut cidr_rule_keys = HashSet::new();
        for (key, limits) in cidr_limits {
            if limits.up_bps == 0 && limits.down_bps == 0 {
                continue;
            }
            match key {
                CidrRateLimitKey::Network(cidr) => {
                    let key = cidr.to_string();
                    let rule = CidrRule {
                        key: key.clone(),
                        cidr,
                        limits,
                        prefix_len: cidr.prefix(),
                    };
                    cidr_rule_keys.insert(key);
                    match rule.cidr {
                        IpNetwork::V4(_) => cidr_rules_v4.push(rule),
                        IpNetwork::V6(_) => cidr_rules_v6.push(rule),
                    }
                }
                CidrRateLimitKey::AutoV4(prefix_len) => {
                    cidr_auto_rules_v4.push(CidrAutoRule { prefix_len, limits });
                }
                CidrRateLimitKey::AutoV6(prefix_len) => {
                    cidr_auto_rules_v6.push(CidrAutoRule { prefix_len, limits });
                }
                CidrRateLimitKey::AutoDual(prefix_len) => {
                    cidr_auto_rules_v4.push(CidrAutoRule { prefix_len, limits });
                    cidr_auto_rules_v6.push(CidrAutoRule {
                        prefix_len: prefix_len.saturating_mul(4),
                        limits,
                    });
                }
            }
        }

        cidr_rules_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_rules_v6.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_auto_rules_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_auto_rules_v6.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        let cidr_policy_entries =
            cidr_rule_keys.len() + cidr_auto_rules_v4.len() + cidr_auto_rules_v6.len();

        self.user_scope
            .policy_entries
            .store(filtered_users.len() as u64, Ordering::Relaxed);
        self.cidr_scope
            .policy_entries
            .store(cidr_policy_entries as u64, Ordering::Relaxed);

        self.policy.store(Arc::new(PolicySnapshot {
            user_limits: filtered_users,
            cidr_rules_v4,
            cidr_rules_v6,
            cidr_auto_rules_v4,
            cidr_auto_rules_v6,
            cidr_rule_keys,
        }));

        self.maybe_cleanup();
    }

    pub fn acquire_lease(
        self: &Arc<Self>,
        user: &str,
        client_ip: IpAddr,
    ) -> Option<Arc<TrafficLease>> {
        let policy = self.policy.load_full();
        let mut user_bucket = None;
        if let Some(limit) = policy.user_limits.get(user).copied() {
            let bucket = self
                .user_buckets
                .get_or_insert_with(user, || UserBucket::new(limit));
            bucket.set_rates(limit);
            bucket.active_leases.fetch_add(1, Ordering::Relaxed);
            self.user_scope
                .active_leases
                .fetch_add(1, Ordering::Relaxed);
            user_bucket = Some(bucket);
        }

        let mut cidr_bucket = None;
        let mut cidr_user_key = None;
        let mut cidr_user_share = None;
        if let Some(rule_match) = policy.match_cidr(client_ip) {
            let (key, limits) = match &rule_match {
                CidrPolicyMatch::Explicit(rule) => (rule.key.as_str(), rule.limits),
                CidrPolicyMatch::Auto { key, limits } => (key.as_str(), *limits),
            };
            let bucket = self
                .cidr_buckets
                .get_or_insert_with(key, || CidrBucket::new(limits));
            bucket.set_rates(limits);
            bucket.active_leases.fetch_add(1, Ordering::Relaxed);
            self.cidr_scope
                .active_leases
                .fetch_add(1, Ordering::Relaxed);
            let share = bucket.acquire_user_share(user);
            cidr_user_key = Some(user.to_string());
            cidr_user_share = Some(share);
            cidr_bucket = Some(bucket);
        }

        if user_bucket.is_none() && cidr_bucket.is_none() {
            return None;
        }

        self.maybe_cleanup();
        Some(Arc::new(TrafficLease {
            limiter: Arc::clone(self),
            user_bucket,
            cidr_bucket,
            cidr_user_key,
            cidr_user_share,
        }))
    }

    pub fn metrics_snapshot(&self) -> TrafficLimiterMetricsSnapshot {
        TrafficLimiterMetricsSnapshot {
            user_throttle_up_total: self.user_scope.throttle_up_total.load(Ordering::Relaxed),
            user_throttle_down_total: self.user_scope.throttle_down_total.load(Ordering::Relaxed),
            cidr_throttle_up_total: self.cidr_scope.throttle_up_total.load(Ordering::Relaxed),
            cidr_throttle_down_total: self.cidr_scope.throttle_down_total.load(Ordering::Relaxed),
            user_wait_up_ms_total: self.user_scope.wait_up_ms_total.load(Ordering::Relaxed),
            user_wait_down_ms_total: self.user_scope.wait_down_ms_total.load(Ordering::Relaxed),
            cidr_wait_up_ms_total: self.cidr_scope.wait_up_ms_total.load(Ordering::Relaxed),
            cidr_wait_down_ms_total: self.cidr_scope.wait_down_ms_total.load(Ordering::Relaxed),
            user_active_leases: self.user_scope.active_leases.load(Ordering::Relaxed),
            cidr_active_leases: self.cidr_scope.active_leases.load(Ordering::Relaxed),
            user_policy_entries: self.user_scope.policy_entries.load(Ordering::Relaxed),
            cidr_policy_entries: self.cidr_scope.policy_entries.load(Ordering::Relaxed),
        }
    }

    fn observe_throttle(&self, direction: RateDirection, blocked_user: bool, blocked_cidr: bool) {
        if blocked_user {
            self.user_scope.throttle(direction);
        }
        if blocked_cidr {
            self.cidr_scope.throttle(direction);
        }
    }

    fn observe_wait(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
        wait_ms: u64,
    ) {
        if blocked_user {
            self.user_scope.wait_ms(direction, wait_ms);
        }
        if blocked_cidr {
            self.cidr_scope.wait_ms(direction, wait_ms);
        }
    }

    fn maybe_cleanup(&self) {
        let now_epoch_secs = now_epoch_secs();
        let last = self.last_cleanup_epoch_secs.load(Ordering::Relaxed);
        if now_epoch_secs.saturating_sub(last) < CLEANUP_INTERVAL_SECS {
            return;
        }
        if self
            .last_cleanup_epoch_secs
            .compare_exchange(last, now_epoch_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let policy = self.policy.load_full();
        self.user_buckets.retain(|user, bucket| {
            bucket.active_leases.load(Ordering::Relaxed) > 0
                || policy.user_limits.contains_key(user)
        });
        self.cidr_buckets.retain(|cidr_key, bucket| {
            bucket.cleanup_idle_users();
            bucket.active_leases.load(Ordering::Relaxed) > 0
                || policy.cidr_rule_keys.contains(cidr_key)
        });
    }
}

pub fn next_refill_delay() -> Duration {
    let start = limiter_epoch_start();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let epoch_pos = elapsed_ms % FAIR_EPOCH_MS;
    let wait_ms = FAIR_EPOCH_MS.saturating_sub(epoch_pos).max(1);
    Duration::from_millis(wait_ms)
}

fn decrement_atomic_saturating(counter: &AtomicU64, by: u64) {
    if by == 0 {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return;
        }
        let next = current.saturating_sub(by);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn bytes_per_epoch(bps: u64) -> u64 {
    if bps == 0 {
        return 0;
    }
    let numerator = bps.saturating_mul(FAIR_EPOCH_MS);
    let bytes = numerator.saturating_div(8_000);
    bytes.max(1)
}

fn auto_cidr_bucket_key(ip: IpAddr, prefix_len: u8) -> Option<String> {
    let cidr = IpNetwork::new(ip, prefix_len).ok()?;
    let network = IpNetwork::new(cidr.network(), prefix_len).ok()?;
    let family = match network {
        IpNetwork::V4(_) => "4",
        IpNetwork::V6(_) => "6",
    };
    Some(format!("auto:{family}:{network}"))
}

fn current_epoch() -> u64 {
    let start = limiter_epoch_start();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    elapsed_ms / FAIR_EPOCH_MS
}

fn limiter_epoch_start() -> &'static Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(up_bps: u64, down_bps: u64) -> RateLimitBps {
        RateLimitBps { up_bps, down_bps }
    }

    #[test]
    fn explicit_cidr_rule_wins_over_auto_template() {
        let limiter = TrafficLimiter::new();
        let mut cidr_limits = HashMap::new();
        cidr_limits.insert(CidrRateLimitKey::AutoV4(24), rate(1_000, 0));
        cidr_limits.insert(
            CidrRateLimitKey::Network("203.0.113.7/32".parse().unwrap()),
            rate(2_000, 0),
        );

        limiter.apply_policy(HashMap::new(), cidr_limits);
        let policy = limiter.policy.load_full();
        let matched = policy.match_cidr("203.0.113.7".parse().unwrap()).unwrap();

        match matched {
            CidrPolicyMatch::Explicit(rule) => assert_eq!(rule.key.as_str(), "203.0.113.7/32"),
            CidrPolicyMatch::Auto { .. } => panic!("explicit CIDR must have priority"),
        }
    }

    #[test]
    fn auto_template_uses_longest_prefix() {
        let limiter = TrafficLimiter::new();
        let mut cidr_limits = HashMap::new();
        cidr_limits.insert(CidrRateLimitKey::AutoV4(24), rate(1_000, 0));
        cidr_limits.insert(CidrRateLimitKey::AutoV4(32), rate(2_000, 0));

        limiter.apply_policy(HashMap::new(), cidr_limits);
        let policy = limiter.policy.load_full();
        let matched = policy.match_cidr("203.0.113.129".parse().unwrap()).unwrap();

        match matched {
            CidrPolicyMatch::Auto { key, limits } => {
                assert_eq!(key, "auto:4:203.0.113.129/32");
                assert_eq!(limits.up_bps, 2_000);
            }
            CidrPolicyMatch::Explicit(_) => panic!("auto-template match expected"),
        }
    }

    #[test]
    fn dual_auto_template_maps_v6_prefix_by_four() {
        let limiter = TrafficLimiter::new();
        let mut cidr_limits = HashMap::new();
        cidr_limits.insert(CidrRateLimitKey::AutoDual(32), rate(1_000, 0));

        limiter.apply_policy(HashMap::new(), cidr_limits);
        let policy = limiter.policy.load_full();
        let matched = policy.match_cidr("2001:db8::1".parse().unwrap()).unwrap();

        match matched {
            CidrPolicyMatch::Auto { key, .. } => {
                assert_eq!(key, "auto:6:2001:db8::1/128");
            }
            CidrPolicyMatch::Explicit(_) => panic!("auto-template match expected"),
        }
    }

    #[test]
    fn auto_cidr_bucket_key_canonicalizes_network_address() {
        assert_eq!(
            auto_cidr_bucket_key("203.0.113.129".parse().unwrap(), 24).unwrap(),
            "auto:4:203.0.113.0/24"
        );
        assert_eq!(
            auto_cidr_bucket_key("2001:db8::abcd".parse().unwrap(), 64).unwrap(),
            "auto:6:2001:db8::/64"
        );
    }
}
