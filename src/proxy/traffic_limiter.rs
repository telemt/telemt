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

use crate::config::RateLimitBps;

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

#[derive(Default)]
struct PolicySnapshot {
    user_limits: HashMap<String, RateLimitBps>,
    cidr_rules_v4: Vec<CidrRule>,
    cidr_rules_v6: Vec<CidrRule>,
    cidr_rule_keys: HashSet<String>,
}

impl PolicySnapshot {
    fn match_cidr(&self, ip: IpAddr) -> Option<&CidrRule> {
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
        cidr_limits: HashMap<IpNetwork, RateLimitBps>,
    ) {
        let filtered_users = user_limits
            .into_iter()
            .filter(|(_, limit)| limit.up_bps > 0 || limit.down_bps > 0)
            .collect::<HashMap<_, _>>();

        let mut cidr_rules_v4 = Vec::new();
        let mut cidr_rules_v6 = Vec::new();
        let mut cidr_rule_keys = HashSet::new();
        for (cidr, limits) in cidr_limits {
            if limits.up_bps == 0 && limits.down_bps == 0 {
                continue;
            }
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

        cidr_rules_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_rules_v6.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));

        self.user_scope
            .policy_entries
            .store(filtered_users.len() as u64, Ordering::Relaxed);
        self.cidr_scope
            .policy_entries
            .store(cidr_rule_keys.len() as u64, Ordering::Relaxed);

        self.policy.store(Arc::new(PolicySnapshot {
            user_limits: filtered_users,
            cidr_rules_v4,
            cidr_rules_v6,
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
        if let Some(rule) = policy.match_cidr(client_ip) {
            let bucket = self
                .cidr_buckets
                .get_or_insert_with(rule.key.as_str(), || CidrBucket::new(rule.limits));
            bucket.set_rates(rule.limits);
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
mod pure_helpers_tests {
    use super::*;

    #[test]
    fn decrement_saturating_does_nothing_when_zero_or_by_zero() {
        let c = AtomicU64::new(0);
        decrement_atomic_saturating(&c, 5);
        assert_eq!(c.load(Ordering::Relaxed), 0);

        let c = AtomicU64::new(100);
        decrement_atomic_saturating(&c, 0);
        assert_eq!(c.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn decrement_saturating_clamps_at_zero() {
        let c = AtomicU64::new(3);
        decrement_atomic_saturating(&c, 10);
        assert_eq!(c.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn decrement_saturating_subtracts_normally() {
        let c = AtomicU64::new(50);
        decrement_atomic_saturating(&c, 20);
        assert_eq!(c.load(Ordering::Relaxed), 30);
        decrement_atomic_saturating(&c, 30);
        assert_eq!(c.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bytes_per_epoch_is_zero_when_bps_is_zero() {
        assert_eq!(bytes_per_epoch(0), 0);
    }

    #[test]
    fn bytes_per_epoch_floors_at_one_for_nonzero_bps() {
        // 1 bit/s is way below the 20 ms-worth threshold but the function
        // contract is "never zero when bps>0" — useful so we don't starve
        // tiny budgets to literally zero.
        assert_eq!(bytes_per_epoch(1), 1);
        assert_eq!(bytes_per_epoch(7), 1);
    }

    #[test]
    fn bytes_per_epoch_matches_expected_math() {
        // 8 Mbps × 20 ms / 8 (bits→bytes) / 1000 (ms→s) = 20_000 bytes.
        // The function computes (bps × 20) / 8_000.
        assert_eq!(bytes_per_epoch(8_000_000), 20_000);
        // 1 Mbps → 2500 bytes per 20 ms epoch.
        assert_eq!(bytes_per_epoch(1_000_000), 2_500);
        // 100 Mbps → 250_000 bytes per epoch.
        assert_eq!(bytes_per_epoch(100_000_000), 250_000);
    }

    #[test]
    fn bytes_per_epoch_saturates_on_overflow() {
        // u64::MAX bps must not overflow — saturating_mul/div protect us.
        let b = bytes_per_epoch(u64::MAX);
        assert!(b > 0);
    }

    #[test]
    fn next_refill_delay_is_within_fair_epoch_window() {
        let d = next_refill_delay();
        let ms = d.as_millis() as u64;
        assert!(ms >= 1, "delay must be at least 1 ms");
        assert!(
            ms <= FAIR_EPOCH_MS,
            "delay must not exceed FAIR_EPOCH_MS ({} ms), got {}",
            FAIR_EPOCH_MS,
            ms
        );
    }

    #[test]
    fn limiter_epoch_start_is_stable_across_calls() {
        // The OnceLock-backed start time must be the same instant every
        // time — without that invariant `current_epoch()` and
        // `next_refill_delay()` would drift relative to each other.
        let a = *limiter_epoch_start();
        let b = *limiter_epoch_start();
        assert_eq!(a, b);
    }

    #[test]
    fn current_epoch_is_monotonic_non_decreasing() {
        let e1 = current_epoch();
        let e2 = current_epoch();
        assert!(e2 >= e1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── AtomicRatePair set/get direction isolation ───────────

    mod atomic_rate_pair {
        use super::*;

        #[test]
        fn set_up_does_not_affect_down() {
            let pair = AtomicRatePair::default();
            pair.set(RateLimitBps {
                up_bps: 1000,
                down_bps: 0,
            });
            assert_eq!(pair.get(RateDirection::Up), 1000);
            assert_eq!(pair.get(RateDirection::Down), 0);
        }

        #[test]
        fn set_down_does_not_affect_up() {
            let pair = AtomicRatePair::default();
            pair.set(RateLimitBps {
                up_bps: 0,
                down_bps: 500,
            });
            assert_eq!(pair.get(RateDirection::Up), 0);
            assert_eq!(pair.get(RateDirection::Down), 500);
        }

        #[test]
        fn set_both_independent() {
            let pair = AtomicRatePair::default();
            pair.set(RateLimitBps {
                up_bps: 200,
                down_bps: 400,
            });
            assert_eq!(pair.get(RateDirection::Up), 200);
            assert_eq!(pair.get(RateDirection::Down), 400);
        }

        #[test]
        fn overwrite_previous() {
            let pair = AtomicRatePair::default();
            pair.set(RateLimitBps {
                up_bps: 100,
                down_bps: 200,
            });
            pair.set(RateLimitBps {
                up_bps: 300,
                down_bps: 400,
            });
            assert_eq!(pair.get(RateDirection::Up), 300);
            assert_eq!(pair.get(RateDirection::Down), 400);
        }
    }

    // ── DirectionBucket token math ───────────────────────────

    mod direction_bucket {
        use super::*;

        #[test]
        fn try_consume_requested_zero_grants_zero() {
            let bucket = DirectionBucket::default();
            let granted = bucket.try_consume(1000, 0);
            assert_eq!(granted, 0);
        }

        #[test]
        fn try_consume_cap_zero_grants_all() {
            let bucket = DirectionBucket::default();
            let granted = bucket.try_consume(0, 500);
            assert_eq!(granted, 500);
        }

        #[test]
        fn try_consume_within_cap_grants_requested() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let granted = bucket.try_consume(cap_bps, 100);
            assert_eq!(granted, 100);
        }

        #[test]
        fn try_consume_exceeds_cap_grants_partial() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let cap_epoch = bytes_per_epoch(cap_bps);
            let requested = cap_epoch + 1000;
            let granted = bucket.try_consume(cap_bps, requested);
            assert!(granted <= cap_epoch);
            assert!(granted > 0);
        }

        #[test]
        fn try_consume_drains_to_zero_then_blocks() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let cap_epoch = bytes_per_epoch(cap_bps);

            let first = bucket.try_consume(cap_bps, cap_epoch);
            assert!(first > 0);

            let second = bucket.try_consume(cap_bps, 1);
            assert_eq!(second, 0);
        }

        #[test]
        fn try_consume_multiple_small_requests_exhaust_cap() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let cap_epoch = bytes_per_epoch(cap_bps);

            let mut total_granted = 0u64;
            for _ in 0..cap_epoch {
                let g = bucket.try_consume(cap_bps, 1);
                total_granted += g;
                if g == 0 {
                    break;
                }
            }
            assert_eq!(total_granted, cap_epoch);
        }

        #[test]
        fn refund_noop_on_zero() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let g1 = bucket.try_consume(cap_bps, 100);
            bucket.refund(0);
            let g2 = bucket.try_consume(cap_bps, 100);
            assert_eq!(g1 + g2, 200);
        }

        #[test]
        fn refund_restores_capacity() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let cap_epoch = bytes_per_epoch(cap_bps);

            let first = bucket.try_consume(cap_bps, cap_epoch);
            assert!(first > 0);

            bucket.refund(first);

            let after_refund = bucket.try_consume(cap_bps, first);
            assert_eq!(after_refund, first);
        }

        #[test]
        fn refund_clamps_at_cap() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let cap_epoch = bytes_per_epoch(cap_bps);

            bucket.refund(cap_epoch * 10);

            let granted = bucket.try_consume(cap_bps, cap_epoch);
            assert_eq!(granted, cap_epoch);
            let extra = bucket.try_consume(cap_bps, 1);
            assert_eq!(extra, 0);
        }

        #[test]
        fn sync_epoch_resets_used() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let _ = bucket.try_consume(cap_bps, 500);

            let epoch = current_epoch() + 1_000_000;
            bucket.sync_epoch(epoch);

            assert_eq!(bucket.used.load(Ordering::Relaxed), 0);
            assert_eq!(bucket.epoch.load(Ordering::Relaxed), epoch);
        }

        #[test]
        fn sync_epoch_same_epoch_noop() {
            let bucket = DirectionBucket::default();
            let epoch = current_epoch();
            bucket.sync_epoch(epoch);
            let used_before = bucket.used.load(Ordering::Relaxed);
            bucket.sync_epoch(epoch);
            assert_eq!(bucket.used.load(Ordering::Relaxed), used_before);
        }

        #[test]
        fn monotonicity_after_consume() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let n = 50u64;
            let _ = bucket.try_consume(cap_bps, n);
            let used = bucket.used.load(Ordering::Relaxed);
            assert!(used >= n);
        }
    }

    // ── UserBucket direction isolation ───────────────────────

    mod user_bucket {
        use super::*;

        #[test]
        fn new_sets_initial_rates() {
            let limits = RateLimitBps {
                up_bps: 1000,
                down_bps: 2000,
            };
            let ub = UserBucket::new(limits);
            assert_eq!(ub.rates.get(RateDirection::Up), 1000);
            assert_eq!(ub.rates.get(RateDirection::Down), 2000);
        }

        #[test]
        fn set_rates_updates_both() {
            let ub = UserBucket::new(RateLimitBps {
                up_bps: 0,
                down_bps: 0,
            });
            ub.set_rates(RateLimitBps {
                up_bps: 500,
                down_bps: 600,
            });
            assert_eq!(ub.rates.get(RateDirection::Up), 500);
            assert_eq!(ub.rates.get(RateDirection::Down), 600);
        }

        #[test]
        fn try_consume_up_does_not_touch_down() {
            let limits = RateLimitBps {
                up_bps: 8_000_000,
                down_bps: 8_000_000,
            };
            let ub = UserBucket::new(limits);
            let up_granted = ub.try_consume(RateDirection::Up, 100);
            assert_eq!(up_granted, 100);
            let down_used = ub.down.used.load(Ordering::Relaxed);
            assert_eq!(down_used, 0);
        }

        #[test]
        fn try_consume_down_does_not_touch_up() {
            let limits = RateLimitBps {
                up_bps: 8_000_000,
                down_bps: 8_000_000,
            };
            let ub = UserBucket::new(limits);
            let down_granted = ub.try_consume(RateDirection::Down, 100);
            assert_eq!(down_granted, 100);
            let up_used = ub.up.used.load(Ordering::Relaxed);
            assert_eq!(up_used, 0);
        }

        #[test]
        fn refund_direction_isolation() {
            let limits = RateLimitBps {
                up_bps: 8_000_000,
                down_bps: 8_000_000,
            };
            let ub = UserBucket::new(limits);
            let _ = ub.try_consume(RateDirection::Up, 200);
            let _ = ub.try_consume(RateDirection::Down, 200);
            ub.refund(RateDirection::Up, 200);
            assert_eq!(ub.up.used.load(Ordering::Relaxed), 0);
            assert_eq!(ub.down.used.load(Ordering::Relaxed), 200);
        }
    }

    // ── ShardedRegistry routing ──────────────────────────────

    mod sharded_registry {
        use super::*;

        #[test]
        fn shard_index_deterministic() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(64);
            let key = "user-12345";
            let i1 = reg.shard_index(key);
            let i2 = reg.shard_index(key);
            assert_eq!(i1, i2);
        }

        #[test]
        fn shard_index_different_keys_may_differ() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(64);
            let a = reg.shard_index("alice");
            let b = reg.shard_index("bob");
            assert!(a < 64);
            assert!(b < 64);
        }

        #[test]
        fn shard_index_within_bounds() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(64);
            for key in &["a", "b", "c", "d", "e", "f", "g", "h"] {
                let idx = reg.shard_index(key);
                assert!(idx < 64, "shard index {} out of bounds for key {}", idx, key);
            }
        }

        #[test]
        fn shard_index_uniformity_modulo() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(64);
            let mut seen = std::collections::HashSet::new();
            for i in 0..200u64 {
                let key = format!("key-{i}");
                seen.insert(reg.shard_index(&key));
            }
            assert!(
                seen.len() > 8,
                "expected spread across many shards, got only {}",
                seen.len()
            );
        }

        #[test]
        fn new_rounds_to_power_of_two() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(10);
            assert_eq!(reg.shards.len(), 16);
            assert_eq!(reg.mask, 15);
        }

        #[test]
        fn new_with_one_shard() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(1);
            assert_eq!(reg.shards.len(), 1);
            assert_eq!(reg.mask, 0);
        }

        #[test]
        fn get_or_insert_creates_then_returns_same() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(4);
            let a = reg.get_or_insert_with("x", || 42);
            let b = reg.get_or_insert_with("x", || 99);
            assert_eq!(*a, 42);
            assert_eq!(*b, 42);
        }

        #[test]
        fn remove_if_returns_false_for_absent_key() {
            let reg: ShardedRegistry<u64> = ShardedRegistry::new(4);
            assert!(!reg.remove_if("nope", |_| true));
        }

        #[test]
        fn retain_removes_matching() {
            let reg: ShardedRegistry<String> = ShardedRegistry::new(4);
            reg.get_or_insert_with("keep", || "keep".to_string());
            reg.get_or_insert_with("drop", || "drop".to_string());
            reg.retain(|_, v| v.as_str() != "drop");
            let val = reg.get_or_insert_with("keep", || unreachable!());
            assert_eq!(val.as_str(), "keep");
        }
    }

    // ── PolicySnapshot CIDR matching ─────────────────────────

    mod policy_cidr {
        use super::*;

        fn make_rule(cidr: &str, up: u64, down: u64) -> CidrRule {
            let network: IpNetwork = cidr.parse().unwrap();
            CidrRule {
                key: cidr.to_string(),
                cidr: network,
                limits: RateLimitBps {
                    up_bps: up,
                    down_bps: down,
                },
                prefix_len: network.prefix(),
            }
        }

        #[test]
        fn match_cidr_v4_hit() {
            let mut snap = PolicySnapshot::default();
            snap.cidr_rules_v4.push(make_rule("10.0.0.0/8", 100, 200));
            let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
            let rule = snap.match_cidr(ip).unwrap();
            assert_eq!(rule.limits.up_bps, 100);
        }

        #[test]
        fn match_cidr_v4_miss() {
            let mut snap = PolicySnapshot::default();
            snap.cidr_rules_v4.push(make_rule("10.0.0.0/8", 100, 200));
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert!(snap.match_cidr(ip).is_none());
        }

        #[test]
        fn match_cidr_v6_hit() {
            let mut snap = PolicySnapshot::default();
            snap.cidr_rules_v6.push(make_rule("fd00::/64", 300, 400));
            let ip = IpAddr::V6("fd00::1".parse().unwrap());
            let rule = snap.match_cidr(ip).unwrap();
            assert_eq!(rule.limits.down_bps, 400);
        }

        #[test]
        fn match_cidr_v6_miss() {
            let mut snap = PolicySnapshot::default();
            snap.cidr_rules_v6.push(make_rule("fd00::/64", 300, 400));
            let ip = IpAddr::V6("fe80::1".parse().unwrap());
            assert!(snap.match_cidr(ip).is_none());
        }

        #[test]
        fn match_cidr_prefers_longest_prefix_v4() {
            let mut snap = PolicySnapshot::default();
            snap.cidr_rules_v4.push(make_rule("10.0.0.0/8", 100, 100));
            snap.cidr_rules_v4.push(make_rule("10.0.1.0/24", 200, 200));
            snap.cidr_rules_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));

            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5));
            let rule = snap.match_cidr(ip).unwrap();
            assert_eq!(rule.limits.up_bps, 200);
        }

        #[test]
        fn match_cidr_empty_rules_returns_none() {
            let snap = PolicySnapshot::default();
            let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            assert!(snap.match_cidr(ip).is_none());
        }
    }

    // ── CidrUserDirectionState epoch tracking ────────────────

    mod cidr_user_state {
        use super::*;

        #[test]
        fn sync_epoch_sets_used_to_zero() {
            let state = CidrUserDirectionState::default();
            state.used.store(100, Ordering::Relaxed);
            let epoch = current_epoch() + 5_000_000;
            let active = AtomicU64::new(0);
            state.sync_epoch_and_mark_active(epoch, &active);
            assert_eq!(state.used.load(Ordering::Relaxed), 0);
            assert_eq!(active.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn sync_epoch_same_epoch_noop() {
            let state = CidrUserDirectionState::default();
            let epoch = current_epoch();
            let active = AtomicU64::new(5);
            state.epoch.store(epoch, Ordering::Relaxed);
            state.used.store(999, Ordering::Relaxed);
            state.sync_epoch_and_mark_active(epoch, &active);
            assert_eq!(state.used.load(Ordering::Relaxed), 999);
            assert_eq!(active.load(Ordering::Relaxed), 5);
        }

        #[test]
        fn refund_noop_on_zero() {
            let state = CidrUserDirectionState::default();
            state.used.store(100, Ordering::Relaxed);
            state.refund(0);
            assert_eq!(state.used.load(Ordering::Relaxed), 100);
        }

        #[test]
        fn refund_decrements() {
            let state = CidrUserDirectionState::default();
            state.used.store(100, Ordering::Relaxed);
            state.refund(30);
            assert_eq!(state.used.load(Ordering::Relaxed), 70);
        }

        #[test]
        fn refund_clamps_at_zero() {
            let state = CidrUserDirectionState::default();
            state.used.store(5, Ordering::Relaxed);
            state.refund(100);
            assert_eq!(state.used.load(Ordering::Relaxed), 0);
        }
    }

    // ── ScopeMetrics direction isolation ─────────────────────

    mod scope_metrics {
        use super::*;

        #[test]
        fn throttle_up_only_increments_up() {
            let m = ScopeMetrics::default();
            m.throttle(RateDirection::Up);
            assert_eq!(m.throttle_up_total.load(Ordering::Relaxed), 1);
            assert_eq!(m.throttle_down_total.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn throttle_down_only_increments_down() {
            let m = ScopeMetrics::default();
            m.throttle(RateDirection::Down);
            assert_eq!(m.throttle_up_total.load(Ordering::Relaxed), 0);
            assert_eq!(m.throttle_down_total.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn wait_ms_up_accumulates() {
            let m = ScopeMetrics::default();
            m.wait_ms(RateDirection::Up, 10);
            m.wait_ms(RateDirection::Up, 20);
            assert_eq!(m.wait_up_ms_total.load(Ordering::Relaxed), 30);
            assert_eq!(m.wait_down_ms_total.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn wait_ms_down_accumulates() {
            let m = ScopeMetrics::default();
            m.wait_ms(RateDirection::Down, 5);
            assert_eq!(m.wait_down_ms_total.load(Ordering::Relaxed), 5);
            assert_eq!(m.wait_up_ms_total.load(Ordering::Relaxed), 0);
        }
    }

    // ── Edge cases: saturating arithmetic ────────────────────

    mod edge_cases {
        use super::*;

        #[test]
        fn decrement_saturating_at_u64_max() {
            let c = AtomicU64::new(u64::MAX);
            decrement_atomic_saturating(&c, 1);
            assert_eq!(c.load(Ordering::Relaxed), u64::MAX - 1);
        }

        #[test]
        fn decrement_saturating_overflow_by_sub() {
            let c = AtomicU64::new(1);
            decrement_atomic_saturating(&c, u64::MAX);
            assert_eq!(c.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn bytes_per_epoch_large_bps_does_not_panic() {
            let _ = bytes_per_epoch(u64::MAX / 2);
        }

        #[test]
        fn direction_bucket_consume_then_full_refund() {
            let bucket = DirectionBucket::default();
            let cap_bps = 8_000_000;
            let cap_epoch = bytes_per_epoch(cap_bps);
            let g = bucket.try_consume(cap_bps, cap_epoch);
            assert_eq!(g, cap_epoch);
            bucket.refund(g);
            let g2 = bucket.try_consume(cap_bps, cap_epoch);
            assert_eq!(g2, cap_epoch);
        }
    }

}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn try_consume_never_exceeds_cap(
            cap_bps in 1_000u64..100_000_000u64,
            request in 1u64..500_000u64,
        ) {
            let bucket = DirectionBucket::default();
            let cap_epoch = bytes_per_epoch(cap_bps);
            let mut total_granted = 0u64;
            for _ in 0..100 {
                let g = bucket.try_consume(cap_bps, request);
                total_granted += g;
                if g == 0 {
                    break;
                }
            }
            assert!(
                total_granted <= cap_epoch,
                "total_granted {} exceeded cap_epoch {}",
                total_granted,
                cap_epoch
            );
        }

        #[test]
        fn refund_clamps_to_cap(
            cap_bps in 1_000u64..100_000_000u64,
            refund_amount in 1u64..10_000_000u64,
        ) {
            let bucket = DirectionBucket::default();
            let cap_epoch = bytes_per_epoch(cap_bps);
            bucket.refund(refund_amount);
            let granted = bucket.try_consume(cap_bps, cap_epoch.saturating_add(1));
            assert!(
                granted <= cap_epoch,
                "granted {} exceeded cap_epoch {} after refund",
                granted,
                cap_epoch
            );
        }

        #[test]
        fn bytes_per_epoch_never_zero_for_nonzero_bps(bps in 1u64..u64::MAX) {
            let result = bytes_per_epoch(bps);
            assert!(result > 0, "bytes_per_epoch({}) returned 0", bps);
        }
    }
}
