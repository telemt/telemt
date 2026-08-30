use crate::config::CidrRateLimitKey;

use super::*;
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
            let bucket = self.user_buckets.get_or_insert_with(
                user,
                || UserBucket::new(limit),
                |bucket| {
                    bucket.active_leases.fetch_add(1, Ordering::Relaxed);
                },
            );
            bucket.set_rates(limit);
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
            let bucket = self.cidr_buckets.get_or_insert_with(
                key,
                || CidrBucket::new(limits),
                |bucket| {
                    bucket.active_leases.fetch_add(1, Ordering::Relaxed);
                },
            );
            bucket.set_rates(limits);
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

    pub(super) fn observe_throttle(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
    ) {
        if blocked_user {
            self.user_scope.throttle(direction);
        }
        if blocked_cidr {
            self.cidr_scope.throttle(direction);
        }
    }

    pub(super) fn observe_wait(
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

    pub(super) fn maybe_cleanup(&self) {
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
