use super::*;

impl UserIpTracker {
    pub async fn set_limit_policy(&self, mode: UserMaxUniqueIpsMode, window_secs: u64) {
        self.limit_policy.rcu(|current| {
            Arc::new(UserIpLimitPolicy {
                mode,
                window_secs: window_secs.max(1),
                ..(**current).clone()
            })
        });
    }

    pub async fn set_user_limit(&self, username: &str, max_ips: usize) {
        let username = username.to_string();
        self.limit_policy.rcu(|current| {
            let mut limits = current.max_ips.as_ref().clone();
            limits.insert(username.clone(), max_ips);
            Arc::new(UserIpLimitPolicy {
                max_ips: Arc::new(limits),
                ..(**current).clone()
            })
        });
    }

    pub async fn remove_user_limit(&self, username: &str) {
        self.limit_policy.rcu(|current| {
            let mut limits = current.max_ips.as_ref().clone();
            limits.remove(username);
            Arc::new(UserIpLimitPolicy {
                max_ips: Arc::new(limits),
                ..(**current).clone()
            })
        });
    }

    pub async fn load_limits(&self, default_limit: usize, limits: &HashMap<String, usize>) {
        let limits = Arc::new(limits.clone());
        self.limit_policy.rcu(|current| {
            Arc::new(UserIpLimitPolicy {
                max_ips: Arc::clone(&limits),
                default_max_ips: default_limit,
                ..(**current).clone()
            })
        });
    }

    pub(super) fn prune_recent(
        user_recent: &mut HashMap<IpAddr, Instant>,
        now: Instant,
        window: Duration,
    ) -> usize {
        if user_recent.is_empty() {
            return 0;
        }
        let before = user_recent.len();
        user_recent.retain(|_, seen_at| now.duration_since(*seen_at) <= window);
        before.saturating_sub(user_recent.len())
    }

    pub async fn check_and_add(&self, username: &str, ip: IpAddr) -> Result<(), String> {
        self.drain_cleanup_for_user(username).await;
        self.maybe_compact_empty_users().await;
        let policy = self.limit_policy.load();
        let limit = Self::user_limit(&policy, username);
        let mode = policy.mode;
        let window = Self::limit_window(&policy);
        let now = Instant::now();

        let shard_idx = Self::shard_idx(username);
        let mut shard = self.shards[shard_idx].write().await;
        let user_active = shard.active_ips.entry(username.to_string()).or_default();
        let active_contains_ip = user_active.contains_key(&ip);
        let active_len = user_active.len();
        let user_recent = shard.recent_ips.entry(username.to_string()).or_default();
        let pruned_recent_entries = Self::prune_recent(user_recent, now, window);
        Self::decrement_counter(&self.recent_entry_count, pruned_recent_entries);
        let recent_contains_ip = user_recent.contains_key(&ip);
        let recent_len = user_recent.len();

        if active_contains_ip {
            if !recent_contains_ip
                && !Self::try_increment_counter(&self.recent_entry_count, MAX_RECENT_IP_ENTRIES)
            {
                self.recent_cap_rejects.fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "IP tracker recent entry cap reached: entries={}/{}",
                    self.recent_entry_count.load(Ordering::Relaxed),
                    MAX_RECENT_IP_ENTRIES
                ));
            }
            let Some(count) = shard
                .active_ips
                .get_mut(username)
                .and_then(|user_active| user_active.get_mut(&ip))
            else {
                return Err(format!(
                    "IP tracker active entry unavailable for user '{username}'"
                ));
            };
            *count = count.saturating_add(1);
            if let Some(user_recent) = shard.recent_ips.get_mut(username) {
                user_recent.insert(ip, now);
            }
            return Ok(());
        }

        let is_new_ip = !recent_contains_ip;

        if let Some(limit) = limit {
            let active_limit_reached = active_len >= limit;
            let recent_limit_reached = recent_len >= limit && is_new_ip;
            let deny = match mode {
                UserMaxUniqueIpsMode::ActiveWindow => active_limit_reached,
                UserMaxUniqueIpsMode::TimeWindow => recent_limit_reached,
                UserMaxUniqueIpsMode::Combined => active_limit_reached || recent_limit_reached,
            };

            if deny {
                return Err(format!(
                    "IP limit reached for user '{}': active={}/{} recent={}/{} mode={:?}",
                    username, active_len, limit, recent_len, limit, mode
                ));
            }
        }

        if !Self::try_increment_counter(&self.active_entry_count, MAX_ACTIVE_IP_ENTRIES) {
            self.active_cap_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "IP tracker active entry cap reached: entries={}/{}",
                self.active_entry_count.load(Ordering::Relaxed),
                MAX_ACTIVE_IP_ENTRIES
            ));
        }
        let mut reserved_recent = false;
        if is_new_ip {
            if !Self::try_increment_counter(&self.recent_entry_count, MAX_RECENT_IP_ENTRIES) {
                Self::decrement_counter(&self.active_entry_count, 1);
                self.recent_cap_rejects.fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "IP tracker recent entry cap reached: entries={}/{}",
                    self.recent_entry_count.load(Ordering::Relaxed),
                    MAX_RECENT_IP_ENTRIES
                ));
            }
            reserved_recent = true;
        }

        let Some(user_active) = shard.active_ips.get_mut(username) else {
            Self::decrement_counter(&self.active_entry_count, 1);
            if reserved_recent {
                Self::decrement_counter(&self.recent_entry_count, 1);
            }
            return Err(format!(
                "IP tracker active entry unavailable for user '{username}'"
            ));
        };
        if user_active.insert(ip, 1).is_some() {
            Self::decrement_counter(&self.active_entry_count, 1);
        }
        let Some(user_recent) = shard.recent_ips.get_mut(username) else {
            Self::decrement_counter(&self.active_entry_count, 1);
            if reserved_recent {
                Self::decrement_counter(&self.recent_entry_count, 1);
            }
            return Err(format!(
                "IP tracker recent entry unavailable for user '{username}'"
            ));
        };
        if user_recent.insert(ip, now).is_some() && reserved_recent {
            Self::decrement_counter(&self.recent_entry_count, 1);
        }
        Ok(())
    }

    pub async fn remove_ip(&self, username: &str, ip: IpAddr) {
        self.maybe_compact_empty_users().await;
        let shard_idx = Self::shard_idx(username);
        let mut shard = self.shards[shard_idx].write().await;
        let mut removed_active_entries = 0usize;
        if let Some(user_ips) = shard.active_ips.get_mut(username) {
            if let Some(count) = user_ips.get_mut(&ip) {
                if *count > 1 {
                    *count -= 1;
                } else if user_ips.remove(&ip).is_some() {
                    removed_active_entries = 1;
                }
            }
            if user_ips.is_empty() {
                shard.active_ips.remove(username);
            }
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
    }
}
