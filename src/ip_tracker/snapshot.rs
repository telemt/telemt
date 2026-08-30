use super::*;

impl UserIpTracker {
    pub(super) async fn maybe_compact_empty_users(&self) {
        const COMPACT_INTERVAL_SECS: u64 = 60;
        let now_epoch_secs = Self::now_epoch_secs();
        let last_compact_epoch_secs = self.last_compact_epoch_secs.load(Ordering::Relaxed);
        if now_epoch_secs.saturating_sub(last_compact_epoch_secs) < COMPACT_INTERVAL_SECS {
            return;
        }
        if self
            .last_compact_epoch_secs
            .compare_exchange(
                last_compact_epoch_secs,
                now_epoch_secs,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let policy = self.limit_policy.load();
        let window = Self::limit_window(&policy);
        let now = Instant::now();
        for shard_lock in self.shards.iter() {
            let mut shard = shard_lock.write().await;
            let mut pruned_recent_entries = 0usize;
            for user_recent in shard.recent_ips.values_mut() {
                pruned_recent_entries = pruned_recent_entries.saturating_add(Self::prune_recent(
                    user_recent,
                    now,
                    window,
                ));
            }
            Self::decrement_counter(&self.recent_entry_count, pruned_recent_entries);

            let mut users = Vec::<String>::with_capacity(
                shard
                    .active_ips
                    .len()
                    .saturating_add(shard.recent_ips.len()),
            );
            users.extend(shard.active_ips.keys().cloned());
            for user in shard.recent_ips.keys() {
                if !shard.active_ips.contains_key(user) {
                    users.push(user.clone());
                }
            }

            for user in users {
                let active_empty = shard
                    .active_ips
                    .get(&user)
                    .map(|ips| ips.is_empty())
                    .unwrap_or(true);
                let recent_empty = shard
                    .recent_ips
                    .get(&user)
                    .map(|ips| ips.is_empty())
                    .unwrap_or(true);
                if active_empty && recent_empty {
                    shard.active_ips.remove(&user);
                    shard.recent_ips.remove(&user);
                }
            }
        }
    }

    pub async fn run_periodic_maintenance(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            self.drain_cleanup_queue().await;
            self.maybe_compact_empty_users().await;
        }
    }

    pub async fn memory_stats(&self) -> UserIpTrackerMemoryStats {
        let cleanup_queue_len = self.cleanup_queue_len.load(Ordering::Relaxed) as usize;
        let mut active_users = 0usize;
        let mut recent_users = 0usize;
        let mut active_entries = 0usize;
        let mut recent_entries = 0usize;
        for shard_lock in self.shards.iter() {
            let shard = shard_lock.read().await;
            active_users = active_users.saturating_add(shard.active_ips.len());
            recent_users = recent_users.saturating_add(shard.recent_ips.len());
            active_entries =
                active_entries.saturating_add(shard.active_ips.values().map(HashMap::len).sum());
            recent_entries =
                recent_entries.saturating_add(shard.recent_ips.values().map(HashMap::len).sum());
        }

        UserIpTrackerMemoryStats {
            active_users,
            recent_users,
            active_entries,
            recent_entries,
            cleanup_queue_len,
            active_cap_rejects: self.active_cap_rejects.load(Ordering::Relaxed),
            recent_cap_rejects: self.recent_cap_rejects.load(Ordering::Relaxed),
            cleanup_deferred_releases: self.cleanup_deferred_releases.load(Ordering::Relaxed),
        }
    }

    pub async fn get_recent_counts_for_users(&self, users: &[String]) -> HashMap<String, usize> {
        self.drain_cleanup_queue().await;
        self.get_recent_counts_for_users_snapshot(users).await
    }

    pub(crate) async fn get_recent_counts_for_users_snapshot(
        &self,
        users: &[String],
    ) -> HashMap<String, usize> {
        let policy = self.limit_policy.load();
        let window = Self::limit_window(&policy);
        let now = Instant::now();

        let mut counts = HashMap::with_capacity(users.len());
        for user in users {
            let shard_idx = Self::shard_idx(user);
            let shard = self.shards[shard_idx].read().await;
            let count = if let Some(user_recent) = shard.recent_ips.get(user) {
                user_recent
                    .values()
                    .filter(|seen_at| now.duration_since(**seen_at) <= window)
                    .count()
            } else {
                0
            };
            counts.insert(user.clone(), count);
        }
        counts
    }

    pub async fn get_active_ips_for_users(&self, users: &[String]) -> HashMap<String, Vec<IpAddr>> {
        self.drain_cleanup_queue().await;
        let mut out = HashMap::with_capacity(users.len());
        for user in users {
            let shard_idx = Self::shard_idx(user);
            let shard = self.shards[shard_idx].read().await;
            let mut ips = shard
                .active_ips
                .get(user)
                .map(|per_ip| per_ip.keys().copied().collect::<Vec<_>>())
                .unwrap_or_else(Vec::new);
            ips.sort();
            out.insert(user.clone(), ips);
        }
        out
    }

    pub async fn get_recent_ips_for_users(&self, users: &[String]) -> HashMap<String, Vec<IpAddr>> {
        self.drain_cleanup_queue().await;
        let policy = self.limit_policy.load();
        let window = Self::limit_window(&policy);
        let now = Instant::now();

        let mut out = HashMap::with_capacity(users.len());
        for user in users {
            let shard_idx = Self::shard_idx(user);
            let shard = self.shards[shard_idx].read().await;
            let mut ips = if let Some(user_recent) = shard.recent_ips.get(user) {
                user_recent
                    .iter()
                    .filter(|(_, seen_at)| now.duration_since(**seen_at) <= window)
                    .map(|(ip, _)| *ip)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            ips.sort();
            out.insert(user.clone(), ips);
        }
        out
    }

    pub async fn get_active_ip_count(&self, username: &str) -> usize {
        self.drain_cleanup_queue().await;
        let shard_idx = Self::shard_idx(username);
        let shard = self.shards[shard_idx].read().await;
        shard
            .active_ips
            .get(username)
            .map(|ips| ips.len())
            .unwrap_or(0)
    }

    pub async fn get_active_ips(&self, username: &str) -> Vec<IpAddr> {
        self.drain_cleanup_queue().await;
        let shard_idx = Self::shard_idx(username);
        let shard = self.shards[shard_idx].read().await;
        shard
            .active_ips
            .get(username)
            .map(|ips| ips.keys().copied().collect())
            .unwrap_or_else(Vec::new)
    }

    pub async fn get_stats(&self) -> Vec<(String, usize, usize)> {
        self.drain_cleanup_queue().await;
        self.get_stats_snapshot().await
    }

    pub(crate) async fn get_stats_snapshot(&self) -> Vec<(String, usize, usize)> {
        let policy = self.limit_policy.load();
        let mut active_counts = Vec::new();
        for shard_lock in self.shards.iter() {
            let shard = shard_lock.read().await;
            active_counts.extend(
                shard
                    .active_ips
                    .iter()
                    .map(|(username, user_ips)| (username.clone(), user_ips.len())),
            );
        }

        let mut stats = Vec::with_capacity(active_counts.len());
        for (username, active_count) in active_counts {
            let limit = Self::user_limit(&policy, &username).unwrap_or(0);
            stats.push((username, active_count, limit));
        }

        stats.sort_by(|a, b| a.0.cmp(&b.0));
        stats
    }

    pub async fn clear_user_ips(&self, username: &str) {
        let shard_idx = Self::shard_idx(username);
        let mut shard = self.shards[shard_idx].write().await;
        let removed_active_entries = shard
            .active_ips
            .remove(username)
            .map(|ips| ips.len())
            .unwrap_or(0);
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);

        let removed_recent_entries = shard
            .recent_ips
            .remove(username)
            .map(|ips| ips.len())
            .unwrap_or(0);
        Self::decrement_counter(&self.recent_entry_count, removed_recent_entries);
    }

    pub async fn clear_all(&self) {
        for shard_lock in self.shards.iter() {
            let mut shard = shard_lock.write().await;
            shard.active_ips.clear();
            shard.recent_ips.clear();
        }
        self.active_entry_count.store(0, Ordering::Relaxed);
        self.recent_entry_count.store(0, Ordering::Relaxed);
        for cleanup_shard in self.cleanup_shards.iter() {
            match cleanup_shard.queue.lock() {
                Ok(mut queue) => queue.clear(),
                Err(poisoned) => {
                    poisoned.into_inner().clear();
                    cleanup_shard.queue.clear_poison();
                }
            }
        }
        self.cleanup_queue_len.store(0, Ordering::Relaxed);
    }

    pub async fn is_ip_active(&self, username: &str, ip: IpAddr) -> bool {
        self.drain_cleanup_queue().await;
        let shard_idx = Self::shard_idx(username);
        let shard = self.shards[shard_idx].read().await;
        shard
            .active_ips
            .get(username)
            .map(|ips| ips.contains_key(&ip))
            .unwrap_or(false)
    }

    pub async fn get_user_limit(&self, username: &str) -> Option<usize> {
        let policy = self.limit_policy.load();
        Self::user_limit(&policy, username)
    }

    pub async fn format_stats(&self) -> String {
        let stats = self.get_stats().await;

        if stats.is_empty() {
            return String::from("No active users");
        }

        let mut output = String::from("User IP Statistics:\n");
        output.push_str("==================\n");

        for (username, active_count, limit) in stats {
            output.push_str(&format!(
                "User: {:<20} Active IPs: {}/{}\n",
                username,
                active_count,
                if limit > 0 {
                    limit.to_string()
                } else {
                    "unlimited".to_string()
                }
            ));

            let ips = self.get_active_ips(&username).await;
            for ip in ips {
                output.push_str(&format!("  - {}\n", ip));
            }
        }

        output
    }
}
