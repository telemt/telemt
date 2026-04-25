// IP address tracking and per-user unique IP limiting.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, RwLock};

use crate::config::UserMaxUniqueIpsMode;

#[derive(Debug, Clone)]
pub struct UserIpTracker {
    active_ips: Arc<RwLock<HashMap<String, HashMap<IpAddr, usize>>>>,
    recent_ips: Arc<RwLock<HashMap<String, HashMap<IpAddr, Instant>>>>,
    max_ips: Arc<RwLock<HashMap<String, usize>>>,
    default_max_ips: Arc<RwLock<usize>>,
    limit_mode: Arc<RwLock<UserMaxUniqueIpsMode>>,
    limit_window: Arc<RwLock<Duration>>,
    last_compact_epoch_secs: Arc<AtomicU64>,
    cleanup_queue: Arc<Mutex<HashMap<(String, IpAddr), usize>>>,
    cleanup_drain_lock: Arc<AsyncMutex<()>>,
}

#[derive(Debug, Clone, Copy)]
pub struct UserIpTrackerMemoryStats {
    pub active_users: usize,
    pub recent_users: usize,
    pub active_entries: usize,
    pub recent_entries: usize,
    pub cleanup_queue_len: usize,
}

impl UserIpTracker {
    pub fn new() -> Self {
        Self {
            active_ips: Arc::new(RwLock::new(HashMap::new())),
            recent_ips: Arc::new(RwLock::new(HashMap::new())),
            max_ips: Arc::new(RwLock::new(HashMap::new())),
            default_max_ips: Arc::new(RwLock::new(0)),
            limit_mode: Arc::new(RwLock::new(UserMaxUniqueIpsMode::ActiveWindow)),
            limit_window: Arc::new(RwLock::new(Duration::from_secs(30))),
            last_compact_epoch_secs: Arc::new(AtomicU64::new(0)),
            cleanup_queue: Arc::new(Mutex::new(HashMap::new())),
            cleanup_drain_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn enqueue_cleanup(&self, user: String, ip: IpAddr) {
        match self.cleanup_queue.lock() {
            Ok(mut queue) => {
                let count = queue.entry((user, ip)).or_insert(0);
                *count = count.saturating_add(1);
            }
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                let count = queue.entry((user.clone(), ip)).or_insert(0);
                *count = count.saturating_add(1);
                self.cleanup_queue.clear_poison();
                tracing::warn!(
                    "UserIpTracker cleanup_queue lock poisoned; recovered and enqueued IP cleanup for {} ({})",
                    user,
                    ip
                );
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_len_for_tests(&self) -> usize {
        self.cleanup_queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_mutex_for_tests(
        &self,
    ) -> Arc<Mutex<HashMap<(String, IpAddr), usize>>> {
        Arc::clone(&self.cleanup_queue)
    }

    pub(crate) async fn drain_cleanup_queue(&self) {
        // Serialize queue draining and active-IP mutation so check-and-add cannot
        // observe stale active entries that are already queued for removal.
        let _drain_guard = self.cleanup_drain_lock.lock().await;
        let to_remove = {
            match self.cleanup_queue.lock() {
                Ok(mut queue) => {
                    if queue.is_empty() {
                        return;
                    }
                    std::mem::take(&mut *queue)
                }
                Err(poisoned) => {
                    let mut queue = poisoned.into_inner();
                    if queue.is_empty() {
                        self.cleanup_queue.clear_poison();
                        return;
                    }
                    let drained = std::mem::take(&mut *queue);
                    self.cleanup_queue.clear_poison();
                    drained
                }
            }
        };

        let mut active_ips = self.active_ips.write().await;
        for ((user, ip), pending_count) in to_remove {
            if pending_count == 0 {
                continue;
            }
            if let Some(user_ips) = active_ips.get_mut(&user) {
                if let Some(count) = user_ips.get_mut(&ip) {
                    if *count > pending_count {
                        *count -= pending_count;
                    } else {
                        user_ips.remove(&ip);
                    }
                }
                if user_ips.is_empty() {
                    active_ips.remove(&user);
                }
            }
        }
    }

    fn now_epoch_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    async fn maybe_compact_empty_users(&self) {
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

        let mut active_ips = self.active_ips.write().await;
        let mut recent_ips = self.recent_ips.write().await;
        let window = *self.limit_window.read().await;
        let now = Instant::now();

        for user_recent in recent_ips.values_mut() {
            Self::prune_recent(user_recent, now, window);
        }

        let mut users =
            Vec::<String>::with_capacity(active_ips.len().saturating_add(recent_ips.len()));
        users.extend(active_ips.keys().cloned());
        for user in recent_ips.keys() {
            if !active_ips.contains_key(user) {
                users.push(user.clone());
            }
        }

        for user in users {
            let active_empty = active_ips
                .get(&user)
                .map(|ips| ips.is_empty())
                .unwrap_or(true);
            let recent_empty = recent_ips
                .get(&user)
                .map(|ips| ips.is_empty())
                .unwrap_or(true);
            if active_empty && recent_empty {
                active_ips.remove(&user);
                recent_ips.remove(&user);
            }
        }
    }

    pub async fn memory_stats(&self) -> UserIpTrackerMemoryStats {
        let cleanup_queue_len = self
            .cleanup_queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        let active_ips = self.active_ips.read().await;
        let recent_ips = self.recent_ips.read().await;
        let active_entries = active_ips.values().map(HashMap::len).sum();
        let recent_entries = recent_ips.values().map(HashMap::len).sum();

        UserIpTrackerMemoryStats {
            active_users: active_ips.len(),
            recent_users: recent_ips.len(),
            active_entries,
            recent_entries,
            cleanup_queue_len,
        }
    }

    pub async fn set_limit_policy(&self, mode: UserMaxUniqueIpsMode, window_secs: u64) {
        {
            let mut current_mode = self.limit_mode.write().await;
            *current_mode = mode;
        }
        let mut current_window = self.limit_window.write().await;
        *current_window = Duration::from_secs(window_secs.max(1));
    }

    pub async fn set_user_limit(&self, username: &str, max_ips: usize) {
        let mut limits = self.max_ips.write().await;
        limits.insert(username.to_string(), max_ips);
    }

    pub async fn remove_user_limit(&self, username: &str) {
        let mut limits = self.max_ips.write().await;
        limits.remove(username);
    }

    pub async fn load_limits(&self, default_limit: usize, limits: &HashMap<String, usize>) {
        let mut default_max_ips = self.default_max_ips.write().await;
        *default_max_ips = default_limit;
        drop(default_max_ips);
        let mut max_ips = self.max_ips.write().await;
        max_ips.clone_from(limits);
    }

    fn prune_recent(user_recent: &mut HashMap<IpAddr, Instant>, now: Instant, window: Duration) {
        if user_recent.is_empty() {
            return;
        }
        user_recent.retain(|_, seen_at| now.duration_since(*seen_at) <= window);
    }

    pub async fn check_and_add(&self, username: &str, ip: IpAddr) -> Result<(), String> {
        self.drain_cleanup_queue().await;
        self.maybe_compact_empty_users().await;
        let default_max_ips = *self.default_max_ips.read().await;
        let limit = {
            let max_ips = self.max_ips.read().await;
            max_ips
                .get(username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((default_max_ips > 0).then_some(default_max_ips))
        };
        let mode = *self.limit_mode.read().await;
        let window = *self.limit_window.read().await;
        let now = Instant::now();

        let mut active_ips = self.active_ips.write().await;
        let user_active = active_ips
            .entry(username.to_string())
            .or_insert_with(HashMap::new);

        let mut recent_ips = self.recent_ips.write().await;
        let user_recent = recent_ips
            .entry(username.to_string())
            .or_insert_with(HashMap::new);
        Self::prune_recent(user_recent, now, window);

        if let Some(count) = user_active.get_mut(&ip) {
            *count = count.saturating_add(1);
            user_recent.insert(ip, now);
            return Ok(());
        }

        if let Some(limit) = limit {
            let active_limit_reached = user_active.len() >= limit;
            let recent_limit_reached = user_recent.len() >= limit;
            let deny = match mode {
                UserMaxUniqueIpsMode::ActiveWindow => active_limit_reached,
                UserMaxUniqueIpsMode::TimeWindow => recent_limit_reached,
                UserMaxUniqueIpsMode::Combined => active_limit_reached || recent_limit_reached,
            };

            if deny {
                return Err(format!(
                    "IP limit reached for user '{}': active={}/{} recent={}/{} mode={:?}",
                    username,
                    user_active.len(),
                    limit,
                    user_recent.len(),
                    limit,
                    mode
                ));
            }
        }

        user_active.insert(ip, 1);
        user_recent.insert(ip, now);
        Ok(())
    }

    pub async fn remove_ip(&self, username: &str, ip: IpAddr) {
        self.maybe_compact_empty_users().await;
        let mut active_ips = self.active_ips.write().await;
        if let Some(user_ips) = active_ips.get_mut(username) {
            if let Some(count) = user_ips.get_mut(&ip) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    user_ips.remove(&ip);
                }
            }
            if user_ips.is_empty() {
                active_ips.remove(username);
            }
        }
    }

    pub async fn get_recent_counts_for_users(&self, users: &[String]) -> HashMap<String, usize> {
        self.drain_cleanup_queue().await;
        let window = *self.limit_window.read().await;
        let now = Instant::now();
        let recent_ips = self.recent_ips.read().await;

        let mut counts = HashMap::with_capacity(users.len());
        for user in users {
            let count = if let Some(user_recent) = recent_ips.get(user) {
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
        let active_ips = self.active_ips.read().await;
        let mut out = HashMap::with_capacity(users.len());
        for user in users {
            let mut ips = active_ips
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
        let window = *self.limit_window.read().await;
        let now = Instant::now();
        let recent_ips = self.recent_ips.read().await;

        let mut out = HashMap::with_capacity(users.len());
        for user in users {
            let mut ips = if let Some(user_recent) = recent_ips.get(user) {
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
        let active_ips = self.active_ips.read().await;
        active_ips.get(username).map(|ips| ips.len()).unwrap_or(0)
    }

    pub async fn get_active_ips(&self, username: &str) -> Vec<IpAddr> {
        self.drain_cleanup_queue().await;
        let active_ips = self.active_ips.read().await;
        active_ips
            .get(username)
            .map(|ips| ips.keys().copied().collect())
            .unwrap_or_else(Vec::new)
    }

    pub async fn get_stats(&self) -> Vec<(String, usize, usize)> {
        self.drain_cleanup_queue().await;
        let active_ips = self.active_ips.read().await;
        let max_ips = self.max_ips.read().await;
        let default_max_ips = *self.default_max_ips.read().await;

        let mut stats = Vec::new();
        for (username, user_ips) in active_ips.iter() {
            let limit = max_ips
                .get(username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((default_max_ips > 0).then_some(default_max_ips))
                .unwrap_or(0);
            stats.push((username.clone(), user_ips.len(), limit));
        }

        stats.sort_by(|a, b| a.0.cmp(&b.0));
        stats
    }

    pub async fn clear_user_ips(&self, username: &str) {
        let mut active_ips = self.active_ips.write().await;
        active_ips.remove(username);
        drop(active_ips);

        let mut recent_ips = self.recent_ips.write().await;
        recent_ips.remove(username);
    }

    pub async fn clear_all(&self) {
        let mut active_ips = self.active_ips.write().await;
        active_ips.clear();
        drop(active_ips);

        let mut recent_ips = self.recent_ips.write().await;
        recent_ips.clear();
    }

    pub async fn is_ip_active(&self, username: &str, ip: IpAddr) -> bool {
        self.drain_cleanup_queue().await;
        let active_ips = self.active_ips.read().await;
        active_ips
            .get(username)
            .map(|ips| ips.contains_key(&ip))
            .unwrap_or(false)
    }

    pub async fn get_user_limit(&self, username: &str) -> Option<usize> {
        let default_max_ips = *self.default_max_ips.read().await;
        let max_ips = self.max_ips.read().await;
        max_ips
            .get(username)
            .copied()
            .filter(|limit| *limit > 0)
            .or((default_max_ips > 0).then_some(default_max_ips))
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

impl Default for UserIpTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::Ordering;

    fn test_ipv4(oct1: u8, oct2: u8, oct3: u8, oct4: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(oct1, oct2, oct3, oct4))
    }

    fn test_ipv6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    }

    #[tokio::test]
    async fn test_basic_ip_limit() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());

        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_active_window_rejects_new_ip_and_keeps_existing_session() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::ActiveWindow, 30)
            .await;

        let ip1 = test_ipv4(10, 10, 10, 1);
        let ip2 = test_ipv4(10, 10, 10, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());

        // Existing session remains active; only new unique IP is denied.
        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
    }

    #[tokio::test]
    async fn test_reconnection_from_same_ip() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
    }

    #[tokio::test]
    async fn test_same_ip_disconnect_keeps_active_while_other_session_alive() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

        tracker.remove_ip("test_user", ip1).await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

        tracker.remove_ip("test_user", ip1).await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
    }

    #[tokio::test]
    async fn test_ip_removal() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());

        tracker.remove_ip("test_user", ip1).await;

        assert!(tracker.check_and_add("test_user", ip3).await.is_ok());
        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_no_limit() {
        let tracker = UserIpTracker::new();

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_ok());

        assert_eq!(tracker.get_active_ip_count("test_user").await, 3);
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("user1", 2).await;
        tracker.set_user_limit("user2", 1).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        assert!(tracker.check_and_add("user1", ip1).await.is_ok());
        assert!(tracker.check_and_add("user1", ip2).await.is_ok());

        assert!(tracker.check_and_add("user2", ip1).await.is_ok());
        assert!(tracker.check_and_add("user2", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_ipv6_support() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ipv4 = test_ipv4(192, 168, 1, 1);
        let ipv6 = test_ipv6();

        assert!(tracker.check_and_add("test_user", ipv4).await.is_ok());
        assert!(tracker.check_and_add("test_user", ipv6).await.is_ok());

        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_get_active_ips() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 3).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        tracker.check_and_add("test_user", ip2).await.unwrap();

        let active_ips = tracker.get_active_ips("test_user").await;
        assert_eq!(active_ips.len(), 2);
        assert!(active_ips.contains(&ip1));
        assert!(active_ips.contains(&ip2));
    }

    #[tokio::test]
    async fn test_stats() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("user1", 3).await;
        tracker.set_user_limit("user2", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("user1", ip1).await.unwrap();
        tracker.check_and_add("user2", ip2).await.unwrap();

        let stats = tracker.get_stats().await;
        assert_eq!(stats.len(), 2);

        assert!(stats.iter().any(|(name, _, _)| name == "user1"));
        assert!(stats.iter().any(|(name, _, _)| name == "user2"));
    }

    #[tokio::test]
    async fn test_clear_user_ips() {
        let tracker = UserIpTracker::new();
        let ip1 = test_ipv4(192, 168, 1, 1);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

        tracker.clear_user_ips("test_user").await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
    }

    #[tokio::test]
    async fn test_is_ip_active() {
        let tracker = UserIpTracker::new();
        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();

        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert!(!tracker.is_ip_active("test_user", ip2).await);
    }

    #[tokio::test]
    async fn test_load_limits_from_config() {
        let tracker = UserIpTracker::new();

        let mut config_limits = HashMap::new();
        config_limits.insert("user1".to_string(), 5);
        config_limits.insert("user2".to_string(), 3);

        tracker.load_limits(0, &config_limits).await;

        assert_eq!(tracker.get_user_limit("user1").await, Some(5));
        assert_eq!(tracker.get_user_limit("user2").await, Some(3));
        assert_eq!(tracker.get_user_limit("user3").await, None);
    }

    #[tokio::test]
    async fn test_load_limits_replaces_previous_map() {
        let tracker = UserIpTracker::new();

        let mut first = HashMap::new();
        first.insert("user1".to_string(), 2);
        first.insert("user2".to_string(), 3);
        tracker.load_limits(0, &first).await;

        let mut second = HashMap::new();
        second.insert("user2".to_string(), 5);
        tracker.load_limits(0, &second).await;

        assert_eq!(tracker.get_user_limit("user1").await, None);
        assert_eq!(tracker.get_user_limit("user2").await, Some(5));
    }

    #[tokio::test]
    async fn test_global_each_limit_applies_without_user_override() {
        let tracker = UserIpTracker::new();
        tracker.load_limits(2, &HashMap::new()).await;

        let ip1 = test_ipv4(172, 16, 0, 1);
        let ip2 = test_ipv4(172, 16, 0, 2);
        let ip3 = test_ipv4(172, 16, 0, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());
        assert_eq!(tracker.get_user_limit("test_user").await, Some(2));
    }

    #[tokio::test]
    async fn test_user_override_wins_over_global_each_limit() {
        let tracker = UserIpTracker::new();
        let mut limits = HashMap::new();
        limits.insert("test_user".to_string(), 1);
        tracker.load_limits(3, &limits).await;

        let ip1 = test_ipv4(172, 17, 0, 1);
        let ip2 = test_ipv4(172, 17, 0, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());
        assert_eq!(tracker.get_user_limit("test_user").await, Some(1));
    }

    #[tokio::test]
    async fn test_time_window_mode_blocks_recent_ip_churn() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 30)
            .await;

        let ip1 = test_ipv4(10, 0, 0, 1);
        let ip2 = test_ipv4(10, 0, 0, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_combined_mode_enforces_active_and_recent_limits() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::Combined, 30)
            .await;

        let ip1 = test_ipv4(10, 0, 1, 1);
        let ip2 = test_ipv4(10, 0, 1, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());

        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_time_window_expires() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
            .await;

        let ip1 = test_ipv4(10, 1, 0, 1);
        let ip2 = test_ipv4(10, 1, 0, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
    }

    #[tokio::test]
    async fn test_memory_stats_reports_queue_and_entry_counts() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 4).await;
        let ip1 = test_ipv4(10, 2, 0, 1);
        let ip2 = test_ipv4(10, 2, 0, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        tracker.check_and_add("test_user", ip2).await.unwrap();
        tracker.enqueue_cleanup("test_user".to_string(), ip1);

        let snapshot = tracker.memory_stats().await;
        assert_eq!(snapshot.active_users, 1);
        assert_eq!(snapshot.recent_users, 1);
        assert_eq!(snapshot.active_entries, 2);
        assert_eq!(snapshot.recent_entries, 2);
        assert_eq!(snapshot.cleanup_queue_len, 1);
    }

    #[tokio::test]
    async fn test_compact_prunes_stale_recent_entries() {
        let tracker = UserIpTracker::new();
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
            .await;

        let stale_user = "stale-user".to_string();
        let stale_ip = test_ipv4(10, 3, 0, 1);
        {
            let mut recent_ips = tracker.recent_ips.write().await;
            recent_ips
                .entry(stale_user.clone())
                .or_insert_with(HashMap::new)
                .insert(stale_ip, Instant::now() - Duration::from_secs(5));
        }

        tracker.last_compact_epoch_secs.store(0, Ordering::Relaxed);
        tracker
            .check_and_add("trigger-user", test_ipv4(10, 3, 0, 2))
            .await
            .unwrap();

        let recent_ips = tracker.recent_ips.read().await;
        let stale_exists = recent_ips
            .get(&stale_user)
            .map(|ips| ips.contains_key(&stale_ip))
            .unwrap_or(false);
        assert!(!stale_exists);
    }
}
