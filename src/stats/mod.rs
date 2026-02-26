//! Statistics and replay protection

#![allow(dead_code)]

pub mod beobachten;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};
use dashmap::DashMap;
use parking_lot::Mutex;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use tracing::debug;

// ============= Stats =============

#[derive(Default)]
pub struct Stats {
    connects_all: AtomicU64,
    connects_bad: AtomicU64,
    handshake_timeouts: AtomicU64,
    me_keepalive_sent: AtomicU64,
    me_keepalive_failed: AtomicU64,
    me_keepalive_pong: AtomicU64,
    me_keepalive_timeout: AtomicU64,
    me_reconnect_attempts: AtomicU64,
    me_reconnect_success: AtomicU64,
    me_crc_mismatch: AtomicU64,
    me_seq_mismatch: AtomicU64,
    me_route_drop_no_conn: AtomicU64,
    me_route_drop_channel_closed: AtomicU64,
    me_route_drop_queue_full: AtomicU64,
    secure_padding_invalid: AtomicU64,
    desync_total: AtomicU64,
    desync_full_logged: AtomicU64,
    desync_suppressed: AtomicU64,
    desync_frames_bucket_0: AtomicU64,
    desync_frames_bucket_1_2: AtomicU64,
    desync_frames_bucket_3_10: AtomicU64,
    desync_frames_bucket_gt_10: AtomicU64,
    pool_swap_total: AtomicU64,
    pool_drain_active: AtomicU64,
    pool_force_close_total: AtomicU64,
    pool_stale_pick_total: AtomicU64,
    me_writer_removed_total: AtomicU64,
    me_writer_removed_unexpected_total: AtomicU64,
    me_refill_triggered_total: AtomicU64,
    me_refill_skipped_inflight_total: AtomicU64,
    me_refill_failed_total: AtomicU64,
    me_writer_restored_same_endpoint_total: AtomicU64,
    me_writer_restored_fallback_total: AtomicU64,
    user_stats: DashMap<String, UserStats>,
    start_time: parking_lot::RwLock<Option<Instant>>,
}

#[derive(Default)]
pub struct UserStats {
    pub connects: AtomicU64,
    pub curr_connects: AtomicU64,
    pub octets_from_client: AtomicU64,
    pub octets_to_client: AtomicU64,
    pub msgs_from_client: AtomicU64,
    pub msgs_to_client: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        let stats = Self::default();
        *stats.start_time.write() = Some(Instant::now());
        stats
    }
    
    pub fn increment_connects_all(&self) { self.connects_all.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_connects_bad(&self) { self.connects_bad.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_handshake_timeouts(&self) { self.handshake_timeouts.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_keepalive_sent(&self) { self.me_keepalive_sent.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_keepalive_failed(&self) { self.me_keepalive_failed.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_keepalive_pong(&self) { self.me_keepalive_pong.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_keepalive_timeout(&self) { self.me_keepalive_timeout.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_keepalive_timeout_by(&self, value: u64) {
        self.me_keepalive_timeout.fetch_add(value, Ordering::Relaxed);
    }
    pub fn increment_me_reconnect_attempt(&self) { self.me_reconnect_attempts.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_reconnect_success(&self) { self.me_reconnect_success.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_crc_mismatch(&self) { self.me_crc_mismatch.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_seq_mismatch(&self) { self.me_seq_mismatch.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_route_drop_no_conn(&self) { self.me_route_drop_no_conn.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_me_route_drop_channel_closed(&self) {
        self.me_route_drop_channel_closed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_route_drop_queue_full(&self) {
        self.me_route_drop_queue_full.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_secure_padding_invalid(&self) {
        self.secure_padding_invalid.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_desync_total(&self) {
        self.desync_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_desync_full_logged(&self) {
        self.desync_full_logged.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_desync_suppressed(&self) {
        self.desync_suppressed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn observe_desync_frames_ok(&self, frames_ok: u64) {
        match frames_ok {
            0 => {
                self.desync_frames_bucket_0.fetch_add(1, Ordering::Relaxed);
            }
            1..=2 => {
                self.desync_frames_bucket_1_2.fetch_add(1, Ordering::Relaxed);
            }
            3..=10 => {
                self.desync_frames_bucket_3_10.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.desync_frames_bucket_gt_10.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_pool_swap_total(&self) {
        self.pool_swap_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_pool_drain_active(&self) {
        self.pool_drain_active.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_pool_drain_active(&self) {
        let mut current = self.pool_drain_active.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            match self.pool_drain_active.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
    pub fn increment_pool_force_close_total(&self) {
        self.pool_force_close_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_pool_stale_pick_total(&self) {
        self.pool_stale_pick_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_writer_removed_total(&self) {
        self.me_writer_removed_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_writer_removed_unexpected_total(&self) {
        self.me_writer_removed_unexpected_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_refill_triggered_total(&self) {
        self.me_refill_triggered_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_refill_skipped_inflight_total(&self) {
        self.me_refill_skipped_inflight_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_refill_failed_total(&self) {
        self.me_refill_failed_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_writer_restored_same_endpoint_total(&self) {
        self.me_writer_restored_same_endpoint_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_writer_restored_fallback_total(&self) {
        self.me_writer_restored_fallback_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get_connects_all(&self) -> u64 { self.connects_all.load(Ordering::Relaxed) }
    pub fn get_connects_bad(&self) -> u64 { self.connects_bad.load(Ordering::Relaxed) }
    pub fn get_me_keepalive_sent(&self) -> u64 { self.me_keepalive_sent.load(Ordering::Relaxed) }
    pub fn get_me_keepalive_failed(&self) -> u64 { self.me_keepalive_failed.load(Ordering::Relaxed) }
    pub fn get_me_keepalive_pong(&self) -> u64 { self.me_keepalive_pong.load(Ordering::Relaxed) }
    pub fn get_me_keepalive_timeout(&self) -> u64 { self.me_keepalive_timeout.load(Ordering::Relaxed) }
    pub fn get_me_reconnect_attempts(&self) -> u64 { self.me_reconnect_attempts.load(Ordering::Relaxed) }
    pub fn get_me_reconnect_success(&self) -> u64 { self.me_reconnect_success.load(Ordering::Relaxed) }
    pub fn get_me_crc_mismatch(&self) -> u64 { self.me_crc_mismatch.load(Ordering::Relaxed) }
    pub fn get_me_seq_mismatch(&self) -> u64 { self.me_seq_mismatch.load(Ordering::Relaxed) }
    pub fn get_me_route_drop_no_conn(&self) -> u64 { self.me_route_drop_no_conn.load(Ordering::Relaxed) }
    pub fn get_me_route_drop_channel_closed(&self) -> u64 {
        self.me_route_drop_channel_closed.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full(&self) -> u64 {
        self.me_route_drop_queue_full.load(Ordering::Relaxed)
    }
    pub fn get_secure_padding_invalid(&self) -> u64 {
        self.secure_padding_invalid.load(Ordering::Relaxed)
    }
    pub fn get_desync_total(&self) -> u64 {
        self.desync_total.load(Ordering::Relaxed)
    }
    pub fn get_desync_full_logged(&self) -> u64 {
        self.desync_full_logged.load(Ordering::Relaxed)
    }
    pub fn get_desync_suppressed(&self) -> u64 {
        self.desync_suppressed.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_0(&self) -> u64 {
        self.desync_frames_bucket_0.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_1_2(&self) -> u64 {
        self.desync_frames_bucket_1_2.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_3_10(&self) -> u64 {
        self.desync_frames_bucket_3_10.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_gt_10(&self) -> u64 {
        self.desync_frames_bucket_gt_10.load(Ordering::Relaxed)
    }
    pub fn get_pool_swap_total(&self) -> u64 {
        self.pool_swap_total.load(Ordering::Relaxed)
    }
    pub fn get_pool_drain_active(&self) -> u64 {
        self.pool_drain_active.load(Ordering::Relaxed)
    }
    pub fn get_pool_force_close_total(&self) -> u64 {
        self.pool_force_close_total.load(Ordering::Relaxed)
    }
    pub fn get_pool_stale_pick_total(&self) -> u64 {
        self.pool_stale_pick_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_removed_total(&self) -> u64 {
        self.me_writer_removed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_removed_unexpected_total(&self) -> u64 {
        self.me_writer_removed_unexpected_total.load(Ordering::Relaxed)
    }
    pub fn get_me_refill_triggered_total(&self) -> u64 {
        self.me_refill_triggered_total.load(Ordering::Relaxed)
    }
    pub fn get_me_refill_skipped_inflight_total(&self) -> u64 {
        self.me_refill_skipped_inflight_total.load(Ordering::Relaxed)
    }
    pub fn get_me_refill_failed_total(&self) -> u64 {
        self.me_refill_failed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_restored_same_endpoint_total(&self) -> u64 {
        self.me_writer_restored_same_endpoint_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_restored_fallback_total(&self) -> u64 {
        self.me_writer_restored_fallback_total.load(Ordering::Relaxed)
    }
    
    pub fn increment_user_connects(&self, user: &str) {
        self.user_stats.entry(user.to_string()).or_default()
            .connects.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_user_curr_connects(&self, user: &str) {
        self.user_stats.entry(user.to_string()).or_default()
            .curr_connects.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn decrement_user_curr_connects(&self, user: &str) {
        if let Some(stats) = self.user_stats.get(user) {
            let counter = &stats.curr_connects;
            let mut current = counter.load(Ordering::Relaxed);
            loop {
                if current == 0 {
                    break;
                }
                match counter.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
        }
    }
    
    pub fn get_user_curr_connects(&self, user: &str) -> u64 {
        self.user_stats.get(user)
            .map(|s| s.curr_connects.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    
    pub fn add_user_octets_from(&self, user: &str, bytes: u64) {
        self.user_stats.entry(user.to_string()).or_default()
            .octets_from_client.fetch_add(bytes, Ordering::Relaxed);
    }
    
    pub fn add_user_octets_to(&self, user: &str, bytes: u64) {
        self.user_stats.entry(user.to_string()).or_default()
            .octets_to_client.fetch_add(bytes, Ordering::Relaxed);
    }
    
    pub fn increment_user_msgs_from(&self, user: &str) {
        self.user_stats.entry(user.to_string()).or_default()
            .msgs_from_client.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_user_msgs_to(&self, user: &str) {
        self.user_stats.entry(user.to_string()).or_default()
            .msgs_to_client.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_user_total_octets(&self, user: &str) -> u64 {
        self.user_stats.get(user)
            .map(|s| {
                s.octets_from_client.load(Ordering::Relaxed) +
                s.octets_to_client.load(Ordering::Relaxed)
            })
            .unwrap_or(0)
    }
    
    pub fn get_handshake_timeouts(&self) -> u64 { self.handshake_timeouts.load(Ordering::Relaxed) }

    pub fn iter_user_stats(&self) -> dashmap::iter::Iter<'_, String, UserStats> {
        self.user_stats.iter()
    }

    pub fn uptime_secs(&self) -> f64 {
        self.start_time.read()
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(0.0)
    }
}

// ============= Replay Checker =============

pub struct ReplayChecker {
    shards: Vec<Mutex<ReplayShard>>,
    shard_mask: usize,
    window: Duration,
    checks: AtomicU64,
    hits: AtomicU64,
    additions: AtomicU64,
    cleanups: AtomicU64,
}

struct ReplayEntry {
    seen_at: Instant,
    seq: u64,
}

struct ReplayShard {
    cache: LruCache<Box<[u8]>, ReplayEntry>,
    queue: VecDeque<(Instant, Box<[u8]>, u64)>,
    seq_counter: u64,
}

impl ReplayShard {
    fn new(cap: NonZeroUsize) -> Self {
        Self {
            cache: LruCache::new(cap),
            queue: VecDeque::with_capacity(cap.get()),
            seq_counter: 0,
        }
    }
    
    fn next_seq(&mut self) -> u64 {
        self.seq_counter += 1;
        self.seq_counter
    }

    fn cleanup(&mut self, now: Instant, window: Duration) {
        if window.is_zero() {
            return;
        }
        let cutoff = now.checked_sub(window).unwrap_or(now);
        
        while let Some((ts, _, _)) = self.queue.front() {
            if *ts >= cutoff {
                break;
            }
            let (_, key, queue_seq) = self.queue.pop_front().unwrap();
            
            // Use key.as_ref() to get &[u8] — avoids Borrow<Q> ambiguity
            // between Borrow<[u8]> and Borrow<Box<[u8]>>
            if let Some(entry) = self.cache.peek(key.as_ref())
                && entry.seq == queue_seq
            {
                self.cache.pop(key.as_ref());
            }
        }
    }
    
    fn check(&mut self, key: &[u8], now: Instant, window: Duration) -> bool {
        self.cleanup(now, window);
        // key is &[u8], resolves Q=[u8] via Box<[u8]>: Borrow<[u8]>
        self.cache.get(key).is_some()
    }
    
    fn add(&mut self, key: &[u8], now: Instant, window: Duration) {
        self.cleanup(now, window);
        
        let seq = self.next_seq();
        let boxed_key: Box<[u8]> = key.into();
        
        self.cache.put(boxed_key.clone(), ReplayEntry { seen_at: now, seq });
        self.queue.push_back((now, boxed_key, seq));
    }
    
    fn len(&self) -> usize {
        self.cache.len()
    }
}

impl ReplayChecker {
    pub fn new(total_capacity: usize, window: Duration) -> Self {
        let num_shards = 64;
        let shard_capacity = (total_capacity / num_shards).max(1);
        let cap = NonZeroUsize::new(shard_capacity).unwrap();

        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(Mutex::new(ReplayShard::new(cap)));
        }

        Self {
            shards,
            shard_mask: num_shards - 1,
            window,
            checks: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            additions: AtomicU64::new(0),
            cleanups: AtomicU64::new(0),
        }
    }

    fn get_shard_idx(&self, key: &[u8]) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.shard_mask
    }

    fn check_and_add_internal(&self, data: &[u8]) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let mut shard = self.shards[idx].lock();
        let now = Instant::now();
        let found = shard.check(data, now, self.window);
        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            shard.add(data, now, self.window);
            self.additions.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    fn add_only(&self, data: &[u8]) {
        self.additions.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let mut shard = self.shards[idx].lock();
        shard.add(data, Instant::now(), self.window);
    }

    pub fn check_and_add_handshake(&self, data: &[u8]) -> bool {
        self.check_and_add_internal(data)
    }

    pub fn check_and_add_tls_digest(&self, data: &[u8]) -> bool {
        self.check_and_add_internal(data)
    }

    // Compatibility helpers (non-atomic split operations) — prefer check_and_add_*.
    pub fn check_handshake(&self, data: &[u8]) -> bool { self.check_and_add_handshake(data) }
    pub fn add_handshake(&self, data: &[u8]) { self.add_only(data) }
    pub fn check_tls_digest(&self, data: &[u8]) -> bool { self.check_and_add_tls_digest(data) }
    pub fn add_tls_digest(&self, data: &[u8]) { self.add_only(data) }
    
    pub fn stats(&self) -> ReplayStats {
        let mut total_entries = 0;
        let mut total_queue_len = 0;
        for shard in &self.shards {
            let s = shard.lock();
            total_entries += s.cache.len();
            total_queue_len += s.queue.len();
        }
        
        ReplayStats {
            total_entries,
            total_queue_len,
            total_checks: self.checks.load(Ordering::Relaxed),
            total_hits: self.hits.load(Ordering::Relaxed),
            total_additions: self.additions.load(Ordering::Relaxed),
            total_cleanups: self.cleanups.load(Ordering::Relaxed),
            num_shards: self.shards.len(),
            window_secs: self.window.as_secs(),
        }
    }
    
    pub async fn run_periodic_cleanup(&self) {
        let interval = if self.window.as_secs() > 60 {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(self.window.as_secs().max(1) / 2)
        };
        
        loop {
            tokio::time::sleep(interval).await;
            
            let now = Instant::now();
            let mut cleaned = 0usize;
            
            for shard_mutex in &self.shards {
                let mut shard = shard_mutex.lock();
                let before = shard.len();
                shard.cleanup(now, self.window);
                let after = shard.len();
                cleaned += before.saturating_sub(after);
            }
            
            self.cleanups.fetch_add(1, Ordering::Relaxed);
            
            if cleaned > 0 {
                debug!(cleaned = cleaned, "Replay checker: periodic cleanup");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplayStats {
    pub total_entries: usize,
    pub total_queue_len: usize,
    pub total_checks: u64,
    pub total_hits: u64,
    pub total_additions: u64,
    pub total_cleanups: u64,
    pub num_shards: usize,
    pub window_secs: u64,
}

impl ReplayStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total_checks == 0 { 0.0 }
        else { (self.total_hits as f64 / self.total_checks as f64) * 100.0 }
    }
    
    pub fn ghost_ratio(&self) -> f64 {
        if self.total_entries == 0 { 0.0 }
        else { self.total_queue_len as f64 / self.total_entries as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    
    #[test]
    fn test_stats_shared_counters() {
        let stats = Arc::new(Stats::new());
        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_all();
        assert_eq!(stats.get_connects_all(), 3);
    }
    
    #[test]
    fn test_replay_checker_basic() {
        let checker = ReplayChecker::new(100, Duration::from_secs(60));
        assert!(!checker.check_handshake(b"test1")); // first time, inserts
        assert!(checker.check_handshake(b"test1"));  // duplicate
        assert!(!checker.check_handshake(b"test2")); // new key inserts
    }
    
    #[test]
    fn test_replay_checker_duplicate_add() {
        let checker = ReplayChecker::new(100, Duration::from_secs(60));
        checker.add_handshake(b"dup");
        checker.add_handshake(b"dup");
        assert!(checker.check_handshake(b"dup"));
    }
    
    #[test]
    fn test_replay_checker_expiration() {
        let checker = ReplayChecker::new(100, Duration::from_millis(50));
        assert!(!checker.check_handshake(b"expire"));
        assert!(checker.check_handshake(b"expire"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!checker.check_handshake(b"expire"));
    }
    
    #[test]
    fn test_replay_checker_stats() {
        let checker = ReplayChecker::new(100, Duration::from_secs(60));
        assert!(!checker.check_handshake(b"k1"));
        assert!(!checker.check_handshake(b"k2"));
        assert!(checker.check_handshake(b"k1"));
        assert!(!checker.check_handshake(b"k3"));
        let stats = checker.stats();
        assert_eq!(stats.total_additions, 3);
        assert_eq!(stats.total_checks, 4);
        assert_eq!(stats.total_hits, 1);
    }
    
    #[test]
    fn test_replay_checker_many_keys() {
        let checker = ReplayChecker::new(10_000, Duration::from_secs(60));
        for i in 0..500u32 {
            checker.add_only(&i.to_le_bytes());
        }
        for i in 0..500u32 {
            assert!(checker.check_handshake(&i.to_le_bytes()));
        }
        assert_eq!(checker.stats().total_entries, 500);
    }
}
