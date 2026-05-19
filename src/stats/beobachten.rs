//! Per-IP forensic buckets for scanner and handshake failure observation.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_BEOBACHTEN_ENTRIES: usize = 65_536;

#[derive(Default)]
struct BeobachtenInner {
    entries: HashMap<(String, IpAddr), BeobachtenEntry>,
    last_cleanup: Option<Instant>,
}

#[derive(Clone, Copy)]
struct BeobachtenEntry {
    tries: u64,
    last_seen: Instant,
}

/// In-memory, TTL-scoped per-IP counters keyed by source class.
pub struct BeobachtenStore {
    inner: Mutex<BeobachtenInner>,
}

impl Default for BeobachtenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BeobachtenStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BeobachtenInner::default()),
        }
    }

    pub fn record(&self, class: &str, ip: IpAddr, ttl: Duration) {
        if class.is_empty() || ttl.is_zero() {
            return;
        }

        let now = Instant::now();
        let mut guard = self.inner.lock();
        Self::cleanup_if_needed(&mut guard, now, ttl);

        let key = (class.to_string(), ip);
        if let Some(entry) = guard.entries.get_mut(&key) {
            entry.tries = entry.tries.saturating_add(1);
            entry.last_seen = now;
            return;
        }

        if guard.entries.len() >= MAX_BEOBACHTEN_ENTRIES {
            return;
        }

        guard.entries.insert(
            key,
            BeobachtenEntry {
                tries: 1,
                last_seen: now,
            },
        );
    }

    pub fn snapshot_text(&self, ttl: Duration) -> String {
        if ttl.is_zero() {
            return "beobachten disabled\n".to_string();
        }

        let now = Instant::now();
        let entries = {
            let mut guard = self.inner.lock();
            Self::cleanup(&mut guard, now, ttl);
            guard.last_cleanup = Some(now);

            guard
                .entries
                .iter()
                .map(|((class, ip), entry)| (class.clone(), *ip, entry.tries))
                .collect::<Vec<_>>()
        };

        let mut grouped = BTreeMap::<String, Vec<(IpAddr, u64)>>::new();
        for (class, ip, tries) in entries {
            grouped.entry(class).or_default().push((ip, tries));
        }

        if grouped.is_empty() {
            return "empty\n".to_string();
        }

        let mut out = String::with_capacity(grouped.len() * 64);
        for (class, entries) in &mut grouped {
            out.push('[');
            out.push_str(class);
            out.push_str("]\n");

            entries.sort_by(|(ip_a, tries_a), (ip_b, tries_b)| {
                tries_b
                    .cmp(tries_a)
                    .then_with(|| ip_a.to_string().cmp(&ip_b.to_string()))
            });

            for (ip, tries) in entries {
                out.push_str(&format!("{ip}-{tries}\n"));
            }
        }

        out
    }

    fn cleanup_if_needed(inner: &mut BeobachtenInner, now: Instant, ttl: Duration) {
        let should_cleanup = match inner.last_cleanup {
            Some(last) => now.saturating_duration_since(last) >= CLEANUP_INTERVAL,
            None => true,
        };
        if should_cleanup {
            Self::cleanup(inner, now, ttl);
            inner.last_cleanup = Some(now);
        }
    }

    fn cleanup(inner: &mut BeobachtenInner, now: Instant, ttl: Duration) {
        inner
            .entries
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn record_and_snapshot_contains_entries_across_classes() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);

        store.record("scanner", ip("203.0.113.1"), ttl);
        store.record("scanner", ip("203.0.113.2"), ttl);
        store.record("handshake_fail", ip("198.51.100.10"), ttl);

        let snap = store.snapshot_text(ttl);
        assert!(snap.contains("[scanner]"), "scanner class header present");
        assert!(snap.contains("[handshake_fail]"), "handshake_fail class header present");
        assert!(snap.contains("203.0.113.1-1"));
        assert!(snap.contains("203.0.113.2-1"));
        assert!(snap.contains("198.51.100.10-1"));
    }

    #[test]
    fn record_idempotent_same_ip_within_ttl() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);

        store.record("scanner", ip("203.0.113.1"), ttl);
        store.record("scanner", ip("203.0.113.1"), ttl);
        store.record("scanner", ip("203.0.113.1"), ttl);

        let snap = store.snapshot_text(ttl);
        assert!(snap.contains("203.0.113.1-3"), "tries incremented, not duplicated");
        assert_eq!(snap.matches("203.0.113.1").count(), 1, "IP appears exactly once");
    }

    #[test]
    fn different_classes_are_separated() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);

        store.record("alpha", ip("10.0.0.1"), ttl);
        store.record("beta", ip("10.0.0.1"), ttl);

        let snap = store.snapshot_text(ttl);
        assert!(snap.contains("[alpha]"));
        assert!(snap.contains("[beta]"));
        let alpha_block = snap.split("[alpha]").nth(1).unwrap();
        let alpha_section = alpha_block.split('[').next().unwrap();
        assert!(alpha_section.contains("10.0.0.1-1"));
        let beta_block = snap.split("[beta]").nth(1).unwrap();
        let beta_section = beta_block.split('[').next().unwrap();
        assert!(beta_section.contains("10.0.0.1-1"));
    }

    #[test]
    fn snapshot_text_empty_when_no_entries() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);
        let snap = store.snapshot_text(ttl);
        assert_eq!(snap, "empty\n");
    }

    #[test]
    fn snapshot_text_zero_ttl_returns_disabled() {
        let store = BeobachtenStore::new();
        let snap = store.snapshot_text(Duration::ZERO);
        assert_eq!(snap, "beobachten disabled\n");
    }

    #[test]
    fn record_empty_class_is_noop() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);
        store.record("", ip("203.0.113.1"), ttl);
        let snap = store.snapshot_text(ttl);
        assert_eq!(snap, "empty\n");
    }

    #[test]
    fn record_zero_ttl_is_noop() {
        let store = BeobachtenStore::new();
        store.record("scanner", ip("203.0.113.1"), Duration::ZERO);
        let snap = store.snapshot_text(Duration::from_secs(600));
        assert_eq!(snap, "empty\n");
    }

    #[test]
    fn snapshot_sorted_by_tries_desc_then_ip() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);

        store.record("scanner", ip("10.0.0.1"), ttl);
        store.record("scanner", ip("10.0.0.1"), ttl);
        store.record("scanner", ip("10.0.0.1"), ttl);
        store.record("scanner", ip("10.0.0.2"), ttl);
        store.record("scanner", ip("10.0.0.2"), ttl);

        let snap = store.snapshot_text(ttl);
        let scanner_section = snap.split("[scanner]\n").nth(1).unwrap();
        let lines: Vec<&str> = scanner_section.lines().take(2).collect();
        assert!(lines[0].contains("10.0.0.1-3"), "higher tries first");
        assert!(lines[1].contains("10.0.0.2-2"), "lower tries second");
    }

    #[test]
    fn cleanup_removes_expired_entries_via_snapshot() {
        let store = BeobachtenStore::new();
        let short_ttl = Duration::from_millis(50);

        store.record("scanner", ip("203.0.113.1"), short_ttl);

        let snap_before = store.snapshot_text(Duration::from_secs(600));
        assert!(snap_before.contains("203.0.113.1"), "visible with long TTL");

        std::thread::sleep(Duration::from_millis(200));

        let snap_after = store.snapshot_text(short_ttl);
        assert_eq!(snap_after, "empty\n", "expired entries removed");
    }

    #[test]
    fn max_entries_cap_respected() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(600);

        for i in 0..=MAX_BEOBACHTEN_ENTRIES {
            let octet3 = ((i >> 16) & 0xFF) as u8;
            let octet2 = ((i >> 8) & 0xFF) as u8;
            let octet1 = (i & 0xFF) as u8;
            let addr: IpAddr = format!("10.{octet3}.{octet2}.{octet1}").parse().unwrap();
            store.record("scanner", addr, ttl);
        }

        let snap = store.snapshot_text(ttl);
        let count = snap.lines().filter(|l| l.contains("-1") && !l.starts_with('[')).count();
        assert!(count <= MAX_BEOBACHTEN_ENTRIES, "capped at max entries");
    }
}
