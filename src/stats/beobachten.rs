//! Per-IP forensic buckets for scanner and handshake failure observation.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

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
        let entry = guard.entries.entry(key).or_insert(BeobachtenEntry {
            tries: 0,
            last_seen: now,
        });
        entry.tries = entry.tries.saturating_add(1);
        entry.last_seen = now;
    }

    pub fn snapshot_text(&self, ttl: Duration) -> String {
        if ttl.is_zero() {
            return "beobachten disabled\n".to_string();
        }

        let now = Instant::now();
        let mut guard = self.inner.lock();
        Self::cleanup(&mut guard, now, ttl);
        guard.last_cleanup = Some(now);

        let mut grouped = BTreeMap::<String, Vec<(IpAddr, u64)>>::new();
        for ((class, ip), entry) in &guard.entries {
            grouped
                .entry(class.clone())
                .or_default()
                .push((*ip, entry.tries));
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
        inner.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.last_seen) <= ttl
        });
    }
}
