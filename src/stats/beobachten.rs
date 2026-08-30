//! Per-IP forensic buckets for scanner and handshake failure observation.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const BEOBACHTEN_SHARDS: usize = 64;
const BEOBACHTEN_ENTRIES_PER_SHARD: usize = 1024;

#[derive(Default)]
struct BeobachtenShard {
    classes: HashMap<String, HashMap<IpAddr, BeobachtenEntry>>,
    entries: usize,
    last_cleanup: Option<Instant>,
}

#[derive(Clone, Copy)]
struct BeobachtenEntry {
    tries: u64,
    last_seen: Instant,
}

/// In-memory, TTL-scoped per-IP counters keyed by source class.
pub struct BeobachtenStore {
    shards: Vec<Mutex<BeobachtenShard>>,
    hash_builder: RandomState,
}

impl Default for BeobachtenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BeobachtenStore {
    pub fn new() -> Self {
        Self {
            shards: (0..BEOBACHTEN_SHARDS)
                .map(|_| Mutex::new(BeobachtenShard::default()))
                .collect(),
            hash_builder: RandomState::new(),
        }
    }

    pub fn record(&self, class: &str, ip: IpAddr, ttl: Duration) {
        if class.is_empty() || ttl.is_zero() {
            return;
        }

        let now = Instant::now();
        let shard_index = self.shard_index(class, ip);
        let mut shard = self.shards[shard_index].lock();
        Self::cleanup_if_needed(&mut shard, now, ttl);

        if let Some(entry) = shard
            .classes
            .get_mut(class)
            .and_then(|entries| entries.get_mut(&ip))
        {
            entry.tries = entry.tries.saturating_add(1);
            entry.last_seen = now;
            return;
        }

        if shard.entries >= BEOBACHTEN_ENTRIES_PER_SHARD {
            return;
        }
        shard.classes.entry(class.to_string()).or_default().insert(
            ip,
            BeobachtenEntry {
                tries: 1,
                last_seen: now,
            },
        );
        shard.entries = shard.entries.saturating_add(1);
    }

    pub fn snapshot_text(&self, ttl: Duration) -> String {
        if ttl.is_zero() {
            return "beobachten disabled\n".to_string();
        }

        let now = Instant::now();
        let mut grouped = BTreeMap::<String, Vec<(IpAddr, u64)>>::new();
        for shard in &self.shards {
            let mut shard = shard.lock();
            Self::cleanup(&mut shard, now, ttl);
            shard.last_cleanup = Some(now);
            for (class, entries) in &shard.classes {
                let output = grouped.entry(class.clone()).or_default();
                output.extend(entries.iter().map(|(ip, entry)| (*ip, entry.tries)));
            }
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

    fn shard_index(&self, class: &str, ip: IpAddr) -> usize {
        let mut hasher = self.hash_builder.build_hasher();
        class.hash(&mut hasher);
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % BEOBACHTEN_SHARDS
    }

    fn cleanup_if_needed(shard: &mut BeobachtenShard, now: Instant, ttl: Duration) {
        let should_cleanup = match shard.last_cleanup {
            Some(last) => now.saturating_duration_since(last) >= CLEANUP_INTERVAL,
            None => true,
        };
        if should_cleanup {
            Self::cleanup(shard, now, ttl);
            shard.last_cleanup = Some(now);
        }
    }

    fn cleanup(shard: &mut BeobachtenShard, now: Instant, ttl: Duration) {
        for entries in shard.classes.values_mut() {
            entries.retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= ttl);
        }
        shard.classes.retain(|_, entries| !entries.is_empty());
        shard.entries = shard.classes.values().map(HashMap::len).sum();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shard_never_exceeds_its_allocation_bound() {
        let store = BeobachtenStore::new();
        let ttl = Duration::from_secs(60);
        let target_shard = 0;
        let mut inserted = 0usize;
        for suffix in 0..u32::MAX {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(suffix));
            if store.shard_index("scanner", ip) != target_shard {
                continue;
            }
            store.record("scanner", ip, ttl);
            inserted = inserted.saturating_add(1);
            if inserted > BEOBACHTEN_ENTRIES_PER_SHARD + 64 {
                break;
            }
        }

        assert_eq!(
            store.shards[target_shard].lock().entries,
            BEOBACHTEN_ENTRIES_PER_SHARD
        );
    }
}
