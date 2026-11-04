use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::config::{ProxyConfig, WebRuntimeVhost, WebWildcardLimitsConfig};

/// Request-owned table; a cold allocation is bounded by the HTTP handler permit.
pub(crate) enum CapabilityTable {
    /// Positive cache hit, including its retained-memory lease.
    Warm(Arc<CacheEntry>),
    /// Complete temporary derivation, not yet eligible for retention.
    Cold(Box<[[u8; 32]]>),
}

impl CapabilityTable {
    /// Returns the dense table used for both containment and full authentication scans.
    pub(crate) fn capabilities(&self) -> &[[u8; 32]] {
        match self {
            Self::Warm(entry) => &entry.capabilities,
            Self::Cold(capabilities) => capabilities,
        }
    }
}

/// A cache entry retains no runtime generation, template, policy, or decoy snapshot.
pub(crate) struct CacheEntry {
    snapshot: u64,
    group: usize,
    sequence: u64,
    capabilities: Box<[[u8; 32]]>,
    charged: usize,
    live_bytes: Arc<AtomicUsize>,
}

impl Drop for CacheEntry {
    fn drop(&mut self) {
        self.live_bytes.fetch_sub(self.charged, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct State {
    hosts: BTreeMap<String, Arc<CacheEntry>>,
    fifo: BTreeMap<u64, String>,
    known: BTreeMap<[u8; 32], usize>,
    next_sequence: u64,
    last: Option<Instant>,
    tokens: f64,
    #[cfg(test)]
    evaluations: usize,
}

/// Process-owned positive cache and atomic HMAC token bucket, independent of quotas.
pub(crate) struct WildcardState {
    limits: WebWildcardLimitsConfig,
    state: Mutex<State>,
    live_bytes: Arc<AtomicUsize>,
}

impl WildcardState {
    /// Initializes an empty process-scoped cache without allocating hostname inventories.
    pub(crate) fn new(limits: WebWildcardLimitsConfig) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
            live_bytes: Arc::default(),
        }
    }

    /// Returns a hit or reserves the entire cold cost before any HMAC evaluation.
    pub(crate) fn prepare(
        &self,
        config: &ProxyConfig,
        vhost: &WebRuntimeVhost,
        host: &str,
    ) -> Option<CapabilityTable> {
        let group = vhost.wildcard.as_ref()?;
        let snapshot = config.web.runtime.as_ref()?.snapshot_id;
        {
            let mut state = self.state.lock();
            if let Some(entry) = state
                .hosts
                .get(host)
                .filter(|entry| entry.snapshot == snapshot && entry.group == group.group_id)
            {
                return Some(CapabilityTable::Warm(Arc::clone(entry)));
            }
            let count = group.profiles.len();
            if count > self.limits.max_profiles_per_request
                || !reserve(&mut state, Instant::now(), count, &self.limits)
            {
                return None;
            }
        }
        // No registry lock spans derivation or immutable authentication lookup.
        config
            .wildcard_capabilities(vhost, host)
            .ok()
            .map(CapabilityTable::Cold)
    }

    /// Tests only positive-cache membership; this never authorizes a profile.
    pub(crate) fn contains(&self, candidate: &[u8; 32]) -> bool {
        let digest: [u8; 32] = Sha256::digest(candidate).into();
        self.state.lock().known.contains_key(&digest)
    }

    /// Retains a complete table only after successful bootstrap issuance.
    pub(crate) fn publish(
        &self,
        snapshot: u64,
        vhost: &WebRuntimeVhost,
        host: &str,
        table: CapabilityTable,
        is_current: impl FnOnce() -> bool,
    ) {
        let CapabilityTable::Cold(capabilities) = table else {
            return;
        };
        let Some(group) = vhost.wildcard.as_ref() else {
            return;
        };
        if self.limits.cache_hosts == 0 {
            return;
        }
        // Includes dense bytes, digest-index nodes, two owned host keys, tree nodes,
        // Arc headers and allocator overhead; detached borrowers keep the full charge.
        let Some(charged) = capabilities
            .len()
            .checked_mul(256)
            .and_then(|value| value.checked_add(2048 + 2 * host.len()))
            .filter(|value| *value <= self.limits.cache_bytes)
        else {
            return;
        };
        let mut state = self.state.lock();
        // Snapshot IDs are unique, not activation-ordered. Recheck under the cache
        // lock so a late old request cannot replace an already published current entry.
        if !is_current() {
            return;
        }
        if state
            .hosts
            .get(host)
            .is_some_and(|entry| entry.snapshot == snapshot && entry.group == group.group_id)
        {
            return;
        }
        if let Some(entry) = state.hosts.remove(host) {
            detach(&mut state, &entry);
        }
        loop {
            if state.hosts.len() < self.limits.cache_hosts
                && self.live_bytes.load(Ordering::Acquire) <= self.limits.cache_bytes - charged
            {
                break;
            }
            let Some((_, oldest)) = state.fifo.first_key_value() else {
                return;
            };
            let oldest = oldest.clone();
            if let Some(entry) = state.hosts.remove(&oldest) {
                detach(&mut state, &entry);
            }
        }
        let Some(next) = state.next_sequence.checked_add(1) else {
            return;
        };
        let sequence = state.next_sequence;
        state.next_sequence = next;
        self.live_bytes.fetch_add(charged, Ordering::AcqRel);
        for capability in &capabilities {
            *state
                .known
                .entry(Sha256::digest(capability).into())
                .or_default() += 1;
        }
        state.fifo.insert(sequence, host.to_string());
        state.hosts.insert(
            host.to_string(),
            Arc::new(CacheEntry {
                snapshot,
                group: group.group_id,
                sequence,
                capabilities,
                charged,
                live_bytes: Arc::clone(&self.live_bytes),
            }),
        );
    }
}

fn detach(state: &mut State, entry: &CacheEntry) {
    state.fifo.remove(&entry.sequence);
    for capability in &entry.capabilities {
        let digest: [u8; 32] = Sha256::digest(capability).into();
        if let Some(count) = state.known.get_mut(&digest) {
            *count -= 1;
            if *count == 0 {
                state.known.remove(&digest);
            }
        }
    }
    // Empty BTreeMaps may retain root allocations. Release them explicitly so
    // a fully detached cache has no index memory outside live entry leases.
    if state.hosts.is_empty() {
        state.hosts = BTreeMap::new();
    }
    if state.fifo.is_empty() {
        state.fifo = BTreeMap::new();
    }
    if state.known.is_empty() {
        state.known = BTreeMap::new();
    }
}

fn reserve(state: &mut State, now: Instant, cost: usize, limits: &WebWildcardLimitsConfig) -> bool {
    let burst = f64::from(limits.cold_hmac_burst);
    state.tokens = state.last.map_or(burst, |last| {
        (state.tokens
            + now.saturating_duration_since(last).as_secs_f64()
                * f64::from(limits.cold_hmac_per_minute)
                / 60.0)
            .min(burst)
    });
    state.last = Some(now);
    if state.tokens < cost as f64 {
        return false;
    }
    state.tokens -= cost as f64;
    #[cfg(test)]
    {
        state.evaluations += cost;
    }
    true
}

#[cfg(test)]
impl WildcardState {
    /// Exposes deterministic resource evidence without production metrics or hot-path counters.
    pub(crate) fn test_stats(&self) -> (usize, usize, usize) {
        let state = self.state.lock();
        (
            state.hosts.len(),
            self.live_bytes.load(Ordering::Acquire),
            state.evaluations,
        )
    }
}

// Cache accounting and token-bucket invariants are tested without network timing.
#[cfg(test)]
mod tests;
