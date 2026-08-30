use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::tls_front::types::{
    CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsFetchResult, TlsProfileQuality,
    TlsProfileSource,
};

// Runtime TLS profile cache operations.
mod runtime;
// Bounded disk-cache reads and domain matching.
mod disk;

use disk::*;

#[cfg(test)]
mod tests;
const FULL_CERT_SENT_SWEEP_INTERVAL_SECS: u64 = 1;
const FULL_CERT_SENT_MAX_ENTRIES: usize = 65_536;
const FULL_CERT_SENT_SHARDS: usize = 64;
const FULL_CERT_SENT_MAX_ENTRIES_PER_SHARD: usize =
    (FULL_CERT_SENT_MAX_ENTRIES / FULL_CERT_SENT_SHARDS) * 2;
const TLS_FRONT_DISK_ENTRY_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FullCertBudgetKey {
    domain: Arc<str>,
    client_ip: IpAddr,
}

#[derive(Debug)]
struct FullCertBudgetEntry {
    expires_at: Option<Instant>,
}

/// Process-owned, bounded TLS full-certificate admission history.
#[derive(Debug)]
pub(crate) struct TlsFullCertBudget {
    shards: Vec<RwLock<HashMap<FullCertBudgetKey, FullCertBudgetEntry>>>,
    hash_builder: RandomState,
    entries: AtomicUsize,
    cap_drops: AtomicU64,
    last_sweep_epoch_secs: AtomicU64,
    sweep_cursor: AtomicUsize,
}

impl TlsFullCertBudget {
    /// Creates an empty process-owned full-certificate budget.
    pub(crate) fn new() -> Self {
        Self {
            shards: (0..FULL_CERT_SENT_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            hash_builder: RandomState::new(),
            entries: AtomicUsize::new(0),
            cap_drops: AtomicU64::new(0),
            last_sweep_epoch_secs: AtomicU64::new(0),
            sweep_cursor: AtomicUsize::new(0),
        }
    }

    fn shard_index(&self, key: &FullCertBudgetKey) -> usize {
        let mut hasher = self.hash_builder.build_hasher();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % FULL_CERT_SENT_SHARDS
    }

    fn decrement_entries(&self, amount: usize) {
        if amount == 0 {
            return;
        }
        let _ = self
            .entries
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(amount))
            });
    }

    fn try_reserve_entry(&self) -> bool {
        let mut current = self.entries.load(Ordering::Relaxed);
        loop {
            if current >= FULL_CERT_SENT_MAX_ENTRIES {
                return false;
            }
            match self.entries.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    async fn sweep_one_shard(&self, now: Instant) {
        let shard_index = self.sweep_cursor.fetch_add(1, Ordering::Relaxed) % FULL_CERT_SENT_SHARDS;
        let mut guard = self.shards[shard_index].write().await;
        let before = guard.len();
        guard.retain(|_, entry| entry.expires_at.map_or(true, |expires_at| expires_at > now));
        self.decrement_entries(before.saturating_sub(guard.len()));
    }

    async fn maybe_sweep(&self, now: Instant) {
        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let should_sweep = self
            .last_sweep_epoch_secs
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |last_sweep| {
                if now_epoch_secs.saturating_sub(last_sweep) >= FULL_CERT_SENT_SWEEP_INTERVAL_SECS {
                    Some(now_epoch_secs)
                } else {
                    None
                }
            })
            .is_ok();
        if should_sweep {
            self.sweep_one_shard(now).await;
        }
    }

    async fn take(&self, domain: Arc<str>, client_ip: IpAddr, ttl: Duration) -> bool {
        if ttl.is_zero() {
            return true;
        }

        let now = Instant::now();
        self.maybe_sweep(now).await;
        let expires_at = now.checked_add(ttl);
        let key = FullCertBudgetKey { domain, client_ip };
        let shard_index = self.shard_index(&key);
        let mut guard = self.shards[shard_index].write().await;

        if let Some(entry) = guard.get_mut(&key) {
            if entry.expires_at.is_some_and(|expires_at| expires_at <= now) {
                entry.expires_at = expires_at;
                return true;
            }
            return false;
        }

        if guard.len() >= FULL_CERT_SENT_MAX_ENTRIES_PER_SHARD {
            let before = guard.len();
            guard.retain(|_, entry| entry.expires_at.map_or(true, |expires_at| expires_at > now));
            self.decrement_entries(before.saturating_sub(guard.len()));
        }
        if guard.len() >= FULL_CERT_SENT_MAX_ENTRIES_PER_SHARD || !self.try_reserve_entry() {
            self.cap_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        guard.insert(key, FullCertBudgetEntry { expires_at });
        true
    }

    /// Returns the current number of retained domain and client IP entries.
    pub(crate) fn entries_for_metrics(&self) -> u64 {
        self.entries.load(Ordering::Relaxed) as u64
    }

    /// Returns the cumulative number of entries rejected by hard bounds.
    pub(crate) fn cap_drops_for_metrics(&self) -> u64 {
        self.cap_drops.load(Ordering::Relaxed)
    }
}

/// Lightweight in-memory + optional on-disk cache for TLS fronting data.
#[derive(Debug)]
pub struct TlsFrontCache {
    memory: RwLock<HashMap<String, Arc<CachedTlsData>>>,
    default: Arc<CachedTlsData>,
    full_cert_budget: Arc<TlsFullCertBudget>,
    full_cert_domain_keys: HashMap<String, Arc<str>>,
    disk_entry_names: HashSet<String>,
    disk_path: PathBuf,
}

/// Read-only health view for one configured TLS front domain.
#[derive(Debug, Clone)]
pub(crate) struct TlsFrontProfileHealth {
    pub(crate) domain: String,
    pub(crate) source: &'static str,
    pub(crate) quality: &'static str,
    pub(crate) key_share_group: &'static str,
    pub(crate) age_seconds: u64,
    pub(crate) is_default: bool,
    pub(crate) has_cert_info: bool,
    pub(crate) has_cert_payload: bool,
    pub(crate) server_hello_record_len: usize,
    pub(crate) server_hello_extensions: usize,
    pub(crate) app_data_records: usize,
    pub(crate) ticket_records: usize,
    pub(crate) change_cipher_spec_count: u8,
    pub(crate) total_app_data_len: usize,
}

fn profile_source_label(source: TlsProfileSource) -> &'static str {
    match source {
        TlsProfileSource::Default => "default",
        TlsProfileSource::Raw => "raw",
        TlsProfileSource::Rustls => "rustls",
        TlsProfileSource::Merged => "merged",
    }
}

fn profile_quality_label(quality: TlsProfileQuality) -> &'static str {
    match quality {
        TlsProfileQuality::Fallback => "fallback",
        TlsProfileQuality::RawPartial => "raw_partial",
        TlsProfileQuality::RawStrict => "raw_strict",
    }
}

fn key_share_group_label(group: Option<u16>) -> &'static str {
    match group {
        Some(0x001d) => "x25519",
        Some(0x11ec) => "x25519mlkem768",
        Some(_) => "other",
        None => "none",
    }
}
