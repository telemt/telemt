use std::collections::{HashMap, HashSet};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tokio::io::AsyncReadExt;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::tls_front::types::{
    CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsFetchResult, TlsProfileQuality,
    TlsProfileSource,
};

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
        let shard_index = self.sweep_cursor.fetch_add(1, Ordering::Relaxed)
            % FULL_CERT_SENT_SHARDS;
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
                if now_epoch_secs.saturating_sub(last_sweep)
                    >= FULL_CERT_SENT_SWEEP_INTERVAL_SECS
                {
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
            guard.retain(|_, entry| {
                entry.expires_at.map_or(true, |expires_at| expires_at > now)
            });
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

#[allow(dead_code)]
impl TlsFrontCache {
    pub fn new(domains: &[String], default_len: usize, disk_path: impl AsRef<Path>) -> Self {
        Self::new_with_full_cert_budget(
            domains,
            default_len,
            disk_path,
            Arc::new(TlsFullCertBudget::new()),
        )
    }

    /// Creates a generation-local cache backed by the process-owned full-cert budget.
    pub(crate) fn new_with_full_cert_budget(
        domains: &[String],
        default_len: usize,
        disk_path: impl AsRef<Path>,
        full_cert_budget: Arc<TlsFullCertBudget>,
    ) -> Self {
        let default_template = ParsedServerHello {
            version: [0x03, 0x03],
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suite: [0x13, 0x01],
            compression: 0,
            extensions: Vec::new(),
        };

        let default = Arc::new(CachedTlsData {
            server_hello_template: default_template,
            cert_info: None,
            cert_payload: None,
            app_data_records_sizes: vec![default_len],
            total_app_data_len: default_len,
            behavior_profile: TlsBehaviorProfile::default(),
            fetched_at: SystemTime::now(),
            domain: "default".to_string(),
        });

        let mut map = HashMap::new();
        let mut full_cert_domain_keys = HashMap::new();
        let mut disk_entry_names = HashSet::new();
        for d in domains {
            map.insert(d.clone(), default.clone());
            disk_entry_names.insert(format!("{}.json", d.replace(['/', '\\'], "_")));
            let canonical: Arc<str> = Arc::from(normalize_dns_name(d));
            full_cert_domain_keys.insert(d.clone(), canonical.clone());
            full_cert_domain_keys
                .entry(canonical.to_string())
                .or_insert(canonical);
        }

        Self {
            memory: RwLock::new(map),
            default,
            full_cert_budget,
            full_cert_domain_keys,
            disk_entry_names,
            disk_path: disk_path.as_ref().to_path_buf(),
        }
    }

    pub async fn get(&self, sni: &str) -> Arc<CachedTlsData> {
        let guard = self.memory.read().await;
        guard
            .get(sni)
            .cloned()
            .unwrap_or_else(|| self.default.clone())
    }

    pub async fn contains_domain(&self, domain: &str) -> bool {
        self.memory.read().await.contains_key(domain)
    }

    pub(crate) async fn profile_health_snapshot(
        &self,
        domains: &[String],
        max_domains: usize,
    ) -> (Vec<TlsFrontProfileHealth>, usize) {
        let guard = self.memory.read().await;
        let now = SystemTime::now();
        let mut snapshot = Vec::with_capacity(domains.len().min(max_domains));
        let mut suppressed = 0usize;

        for domain in domains {
            if snapshot.len() >= max_domains {
                suppressed = suppressed.saturating_add(1);
                continue;
            }

            let cached = guard
                .get(domain)
                .cloned()
                .unwrap_or_else(|| self.default.clone());
            let mut behavior = cached.behavior_profile.clone();
            behavior.refresh_server_hello_summary(&cached.server_hello_template);
            let age_seconds = now
                .duration_since(cached.fetched_at)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);

            snapshot.push(TlsFrontProfileHealth {
                domain: domain.clone(),
                source: profile_source_label(behavior.source),
                quality: profile_quality_label(behavior.quality),
                key_share_group: key_share_group_label(behavior.server_hello_key_share_group),
                age_seconds,
                is_default: cached.domain == "default",
                has_cert_info: cached.cert_info.is_some(),
                has_cert_payload: cached.cert_payload.is_some(),
                server_hello_record_len: behavior.server_hello_record_len,
                server_hello_extensions: behavior.server_hello_extension_types.len(),
                app_data_records: cached
                    .app_data_records_sizes
                    .len()
                    .max(behavior.app_data_record_sizes.len()),
                ticket_records: behavior.ticket_record_sizes.len(),
                change_cipher_spec_count: behavior.change_cipher_spec_count,
                total_app_data_len: cached.total_app_data_len,
            });
        }

        (snapshot, suppressed)
    }

    /// Returns configured domains that still resolve to the synthetic default profile.
    pub(crate) async fn default_profile_domains(&self, domains: &[String]) -> Vec<String> {
        let guard = self.memory.read().await;
        domains
            .iter()
            .filter(|domain| {
                guard.get(domain.as_str()).unwrap_or(&self.default).domain == "default"
            })
            .cloned()
            .collect()
    }

    fn full_cert_domain_key(&self, domain: &str) -> Arc<str> {
        self.full_cert_domain_keys
            .get(domain)
            .cloned()
            .unwrap_or_else(|| Arc::from(normalize_dns_name(domain)))
    }

    /// Returns true when the selected domain and client IP may receive a full cert payload.
    pub async fn take_full_cert_budget_for_ip(
        &self,
        domain: &str,
        client_ip: IpAddr,
        ttl: Duration,
    ) -> bool {
        self.full_cert_budget
            .take(self.full_cert_domain_key(domain), client_ip, ttl)
            .await
    }

    /// Returns the current process-owned full-cert budget entry count.
    pub(crate) fn full_cert_budget_entries_for_metrics(&self) -> u64 {
        self.full_cert_budget.entries_for_metrics()
    }

    /// Returns the cumulative process-owned full-cert budget cap drops.
    pub(crate) fn full_cert_budget_cap_drops_for_metrics(&self) -> u64 {
        self.full_cert_budget.cap_drops_for_metrics()
    }

    #[cfg(test)]
    async fn insert_full_cert_sent_for_tests(
        &self,
        domain: &str,
        client_ip: IpAddr,
        expires_at: Instant,
    ) {
        let key = FullCertBudgetKey {
            domain: self.full_cert_domain_key(domain),
            client_ip,
        };
        let shard_index = self.full_cert_budget.shard_index(&key);
        let mut guard = self.full_cert_budget.shards[shard_index].write().await;
        if guard
            .insert(
                key,
                FullCertBudgetEntry {
                    expires_at: Some(expires_at),
                },
            )
            .is_none()
        {
            self.full_cert_budget
                .entries
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    async fn full_cert_sent_is_empty_for_tests(&self) -> bool {
        for shard in &self.full_cert_budget.shards {
            if !shard.read().await.is_empty() {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    async fn full_cert_sent_contains_for_tests(&self, domain: &str, client_ip: IpAddr) -> bool {
        let key = FullCertBudgetKey {
            domain: self.full_cert_domain_key(domain),
            client_ip,
        };
        let shard_index = self.full_cert_budget.shard_index(&key);
        self.full_cert_budget.shards[shard_index]
            .read()
            .await
            .contains_key(&key)
    }

    pub async fn set(&self, domain: &str, data: CachedTlsData) {
        let mut guard = self.memory.write().await;
        guard.insert(domain.to_string(), Arc::new(data));
    }

    pub async fn load_from_disk(&self) {
        let path = self.disk_path.clone();
        if tokio::fs::create_dir_all(&path).await.is_err() {
            return;
        }
        let mut loaded = 0usize;
        for name in &self.disk_entry_names {
            let entry_path = path.join(name);
            let Ok(metadata) = tokio::fs::symlink_metadata(&entry_path).await else {
                continue;
            };
            if !metadata.file_type().is_file() {
                continue;
            }
            if let Ok(data) = read_disk_entry_bounded(&entry_path).await
                && let Ok(mut cached) = serde_json::from_slice::<CachedTlsData>(&data)
            {
                if cached.domain.is_empty()
                    || cached.domain.len() > 255
                    || !cached
                        .domain
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
                    warn!(file = %name, "Skipping TLS cache entry with invalid domain");
                    continue;
                }
                if !self.full_cert_domain_keys.contains_key(&cached.domain) {
                    warn!(
                        file = %name,
                        domain = %cached.domain,
                        "Skipping TLS cache entry outside configured domains"
                    );
                    continue;
                }
                if !cert_info_matches_domain(&cached) {
                    warn!(
                        file = %name,
                        domain = %cached.domain,
                        "Skipping TLS cache entry with mismatched certificate metadata"
                    );
                    continue;
                }
                // fetched_at is skipped during deserialization; approximate with file mtime if available.
                if let Ok(modified) = metadata.modified() {
                    cached.fetched_at = modified;
                }
                // Drop entries older than 72h
                if let Ok(age) = cached.fetched_at.elapsed()
                    && age > Duration::from_secs(72 * 3600)
                {
                    warn!(domain = %cached.domain, "Skipping stale TLS cache entry (>72h)");
                    continue;
                }
                cached
                    .behavior_profile
                    .refresh_server_hello_summary(&cached.server_hello_template);
                let domain = cached.domain.clone();
                self.set(&domain, cached).await;
                loaded += 1;
            }
        }
        if loaded > 0 {
            info!(count = loaded, "Loaded TLS cache entries from disk");
        }
    }

    async fn persist(&self, domain: &str, data: &CachedTlsData) {
        if tokio::fs::create_dir_all(&self.disk_path).await.is_err() {
            return;
        }
        let fname = format!("{}.json", domain.replace(['/', '\\'], "_"));
        let path = self.disk_path.join(fname);
        if let Ok(json) = serde_json::to_vec_pretty(data) {
            if json.len() as u64 > TLS_FRONT_DISK_ENTRY_MAX_BYTES {
                warn!(
                    domain,
                    bytes = json.len(),
                    "Skipping oversized TLS cache persistence"
                );
                return;
            }
            // best-effort write
            let _ = tokio::fs::write(path, json).await;
        }
    }

    /// Spawn background updater that periodically refreshes cached domains using provided fetcher.
    pub fn spawn_updater<F>(self: Arc<Self>, domains: Vec<String>, interval: Duration, fetcher: F)
    where
        F: Fn(String) -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
    {
        tokio::spawn(async move {
            loop {
                for domain in &domains {
                    let _ = fetcher(domain.clone()).await;
                }
                sleep(interval).await;
            }
        });
    }

    /// Replace cached entry from a fetch result.
    pub async fn update_from_fetch(&self, domain: &str, fetched: TlsFetchResult) {
        let TlsFetchResult {
            server_hello_parsed,
            app_data_records_sizes,
            total_app_data_len,
            mut behavior_profile,
            cert_info,
            cert_payload,
        } = fetched;
        behavior_profile.refresh_server_hello_summary(&server_hello_parsed);
        let quality = behavior_profile.quality;
        let data = CachedTlsData {
            server_hello_template: server_hello_parsed,
            cert_info,
            cert_payload,
            app_data_records_sizes: app_data_records_sizes.clone(),
            total_app_data_len,
            behavior_profile,
            fetched_at: SystemTime::now(),
            domain: domain.to_string(),
        };

        self.set(domain, data.clone()).await;
        self.persist(domain, &data).await;
        if quality == TlsProfileQuality::RawStrict {
            debug!(domain = %domain, len = total_app_data_len, "TLS cache updated");
        } else {
            warn!(
                domain = %domain,
                quality = profile_quality_label(quality),
                len = total_app_data_len,
                "TLS cache updated with non-strict front profile"
            );
        }
    }

    pub fn default_entry(&self) -> Arc<CachedTlsData> {
        self.default.clone()
    }

    pub fn disk_path(&self) -> &Path {
        &self.disk_path
    }
}

async fn read_disk_entry_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    if file.metadata().await?.len() > TLS_FRONT_DISK_ENTRY_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS cache entry exceeds the 1 MiB limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(TLS_FRONT_DISK_ENTRY_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > TLS_FRONT_DISK_ENTRY_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS cache entry grew beyond the 1 MiB limit while reading",
        ));
    }
    Ok(bytes)
}

fn cert_info_matches_domain(cached: &CachedTlsData) -> bool {
    let Some(cert_info) = cached.cert_info.as_ref() else {
        return true;
    };
    if !cert_info.san_names.is_empty() {
        return cert_info
            .san_names
            .iter()
            .any(|name| dns_name_matches_domain(name, &cached.domain));
    }
    cert_info
        .subject_cn
        .as_deref()
        .map_or(true, |name| dns_name_matches_domain(name, &cached.domain))
}

fn dns_name_matches_domain(pattern: &str, domain: &str) -> bool {
    let pattern = normalize_dns_name(pattern);
    let domain = normalize_dns_name(domain);
    if pattern == domain {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(prefix) = domain.strip_suffix(suffix) else {
        return false;
    };
    prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
}

fn normalize_dns_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached_with_cert_info(
        domain: &str,
        subject_cn: Option<&str>,
        san_names: Vec<&str>,
    ) -> CachedTlsData {
        CachedTlsData {
            server_hello_template: ParsedServerHello {
                version: [0x03, 0x03],
                random: [0u8; 32],
                session_id: Vec::new(),
                cipher_suite: [0x13, 0x01],
                compression: 0,
                extensions: Vec::new(),
            },
            cert_info: Some(crate::tls_front::types::ParsedCertificateInfo {
                not_after_unix: None,
                not_before_unix: None,
                issuer_cn: None,
                subject_cn: subject_cn.map(str::to_string),
                san_names: san_names.into_iter().map(str::to_string).collect(),
            }),
            cert_payload: None,
            app_data_records_sizes: vec![1024],
            total_app_data_len: 1024,
            behavior_profile: TlsBehaviorProfile::default(),
            fetched_at: SystemTime::now(),
            domain: domain.to_string(),
        }
    }

    #[test]
    fn cert_info_domain_match_accepts_exact_san() {
        let cached = cached_with_cert_info("b.com", Some("a.com"), vec!["b.com"]);
        assert!(cert_info_matches_domain(&cached));
    }

    #[test]
    fn cert_info_domain_match_rejects_wrong_san() {
        let cached = cached_with_cert_info("b.com", Some("b.com"), vec!["a.com"]);
        assert!(!cert_info_matches_domain(&cached));
    }

    #[test]
    fn cert_info_domain_match_accepts_single_label_wildcard_san() {
        let cached = cached_with_cert_info("api.b.com", None, vec!["*.b.com"]);
        assert!(cert_info_matches_domain(&cached));
    }

    #[test]
    fn cert_info_domain_match_rejects_multi_label_wildcard_san() {
        let cached = cached_with_cert_info("deep.api.b.com", None, vec!["*.b.com"]);
        assert!(!cert_info_matches_domain(&cached));
    }

    #[tokio::test]
    async fn default_profile_domains_reports_only_unprepared_entries() {
        let domains = vec!["ready.example".to_string(), "pending.example".to_string()];
        let cache = TlsFrontCache::new(&domains, 1024, "tlsfront-test-cache");
        cache
            .set(
                "ready.example",
                cached_with_cert_info("ready.example", None, Vec::new()),
            )
            .await;

        assert_eq!(
            cache.default_profile_domains(&domains).await,
            vec!["pending.example".to_string()]
        );
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_uses_ttl() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let ttl = Duration::from_millis(80);

        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", ip, ttl)
                .await
        );
        assert!(
            !cache
                .take_full_cert_budget_for_ip("example.com", ip, ttl)
                .await
        );

        tokio::time::sleep(Duration::from_millis(90)).await;

        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", ip, ttl)
                .await
        );
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_zero_ttl_always_allows_full_payload() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let ttl = Duration::ZERO;

        for idx in 0..100_000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                ((idx >> 16) & 0xff) as u8,
                ((idx >> 8) & 0xff) as u8,
                (idx & 0xff) as u8,
            ));
            assert!(
                cache
                    .take_full_cert_budget_for_ip("example.com", ip, ttl)
                    .await
            );
        }

        assert!(cache.full_cert_sent_is_empty_for_tests().await);
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_sweeps_expired_entries_when_due() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let stale_ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let new_ip: IpAddr = "127.0.0.2".parse().expect("ip");
        let ttl = Duration::from_secs(1);
        let stale_expires_at = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        cache
            .insert_full_cert_sent_for_tests("example.com", stale_ip, stale_expires_at)
            .await;
        let stale_key = FullCertBudgetKey {
            domain: cache.full_cert_domain_key("example.com"),
            client_ip: stale_ip,
        };
        cache.full_cert_budget.sweep_cursor.store(
            cache.full_cert_budget.shard_index(&stale_key),
            Ordering::Relaxed,
        );
        cache
            .full_cert_budget
            .last_sweep_epoch_secs
            .store(0, Ordering::Relaxed);

        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", new_ip, ttl)
                .await
        );

        assert!(
            !cache
                .full_cert_sent_contains_for_tests("example.com", stale_ip)
                .await
        );
        assert!(
            cache
                .full_cert_sent_contains_for_tests("example.com", new_ip)
                .await
        );
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_does_not_sweep_every_call() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let stale_ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let new_ip: IpAddr = "127.0.0.2".parse().expect("ip");
        let ttl = Duration::from_secs(1);
        let stale_expires_at = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        cache
            .insert_full_cert_sent_for_tests("example.com", stale_ip, stale_expires_at)
            .await;
        cache
            .full_cert_budget
            .last_sweep_epoch_secs
            .store(now_epoch_secs, Ordering::Relaxed);

        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", new_ip, ttl)
                .await
        );

        assert!(
            cache
                .full_cert_sent_contains_for_tests("example.com", stale_ip)
                .await
        );
        assert!(
            cache
                .full_cert_sent_contains_for_tests("example.com", new_ip)
                .await
        );
    }

    #[tokio::test]
    async fn full_cert_budget_is_shared_across_cache_generations_and_scoped_by_domain() {
        let budget = Arc::new(TlsFullCertBudget::new());
        let domains = ["one.example".to_string(), "two.example".to_string()];
        let first = TlsFrontCache::new_with_full_cert_budget(
            &domains,
            1024,
            "tlsfront-test-cache",
            budget.clone(),
        );
        let second = TlsFrontCache::new_with_full_cert_budget(
            &domains,
            1024,
            "tlsfront-test-cache",
            budget,
        );
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let ttl = Duration::from_secs(60);

        assert!(
            first
                .take_full_cert_budget_for_ip("one.example", ip, ttl)
                .await
        );
        assert!(
            !second
                .take_full_cert_budget_for_ip("one.example", ip, ttl)
                .await
        );
        assert!(
            second
                .take_full_cert_budget_for_ip("two.example", ip, ttl)
                .await
        );
        assert_eq!(second.full_cert_budget_entries_for_metrics(), 2);
    }

    #[tokio::test]
    async fn existing_full_cert_entry_keeps_its_own_expiry_after_ttl_change() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");

        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", ip, Duration::from_millis(80))
                .await
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !cache
                .take_full_cert_budget_for_ip("example.com", ip, Duration::from_millis(1))
                .await
        );
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", ip, Duration::from_millis(1))
                .await
        );
    }

    #[tokio::test]
    async fn disk_reader_rejects_an_entry_above_the_hard_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.json");
        tokio::fs::write(
            &path,
            vec![0u8; TLS_FRONT_DISK_ENTRY_MAX_BYTES as usize + 1],
        )
        .await
        .unwrap();

        let error = read_disk_entry_bounded(&path).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn disk_loader_does_not_follow_a_configured_name_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("outside.json");
        let cached = cached_with_cert_info("example.com", None, Vec::new());
        tokio::fs::write(&target, serde_json::to_vec(&cached).unwrap())
            .await
            .unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join("example.com.json")).unwrap();
        let cache = TlsFrontCache::new(
            &["example.com".to_string()],
            1024,
            directory.path(),
        );

        cache.load_from_disk().await;

        assert_eq!(cache.get("example.com").await.domain, "default");
    }
}
