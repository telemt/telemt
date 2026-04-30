use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::tls_front::types::{
    CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsFetchResult,
};

const FULL_CERT_SENT_SWEEP_INTERVAL_SECS: u64 = 30;
const FULL_CERT_SENT_MAX_IPS: usize = 65_536;
const FULL_CERT_SENT_SHARDS: usize = 64;

static FULL_CERT_SENT_IPS_GAUGE: AtomicU64 = AtomicU64::new(0);
static FULL_CERT_SENT_CAP_DROPS: AtomicU64 = AtomicU64::new(0);

/// Current number of IPs tracked by the TLS full-cert budget gate.
pub(crate) fn full_cert_sent_ips_for_metrics() -> u64 {
    FULL_CERT_SENT_IPS_GAUGE.load(Ordering::Relaxed)
}

/// Number of new IPs denied a full-cert budget slot because the cap was reached.
pub(crate) fn full_cert_sent_cap_drops_for_metrics() -> u64 {
    FULL_CERT_SENT_CAP_DROPS.load(Ordering::Relaxed)
}

/// Lightweight in-memory + optional on-disk cache for TLS fronting data.
#[derive(Debug)]
pub struct TlsFrontCache {
    memory: RwLock<HashMap<String, Arc<CachedTlsData>>>,
    default: Arc<CachedTlsData>,
    full_cert_sent_shards: Vec<RwLock<HashMap<IpAddr, Instant>>>,
    full_cert_sent_last_sweep_epoch_secs: AtomicU64,
    disk_path: PathBuf,
}

#[allow(dead_code)]
impl TlsFrontCache {
    pub fn new(domains: &[String], default_len: usize, disk_path: impl AsRef<Path>) -> Self {
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
        for d in domains {
            map.insert(d.clone(), default.clone());
        }

        Self {
            memory: RwLock::new(map),
            default,
            full_cert_sent_shards: (0..FULL_CERT_SENT_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            full_cert_sent_last_sweep_epoch_secs: AtomicU64::new(0),
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

    fn full_cert_sent_shard_index(client_ip: IpAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        client_ip.hash(&mut hasher);
        (hasher.finish() as usize) % FULL_CERT_SENT_SHARDS
    }

    fn full_cert_sent_shard(&self, client_ip: IpAddr) -> &RwLock<HashMap<IpAddr, Instant>> {
        &self.full_cert_sent_shards[Self::full_cert_sent_shard_index(client_ip)]
    }

    fn decrement_full_cert_sent_entries(amount: usize) {
        if amount == 0 {
            return;
        }
        let amount = amount as u64;
        let _ =
            FULL_CERT_SENT_IPS_GAUGE.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(amount))
            });
    }

    fn try_reserve_full_cert_sent_entry() -> bool {
        let mut current = FULL_CERT_SENT_IPS_GAUGE.load(Ordering::Relaxed);
        loop {
            if current >= FULL_CERT_SENT_MAX_IPS as u64 {
                return false;
            }
            match FULL_CERT_SENT_IPS_GAUGE.compare_exchange_weak(
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

    async fn sweep_full_cert_sent_shards(&self, now: Instant, ttl: Duration) {
        for shard in &self.full_cert_sent_shards {
            let mut guard = shard.write().await;
            let before = guard.len();
            guard.retain(|_, seen_at| now.duration_since(*seen_at) < ttl);
            Self::decrement_full_cert_sent_entries(before.saturating_sub(guard.len()));
        }
    }

    /// Returns true when full cert payload should be sent for client_ip
    /// according to TTL policy.
    pub async fn take_full_cert_budget_for_ip(&self, client_ip: IpAddr, ttl: Duration) -> bool {
        if ttl.is_zero() {
            return true;
        }

        let now = Instant::now();
        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let should_sweep = self
            .full_cert_sent_last_sweep_epoch_secs
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |last_sweep| {
                if now_epoch_secs.saturating_sub(last_sweep) >= FULL_CERT_SENT_SWEEP_INTERVAL_SECS {
                    Some(now_epoch_secs)
                } else {
                    None
                }
            })
            .is_ok();

        if should_sweep {
            self.sweep_full_cert_sent_shards(now, ttl).await;
        }

        let mut guard = self.full_cert_sent_shard(client_ip).write().await;
        let allowed = match guard.get_mut(&client_ip) {
            Some(seen_at) => {
                if now.duration_since(*seen_at) >= ttl {
                    *seen_at = now;
                    true
                } else {
                    false
                }
            }
            None => {
                if !Self::try_reserve_full_cert_sent_entry() {
                    FULL_CERT_SENT_CAP_DROPS.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                guard.insert(client_ip, now);
                true
            }
        };
        allowed
    }

    #[cfg(test)]
    async fn insert_full_cert_sent_for_tests(&self, client_ip: IpAddr, seen_at: Instant) {
        let mut guard = self.full_cert_sent_shard(client_ip).write().await;
        if guard.insert(client_ip, seen_at).is_none() {
            FULL_CERT_SENT_IPS_GAUGE.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    async fn full_cert_sent_is_empty_for_tests(&self) -> bool {
        for shard in &self.full_cert_sent_shards {
            if !shard.read().await.is_empty() {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    async fn full_cert_sent_contains_for_tests(&self, client_ip: IpAddr) -> bool {
        self.full_cert_sent_shard(client_ip)
            .read()
            .await
            .contains_key(&client_ip)
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
        if let Ok(mut dir) = tokio::fs::read_dir(&path).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Ok(name) = entry.file_name().into_string() {
                    if !name.ends_with(".json") {
                        continue;
                    }
                    if let Ok(data) = tokio::fs::read(entry.path()).await
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
                        if !cert_info_matches_domain(&cached) {
                            warn!(
                                file = %name,
                                domain = %cached.domain,
                                "Skipping TLS cache entry with mismatched certificate metadata"
                            );
                            continue;
                        }
                        // fetched_at is skipped during deserialization; approximate with file mtime if available.
                        if let Ok(meta) = entry.metadata().await
                            && let Ok(modified) = meta.modified()
                        {
                            cached.fetched_at = modified;
                        }
                        // Drop entries older than 72h
                        if let Ok(age) = cached.fetched_at.elapsed()
                            && age > Duration::from_secs(72 * 3600)
                        {
                            warn!(domain = %cached.domain, "Skipping stale TLS cache entry (>72h)");
                            continue;
                        }
                        let domain = cached.domain.clone();
                        self.set(&domain, cached).await;
                        loaded += 1;
                    }
                }
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
        let data = CachedTlsData {
            server_hello_template: fetched.server_hello_parsed,
            cert_info: fetched.cert_info,
            cert_payload: fetched.cert_payload,
            app_data_records_sizes: fetched.app_data_records_sizes.clone(),
            total_app_data_len: fetched.total_app_data_len,
            behavior_profile: fetched.behavior_profile,
            fetched_at: SystemTime::now(),
            domain: domain.to_string(),
        };

        self.set(domain, data.clone()).await;
        self.persist(domain, &data).await;
        debug!(domain = %domain, len = fetched.total_app_data_len, "TLS cache updated");
    }

    pub fn default_entry(&self) -> Arc<CachedTlsData> {
        self.default.clone()
    }

    pub fn disk_path(&self) -> &Path {
        &self.disk_path
    }
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
    async fn test_take_full_cert_budget_for_ip_uses_ttl() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let ttl = Duration::from_millis(80);

        assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        assert!(!cache.take_full_cert_budget_for_ip(ip, ttl).await);

        tokio::time::sleep(Duration::from_millis(90)).await;

        assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
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
            assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        }

        assert!(cache.full_cert_sent_is_empty_for_tests().await);
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_sweeps_expired_entries_when_due() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let stale_ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let new_ip: IpAddr = "127.0.0.2".parse().expect("ip");
        let ttl = Duration::from_secs(1);
        let stale_seen_at = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .unwrap_or_else(Instant::now);

        cache
            .insert_full_cert_sent_for_tests(stale_ip, stale_seen_at)
            .await;
        cache
            .full_cert_sent_last_sweep_epoch_secs
            .store(0, Ordering::Relaxed);

        assert!(cache.take_full_cert_budget_for_ip(new_ip, ttl).await);

        assert!(!cache.full_cert_sent_contains_for_tests(stale_ip).await);
        assert!(cache.full_cert_sent_contains_for_tests(new_ip).await);
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_does_not_sweep_every_call() {
        let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
        let stale_ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let new_ip: IpAddr = "127.0.0.2".parse().expect("ip");
        let ttl = Duration::from_secs(1);
        let stale_seen_at = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .unwrap_or_else(Instant::now);
        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        cache
            .insert_full_cert_sent_for_tests(stale_ip, stale_seen_at)
            .await;
        cache
            .full_cert_sent_last_sweep_epoch_secs
            .store(now_epoch_secs, Ordering::Relaxed);

        assert!(cache.take_full_cert_budget_for_ip(new_ip, ttl).await);

        assert!(cache.full_cert_sent_contains_for_tests(stale_ip).await);
        assert!(cache.full_cert_sent_contains_for_tests(new_ip).await);
    }
}
