use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, warn, info};

use crate::tls_front::types::{CachedTlsData, ParsedServerHello, TlsFetchResult};

// Hard limits for CachedTlsData fields loaded from disk to prevent OOM from malicious
// or corrupted cache files. A compromised upstream TLS server could otherwise push an
// oversized cert payload that causes ensure_payload_capacity to allocate thousands of
// record-size slots and build a 50+ MB fake TLS response per connection.
const MAX_CERT_MESSAGE_LEN: usize = 131_072;   // 128 KB
const MAX_CERT_CHAIN_TOTAL: usize = 262_144;   // 256 KB
const MAX_SAN_NAMES_COUNT: usize = 64;
const MAX_APP_DATA_RECORDS: usize = 32;

// Maximum number of distinct source IPs tracked for full-cert-payload rate limiting.
// Beyond this cap new IPs are granted unconditionally (fail-open) to prevent OOM
// under an IP-flood attack. The retain() O(n) scan is bounded to at most this many
// entries per call.
pub(crate) const FULL_CERT_SENT_IP_CAP: usize = 100_000;

// retain() scans the entire IP map (O(n)). With 100 000 entries an adversarial
// connection flood calling retain on every request would dominate CPU.
// Throttle the scan to at most once per TTL/10, capped at 1 s, so the map stays
// reasonably fresh while the per-request overhead remains bounded.
const FULL_CERT_RETAIN_DIVISOR: u128 = 10;
const FULL_CERT_RETAIN_CAP_MS: u64 = 1_000;

/// Lightweight in-memory + optional on-disk cache for TLS fronting data.
#[derive(Debug)]
pub struct TlsFrontCache {
    memory: RwLock<HashMap<String, Arc<CachedTlsData>>>,
    default: Arc<CachedTlsData>,
    full_cert_sent: RwLock<HashMap<IpAddr, Instant>>,
    // Epoch-ms timestamp of the last retain() scan; used by the throttle in
    // take_full_cert_budget_for_ip to avoid O(n) work on every request.
    full_cert_sent_last_retain_ms: AtomicU64,
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
            full_cert_sent: RwLock::new(HashMap::new()),
            full_cert_sent_last_retain_ms: AtomicU64::new(0),
            disk_path: disk_path.as_ref().to_path_buf(),
        }
    }

    pub async fn get(&self, sni: &str) -> Arc<CachedTlsData> {
        let guard = self.memory.read().await;
        guard.get(sni).cloned().unwrap_or_else(|| self.default.clone())
    }

    pub async fn contains_domain(&self, domain: &str) -> bool {
        self.memory.read().await.contains_key(domain)
    }

/// Returns true when full cert payload should be sent for `client_ip`
    /// according to TTL policy.
    pub async fn take_full_cert_budget_for_ip(
        &self,
        client_ip: IpAddr,
        ttl: Duration,
    ) -> bool {
        // Zero TTL means: always grant full payload with no rate-limiting.
        // Do not touch the map — there is nothing to expire and no budget to track.
        if ttl.is_zero() {
            return true;
        }

        let now = Instant::now();
        let mut guard = self.full_cert_sent.write().await;

        // Throttle O(n) retain scan: run at most once per ttl/10, capped at 1 s.
        // With FULL_CERT_SENT_IP_CAP = 100 000 entries, calling retain on every
        // request at high connection rates would burn unbounded CPU.
        let retain_interval_ms = (ttl.as_millis() / FULL_CERT_RETAIN_DIVISOR)
            .min(u128::from(FULL_CERT_RETAIN_CAP_MS)) as u64;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last_retain_ms = self.full_cert_sent_last_retain_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_retain_ms) >= retain_interval_ms {
            guard.retain(|_, seen_at| now.duration_since(*seen_at) < ttl);
            self.full_cert_sent_last_retain_ms.store(now_ms, Ordering::Relaxed);
        }

        match guard.get(&client_ip) {
            // IP already has an active budget entry — suppress the full payload.
            Some(_) => false,
            None => {
                // Fail-open when the map is at capacity: grant the full payload without
                // inserting, so an IP flood cannot grow the map without bound. An
                // attacker achieving this gets more cert payloads, not a DoS.
                if guard.len() < FULL_CERT_SENT_IP_CAP {
                    guard.insert(client_ip, now);
                }
                true
            }
        }
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
                            || !cached.domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                        {
                            warn!(file = %name, "Skipping TLS cache entry with invalid domain");
                            continue;
                        }
                        // Reject entries whose payload fields exceed hard limits to prevent
                        // OOM from malicious or corrupted cache files. A compromised upstream
                        // server could push a 50 MB cert payload that causes the emulator to
                        // allocate thousands of record slots and build a 50+ MB response.
                        if let Some(ref cp) = cached.cert_payload {
                            if cp.certificate_message.len() > MAX_CERT_MESSAGE_LEN {
                                warn!(domain = %cached.domain, "Skipping TLS cache entry: cert_message exceeds 128 KB");
                                continue;
                            }
                            let chain_total: usize = cp.cert_chain_der.iter().map(Vec::len).sum();
                            if chain_total > MAX_CERT_CHAIN_TOTAL {
                                warn!(domain = %cached.domain, "Skipping TLS cache entry: cert_chain total exceeds 256 KB");
                                continue;
                            }
                        }
                        if let Some(ref ci) = cached.cert_info
                            && ci.san_names.len() > MAX_SAN_NAMES_COUNT
                        {
                            warn!(domain = %cached.domain, "Skipping TLS cache entry: san_names exceeds 64 entries");
                            continue;
                        }
                        if cached.app_data_records_sizes.len() > MAX_APP_DATA_RECORDS {
                            warn!(domain = %cached.domain, "Skipping TLS cache entry: app_data_records_sizes exceeds 32 entries");
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
        // Validate domain with the same rules used in load_from_disk to prevent
        // unexpected filenames being written to the cache directory.
        if domain.is_empty()
            || domain.len() > 255
            || !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return;
        }
        if tokio::fs::create_dir_all(&self.disk_path).await.is_err() {
            return;
        }
        let fname = format!("{}.json", domain);
        let path = self.disk_path.join(fname);
        if let Ok(json) = serde_json::to_vec_pretty(data) {
            // best-effort write
            let _ = tokio::fs::write(path, json).await;
        }
    }

    /// Spawn background updater that periodically refreshes cached domains using provided fetcher.
    pub fn spawn_updater<F>(
        self: Arc<Self>,
        domains: Vec<String>,
        interval: Duration,
        fetcher: F,
    ) where
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
        // Apply the same field-size limits as load_from_disk. A MITM or BGP-hijacked
        // upstream domain can serve oversized cert payloads; without this guard, an
        // uncapped 50 MB certificate_message propagates into ensure_payload_capacity,
        // which loops ~3 000 times and emits ~50 MB per subsequent emulated response.
        if let Some(ref cp) = fetched.cert_payload {
            if cp.certificate_message.len() > MAX_CERT_MESSAGE_LEN {
                warn!(domain = %domain, "Rejecting fetched TLS data: cert_message exceeds 128 KB");
                return;
            }
            let chain_total: usize = cp.cert_chain_der.iter().map(Vec::len).sum();
            if chain_total > MAX_CERT_CHAIN_TOTAL {
                warn!(domain = %domain, "Rejecting fetched TLS data: cert_chain total exceeds 256 KB");
                return;
            }
        }
        if let Some(ref ci) = fetched.cert_info
            && ci.san_names.len() > MAX_SAN_NAMES_COUNT
        {
            warn!(domain = %domain, "Rejecting fetched TLS data: san_names exceeds 64 entries");
            return;
        }
        if fetched.app_data_records_sizes.len() > MAX_APP_DATA_RECORDS {
            warn!(domain = %domain, "Rejecting fetched TLS data: app_data_records_sizes exceeds 32 entries");
            return;
        }

        let data = CachedTlsData {
            server_hello_template: fetched.server_hello_parsed,
            cert_info: fetched.cert_info,
            cert_payload: fetched.cert_payload,
            app_data_records_sizes: fetched.app_data_records_sizes.clone(),
            total_app_data_len: fetched.total_app_data_len,
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

    #[cfg(test)]
    async fn full_cert_sent_map_len(&self) -> usize {
        self.full_cert_sent.read().await.len()
    }

    /// Directly pre-fills the internal rate-limit map for testing cap enforcement.
    /// Bypasses the FULL_CERT_SENT_IP_CAP guard intentionally to set up boundary tests.
    #[cfg(test)]
    async fn fill_cert_sent_map_for_test(&self, count: usize) {
        let mut guard = self.full_cert_sent.write().await;
        let now = Instant::now();
        for i in 0..count as u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i));
            guard.insert(ip, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_front::types::{ParsedCertificateInfo, TlsCertPayload};

    fn make_cached_data(domain: &str) -> CachedTlsData {
        use crate::tls_front::types::ParsedServerHello;
        CachedTlsData {
            server_hello_template: ParsedServerHello {
                version: [0x03, 0x03],
                random: [0u8; 32],
                session_id: Vec::new(),
                cipher_suite: [0x13, 0x01],
                compression: 0,
                extensions: Vec::new(),
            },
            cert_info: None,
            cert_payload: None,
            app_data_records_sizes: vec![1024],
            total_app_data_len: 1024,
            fetched_at: std::time::SystemTime::now(),
            domain: domain.to_string(),
        }
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_uses_ttl() {
        let cache = TlsFrontCache::new(
            &["example.com".to_string()],
            1024,
            "tlsfront-test-cache",
        );
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let ttl = Duration::from_millis(80);

        assert!(cache
            .take_full_cert_budget_for_ip(ip, ttl)
            .await);
        assert!(!cache
            .take_full_cert_budget_for_ip(ip, ttl)
            .await);

        tokio::time::sleep(Duration::from_millis(90)).await;

        assert!(cache
            .take_full_cert_budget_for_ip(ip, ttl)
            .await);
    }

    #[tokio::test]
    async fn test_take_full_cert_budget_for_ip_zero_ttl_always_allows_full_payload() {
        let cache = TlsFrontCache::new(
            &["example.com".to_string()],
            1024,
            "tlsfront-test-cache",
        );
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let ttl = Duration::ZERO;

        assert!(cache
            .take_full_cert_budget_for_ip(ip, ttl)
            .await);
        assert!(cache
            .take_full_cert_budget_for_ip(ip, ttl)
            .await);
    }

    #[tokio::test]
    async fn take_full_cert_budget_zero_ttl_does_not_grow_internal_map() {
        // With the old code, every zero-TTL call inserted into the map without
        // ever calling retain, causing unbounded memory growth under an IP flood.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-zero-ttl-leak-test");

        for i in 0u8..=255 {
            let ip = IpAddr::from([10, 0, 0, i]);
            assert!(cache.take_full_cert_budget_for_ip(ip, Duration::ZERO).await);
        }

        assert_eq!(
            cache.full_cert_sent_map_len().await,
            0,
            "zero TTL must not insert into the map"
        );
    }

    #[tokio::test]
    async fn take_full_cert_budget_multiple_ips_each_granted_once_per_ttl() {
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-multi-ip-test");
        let ttl = Duration::from_secs(3600);

        for i in 0u8..10 {
            let ip = IpAddr::from([10, 0, 0, i]);
            assert!(
                cache.take_full_cert_budget_for_ip(ip, ttl).await,
                "first grant denied for ip {i}"
            );
            assert!(
                !cache.take_full_cert_budget_for_ip(ip, ttl).await,
                "second call not suppressed for ip {i}"
            );
        }
        assert_eq!(cache.full_cert_sent_map_len().await, 10);
    }

    #[tokio::test]
    async fn take_full_cert_budget_retain_clears_expired_ips() {
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-retain-test");
        let ttl = Duration::from_millis(30);

        for i in 0u8..5 {
            let ip = IpAddr::from([192, 168, 0, i]);
            assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        }
        assert_eq!(cache.full_cert_sent_map_len().await, 5);

        tokio::time::sleep(Duration::from_millis(60)).await;

        // Any new call triggers retain, removing all 5 expired entries.
        let new_ip: IpAddr = "192.168.1.0".parse().expect("ip");
        assert!(cache.take_full_cert_budget_for_ip(new_ip, ttl).await);
        assert_eq!(
            cache.full_cert_sent_map_len().await,
            1,
            "all 5 expired entries must be swept; only the new IP remains"
        );
    }

    #[tokio::test]
    async fn take_full_cert_budget_ipv6_works_correctly() {
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-ipv6-test");
        let ip: IpAddr = "::1".parse().expect("ipv6");
        let ttl = Duration::from_secs(60);

        assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        assert!(!cache.take_full_cert_budget_for_ip(ip, ttl).await);
    }

    #[tokio::test]
    async fn take_full_cert_budget_ip_still_blocked_before_ttl_expires() {
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-boundary-test");
        let ip: IpAddr = "172.16.0.1".parse().expect("ip");
        let ttl = Duration::from_millis(100);

        assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        // Sleep for less than TTL — the budget must not be re-granted.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!cache.take_full_cert_budget_for_ip(ip, ttl).await);
    }

    #[tokio::test]
    async fn take_full_cert_budget_re_grant_occurs_after_ttl() {
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-regrant-test");
        let ip: IpAddr = "172.16.0.2".parse().expect("ip");
        let ttl = Duration::from_millis(40);

        assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            cache.take_full_cert_budget_for_ip(ip, ttl).await,
            "must re-grant after TTL expires"
        );
    }

    #[tokio::test]
    async fn persist_rejects_domain_with_path_separator() {
        let dir = std::env::temp_dir().join("tlsfront-persist-sep-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&[], 1024, &dir);

        // Domains with '/' would produce filenames that naively traverse directories
        // when joined; the validation must reject them before any write.
        let data = make_cached_data("../evil");
        cache.persist("../evil", &data).await;

        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            let mut unexpected = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                unexpected.push(entry.path());
            }
            assert!(unexpected.is_empty(), "persist must write nothing for invalid domain '../evil', found: {:?}", unexpected);
        }
    }

    #[tokio::test]
    async fn persist_rejects_empty_domain() {
        let dir = std::env::temp_dir().join("tlsfront-persist-empty-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&[], 1024, &dir);

        let data = make_cached_data("");
        cache.persist("", &data).await;

        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            let mut unexpected = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                unexpected.push(entry.path());
            }
            assert!(unexpected.is_empty(), "persist wrote a file for an empty domain: {:?}", unexpected);
        }
    }

    #[tokio::test]
    async fn persist_rejects_domain_with_over_255_chars() {
        let dir = std::env::temp_dir().join("tlsfront-persist-long-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&[], 1024, &dir);

        let long_domain = "a".repeat(256);
        let data = make_cached_data(&long_domain);
        cache.persist(&long_domain, &data).await;

        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            let mut unexpected = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                unexpected.push(entry.path());
            }
            assert!(unexpected.is_empty(), "persist wrote a file for a 256-char domain: {:?}", unexpected);
        }
    }

    #[tokio::test]
    async fn persist_writes_valid_domain() {
        let dir = std::env::temp_dir().join("tlsfront-persist-valid-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&[], 1024, &dir);

        let data = make_cached_data("example.com");
        cache.persist("example.com", &data).await;

        let file = dir.join("example.com.json");
        assert!(file.exists(), "persist must write example.com.json for a valid domain");
    }

    // ---- N-4: full_cert_sent IP-flood cap tests ----

    #[tokio::test]
    async fn take_full_cert_budget_ip_cap_is_respected_fail_open() {
        // Pre-fill map to exactly FULL_CERT_SENT_IP_CAP entries, then verify that
        // one more IP is granted (fail-open) without growing the map past the cap.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-cap-fail-open-test");
        cache.fill_cert_sent_map_for_test(FULL_CERT_SENT_IP_CAP).await;
        assert_eq!(cache.full_cert_sent_map_len().await, FULL_CERT_SENT_IP_CAP);

        let overflow_ip = IpAddr::V4(std::net::Ipv4Addr::from(FULL_CERT_SENT_IP_CAP as u32));
        let ttl = Duration::from_secs(3600);
        let granted = cache.take_full_cert_budget_for_ip(overflow_ip, ttl).await;
        assert!(granted, "beyond-cap IP must be granted full cert payload (fail-open)");
        assert_eq!(
            cache.full_cert_sent_map_len().await,
            FULL_CERT_SENT_IP_CAP,
            "map must not grow past FULL_CERT_SENT_IP_CAP",
        );
    }

    #[tokio::test]
    async fn take_full_cert_budget_ip_cap_does_not_affect_suppression_of_known_ip() {
        // An IP already in the map must still be suppressed even when map is at cap.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-cap-suppress-test");
        let ttl = Duration::from_secs(3600);
        let known_ip: IpAddr = "10.0.0.1".parse().expect("ip");

        assert!(cache.take_full_cert_budget_for_ip(known_ip, ttl).await, "first grant");
        // Fill remaining slots with other IPs (known_ip = 167772161 >> 99999, no collision).
        cache.fill_cert_sent_map_for_test(FULL_CERT_SENT_IP_CAP - 1).await;
        assert_eq!(cache.full_cert_sent_map_len().await, FULL_CERT_SENT_IP_CAP);

        assert!(
            !cache.take_full_cert_budget_for_ip(known_ip, ttl).await,
            "known IP must still be suppressed when map is at cap",
        );
    }

    #[tokio::test]
    async fn take_full_cert_budget_ip_cap_flood_with_zero_ttl_never_grows_map() {
        // Zero TTL bypasses the map entirely; a flood of distinct IPs must not fill it.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-zero-ttl-cap-test");
        for i in 0..(FULL_CERT_SENT_IP_CAP + 100) as u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i));
            assert!(cache.take_full_cert_budget_for_ip(ip, Duration::ZERO).await);
        }
        assert_eq!(cache.full_cert_sent_map_len().await, 0, "zero TTL must leave map empty");
    }

    // ---- O-1: load_from_disk field-size validation tests ----

    #[tokio::test]
    async fn load_from_disk_rejects_oversized_cert_message() {
        let dir = std::env::temp_dir().join("tlsfront-oversize-cert-msg-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let mut data = make_cached_data("oversize-cert.example.com");
        data.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![],
            certificate_message: vec![0u8; MAX_CERT_MESSAGE_LEN + 1],
        });
        let bytes = serde_json::to_vec(&data).unwrap();
        tokio::fs::write(dir.join("oversize-cert.example.com.json"), bytes).await.unwrap();

        let cache = TlsFrontCache::new(&[], 1024, &dir);
        cache.load_from_disk().await;
        assert!(
            !cache.contains_domain("oversize-cert.example.com").await,
            "entry with certificate_message > 128 KB must be rejected on load",
        );
    }

    #[tokio::test]
    async fn load_from_disk_rejects_oversized_cert_chain() {
        let dir = std::env::temp_dir().join("tlsfront-oversize-cert-chain-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let mut data = make_cached_data("oversize-chain.example.com");
        data.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![vec![0u8; MAX_CERT_CHAIN_TOTAL + 1]],
            certificate_message: vec![],
        });
        let bytes = serde_json::to_vec(&data).unwrap();
        tokio::fs::write(dir.join("oversize-chain.example.com.json"), bytes).await.unwrap();

        let cache = TlsFrontCache::new(&[], 1024, &dir);
        cache.load_from_disk().await;
        assert!(
            !cache.contains_domain("oversize-chain.example.com").await,
            "entry with cert_chain_der total > 256 KB must be rejected on load",
        );
    }

    #[tokio::test]
    async fn load_from_disk_rejects_too_many_san_names() {
        let dir = std::env::temp_dir().join("tlsfront-too-many-san-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let mut data = make_cached_data("many-san.example.com");
        data.cert_info = Some(ParsedCertificateInfo {
            not_after_unix: None,
            not_before_unix: None,
            issuer_cn: None,
            subject_cn: None,
            san_names: (0..=MAX_SAN_NAMES_COUNT)
                .map(|i| format!("sub{i}.example.com"))
                .collect(),
        });
        let bytes = serde_json::to_vec(&data).unwrap();
        tokio::fs::write(dir.join("many-san.example.com.json"), bytes).await.unwrap();

        let cache = TlsFrontCache::new(&[], 1024, &dir);
        cache.load_from_disk().await;
        assert!(
            !cache.contains_domain("many-san.example.com").await,
            "entry with san_names count > 64 must be rejected on load",
        );
    }

    #[tokio::test]
    async fn load_from_disk_rejects_too_many_app_data_records() {
        let dir = std::env::temp_dir().join("tlsfront-too-many-records-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let mut data = make_cached_data("many-records.example.com");
        data.app_data_records_sizes = vec![1024usize; MAX_APP_DATA_RECORDS + 1];
        let bytes = serde_json::to_vec(&data).unwrap();
        tokio::fs::write(dir.join("many-records.example.com.json"), bytes).await.unwrap();

        let cache = TlsFrontCache::new(&[], 1024, &dir);
        cache.load_from_disk().await;
        assert!(
            !cache.contains_domain("many-records.example.com").await,
            "entry with app_data_records_sizes len > 32 must be rejected on load",
        );
    }

    #[tokio::test]
    async fn load_from_disk_accepts_entry_within_all_field_bounds() {
        let dir = std::env::temp_dir().join("tlsfront-valid-bounds-test");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let mut data = make_cached_data("valid-bounds.example.com");
        data.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![vec![0u8; 2048]],
            certificate_message: vec![0u8; 4096],
        });
        data.cert_info = Some(ParsedCertificateInfo {
            not_after_unix: Some(1_900_000_000),
            not_before_unix: Some(1_700_000_000),
            issuer_cn: Some("Test CA".to_string()),
            subject_cn: Some("valid-bounds.example.com".to_string()),
            san_names: vec!["valid-bounds.example.com".to_string()],
        });
        data.app_data_records_sizes = vec![1024; 4];
        let bytes = serde_json::to_vec(&data).unwrap();
        tokio::fs::write(dir.join("valid-bounds.example.com.json"), bytes).await.unwrap();

        let cache = TlsFrontCache::new(&[], 1024, &dir);
        cache.load_from_disk().await;
        assert!(
            cache.contains_domain("valid-bounds.example.com").await,
            "valid entry within all field bounds must be loaded from disk",
        );
    }

    #[tokio::test]
    async fn load_from_disk_rejects_cert_message_exactly_at_limit_plus_one() {
        // Boundary: MAX_CERT_MESSAGE_LEN bytes must be accepted; +1 must be rejected.
        let dir_ok = std::env::temp_dir().join("tlsfront-cert-msg-at-limit-ok");
        let dir_bad = std::env::temp_dir().join("tlsfront-cert-msg-at-limit-bad");
        let _ = tokio::fs::remove_dir_all(&dir_ok).await;
        let _ = tokio::fs::remove_dir_all(&dir_bad).await;
        tokio::fs::create_dir_all(&dir_ok).await.unwrap();
        tokio::fs::create_dir_all(&dir_bad).await.unwrap();

        let mut ok_data = make_cached_data("certlimit-ok.example.com");
        ok_data.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![],
            certificate_message: vec![0u8; MAX_CERT_MESSAGE_LEN],
        });
        tokio::fs::write(
            dir_ok.join("certlimit-ok.example.com.json"),
            serde_json::to_vec(&ok_data).unwrap(),
        ).await.unwrap();

        let mut bad_data = make_cached_data("certlimit-bad.example.com");
        bad_data.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![],
            certificate_message: vec![0u8; MAX_CERT_MESSAGE_LEN + 1],
        });
        tokio::fs::write(
            dir_bad.join("certlimit-bad.example.com.json"),
            serde_json::to_vec(&bad_data).unwrap(),
        ).await.unwrap();

        let cache_ok = TlsFrontCache::new(&[], 1024, &dir_ok);
        cache_ok.load_from_disk().await;
        assert!(cache_ok.contains_domain("certlimit-ok.example.com").await, "MAX bytes must be accepted");

        let cache_bad = TlsFrontCache::new(&[], 1024, &dir_bad);
        cache_bad.load_from_disk().await;
        assert!(!cache_bad.contains_domain("certlimit-bad.example.com").await, "MAX+1 bytes must be rejected");
    }

    // ---- N-1: retain() throttle tests ----

    fn make_fetch_result_valid() -> TlsFetchResult {
        TlsFetchResult {
            server_hello_parsed: ParsedServerHello {
                version: [0x03, 0x03],
                random: [0u8; 32],
                session_id: vec![],
                cipher_suite: [0x13, 0x01],
                compression: 0,
                extensions: vec![],
            },
            app_data_records_sizes: vec![1024],
            total_app_data_len: 1024,
            cert_info: None,
            cert_payload: None,
        }
    }

    #[tokio::test]
    async fn retain_throttle_does_not_block_suppression_of_known_ip() {
        // Even when retain is throttled (< interval since last run), a known IP must still
        // be suppressed by the Some(_) => false branch. The throttle only skips the O(n)
        // scan; it must not affect per-IP lookup correctness.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-throttle-suppress-test");
        let ttl = Duration::from_secs(3600); // throttle = 360 s → will not fire mid-test
        let ip: IpAddr = "10.10.10.10".parse().expect("ip");

        assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await, "first call must grant");
        // Rapid calls: retain throttled, but the HashMap lookup path still returns Some(_).
        for _ in 0..200 {
            assert!(
                !cache.take_full_cert_budget_for_ip(ip, ttl).await,
                "all subsequent rapid calls must be suppressed regardless of retain throttle",
            );
        }
    }

    #[tokio::test]
    async fn retain_throttle_distinct_ips_all_inserted_correctly() {
        // Simulates 500 rapid distinct-IP calls. Without throttle, retain would run 500
        // times; with throttle only the first call runs it. Correctness of insertions must
        // not be affected.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-throttle-bulk-test");
        let ttl = Duration::from_secs(3600);

        for i in 0u32..500 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i + 1));
            assert!(
                cache.take_full_cert_budget_for_ip(ip, ttl).await,
                "distinct IP {i} must be granted",
            );
        }
        assert_eq!(cache.full_cert_sent_map_len().await, 500);

        // Verify each IP is now blocked (still within TTL).
        for i in 0u32..500 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i + 1));
            assert!(
                !cache.take_full_cert_budget_for_ip(ip, ttl).await,
                "IP {i} must be suppressed on second call",
            );
        }
    }

    #[tokio::test]
    async fn retain_throttle_expired_entries_eventually_cleared_after_interval() {
        // Verify that once the throttle interval passes, expired entries are cleared.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-throttle-clear-test");
        // TTL=50ms → throttle = max(50/10, 0) = 5 ms.
        let ttl = Duration::from_millis(50);

        for i in 0u8..5 {
            let ip = IpAddr::from([172, 20, 0, i]);
            assert!(cache.take_full_cert_budget_for_ip(ip, ttl).await);
        }
        assert_eq!(cache.full_cert_sent_map_len().await, 5);

        // Sleep 3× TTL to ensure both TTL expiry AND throttle interval have passed.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let new_ip: IpAddr = "172.20.1.0".parse().expect("ip");
        assert!(cache.take_full_cert_budget_for_ip(new_ip, ttl).await);
        assert_eq!(
            cache.full_cert_sent_map_len().await,
            1,
            "all 5 expired entries must be swept after throttle-interval expires",
        );
    }

    #[tokio::test]
    async fn retain_throttle_with_zero_ttl_leaves_map_empty_even_with_many_ips() {
        // Zero TTL must bypass retain entirely; the throttle path is never reached.
        let cache = TlsFrontCache::new(&[], 1024, "tlsfront-zero-ttl-throttle-test");
        for i in 0u32..1000 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i));
            assert!(cache.take_full_cert_budget_for_ip(ip, Duration::ZERO).await);
        }
        assert_eq!(cache.full_cert_sent_map_len().await, 0);
    }

    // ---- N-2: update_from_fetch payload-size validation tests ----

    #[tokio::test]
    async fn update_from_fetch_rejects_oversized_cert_message() {
        // A MITM upstream that serves a 50 MB cert bypasses load_from_disk guards if
        // update_from_fetch has no caps. The cache entry must remain unchanged.
        let dir = std::env::temp_dir().join("tlsfront-update-oversize-msg");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&["victim.example.com".to_string()], 512, &dir);
        let orig_len = cache.get("victim.example.com").await.total_app_data_len;

        let mut r = make_fetch_result_valid();
        r.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![],
            certificate_message: vec![0u8; MAX_CERT_MESSAGE_LEN + 1],
        });
        cache.update_from_fetch("victim.example.com", r).await;

        assert_eq!(
            cache.get("victim.example.com").await.total_app_data_len,
            orig_len,
            "cache must NOT be updated when cert_message > 128 KB",
        );
    }

    #[tokio::test]
    async fn update_from_fetch_rejects_oversized_cert_chain() {
        let dir = std::env::temp_dir().join("tlsfront-update-oversize-chain");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&["chain.example.com".to_string()], 512, &dir);
        let orig_len = cache.get("chain.example.com").await.total_app_data_len;

        let mut r = make_fetch_result_valid();
        r.cert_payload = Some(TlsCertPayload {
            // Single DER blob larger than MAX_CERT_CHAIN_TOTAL.
            cert_chain_der: vec![vec![0u8; MAX_CERT_CHAIN_TOTAL + 1]],
            certificate_message: vec![],
        });
        cache.update_from_fetch("chain.example.com", r).await;

        assert_eq!(
            cache.get("chain.example.com").await.total_app_data_len,
            orig_len,
            "cache must NOT be updated when cert_chain total > 256 KB",
        );
    }

    #[tokio::test]
    async fn update_from_fetch_rejects_excessive_san_names() {
        let dir = std::env::temp_dir().join("tlsfront-update-san-count");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&["san.example.com".to_string()], 512, &dir);
        let orig_len = cache.get("san.example.com").await.total_app_data_len;

        let mut r = make_fetch_result_valid();
        r.cert_info = Some(ParsedCertificateInfo {
            not_after_unix: None,
            not_before_unix: None,
            issuer_cn: None,
            subject_cn: None,
            san_names: (0..=MAX_SAN_NAMES_COUNT)
                .map(|i| format!("s{i}.example.com"))
                .collect(),
        });
        cache.update_from_fetch("san.example.com", r).await;

        assert_eq!(
            cache.get("san.example.com").await.total_app_data_len,
            orig_len,
            "cache must NOT be updated when san_names > 64",
        );
    }

    #[tokio::test]
    async fn update_from_fetch_rejects_too_many_app_data_records() {
        let dir = std::env::temp_dir().join("tlsfront-update-records-count");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&["recs.example.com".to_string()], 512, &dir);
        let orig_len = cache.get("recs.example.com").await.total_app_data_len;

        let mut r = make_fetch_result_valid();
        r.app_data_records_sizes = vec![1024usize; MAX_APP_DATA_RECORDS + 1];
        cache.update_from_fetch("recs.example.com", r).await;

        assert_eq!(
            cache.get("recs.example.com").await.total_app_data_len,
            orig_len,
            "cache must NOT be updated when app_data_records_sizes > 32",
        );
    }

    #[tokio::test]
    async fn update_from_fetch_accepts_valid_payload_within_all_bounds() {
        let dir = std::env::temp_dir().join("tlsfront-update-valid");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&["ok.example.com".to_string()], 512, &dir);

        let mut r = make_fetch_result_valid();
        r.total_app_data_len = 8192;
        r.app_data_records_sizes = vec![4096, 4096];
        r.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![vec![0u8; 4096]],
            certificate_message: vec![0u8; 4096],
        });
        r.cert_info = Some(ParsedCertificateInfo {
            not_after_unix: Some(1_900_000_000),
            not_before_unix: Some(1_700_000_000),
            issuer_cn: Some("Test CA".to_string()),
            subject_cn: Some("ok.example.com".to_string()),
            san_names: vec!["ok.example.com".to_string()],
        });
        cache.update_from_fetch("ok.example.com", r).await;

        assert_eq!(
            cache.get("ok.example.com").await.total_app_data_len,
            8192,
            "valid in-bounds fetch result must be stored",
        );
    }

    #[tokio::test]
    async fn update_from_fetch_oversized_payload_does_not_write_to_disk() {
        // Ensure the rejected payload is also NOT persisted to disk (no side-channel).
        let dir = std::env::temp_dir().join("tlsfront-update-no-disk-write");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let cache = TlsFrontCache::new(&[], 512, &dir);

        let mut r = make_fetch_result_valid();
        r.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![],
            certificate_message: vec![0u8; MAX_CERT_MESSAGE_LEN + 1],
        });
        cache.update_from_fetch("nodisk.example.com", r).await;

        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            let mut unexpected = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                unexpected.push(entry.path());
            }
            assert!(
                unexpected.is_empty(),
                "update_from_fetch must not write to disk for rejected payload, found: {:?}",
                unexpected
            );
        }
    }

    #[tokio::test]
    async fn update_from_fetch_cert_message_at_exact_limit_is_accepted() {
        // Boundary: exactly MAX_CERT_MESSAGE_LEN bytes must be accepted (not rejected).
        let dir = std::env::temp_dir().join("tlsfront-update-exact-limit");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let cache = TlsFrontCache::new(&["limit.example.com".to_string()], 512, &dir);

        let mut r = make_fetch_result_valid();
        r.total_app_data_len = MAX_CERT_MESSAGE_LEN;
        r.cert_payload = Some(TlsCertPayload {
            cert_chain_der: vec![],
            certificate_message: vec![0u8; MAX_CERT_MESSAGE_LEN],
        });
        cache.update_from_fetch("limit.example.com", r).await;

        assert_eq!(
            cache.get("limit.example.com").await.total_app_data_len,
            MAX_CERT_MESSAGE_LEN,
            "cert_message of exactly MAX_CERT_MESSAGE_LEN bytes must be accepted",
        );
    }
}
