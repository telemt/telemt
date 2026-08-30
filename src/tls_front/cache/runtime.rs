use std::path::Path;

use tokio::time::sleep;
use tracing::{debug, info, warn};

use super::*;
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

    pub(super) fn full_cert_domain_key(&self, domain: &str) -> Arc<str> {
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
    pub(super) async fn insert_full_cert_sent_for_tests(
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
    pub(super) async fn full_cert_sent_is_empty_for_tests(&self) -> bool {
        for shard in &self.full_cert_budget.shards {
            if !shard.read().await.is_empty() {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    pub(super) async fn full_cert_sent_contains_for_tests(
        &self,
        domain: &str,
        client_ip: IpAddr,
    ) -> bool {
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
