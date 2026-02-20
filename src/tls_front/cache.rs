use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, Duration};

use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, warn, info};

use crate::tls_front::types::{CachedTlsData, ParsedServerHello, TlsFetchResult};

/// Lightweight in-memory + optional on-disk cache for TLS fronting data.
#[derive(Debug)]
pub struct TlsFrontCache {
    memory: RwLock<HashMap<String, Arc<CachedTlsData>>>,
    default: Arc<CachedTlsData>,
    disk_path: PathBuf,
}

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
            disk_path: disk_path.as_ref().to_path_buf(),
        }
    }

    pub async fn get(&self, sni: &str) -> Arc<CachedTlsData> {
        let guard = self.memory.read().await;
        guard.get(sni).cloned().unwrap_or_else(|| self.default.clone())
    }

    pub async fn set(&self, domain: &str, data: CachedTlsData) {
        let mut guard = self.memory.write().await;
        guard.insert(domain.to_string(), Arc::new(data));
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
                    fetcher(domain.clone()).await;
                }
                sleep(interval).await;
            }
        });
    }

    /// Replace cached entry from a fetch result.
    pub async fn update_from_fetch(&self, domain: &str, fetched: TlsFetchResult) {
        let data = CachedTlsData {
            server_hello_template: fetched.server_hello_parsed,
            cert_info: None,
            app_data_records_sizes: fetched.app_data_records_sizes.clone(),
            total_app_data_len: fetched.total_app_data_len,
            fetched_at: SystemTime::now(),
            domain: domain.to_string(),
        };

        self.set(domain, data).await;
        debug!(domain = %domain, len = fetched.total_app_data_len, "TLS cache updated");
    }

    pub fn default_entry(&self) -> Arc<CachedTlsData> {
        self.default.clone()
    }

    pub fn disk_path(&self) -> &Path {
        &self.disk_path
    }
}
