//! Runtime configuration for Middle Proxy
//!
//! Manages:
//! - PROXY_SECRET (initial hardcoded + periodic updates from Telegram)
//! - Middle proxy DC address lists (v4 / v6, periodic updates)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use regex::Regex;
use tracing::{debug, info, warn, error};

// ============= Initial Proxy Secret =============

/// Hardcoded initial proxy secret (128 bytes).
/// Updated at runtime from `https://core.telegram.org/getProxySecret`.
const INITIAL_PROXY_SECRET_HEX: &str = concat!(
    "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721",
    "d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698",
    "6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c",
    "54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212",
);

const PROXY_SECRET_URL: &str = "https://core.telegram.org/getProxySecret";
const PROXY_CONFIG_V4_URL: &str = "https://core.telegram.org/getProxyConfig";
const PROXY_CONFIG_V6_URL: &str = "https://core.telegram.org/getProxyConfigV6";

/// Default update interval for DC lists and secret (24 hours)
const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// HTTP request timeout
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

// ============= MiddleProxyConfig =============

/// Thread-safe runtime configuration for middle proxy connections.
#[derive(Clone)]
pub struct MiddleProxyConfig {
    proxy_secret: Arc<RwLock<Vec<u8>>>,
    middle_proxies_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    middle_proxies_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
}

impl MiddleProxyConfig {
    /// Create with hardcoded defaults.
    pub fn new() -> Self {
        let secret = hex::decode(INITIAL_PROXY_SECRET_HEX)
            .expect("hardcoded proxy secret is valid hex");

        Self {
            proxy_secret: Arc::new(RwLock::new(secret)),
            middle_proxies_v4: Arc::new(RwLock::new(
                crate::protocol::constants::TG_MIDDLE_PROXIES_V4.clone(),
            )),
            middle_proxies_v6: Arc::new(RwLock::new(
                crate::protocol::constants::TG_MIDDLE_PROXIES_V6.clone(),
            )),
        }
    }

    /// Get a snapshot of the current proxy secret.
    pub async fn get_proxy_secret(&self) -> Vec<u8> {
        self.proxy_secret.read().await.clone()
    }

    /// Get key_selector (first 4 bytes of proxy secret).
    pub async fn get_key_selector(&self) -> [u8; 4] {
        let secret = self.proxy_secret.read().await;
        let mut sel = [0u8; 4];
        sel.copy_from_slice(&secret[..4]);
        sel
    }

    /// Pick a random middle-proxy address for the given DC index.
    pub async fn get_middle_proxy_addr(
        &self,
        dc_idx: i32,
        prefer_ipv6: bool,
        rng: &crate::crypto::SecureRandom,
    ) -> Option<(IpAddr, u16)> {
        if prefer_ipv6 {
            let map = self.middle_proxies_v6.read().await;
            if let Some(addrs) = map.get(&dc_idx) {
                if !addrs.is_empty() {
                    return rng.choose(addrs).copied();
                }
            }
        }
        let map = self.middle_proxies_v4.read().await;
        map.get(&dc_idx).and_then(|addrs| rng.choose(addrs).copied())
    }

    /// Get all known DC indices from the v4 map.
    pub async fn known_dc_indices(&self) -> Vec<i32> {
        self.middle_proxies_v4.read().await.keys().copied().collect()
    }

    // ============= Background Update Loop =============

    pub async fn run_update_loop(&self) {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            self.update_proxy_secret().await;
            self.update_dc_list_v4().await;
            self.update_dc_list_v6().await;
            tokio::time::sleep(DEFAULT_UPDATE_INTERVAL).await;
        }
    }

    async fn update_proxy_secret(&self) {
        match fetch_bytes(PROXY_SECRET_URL).await {
            Ok(new_secret) if !new_secret.is_empty() => {
                let mut current = self.proxy_secret.write().await;
                if *current != new_secret {
                    info!(len = new_secret.len(), "Middle proxy secret updated");
                    *current = new_secret;
                } else {
                    debug!("Middle proxy secret unchanged");
                }
            }
            Ok(_) => warn!("Empty proxy secret received, keeping old"),
            Err(e) => warn!("Failed to update proxy secret: {}", e),
        }
    }

    async fn update_dc_list_v4(&self) {
        match fetch_and_parse_dc_list(PROXY_CONFIG_V4_URL).await {
            Ok(new_map) if !new_map.is_empty() => {
                let total_addrs: usize = new_map.values().map(|v| v.len()).sum();
                let mut current = self.middle_proxies_v4.write().await;
                info!(dcs = new_map.len(), addrs = total_addrs, "Updated middle proxy IPv4 list");
                *current = new_map;
            }
            Ok(_) => warn!("Empty IPv4 DC list received, keeping old"),
            Err(e) => warn!("Failed to update IPv4 DC list: {}", e),
        }
    }

    async fn update_dc_list_v6(&self) {
        match fetch_and_parse_dc_list(PROXY_CONFIG_V6_URL).await {
            Ok(new_map) if !new_map.is_empty() => {
                let total_addrs: usize = new_map.values().map(|v| v.len()).sum();
                let mut current = self.middle_proxies_v6.write().await;
                info!(dcs = new_map.len(), addrs = total_addrs, "Updated middle proxy IPv6 list");
                *current = new_map;
            }
            Ok(_) => warn!("Empty IPv6 DC list received, keeping old"),
            Err(e) => warn!("Failed to update IPv6 DC list: {}", e),
        }
    }
}

impl Default for MiddleProxyConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============= HTTP Helpers =============

async fn fetch_bytes(url: &str) -> std::result::Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read body: {}", e))
}

async fn fetch_and_parse_dc_list(
    url: &str,
) -> std::result::Result<HashMap<i32, Vec<(IpAddr, u16)>>, String> {
    let body_bytes = fetch_bytes(url).await?;
    let body = String::from_utf8_lossy(&body_bytes);
    parse_dc_list(&body)
}

/// Parse `proxy_for <dc_idx> <host>:<port>;` lines from config text.
///
/// Ignores comment lines (`#`), `default` directives, and anything else
/// that doesn't match the `proxy_for` pattern. Multiple addresses per
/// DC index are accumulated into vectors.
fn parse_dc_list(
    text: &str,
) -> std::result::Result<HashMap<i32, Vec<(IpAddr, u16)>>, String> {
    let re = Regex::new(r"proxy_for\s+(-?\d+)\s+(.+):(\d+)\s*;")
        .map_err(|e| format!("regex error: {}", e))?;

    let mut result: HashMap<i32, Vec<(IpAddr, u16)>> = HashMap::new();

    for cap in re.captures_iter(text) {
        let dc_idx: i32 = cap[1].parse().unwrap_or(0);
        let mut host = cap[2].to_string();
        let port: u16 = cap[3].parse().unwrap_or(0);

        // Strip brackets from IPv6: [::1] -> ::1
        if host.starts_with('[') && host.ends_with(']') {
            host = host[1..host.len() - 1].to_string();
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            result.entry(dc_idx).or_default().push((ip, port));
        }
    }

    Ok(result)
}

// ============= Tests =============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_secret_length() {
        let secret = hex::decode(INITIAL_PROXY_SECRET_HEX).unwrap();
        assert_eq!(secret.len(), 128);
    }

    /// Test with the exact getProxyConfig response from core.telegram.org
    #[test]
    fn test_parse_real_proxy_config() {
        let real_config = r#"
# force_probability 10 10
default 2;
proxy_for 1 149.154.175.50:8888;
proxy_for -1 149.154.175.50:8888;
proxy_for 2 149.154.161.144:8888;
proxy_for -2 149.154.161.144:8888;
proxy_for 3 149.154.175.100:8888;
proxy_for -3 149.154.175.100:8888;
proxy_for 4 91.108.4.159:8888;
proxy_for 4 91.108.4.224:8888;
proxy_for 4 91.108.4.156:8888;
proxy_for 4 91.108.4.135:8888;
proxy_for 4 91.108.4.134:8888;
proxy_for 4 91.108.4.189:8888;
proxy_for 4 91.108.4.139:8888;
proxy_for 4 91.108.4.171:8888;
proxy_for 4 91.108.4.180:8888;
proxy_for 4 91.108.4.214:8888;
proxy_for -4 149.154.165.250:8888;
proxy_for -4 149.154.165.109:8888;
proxy_for 5 91.108.56.176:8888;
proxy_for 5 91.108.56.146:8888;
proxy_for -5 91.108.56.176:8888;
proxy_for -5 91.108.56.146:8888;
"#;

        let map = parse_dc_list(real_config).unwrap();

        // Total: 12 unique DC indices
        assert_eq!(map.len(), 12);

        // DC1, DC-1: 1 address each
        assert_eq!(map[&1].len(), 1);
        assert_eq!(map[&-1].len(), 1);
        assert_eq!(map[&1][0].0.to_string(), "149.154.175.50");
        assert_eq!(map[&1][0].1, 8888);

        // DC2, DC-2: 1 address each
        assert_eq!(map[&2].len(), 1);
        assert_eq!(map[&-2].len(), 1);

        // DC3, DC-3: 1 address each
        assert_eq!(map[&3].len(), 1);
        assert_eq!(map[&-3].len(), 1);

        // DC4: 10 addresses (load balanced!)
        assert_eq!(map[&4].len(), 10);
        assert_eq!(map[&4][0].0.to_string(), "91.108.4.159");
        assert_eq!(map[&4][9].0.to_string(), "91.108.4.214");

        // DC-4: 2 addresses
        assert_eq!(map[&-4].len(), 2);

        // DC5, DC-5: 2 addresses each
        assert_eq!(map[&5].len(), 2);
        assert_eq!(map[&-5].len(), 2);

        // Total addresses
        let total: usize = map.values().map(|v| v.len()).sum();
        assert_eq!(total, 22);

        // Comment, default, empty lines — all ignored
        // (no panic, no extra entries)
    }

    #[test]
    fn test_parse_dc_list_v6() {
        let text = r#"
proxy_for 1 [2001:b28:f23d:f001::d]:8888;
proxy_for 2 [2001:67c:04e8:f002::d]:80;
"#;
        let map = parse_dc_list(text).unwrap();
        assert_eq!(map.len(), 2);
        assert!(map[&1][0].0.is_ipv6());
        assert_eq!(map[&2][0].1, 80);
    }

    #[test]
    fn test_parse_dc_list_empty() {
        let map = parse_dc_list("# only comments\ndefault 2;\n").unwrap();
        assert!(map.is_empty());
    }

    #[tokio::test]
    async fn test_config_default() {
        let cfg = MiddleProxyConfig::new();
        let secret = cfg.get_proxy_secret().await;
        assert_eq!(secret.len(), 128);
        let sel = cfg.get_key_selector().await;
        assert_eq!(sel, [0xc4, 0xf9, 0xfa, 0xca]);
    }
}