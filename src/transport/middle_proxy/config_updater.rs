use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use httpdate;
use tracing::{debug, info, warn};

use crate::error::Result;

use super::MePool;
use super::secret::download_proxy_secret;
use crate::crypto::SecureRandom;
use std::time::SystemTime;

#[derive(Debug, Clone, Default)]
pub struct ProxyConfigData {
    pub map: HashMap<i32, Vec<(IpAddr, u16)>>,
    pub default_dc: Option<i32>,
}

pub async fn fetch_proxy_config(url: &str) -> Result<ProxyConfigData> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| crate::error::ProxyError::Proxy(format!("fetch_proxy_config GET failed: {e}")))?
        ;

    if let Some(date) = resp.headers().get(reqwest::header::DATE) {
        if let Ok(date_str) = date.to_str() {
            if let Ok(server_time) = httpdate::parse_http_date(date_str) {
                if let Ok(skew) = SystemTime::now().duration_since(server_time).or_else(|e| {
                    server_time.duration_since(SystemTime::now()).map_err(|_| e)
                }) {
                    let skew_secs = skew.as_secs();
                    if skew_secs > 60 {
                        warn!(skew_secs, "Time skew >60s detected from fetch_proxy_config Date header");
                    } else if skew_secs > 30 {
                        warn!(skew_secs, "Time skew >30s detected from fetch_proxy_config Date header");
                    }
                }
            }
        }
    }

    let text = resp
        .text()
        .await
        .map_err(|e| crate::error::ProxyError::Proxy(format!("fetch_proxy_config read failed: {e}")))?;

    // Matches both IPv4 `host:port` and IPv6 `[host]:port` formats
    let re_proxy = Regex::new(r"proxy_for\s+(-?\d+)\s+\[?([^\]\s]+)\]?:(\d+)\s*;").unwrap();
    let re_default = Regex::new(r"default\s+(-?\d+)\s*;").unwrap();

    let mut map: HashMap<i32, Vec<(IpAddr, u16)>> = HashMap::new();
    for cap in re_proxy.captures_iter(&text) {
        if let (Some(dc), Some(host), Some(port)) = (cap.get(1), cap.get(2), cap.get(3)) {
            if let Ok(dc_idx) = dc.as_str().parse::<i32>() {
                if let Ok(ip) = host.as_str().parse::<IpAddr>() {
                    if let Ok(port_num) = port.as_str().parse::<u16>() {
                        map.entry(dc_idx).or_default().push((ip, port_num));
                    }
                }
            }
        }
    }

    let default_dc = re_default
        .captures(&text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i32>().ok());

    Ok(ProxyConfigData { map, default_dc })
}

pub async fn me_config_updater(pool: Arc<MePool>, rng: Arc<SecureRandom>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    // skip immediate tick to avoid double-fetch right after startup
    tick.tick().await;
    loop {
        tick.tick().await;

        // Update proxy config v4
        if let Ok(cfg) = fetch_proxy_config("https://core.telegram.org/getProxyConfig").await {
            let changed = pool.update_proxy_maps(cfg.map.clone(), None).await;
            if let Some(dc) = cfg.default_dc {
                pool.default_dc.store(dc, std::sync::atomic::Ordering::Relaxed);
            }
            if changed {
                info!("ME config updated (v4), reconciling connections");
                pool.reconcile_connections(&rng).await;
            } else {
                debug!("ME config v4 unchanged");
            }
        } else {
            warn!("getProxyConfig update failed");
        }

        // Update proxy config v6 (optional)
        if let Ok(cfg_v6) = fetch_proxy_config("https://core.telegram.org/getProxyConfigV6").await {
            let _ = pool.update_proxy_maps(HashMap::new(), Some(cfg_v6.map)).await;
        }

        // Update proxy-secret
        match download_proxy_secret().await {
            Ok(secret) => {
                if pool.update_secret(secret).await {
                    info!("proxy-secret updated and pool reconnect scheduled");
                }
            }
            Err(e) => warn!(error = %e, "proxy-secret update failed"),
        }
    }
}
