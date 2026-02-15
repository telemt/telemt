use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use tracing::{debug, info, warn};

use crate::error::Result;

use super::MePool;
use super::secret::download_proxy_secret;

#[derive(Debug, Clone, Default)]
pub struct ProxyConfigData {
    pub map: HashMap<i32, Vec<(IpAddr, u16)>>,
    pub default_dc: Option<i32>,
}

pub async fn fetch_proxy_config(url: &str) -> Result<ProxyConfigData> {
    let text = reqwest::get(url)
        .await
        .map_err(|e| crate::error::ProxyError::Proxy(format!("fetch_proxy_config GET failed: {e}")))?
        .text()
        .await
        .map_err(|e| crate::error::ProxyError::Proxy(format!("fetch_proxy_config read failed: {e}")))?;

    let re_proxy = Regex::new(r"proxy_for\s+(-?\d+)\s+([^\s:]+):(\d+)\s*;").unwrap();
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

pub async fn me_config_updater(pool: Arc<MePool>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;

        // Update proxy config v4
        if let Ok(cfg) = fetch_proxy_config("https://core.telegram.org/getProxyConfig").await {
            let changed = pool.update_proxy_maps(cfg.map.clone(), None).await;
            if let Some(dc) = cfg.default_dc {
                pool.default_dc.store(dc, std::sync::atomic::Ordering::Relaxed);
            }
            if changed {
                info!("ME config updated (v4)");
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
