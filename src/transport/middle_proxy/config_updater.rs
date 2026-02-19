use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use httpdate;
use tracing::{debug, info, warn};

use crate::error::Result;

use super::MePool;
use super::secret::download_proxy_secret;
use crate::crypto::SecureRandom;
use std::time::SystemTime;

async fn retry_fetch(url: &str) -> Option<ProxyConfigData> {
    let delays = [1u64, 5, 15];
    for (i, d) in delays.iter().enumerate() {
        match fetch_proxy_config(url).await {
            Ok(cfg) => return Some(cfg),
            Err(e) => {
                if i == delays.len() - 1 {
                    warn!(error = %e, url, "fetch_proxy_config failed");
                } else {
                    debug!(error = %e, url, "fetch_proxy_config retrying");
                    tokio::time::sleep(Duration::from_secs(*d)).await;
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct ProxyConfigData {
    pub map: HashMap<i32, Vec<(IpAddr, u16)>>,
    pub default_dc: Option<i32>,
}

fn parse_host_port(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(bracket_end) = s.rfind(']') {
        if s.starts_with('[') && bracket_end + 1 < s.len() && s.as_bytes().get(bracket_end + 1) == Some(&b':') {
            let host = &s[1..bracket_end];
            let port_str = &s[bracket_end + 2..];
            let ip = host.parse::<IpAddr>().ok()?;
            let port = port_str.parse::<u16>().ok()?;
            return Some((ip, port));
        }
    }

    let idx = s.rfind(':')?;
    let host = &s[..idx];
    let port_str = &s[idx + 1..];
    let ip = host.parse::<IpAddr>().ok()?;
    let port = port_str.parse::<u16>().ok()?;
    Some((ip, port))
}

fn parse_proxy_line(line: &str) -> Option<(i32, IpAddr, u16)> {
    // Accepts lines like:
    // proxy_for 4 91.108.4.195:8888;
    // proxy_for 2 [2001:67c:04e8:f002::d]:80;
    // proxy_for 2 2001:67c:04e8:f002::d:80;
    let trimmed = line.trim();
    if !trimmed.starts_with("proxy_for") {
        return None;
    }
    // Capture everything between dc and trailing ';'
    let without_prefix = trimmed.trim_start_matches("proxy_for").trim();
    let mut parts = without_prefix.split_whitespace();
    let dc_str = parts.next()?;
    let rest = parts.next()?;
    let host_port = rest.trim_end_matches(';');
    let dc = dc_str.parse::<i32>().ok()?;
    let (ip, port) = parse_host_port(host_port)?;
    Some((dc, ip, port))
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

    let mut map: HashMap<i32, Vec<(IpAddr, u16)>> = HashMap::new();
    for line in text.lines() {
        if let Some((dc, ip, port)) = parse_proxy_line(line) {
            map.entry(dc).or_default().push((ip, port));
        }
    }

    let default_dc = text
        .lines()
        .find_map(|l| {
            let t = l.trim();
            if let Some(rest) = t.strip_prefix("default") {
                return rest
                    .trim()
                    .trim_end_matches(';')
                    .parse::<i32>()
                    .ok();
            }
            None
        });

    Ok(ProxyConfigData { map, default_dc })
}

pub async fn me_config_updater(pool: Arc<MePool>, rng: Arc<SecureRandom>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    // skip immediate tick to avoid double-fetch right after startup
    tick.tick().await;
    loop {
        tick.tick().await;

        // Update proxy config v4
        let cfg_v4 = retry_fetch("https://core.telegram.org/getProxyConfig").await;
        if let Some(cfg) = cfg_v4 {
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
        }

        // Update proxy config v6 (optional)
        let cfg_v6 = retry_fetch("https://core.telegram.org/getProxyConfigV6").await;
        if let Some(cfg_v6) = cfg_v6 {
            let changed = pool.update_proxy_maps(HashMap::new(), Some(cfg_v6.map)).await;
            if changed {
                info!("ME config updated (v6), reconciling connections");
                pool.reconcile_connections(&rng).await;
            } else {
                debug!("ME config v6 unchanged");
            }
        }
        pool.reset_stun_state();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv6_bracketed() {
        let line = "proxy_for 2 [2001:67c:04e8:f002::d]:80;";
        let res = parse_proxy_line(line).unwrap();
        assert_eq!(res.0, 2);
        assert_eq!(res.1, "2001:67c:04e8:f002::d".parse::<IpAddr>().unwrap());
        assert_eq!(res.2, 80);
    }

    #[test]
    fn parse_ipv6_plain() {
        let line = "proxy_for 2 2001:67c:04e8:f002::d:80;";
        let res = parse_proxy_line(line).unwrap();
        assert_eq!(res.0, 2);
        assert_eq!(res.1, "2001:67c:04e8:f002::d".parse::<IpAddr>().unwrap());
        assert_eq!(res.2, 80);
    }

    #[test]
    fn parse_ipv4() {
        let line = "proxy_for 4 91.108.4.195:8888;";
        let res = parse_proxy_line(line).unwrap();
        assert_eq!(res.0, 4);
        assert_eq!(res.1, "91.108.4.195".parse::<IpAddr>().unwrap());
        assert_eq!(res.2, 8888);
    }
}
