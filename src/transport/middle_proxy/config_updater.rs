use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use httpdate;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::error::Result;

use super::MePool;
use super::secret::download_proxy_secret_with_max_len;
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

#[derive(Debug, Default)]
struct StableSnapshot {
    candidate_hash: Option<u64>,
    candidate_hits: u8,
    applied_hash: Option<u64>,
}

impl StableSnapshot {
    fn observe(&mut self, hash: u64) -> u8 {
        if self.candidate_hash == Some(hash) {
            self.candidate_hits = self.candidate_hits.saturating_add(1);
        } else {
            self.candidate_hash = Some(hash);
            self.candidate_hits = 1;
        }
        self.candidate_hits
    }

    fn is_applied(&self, hash: u64) -> bool {
        self.applied_hash == Some(hash)
    }

    fn mark_applied(&mut self, hash: u64) {
        self.applied_hash = Some(hash);
    }
}

#[derive(Debug, Default)]
struct UpdaterState {
    config_v4: StableSnapshot,
    config_v6: StableSnapshot,
    secret: StableSnapshot,
    last_map_apply_at: Option<tokio::time::Instant>,
}

fn hash_proxy_config(cfg: &ProxyConfigData) -> u64 {
    let mut hasher = DefaultHasher::new();
    cfg.default_dc.hash(&mut hasher);

    let mut by_dc: Vec<(i32, Vec<(IpAddr, u16)>)> =
        cfg.map.iter().map(|(dc, addrs)| (*dc, addrs.clone())).collect();
    by_dc.sort_by_key(|(dc, _)| *dc);
    for (dc, mut addrs) in by_dc {
        dc.hash(&mut hasher);
        addrs.sort_unstable();
        for (ip, port) in addrs {
            ip.hash(&mut hasher);
            port.hash(&mut hasher);
        }
    }

    hasher.finish()
}

fn hash_secret(secret: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    secret.hash(&mut hasher);
    hasher.finish()
}

fn map_apply_cooldown_ready(
    last_applied: Option<tokio::time::Instant>,
    cooldown: Duration,
) -> bool {
    if cooldown.is_zero() {
        return true;
    }
    match last_applied {
        Some(ts) => ts.elapsed() >= cooldown,
        None => true,
    }
}

fn map_apply_cooldown_remaining_secs(
    last_applied: tokio::time::Instant,
    cooldown: Duration,
) -> u64 {
    if cooldown.is_zero() {
        return 0;
    }
    cooldown
        .checked_sub(last_applied.elapsed())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_host_port(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(bracket_end) = s.rfind(']')
        && s.starts_with('[')
        && bracket_end + 1 < s.len()
        && s.as_bytes().get(bracket_end + 1) == Some(&b':')
    {
        let host = &s[1..bracket_end];
        let port_str = &s[bracket_end + 2..];
        let ip = host.parse::<IpAddr>().ok()?;
        let port = port_str.parse::<u16>().ok()?;
        return Some((ip, port));
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

    if let Some(date) = resp.headers().get(reqwest::header::DATE)
        && let Ok(date_str) = date.to_str()
        && let Ok(server_time) = httpdate::parse_http_date(date_str)
        && let Ok(skew) = SystemTime::now().duration_since(server_time).or_else(|e| {
            server_time.duration_since(SystemTime::now()).map_err(|_| e)
        })
    {
        let skew_secs = skew.as_secs();
        if skew_secs > 60 {
            warn!(skew_secs, "Time skew >60s detected from fetch_proxy_config Date header");
        } else if skew_secs > 30 {
            warn!(skew_secs, "Time skew >30s detected from fetch_proxy_config Date header");
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

async fn run_update_cycle(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    cfg: &ProxyConfig,
    state: &mut UpdaterState,
) {
    pool.update_runtime_reinit_policy(
        cfg.general.hardswap,
        cfg.general.me_pool_drain_ttl_secs,
        cfg.general.effective_me_pool_force_close_secs(),
        cfg.general.me_pool_min_fresh_ratio,
        cfg.general.me_hardswap_warmup_delay_min_ms,
        cfg.general.me_hardswap_warmup_delay_max_ms,
        cfg.general.me_hardswap_warmup_extra_passes,
        cfg.general.me_hardswap_warmup_pass_backoff_base_ms,
    );

    let required_cfg_snapshots = cfg.general.me_config_stable_snapshots.max(1);
    let required_secret_snapshots = cfg.general.proxy_secret_stable_snapshots.max(1);
    let apply_cooldown = Duration::from_secs(cfg.general.me_config_apply_cooldown_secs);
    let mut maps_changed = false;

    let mut ready_v4: Option<(ProxyConfigData, u64)> = None;
    let cfg_v4 = retry_fetch("https://core.telegram.org/getProxyConfig").await;
    if let Some(cfg_v4) = cfg_v4 {
        let cfg_v4_hash = hash_proxy_config(&cfg_v4);
        let stable_hits = state.config_v4.observe(cfg_v4_hash);
        if stable_hits < required_cfg_snapshots {
            debug!(
                stable_hits,
                required_cfg_snapshots,
                snapshot = format_args!("0x{cfg_v4_hash:016x}"),
                "ME config v4 candidate observed"
            );
        } else if state.config_v4.is_applied(cfg_v4_hash) {
            debug!(
                snapshot = format_args!("0x{cfg_v4_hash:016x}"),
                "ME config v4 stable snapshot already applied"
            );
        } else {
            ready_v4 = Some((cfg_v4, cfg_v4_hash));
        }
    }

    let mut ready_v6: Option<(ProxyConfigData, u64)> = None;
    let cfg_v6 = retry_fetch("https://core.telegram.org/getProxyConfigV6").await;
    if let Some(cfg_v6) = cfg_v6 {
        let cfg_v6_hash = hash_proxy_config(&cfg_v6);
        let stable_hits = state.config_v6.observe(cfg_v6_hash);
        if stable_hits < required_cfg_snapshots {
            debug!(
                stable_hits,
                required_cfg_snapshots,
                snapshot = format_args!("0x{cfg_v6_hash:016x}"),
                "ME config v6 candidate observed"
            );
        } else if state.config_v6.is_applied(cfg_v6_hash) {
            debug!(
                snapshot = format_args!("0x{cfg_v6_hash:016x}"),
                "ME config v6 stable snapshot already applied"
            );
        } else {
            ready_v6 = Some((cfg_v6, cfg_v6_hash));
        }
    }

    if ready_v4.is_some() || ready_v6.is_some() {
        if map_apply_cooldown_ready(state.last_map_apply_at, apply_cooldown) {
            let update_v4 = ready_v4
                .as_ref()
                .map(|(snapshot, _)| snapshot.map.clone())
                .unwrap_or_default();
            let update_v6 = ready_v6
                .as_ref()
                .map(|(snapshot, _)| snapshot.map.clone());

            let changed = pool.update_proxy_maps(update_v4, update_v6).await;

            if let Some((snapshot, hash)) = ready_v4 {
                if let Some(dc) = snapshot.default_dc {
                    pool.default_dc
                        .store(dc, std::sync::atomic::Ordering::Relaxed);
                }
                state.config_v4.mark_applied(hash);
            }

            if let Some((_snapshot, hash)) = ready_v6 {
                state.config_v6.mark_applied(hash);
            }

            state.last_map_apply_at = Some(tokio::time::Instant::now());

            if changed {
                maps_changed = true;
                info!("ME config update applied after stable-gate");
            } else {
                debug!("ME config stable-gate applied with no map delta");
            }
        } else if let Some(last) = state.last_map_apply_at {
            let wait_secs = map_apply_cooldown_remaining_secs(last, apply_cooldown);
            debug!(
                wait_secs,
                "ME config stable snapshot deferred by cooldown"
            );
        }
    }

    if maps_changed {
        pool.zero_downtime_reinit_after_map_change(rng.as_ref())
            .await;
    }

    pool.reset_stun_state();

    if cfg.general.proxy_secret_rotate_runtime {
        match download_proxy_secret_with_max_len(cfg.general.proxy_secret_len_max).await {
            Ok(secret) => {
                let secret_hash = hash_secret(&secret);
                let stable_hits = state.secret.observe(secret_hash);
                if stable_hits < required_secret_snapshots {
                    debug!(
                        stable_hits,
                        required_secret_snapshots,
                        snapshot = format_args!("0x{secret_hash:016x}"),
                        "proxy-secret candidate observed"
                    );
                } else if state.secret.is_applied(secret_hash) {
                    debug!(
                        snapshot = format_args!("0x{secret_hash:016x}"),
                        "proxy-secret stable snapshot already applied"
                    );
                } else {
                    let rotated = pool.update_secret(secret).await;
                    state.secret.mark_applied(secret_hash);
                    if rotated {
                        info!("proxy-secret rotated after stable-gate");
                    } else {
                        debug!("proxy-secret stable snapshot confirmed as unchanged");
                    }
                }
            }
            Err(e) => warn!(error = %e, "proxy-secret update failed"),
        }
    } else {
        debug!("proxy-secret runtime rotation disabled by config");
    }
}

pub async fn me_config_updater(
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
) {
    let mut state = UpdaterState::default();
    let mut update_every_secs = config_rx
        .borrow()
        .general
        .effective_update_every_secs()
        .max(1);
    let mut update_every = Duration::from_secs(update_every_secs);
    let mut next_tick = tokio::time::Instant::now() + update_every;
    info!(update_every_secs, "ME config updater started");

    loop {
        let sleep = tokio::time::sleep_until(next_tick);
        tokio::pin!(sleep);

        tokio::select! {
            _ = &mut sleep => {
                let cfg = config_rx.borrow().clone();
                run_update_cycle(&pool, &rng, cfg.as_ref(), &mut state).await;
                let refreshed_secs = cfg.general.effective_update_every_secs().max(1);
                if refreshed_secs != update_every_secs {
                    info!(
                        old_update_every_secs = update_every_secs,
                        new_update_every_secs = refreshed_secs,
                        "ME config updater interval changed"
                    );
                    update_every_secs = refreshed_secs;
                    update_every = Duration::from_secs(update_every_secs);
                }
                next_tick = tokio::time::Instant::now() + update_every;
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    warn!("ME config updater stopped: config channel closed");
                    break;
                }
                let cfg = config_rx.borrow().clone();
                pool.update_runtime_reinit_policy(
                    cfg.general.hardswap,
                    cfg.general.me_pool_drain_ttl_secs,
                    cfg.general.effective_me_pool_force_close_secs(),
                    cfg.general.me_pool_min_fresh_ratio,
                    cfg.general.me_hardswap_warmup_delay_min_ms,
                    cfg.general.me_hardswap_warmup_delay_max_ms,
                    cfg.general.me_hardswap_warmup_extra_passes,
                    cfg.general.me_hardswap_warmup_pass_backoff_base_ms,
                );
                let new_secs = cfg.general.effective_update_every_secs().max(1);
                if new_secs == update_every_secs {
                    continue;
                }

                if new_secs < update_every_secs {
                    info!(
                        old_update_every_secs = update_every_secs,
                        new_update_every_secs = new_secs,
                        "ME config updater interval decreased, running immediate refresh"
                    );
                    update_every_secs = new_secs;
                    update_every = Duration::from_secs(update_every_secs);
                    run_update_cycle(&pool, &rng, cfg.as_ref(), &mut state).await;
                    next_tick = tokio::time::Instant::now() + update_every;
                } else {
                    info!(
                        old_update_every_secs = update_every_secs,
                        new_update_every_secs = new_secs,
                        "ME config updater interval increased"
                    );
                    update_every_secs = new_secs;
                    update_every = Duration::from_secs(update_every_secs);
                    next_tick = tokio::time::Instant::now() + update_every;
                }
            }
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
