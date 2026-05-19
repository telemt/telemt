use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use httpdate;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::error::Result;
use crate::transport::UpstreamManager;

use super::MePool;
use super::http_fetch::https_get;
use super::rotation::{MeReinitTrigger, enqueue_reinit_trigger};
use super::secret::download_proxy_secret_with_max_len_via_upstream;
use super::selftest::record_timeskew_sample;
use std::time::SystemTime;

async fn retry_fetch(url: &str, upstream: Option<Arc<UpstreamManager>>) -> Option<ProxyConfigData> {
    let delays = [1u64, 5, 15];
    for (i, d) in delays.iter().enumerate() {
        match fetch_proxy_config_via_upstream(url, upstream.clone()).await {
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
    pub http_status: u16,
    pub proxy_for_lines: u32,
}

pub fn parse_proxy_config_text(text: &str, http_status: u16) -> ProxyConfigData {
    let mut map: HashMap<i32, Vec<(IpAddr, u16)>> = HashMap::new();
    let mut proxy_for_lines: u32 = 0;
    for line in text.lines() {
        if let Some((dc, ip, port)) = parse_proxy_line(line) {
            map.entry(dc).or_default().push((ip, port));
            proxy_for_lines = proxy_for_lines.saturating_add(1);
        }
    }

    let default_dc = text.lines().find_map(|l| {
        let t = l.trim();
        if let Some(rest) = t.strip_prefix("default") {
            return rest.trim().trim_end_matches(';').parse::<i32>().ok();
        }
        None
    });

    ProxyConfigData {
        map,
        default_dc,
        http_status,
        proxy_for_lines,
    }
}

pub async fn load_proxy_config_cache(path: &str) -> Result<ProxyConfigData> {
    let text = tokio::fs::read_to_string(path).await.map_err(|e| {
        crate::error::ProxyError::Proxy(format!("read proxy-config cache '{path}' failed: {e}"))
    })?;
    Ok(parse_proxy_config_text(&text, 200))
}

pub async fn save_proxy_config_cache(path: &str, raw_text: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            crate::error::ProxyError::Proxy(format!(
                "create proxy-config cache dir '{}' failed: {e}",
                parent.display()
            ))
        })?;
    }

    tokio::fs::write(path, raw_text).await.map_err(|e| {
        crate::error::ProxyError::Proxy(format!("write proxy-config cache '{path}' failed: {e}"))
    })?;
    Ok(())
}

#[allow(dead_code)]
pub async fn fetch_proxy_config_with_raw(url: &str) -> Result<(ProxyConfigData, String)> {
    fetch_proxy_config_with_raw_via_upstream(url, None).await
}

pub async fn fetch_proxy_config_with_raw_via_upstream(
    url: &str,
    upstream: Option<Arc<UpstreamManager>>,
) -> Result<(ProxyConfigData, String)> {
    let resp = https_get(url, upstream).await?;
    let http_status = resp.status;

    if let Some(date_str) = resp.date_header.as_deref()
        && let Ok(server_time) = httpdate::parse_http_date(date_str)
        && let Ok(skew) = SystemTime::now()
            .duration_since(server_time)
            .or_else(|e| server_time.duration_since(SystemTime::now()).map_err(|_| e))
    {
        let skew_secs = skew.as_secs();
        record_timeskew_sample("proxy_config_date_header", skew_secs);
        if skew_secs > 60 {
            warn!(
                skew_secs,
                "Time skew >60s detected from fetch_proxy_config Date header"
            );
        } else if skew_secs > 30 {
            warn!(
                skew_secs,
                "Time skew >30s detected from fetch_proxy_config Date header"
            );
        }
    }

    let text = String::from_utf8_lossy(&resp.body).into_owned();
    let parsed = parse_proxy_config_text(&text, http_status);
    Ok((parsed, text))
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

    let mut by_dc: Vec<(i32, Vec<(IpAddr, u16)>)> = cfg
        .map
        .iter()
        .map(|(dc, addrs)| (*dc, addrs.clone()))
        .collect();
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

#[allow(dead_code)]
pub async fn fetch_proxy_config(url: &str) -> Result<ProxyConfigData> {
    fetch_proxy_config_via_upstream(url, None).await
}

pub async fn fetch_proxy_config_via_upstream(
    url: &str,
    upstream: Option<Arc<UpstreamManager>>,
) -> Result<ProxyConfigData> {
    fetch_proxy_config_with_raw_via_upstream(url, upstream)
        .await
        .map(|(parsed, _raw)| parsed)
}

fn snapshot_passes_guards(
    cfg: &ProxyConfig,
    snapshot: &ProxyConfigData,
    snapshot_name: &'static str,
) -> bool {
    if cfg.general.me_snapshot_require_http_2xx && !(200..=299).contains(&snapshot.http_status) {
        warn!(
            snapshot = snapshot_name,
            http_status = snapshot.http_status,
            "ME snapshot rejected by non-2xx HTTP status"
        );
        return false;
    }

    let min_proxy_for = cfg.general.me_snapshot_min_proxy_for_lines;
    if snapshot.proxy_for_lines < min_proxy_for {
        warn!(
            snapshot = snapshot_name,
            parsed_proxy_for_lines = snapshot.proxy_for_lines,
            min_proxy_for_lines = min_proxy_for,
            "ME snapshot rejected by proxy_for line floor"
        );
        return false;
    }

    true
}

async fn run_update_cycle(
    pool: &Arc<MePool>,
    cfg: &ProxyConfig,
    state: &mut UpdaterState,
    reinit_tx: &mpsc::Sender<MeReinitTrigger>,
) {
    let upstream = pool.upstream.clone();

    let required_cfg_snapshots = cfg.general.me_config_stable_snapshots.max(1);
    let required_secret_snapshots = cfg.general.proxy_secret_stable_snapshots.max(1);
    let apply_cooldown = Duration::from_secs(cfg.general.me_config_apply_cooldown_secs);
    let mut maps_changed = false;

    let mut ready_v4: Option<(ProxyConfigData, u64)> = None;
    let cfg_v4 = retry_fetch(
        cfg.general
            .proxy_config_v4_url
            .as_deref()
            .unwrap_or("https://core.telegram.org/getProxyConfig"),
        upstream.clone(),
    )
    .await;
    if let Some(cfg_v4) = cfg_v4
        && snapshot_passes_guards(cfg, &cfg_v4, "getProxyConfig")
    {
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
    let cfg_v6 = retry_fetch(
        cfg.general
            .proxy_config_v6_url
            .as_deref()
            .unwrap_or("https://core.telegram.org/getProxyConfigV6"),
        upstream.clone(),
    )
    .await;
    if let Some(cfg_v6) = cfg_v6
        && snapshot_passes_guards(cfg, &cfg_v6, "getProxyConfigV6")
    {
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
            let update_v6 = ready_v6.as_ref().map(|(snapshot, _)| snapshot.map.clone());
            let update_is_empty =
                update_v4.is_empty() && update_v6.as_ref().is_none_or(|v| v.is_empty());
            let apply_outcome = if update_is_empty && !cfg.general.me_snapshot_reject_empty_map {
                super::pool_config::SnapshotApplyOutcome::AppliedNoDelta
            } else {
                pool.update_proxy_maps(update_v4, update_v6).await
            };

            if matches!(
                apply_outcome,
                super::pool_config::SnapshotApplyOutcome::RejectedEmpty
            ) {
                warn!("ME config stable snapshot rejected (empty endpoint map)");
            } else {
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

                if apply_outcome.changed() {
                    maps_changed = true;
                    info!("ME config update applied after stable-gate");
                } else {
                    debug!("ME config stable-gate applied with no map delta");
                }
            }
        } else if let Some(last) = state.last_map_apply_at {
            let wait_secs = map_apply_cooldown_remaining_secs(last, apply_cooldown);
            debug!(wait_secs, "ME config stable snapshot deferred by cooldown");
        }
    }

    if maps_changed {
        enqueue_reinit_trigger(reinit_tx, MeReinitTrigger::MapChanged);
    }

    pool.reset_stun_state();

    if cfg.general.proxy_secret_rotate_runtime {
        match download_proxy_secret_with_max_len_via_upstream(
            cfg.general.proxy_secret_len_max,
            upstream,
            cfg.general.proxy_secret_url.as_deref(),
        )
        .await
        {
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
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
    reinit_tx: mpsc::Sender<MeReinitTrigger>,
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
                run_update_cycle(&pool, cfg.as_ref(), &mut state, &reinit_tx).await;
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
                    cfg.general.me_instadrain,
                    cfg.general.me_pool_drain_threshold,
                    cfg.general.me_pool_drain_soft_evict_enabled,
                    cfg.general.me_pool_drain_soft_evict_grace_secs,
                    cfg.general.me_pool_drain_soft_evict_per_writer,
                    cfg.general.me_pool_drain_soft_evict_budget_per_core,
                    cfg.general.me_pool_drain_soft_evict_cooldown_ms,
                    cfg.general.effective_me_pool_force_close_secs(),
                    cfg.general.me_pool_min_fresh_ratio,
                    cfg.general.me_hardswap_warmup_delay_min_ms,
                    cfg.general.me_hardswap_warmup_delay_max_ms,
                    cfg.general.me_hardswap_warmup_extra_passes,
                    cfg.general.me_hardswap_warmup_pass_backoff_base_ms,
                    cfg.general.me_bind_stale_mode,
                    cfg.general.me_bind_stale_ttl_secs,
                    cfg.general.me_secret_atomic_snapshot,
                    cfg.general.me_deterministic_writer_sort,
                    cfg.general.me_writer_pick_mode,
                    cfg.general.me_writer_pick_sample_size,
                    cfg.general.me_single_endpoint_shadow_writers,
                    cfg.general.me_single_endpoint_outage_mode_enabled,
                    cfg.general.me_single_endpoint_outage_disable_quarantine,
                    cfg.general.me_single_endpoint_outage_backoff_min_ms,
                    cfg.general.me_single_endpoint_outage_backoff_max_ms,
                    cfg.general.me_single_endpoint_shadow_rotate_every_secs,
                    cfg.general.me_floor_mode,
                    cfg.general.me_adaptive_floor_idle_secs,
                    cfg.general.me_adaptive_floor_min_writers_single_endpoint,
                    cfg.general.me_adaptive_floor_min_writers_multi_endpoint,
                    cfg.general.me_adaptive_floor_recover_grace_secs,
                    cfg.general.me_adaptive_floor_writers_per_core_total,
                    cfg.general.me_adaptive_floor_cpu_cores_override,
                    cfg.general.me_adaptive_floor_max_extra_writers_single_per_core,
                    cfg.general.me_adaptive_floor_max_extra_writers_multi_per_core,
                    cfg.general.me_adaptive_floor_max_active_writers_per_core,
                    cfg.general.me_adaptive_floor_max_warm_writers_per_core,
                    cfg.general.me_adaptive_floor_max_active_writers_global,
                    cfg.general.me_adaptive_floor_max_warm_writers_global,
                    cfg.general.me_health_interval_ms_unhealthy,
                    cfg.general.me_health_interval_ms_healthy,
                    cfg.general.me_warn_rate_limit_ms,
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
                    run_update_cycle(&pool, cfg.as_ref(), &mut state, &reinit_tx).await;
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

    #[test]
    fn parse_proxy_config_text_empty() {
        let cfg = parse_proxy_config_text("", 200);
        assert!(cfg.map.is_empty());
        assert_eq!(cfg.default_dc, None);
        assert_eq!(cfg.http_status, 200);
        assert_eq!(cfg.proxy_for_lines, 0);
    }

    #[test]
    fn parse_proxy_config_text_one_line_and_default() {
        let text = "proxy_for 4 91.108.4.195:8888;\ndefault 4;";
        let cfg = parse_proxy_config_text(text, 200);
        assert_eq!(cfg.default_dc, Some(4));
        assert_eq!(cfg.proxy_for_lines, 1);
        let addrs = cfg.map.get(&4).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].1, 8888);
    }

    #[test]
    fn parse_proxy_config_text_v4_and_v6() {
        let text = "\
            proxy_for 4 91.108.4.195:8888;\n\
            proxy_for 2 [2001:67c:04e8:f002::d]:80;\n\
            proxy_for 4 149.154.167.40:443;";
        let cfg = parse_proxy_config_text(text, 200);
        assert_eq!(cfg.proxy_for_lines, 3);
        assert_eq!(cfg.map.get(&4).unwrap().len(), 2);
        assert_eq!(cfg.map.get(&2).unwrap().len(), 1);
    }

    #[test]
    fn parse_proxy_config_text_malformed_lines_skipped() {
        let text = "\
            garbage line\n\
            proxy_for 4 91.108.4.195:8888;\n\
            proxy_for X badhost:;\n\
            default 2;";
        let cfg = parse_proxy_config_text(text, 200);
        assert_eq!(cfg.proxy_for_lines, 1);
        assert_eq!(cfg.default_dc, Some(2));
        assert!(cfg.map.contains_key(&4));
    }

    #[test]
    fn parse_proxy_config_text_non_200_status_reflected() {
        let cfg_200 = parse_proxy_config_text("proxy_for 4 1.2.3.4:443;", 200);
        let cfg_503 = parse_proxy_config_text("proxy_for 4 1.2.3.4:443;", 503);
        assert_eq!(cfg_200.http_status, 200);
        assert_eq!(cfg_503.http_status, 503);
        assert_eq!(cfg_200.map, cfg_503.map);
    }

    #[test]
    fn hash_proxy_config_differs_on_content_change() {
        let cfg_a = parse_proxy_config_text("proxy_for 4 91.108.4.195:8888;", 200);
        let cfg_b = parse_proxy_config_text("proxy_for 4 149.154.167.40:443;", 200);
        assert_ne!(hash_proxy_config(&cfg_a), hash_proxy_config(&cfg_b));
    }

    #[test]
    fn hash_secret_differs_on_change() {
        let a = b"abcdef0123456789abcdef0123456789";
        let b = b"abcdef0123456789abcdef0123456780";
        assert_ne!(hash_secret(a), hash_secret(b));
    }

    #[test]
    fn parse_host_port_ipv4() {
        let (ip, port) = parse_host_port("91.108.4.195:8888").unwrap();
        assert_eq!(ip, "91.108.4.195".parse::<IpAddr>().unwrap());
        assert_eq!(port, 8888);
    }

    #[test]
    fn parse_host_port_ipv6_bracketed() {
        let (ip, port) = parse_host_port("[2001:67c:04e8:f002::d]:80").unwrap();
        assert_eq!(ip, "2001:67c:04e8:f002::d".parse::<IpAddr>().unwrap());
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_host_port_rejects_empty_host() {
        assert!(parse_host_port(":443").is_none());
    }

    #[test]
    fn parse_host_port_rejects_malformed() {
        assert!(parse_host_port("notaaddress").is_none());
        assert!(parse_host_port("1.2.3.4:99999").is_none());
        assert!(parse_host_port("1.2.3.4:").is_none());
        assert!(parse_host_port("").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_non_proxy_for() {
        assert!(parse_proxy_line("default 4;").is_none());
        assert!(parse_proxy_line("random text").is_none());
        assert!(parse_proxy_line("").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_malformed_dc() {
        assert!(parse_proxy_line("proxy_for abc 1.2.3.4:443;").is_none());
    }

    #[test]
    fn snapshot_passes_guards_accepts_2xx_and_enough_lines() {
        let cfg = ProxyConfig::default();
        let snap = ProxyConfigData {
            map: HashMap::new(),
            default_dc: None,
            http_status: 200,
            proxy_for_lines: 5,
        };
        assert!(snapshot_passes_guards(&cfg, &snap, "test"));
    }

    #[test]
    fn snapshot_passes_guards_rejects_non_2xx_when_required() {
        let cfg = ProxyConfig::default();
        let snap = ProxyConfigData {
            map: HashMap::new(),
            default_dc: None,
            http_status: 503,
            proxy_for_lines: 5,
        };
        assert!(!snapshot_passes_guards(&cfg, &snap, "test"));
    }

    #[test]
    fn snapshot_passes_guards_rejects_too_few_proxy_for_lines() {
        let mut cfg = ProxyConfig::default();
        cfg.general.me_snapshot_min_proxy_for_lines = 10;
        let snap = ProxyConfigData {
            map: HashMap::new(),
            default_dc: None,
            http_status: 200,
            proxy_for_lines: 3,
        };
        assert!(!snapshot_passes_guards(&cfg, &snap, "test"));
    }
}
