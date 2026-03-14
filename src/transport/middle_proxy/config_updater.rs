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
use crate::network::probe::is_bogon;

use super::MePool;
use super::rotation::{MeReinitTrigger, enqueue_reinit_trigger};
use super::secret::download_proxy_secret_with_max_len;
use super::selftest::record_timeskew_sample;
use std::time::SystemTime;

/// Hard cap on response body size before any content parsing.
/// Guards against memory exhaustion from a compromised or MITM-proxied endpoint.
const MAX_PROXY_CONFIG_RESPONSE_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum number of proxy-for entries stored across all DC groups.
/// Prevents unbounded HashMap growth from a malformed or adversarial config.
const MAX_PROXY_CONFIG_ENTRIES: usize = 10_000;

/// Maximum number of distinct DC groups.
const MAX_PROXY_CONFIG_DC_GROUPS: usize = 500;

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
    pub http_status: u16,
    pub proxy_for_lines: u32,
}

pub fn parse_proxy_config_text(text: &str, http_status: u16) -> ProxyConfigData {
    let mut map: HashMap<i32, Vec<(IpAddr, u16)>> = HashMap::new();
    let mut proxy_for_lines: u32 = 0;
    for line in text.lines() {
        if let Some((dc, ip, port)) = parse_proxy_line(line) {
            // Enforce per-total and per-DC-group entry caps to bound memory usage.
            if proxy_for_lines as usize >= MAX_PROXY_CONFIG_ENTRIES {
                warn!(
                    limit = MAX_PROXY_CONFIG_ENTRIES,
                    "proxy-config entry limit reached; remaining lines ignored"
                );
                break;
            }
            if !map.contains_key(&dc) && map.len() >= MAX_PROXY_CONFIG_DC_GROUPS {
                warn!(
                    dc,
                    limit = MAX_PROXY_CONFIG_DC_GROUPS,
                    "proxy-config DC group limit reached; entry skipped"
                );
                continue;
            }
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

pub async fn fetch_proxy_config_with_raw(url: &str) -> Result<(ProxyConfigData, String)> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| crate::error::ProxyError::Proxy(format!("fetch_proxy_config GET failed: {e}")))?;
    let http_status = resp.status().as_u16();

    // Reject early when Content-Length already exceeds the response hard cap.
    if let Some(content_len) = resp.content_length()
        && content_len > MAX_PROXY_CONFIG_RESPONSE_BYTES as u64
    {
        return Err(crate::error::ProxyError::Proxy(format!(
            "proxy-config Content-Length {content_len} exceeds hard cap {MAX_PROXY_CONFIG_RESPONSE_BYTES}"
        )));
    }

    if let Some(date) = resp.headers().get(reqwest::header::DATE)
        && let Ok(date_str) = date.to_str()
        && let Ok(server_time) = httpdate::parse_http_date(date_str)
        && let Ok(skew) = SystemTime::now().duration_since(server_time).or_else(|e| {
            server_time.duration_since(SystemTime::now()).map_err(|_| e)
        })
    {
        let skew_secs = skew.as_secs();
        record_timeskew_sample("proxy_config_date_header", skew_secs);
        if skew_secs > 60 {
            warn!(skew_secs, "Time skew >60s detected from fetch_proxy_config Date header");
        } else if skew_secs > 30 {
            warn!(skew_secs, "Time skew >30s detected from fetch_proxy_config Date header");
        }
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| crate::error::ProxyError::Proxy(format!("fetch_proxy_config read failed: {e}")))?;

    // Secondary cap covers chunked responses that omit Content-Length.
    if body.len() > MAX_PROXY_CONFIG_RESPONSE_BYTES {
        return Err(crate::error::ProxyError::Proxy(format!(
            "proxy-config response body {} bytes exceeds hard cap {MAX_PROXY_CONFIG_RESPONSE_BYTES}",
            body.len()
        )));
    }

    let text = String::from_utf8_lossy(&body).into_owned();
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

    const fn mark_applied(&mut self, hash: u64) {
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
    // Reject bogon/reserved addresses to prevent SSRF from a compromised config source.
    // A censor that intercepts the config download could otherwise inject loopback,
    // private-network, or cloud-metadata IPs and use the proxy as an SSRF relay.
    if is_bogon(ip) || ip.is_unspecified() {
        return None;
    }
    // Port 0 is not a valid proxy endpoint and must be rejected before use.
    if port == 0 {
        return None;
    }
    Some((dc, ip, port))
}

pub async fn fetch_proxy_config(url: &str) -> Result<ProxyConfigData> {
    fetch_proxy_config_with_raw(url)
        .await
        .map(|(parsed, _raw)| parsed)
}

fn snapshot_passes_guards(
    cfg: &ProxyConfig,
    snapshot: &ProxyConfigData,
    snapshot_name: &'static str,
) -> bool {
    if cfg.general.me_snapshot_require_http_2xx
        && !(200..=299).contains(&snapshot.http_status)
    {
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
    pool.update_runtime_reinit_policy(
        cfg.general.hardswap,
        cfg.general.me_pool_drain_ttl_secs,
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

    let required_cfg_snapshots = cfg.general.me_config_stable_snapshots.max(1);
    let required_secret_snapshots = cfg.general.proxy_secret_stable_snapshots.max(1);
    let apply_cooldown = Duration::from_secs(cfg.general.me_config_apply_cooldown_secs);
    let mut maps_changed = false;

    let mut ready_v4: Option<(ProxyConfigData, u64)> = None;
    let cfg_v4 = retry_fetch("https://core.telegram.org/getProxyConfig").await;
    if let Some(cfg_v4) = cfg_v4
        && snapshot_passes_guards(cfg, &cfg_v4, "getProxyConfig") {
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
    if let Some(cfg_v6) = cfg_v6
        && snapshot_passes_guards(cfg, &cfg_v6, "getProxyConfigV6") {
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
            debug!(
                wait_secs,
                "ME config stable snapshot deferred by cooldown"
            );
        }
    }

    if maps_changed {
        enqueue_reinit_trigger(reinit_tx, MeReinitTrigger::MapChanged);
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

    // --- bogon / reserved-IP / port-0 rejection (SSRF guard) ---
    //
    // A censor that intercepts the proxy-config HTTPS download could inject
    // entries pointing to loopback, private-network, or cloud-metadata addresses.
    // Every variant must be silently dropped by parse_proxy_line.

    #[test]
    fn parse_proxy_line_rejects_ipv4_loopback() {
        assert!(parse_proxy_line("proxy_for 1 127.0.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 127.255.255.255:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv4_unspecified() {
        assert!(parse_proxy_line("proxy_for 1 0.0.0.0:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv4_class_a_private() {
        assert!(parse_proxy_line("proxy_for 1 10.0.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 10.255.255.255:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv4_class_b_private() {
        assert!(parse_proxy_line("proxy_for 1 172.16.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 172.31.255.255:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv4_class_c_private() {
        assert!(parse_proxy_line("proxy_for 1 192.168.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 192.168.255.255:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_cgnat_range() {
        // RFC 6598: 100.64.0.0/10
        assert!(parse_proxy_line("proxy_for 1 100.64.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 100.127.255.255:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_link_local() {
        assert!(parse_proxy_line("proxy_for 1 169.254.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 169.254.169.254:80;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_documentation_ranges() {
        // RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        assert!(parse_proxy_line("proxy_for 1 192.0.2.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 198.51.100.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 203.0.113.1:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv4_multicast_and_reserved() {
        assert!(parse_proxy_line("proxy_for 1 224.0.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 240.0.0.1:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 255.255.255.255:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv6_loopback() {
        assert!(parse_proxy_line("proxy_for 1 [::1]:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv6_link_local() {
        assert!(parse_proxy_line("proxy_for 1 [fe80::1]:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 [fe80::dead:beef]:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv6_unique_local() {
        // fc00::/7 — includes both fc00::/8 and fd00::/8
        assert!(parse_proxy_line("proxy_for 1 [fc00::1]:443;").is_none());
        assert!(parse_proxy_line("proxy_for 1 [fd00::1]:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_ipv6_unspecified() {
        assert!(parse_proxy_line("proxy_for 1 [::]:443;").is_none());
    }

    #[test]
    fn parse_proxy_line_rejects_port_zero() {
        // Port 0 is an OS-assigned ephemeral port and cannot be a valid ME endpoint.
        assert!(parse_proxy_line("proxy_for 1 91.108.4.195:0;").is_none());
        assert!(parse_proxy_line("proxy_for 1 [2001:67c:04e8:f002::d]:0;").is_none());
    }

    #[test]
    fn parse_proxy_line_accepts_routable_ipv4() {
        let res = parse_proxy_line("proxy_for 1 91.108.4.195:443;");
        assert!(res.is_some(), "public routable IPv4 must be accepted");
    }

    #[test]
    fn parse_proxy_line_accepts_routable_ipv6() {
        let res = parse_proxy_line("proxy_for 1 [2001:67c:04e8:f002::d]:443;");
        assert!(res.is_some(), "public routable IPv6 must be accepted");
    }

    #[test]
    fn parse_proxy_config_text_strips_all_bogon_entries_leaves_only_public() {
        // An adversarial config that mixes bogon and legitimate IPs.
        // Only the public entries must pass the filter.
        let text = [
            "proxy_for 1 127.0.0.1:443;",
            "proxy_for 1 10.0.0.1:443;",
            "proxy_for 1 192.168.1.1:8888;",
            "proxy_for 1 169.254.169.254:80;",
            "proxy_for 1 [::1]:443;",
            "proxy_for 1 [fe80::1]:443;",
            "proxy_for 1 91.108.4.1:443;",
            "proxy_for 1 149.154.160.1:8888;",
        ]
        .join("\n");
        let data = parse_proxy_config_text(&text, 200);
        assert_eq!(data.proxy_for_lines, 2, "only the two public IPs should be counted");
        let addrs = data.map.get(&1).expect("DC 1 must have entries");
        assert_eq!(addrs.len(), 2);
        let ips: Vec<_> = addrs.iter().map(|(ip, _)| ip.to_string()).collect();
        assert!(ips.contains(&"91.108.4.1".to_string()));
        assert!(ips.contains(&"149.154.160.1".to_string()));
    }

    #[test]
    fn parse_proxy_config_text_pure_bogon_config_yields_empty_map() {
        // A config containing only bogon entries must produce an empty map,
        // triggering the empty-snapshot guard further up the call chain.
        let text = [
            "proxy_for 1 127.0.0.1:443;",
            "proxy_for 2 10.0.0.1:8888;",
            "proxy_for 3 192.168.0.1:443;",
            "proxy_for 4 [::1]:443;",
        ]
        .join("\n");
        let data = parse_proxy_config_text(&text, 200);
        assert!(data.map.is_empty(), "pure bogon config must yield empty map");
        assert_eq!(data.proxy_for_lines, 0);
    }

    // --- parse_proxy_config_text: entry and DC-group limits ---
    // (uses 91.108.x.x — routable public addresses, not private/bogon)

    fn make_proxy_line(dc: i32, _octet: u8, idx: u32) -> String {
        format!("proxy_for {dc} 91.108.{}.{}:443;", (idx >> 8) & 0xFF, idx & 0xFF)
    }

    #[test]
    fn parse_proxy_config_entry_limit_stops_at_max() {
        // Build MAX_PROXY_CONFIG_ENTRIES + 500 lines in DC 1 with distinct public IPs.
        let extra = 500usize;
        let total_lines = MAX_PROXY_CONFIG_ENTRIES + extra;
        let mut text = String::new();
        for i in 0..total_lines {
            text.push_str(&format!(
                "proxy_for 1 91.108.{}.{}:443;\n",
                (i / 256) & 0xFF,
                i & 0xFF
            ));
        }
        let data = parse_proxy_config_text(&text, 200);
        assert_eq!(
            data.proxy_for_lines as usize,
            MAX_PROXY_CONFIG_ENTRIES,
            "parser must stop at MAX_PROXY_CONFIG_ENTRIES"
        );
    }

    #[test]
    fn parse_proxy_config_dc_group_limit_stops_at_max() {
        // One entry per DC group; build MAX_PROXY_CONFIG_DC_GROUPS + 50 groups.
        let extra = 50usize;
        let total_dcs = MAX_PROXY_CONFIG_DC_GROUPS + extra;
        let mut text = String::new();
        for dc in 1..=(total_dcs as i32) {
            text.push_str(&format!("proxy_for {dc} 91.108.0.1:443;\n"));
        }
        let data = parse_proxy_config_text(&text, 200);
        assert!(
            data.map.len() <= MAX_PROXY_CONFIG_DC_GROUPS,
            "DC group count {} must not exceed MAX_PROXY_CONFIG_DC_GROUPS {}",
            data.map.len(),
            MAX_PROXY_CONFIG_DC_GROUPS,
        );
    }

    #[test]
    fn parse_proxy_config_existing_dc_group_still_accepted_when_dc_cap_full() {
        // Fill the DC group cap then add more entries to an EXISTING DC group.
        // Those must still be accepted (cap is only on new DC groups).
        let mut text = String::new();
        for dc in 1..=(MAX_PROXY_CONFIG_DC_GROUPS as i32) {
            text.push_str(&make_proxy_line(dc, 10, 0));
            text.push('\n');
        }
        // Two more entries for DC 1 (already present).
        text.push_str(&make_proxy_line(1, 10, 1));
        text.push('\n');
        text.push_str(&make_proxy_line(1, 10, 2));
        text.push('\n');
        let data = parse_proxy_config_text(&text, 200);
        let dc1_count = data.map.get(&1).map(|v| v.len()).unwrap_or(0);
        assert_eq!(
            dc1_count, 3,
            "entries in an existing DC group must be accepted even after DC cap is reached"
        );
    }

    #[test]
    fn parse_proxy_config_empty_text_produces_empty_map() {
        let data = parse_proxy_config_text("", 200);
        assert!(data.map.is_empty());
        assert_eq!(data.proxy_for_lines, 0);
    }

    #[test]
    fn parse_proxy_config_valid_small_text_round_trips() {
        let text = "proxy_for 1 91.108.4.1:443;\nproxy_for 2 91.108.4.2:8080;\n";
        let data = parse_proxy_config_text(text, 200);
        assert_eq!(data.proxy_for_lines, 2);
        assert_eq!(data.map.len(), 2);
    }

    #[test]
    fn parse_proxy_config_ignores_non_proxy_for_lines() {
        let text = "default 1;\nproxy_for 1 91.108.4.1:443;\n# comment\nsome garbage\n";
        let data = parse_proxy_config_text(text, 200);
        assert_eq!(data.proxy_for_lines, 1);
        assert_eq!(data.default_dc, Some(1));
    }

    // --- response size cap constants ---

    #[test]
    fn max_proxy_config_response_cap_is_at_least_one_mib() {
        const {
            assert!(
                MAX_PROXY_CONFIG_RESPONSE_BYTES >= 1_048_576,
                "response cap must accommodate large but legitimate configs"
            )
        };
    }

    #[test]
    fn content_length_precheck_rejects_over_cap() {
        let over: u64 = MAX_PROXY_CONFIG_RESPONSE_BYTES as u64 + 1;
        assert!(over > MAX_PROXY_CONFIG_RESPONSE_BYTES as u64);
    }

    #[test]
    fn body_size_check_rejects_over_cap() {
        let body = vec![b'x'; MAX_PROXY_CONFIG_RESPONSE_BYTES + 1];
        assert!(
            body.len() > MAX_PROXY_CONFIG_RESPONSE_BYTES,
            "body over cap must be detected"
        );
    }

    #[test]
    fn body_size_check_accepts_exact_cap() {
        let body = vec![b'x'; MAX_PROXY_CONFIG_RESPONSE_BYTES];
        assert!(body.len() <= MAX_PROXY_CONFIG_RESPONSE_BYTES);
    }
}
