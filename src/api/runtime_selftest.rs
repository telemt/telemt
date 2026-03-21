use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::{ProxyConfig, UpstreamType};
use crate::network::probe::{detect_interface_ipv4, detect_interface_ipv6, is_bogon};
use crate::transport::UpstreamRouteKind;
use crate::transport::middle_proxy::{bnd_snapshot, timeskew_snapshot, upstream_bnd_snapshots};

use super::ApiShared;

const SOURCE_UNAVAILABLE_REASON: &str = "source_unavailable";
const KDF_EWMA_TAU_SECS: f64 = 600.0;
const KDF_EWMA_THRESHOLD_ERRORS_PER_MIN: f64 = 0.30;
const TIMESKEW_THRESHOLD_SECS: u64 = 60;

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestKdfData {
    pub(super) state: &'static str,
    pub(super) ewma_errors_per_min: f64,
    pub(super) threshold_errors_per_min: f64,
    pub(super) errors_total: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestTimeskewData {
    pub(super) state: &'static str,
    pub(super) max_skew_secs_15m: Option<u64>,
    pub(super) samples_15m: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_skew_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_seen_age_secs: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestIpFamilyData {
    pub(super) addr: String,
    pub(super) state: &'static str,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestIpData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) v4: Option<RuntimeMeSelftestIpFamilyData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) v6: Option<RuntimeMeSelftestIpFamilyData>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestPidData {
    pub(super) pid: u32,
    pub(super) state: &'static str,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestBndData {
    pub(super) addr_state: &'static str,
    pub(super) port_state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_seen_age_secs: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestUpstreamData {
    pub(super) upstream_id: usize,
    pub(super) route_kind: &'static str,
    pub(super) address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) bnd: Option<RuntimeMeSelftestBndData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ip: Option<String>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestPayload {
    pub(super) kdf: RuntimeMeSelftestKdfData,
    pub(super) timeskew: RuntimeMeSelftestTimeskewData,
    pub(super) ip: RuntimeMeSelftestIpData,
    pub(super) pid: RuntimeMeSelftestPidData,
    pub(super) bnd: Option<RuntimeMeSelftestBndData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) upstreams: Option<Vec<RuntimeMeSelftestUpstreamData>>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeSelftestData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<RuntimeMeSelftestPayload>,
}

#[derive(Default)]
struct KdfEwmaState {
    initialized: bool,
    last_epoch_secs: u64,
    last_total_errors: u64,
    ewma_errors_per_min: f64,
}

static KDF_EWMA_STATE: OnceLock<Mutex<KdfEwmaState>> = OnceLock::new();

fn kdf_ewma_state() -> &'static Mutex<KdfEwmaState> {
    KDF_EWMA_STATE.get_or_init(|| Mutex::new(KdfEwmaState::default()))
}

pub(super) async fn build_runtime_me_selftest_data(
    shared: &ApiShared,
    cfg: &ProxyConfig,
) -> RuntimeMeSelftestData {
    let now_epoch_secs = now_epoch_secs();
    if shared.me_pool.read().await.is_none() {
        return RuntimeMeSelftestData {
            enabled: false,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs: now_epoch_secs,
            data: None,
        };
    }

    let kdf_errors_total = shared
        .stats
        .get_me_kdf_drift_total()
        .saturating_add(shared.stats.get_me_socks_kdf_strict_reject());
    let kdf_ewma = update_kdf_ewma(now_epoch_secs, kdf_errors_total);
    let kdf_state = if kdf_ewma >= KDF_EWMA_THRESHOLD_ERRORS_PER_MIN {
        "error"
    } else {
        "ok"
    };

    let skew = timeskew_snapshot();
    let timeskew_state = if skew.max_skew_secs_15m.unwrap_or(0) > TIMESKEW_THRESHOLD_SECS {
        "error"
    } else {
        "ok"
    };

    let ip_v4 = detect_interface_ipv4().map(|ip| RuntimeMeSelftestIpFamilyData {
        addr: ip.to_string(),
        state: classify_ip(IpAddr::V4(ip)),
    });
    let ip_v6 = detect_interface_ipv6().map(|ip| RuntimeMeSelftestIpFamilyData {
        addr: ip.to_string(),
        state: classify_ip(IpAddr::V6(ip)),
    });

    let pid = std::process::id();
    let pid_state = if pid == 1 { "one" } else { "non-one" };

    let has_socks_upstreams = cfg.upstreams.iter().any(|upstream| {
        upstream.enabled
            && matches!(
                upstream.upstream_type,
                UpstreamType::Socks4 { .. } | UpstreamType::Socks5 { .. }
            )
    });

    let bnd = if has_socks_upstreams {
        let snapshot = bnd_snapshot();
        Some(RuntimeMeSelftestBndData {
            addr_state: snapshot.addr_status,
            port_state: snapshot.port_status,
            last_addr: snapshot.last_addr.map(|value| value.to_string()),
            last_seen_age_secs: snapshot.last_seen_age_secs,
        })
    } else {
        None
    };
    let upstreams = build_upstream_selftest_data(shared);

    RuntimeMeSelftestData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs: now_epoch_secs,
        data: Some(RuntimeMeSelftestPayload {
            kdf: RuntimeMeSelftestKdfData {
                state: kdf_state,
                ewma_errors_per_min: round3(kdf_ewma),
                threshold_errors_per_min: KDF_EWMA_THRESHOLD_ERRORS_PER_MIN,
                errors_total: kdf_errors_total,
            },
            timeskew: RuntimeMeSelftestTimeskewData {
                state: timeskew_state,
                max_skew_secs_15m: skew.max_skew_secs_15m,
                samples_15m: skew.samples_15m,
                last_skew_secs: skew.last_skew_secs,
                last_source: skew.last_source,
                last_seen_age_secs: skew.last_seen_age_secs,
            },
            ip: RuntimeMeSelftestIpData {
                v4: ip_v4,
                v6: ip_v6,
            },
            pid: RuntimeMeSelftestPidData {
                pid,
                state: pid_state,
            },
            bnd,
            upstreams,
        }),
    }
}

fn build_upstream_selftest_data(shared: &ApiShared) -> Option<Vec<RuntimeMeSelftestUpstreamData>> {
    let snapshot = shared.upstream_manager.try_api_snapshot()?;
    if snapshot.summary.configured_total <= 1 {
        return None;
    }

    let mut upstream_bnd_by_id: HashMap<usize, _> = upstream_bnd_snapshots()
        .into_iter()
        .map(|entry| (entry.upstream_id, entry))
        .collect();
    let mut rows = Vec::with_capacity(snapshot.upstreams.len());
    for upstream in snapshot.upstreams {
        let upstream_bnd = upstream_bnd_by_id.remove(&upstream.upstream_id);
        rows.push(RuntimeMeSelftestUpstreamData {
            upstream_id: upstream.upstream_id,
            route_kind: map_route_kind(upstream.route_kind),
            address: upstream.address,
            bnd: upstream_bnd.as_ref().map(|entry| RuntimeMeSelftestBndData {
                addr_state: entry.addr_status,
                port_state: entry.port_status,
                last_addr: entry.last_addr.map(|value| value.to_string()),
                last_seen_age_secs: entry.last_seen_age_secs,
            }),
            ip: upstream_bnd.and_then(|entry| entry.last_ip.map(|value| value.to_string())),
        });
    }
    Some(rows)
}

fn update_kdf_ewma(now_epoch_secs: u64, total_errors: u64) -> f64 {
    let Ok(mut guard) = kdf_ewma_state().lock() else {
        return 0.0;
    };

    if !guard.initialized {
        guard.initialized = true;
        guard.last_epoch_secs = now_epoch_secs;
        guard.last_total_errors = total_errors;
        guard.ewma_errors_per_min = 0.0;
        return guard.ewma_errors_per_min;
    }

    let dt_secs = now_epoch_secs.saturating_sub(guard.last_epoch_secs);
    if dt_secs == 0 {
        return guard.ewma_errors_per_min;
    }

    let delta_errors = total_errors.saturating_sub(guard.last_total_errors);
    let instant_rate_per_min = (delta_errors as f64) * 60.0 / (dt_secs as f64);
    let alpha = 1.0 - f64::exp(-(dt_secs as f64) / KDF_EWMA_TAU_SECS);
    guard.ewma_errors_per_min =
        guard.ewma_errors_per_min + alpha * (instant_rate_per_min - guard.ewma_errors_per_min);
    guard.last_epoch_secs = now_epoch_secs;
    guard.last_total_errors = total_errors;
    guard.ewma_errors_per_min
}

fn classify_ip(ip: IpAddr) -> &'static str {
    if ip.is_loopback() {
        return "loopback";
    }
    if is_bogon(ip) {
        return "bogon";
    }
    "good"
}

fn map_route_kind(value: UpstreamRouteKind) -> &'static str {
    match value {
        UpstreamRouteKind::Direct => "direct",
        UpstreamRouteKind::Socks4 => "socks4",
        UpstreamRouteKind::Socks5 => "socks5",
        UpstreamRouteKind::Shadowsocks => "shadowsocks",
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
