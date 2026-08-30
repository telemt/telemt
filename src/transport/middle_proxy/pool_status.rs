use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::pool::{MePool, ReinitStatusSnapshot, WriterContour};
use crate::config::{MeBindStaleMode, MeFloorMode, MeSocksKdfPolicy};
use crate::transport::upstream::IpPreference;

// ME writer and DC coverage snapshots.
mod status_snapshot;
// ME runtime policy and coherent snapshot assembly.
mod runtime_snapshot;
#[derive(Clone, Debug)]
pub(crate) struct MeApiWriterStatusSnapshot {
    pub writer_id: u64,
    pub dc: Option<i16>,
    pub endpoint: SocketAddr,
    pub generation: u64,
    pub state: &'static str,
    pub draining: bool,
    pub degraded: bool,
    pub bound_clients: usize,
    pub idle_for_secs: Option<u64>,
    pub rtt_ema_ms: Option<f64>,
    pub matches_active_generation: bool,
    pub in_desired_map: bool,
    pub allow_drain_fallback: bool,
    pub drain_started_at_epoch_secs: Option<u64>,
    pub drain_deadline_epoch_secs: Option<u64>,
    pub drain_over_ttl: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcStatusSnapshot {
    pub dc: i16,
    pub endpoints: Vec<SocketAddr>,
    pub endpoint_writers: Vec<MeApiDcEndpointWriterSnapshot>,
    pub available_endpoints: usize,
    pub available_pct: f64,
    pub required_writers: usize,
    pub floor_min: usize,
    pub floor_target: usize,
    pub floor_max: usize,
    pub floor_capped: bool,
    pub alive_writers: usize,
    pub coverage_pct: f64,
    pub fresh_alive_writers: usize,
    pub fresh_coverage_pct: f64,
    pub rtt_ms: Option<f64>,
    pub load: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcEndpointWriterSnapshot {
    pub endpoint: SocketAddr,
    pub active_writers: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiStatusSnapshot {
    pub generated_at_epoch_secs: u64,
    pub configured_dc_groups: usize,
    pub configured_endpoints: usize,
    pub available_endpoints: usize,
    pub available_pct: f64,
    pub required_writers: usize,
    pub alive_writers: usize,
    pub coverage_pct: f64,
    pub fresh_alive_writers: usize,
    pub fresh_coverage_pct: f64,
    pub writers: Vec<MeApiWriterStatusSnapshot>,
    pub dcs: Vec<MeApiDcStatusSnapshot>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiQuarantinedEndpointSnapshot {
    pub endpoint: SocketAddr,
    pub remaining_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcPathSnapshot {
    pub dc: i16,
    pub ip_preference: Option<&'static str>,
    pub selected_addr_v4: Option<SocketAddr>,
    pub selected_addr_v6: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiRuntimeSnapshot {
    pub active_generation: u64,
    pub warm_generation: u64,
    pub warm_generations: Vec<u64>,
    pub pending_hardswap_generation: u64,
    pub pending_hardswap_age_secs: Option<u64>,
    pub reinit_inflight: usize,
    pub reinit_max_concurrency_effective: usize,
    pub hardswap_enabled: bool,
    pub floor_mode: &'static str,
    pub adaptive_floor_idle_secs: u64,
    pub adaptive_floor_min_writers_single_endpoint: u8,
    pub adaptive_floor_min_writers_multi_endpoint: u8,
    pub adaptive_floor_recover_grace_secs: u64,
    pub adaptive_floor_writers_per_core_total: u16,
    pub adaptive_floor_cpu_cores_override: u16,
    pub adaptive_floor_max_extra_writers_single_per_core: u16,
    pub adaptive_floor_max_extra_writers_multi_per_core: u16,
    pub adaptive_floor_max_active_writers_per_core: u16,
    pub adaptive_floor_max_warm_writers_per_core: u16,
    pub adaptive_floor_max_active_writers_global: u32,
    pub adaptive_floor_max_warm_writers_global: u32,
    pub adaptive_floor_cpu_cores_detected: u32,
    pub adaptive_floor_cpu_cores_effective: u32,
    pub adaptive_floor_global_cap_raw: u64,
    pub adaptive_floor_global_cap_effective: u64,
    pub adaptive_floor_target_writers_total: u64,
    pub adaptive_floor_active_cap_configured: u64,
    pub adaptive_floor_active_cap_effective: u64,
    pub adaptive_floor_warm_cap_configured: u64,
    pub adaptive_floor_warm_cap_effective: u64,
    pub adaptive_floor_active_writers_current: u64,
    pub adaptive_floor_warm_writers_current: u64,
    pub me_keepalive_enabled: bool,
    pub me_keepalive_interval_secs: u64,
    pub me_keepalive_jitter_secs: u64,
    pub me_keepalive_payload_random: bool,
    pub rpc_proxy_req_every_secs: u64,
    pub me_reconnect_max_concurrent_per_dc: u32,
    pub me_reconnect_backoff_base_ms: u64,
    pub me_reconnect_backoff_cap_ms: u64,
    pub me_reconnect_fast_retry_count: u32,
    pub me_pool_drain_ttl_secs: u64,
    pub me_pool_force_close_secs: u64,
    pub me_pool_min_fresh_ratio: f32,
    pub me_bind_stale_mode: &'static str,
    pub me_bind_stale_ttl_secs: u64,
    pub me_single_endpoint_shadow_writers: u8,
    pub me_single_endpoint_outage_mode_enabled: bool,
    pub me_single_endpoint_outage_disable_quarantine: bool,
    pub me_single_endpoint_outage_backoff_min_ms: u64,
    pub me_single_endpoint_outage_backoff_max_ms: u64,
    pub me_single_endpoint_shadow_rotate_every_secs: u64,
    pub me_deterministic_writer_sort: bool,
    pub me_writer_pick_mode: &'static str,
    pub me_writer_pick_sample_size: u8,
    pub me_socks_kdf_policy: &'static str,
    pub quarantined_endpoints: Vec<MeApiQuarantinedEndpointSnapshot>,
    pub network_path: Vec<MeApiDcPathSnapshot>,
}

fn ratio_pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let pct = ((part as f64) / (total as f64)) * 100.0;
    pct.clamp(0.0, 100.0)
}

fn extend_signed_endpoints(
    endpoints_by_dc: &mut BTreeMap<i16, BTreeSet<SocketAddr>>,
    map: HashMap<i32, Vec<(IpAddr, u16)>>,
) {
    for (dc, addrs) in map {
        if dc == 0 {
            continue;
        }
        let Ok(dc_idx) = i16::try_from(dc) else {
            continue;
        };
        let entry = endpoints_by_dc.entry(dc_idx).or_default();
        for (ip, port) in addrs {
            entry.insert(SocketAddr::new(ip, port));
        }
    }
}

fn floor_mode_label(mode: MeFloorMode) -> &'static str {
    match mode {
        MeFloorMode::Static => "static",
        MeFloorMode::Adaptive => "adaptive",
    }
}

fn bind_stale_mode_label(mode: MeBindStaleMode) -> &'static str {
    match mode {
        MeBindStaleMode::Never => "never",
        MeBindStaleMode::Ttl => "ttl",
        MeBindStaleMode::Always => "always",
    }
}

fn writer_pick_mode_label(mode: crate::config::MeWriterPickMode) -> &'static str {
    match mode {
        crate::config::MeWriterPickMode::SortedRr => "sorted_rr",
        crate::config::MeWriterPickMode::P2c => "p2c",
    }
}

fn socks_kdf_policy_label(policy: MeSocksKdfPolicy) -> &'static str {
    match policy {
        MeSocksKdfPolicy::Strict => "strict",
        MeSocksKdfPolicy::Compat => "compat",
    }
}

fn ip_preference_label(preference: IpPreference) -> &'static str {
    match preference {
        IpPreference::Unknown => "unknown",
        IpPreference::PreferV6 => "prefer_v6",
        IpPreference::PreferV4 => "prefer_v4",
        IpPreference::BothWork => "both",
        IpPreference::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::ratio_pct;

    #[test]
    fn ratio_pct_is_zero_when_denominator_is_zero() {
        assert_eq!(ratio_pct(1, 0), 0.0);
    }

    #[test]
    fn ratio_pct_is_capped_at_100() {
        assert_eq!(ratio_pct(7, 3), 100.0);
    }

    #[test]
    fn ratio_pct_reports_expected_value() {
        assert_eq!(ratio_pct(1, 4), 25.0);
    }
}
