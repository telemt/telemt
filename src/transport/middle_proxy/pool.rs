use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, Notify, RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::config::{
    MeBindStaleMode, MeFloorMode, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode,
};
use crate::crypto::SecureRandom;
use crate::network::IpFamily;
use crate::network::probe::NetworkDecision;
use crate::transport::UpstreamManager;

use super::ConnRegistry;
use super::codec::WriterCommand;

const ME_FORCE_CLOSE_SAFETY_FALLBACK_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct RefillDcKey {
    pub dc: i32,
    pub family: IpFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct RefillEndpointKey {
    pub dc: i32,
    pub addr: SocketAddr,
}

#[derive(Clone)]
pub struct MeWriter {
    pub id: u64,
    pub addr: SocketAddr,
    pub source_ip: IpAddr,
    pub writer_dc: i32,
    pub generation: u64,
    pub contour: Arc<AtomicU8>,
    pub created_at: Instant,
    pub tx: mpsc::Sender<WriterCommand>,
    pub cancel: CancellationToken,
    pub degraded: Arc<AtomicBool>,
    pub rtt_ema_ms_x10: Arc<AtomicU32>,
    pub draining: Arc<AtomicBool>,
    pub draining_started_at_epoch_secs: Arc<AtomicU64>,
    pub drain_deadline_epoch_secs: Arc<AtomicU64>,
    pub allow_drain_fallback: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum WriterContour {
    Warm = 0,
    Active = 1,
    Draining = 2,
}

impl WriterContour {
    pub(super) fn as_u8(self) -> u8 {
        self as u8
    }

    pub(super) fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Warm,
            1 => Self::Active,
            2 => Self::Draining,
            _ => Self::Draining,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MeFamilyRuntimeState {
    Healthy = 0,
    Degraded = 1,
    Suppressed = 2,
    Recovering = 3,
}

impl MeFamilyRuntimeState {
    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Degraded,
            2 => Self::Suppressed,
            3 => Self::Recovering,
            _ => Self::Healthy,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Suppressed => "suppressed",
            Self::Recovering => "recovering",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MeDrainGateReason {
    Open = 0,
    CoverageQuorum = 1,
    Redundancy = 2,
    SuppressionActive = 3,
}

impl MeDrainGateReason {
    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::CoverageQuorum,
            2 => Self::Redundancy,
            3 => Self::SuppressionActive,
            _ => Self::Open,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::CoverageQuorum => "coverage_quorum",
            Self::Redundancy => "redundancy",
            Self::SuppressionActive => "suppression_active",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretSnapshot {
    pub epoch: u64,
    pub key_selector: u32,
    pub secret: Vec<u8>,
}

#[allow(dead_code)]
pub struct MePool {
    pub(super) registry: Arc<ConnRegistry>,
    pub(super) writers: Arc<RwLock<Vec<MeWriter>>>,
    pub(super) rr: AtomicU64,
    pub(super) decision: NetworkDecision,
    pub(super) upstream: Option<Arc<UpstreamManager>>,
    pub(super) rng: Arc<SecureRandom>,
    pub(super) proxy_tag: Option<Vec<u8>>,
    pub(super) proxy_secret: Arc<RwLock<SecretSnapshot>>,
    pub(super) nat_ip_cfg: Option<IpAddr>,
    pub(super) nat_ip_detected: Arc<RwLock<Option<IpAddr>>>,
    pub(super) nat_probe: bool,
    pub(super) nat_stun: Option<String>,
    pub(super) nat_stun_servers: Vec<String>,
    pub(super) nat_stun_live_servers: Arc<RwLock<Vec<String>>>,
    pub(super) nat_probe_concurrency: usize,
    pub(super) detected_ipv6: Option<Ipv6Addr>,
    pub(super) nat_probe_attempts: std::sync::atomic::AtomicU8,
    pub(super) nat_probe_disabled: std::sync::atomic::AtomicBool,
    pub(super) stun_backoff_until: Arc<RwLock<Option<Instant>>>,
    pub(super) me_one_retry: u8,
    pub(super) me_one_timeout: Duration,
    pub(super) me_keepalive_enabled: bool,
    pub(super) me_keepalive_interval: Duration,
    pub(super) me_keepalive_jitter: Duration,
    pub(super) me_keepalive_payload_random: bool,
    pub(super) rpc_proxy_req_every_secs: AtomicU64,
    pub(super) writer_cmd_channel_capacity: usize,
    pub(super) me_warmup_stagger_enabled: bool,
    pub(super) me_warmup_step_delay: Duration,
    pub(super) me_warmup_step_jitter: Duration,
    pub(super) me_reconnect_max_concurrent_per_dc: u32,
    pub(super) me_reconnect_backoff_base: Duration,
    pub(super) me_reconnect_backoff_cap: Duration,
    pub(super) me_reconnect_fast_retry_count: u32,
    pub(super) me_single_endpoint_shadow_writers: AtomicU8,
    pub(super) me_single_endpoint_outage_mode_enabled: AtomicBool,
    pub(super) me_single_endpoint_outage_disable_quarantine: AtomicBool,
    pub(super) me_single_endpoint_outage_backoff_min_ms: AtomicU64,
    pub(super) me_single_endpoint_outage_backoff_max_ms: AtomicU64,
    pub(super) me_single_endpoint_shadow_rotate_every_secs: AtomicU64,
    pub(super) me_floor_mode: AtomicU8,
    pub(super) me_adaptive_floor_idle_secs: AtomicU64,
    pub(super) me_adaptive_floor_min_writers_single_endpoint: AtomicU8,
    pub(super) me_adaptive_floor_min_writers_multi_endpoint: AtomicU8,
    pub(super) me_adaptive_floor_recover_grace_secs: AtomicU64,
    pub(super) me_adaptive_floor_writers_per_core_total: AtomicU32,
    pub(super) me_adaptive_floor_cpu_cores_override: AtomicU32,
    pub(super) me_adaptive_floor_max_extra_writers_single_per_core: AtomicU32,
    pub(super) me_adaptive_floor_max_extra_writers_multi_per_core: AtomicU32,
    pub(super) me_adaptive_floor_max_active_writers_per_core: AtomicU32,
    pub(super) me_adaptive_floor_max_warm_writers_per_core: AtomicU32,
    pub(super) me_adaptive_floor_max_active_writers_global: AtomicU32,
    pub(super) me_adaptive_floor_max_warm_writers_global: AtomicU32,
    pub(super) me_adaptive_floor_cpu_cores_detected: AtomicU32,
    pub(super) me_adaptive_floor_cpu_cores_effective: AtomicU32,
    pub(super) me_adaptive_floor_global_cap_raw: AtomicU64,
    pub(super) me_adaptive_floor_global_cap_effective: AtomicU64,
    pub(super) me_adaptive_floor_target_writers_total: AtomicU64,
    pub(super) me_adaptive_floor_active_cap_configured: AtomicU64,
    pub(super) me_adaptive_floor_active_cap_effective: AtomicU64,
    pub(super) me_adaptive_floor_warm_cap_configured: AtomicU64,
    pub(super) me_adaptive_floor_warm_cap_effective: AtomicU64,
    pub(super) me_adaptive_floor_active_writers_current: AtomicU64,
    pub(super) me_adaptive_floor_warm_writers_current: AtomicU64,
    pub(super) proxy_map_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) proxy_map_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) endpoint_dc_map: Arc<RwLock<HashMap<SocketAddr, Option<i32>>>>,
    pub(super) default_dc: AtomicI32,
    pub(super) next_writer_id: AtomicU64,
    pub(super) ping_tracker: Arc<Mutex<HashMap<i64, (std::time::Instant, u64)>>>,
    pub(super) ping_tracker_last_cleanup_epoch_ms: AtomicU64,
    pub(super) rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    pub(super) nat_reflection_cache: Arc<Mutex<NatReflectionCache>>,
    pub(super) nat_reflection_singleflight_v4: Arc<Mutex<()>>,
    pub(super) nat_reflection_singleflight_v6: Arc<Mutex<()>>,
    pub(super) writer_available: Arc<Notify>,
    pub(super) refill_inflight: Arc<Mutex<HashSet<RefillEndpointKey>>>,
    pub(super) refill_inflight_dc: Arc<Mutex<HashSet<RefillDcKey>>>,
    pub(super) conn_count: AtomicUsize,
    pub(super) stats: Arc<crate::stats::Stats>,
    pub(super) generation: AtomicU64,
    pub(super) active_generation: AtomicU64,
    pub(super) warm_generation: AtomicU64,
    pub(super) pending_hardswap_generation: AtomicU64,
    pub(super) pending_hardswap_started_at_epoch_secs: AtomicU64,
    pub(super) pending_hardswap_map_hash: AtomicU64,
    pub(super) hardswap: AtomicBool,
    pub(super) endpoint_quarantine: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    pub(super) kdf_material_fingerprint: Arc<RwLock<HashMap<SocketAddr, (u64, u16)>>>,
    pub(super) me_pool_drain_ttl_secs: AtomicU64,
    pub(super) me_instadrain: AtomicBool,
    pub(super) me_pool_drain_threshold: AtomicU64,
    pub(super) me_pool_drain_soft_evict_enabled: AtomicBool,
    pub(super) me_pool_drain_soft_evict_grace_secs: AtomicU64,
    pub(super) me_pool_drain_soft_evict_per_writer: AtomicU8,
    pub(super) me_pool_drain_soft_evict_budget_per_core: AtomicU32,
    pub(super) me_pool_drain_soft_evict_cooldown_ms: AtomicU64,
    pub(super) me_pool_force_close_secs: AtomicU64,
    pub(super) me_pool_min_fresh_ratio_permille: AtomicU32,
    pub(super) me_hardswap_warmup_delay_min_ms: AtomicU64,
    pub(super) me_hardswap_warmup_delay_max_ms: AtomicU64,
    pub(super) me_hardswap_warmup_extra_passes: AtomicU32,
    pub(super) me_hardswap_warmup_pass_backoff_base_ms: AtomicU64,
    pub(super) me_bind_stale_mode: AtomicU8,
    pub(super) me_bind_stale_ttl_secs: AtomicU64,
    pub(super) secret_atomic_snapshot: AtomicBool,
    pub(super) me_deterministic_writer_sort: AtomicBool,
    pub(super) me_writer_pick_mode: AtomicU8,
    pub(super) me_writer_pick_sample_size: AtomicU8,
    pub(super) me_socks_kdf_policy: AtomicU8,
    pub(super) me_reader_route_data_wait_ms: Arc<AtomicU64>,
    pub(super) me_route_no_writer_mode: AtomicU8,
    pub(super) me_route_no_writer_wait: Duration,
    pub(super) me_route_hybrid_max_wait: Duration,
    pub(super) me_route_blocking_send_timeout: Duration,
    pub(super) me_route_inline_recovery_attempts: u32,
    pub(super) me_route_inline_recovery_wait: Duration,
    pub(super) me_health_interval_ms_unhealthy: AtomicU64,
    pub(super) me_health_interval_ms_healthy: AtomicU64,
    pub(super) me_warn_rate_limit_ms: AtomicU64,
    pub(super) me_family_v4_runtime_state: AtomicU8,
    pub(super) me_family_v6_runtime_state: AtomicU8,
    pub(super) me_family_v4_state_since_epoch_secs: AtomicU64,
    pub(super) me_family_v6_state_since_epoch_secs: AtomicU64,
    pub(super) me_family_v4_suppressed_until_epoch_secs: AtomicU64,
    pub(super) me_family_v6_suppressed_until_epoch_secs: AtomicU64,
    pub(super) me_family_v4_fail_streak: AtomicU32,
    pub(super) me_family_v6_fail_streak: AtomicU32,
    pub(super) me_family_v4_recover_success_streak: AtomicU32,
    pub(super) me_family_v6_recover_success_streak: AtomicU32,
    pub(super) me_last_drain_gate_route_quorum_ok: AtomicBool,
    pub(super) me_last_drain_gate_redundancy_ok: AtomicBool,
    pub(super) me_last_drain_gate_block_reason: AtomicU8,
    pub(super) me_last_drain_gate_updated_at_epoch_secs: AtomicU64,
    pub(super) runtime_ready: AtomicBool,
    pool_size: usize,
    pub(super) preferred_endpoints_by_dc: Arc<RwLock<HashMap<i32, Vec<SocketAddr>>>>,
}

#[derive(Debug, Default)]
pub struct NatReflectionCache {
    pub v4: Option<(std::time::Instant, std::net::SocketAddr)>,
    pub v6: Option<(std::time::Instant, std::net::SocketAddr)>,
}

impl MePool {
    fn ratio_to_permille(ratio: f32) -> u32 {
        let clamped = ratio.clamp(0.0, 1.0);
        (clamped * 1000.0).round() as u32
    }

    pub(super) fn permille_to_ratio(permille: u32) -> f32 {
        (permille.min(1000) as f32) / 1000.0
    }

    pub(super) fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn normalize_force_close_secs(force_close_secs: u64) -> u64 {
        if force_close_secs == 0 {
            ME_FORCE_CLOSE_SAFETY_FALLBACK_SECS
        } else {
            force_close_secs
        }
    }

    pub fn new(
        proxy_tag: Option<Vec<u8>>,
        proxy_secret: Vec<u8>,
        nat_ip: Option<IpAddr>,
        nat_probe: bool,
        nat_stun: Option<String>,
        nat_stun_servers: Vec<String>,
        nat_probe_concurrency: usize,
        detected_ipv6: Option<Ipv6Addr>,
        me_one_retry: u8,
        me_one_timeout_ms: u64,
        proxy_map_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        proxy_map_v6: HashMap<i32, Vec<(IpAddr, u16)>>,
        default_dc: Option<i32>,
        decision: NetworkDecision,
        upstream: Option<Arc<UpstreamManager>>,
        rng: Arc<SecureRandom>,
        stats: Arc<crate::stats::Stats>,
        me_keepalive_enabled: bool,
        me_keepalive_interval_secs: u64,
        me_keepalive_jitter_secs: u64,
        me_keepalive_payload_random: bool,
        rpc_proxy_req_every_secs: u64,
        me_warmup_stagger_enabled: bool,
        me_warmup_step_delay_ms: u64,
        me_warmup_step_jitter_ms: u64,
        me_reconnect_max_concurrent_per_dc: u32,
        me_reconnect_backoff_base_ms: u64,
        me_reconnect_backoff_cap_ms: u64,
        me_reconnect_fast_retry_count: u32,
        me_single_endpoint_shadow_writers: u8,
        me_single_endpoint_outage_mode_enabled: bool,
        me_single_endpoint_outage_disable_quarantine: bool,
        me_single_endpoint_outage_backoff_min_ms: u64,
        me_single_endpoint_outage_backoff_max_ms: u64,
        me_single_endpoint_shadow_rotate_every_secs: u64,
        me_floor_mode: MeFloorMode,
        me_adaptive_floor_idle_secs: u64,
        me_adaptive_floor_min_writers_single_endpoint: u8,
        me_adaptive_floor_min_writers_multi_endpoint: u8,
        me_adaptive_floor_recover_grace_secs: u64,
        me_adaptive_floor_writers_per_core_total: u16,
        me_adaptive_floor_cpu_cores_override: u16,
        me_adaptive_floor_max_extra_writers_single_per_core: u16,
        me_adaptive_floor_max_extra_writers_multi_per_core: u16,
        me_adaptive_floor_max_active_writers_per_core: u16,
        me_adaptive_floor_max_warm_writers_per_core: u16,
        me_adaptive_floor_max_active_writers_global: u32,
        me_adaptive_floor_max_warm_writers_global: u32,
        hardswap: bool,
        me_pool_drain_ttl_secs: u64,
        me_instadrain: bool,
        me_pool_drain_threshold: u64,
        me_pool_drain_soft_evict_enabled: bool,
        me_pool_drain_soft_evict_grace_secs: u64,
        me_pool_drain_soft_evict_per_writer: u8,
        me_pool_drain_soft_evict_budget_per_core: u16,
        me_pool_drain_soft_evict_cooldown_ms: u64,
        me_pool_force_close_secs: u64,
        me_pool_min_fresh_ratio: f32,
        me_hardswap_warmup_delay_min_ms: u64,
        me_hardswap_warmup_delay_max_ms: u64,
        me_hardswap_warmup_extra_passes: u8,
        me_hardswap_warmup_pass_backoff_base_ms: u64,
        me_bind_stale_mode: MeBindStaleMode,
        me_bind_stale_ttl_secs: u64,
        me_secret_atomic_snapshot: bool,
        me_deterministic_writer_sort: bool,
        me_writer_pick_mode: MeWriterPickMode,
        me_writer_pick_sample_size: u8,
        me_socks_kdf_policy: MeSocksKdfPolicy,
        me_writer_cmd_channel_capacity: usize,
        me_route_channel_capacity: usize,
        me_route_backpressure_base_timeout_ms: u64,
        me_route_backpressure_high_timeout_ms: u64,
        me_route_backpressure_high_watermark_pct: u8,
        me_reader_route_data_wait_ms: u64,
        me_health_interval_ms_unhealthy: u64,
        me_health_interval_ms_healthy: u64,
        me_warn_rate_limit_ms: u64,
        me_route_no_writer_mode: MeRouteNoWriterMode,
        me_route_no_writer_wait_ms: u64,
        me_route_hybrid_max_wait_ms: u64,
        me_route_blocking_send_timeout_ms: u64,
        me_route_inline_recovery_attempts: u32,
        me_route_inline_recovery_wait_ms: u64,
    ) -> Arc<Self> {
        let endpoint_dc_map = Self::build_endpoint_dc_map_from_maps(&proxy_map_v4, &proxy_map_v6);
        let preferred_endpoints_by_dc =
            Self::build_preferred_endpoints_by_dc(&decision, &proxy_map_v4, &proxy_map_v6);
        let registry = Arc::new(ConnRegistry::with_route_channel_capacity(
            me_route_channel_capacity,
        ));
        registry.update_route_backpressure_policy(
            me_route_backpressure_base_timeout_ms,
            me_route_backpressure_high_timeout_ms,
            me_route_backpressure_high_watermark_pct,
        );
        Arc::new(Self {
            registry,
            writers: Arc::new(RwLock::new(Vec::new())),
            rr: AtomicU64::new(0),
            decision,
            upstream,
            rng,
            proxy_tag,
            proxy_secret: Arc::new(RwLock::new(SecretSnapshot {
                epoch: 1,
                key_selector: if proxy_secret.len() >= 4 {
                    u32::from_le_bytes([
                        proxy_secret[0],
                        proxy_secret[1],
                        proxy_secret[2],
                        proxy_secret[3],
                    ])
                } else {
                    0
                },
                secret: proxy_secret,
            })),
            nat_ip_cfg: nat_ip,
            nat_ip_detected: Arc::new(RwLock::new(None)),
            nat_probe,
            nat_stun,
            nat_stun_servers,
            nat_stun_live_servers: Arc::new(RwLock::new(Vec::new())),
            nat_probe_concurrency: nat_probe_concurrency.max(1),
            detected_ipv6,
            nat_probe_attempts: std::sync::atomic::AtomicU8::new(0),
            nat_probe_disabled: std::sync::atomic::AtomicBool::new(false),
            stun_backoff_until: Arc::new(RwLock::new(None)),
            me_one_retry,
            me_one_timeout: Duration::from_millis(me_one_timeout_ms),
            stats,
            me_keepalive_enabled,
            me_keepalive_interval: Duration::from_secs(me_keepalive_interval_secs),
            me_keepalive_jitter: Duration::from_secs(me_keepalive_jitter_secs),
            me_keepalive_payload_random,
            rpc_proxy_req_every_secs: AtomicU64::new(rpc_proxy_req_every_secs),
            writer_cmd_channel_capacity: me_writer_cmd_channel_capacity.max(1),
            me_warmup_stagger_enabled,
            me_warmup_step_delay: Duration::from_millis(me_warmup_step_delay_ms),
            me_warmup_step_jitter: Duration::from_millis(me_warmup_step_jitter_ms),
            me_reconnect_max_concurrent_per_dc,
            me_reconnect_backoff_base: Duration::from_millis(me_reconnect_backoff_base_ms),
            me_reconnect_backoff_cap: Duration::from_millis(me_reconnect_backoff_cap_ms),
            me_reconnect_fast_retry_count,
            me_single_endpoint_shadow_writers: AtomicU8::new(me_single_endpoint_shadow_writers),
            me_single_endpoint_outage_mode_enabled: AtomicBool::new(
                me_single_endpoint_outage_mode_enabled,
            ),
            me_single_endpoint_outage_disable_quarantine: AtomicBool::new(
                me_single_endpoint_outage_disable_quarantine,
            ),
            me_single_endpoint_outage_backoff_min_ms: AtomicU64::new(
                me_single_endpoint_outage_backoff_min_ms,
            ),
            me_single_endpoint_outage_backoff_max_ms: AtomicU64::new(
                me_single_endpoint_outage_backoff_max_ms,
            ),
            me_single_endpoint_shadow_rotate_every_secs: AtomicU64::new(
                me_single_endpoint_shadow_rotate_every_secs,
            ),
            me_floor_mode: AtomicU8::new(me_floor_mode.as_u8()),
            me_adaptive_floor_idle_secs: AtomicU64::new(me_adaptive_floor_idle_secs),
            me_adaptive_floor_min_writers_single_endpoint: AtomicU8::new(
                me_adaptive_floor_min_writers_single_endpoint,
            ),
            me_adaptive_floor_min_writers_multi_endpoint: AtomicU8::new(
                me_adaptive_floor_min_writers_multi_endpoint,
            ),
            me_adaptive_floor_recover_grace_secs: AtomicU64::new(
                me_adaptive_floor_recover_grace_secs,
            ),
            me_adaptive_floor_writers_per_core_total: AtomicU32::new(
                me_adaptive_floor_writers_per_core_total as u32,
            ),
            me_adaptive_floor_cpu_cores_override: AtomicU32::new(
                me_adaptive_floor_cpu_cores_override as u32,
            ),
            me_adaptive_floor_max_extra_writers_single_per_core: AtomicU32::new(
                me_adaptive_floor_max_extra_writers_single_per_core as u32,
            ),
            me_adaptive_floor_max_extra_writers_multi_per_core: AtomicU32::new(
                me_adaptive_floor_max_extra_writers_multi_per_core as u32,
            ),
            me_adaptive_floor_max_active_writers_per_core: AtomicU32::new(
                me_adaptive_floor_max_active_writers_per_core as u32,
            ),
            me_adaptive_floor_max_warm_writers_per_core: AtomicU32::new(
                me_adaptive_floor_max_warm_writers_per_core as u32,
            ),
            me_adaptive_floor_max_active_writers_global: AtomicU32::new(
                me_adaptive_floor_max_active_writers_global,
            ),
            me_adaptive_floor_max_warm_writers_global: AtomicU32::new(
                me_adaptive_floor_max_warm_writers_global,
            ),
            me_adaptive_floor_cpu_cores_detected: AtomicU32::new(1),
            me_adaptive_floor_cpu_cores_effective: AtomicU32::new(1),
            me_adaptive_floor_global_cap_raw: AtomicU64::new(0),
            me_adaptive_floor_global_cap_effective: AtomicU64::new(0),
            me_adaptive_floor_target_writers_total: AtomicU64::new(0),
            me_adaptive_floor_active_cap_configured: AtomicU64::new(0),
            me_adaptive_floor_active_cap_effective: AtomicU64::new(0),
            me_adaptive_floor_warm_cap_configured: AtomicU64::new(0),
            me_adaptive_floor_warm_cap_effective: AtomicU64::new(0),
            me_adaptive_floor_active_writers_current: AtomicU64::new(0),
            me_adaptive_floor_warm_writers_current: AtomicU64::new(0),
            pool_size: 2,
            proxy_map_v4: Arc::new(RwLock::new(proxy_map_v4)),
            proxy_map_v6: Arc::new(RwLock::new(proxy_map_v6)),
            endpoint_dc_map: Arc::new(RwLock::new(endpoint_dc_map)),
            default_dc: AtomicI32::new(default_dc.unwrap_or(2)),
            next_writer_id: AtomicU64::new(1),
            ping_tracker: Arc::new(Mutex::new(HashMap::new())),
            ping_tracker_last_cleanup_epoch_ms: AtomicU64::new(0),
            rtt_stats: Arc::new(Mutex::new(HashMap::new())),
            nat_reflection_cache: Arc::new(Mutex::new(NatReflectionCache::default())),
            nat_reflection_singleflight_v4: Arc::new(Mutex::new(())),
            nat_reflection_singleflight_v6: Arc::new(Mutex::new(())),
            writer_available: Arc::new(Notify::new()),
            refill_inflight: Arc::new(Mutex::new(HashSet::new())),
            refill_inflight_dc: Arc::new(Mutex::new(HashSet::new())),
            conn_count: AtomicUsize::new(0),
            generation: AtomicU64::new(1),
            active_generation: AtomicU64::new(1),
            warm_generation: AtomicU64::new(0),
            pending_hardswap_generation: AtomicU64::new(0),
            pending_hardswap_started_at_epoch_secs: AtomicU64::new(0),
            pending_hardswap_map_hash: AtomicU64::new(0),
            hardswap: AtomicBool::new(hardswap),
            endpoint_quarantine: Arc::new(Mutex::new(HashMap::new())),
            kdf_material_fingerprint: Arc::new(RwLock::new(HashMap::new())),
            me_pool_drain_ttl_secs: AtomicU64::new(me_pool_drain_ttl_secs),
            me_instadrain: AtomicBool::new(me_instadrain),
            me_pool_drain_threshold: AtomicU64::new(me_pool_drain_threshold),
            me_pool_drain_soft_evict_enabled: AtomicBool::new(me_pool_drain_soft_evict_enabled),
            me_pool_drain_soft_evict_grace_secs: AtomicU64::new(me_pool_drain_soft_evict_grace_secs),
            me_pool_drain_soft_evict_per_writer: AtomicU8::new(
                me_pool_drain_soft_evict_per_writer.max(1),
            ),
            me_pool_drain_soft_evict_budget_per_core: AtomicU32::new(
                me_pool_drain_soft_evict_budget_per_core.max(1) as u32,
            ),
            me_pool_drain_soft_evict_cooldown_ms: AtomicU64::new(
                me_pool_drain_soft_evict_cooldown_ms.max(1),
            ),
            me_pool_force_close_secs: AtomicU64::new(Self::normalize_force_close_secs(
                me_pool_force_close_secs,
            )),
            me_pool_min_fresh_ratio_permille: AtomicU32::new(Self::ratio_to_permille(
                me_pool_min_fresh_ratio,
            )),
            me_hardswap_warmup_delay_min_ms: AtomicU64::new(me_hardswap_warmup_delay_min_ms),
            me_hardswap_warmup_delay_max_ms: AtomicU64::new(me_hardswap_warmup_delay_max_ms),
            me_hardswap_warmup_extra_passes: AtomicU32::new(me_hardswap_warmup_extra_passes as u32),
            me_hardswap_warmup_pass_backoff_base_ms: AtomicU64::new(
                me_hardswap_warmup_pass_backoff_base_ms,
            ),
            me_bind_stale_mode: AtomicU8::new(me_bind_stale_mode.as_u8()),
            me_bind_stale_ttl_secs: AtomicU64::new(me_bind_stale_ttl_secs),
            secret_atomic_snapshot: AtomicBool::new(me_secret_atomic_snapshot),
            me_deterministic_writer_sort: AtomicBool::new(me_deterministic_writer_sort),
            me_writer_pick_mode: AtomicU8::new(me_writer_pick_mode.as_u8()),
            me_writer_pick_sample_size: AtomicU8::new(me_writer_pick_sample_size.clamp(2, 4)),
            me_socks_kdf_policy: AtomicU8::new(me_socks_kdf_policy.as_u8()),
            me_reader_route_data_wait_ms: Arc::new(AtomicU64::new(me_reader_route_data_wait_ms)),
            me_route_no_writer_mode: AtomicU8::new(me_route_no_writer_mode.as_u8()),
            me_route_no_writer_wait: Duration::from_millis(me_route_no_writer_wait_ms),
            me_route_hybrid_max_wait: Duration::from_millis(me_route_hybrid_max_wait_ms),
            me_route_blocking_send_timeout: Duration::from_millis(
                me_route_blocking_send_timeout_ms,
            ),
            me_route_inline_recovery_attempts,
            me_route_inline_recovery_wait: Duration::from_millis(me_route_inline_recovery_wait_ms),
            me_health_interval_ms_unhealthy: AtomicU64::new(me_health_interval_ms_unhealthy.max(1)),
            me_health_interval_ms_healthy: AtomicU64::new(me_health_interval_ms_healthy.max(1)),
            me_warn_rate_limit_ms: AtomicU64::new(me_warn_rate_limit_ms.max(1)),
            me_family_v4_runtime_state: AtomicU8::new(MeFamilyRuntimeState::Healthy as u8),
            me_family_v6_runtime_state: AtomicU8::new(MeFamilyRuntimeState::Healthy as u8),
            me_family_v4_state_since_epoch_secs: AtomicU64::new(Self::now_epoch_secs()),
            me_family_v6_state_since_epoch_secs: AtomicU64::new(Self::now_epoch_secs()),
            me_family_v4_suppressed_until_epoch_secs: AtomicU64::new(0),
            me_family_v6_suppressed_until_epoch_secs: AtomicU64::new(0),
            me_family_v4_fail_streak: AtomicU32::new(0),
            me_family_v6_fail_streak: AtomicU32::new(0),
            me_family_v4_recover_success_streak: AtomicU32::new(0),
            me_family_v6_recover_success_streak: AtomicU32::new(0),
            me_last_drain_gate_route_quorum_ok: AtomicBool::new(false),
            me_last_drain_gate_redundancy_ok: AtomicBool::new(false),
            me_last_drain_gate_block_reason: AtomicU8::new(MeDrainGateReason::Open as u8),
            me_last_drain_gate_updated_at_epoch_secs: AtomicU64::new(Self::now_epoch_secs()),
            runtime_ready: AtomicBool::new(false),
            preferred_endpoints_by_dc: Arc::new(RwLock::new(preferred_endpoints_by_dc)),
        })
    }

    pub fn current_generation(&self) -> u64 {
        self.active_generation.load(Ordering::Relaxed)
    }

    pub fn set_runtime_ready(&self, ready: bool) {
        self.runtime_ready.store(ready, Ordering::Relaxed);
    }

    pub fn is_runtime_ready(&self) -> bool {
        self.runtime_ready.load(Ordering::Relaxed)
    }

    pub(super) fn set_family_runtime_state(
        &self,
        family: IpFamily,
        state: MeFamilyRuntimeState,
        state_since_epoch_secs: u64,
        suppressed_until_epoch_secs: u64,
        fail_streak: u32,
        recover_success_streak: u32,
    ) {
        match family {
            IpFamily::V4 => {
                self.me_family_v4_runtime_state
                    .store(state as u8, Ordering::Relaxed);
                self.me_family_v4_state_since_epoch_secs
                    .store(state_since_epoch_secs, Ordering::Relaxed);
                self.me_family_v4_suppressed_until_epoch_secs
                    .store(suppressed_until_epoch_secs, Ordering::Relaxed);
                self.me_family_v4_fail_streak
                    .store(fail_streak, Ordering::Relaxed);
                self.me_family_v4_recover_success_streak
                    .store(recover_success_streak, Ordering::Relaxed);
            }
            IpFamily::V6 => {
                self.me_family_v6_runtime_state
                    .store(state as u8, Ordering::Relaxed);
                self.me_family_v6_state_since_epoch_secs
                    .store(state_since_epoch_secs, Ordering::Relaxed);
                self.me_family_v6_suppressed_until_epoch_secs
                    .store(suppressed_until_epoch_secs, Ordering::Relaxed);
                self.me_family_v6_fail_streak
                    .store(fail_streak, Ordering::Relaxed);
                self.me_family_v6_recover_success_streak
                    .store(recover_success_streak, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn family_runtime_state(&self, family: IpFamily) -> MeFamilyRuntimeState {
        match family {
            IpFamily::V4 => MeFamilyRuntimeState::from_u8(
                self.me_family_v4_runtime_state.load(Ordering::Relaxed),
            ),
            IpFamily::V6 => MeFamilyRuntimeState::from_u8(
                self.me_family_v6_runtime_state.load(Ordering::Relaxed),
            ),
        }
    }

    pub(crate) fn family_runtime_state_since_epoch_secs(&self, family: IpFamily) -> u64 {
        match family {
            IpFamily::V4 => self
                .me_family_v4_state_since_epoch_secs
                .load(Ordering::Relaxed),
            IpFamily::V6 => self
                .me_family_v6_state_since_epoch_secs
                .load(Ordering::Relaxed),
        }
    }

    pub(crate) fn family_suppressed_until_epoch_secs(&self, family: IpFamily) -> u64 {
        match family {
            IpFamily::V4 => self
                .me_family_v4_suppressed_until_epoch_secs
                .load(Ordering::Relaxed),
            IpFamily::V6 => self
                .me_family_v6_suppressed_until_epoch_secs
                .load(Ordering::Relaxed),
        }
    }

    pub(crate) fn family_fail_streak(&self, family: IpFamily) -> u32 {
        match family {
            IpFamily::V4 => self.me_family_v4_fail_streak.load(Ordering::Relaxed),
            IpFamily::V6 => self.me_family_v6_fail_streak.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn family_recover_success_streak(&self, family: IpFamily) -> u32 {
        match family {
            IpFamily::V4 => self
                .me_family_v4_recover_success_streak
                .load(Ordering::Relaxed),
            IpFamily::V6 => self
                .me_family_v6_recover_success_streak
                .load(Ordering::Relaxed),
        }
    }

    pub(crate) fn is_family_temporarily_suppressed(
        &self,
        family: IpFamily,
        now_epoch_secs: u64,
    ) -> bool {
        self.family_suppressed_until_epoch_secs(family) > now_epoch_secs
    }

    pub(super) fn family_enabled_for_drain_coverage(
        &self,
        family: IpFamily,
        now_epoch_secs: u64,
    ) -> bool {
        let configured = match family {
            IpFamily::V4 => self.decision.ipv4_me,
            IpFamily::V6 => self.decision.ipv6_me,
        };
        configured && !self.is_family_temporarily_suppressed(family, now_epoch_secs)
    }

    pub(super) fn set_last_drain_gate(
        &self,
        route_quorum_ok: bool,
        redundancy_ok: bool,
        block_reason: MeDrainGateReason,
        updated_at_epoch_secs: u64,
    ) {
        self.me_last_drain_gate_route_quorum_ok
            .store(route_quorum_ok, Ordering::Relaxed);
        self.me_last_drain_gate_redundancy_ok
            .store(redundancy_ok, Ordering::Relaxed);
        self.me_last_drain_gate_block_reason
            .store(block_reason as u8, Ordering::Relaxed);
        self.me_last_drain_gate_updated_at_epoch_secs
            .store(updated_at_epoch_secs, Ordering::Relaxed);
    }

    pub(crate) fn last_drain_gate_route_quorum_ok(&self) -> bool {
        self.me_last_drain_gate_route_quorum_ok
            .load(Ordering::Relaxed)
    }

    pub(crate) fn last_drain_gate_redundancy_ok(&self) -> bool {
        self.me_last_drain_gate_redundancy_ok
            .load(Ordering::Relaxed)
    }

    pub(crate) fn last_drain_gate_block_reason(&self) -> MeDrainGateReason {
        MeDrainGateReason::from_u8(
            self.me_last_drain_gate_block_reason
                .load(Ordering::Relaxed),
        )
    }

    pub(crate) fn last_drain_gate_updated_at_epoch_secs(&self) -> u64 {
        self.me_last_drain_gate_updated_at_epoch_secs
            .load(Ordering::Relaxed)
    }

    pub fn update_runtime_reinit_policy(
        &self,
        hardswap: bool,
        drain_ttl_secs: u64,
        instadrain: bool,
        pool_drain_threshold: u64,
        pool_drain_soft_evict_enabled: bool,
        pool_drain_soft_evict_grace_secs: u64,
        pool_drain_soft_evict_per_writer: u8,
        pool_drain_soft_evict_budget_per_core: u16,
        pool_drain_soft_evict_cooldown_ms: u64,
        force_close_secs: u64,
        min_fresh_ratio: f32,
        hardswap_warmup_delay_min_ms: u64,
        hardswap_warmup_delay_max_ms: u64,
        hardswap_warmup_extra_passes: u8,
        hardswap_warmup_pass_backoff_base_ms: u64,
        bind_stale_mode: MeBindStaleMode,
        bind_stale_ttl_secs: u64,
        secret_atomic_snapshot: bool,
        deterministic_writer_sort: bool,
        writer_pick_mode: MeWriterPickMode,
        writer_pick_sample_size: u8,
        single_endpoint_shadow_writers: u8,
        single_endpoint_outage_mode_enabled: bool,
        single_endpoint_outage_disable_quarantine: bool,
        single_endpoint_outage_backoff_min_ms: u64,
        single_endpoint_outage_backoff_max_ms: u64,
        single_endpoint_shadow_rotate_every_secs: u64,
        floor_mode: MeFloorMode,
        adaptive_floor_idle_secs: u64,
        adaptive_floor_min_writers_single_endpoint: u8,
        adaptive_floor_min_writers_multi_endpoint: u8,
        adaptive_floor_recover_grace_secs: u64,
        adaptive_floor_writers_per_core_total: u16,
        adaptive_floor_cpu_cores_override: u16,
        adaptive_floor_max_extra_writers_single_per_core: u16,
        adaptive_floor_max_extra_writers_multi_per_core: u16,
        adaptive_floor_max_active_writers_per_core: u16,
        adaptive_floor_max_warm_writers_per_core: u16,
        adaptive_floor_max_active_writers_global: u32,
        adaptive_floor_max_warm_writers_global: u32,
        me_health_interval_ms_unhealthy: u64,
        me_health_interval_ms_healthy: u64,
        me_warn_rate_limit_ms: u64,
    ) {
        self.hardswap.store(hardswap, Ordering::Relaxed);
        self.me_pool_drain_ttl_secs
            .store(drain_ttl_secs, Ordering::Relaxed);
        self.me_instadrain.store(instadrain, Ordering::Relaxed);
        self.me_pool_drain_threshold
            .store(pool_drain_threshold, Ordering::Relaxed);
        self.me_pool_drain_soft_evict_enabled
            .store(pool_drain_soft_evict_enabled, Ordering::Relaxed);
        self.me_pool_drain_soft_evict_grace_secs
            .store(pool_drain_soft_evict_grace_secs, Ordering::Relaxed);
        self.me_pool_drain_soft_evict_per_writer
            .store(pool_drain_soft_evict_per_writer.max(1), Ordering::Relaxed);
        self.me_pool_drain_soft_evict_budget_per_core.store(
            pool_drain_soft_evict_budget_per_core.max(1) as u32,
            Ordering::Relaxed,
        );
        self.me_pool_drain_soft_evict_cooldown_ms
            .store(pool_drain_soft_evict_cooldown_ms.max(1), Ordering::Relaxed);
        self.me_pool_force_close_secs.store(
            Self::normalize_force_close_secs(force_close_secs),
            Ordering::Relaxed,
        );
        self.me_pool_min_fresh_ratio_permille
            .store(Self::ratio_to_permille(min_fresh_ratio), Ordering::Relaxed);
        self.me_hardswap_warmup_delay_min_ms
            .store(hardswap_warmup_delay_min_ms, Ordering::Relaxed);
        self.me_hardswap_warmup_delay_max_ms
            .store(hardswap_warmup_delay_max_ms, Ordering::Relaxed);
        self.me_hardswap_warmup_extra_passes
            .store(hardswap_warmup_extra_passes as u32, Ordering::Relaxed);
        self.me_hardswap_warmup_pass_backoff_base_ms
            .store(hardswap_warmup_pass_backoff_base_ms, Ordering::Relaxed);
        self.me_bind_stale_mode
            .store(bind_stale_mode.as_u8(), Ordering::Relaxed);
        self.me_bind_stale_ttl_secs
            .store(bind_stale_ttl_secs, Ordering::Relaxed);
        self.secret_atomic_snapshot
            .store(secret_atomic_snapshot, Ordering::Relaxed);
        self.me_deterministic_writer_sort
            .store(deterministic_writer_sort, Ordering::Relaxed);
        let previous_writer_pick_mode = self.writer_pick_mode();
        self.me_writer_pick_mode
            .store(writer_pick_mode.as_u8(), Ordering::Relaxed);
        self.me_writer_pick_sample_size
            .store(writer_pick_sample_size.clamp(2, 4), Ordering::Relaxed);
        if previous_writer_pick_mode != writer_pick_mode {
            self.stats.increment_me_writer_pick_mode_switch_total();
        }
        self.me_single_endpoint_shadow_writers
            .store(single_endpoint_shadow_writers, Ordering::Relaxed);
        self.me_single_endpoint_outage_mode_enabled
            .store(single_endpoint_outage_mode_enabled, Ordering::Relaxed);
        self.me_single_endpoint_outage_disable_quarantine
            .store(single_endpoint_outage_disable_quarantine, Ordering::Relaxed);
        self.me_single_endpoint_outage_backoff_min_ms
            .store(single_endpoint_outage_backoff_min_ms, Ordering::Relaxed);
        self.me_single_endpoint_outage_backoff_max_ms
            .store(single_endpoint_outage_backoff_max_ms, Ordering::Relaxed);
        self.me_single_endpoint_shadow_rotate_every_secs
            .store(single_endpoint_shadow_rotate_every_secs, Ordering::Relaxed);
        let previous_floor_mode = self.floor_mode();
        self.me_floor_mode
            .store(floor_mode.as_u8(), Ordering::Relaxed);
        self.me_adaptive_floor_idle_secs
            .store(adaptive_floor_idle_secs, Ordering::Relaxed);
        self.me_adaptive_floor_min_writers_single_endpoint
            .store(adaptive_floor_min_writers_single_endpoint, Ordering::Relaxed);
        self.me_adaptive_floor_min_writers_multi_endpoint
            .store(adaptive_floor_min_writers_multi_endpoint, Ordering::Relaxed);
        self.me_adaptive_floor_recover_grace_secs
            .store(adaptive_floor_recover_grace_secs, Ordering::Relaxed);
        self.me_adaptive_floor_writers_per_core_total
            .store(adaptive_floor_writers_per_core_total as u32, Ordering::Relaxed);
        self.me_adaptive_floor_cpu_cores_override
            .store(adaptive_floor_cpu_cores_override as u32, Ordering::Relaxed);
        self.me_adaptive_floor_max_extra_writers_single_per_core
            .store(
                adaptive_floor_max_extra_writers_single_per_core as u32,
                Ordering::Relaxed,
            );
        self.me_adaptive_floor_max_extra_writers_multi_per_core
            .store(
                adaptive_floor_max_extra_writers_multi_per_core as u32,
                Ordering::Relaxed,
            );
        self.me_adaptive_floor_max_active_writers_per_core
            .store(
                adaptive_floor_max_active_writers_per_core as u32,
                Ordering::Relaxed,
            );
        self.me_adaptive_floor_max_warm_writers_per_core
            .store(
                adaptive_floor_max_warm_writers_per_core as u32,
                Ordering::Relaxed,
            );
        self.me_adaptive_floor_max_active_writers_global
            .store(adaptive_floor_max_active_writers_global, Ordering::Relaxed);
        self.me_adaptive_floor_max_warm_writers_global
            .store(adaptive_floor_max_warm_writers_global, Ordering::Relaxed);
        self.me_health_interval_ms_unhealthy
            .store(me_health_interval_ms_unhealthy.max(1), Ordering::Relaxed);
        self.me_health_interval_ms_healthy
            .store(me_health_interval_ms_healthy.max(1), Ordering::Relaxed);
        self.me_warn_rate_limit_ms
            .store(me_warn_rate_limit_ms.max(1), Ordering::Relaxed);
        if previous_floor_mode != floor_mode {
            self.stats.increment_me_floor_mode_switch_total();
            match (previous_floor_mode, floor_mode) {
                (MeFloorMode::Static, MeFloorMode::Adaptive) => {
                    self.stats
                        .increment_me_floor_mode_switch_static_to_adaptive_total();
                }
                (MeFloorMode::Adaptive, MeFloorMode::Static) => {
                    self.stats
                        .increment_me_floor_mode_switch_adaptive_to_static_total();
                }
                _ => {}
            }
        }
    }

    pub fn reset_stun_state(&self) {
        self.nat_probe_attempts.store(0, Ordering::Relaxed);
        self.nat_probe_disabled.store(false, Ordering::Relaxed);
        if let Ok(mut live) = self.nat_stun_live_servers.try_write() {
            live.clear();
        }
    }

    /// Translate the local ME address into the address material sent to the proxy.
    pub fn translate_our_addr(&self, addr: SocketAddr) -> SocketAddr {
        self.translate_our_addr_with_reflection(addr, None)
    }

    pub fn registry(&self) -> &Arc<ConnRegistry> {
        &self.registry
    }

    pub fn update_runtime_transport_policy(
        &self,
        socks_kdf_policy: MeSocksKdfPolicy,
        route_backpressure_base_timeout_ms: u64,
        route_backpressure_high_timeout_ms: u64,
        route_backpressure_high_watermark_pct: u8,
        reader_route_data_wait_ms: u64,
    ) {
        self.me_socks_kdf_policy
            .store(socks_kdf_policy.as_u8(), Ordering::Relaxed);
        self.me_reader_route_data_wait_ms
            .store(reader_route_data_wait_ms, Ordering::Relaxed);
        self.registry.update_route_backpressure_policy(
            route_backpressure_base_timeout_ms,
            route_backpressure_high_timeout_ms,
            route_backpressure_high_watermark_pct,
        );
    }

    pub(super) fn socks_kdf_policy(&self) -> MeSocksKdfPolicy {
        MeSocksKdfPolicy::from_u8(self.me_socks_kdf_policy.load(Ordering::Relaxed))
    }

    pub(super) fn writers_arc(&self) -> Arc<RwLock<Vec<MeWriter>>> {
        self.writers.clone()
    }

    pub(super) fn force_close_timeout(&self) -> Option<Duration> {
        let secs =
            Self::normalize_force_close_secs(self.me_pool_force_close_secs.load(Ordering::Relaxed));
        Some(Duration::from_secs(secs))
    }

    pub(super) fn drain_soft_evict_enabled(&self) -> bool {
        self.me_pool_drain_soft_evict_enabled
            .load(Ordering::Relaxed)
    }

    pub(super) fn drain_soft_evict_grace_secs(&self) -> u64 {
        self.me_pool_drain_soft_evict_grace_secs
            .load(Ordering::Relaxed)
    }

    pub(super) fn drain_soft_evict_per_writer(&self) -> usize {
        self.me_pool_drain_soft_evict_per_writer
            .load(Ordering::Relaxed)
            .max(1) as usize
    }

    pub(super) fn drain_soft_evict_budget_per_core(&self) -> usize {
        self.me_pool_drain_soft_evict_budget_per_core
            .load(Ordering::Relaxed)
            .max(1) as usize
    }

    pub(super) fn drain_soft_evict_cooldown(&self) -> Duration {
        Duration::from_millis(
            self.me_pool_drain_soft_evict_cooldown_ms
                .load(Ordering::Relaxed)
                .max(1),
        )
    }

    pub(super) async fn key_selector(&self) -> u32 {
        self.proxy_secret.read().await.key_selector
    }

    pub(super) async fn non_draining_writer_counts_by_contour(&self) -> (usize, usize, usize) {
        let ws = self.writers.read().await;
        let mut active = 0usize;
        let mut warm = 0usize;
        for writer in ws.iter() {
            if writer.draining.load(Ordering::Relaxed) {
                continue;
            }
            match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
                WriterContour::Active => active = active.saturating_add(1),
                WriterContour::Warm => warm = warm.saturating_add(1),
                WriterContour::Draining => {}
            }
        }
        (active, warm, active.saturating_add(warm))
    }

    pub(super) async fn active_contour_writer_count_total(&self) -> usize {
        let (active, _, _) = self.non_draining_writer_counts_by_contour().await;
        active
    }

    pub(super) async fn secret_snapshot(&self) -> SecretSnapshot {
        self.proxy_secret.read().await.clone()
    }

    pub(super) fn bind_stale_mode(&self) -> MeBindStaleMode {
        MeBindStaleMode::from_u8(self.me_bind_stale_mode.load(Ordering::Relaxed))
    }

    pub(super) fn writer_pick_mode(&self) -> MeWriterPickMode {
        MeWriterPickMode::from_u8(self.me_writer_pick_mode.load(Ordering::Relaxed))
    }

    pub(super) fn writer_pick_sample_size(&self) -> usize {
        self.me_writer_pick_sample_size
            .load(Ordering::Relaxed)
            .clamp(2, 4) as usize
    }

    pub(super) fn required_writers_for_dc(&self, endpoint_count: usize) -> usize {
        if endpoint_count == 0 {
            return 0;
        }
        if endpoint_count == 1 {
            let shadow = self
                .me_single_endpoint_shadow_writers
                .load(Ordering::Relaxed) as usize;
            return (1 + shadow).max(3);
        }
        endpoint_count.max(3)
    }

    pub(super) fn floor_mode(&self) -> MeFloorMode {
        MeFloorMode::from_u8(self.me_floor_mode.load(Ordering::Relaxed))
    }

    pub(super) fn adaptive_floor_idle_duration(&self) -> Duration {
        Duration::from_secs(self.me_adaptive_floor_idle_secs.load(Ordering::Relaxed))
    }

    pub(super) fn adaptive_floor_recover_grace_duration(&self) -> Duration {
        Duration::from_secs(
            self.me_adaptive_floor_recover_grace_secs
                .load(Ordering::Relaxed),
        )
    }

    pub(super) fn adaptive_floor_min_writers_multi_endpoint(&self) -> usize {
        (self
            .me_adaptive_floor_min_writers_multi_endpoint
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(super) fn adaptive_floor_max_extra_single_per_core(&self) -> usize {
        self.me_adaptive_floor_max_extra_writers_single_per_core
            .load(Ordering::Relaxed) as usize
    }

    pub(super) fn adaptive_floor_max_extra_multi_per_core(&self) -> usize {
        self.me_adaptive_floor_max_extra_writers_multi_per_core
            .load(Ordering::Relaxed) as usize
    }

    pub(super) fn adaptive_floor_max_active_writers_per_core(&self) -> usize {
        (self
            .me_adaptive_floor_max_active_writers_per_core
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(super) fn adaptive_floor_max_warm_writers_per_core(&self) -> usize {
        (self
            .me_adaptive_floor_max_warm_writers_per_core
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(super) fn adaptive_floor_max_active_writers_global(&self) -> usize {
        (self
            .me_adaptive_floor_max_active_writers_global
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(super) fn adaptive_floor_max_warm_writers_global(&self) -> usize {
        (self
            .me_adaptive_floor_max_warm_writers_global
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(super) fn adaptive_floor_detected_cpu_cores(&self) -> usize {
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
            .max(1)
    }

    pub(super) fn adaptive_floor_effective_cpu_cores(&self) -> usize {
        let detected = self.adaptive_floor_detected_cpu_cores();
        let override_cores = self
            .me_adaptive_floor_cpu_cores_override
            .load(Ordering::Relaxed) as usize;
        let effective = if override_cores == 0 {
            detected
        } else {
            override_cores.max(1)
        };
        self.me_adaptive_floor_cpu_cores_detected
            .store(detected as u32, Ordering::Relaxed);
        self.me_adaptive_floor_cpu_cores_effective
            .store(effective as u32, Ordering::Relaxed);
        self.stats
            .set_me_floor_cpu_cores_detected_gauge(detected as u64);
        self.stats
            .set_me_floor_cpu_cores_effective_gauge(effective as u64);
        effective
    }

    // Keeps per-contour (active/warm) writer budget bounded by CPU count.
    // Baseline is 86 writers on the first core and +48 for each extra core.
    fn adaptive_floor_cpu_budget_per_contour_cap(&self, cores: usize) -> usize {
        const FIRST_CORE_WRITER_BUDGET: usize = 86;
        const EXTRA_CORE_WRITER_BUDGET: usize = 48;
        if cores == 0 {
            return FIRST_CORE_WRITER_BUDGET;
        }
        FIRST_CORE_WRITER_BUDGET.saturating_add(
            cores
                .saturating_sub(1)
                .saturating_mul(EXTRA_CORE_WRITER_BUDGET),
        )
    }

    pub(super) fn adaptive_floor_active_cap_configured_total(&self) -> usize {
        let cores = self.adaptive_floor_effective_cpu_cores();
        let per_contour_budget = self.adaptive_floor_cpu_budget_per_contour_cap(cores);
        let configured = cores
            .saturating_mul(self.adaptive_floor_max_active_writers_per_core())
            .min(self.adaptive_floor_max_active_writers_global())
            .min(per_contour_budget)
            .max(1);
        self.me_adaptive_floor_active_cap_configured
            .store(configured as u64, Ordering::Relaxed);
        self.stats
            .set_me_floor_active_cap_configured_gauge(configured as u64);
        configured
    }

    pub(super) fn adaptive_floor_warm_cap_configured_total(&self) -> usize {
        let cores = self.adaptive_floor_effective_cpu_cores();
        let per_contour_budget = self.adaptive_floor_cpu_budget_per_contour_cap(cores);
        let configured = cores
            .saturating_mul(self.adaptive_floor_max_warm_writers_per_core())
            .min(self.adaptive_floor_max_warm_writers_global())
            .min(per_contour_budget)
            .max(1);
        self.me_adaptive_floor_warm_cap_configured
            .store(configured as u64, Ordering::Relaxed);
        self.stats
            .set_me_floor_warm_cap_configured_gauge(configured as u64);
        configured
    }

    pub(super) fn set_adaptive_floor_runtime_caps(
        &self,
        active_cap_configured: usize,
        active_cap_effective: usize,
        warm_cap_configured: usize,
        warm_cap_effective: usize,
        target_writers_total: usize,
        active_writers_current: usize,
        warm_writers_current: usize,
    ) {
        self.me_adaptive_floor_global_cap_raw
            .store(active_cap_configured as u64, Ordering::Relaxed);
        self.me_adaptive_floor_global_cap_effective
            .store(active_cap_effective as u64, Ordering::Relaxed);
        self.me_adaptive_floor_target_writers_total
            .store(target_writers_total as u64, Ordering::Relaxed);
        self.me_adaptive_floor_active_cap_configured
            .store(active_cap_configured as u64, Ordering::Relaxed);
        self.me_adaptive_floor_active_cap_effective
            .store(active_cap_effective as u64, Ordering::Relaxed);
        self.me_adaptive_floor_warm_cap_configured
            .store(warm_cap_configured as u64, Ordering::Relaxed);
        self.me_adaptive_floor_warm_cap_effective
            .store(warm_cap_effective as u64, Ordering::Relaxed);
        self.me_adaptive_floor_active_writers_current
            .store(active_writers_current as u64, Ordering::Relaxed);
        self.me_adaptive_floor_warm_writers_current
            .store(warm_writers_current as u64, Ordering::Relaxed);
        self.stats
            .set_me_floor_global_cap_raw_gauge(active_cap_configured as u64);
        self.stats
            .set_me_floor_global_cap_effective_gauge(active_cap_effective as u64);
        self.stats
            .set_me_floor_target_writers_total_gauge(target_writers_total as u64);
        self.stats
            .set_me_floor_active_cap_configured_gauge(active_cap_configured as u64);
        self.stats
            .set_me_floor_active_cap_effective_gauge(active_cap_effective as u64);
        self.stats
            .set_me_floor_warm_cap_configured_gauge(warm_cap_configured as u64);
        self.stats
            .set_me_floor_warm_cap_effective_gauge(warm_cap_effective as u64);
        self.stats
            .set_me_writers_active_current_gauge(active_writers_current as u64);
        self.stats
            .set_me_writers_warm_current_gauge(warm_writers_current as u64);
    }

    pub(super) async fn active_coverage_required_total(&self) -> usize {
        let now_epoch_secs = Self::now_epoch_secs();
        let mut endpoints_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();

        if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch_secs) {
            let map = self.proxy_map_v4.read().await;
            for (dc, addrs) in map.iter() {
                let entry = endpoints_by_dc.entry(*dc).or_default();
                for (ip, port) in addrs.iter().copied() {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch_secs) {
            let map = self.proxy_map_v6.read().await;
            for (dc, addrs) in map.iter() {
                let entry = endpoints_by_dc.entry(*dc).or_default();
                for (ip, port) in addrs.iter().copied() {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        endpoints_by_dc
            .values()
            .map(|endpoints| self.required_writers_for_dc_with_floor_mode(endpoints.len(), false))
            .sum()
    }

    pub(super) async fn can_open_writer_for_contour(
        &self,
        contour: WriterContour,
        allow_coverage_override: bool,
    ) -> bool {
        let (active_writers, warm_writers, _) = self.non_draining_writer_counts_by_contour().await;
        match contour {
            WriterContour::Active => {
                let active_cap = self.adaptive_floor_active_cap_configured_total();
                if active_writers < active_cap {
                    return true;
                }
                if !allow_coverage_override {
                    return false;
                }
                let coverage_required = self.active_coverage_required_total().await;
                active_writers < coverage_required
            }
            WriterContour::Warm => warm_writers < self.adaptive_floor_warm_cap_configured_total(),
            WriterContour::Draining => true,
        }
    }

    pub(super) fn required_writers_for_dc_with_floor_mode(
        &self,
        endpoint_count: usize,
        reduce_for_idle: bool,
    ) -> usize {
        let base_required = self.required_writers_for_dc(endpoint_count);
        if !reduce_for_idle {
            return base_required;
        }
        if self.floor_mode() != MeFloorMode::Adaptive {
            return base_required;
        }
        let min_writers = if endpoint_count == 1 {
            (self
                .me_adaptive_floor_min_writers_single_endpoint
                .load(Ordering::Relaxed) as usize)
                .max(1)
        } else {
            (self
                .me_adaptive_floor_min_writers_multi_endpoint
                .load(Ordering::Relaxed) as usize)
                .max(1)
        };
        base_required.min(min_writers)
    }

    pub(super) fn single_endpoint_outage_mode_enabled(&self) -> bool {
        self.me_single_endpoint_outage_mode_enabled
            .load(Ordering::Relaxed)
    }

    pub(super) fn single_endpoint_outage_disable_quarantine(&self) -> bool {
        self.me_single_endpoint_outage_disable_quarantine
            .load(Ordering::Relaxed)
    }

    pub(super) fn single_endpoint_outage_backoff_bounds_ms(&self) -> (u64, u64) {
        let min_ms = self
            .me_single_endpoint_outage_backoff_min_ms
            .load(Ordering::Relaxed);
        let max_ms = self
            .me_single_endpoint_outage_backoff_max_ms
            .load(Ordering::Relaxed);
        if min_ms <= max_ms {
            (min_ms, max_ms)
        } else {
            (max_ms, min_ms)
        }
    }

    pub(super) fn single_endpoint_shadow_rotate_interval(&self) -> Option<Duration> {
        let secs = self
            .me_single_endpoint_shadow_rotate_every_secs
            .load(Ordering::Relaxed);
        if secs == 0 {
            None
        } else {
            Some(Duration::from_secs(secs))
        }
    }

    pub(super) fn family_order(&self) -> Vec<IpFamily> {
        let mut order = Vec::new();
        if self.decision.prefer_ipv6() {
            if self.decision.ipv6_me {
                order.push(IpFamily::V6);
            }
            if self.decision.ipv4_me {
                order.push(IpFamily::V4);
            }
        } else {
            if self.decision.ipv4_me {
                order.push(IpFamily::V4);
            }
            if self.decision.ipv6_me {
                order.push(IpFamily::V6);
            }
        }
        order
    }

    pub(super) fn default_dc_for_routing(&self) -> i32 {
        let dc = self.default_dc.load(Ordering::Relaxed);
        if dc == 0 { 2 } else { dc }
    }

    pub(super) async fn has_configured_endpoints_for_dc(&self, dc: i32) -> bool {
        if self.decision.ipv4_me {
            let map = self.proxy_map_v4.read().await;
            if map.get(&dc).is_some_and(|endpoints| !endpoints.is_empty()) {
                return true;
            }
        }

        if self.decision.ipv6_me {
            let map = self.proxy_map_v6.read().await;
            if map.get(&dc).is_some_and(|endpoints| !endpoints.is_empty()) {
                return true;
            }
        }

        false
    }

    pub(super) async fn resolve_target_dc_for_routing(&self, target_dc: i32) -> (i32, bool) {
        if target_dc == 0 {
            return (self.default_dc_for_routing(), true);
        }

        if self.has_configured_endpoints_for_dc(target_dc).await {
            return (target_dc, false);
        }

        (self.default_dc_for_routing(), true)
    }

    pub(super) async fn resolve_dc_for_endpoint(&self, addr: SocketAddr) -> i32 {
        if let Some(cached) = self.endpoint_dc_map.read().await.get(&addr).copied()
            && let Some(dc) = cached
        {
            return dc;
        }

        self.default_dc_for_routing()
    }

    pub(super) async fn proxy_map_for_family(
        &self,
        family: IpFamily,
    ) -> HashMap<i32, Vec<(IpAddr, u16)>> {
        match family {
            IpFamily::V4 => self.proxy_map_v4.read().await.clone(),
            IpFamily::V6 => self.proxy_map_v6.read().await.clone(),
        }
    }

    fn merge_endpoint_dc(
        endpoint_dc_map: &mut HashMap<SocketAddr, Option<i32>>,
        dc: i32,
        ip: IpAddr,
        port: u16,
    ) {
        let endpoint = SocketAddr::new(ip, port);
        match endpoint_dc_map.get_mut(&endpoint) {
            None => {
                endpoint_dc_map.insert(endpoint, Some(dc));
            }
            Some(existing) => {
                if existing.is_some_and(|existing_dc| existing_dc != dc) {
                    *existing = None;
                }
            }
        }
    }

    fn build_preferred_endpoints_by_dc(
        decision: &NetworkDecision,
        map_v4: &HashMap<i32, Vec<(IpAddr, u16)>>,
        map_v6: &HashMap<i32, Vec<(IpAddr, u16)>>,
    ) -> HashMap<i32, Vec<SocketAddr>> {
        let mut out = HashMap::<i32, Vec<SocketAddr>>::new();
        let mut dcs = HashSet::<i32>::new();
        dcs.extend(map_v4.keys().copied());
        dcs.extend(map_v6.keys().copied());

        for dc in dcs {
            let v4 = map_v4
                .get(&dc)
                .map(|items| {
                    items
                        .iter()
                        .map(|(ip, port)| SocketAddr::new(*ip, *port))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let v6 = map_v6
                .get(&dc)
                .map(|items| {
                    items
                        .iter()
                        .map(|(ip, port)| SocketAddr::new(*ip, *port))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let mut selected = if decision.effective_multipath {
                let mut both = Vec::<SocketAddr>::with_capacity(v4.len().saturating_add(v6.len()));
                if decision.prefer_ipv6() {
                    both.extend(v6.iter().copied());
                    both.extend(v4.iter().copied());
                } else {
                    both.extend(v4.iter().copied());
                    both.extend(v6.iter().copied());
                }
                both
            } else if decision.prefer_ipv6() {
                if !v6.is_empty() { v6 } else { v4 }
            } else if !v4.is_empty() {
                v4
            } else {
                v6
            };

            selected.sort_unstable();
            selected.dedup();
            out.insert(dc, selected);
        }

        out
    }

    fn build_endpoint_dc_map_from_maps(
        map_v4: &HashMap<i32, Vec<(IpAddr, u16)>>,
        map_v6: &HashMap<i32, Vec<(IpAddr, u16)>>,
    ) -> HashMap<SocketAddr, Option<i32>> {
        let mut endpoint_dc_map = HashMap::<SocketAddr, Option<i32>>::new();
        for (dc, endpoints) in map_v4 {
            for (ip, port) in endpoints {
                Self::merge_endpoint_dc(&mut endpoint_dc_map, *dc, *ip, *port);
            }
        }
        for (dc, endpoints) in map_v6 {
            for (ip, port) in endpoints {
                Self::merge_endpoint_dc(&mut endpoint_dc_map, *dc, *ip, *port);
            }
        }
        endpoint_dc_map
    }

    pub(super) async fn rebuild_endpoint_dc_map(&self) {
        let map_v4 = self.proxy_map_v4.read().await.clone();
        let map_v6 = self.proxy_map_v6.read().await.clone();
        let rebuilt = Self::build_endpoint_dc_map_from_maps(&map_v4, &map_v6);
        let preferred = Self::build_preferred_endpoints_by_dc(&self.decision, &map_v4, &map_v6);
        *self.endpoint_dc_map.write().await = rebuilt;
        *self.preferred_endpoints_by_dc.write().await = preferred;
    }

    pub(super) async fn preferred_endpoints_for_dc(&self, dc: i32) -> Vec<SocketAddr> {
        let guard = self.preferred_endpoints_by_dc.read().await;
        guard.get(&dc).cloned().unwrap_or_default()
    }

    pub(super) fn health_interval_unhealthy(&self) -> Duration {
        Duration::from_millis(self.me_health_interval_ms_unhealthy.load(Ordering::Relaxed).max(1))
    }

    pub(super) fn health_interval_healthy(&self) -> Duration {
        Duration::from_millis(self.me_health_interval_ms_healthy.load(Ordering::Relaxed).max(1))
    }

    pub(super) fn warn_rate_limit_duration(&self) -> Duration {
        Duration::from_millis(self.me_warn_rate_limit_ms.load(Ordering::Relaxed).max(1))
    }
}
