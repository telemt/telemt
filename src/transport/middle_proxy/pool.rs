#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, watch};
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
use super::pool_lifecycle::MePoolLifecycle;

const ME_FORCE_CLOSE_SAFETY_FALLBACK_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct RefillDcKey {
    pub dc: i32,
    pub family: IpFamily,
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
    /// Aggregate resident-memory budget shared by all data commands for this writer.
    pub byte_budget: Arc<Semaphore>,
    pub cancel: CancellationToken,
    pub degraded: Arc<AtomicBool>,
    pub rtt_ema_ms_x10: Arc<AtomicU32>,
    pub draining: Arc<AtomicBool>,
    pub draining_started_at_epoch_secs: Arc<AtomicU64>,
    pub drain_deadline_epoch_secs: Arc<AtomicU64>,
    pub allow_drain_fallback: Arc<AtomicBool>,
}

pub(super) struct WritersState {
    // HARD INVARIANT:
    // All writers.store() calls MUST be guarded by writers_write_guard.
    writers: ArcSwap<Vec<MeWriter>>,
    writers_write_guard: Mutex<()>,
}

impl WritersState {
    pub(super) fn new() -> Self {
        Self {
            writers: ArcSwap::from_pointee(Vec::new()),
            writers_write_guard: Mutex::new(()),
        }
    }

    pub(super) fn snapshot(&self) -> Arc<Vec<MeWriter>> {
        self.writers.load_full()
    }

    pub(super) async fn read(&self) -> Arc<Vec<MeWriter>> {
        self.snapshot()
    }

    pub(super) async fn write(&self) -> WritersWriteGuard<'_> {
        let guard = self.writers_write_guard.lock().await;
        let writers = (*self.writers.load_full()).clone();
        WritersWriteGuard {
            state: self,
            _guard: guard,
            writers,
        }
    }

    pub(super) async fn update<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Vec<MeWriter>) -> R,
    {
        let mut guard = self.write().await;
        f(&mut guard)
    }

    fn debug_assert_store_guarded(&self) {
        debug_assert!(
            self.writers_write_guard.try_lock().is_err(),
            "HARD INVARIANT violated: writers.store() without writers_write_guard"
        );
    }

    fn store_guarded(&self, writers: Vec<MeWriter>) {
        self.debug_assert_store_guarded();
        self.writers.store(Arc::new(writers));
    }
}

pub(super) struct WritersWriteGuard<'a> {
    state: &'a WritersState,
    _guard: tokio::sync::MutexGuard<'a, ()>,
    writers: Vec<MeWriter>,
}

impl Deref for WritersWriteGuard<'_> {
    type Target = Vec<MeWriter>;

    fn deref(&self) -> &Self::Target {
        &self.writers
    }
}

impl DerefMut for WritersWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.writers
    }
}

impl Drop for WritersWriteGuard<'_> {
    fn drop(&mut self) {
        let writers = std::mem::take(&mut self.writers);
        self.state.store_guarded(writers);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum WriterContour {
    Warm = 0,
    Active = 1,
    Draining = 2,
}

pub(super) struct WriterOpenReservation<'a> {
    counter: Option<&'a AtomicUsize>,
}

impl Drop for WriterOpenReservation<'_> {
    fn drop(&mut self) {
        if let Some(counter) = self.counter {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl WriterContour {
    pub(super) fn as_u8(self) -> u8 {
        self as u8
    }

    pub(super) fn from_u8(value: u8) -> Self {
        debug_assert!(
            value <= Self::Draining as u8,
            "Unexpected WriterContour discriminant: {value}"
        );
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

#[derive(Debug, Clone)]
pub(crate) struct FamilyHealthSnapshot {
    pub(crate) state: MeFamilyRuntimeState,
    pub(crate) state_since_epoch_secs: u64,
    pub(crate) suppressed_until_epoch_secs: u64,
    pub(crate) fail_streak: u32,
    pub(crate) recover_success_streak: u32,
}

impl FamilyHealthSnapshot {
    fn new(
        state: MeFamilyRuntimeState,
        state_since_epoch_secs: u64,
        suppressed_until_epoch_secs: u64,
        fail_streak: u32,
        recover_success_streak: u32,
    ) -> Self {
        Self {
            state,
            state_since_epoch_secs,
            suppressed_until_epoch_secs,
            fail_streak,
            recover_success_streak,
        }
    }
}

impl MeFamilyRuntimeState {
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

pub struct RoutingCore {
    pub(super) registry: Arc<ConnRegistry>,
    pub(super) writers: Arc<WritersState>,
    pub(super) rr: AtomicU64,
    pub(super) writer_epoch: watch::Sender<u64>,
    pub(super) preferred_endpoints_by_dc: ArcSwap<HashMap<i32, Vec<SocketAddr>>>,
}

pub(super) struct ReinitCore {
    pub(super) generation: AtomicU64,
    pub(super) active_generation: AtomicU64,
    pub(super) warm_generation: AtomicU64,
    pub(super) pending_hardswap_generation: AtomicU64,
    pub(super) pending_hardswap_started_at_epoch_secs: AtomicU64,
    pub(super) pending_hardswap_map_hash: AtomicU64,
    pub(super) scheduler_inflight: AtomicUsize,
    pub(super) max_concurrency_effective: AtomicUsize,
    pub(super) coordinator: ParkingMutex<ReinitCoordinatorState>,
    pub(super) status: ArcSwap<ReinitStatusSnapshot>,
    pub(super) hardswap: AtomicBool,
    pub(super) me_hardswap_warmup_delay_min_ms: AtomicU64,
    pub(super) me_hardswap_warmup_delay_max_ms: AtomicU64,
    pub(super) me_hardswap_warmup_extra_passes: AtomicU32,
    pub(super) me_hardswap_warmup_pass_backoff_base_ms: AtomicU64,
}

#[derive(Clone, Debug)]
pub(super) struct ReinitStatusSnapshot {
    pub(super) active_generation: u64,
    pub(super) warm_generations: Vec<u64>,
    pub(super) pending_hardswap_generation: u64,
    pub(super) pending_hardswap_started_at_epoch_secs: u64,
    pub(super) pending_hardswap_map_hash: u64,
    pub(super) inflight: usize,
}

#[derive(Clone, Copy)]
pub(super) struct ReinitPendingState {
    pub(super) generation: u64,
    pub(super) started_at_epoch_secs: u64,
    pub(super) map_hash: u64,
}

#[derive(Clone, Copy)]
pub(super) struct ReinitAttemptState {
    pub(super) generation: u64,
    pub(super) map_hash: u64,
    pub(super) hardswap: bool,
    pub(super) committed: bool,
}

pub(super) struct ReinitCoordinatorState {
    pub(super) next_attempt_id: u64,
    pub(super) active_generation: u64,
    pub(super) desired_map_hash: u64,
    pub(super) pending: Option<ReinitPendingState>,
    pub(super) attempts: HashMap<u64, ReinitAttemptState>,
}

pub(super) struct WriterLifecycleCore {
    pub(super) me_keepalive_enabled: bool,
    pub(super) me_keepalive_interval: Duration,
    pub(super) me_keepalive_jitter: Duration,
    pub(super) me_keepalive_payload_random: bool,
    pub(super) rpc_proxy_req_every_secs: AtomicU64,
    pub(super) writer_cmd_channel_capacity: usize,
    pub(super) writer_byte_budget_permits: usize,
}

pub(super) struct RouteRuntimeCore {
    pub(super) me_route_no_writer_mode: AtomicU8,
    pub(super) me_route_no_writer_wait: Duration,
    pub(super) me_route_hybrid_max_wait: Duration,
    pub(super) me_route_blocking_send_timeout: Option<Duration>,
    pub(super) me_route_last_success_epoch_ms: AtomicU64,
    pub(super) me_route_hybrid_timeout_warn_epoch_ms: AtomicU64,
    pub(super) me_async_recovery_last_trigger_epoch_ms: AtomicU64,
    pub(super) me_route_inline_recovery_attempts: u32,
    pub(super) me_route_inline_recovery_wait: Duration,
}

pub(super) struct HealthRuntimeCore {
    pub(super) me_health_interval_ms_unhealthy: AtomicU64,
    pub(super) me_health_interval_ms_healthy: AtomicU64,
    pub(super) me_warn_rate_limit_ms: AtomicU64,
    pub(super) family_health_v4: ArcSwap<FamilyHealthSnapshot>,
    pub(super) family_health_v6: ArcSwap<FamilyHealthSnapshot>,
}

pub(super) struct DrainRuntimeCore {
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
    pub(super) me_last_drain_gate_route_quorum_ok: AtomicBool,
    pub(super) me_last_drain_gate_redundancy_ok: AtomicBool,
    pub(super) me_last_drain_gate_block_reason: AtomicU8,
    pub(super) me_last_drain_gate_updated_at_epoch_secs: AtomicU64,
}

pub(super) struct SingleEndpointRuntimeCore {
    pub(super) me_single_endpoint_shadow_writers: AtomicU8,
    pub(super) me_single_endpoint_outage_mode_enabled: AtomicBool,
    pub(super) me_single_endpoint_outage_disable_quarantine: AtomicBool,
    pub(super) me_single_endpoint_outage_backoff_min_ms: AtomicU64,
    pub(super) me_single_endpoint_outage_backoff_max_ms: AtomicU64,
    pub(super) me_single_endpoint_shadow_rotate_every_secs: AtomicU64,
}

pub(super) struct BindingPolicyCore {
    pub(super) me_bind_stale_mode: AtomicU8,
    pub(super) me_bind_stale_ttl_secs: AtomicU64,
}

pub(super) struct NatRuntimeCore {
    pub(super) nat_ip_cfg: Option<IpAddr>,
    pub(super) nat_ip_detected: Arc<RwLock<Option<IpAddr>>>,
    pub(super) nat_probe: bool,
    pub(super) nat_stun: Option<String>,
    pub(super) nat_stun_servers: Vec<String>,
    pub(super) stun_tcp_fallback: bool,
    pub(super) http_ip_detect_urls: Vec<String>,
    pub(super) nat_stun_live_servers: Arc<RwLock<Vec<String>>>,
    pub(super) nat_probe_concurrency: usize,
    pub(super) detected_ipv6: Option<Ipv6Addr>,
    pub(super) nat_probe_attempts: std::sync::atomic::AtomicU8,
    pub(super) nat_probe_disabled: std::sync::atomic::AtomicBool,
    pub(super) stun_backoff_until: Arc<RwLock<Option<Instant>>>,
    pub(super) nat_reflection_cache: Arc<Mutex<NatReflectionCache>>,
    pub(super) nat_reflection_singleflight_v4: Arc<Mutex<()>>,
    pub(super) nat_reflection_singleflight_v6: Arc<Mutex<()>>,
}

pub(super) struct ReconnectRuntimeCore {
    #[allow(dead_code)]
    pub(super) me_one_retry: u8,
    pub(super) me_one_timeout: Duration,
    pub(super) me_warmup_stagger_enabled: bool,
    pub(super) me_warmup_step_delay: Duration,
    pub(super) me_warmup_step_jitter: Duration,
    pub(super) me_reconnect_max_concurrent_per_dc: u32,
    pub(super) me_reconnect_backoff_base: Duration,
    pub(super) me_reconnect_backoff_cap: Duration,
    pub(super) me_reconnect_fast_retry_count: u32,
}

pub(super) struct FloorRuntimeCore {
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
}

pub(super) struct WriterSelectionPolicyCore {
    pub(super) secret_atomic_snapshot: AtomicBool,
    pub(super) me_deterministic_writer_sort: AtomicBool,
    pub(super) me_writer_pick_mode: AtomicU8,
    pub(super) me_writer_pick_sample_size: AtomicU8,
}

pub(super) struct TransportPolicyCore {
    pub(super) me_socks_kdf_policy: AtomicU8,
    pub(super) me_route_backpressure_enabled: Arc<AtomicBool>,
    pub(super) me_route_fairshare_enabled: Arc<AtomicBool>,
    pub(super) me_reader_route_data_wait_ms: Arc<AtomicU64>,
}

#[allow(dead_code)]
pub struct MePool {
    pub(super) routing: Arc<RoutingCore>,
    pub(super) reinit: Arc<ReinitCore>,
    pub(super) writer_lifecycle: Arc<WriterLifecycleCore>,
    pub(super) route_runtime: Arc<RouteRuntimeCore>,
    pub(super) health_runtime: Arc<HealthRuntimeCore>,
    pub(super) drain_runtime: Arc<DrainRuntimeCore>,
    pub(super) single_endpoint_runtime: Arc<SingleEndpointRuntimeCore>,
    pub(super) binding_policy: Arc<BindingPolicyCore>,
    pub(super) nat_runtime: Arc<NatRuntimeCore>,
    pub(super) reconnect_runtime: Arc<ReconnectRuntimeCore>,
    pub(super) floor_runtime: Arc<FloorRuntimeCore>,
    pub(super) writer_selection_policy: Arc<WriterSelectionPolicyCore>,
    pub(super) transport_policy: Arc<TransportPolicyCore>,
    pub(super) lifecycle: MePoolLifecycle,
    pub(super) decision: NetworkDecision,
    pub(super) upstream: Option<Arc<UpstreamManager>>,
    pub(super) rng: Arc<SecureRandom>,
    pub(super) proxy_tag: Option<Vec<u8>>,
    pub(super) proxy_secret: Arc<RwLock<SecretSnapshot>>,
    pub(super) proxy_map_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) proxy_map_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) endpoint_dc_map: Arc<RwLock<HashMap<SocketAddr, Option<i32>>>>,
    pub(super) default_dc: AtomicI32,
    pub(super) next_writer_id: AtomicU64,
    pub(super) writer_connect_active_reserved: AtomicUsize,
    pub(super) writer_connect_warm_reserved: AtomicUsize,
    pub(super) rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    pub(super) refill_states: Arc<ParkingMutex<HashMap<RefillDcKey, Option<SocketAddr>>>>,
    pub(super) refill_running: AtomicUsize,
    pub(super) refill_pending: AtomicUsize,
    pub(super) conn_count: AtomicUsize,
    pub(super) draining_active_runtime: AtomicU64,
    pub(super) stats: Arc<crate::stats::Stats>,
    pub(super) endpoint_quarantine: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    pub(super) kdf_material_fingerprint: Arc<RwLock<HashMap<SocketAddr, (u64, u16)>>>,
    pub(super) runtime_ready: AtomicBool,
    pool_size: usize,
}

impl Deref for MePool {
    type Target = RoutingCore;

    fn deref(&self) -> &Self::Target {
        self.routing.as_ref()
    }
}

#[derive(Debug, Default)]
pub struct NatReflectionCache {
    pub v4: Option<(std::time::Instant, std::net::SocketAddr)>,
    pub v6: Option<(std::time::Instant, std::net::SocketAddr)>,
}

// Pool construction and immutable process-generation resources.
mod construction;
// Mutable generation and family runtime policy.
mod runtime_policy;
// NAT, transport, and draining runtime policy.
mod transport_policy;
// Writer contour and adaptive-floor selection policy.
mod selection_policy;
// Bounded writer-open admission and coverage accounting.
mod writer_admission;
// Endpoint-to-DC routing and health timing policy.
mod routing;
