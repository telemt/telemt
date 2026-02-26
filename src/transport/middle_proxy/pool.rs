use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use bytes::BytesMut;
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::sync::{Mutex, RwLock, mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::network::probe::NetworkDecision;
use crate::network::IpFamily;
use crate::protocol::constants::*;

use super::ConnRegistry;
use super::registry::BoundConn;
use super::codec::{RpcWriter, WriterCommand};
use super::reader::reader_loop;
const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;

#[derive(Clone)]
pub struct MeWriter {
    pub id: u64,
    pub addr: SocketAddr,
    pub generation: u64,
    pub tx: mpsc::Sender<WriterCommand>,
    pub cancel: CancellationToken,
    pub degraded: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
    pub draining_started_at_epoch_secs: Arc<AtomicU64>,
    pub allow_drain_fallback: Arc<AtomicBool>,
}

#[allow(dead_code)]
pub struct MePool {
    pub(super) registry: Arc<ConnRegistry>,
    pub(super) writers: Arc<RwLock<Vec<MeWriter>>>,
    pub(super) rr: AtomicU64,
    pub(super) decision: NetworkDecision,
    pub(super) rng: Arc<SecureRandom>,
    pub(super) proxy_tag: Option<Vec<u8>>,
    pub(super) proxy_secret: Arc<RwLock<Vec<u8>>>,
    pub(super) nat_ip_cfg: Option<IpAddr>,
    pub(super) nat_ip_detected: Arc<RwLock<Option<IpAddr>>>,
    pub(super) nat_probe: bool,
    pub(super) nat_stun: Option<String>,
    pub(super) nat_stun_servers: Vec<String>,
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
    pub(super) me_warmup_stagger_enabled: bool,
    pub(super) me_warmup_step_delay: Duration,
    pub(super) me_warmup_step_jitter: Duration,
    pub(super) me_reconnect_max_concurrent_per_dc: u32,
    pub(super) me_reconnect_backoff_base: Duration,
    pub(super) me_reconnect_backoff_cap: Duration,
    pub(super) me_reconnect_fast_retry_count: u32,
    pub(super) proxy_map_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) proxy_map_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) default_dc: AtomicI32,
    pub(super) next_writer_id: AtomicU64,
    pub(super) ping_tracker: Arc<Mutex<HashMap<i64, (std::time::Instant, u64)>>>,
    pub(super) rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    pub(super) nat_reflection_cache: Arc<Mutex<NatReflectionCache>>,
    pub(super) writer_available: Arc<Notify>,
    pub(super) refill_inflight: Arc<Mutex<HashSet<SocketAddr>>>,
    pub(super) conn_count: AtomicUsize,
    pub(super) stats: Arc<crate::stats::Stats>,
    pub(super) generation: AtomicU64,
    pub(super) hardswap: AtomicBool,
    pub(super) me_pool_drain_ttl_secs: AtomicU64,
    pub(super) me_pool_force_close_secs: AtomicU64,
    pub(super) me_pool_min_fresh_ratio_permille: AtomicU32,
    pub(super) me_hardswap_warmup_delay_min_ms: AtomicU64,
    pub(super) me_hardswap_warmup_delay_max_ms: AtomicU64,
    pub(super) me_hardswap_warmup_extra_passes: AtomicU32,
    pub(super) me_hardswap_warmup_pass_backoff_base_ms: AtomicU64,
    pool_size: usize,
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

    fn permille_to_ratio(permille: u32) -> f32 {
        (permille.min(1000) as f32) / 1000.0
    }

    fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn new(
        proxy_tag: Option<Vec<u8>>,
        proxy_secret: Vec<u8>,
        nat_ip: Option<IpAddr>,
        nat_probe: bool,
        nat_stun: Option<String>,
        nat_stun_servers: Vec<String>,
        detected_ipv6: Option<Ipv6Addr>,
        me_one_retry: u8,
        me_one_timeout_ms: u64,
        proxy_map_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        proxy_map_v6: HashMap<i32, Vec<(IpAddr, u16)>>,
        default_dc: Option<i32>,
        decision: NetworkDecision,
        rng: Arc<SecureRandom>,
        stats: Arc<crate::stats::Stats>,
        me_keepalive_enabled: bool,
        me_keepalive_interval_secs: u64,
        me_keepalive_jitter_secs: u64,
        me_keepalive_payload_random: bool,
        me_warmup_stagger_enabled: bool,
        me_warmup_step_delay_ms: u64,
        me_warmup_step_jitter_ms: u64,
        me_reconnect_max_concurrent_per_dc: u32,
        me_reconnect_backoff_base_ms: u64,
        me_reconnect_backoff_cap_ms: u64,
        me_reconnect_fast_retry_count: u32,
        hardswap: bool,
        me_pool_drain_ttl_secs: u64,
        me_pool_force_close_secs: u64,
        me_pool_min_fresh_ratio: f32,
        me_hardswap_warmup_delay_min_ms: u64,
        me_hardswap_warmup_delay_max_ms: u64,
        me_hardswap_warmup_extra_passes: u8,
        me_hardswap_warmup_pass_backoff_base_ms: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::new(ConnRegistry::new()),
            writers: Arc::new(RwLock::new(Vec::new())),
            rr: AtomicU64::new(0),
            decision,
            rng,
            proxy_tag,
            proxy_secret: Arc::new(RwLock::new(proxy_secret)),
            nat_ip_cfg: nat_ip,
            nat_ip_detected: Arc::new(RwLock::new(None)),
            nat_probe,
            nat_stun,
            nat_stun_servers,
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
            me_warmup_stagger_enabled,
            me_warmup_step_delay: Duration::from_millis(me_warmup_step_delay_ms),
            me_warmup_step_jitter: Duration::from_millis(me_warmup_step_jitter_ms),
            me_reconnect_max_concurrent_per_dc,
            me_reconnect_backoff_base: Duration::from_millis(me_reconnect_backoff_base_ms),
            me_reconnect_backoff_cap: Duration::from_millis(me_reconnect_backoff_cap_ms),
            me_reconnect_fast_retry_count,
            pool_size: 2,
            proxy_map_v4: Arc::new(RwLock::new(proxy_map_v4)),
            proxy_map_v6: Arc::new(RwLock::new(proxy_map_v6)),
            default_dc: AtomicI32::new(default_dc.unwrap_or(0)),
            next_writer_id: AtomicU64::new(1),
            ping_tracker: Arc::new(Mutex::new(HashMap::new())),
            rtt_stats: Arc::new(Mutex::new(HashMap::new())),
            nat_reflection_cache: Arc::new(Mutex::new(NatReflectionCache::default())),
            writer_available: Arc::new(Notify::new()),
            refill_inflight: Arc::new(Mutex::new(HashSet::new())),
            conn_count: AtomicUsize::new(0),
            generation: AtomicU64::new(1),
            hardswap: AtomicBool::new(hardswap),
            me_pool_drain_ttl_secs: AtomicU64::new(me_pool_drain_ttl_secs),
            me_pool_force_close_secs: AtomicU64::new(me_pool_force_close_secs),
            me_pool_min_fresh_ratio_permille: AtomicU32::new(Self::ratio_to_permille(me_pool_min_fresh_ratio)),
            me_hardswap_warmup_delay_min_ms: AtomicU64::new(me_hardswap_warmup_delay_min_ms),
            me_hardswap_warmup_delay_max_ms: AtomicU64::new(me_hardswap_warmup_delay_max_ms),
            me_hardswap_warmup_extra_passes: AtomicU32::new(me_hardswap_warmup_extra_passes as u32),
            me_hardswap_warmup_pass_backoff_base_ms: AtomicU64::new(me_hardswap_warmup_pass_backoff_base_ms),
        })
    }

    pub fn has_proxy_tag(&self) -> bool {
        self.proxy_tag.is_some()
    }

    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn update_runtime_reinit_policy(
        &self,
        hardswap: bool,
        drain_ttl_secs: u64,
        force_close_secs: u64,
        min_fresh_ratio: f32,
        hardswap_warmup_delay_min_ms: u64,
        hardswap_warmup_delay_max_ms: u64,
        hardswap_warmup_extra_passes: u8,
        hardswap_warmup_pass_backoff_base_ms: u64,
    ) {
        self.hardswap.store(hardswap, Ordering::Relaxed);
        self.me_pool_drain_ttl_secs.store(drain_ttl_secs, Ordering::Relaxed);
        self.me_pool_force_close_secs
            .store(force_close_secs, Ordering::Relaxed);
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
    }

    pub fn reset_stun_state(&self) {
        self.nat_probe_attempts.store(0, Ordering::Relaxed);
        self.nat_probe_disabled.store(false, Ordering::Relaxed);
    }

    pub fn translate_our_addr(&self, addr: SocketAddr) -> SocketAddr {
        let ip = self.translate_ip_for_nat(addr.ip());
        SocketAddr::new(ip, addr.port())
    }

    pub fn registry(&self) -> &Arc<ConnRegistry> {
        &self.registry
    }

    fn writers_arc(&self) -> Arc<RwLock<Vec<MeWriter>>> {
        self.writers.clone()
    }

    fn force_close_timeout(&self) -> Option<Duration> {
        let secs = self.me_pool_force_close_secs.load(Ordering::Relaxed);
        if secs == 0 {
            None
        } else {
            Some(Duration::from_secs(secs))
        }
    }

    fn coverage_ratio(
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
        active_writer_addrs: &HashSet<SocketAddr>,
    ) -> (f32, Vec<i32>) {
        if desired_by_dc.is_empty() {
            return (1.0, Vec::new());
        }

        let mut missing_dc = Vec::<i32>::new();
        let mut covered = 0usize;
        for (dc, endpoints) in desired_by_dc {
            if endpoints.is_empty() {
                continue;
            }
            if endpoints.iter().any(|addr| active_writer_addrs.contains(addr)) {
                covered += 1;
            } else {
                missing_dc.push(*dc);
            }
        }

        missing_dc.sort_unstable();
        let total = desired_by_dc.len().max(1);
        let ratio = (covered as f32) / (total as f32);
        (ratio, missing_dc)
    }

    pub async fn reconcile_connections(self: &Arc<Self>, rng: &SecureRandom) {
        let writers = self.writers.read().await;
        let current: HashSet<SocketAddr> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .map(|w| w.addr)
            .collect();
        drop(writers);

        for family in self.family_order() {
            let map = self.proxy_map_for_family(family).await;
            for (_dc, addrs) in map.iter() {
                let dc_addrs: Vec<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if !dc_addrs.iter().any(|a| current.contains(a)) {
                    let mut shuffled = dc_addrs.clone();
                    shuffled.shuffle(&mut rand::rng());
                    for addr in shuffled {
                        if self.connect_one(addr, rng).await.is_ok() {
                            break;
                        }
                    }
                }
            }
            if !self.decision.effective_multipath && !current.is_empty() {
                break;
            }
        }
    }

    async fn desired_dc_endpoints(&self) -> HashMap<i32, HashSet<SocketAddr>> {
        let mut out: HashMap<i32, HashSet<SocketAddr>> = HashMap::new();

        if self.decision.ipv4_me {
            let map_v4 = self.proxy_map_v4.read().await.clone();
            for (dc, addrs) in map_v4 {
                let entry = out.entry(dc.abs()).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        if self.decision.ipv6_me {
            let map_v6 = self.proxy_map_v6.read().await.clone();
            for (dc, addrs) in map_v6 {
                let entry = out.entry(dc.abs()).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        out
    }

    pub(super) fn required_writers_for_dc(endpoint_count: usize) -> usize {
        endpoint_count.max(3)
    }

    fn hardswap_warmup_connect_delay_ms(&self) -> u64 {
        let min_ms = self
            .me_hardswap_warmup_delay_min_ms
            .load(Ordering::Relaxed);
        let max_ms = self
            .me_hardswap_warmup_delay_max_ms
            .load(Ordering::Relaxed);
        let (min_ms, max_ms) = if min_ms <= max_ms {
            (min_ms, max_ms)
        } else {
            (max_ms, min_ms)
        };
        if min_ms == max_ms {
            return min_ms;
        }
        rand::rng().random_range(min_ms..=max_ms)
    }

    fn hardswap_warmup_backoff_ms(&self, pass_idx: usize) -> u64 {
        let base_ms = self
            .me_hardswap_warmup_pass_backoff_base_ms
            .load(Ordering::Relaxed);
        let cap_ms = (self.me_reconnect_backoff_cap.as_millis() as u64).max(base_ms);
        let shift = (pass_idx as u32).min(20);
        let scaled = base_ms.saturating_mul(1u64 << shift);
        let core = scaled.min(cap_ms);
        let jitter = (core / 2).max(1);
        core.saturating_add(rand::rng().random_range(0..=jitter))
    }

    async fn fresh_writer_count_for_endpoints(
        &self,
        generation: u64,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let ws = self.writers.read().await;
        ws.iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| w.generation == generation)
            .filter(|w| endpoints.contains(&w.addr))
            .count()
    }

    pub(super) async fn connect_endpoints_round_robin(
        self: &Arc<Self>,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
    ) -> bool {
        if endpoints.is_empty() {
            return false;
        }
        let start = (self.rr.fetch_add(1, Ordering::Relaxed) as usize) % endpoints.len();
        for offset in 0..endpoints.len() {
            let idx = (start + offset) % endpoints.len();
            let addr = endpoints[idx];
            match self.connect_one(addr, rng).await {
                Ok(()) => return true,
                Err(e) => debug!(%addr, error = %e, "ME connect failed during round-robin warmup"),
            }
        }
        false
    }

    async fn warmup_generation_for_all_dcs(
        self: &Arc<Self>,
        rng: &SecureRandom,
        generation: u64,
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
    ) {
        let extra_passes = self
            .me_hardswap_warmup_extra_passes
            .load(Ordering::Relaxed)
            .min(10) as usize;
        let total_passes = 1 + extra_passes;

        for (dc, endpoints) in desired_by_dc {
            if endpoints.is_empty() {
                continue;
            }

            let mut endpoint_list: Vec<SocketAddr> = endpoints.iter().copied().collect();
            endpoint_list.sort_unstable();
            let required = Self::required_writers_for_dc(endpoint_list.len());
            let mut completed = false;
            let mut last_fresh_count = self
                .fresh_writer_count_for_endpoints(generation, endpoints)
                .await;

            for pass_idx in 0..total_passes {
                if last_fresh_count >= required {
                    completed = true;
                    break;
                }

                let missing = required.saturating_sub(last_fresh_count);
                debug!(
                    dc = *dc,
                    pass = pass_idx + 1,
                    total_passes,
                    fresh_count = last_fresh_count,
                    required,
                    missing,
                    endpoint_count = endpoint_list.len(),
                    "ME hardswap warmup pass started"
                );

                for attempt_idx in 0..missing {
                    let delay_ms = self.hardswap_warmup_connect_delay_ms();
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                    let connected = self.connect_endpoints_round_robin(&endpoint_list, rng).await;
                    debug!(
                        dc = *dc,
                        pass = pass_idx + 1,
                        total_passes,
                        attempt = attempt_idx + 1,
                        delay_ms,
                        connected,
                        "ME hardswap warmup connect attempt finished"
                    );
                }

                last_fresh_count = self
                    .fresh_writer_count_for_endpoints(generation, endpoints)
                    .await;
                if last_fresh_count >= required {
                    completed = true;
                    info!(
                        dc = *dc,
                        pass = pass_idx + 1,
                        total_passes,
                        fresh_count = last_fresh_count,
                        required,
                        "ME hardswap warmup floor reached for DC"
                    );
                    break;
                }

                if pass_idx + 1 < total_passes {
                    let backoff_ms = self.hardswap_warmup_backoff_ms(pass_idx);
                    debug!(
                        dc = *dc,
                        pass = pass_idx + 1,
                        total_passes,
                        fresh_count = last_fresh_count,
                        required,
                        backoff_ms,
                        "ME hardswap warmup pass incomplete, delaying next pass"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
            }

            if !completed {
                warn!(
                    dc = *dc,
                    fresh_count = last_fresh_count,
                    required,
                    endpoint_count = endpoint_list.len(),
                    total_passes,
                    "ME warmup stopped: unable to reach required writer floor for DC"
                );
            }
        }
    }

    pub async fn zero_downtime_reinit_after_map_change(
        self: &Arc<Self>,
        rng: &SecureRandom,
    ) {
        let desired_by_dc = self.desired_dc_endpoints().await;
        if desired_by_dc.is_empty() {
            warn!("ME endpoint map is empty; skipping stale writer drain");
            return;
        }

        let previous_generation = self.current_generation();
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let hardswap = self.hardswap.load(Ordering::Relaxed);

        if hardswap {
            self.warmup_generation_for_all_dcs(rng, generation, &desired_by_dc)
                .await;
        } else {
            self.reconcile_connections(rng).await;
        }

        let writers = self.writers.read().await;
        let active_writer_addrs: HashSet<SocketAddr> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .map(|w| w.addr)
            .collect();
        let min_ratio = Self::permille_to_ratio(
            self.me_pool_min_fresh_ratio_permille
                .load(Ordering::Relaxed),
        );
        let (coverage_ratio, missing_dc) = Self::coverage_ratio(&desired_by_dc, &active_writer_addrs);
        if !hardswap && coverage_ratio < min_ratio {
            warn!(
                previous_generation,
                generation,
                coverage_ratio = format_args!("{coverage_ratio:.3}"),
                min_ratio = format_args!("{min_ratio:.3}"),
                missing_dc = ?missing_dc,
                "ME reinit coverage below threshold; keeping stale writers"
            );
            return;
        }

        if hardswap {
            let mut fresh_missing_dc = Vec::<(i32, usize, usize)>::new();
            for (dc, endpoints) in &desired_by_dc {
                if endpoints.is_empty() {
                    continue;
                }
                let required = Self::required_writers_for_dc(endpoints.len());
                let fresh_count = writers
                    .iter()
                    .filter(|w| !w.draining.load(Ordering::Relaxed))
                    .filter(|w| w.generation == generation)
                    .filter(|w| endpoints.contains(&w.addr))
                    .count();
                if fresh_count < required {
                    fresh_missing_dc.push((*dc, fresh_count, required));
                }
            }
            if !fresh_missing_dc.is_empty() {
                warn!(
                    previous_generation,
                    generation,
                    missing_dc = ?fresh_missing_dc,
                    "ME hardswap pending: fresh generation coverage incomplete"
                );
                return;
            }
        } else if !missing_dc.is_empty() {
            warn!(
                missing_dc = ?missing_dc,
                // Keep stale writers alive when fresh coverage is incomplete.
                "ME reinit coverage incomplete; keeping stale writers"
            );
            return;
        }

        let desired_addrs: HashSet<SocketAddr> = desired_by_dc
            .values()
            .flat_map(|set| set.iter().copied())
            .collect();

        let stale_writer_ids: Vec<u64> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| {
                if hardswap {
                    w.generation < generation
                } else {
                    !desired_addrs.contains(&w.addr)
                }
            })
            .map(|w| w.id)
            .collect();
        drop(writers);

        if stale_writer_ids.is_empty() {
            debug!("ME reinit cycle completed with no stale writers");
            return;
        }

        let drain_timeout = self.force_close_timeout();
        let drain_timeout_secs = drain_timeout.map(|d| d.as_secs()).unwrap_or(0);
        info!(
            stale_writers = stale_writer_ids.len(),
            previous_generation,
            generation,
            hardswap,
            coverage_ratio = format_args!("{coverage_ratio:.3}"),
            min_ratio = format_args!("{min_ratio:.3}"),
            drain_timeout_secs,
            "ME reinit cycle covered; draining stale writers"
        );
        self.stats.increment_pool_swap_total();
        for writer_id in stale_writer_ids {
            self.mark_writer_draining_with_timeout(writer_id, drain_timeout, !hardswap)
                .await;
        }
    }

    pub async fn zero_downtime_reinit_periodic(
        self: &Arc<Self>,
        rng: &SecureRandom,
    ) {
        self.zero_downtime_reinit_after_map_change(rng).await;
    }

    async fn endpoints_for_same_dc(&self, addr: SocketAddr) -> Vec<SocketAddr> {
        let mut target_dc = HashSet::<i32>::new();
        let mut endpoints = HashSet::<SocketAddr>::new();

        if self.decision.ipv4_me {
            let map = self.proxy_map_v4.read().await.clone();
            for (dc, addrs) in &map {
                if addrs
                    .iter()
                    .any(|(ip, port)| SocketAddr::new(*ip, *port) == addr)
                {
                    target_dc.insert(dc.abs());
                }
            }
            for dc in &target_dc {
                for key in [*dc, -*dc] {
                    if let Some(addrs) = map.get(&key) {
                        for (ip, port) in addrs {
                            endpoints.insert(SocketAddr::new(*ip, *port));
                        }
                    }
                }
            }
        }

        if self.decision.ipv6_me {
            let map = self.proxy_map_v6.read().await.clone();
            for (dc, addrs) in &map {
                if addrs
                    .iter()
                    .any(|(ip, port)| SocketAddr::new(*ip, *port) == addr)
                {
                    target_dc.insert(dc.abs());
                }
            }
            for dc in &target_dc {
                for key in [*dc, -*dc] {
                    if let Some(addrs) = map.get(&key) {
                        for (ip, port) in addrs {
                            endpoints.insert(SocketAddr::new(*ip, *port));
                        }
                    }
                }
            }
        }

        let mut sorted: Vec<SocketAddr> = endpoints.into_iter().collect();
        sorted.sort_unstable();
        sorted
    }

    async fn refill_writer_after_loss(self: &Arc<Self>, addr: SocketAddr) -> bool {
        let fast_retries = self.me_reconnect_fast_retry_count.max(1);

        for attempt in 0..fast_retries {
            self.stats.increment_me_reconnect_attempt();
            match self.connect_one(addr, self.rng.as_ref()).await {
                Ok(()) => {
                    self.stats.increment_me_reconnect_success();
                    self.stats.increment_me_writer_restored_same_endpoint_total();
                    info!(
                        %addr,
                        attempt = attempt + 1,
                        "ME writer restored on the same endpoint"
                    );
                    return true;
                }
                Err(e) => {
                    debug!(
                        %addr,
                        attempt = attempt + 1,
                        error = %e,
                        "ME immediate same-endpoint reconnect failed"
                    );
                }
            }
        }

        let dc_endpoints = self.endpoints_for_same_dc(addr).await;
        if dc_endpoints.is_empty() {
            self.stats.increment_me_refill_failed_total();
            return false;
        }

        for attempt in 0..fast_retries {
            self.stats.increment_me_reconnect_attempt();
            if self
                .connect_endpoints_round_robin(&dc_endpoints, self.rng.as_ref())
                .await
            {
                self.stats.increment_me_reconnect_success();
                self.stats.increment_me_writer_restored_fallback_total();
                info!(
                    %addr,
                    attempt = attempt + 1,
                    "ME writer restored via DC fallback endpoint"
                );
                return true;
            }
        }

        self.stats.increment_me_refill_failed_total();
        false
    }

    pub(crate) fn trigger_immediate_refill(self: &Arc<Self>, addr: SocketAddr) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            {
                let mut guard = pool.refill_inflight.lock().await;
                if !guard.insert(addr) {
                    pool.stats.increment_me_refill_skipped_inflight_total();
                    return;
                }
            }
            pool.stats.increment_me_refill_triggered_total();

            let restored = pool.refill_writer_after_loss(addr).await;
            if !restored {
                warn!(%addr, "ME immediate refill failed");
            }

            let mut guard = pool.refill_inflight.lock().await;
            guard.remove(&addr);
        });
    }

    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> bool {
        let mut changed = false;
        {
            let mut guard = self.proxy_map_v4.write().await;
            if !new_v4.is_empty() && *guard != new_v4 {
                *guard = new_v4;
                changed = true;
            }
        }
        if let Some(v6) = new_v6 {
            let mut guard = self.proxy_map_v6.write().await;
            if !v6.is_empty() && *guard != v6 {
                *guard = v6;
                changed = true;
            }
        }
        // Ensure negative DC entries mirror positives when absent (Telegram convention).
        {
            let mut guard = self.proxy_map_v4.write().await;
            let keys: Vec<i32> = guard.keys().cloned().collect();
            for k in keys.iter().cloned().filter(|k| *k > 0) {
                if !guard.contains_key(&-k)
                    && let Some(addrs) = guard.get(&k).cloned()
                {
                    guard.insert(-k, addrs);
                }
            }
        }
        {
            let mut guard = self.proxy_map_v6.write().await;
            let keys: Vec<i32> = guard.keys().cloned().collect();
            for k in keys.iter().cloned().filter(|k| *k > 0) {
                if !guard.contains_key(&-k)
                    && let Some(addrs) = guard.get(&k).cloned()
                {
                    guard.insert(-k, addrs);
                }
            }
        }
        changed
    }

    pub async fn update_secret(self: &Arc<Self>, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(len = new_secret.len(), "proxy-secret update ignored (too short)");
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        if *guard != new_secret {
            *guard = new_secret;
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    pub async fn reconnect_all(self: &Arc<Self>) {
        let ws = self.writers.read().await.clone();
        for w in ws {
            if let Ok(()) = self.connect_one(w.addr, self.rng.as_ref()).await {
                self.mark_writer_draining(w.id).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    pub(super) async fn key_selector(&self) -> u32 {
        let secret = self.proxy_secret.read().await;
        if secret.len() >= 4 {
            u32::from_le_bytes([secret[0], secret[1], secret[2], secret[3]])
        } else {
            0
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

    async fn proxy_map_for_family(&self, family: IpFamily) -> HashMap<i32, Vec<(IpAddr, u16)>> {
        match family {
            IpFamily::V4 => self.proxy_map_v4.read().await.clone(),
            IpFamily::V6 => self.proxy_map_v6.read().await.clone(),
        }
    }

    pub async fn init(self: &Arc<Self>, pool_size: usize, rng: &Arc<SecureRandom>) -> Result<()> {
        let family_order = self.family_order();
        let ks = self.key_selector().await;
        info!(
            me_servers = self.proxy_map_v4.read().await.len(),
            pool_size,
            key_selector = format_args!("0x{ks:08x}"),
            secret_len = self.proxy_secret.read().await.len(),
            "Initializing ME pool"
        );

        for family in family_order {
            let map = self.proxy_map_for_family(family).await;
            let dc_addrs: Vec<(i32, Vec<(IpAddr, u16)>)> = map
                .iter()
                .map(|(dc, addrs)| (*dc, addrs.clone()))
                .collect();

            // Ensure at least one connection per DC; run DCs in parallel.
            let mut join = tokio::task::JoinSet::new();
            let mut dc_failures = 0usize;
            for (dc, addrs) in dc_addrs.iter().cloned() {
                if addrs.is_empty() {
                    continue;
                }
                let pool = Arc::clone(self);
                let rng_clone = Arc::clone(rng);
                join.spawn(async move {
                    pool.connect_primary_for_dc(dc, addrs, rng_clone).await
                });
            }
            while let Some(res) = join.join_next().await {
                if let Ok(false) = res {
                    dc_failures += 1;
                }
            }
            if dc_failures > 2 {
                return Err(ProxyError::Proxy("Too many ME DC init failures, falling back to direct".into()));
            }

        // Additional connections up to pool_size total (round-robin across DCs), staggered to de-phase lifecycles.
        if self.me_warmup_stagger_enabled {
            for (dc, addrs) in dc_addrs.iter() {
                for (ip, port) in addrs {
                    if self.connection_count() >= pool_size {
                        break;
                    }
                    let addr = SocketAddr::new(*ip, *port);
                    let jitter = rand::rng().random_range(0..=self.me_warmup_step_jitter.as_millis() as u64);
                    let delay_ms = self.me_warmup_step_delay.as_millis() as u64 + jitter;
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    if let Err(e) = self.connect_one(addr, rng.as_ref()).await {
                        debug!(%addr, dc = %dc, error = %e, "Extra ME connect failed (staggered)");
                    }
                }
            }
        } else {
            for (dc, addrs) in dc_addrs.iter() {
                for (ip, port) in addrs {
                    if self.connection_count() >= pool_size {
                        break;
                    }
                    let addr = SocketAddr::new(*ip, *port);
                    if let Err(e) = self.connect_one(addr, rng.as_ref()).await {
                        debug!(%addr, dc = %dc, error = %e, "Extra ME connect failed");
                    }
                }
                if self.connection_count() >= pool_size {
                    break;
                }
            }
        }

            if !self.decision.effective_multipath && self.connection_count() > 0 {
                break;
            }
        }

        if self.writers.read().await.is_empty() {
            return Err(ProxyError::Proxy("No ME connections".into()));
        }
        Ok(())
    }

    pub(crate) async fn connect_one(self: &Arc<Self>, addr: SocketAddr, rng: &SecureRandom) -> Result<()> {
        let secret_len = self.proxy_secret.read().await.len();
        if secret_len < 32 {
            return Err(ProxyError::Proxy("proxy-secret too short for ME auth".into()));
        }

        let (stream, _connect_ms) = self.connect_tcp(addr).await?;
        let hs = self.handshake_only(stream, addr, rng).await?;

        let writer_id = self.next_writer_id.fetch_add(1, Ordering::Relaxed);
        let generation = self.current_generation();
        let cancel = CancellationToken::new();
        let degraded = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let draining_started_at_epoch_secs = Arc::new(AtomicU64::new(0));
        let allow_drain_fallback = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = mpsc::channel::<WriterCommand>(4096);
        let mut rpc_writer = RpcWriter {
            writer: hs.wr,
            key: hs.write_key,
            iv: hs.write_iv,
            seq_no: 0,
            crc_mode: hs.crc_mode,
        };
        let cancel_wr = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(WriterCommand::Data(payload)) => {
                                if rpc_writer.send(&payload).await.is_err() { break; }
                            }
                            Some(WriterCommand::DataAndFlush(payload)) => {
                                if rpc_writer.send_and_flush(&payload).await.is_err() { break; }
                            }
                            Some(WriterCommand::Close) | None => break,
                        }
                    }
                    _ = cancel_wr.cancelled() => break,
                }
            }
        });
        let writer = MeWriter {
            id: writer_id,
            addr,
            generation,
            tx: tx.clone(),
            cancel: cancel.clone(),
            degraded: degraded.clone(),
            draining: draining.clone(),
            draining_started_at_epoch_secs: draining_started_at_epoch_secs.clone(),
            allow_drain_fallback: allow_drain_fallback.clone(),
        };
        self.writers.write().await.push(writer.clone());
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.writer_available.notify_one();

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = self.ping_tracker.clone();
        let ping_tracker_reader = ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let stats_reader = self.stats.clone();
        let stats_ping = self.stats.clone();
        let pool = Arc::downgrade(self);
        let cancel_ping = cancel.clone();
        let tx_ping = tx.clone();
        let ping_tracker_ping = ping_tracker.clone();
        let cleanup_done = Arc::new(AtomicBool::new(false));
        let cleanup_for_reader = cleanup_done.clone();
        let cleanup_for_ping = cleanup_done.clone();
        let keepalive_enabled = self.me_keepalive_enabled;
        let keepalive_interval = self.me_keepalive_interval;
        let keepalive_jitter = self.me_keepalive_jitter;
        let cancel_reader_token = cancel.clone();
        let cancel_ping_token = cancel_ping.clone();

        tokio::spawn(async move {
            let res = reader_loop(
                hs.rd,
                hs.read_key,
                hs.read_iv,
                hs.crc_mode,
                reg.clone(),
                BytesMut::new(),
                BytesMut::new(),
                tx.clone(),
                ping_tracker_reader,
                rtt_stats.clone(),
                stats_reader,
                writer_id,
                degraded.clone(),
                cancel_reader_token.clone(),
            )
            .await;
            if let Some(pool) = pool.upgrade()
                && cleanup_for_reader
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                pool.remove_writer_and_close_clients(writer_id).await;
            }
            if let Err(e) = res {
                warn!(error = %e, "ME reader ended");
            }
            let mut ws = writers_arc.write().await;
            ws.retain(|w| w.id != writer_id);
            info!(remaining = ws.len(), "Dead ME writer removed from pool");
        });

        let pool_ping = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ping_id: i64 = rand::random::<i64>();
            // Per-writer jittered start to avoid phase sync.
            let startup_jitter = if keepalive_enabled {
                let jitter_cap_ms = keepalive_interval.as_millis() / 2;
                let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
                Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
            } else {
                let jitter = rand::rng()
                    .random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
                let wait = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
                Duration::from_secs(wait)
            };
            tokio::select! {
                _ = cancel_ping_token.cancelled() => return,
                _ = tokio::time::sleep(startup_jitter) => {}
            }
            loop {
                let wait = if keepalive_enabled {
                    let jitter_cap_ms = keepalive_interval.as_millis() / 2;
                    let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
                    keepalive_interval
                        + Duration::from_millis(
                            rand::rng().random_range(0..=effective_jitter_ms as u64)
                        )
                } else {
                    let jitter = rand::rng()
                        .random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
                    let secs = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
                    Duration::from_secs(secs)
                };
                tokio::select! {
                    _ = cancel_ping_token.cancelled() => {
                        break;
                    }
                    _ = tokio::time::sleep(wait) => {}
                }
                let sent_id = ping_id;
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&RPC_PING_U32.to_le_bytes());
                p.extend_from_slice(&sent_id.to_le_bytes());
                {
                    let mut tracker = ping_tracker_ping.lock().await;
                    let before = tracker.len();
                    tracker.retain(|_, (ts, _)| ts.elapsed() < Duration::from_secs(120));
                    let expired = before.saturating_sub(tracker.len());
                    if expired > 0 {
                        stats_ping.increment_me_keepalive_timeout_by(expired as u64);
                    }
                    tracker.insert(sent_id, (std::time::Instant::now(), writer_id));
                }
                ping_id = ping_id.wrapping_add(1);
                stats_ping.increment_me_keepalive_sent();
                if tx_ping.send(WriterCommand::DataAndFlush(p)).await.is_err() {
                    stats_ping.increment_me_keepalive_failed();
                    debug!("ME ping failed, removing dead writer");
                    cancel_ping.cancel();
                    if let Some(pool) = pool_ping.upgrade()
                        && cleanup_for_ping
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                            .is_ok()
                    {
                        pool.remove_writer_and_close_clients(writer_id).await;
                    }
                    break;
                }
            }
        });

        Ok(())
    }

    async fn connect_primary_for_dc(
        self: Arc<Self>,
        dc: i32,
        mut addrs: Vec<(IpAddr, u16)>,
        rng: Arc<SecureRandom>,
    ) -> bool {
        if addrs.is_empty() {
            return false;
        }
        addrs.shuffle(&mut rand::rng());
        for (ip, port) in addrs {
            let addr = SocketAddr::new(ip, port);
            match self.connect_one(addr, rng.as_ref()).await {
                Ok(()) => {
                    info!(%addr, dc = %dc, "ME connected");
                    return true;
                }
                Err(e) => warn!(%addr, dc = %dc, error = %e, "ME connect failed, trying next"),
            }
        }
        warn!(dc = %dc, "All ME servers for DC failed at init");
        false
    }

    pub(crate) async fn remove_writer_and_close_clients(self: &Arc<Self>, writer_id: u64) {
        let conns = self.remove_writer_only(writer_id).await;
        for bound in conns {
            let _ = self.registry.route(bound.conn_id, super::MeResponse::Close).await;
            let _ = self.registry.unregister(bound.conn_id).await;
        }
    }

    async fn remove_writer_only(self: &Arc<Self>, writer_id: u64) -> Vec<BoundConn> {
        let mut close_tx: Option<mpsc::Sender<WriterCommand>> = None;
        let mut removed_addr: Option<SocketAddr> = None;
        let mut trigger_refill = false;
        {
            let mut ws = self.writers.write().await;
            if let Some(pos) = ws.iter().position(|w| w.id == writer_id) {
                let w = ws.remove(pos);
                let was_draining = w.draining.load(Ordering::Relaxed);
                if was_draining {
                    self.stats.decrement_pool_drain_active();
                }
                self.stats.increment_me_writer_removed_total();
                w.cancel.cancel();
                removed_addr = Some(w.addr);
                trigger_refill = !was_draining;
                if trigger_refill {
                    self.stats.increment_me_writer_removed_unexpected_total();
                }
                close_tx = Some(w.tx.clone());
                self.conn_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if let Some(tx) = close_tx {
            let _ = tx.send(WriterCommand::Close).await;
        }
        if trigger_refill
            && let Some(addr) = removed_addr
        {
            self.trigger_immediate_refill(addr);
        }
        self.rtt_stats.lock().await.remove(&writer_id);
        self.registry.writer_lost(writer_id).await
    }

    pub(crate) async fn mark_writer_draining_with_timeout(
        self: &Arc<Self>,
        writer_id: u64,
        timeout: Option<Duration>,
        allow_drain_fallback: bool,
    ) {
        let timeout = timeout.filter(|d| !d.is_zero());
        let found = {
            let mut ws = self.writers.write().await;
            if let Some(w) = ws.iter_mut().find(|w| w.id == writer_id) {
                let already_draining = w.draining.swap(true, Ordering::Relaxed);
                w.allow_drain_fallback
                    .store(allow_drain_fallback, Ordering::Relaxed);
                w.draining_started_at_epoch_secs
                    .store(Self::now_epoch_secs(), Ordering::Relaxed);
                if !already_draining {
                    self.stats.increment_pool_drain_active();
                }
                w.draining.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        };

        if !found {
            return;
        }

        let timeout_secs = timeout.map(|d| d.as_secs()).unwrap_or(0);
        debug!(
            writer_id,
            timeout_secs,
            allow_drain_fallback,
            "ME writer marked draining"
        );

        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            let deadline = timeout.map(|t| Instant::now() + t);
            while let Some(p) = pool.upgrade() {
                if let Some(deadline_at) = deadline
                    && Instant::now() >= deadline_at
                {
                    warn!(writer_id, "Drain timeout, force-closing");
                    p.stats.increment_pool_force_close_total();
                    let _ = p.remove_writer_and_close_clients(writer_id).await;
                    break;
                }
                if p.registry.is_writer_empty(writer_id).await {
                    let _ = p.remove_writer_only(writer_id).await;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    pub(crate) async fn mark_writer_draining(self: &Arc<Self>, writer_id: u64) {
        self.mark_writer_draining_with_timeout(writer_id, Some(Duration::from_secs(300)), false)
            .await;
    }

    pub(super) fn writer_accepts_new_binding(&self, writer: &MeWriter) -> bool {
        if !writer.draining.load(Ordering::Relaxed) {
            return true;
        }
        if !writer.allow_drain_fallback.load(Ordering::Relaxed) {
            return false;
        }

        let ttl_secs = self.me_pool_drain_ttl_secs.load(Ordering::Relaxed);
        if ttl_secs == 0 {
            return true;
        }

        let started = writer.draining_started_at_epoch_secs.load(Ordering::Relaxed);
        if started == 0 {
            return false;
        }

        Self::now_epoch_secs().saturating_sub(started) <= ttl_secs
    }

}

#[allow(dead_code)]
fn hex_dump(data: &[u8]) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(data.len() * 2 + 3);
    for (i, b) in data.iter().take(MAX).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02x}"));
    }
    if data.len() > MAX {
        out.push_str(" …");
    }
    out
}
