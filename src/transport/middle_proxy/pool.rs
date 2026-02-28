use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, Notify, RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::crypto::SecureRandom;
use crate::network::IpFamily;
use crate::network::probe::NetworkDecision;

use super::ConnRegistry;
use super::codec::WriterCommand;

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

    pub(super) fn permille_to_ratio(permille: u32) -> f32 {
        (permille.min(1000) as f32) / 1000.0
    }

    pub(super) fn now_epoch_secs() -> u64 {
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
        nat_probe_concurrency: usize,
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
            me_pool_min_fresh_ratio_permille: AtomicU32::new(Self::ratio_to_permille(
                me_pool_min_fresh_ratio,
            )),
            me_hardswap_warmup_delay_min_ms: AtomicU64::new(me_hardswap_warmup_delay_min_ms),
            me_hardswap_warmup_delay_max_ms: AtomicU64::new(me_hardswap_warmup_delay_max_ms),
            me_hardswap_warmup_extra_passes: AtomicU32::new(me_hardswap_warmup_extra_passes as u32),
            me_hardswap_warmup_pass_backoff_base_ms: AtomicU64::new(
                me_hardswap_warmup_pass_backoff_base_ms,
            ),
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
        self.me_pool_drain_ttl_secs
            .store(drain_ttl_secs, Ordering::Relaxed);
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
        if let Ok(mut live) = self.nat_stun_live_servers.try_write() {
            live.clear();
        }
    }

    pub fn translate_our_addr(&self, addr: SocketAddr) -> SocketAddr {
        let ip = self.translate_ip_for_nat(addr.ip());
        SocketAddr::new(ip, addr.port())
    }

    pub fn registry(&self) -> &Arc<ConnRegistry> {
        &self.registry
    }

    pub(super) fn writers_arc(&self) -> Arc<RwLock<Vec<MeWriter>>> {
        self.writers.clone()
    }

    pub(super) fn force_close_timeout(&self) -> Option<Duration> {
        let secs = self.me_pool_force_close_secs.load(Ordering::Relaxed);
        if secs == 0 {
            None
        } else {
            Some(Duration::from_secs(secs))
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

    pub(super) async fn proxy_map_for_family(
        &self,
        family: IpFamily,
    ) -> HashMap<i32, Vec<(IpAddr, u16)>> {
        match family {
            IpFamily::V4 => self.proxy_map_v4.read().await.clone(),
            IpFamily::V6 => self.proxy_map_v6.read().await.clone(),
        }
    }
}
