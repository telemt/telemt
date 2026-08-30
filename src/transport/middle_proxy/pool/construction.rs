use super::*;

impl MePool {
    pub(in crate::transport::middle_proxy) fn ratio_to_permille(ratio: f32) -> u32 {
        let clamped = ratio.clamp(0.0, 1.0);
        (clamped * 1000.0).round() as u32
    }

    pub(in crate::transport::middle_proxy) fn permille_to_ratio(permille: u32) -> f32 {
        (permille.min(1000) as f32) / 1000.0
    }

    pub(in crate::transport::middle_proxy) fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub(in crate::transport::middle_proxy) fn normalize_force_close_secs(
        force_close_secs: u64,
    ) -> u64 {
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
        stun_tcp_fallback: bool,
        http_ip_detect_urls: Vec<String>,
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
        me_writer_byte_budget_bytes: usize,
        me_route_channel_capacity: usize,
        me_route_backpressure_enabled: bool,
        me_route_fairshare_enabled: bool,
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
        me_connection_cleanup_capacity: usize,
    ) -> Arc<Self> {
        let endpoint_dc_map = Self::build_endpoint_dc_map_from_maps(&proxy_map_v4, &proxy_map_v6);
        let preferred_endpoints_by_dc =
            Self::build_preferred_endpoints_by_dc(&decision, &proxy_map_v4, &proxy_map_v6);
        let registry = Arc::new(ConnRegistry::with_route_and_cleanup_capacity(
            me_route_channel_capacity,
            me_connection_cleanup_capacity,
        ));
        registry.update_route_backpressure_policy(
            me_route_backpressure_base_timeout_ms,
            me_route_backpressure_high_timeout_ms,
            me_route_backpressure_high_watermark_pct,
        );
        let (writer_epoch, _) = watch::channel(0u64);
        let now_epoch_secs = Self::now_epoch_secs();
        let reinit_status = ReinitStatusSnapshot {
            active_generation: 1,
            warm_generations: Vec::new(),
            pending_hardswap_generation: 0,
            pending_hardswap_started_at_epoch_secs: 0,
            pending_hardswap_map_hash: 0,
            inflight: 0,
        };
        stats.set_me_writer_byte_budget_limit_bytes(me_writer_byte_budget_bytes);
        Arc::new(Self {
            routing: Arc::new(RoutingCore {
                registry,
                writers: Arc::new(WritersState::new()),
                rr: AtomicU64::new(0),
                writer_epoch,
                preferred_endpoints_by_dc: ArcSwap::from_pointee(preferred_endpoints_by_dc),
            }),
            reinit: Arc::new(ReinitCore {
                generation: AtomicU64::new(1),
                active_generation: AtomicU64::new(1),
                warm_generation: AtomicU64::new(0),
                pending_hardswap_generation: AtomicU64::new(0),
                pending_hardswap_started_at_epoch_secs: AtomicU64::new(0),
                pending_hardswap_map_hash: AtomicU64::new(0),
                scheduler_inflight: AtomicUsize::new(0),
                max_concurrency_effective: AtomicUsize::new(1),
                coordinator: ParkingMutex::new(ReinitCoordinatorState {
                    next_attempt_id: 1,
                    active_generation: 1,
                    desired_map_hash: 0,
                    pending: None,
                    attempts: HashMap::new(),
                }),
                status: ArcSwap::from_pointee(reinit_status),
                hardswap: AtomicBool::new(hardswap),
                me_hardswap_warmup_delay_min_ms: AtomicU64::new(me_hardswap_warmup_delay_min_ms),
                me_hardswap_warmup_delay_max_ms: AtomicU64::new(me_hardswap_warmup_delay_max_ms),
                me_hardswap_warmup_extra_passes: AtomicU32::new(
                    me_hardswap_warmup_extra_passes as u32,
                ),
                me_hardswap_warmup_pass_backoff_base_ms: AtomicU64::new(
                    me_hardswap_warmup_pass_backoff_base_ms,
                ),
            }),
            writer_lifecycle: Arc::new(WriterLifecycleCore {
                me_keepalive_enabled,
                me_keepalive_interval: Duration::from_secs(me_keepalive_interval_secs),
                me_keepalive_jitter: Duration::from_secs(me_keepalive_jitter_secs),
                me_keepalive_payload_random,
                rpc_proxy_req_every_secs: AtomicU64::new(rpc_proxy_req_every_secs),
                writer_cmd_channel_capacity: me_writer_cmd_channel_capacity.max(1),
                writer_byte_budget_permits: me_writer_byte_budget_bytes
                    .div_ceil(crate::config::defaults::ME_WRITER_BYTE_PERMIT_UNIT_BYTES)
                    .max(1),
            }),
            route_runtime: Arc::new(RouteRuntimeCore {
                me_route_no_writer_mode: AtomicU8::new(me_route_no_writer_mode.as_u8()),
                me_route_no_writer_wait: Duration::from_millis(me_route_no_writer_wait_ms),
                me_route_hybrid_max_wait: Duration::from_millis(
                    me_route_hybrid_max_wait_ms.max(50),
                ),
                me_route_blocking_send_timeout: Some(Duration::from_millis(
                    me_route_blocking_send_timeout_ms.clamp(1, 5_000),
                )),
                me_route_last_success_epoch_ms: AtomicU64::new(0),
                me_route_hybrid_timeout_warn_epoch_ms: AtomicU64::new(0),
                me_async_recovery_last_trigger_epoch_ms: AtomicU64::new(0),
                me_route_inline_recovery_attempts,
                me_route_inline_recovery_wait: Duration::from_millis(
                    me_route_inline_recovery_wait_ms,
                ),
            }),
            health_runtime: Arc::new(HealthRuntimeCore {
                me_health_interval_ms_unhealthy: AtomicU64::new(
                    me_health_interval_ms_unhealthy.max(1),
                ),
                me_health_interval_ms_healthy: AtomicU64::new(me_health_interval_ms_healthy.max(1)),
                me_warn_rate_limit_ms: AtomicU64::new(me_warn_rate_limit_ms.max(1)),
                family_health_v4: ArcSwap::from_pointee(FamilyHealthSnapshot::new(
                    MeFamilyRuntimeState::Healthy,
                    now_epoch_secs,
                    0,
                    0,
                    0,
                )),
                family_health_v6: ArcSwap::from_pointee(FamilyHealthSnapshot::new(
                    MeFamilyRuntimeState::Healthy,
                    now_epoch_secs,
                    0,
                    0,
                    0,
                )),
            }),
            drain_runtime: Arc::new(DrainRuntimeCore {
                me_pool_drain_ttl_secs: AtomicU64::new(me_pool_drain_ttl_secs),
                me_instadrain: AtomicBool::new(me_instadrain),
                me_pool_drain_threshold: AtomicU64::new(me_pool_drain_threshold),
                me_pool_drain_soft_evict_enabled: AtomicBool::new(me_pool_drain_soft_evict_enabled),
                me_pool_drain_soft_evict_grace_secs: AtomicU64::new(
                    me_pool_drain_soft_evict_grace_secs,
                ),
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
                me_last_drain_gate_route_quorum_ok: AtomicBool::new(false),
                me_last_drain_gate_redundancy_ok: AtomicBool::new(false),
                me_last_drain_gate_block_reason: AtomicU8::new(MeDrainGateReason::Open as u8),
                me_last_drain_gate_updated_at_epoch_secs: AtomicU64::new(now_epoch_secs),
            }),
            single_endpoint_runtime: Arc::new(SingleEndpointRuntimeCore {
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
            }),
            binding_policy: Arc::new(BindingPolicyCore {
                me_bind_stale_mode: AtomicU8::new(me_bind_stale_mode.as_u8()),
                me_bind_stale_ttl_secs: AtomicU64::new(me_bind_stale_ttl_secs),
            }),
            nat_runtime: Arc::new(NatRuntimeCore {
                nat_ip_cfg: nat_ip,
                nat_ip_detected: Arc::new(RwLock::new(None)),
                nat_probe,
                nat_stun,
                nat_stun_servers,
                stun_tcp_fallback,
                http_ip_detect_urls,
                nat_stun_live_servers: Arc::new(RwLock::new(Vec::new())),
                nat_probe_concurrency: nat_probe_concurrency.max(1),
                detected_ipv6,
                nat_probe_attempts: std::sync::atomic::AtomicU8::new(0),
                nat_probe_disabled: std::sync::atomic::AtomicBool::new(false),
                stun_backoff_until: Arc::new(RwLock::new(None)),
                nat_reflection_cache: Arc::new(Mutex::new(NatReflectionCache::default())),
                nat_reflection_singleflight_v4: Arc::new(Mutex::new(())),
                nat_reflection_singleflight_v6: Arc::new(Mutex::new(())),
            }),
            reconnect_runtime: Arc::new(ReconnectRuntimeCore {
                me_one_retry,
                me_one_timeout: Duration::from_millis(me_one_timeout_ms),
                me_warmup_stagger_enabled,
                me_warmup_step_delay: Duration::from_millis(me_warmup_step_delay_ms),
                me_warmup_step_jitter: Duration::from_millis(me_warmup_step_jitter_ms),
                me_reconnect_max_concurrent_per_dc,
                me_reconnect_backoff_base: Duration::from_millis(me_reconnect_backoff_base_ms),
                me_reconnect_backoff_cap: Duration::from_millis(me_reconnect_backoff_cap_ms),
                me_reconnect_fast_retry_count,
            }),
            floor_runtime: Arc::new(FloorRuntimeCore {
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
            }),
            writer_selection_policy: Arc::new(WriterSelectionPolicyCore {
                secret_atomic_snapshot: AtomicBool::new(me_secret_atomic_snapshot),
                me_deterministic_writer_sort: AtomicBool::new(me_deterministic_writer_sort),
                me_writer_pick_mode: AtomicU8::new(me_writer_pick_mode.as_u8()),
                me_writer_pick_sample_size: AtomicU8::new(me_writer_pick_sample_size.clamp(2, 4)),
            }),
            transport_policy: Arc::new(TransportPolicyCore {
                me_socks_kdf_policy: AtomicU8::new(me_socks_kdf_policy.as_u8()),
                me_route_backpressure_enabled: Arc::new(AtomicBool::new(
                    me_route_backpressure_enabled,
                )),
                me_route_fairshare_enabled: Arc::new(AtomicBool::new(me_route_fairshare_enabled)),
                me_reader_route_data_wait_ms: Arc::new(AtomicU64::new(
                    me_reader_route_data_wait_ms,
                )),
            }),
            lifecycle: MePoolLifecycle::new(),
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
            stats,
            pool_size: 2,
            proxy_map_v4: Arc::new(RwLock::new(proxy_map_v4)),
            proxy_map_v6: Arc::new(RwLock::new(proxy_map_v6)),
            endpoint_dc_map: Arc::new(RwLock::new(endpoint_dc_map)),
            default_dc: AtomicI32::new(default_dc.unwrap_or(2)),
            next_writer_id: AtomicU64::new(1),
            writer_connect_active_reserved: AtomicUsize::new(0),
            writer_connect_warm_reserved: AtomicUsize::new(0),
            rtt_stats: Arc::new(Mutex::new(HashMap::new())),
            refill_states: Arc::new(ParkingMutex::new(HashMap::new())),
            refill_running: AtomicUsize::new(0),
            refill_pending: AtomicUsize::new(0),
            conn_count: AtomicUsize::new(0),
            draining_active_runtime: AtomicU64::new(0),
            endpoint_quarantine: Arc::new(Mutex::new(HashMap::new())),
            kdf_material_fingerprint: Arc::new(RwLock::new(HashMap::new())),
            runtime_ready: AtomicBool::new(false),
        })
    }
}
