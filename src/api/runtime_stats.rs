use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::ApiConfig;
use crate::stats::Stats;
use crate::transport::UpstreamRouteKind;
use crate::transport::upstream::IpPreference;

use super::ApiShared;
use super::model::{
    DcEndpointWriters, DcStatus, DcStatusData, MeWriterStatus, MeWritersData, MeWritersSummary,
    MinimalAllData, MinimalAllPayload, MinimalDcPathData, MinimalMeRuntimeData,
    MinimalQuarantineData, UpstreamDcStatus, UpstreamStatus, UpstreamSummaryData, UpstreamsData,
    ZeroAllData, ZeroCodeCount, ZeroCoreData, ZeroDesyncData, ZeroMiddleProxyData, ZeroPoolData,
    ZeroUpstreamData,
};

const FEATURE_DISABLED_REASON: &str = "feature_disabled";
const SOURCE_UNAVAILABLE_REASON: &str = "source_unavailable";

#[derive(Clone)]
pub(crate) struct MinimalCacheEntry {
    pub(super) expires_at: Instant,
    pub(super) payload: MinimalAllPayload,
    pub(super) generated_at_epoch_secs: u64,
}

pub(super) fn build_zero_all_data(stats: &Stats, configured_users: usize) -> ZeroAllData {
    let telemetry = stats.telemetry_policy();
    let handshake_error_codes = stats
        .get_me_handshake_error_code_counts()
        .into_iter()
        .map(|(code, total)| ZeroCodeCount { code, total })
        .collect();

    ZeroAllData {
        generated_at_epoch_secs: now_epoch_secs(),
        core: ZeroCoreData {
            uptime_seconds: stats.uptime_secs(),
            connections_total: stats.get_connects_all(),
            connections_bad_total: stats.get_connects_bad(),
            handshake_timeouts_total: stats.get_handshake_timeouts(),
            configured_users,
            telemetry_core_enabled: telemetry.core_enabled,
            telemetry_user_enabled: telemetry.user_enabled,
            telemetry_me_level: telemetry.me_level.to_string(),
        },
        upstream: build_zero_upstream_data(stats),
        middle_proxy: ZeroMiddleProxyData {
            keepalive_sent_total: stats.get_me_keepalive_sent(),
            keepalive_failed_total: stats.get_me_keepalive_failed(),
            keepalive_pong_total: stats.get_me_keepalive_pong(),
            keepalive_timeout_total: stats.get_me_keepalive_timeout(),
            rpc_proxy_req_signal_sent_total: stats.get_me_rpc_proxy_req_signal_sent_total(),
            rpc_proxy_req_signal_failed_total: stats.get_me_rpc_proxy_req_signal_failed_total(),
            rpc_proxy_req_signal_skipped_no_meta_total: stats
                .get_me_rpc_proxy_req_signal_skipped_no_meta_total(),
            rpc_proxy_req_signal_response_total: stats.get_me_rpc_proxy_req_signal_response_total(),
            rpc_proxy_req_signal_close_sent_total: stats
                .get_me_rpc_proxy_req_signal_close_sent_total(),
            reconnect_attempt_total: stats.get_me_reconnect_attempts(),
            reconnect_success_total: stats.get_me_reconnect_success(),
            handshake_reject_total: stats.get_me_handshake_reject_total(),
            handshake_error_codes,
            reader_eof_total: stats.get_me_reader_eof_total(),
            idle_close_by_peer_total: stats.get_me_idle_close_by_peer_total(),
            route_drop_no_conn_total: stats.get_me_route_drop_no_conn(),
            route_drop_channel_closed_total: stats.get_me_route_drop_channel_closed(),
            route_drop_queue_full_total: stats.get_me_route_drop_queue_full(),
            route_drop_queue_full_base_total: stats.get_me_route_drop_queue_full_base(),
            route_drop_queue_full_high_total: stats.get_me_route_drop_queue_full_high(),
            d2c_batches_total: stats.get_me_d2c_batches_total(),
            d2c_batch_frames_total: stats.get_me_d2c_batch_frames_total(),
            d2c_batch_bytes_total: stats.get_me_d2c_batch_bytes_total(),
            d2c_flush_reason_queue_drain_total: stats.get_me_d2c_flush_reason_queue_drain_total(),
            d2c_flush_reason_batch_frames_total: stats.get_me_d2c_flush_reason_batch_frames_total(),
            d2c_flush_reason_batch_bytes_total: stats.get_me_d2c_flush_reason_batch_bytes_total(),
            d2c_flush_reason_max_delay_total: stats.get_me_d2c_flush_reason_max_delay_total(),
            d2c_flush_reason_ack_immediate_total: stats
                .get_me_d2c_flush_reason_ack_immediate_total(),
            d2c_flush_reason_close_total: stats.get_me_d2c_flush_reason_close_total(),
            d2c_data_frames_total: stats.get_me_d2c_data_frames_total(),
            d2c_ack_frames_total: stats.get_me_d2c_ack_frames_total(),
            d2c_payload_bytes_total: stats.get_me_d2c_payload_bytes_total(),
            d2c_write_mode_coalesced_total: stats.get_me_d2c_write_mode_coalesced_total(),
            d2c_write_mode_split_total: stats.get_me_d2c_write_mode_split_total(),
            d2c_quota_reject_pre_write_total: stats.get_me_d2c_quota_reject_pre_write_total(),
            d2c_quota_reject_post_write_total: stats.get_me_d2c_quota_reject_post_write_total(),
            d2c_frame_buf_shrink_total: stats.get_me_d2c_frame_buf_shrink_total(),
            d2c_frame_buf_shrink_bytes_total: stats.get_me_d2c_frame_buf_shrink_bytes_total(),
            socks_kdf_strict_reject_total: stats.get_me_socks_kdf_strict_reject(),
            socks_kdf_compat_fallback_total: stats.get_me_socks_kdf_compat_fallback(),
            endpoint_quarantine_total: stats.get_me_endpoint_quarantine_total(),
            kdf_drift_total: stats.get_me_kdf_drift_total(),
            kdf_port_only_drift_total: stats.get_me_kdf_port_only_drift_total(),
            hardswap_pending_reuse_total: stats.get_me_hardswap_pending_reuse_total(),
            hardswap_pending_ttl_expired_total: stats.get_me_hardswap_pending_ttl_expired_total(),
            single_endpoint_outage_enter_total: stats.get_me_single_endpoint_outage_enter_total(),
            single_endpoint_outage_exit_total: stats.get_me_single_endpoint_outage_exit_total(),
            single_endpoint_outage_reconnect_attempt_total: stats
                .get_me_single_endpoint_outage_reconnect_attempt_total(),
            single_endpoint_outage_reconnect_success_total: stats
                .get_me_single_endpoint_outage_reconnect_success_total(),
            single_endpoint_quarantine_bypass_total: stats
                .get_me_single_endpoint_quarantine_bypass_total(),
            single_endpoint_shadow_rotate_total: stats.get_me_single_endpoint_shadow_rotate_total(),
            single_endpoint_shadow_rotate_skipped_quarantine_total: stats
                .get_me_single_endpoint_shadow_rotate_skipped_quarantine_total(),
            floor_mode_switch_total: stats.get_me_floor_mode_switch_total(),
            floor_mode_switch_static_to_adaptive_total: stats
                .get_me_floor_mode_switch_static_to_adaptive_total(),
            floor_mode_switch_adaptive_to_static_total: stats
                .get_me_floor_mode_switch_adaptive_to_static_total(),
        },
        pool: ZeroPoolData {
            pool_swap_total: stats.get_pool_swap_total(),
            pool_drain_active: stats.get_pool_drain_active(),
            pool_force_close_total: stats.get_pool_force_close_total(),
            pool_stale_pick_total: stats.get_pool_stale_pick_total(),
            writer_removed_total: stats.get_me_writer_removed_total(),
            writer_removed_unexpected_total: stats.get_me_writer_removed_unexpected_total(),
            refill_triggered_total: stats.get_me_refill_triggered_total(),
            refill_skipped_inflight_total: stats.get_me_refill_skipped_inflight_total(),
            refill_failed_total: stats.get_me_refill_failed_total(),
            writer_restored_same_endpoint_total: stats.get_me_writer_restored_same_endpoint_total(),
            writer_restored_fallback_total: stats.get_me_writer_restored_fallback_total(),
        },
        desync: ZeroDesyncData {
            secure_padding_invalid_total: stats.get_secure_padding_invalid(),
            desync_total: stats.get_desync_total(),
            desync_full_logged_total: stats.get_desync_full_logged(),
            desync_suppressed_total: stats.get_desync_suppressed(),
            desync_frames_bucket_0: stats.get_desync_frames_bucket_0(),
            desync_frames_bucket_1_2: stats.get_desync_frames_bucket_1_2(),
            desync_frames_bucket_3_10: stats.get_desync_frames_bucket_3_10(),
            desync_frames_bucket_gt_10: stats.get_desync_frames_bucket_gt_10(),
        },
    }
}

fn build_zero_upstream_data(stats: &Stats) -> ZeroUpstreamData {
    ZeroUpstreamData {
        connect_attempt_total: stats.get_upstream_connect_attempt_total(),
        connect_success_total: stats.get_upstream_connect_success_total(),
        connect_fail_total: stats.get_upstream_connect_fail_total(),
        connect_failfast_hard_error_total: stats.get_upstream_connect_failfast_hard_error_total(),
        connect_attempts_bucket_1: stats.get_upstream_connect_attempts_bucket_1(),
        connect_attempts_bucket_2: stats.get_upstream_connect_attempts_bucket_2(),
        connect_attempts_bucket_3_4: stats.get_upstream_connect_attempts_bucket_3_4(),
        connect_attempts_bucket_gt_4: stats.get_upstream_connect_attempts_bucket_gt_4(),
        connect_duration_success_bucket_le_100ms: stats
            .get_upstream_connect_duration_success_bucket_le_100ms(),
        connect_duration_success_bucket_101_500ms: stats
            .get_upstream_connect_duration_success_bucket_101_500ms(),
        connect_duration_success_bucket_501_1000ms: stats
            .get_upstream_connect_duration_success_bucket_501_1000ms(),
        connect_duration_success_bucket_gt_1000ms: stats
            .get_upstream_connect_duration_success_bucket_gt_1000ms(),
        connect_duration_fail_bucket_le_100ms: stats
            .get_upstream_connect_duration_fail_bucket_le_100ms(),
        connect_duration_fail_bucket_101_500ms: stats
            .get_upstream_connect_duration_fail_bucket_101_500ms(),
        connect_duration_fail_bucket_501_1000ms: stats
            .get_upstream_connect_duration_fail_bucket_501_1000ms(),
        connect_duration_fail_bucket_gt_1000ms: stats
            .get_upstream_connect_duration_fail_bucket_gt_1000ms(),
    }
}

pub(super) fn build_upstreams_data(shared: &ApiShared, api_cfg: &ApiConfig) -> UpstreamsData {
    let generated_at_epoch_secs = now_epoch_secs();
    let zero = build_zero_upstream_data(&shared.stats);
    if !api_cfg.minimal_runtime_enabled {
        return UpstreamsData {
            enabled: false,
            reason: Some(FEATURE_DISABLED_REASON),
            generated_at_epoch_secs,
            zero,
            summary: None,
            upstreams: None,
        };
    }

    let Some(snapshot) = shared.upstream_manager.try_api_snapshot() else {
        return UpstreamsData {
            enabled: true,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs,
            zero,
            summary: None,
            upstreams: None,
        };
    };

    let summary = UpstreamSummaryData {
        configured_total: snapshot.summary.configured_total,
        healthy_total: snapshot.summary.healthy_total,
        unhealthy_total: snapshot.summary.unhealthy_total,
        direct_total: snapshot.summary.direct_total,
        socks4_total: snapshot.summary.socks4_total,
        socks5_total: snapshot.summary.socks5_total,
        shadowsocks_total: snapshot.summary.shadowsocks_total,
    };
    let upstreams = snapshot
        .upstreams
        .into_iter()
        .map(|upstream| UpstreamStatus {
            upstream_id: upstream.upstream_id,
            route_kind: map_route_kind(upstream.route_kind),
            address: upstream.address,
            weight: upstream.weight,
            scopes: upstream.scopes,
            healthy: upstream.healthy,
            fails: upstream.fails,
            last_check_age_secs: upstream.last_check_age_secs,
            effective_latency_ms: upstream.effective_latency_ms,
            dc: upstream
                .dc
                .into_iter()
                .map(|dc| UpstreamDcStatus {
                    dc: dc.dc,
                    latency_ema_ms: dc.latency_ema_ms,
                    ip_preference: map_ip_preference(dc.ip_preference),
                })
                .collect(),
        })
        .collect();

    UpstreamsData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs,
        zero,
        summary: Some(summary),
        upstreams: Some(upstreams),
    }
}

pub(super) async fn build_minimal_all_data(
    shared: &ApiShared,
    api_cfg: &ApiConfig,
) -> MinimalAllData {
    let now = now_epoch_secs();
    if !api_cfg.minimal_runtime_enabled {
        return MinimalAllData {
            enabled: false,
            reason: Some(FEATURE_DISABLED_REASON),
            generated_at_epoch_secs: now,
            data: None,
        };
    }

    let Some((generated_at_epoch_secs, payload)) =
        get_minimal_payload_cached(shared, api_cfg.minimal_runtime_cache_ttl_ms).await
    else {
        return MinimalAllData {
            enabled: true,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs: now,
            data: Some(MinimalAllPayload {
                me_writers: disabled_me_writers(now, SOURCE_UNAVAILABLE_REASON),
                dcs: disabled_dcs(now, SOURCE_UNAVAILABLE_REASON),
                me_runtime: None,
                network_path: Vec::new(),
            }),
        };
    };

    MinimalAllData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs,
        data: Some(payload),
    }
}

pub(super) async fn build_me_writers_data(
    shared: &ApiShared,
    api_cfg: &ApiConfig,
) -> MeWritersData {
    let now = now_epoch_secs();
    if !api_cfg.minimal_runtime_enabled {
        return disabled_me_writers(now, FEATURE_DISABLED_REASON);
    }

    let Some((_, payload)) =
        get_minimal_payload_cached(shared, api_cfg.minimal_runtime_cache_ttl_ms).await
    else {
        return disabled_me_writers(now, SOURCE_UNAVAILABLE_REASON);
    };
    payload.me_writers
}

pub(super) async fn build_dcs_data(shared: &ApiShared, api_cfg: &ApiConfig) -> DcStatusData {
    let now = now_epoch_secs();
    if !api_cfg.minimal_runtime_enabled {
        return disabled_dcs(now, FEATURE_DISABLED_REASON);
    }

    let Some((_, payload)) =
        get_minimal_payload_cached(shared, api_cfg.minimal_runtime_cache_ttl_ms).await
    else {
        return disabled_dcs(now, SOURCE_UNAVAILABLE_REASON);
    };
    payload.dcs
}

async fn get_minimal_payload_cached(
    shared: &ApiShared,
    cache_ttl_ms: u64,
) -> Option<(u64, MinimalAllPayload)> {
    if cache_ttl_ms > 0 {
        let now = Instant::now();
        let cached = shared.minimal_cache.lock().await.clone();
        if let Some(entry) = cached
            && now < entry.expires_at
        {
            return Some((entry.generated_at_epoch_secs, entry.payload));
        }
    }

    let pool = shared.me_pool.read().await.clone()?;
    let status = pool.api_status_snapshot().await;
    let runtime = pool.api_runtime_snapshot().await;
    let generated_at_epoch_secs = status.generated_at_epoch_secs;

    let me_writers = MeWritersData {
        middle_proxy_enabled: true,
        reason: None,
        generated_at_epoch_secs,
        summary: MeWritersSummary {
            configured_dc_groups: status.configured_dc_groups,
            configured_endpoints: status.configured_endpoints,
            available_endpoints: status.available_endpoints,
            available_pct: status.available_pct,
            required_writers: status.required_writers,
            alive_writers: status.alive_writers,
            coverage_pct: status.coverage_pct,
            fresh_alive_writers: status.fresh_alive_writers,
            fresh_coverage_pct: status.fresh_coverage_pct,
        },
        writers: status
            .writers
            .into_iter()
            .map(|entry| MeWriterStatus {
                writer_id: entry.writer_id,
                dc: entry.dc,
                endpoint: entry.endpoint.to_string(),
                generation: entry.generation,
                state: entry.state,
                draining: entry.draining,
                degraded: entry.degraded,
                bound_clients: entry.bound_clients,
                idle_for_secs: entry.idle_for_secs,
                rtt_ema_ms: entry.rtt_ema_ms,
                matches_active_generation: entry.matches_active_generation,
                in_desired_map: entry.in_desired_map,
                allow_drain_fallback: entry.allow_drain_fallback,
                drain_started_at_epoch_secs: entry.drain_started_at_epoch_secs,
                drain_deadline_epoch_secs: entry.drain_deadline_epoch_secs,
                drain_over_ttl: entry.drain_over_ttl,
            })
            .collect(),
    };
    let dcs = DcStatusData {
        middle_proxy_enabled: true,
        reason: None,
        generated_at_epoch_secs,
        dcs: status
            .dcs
            .into_iter()
            .map(|entry| DcStatus {
                dc: entry.dc,
                endpoints: entry
                    .endpoints
                    .into_iter()
                    .map(|value| value.to_string())
                    .collect(),
                endpoint_writers: entry
                    .endpoint_writers
                    .into_iter()
                    .map(|coverage| DcEndpointWriters {
                        endpoint: coverage.endpoint.to_string(),
                        active_writers: coverage.active_writers,
                    })
                    .collect(),
                available_endpoints: entry.available_endpoints,
                available_pct: entry.available_pct,
                required_writers: entry.required_writers,
                floor_min: entry.floor_min,
                floor_target: entry.floor_target,
                floor_max: entry.floor_max,
                floor_capped: entry.floor_capped,
                alive_writers: entry.alive_writers,
                coverage_pct: entry.coverage_pct,
                fresh_alive_writers: entry.fresh_alive_writers,
                fresh_coverage_pct: entry.fresh_coverage_pct,
                rtt_ms: entry.rtt_ms,
                load: entry.load,
            })
            .collect(),
    };
    let me_runtime = MinimalMeRuntimeData {
        active_generation: runtime.active_generation,
        warm_generation: runtime.warm_generation,
        pending_hardswap_generation: runtime.pending_hardswap_generation,
        pending_hardswap_age_secs: runtime.pending_hardswap_age_secs,
        hardswap_enabled: runtime.hardswap_enabled,
        floor_mode: runtime.floor_mode,
        adaptive_floor_idle_secs: runtime.adaptive_floor_idle_secs,
        adaptive_floor_min_writers_single_endpoint: runtime
            .adaptive_floor_min_writers_single_endpoint,
        adaptive_floor_min_writers_multi_endpoint: runtime
            .adaptive_floor_min_writers_multi_endpoint,
        adaptive_floor_recover_grace_secs: runtime.adaptive_floor_recover_grace_secs,
        adaptive_floor_writers_per_core_total: runtime.adaptive_floor_writers_per_core_total,
        adaptive_floor_cpu_cores_override: runtime.adaptive_floor_cpu_cores_override,
        adaptive_floor_max_extra_writers_single_per_core: runtime
            .adaptive_floor_max_extra_writers_single_per_core,
        adaptive_floor_max_extra_writers_multi_per_core: runtime
            .adaptive_floor_max_extra_writers_multi_per_core,
        adaptive_floor_max_active_writers_per_core: runtime
            .adaptive_floor_max_active_writers_per_core,
        adaptive_floor_max_warm_writers_per_core: runtime.adaptive_floor_max_warm_writers_per_core,
        adaptive_floor_max_active_writers_global: runtime.adaptive_floor_max_active_writers_global,
        adaptive_floor_max_warm_writers_global: runtime.adaptive_floor_max_warm_writers_global,
        adaptive_floor_cpu_cores_detected: runtime.adaptive_floor_cpu_cores_detected,
        adaptive_floor_cpu_cores_effective: runtime.adaptive_floor_cpu_cores_effective,
        adaptive_floor_global_cap_raw: runtime.adaptive_floor_global_cap_raw,
        adaptive_floor_global_cap_effective: runtime.adaptive_floor_global_cap_effective,
        adaptive_floor_target_writers_total: runtime.adaptive_floor_target_writers_total,
        adaptive_floor_active_cap_configured: runtime.adaptive_floor_active_cap_configured,
        adaptive_floor_active_cap_effective: runtime.adaptive_floor_active_cap_effective,
        adaptive_floor_warm_cap_configured: runtime.adaptive_floor_warm_cap_configured,
        adaptive_floor_warm_cap_effective: runtime.adaptive_floor_warm_cap_effective,
        adaptive_floor_active_writers_current: runtime.adaptive_floor_active_writers_current,
        adaptive_floor_warm_writers_current: runtime.adaptive_floor_warm_writers_current,
        me_keepalive_enabled: runtime.me_keepalive_enabled,
        me_keepalive_interval_secs: runtime.me_keepalive_interval_secs,
        me_keepalive_jitter_secs: runtime.me_keepalive_jitter_secs,
        me_keepalive_payload_random: runtime.me_keepalive_payload_random,
        rpc_proxy_req_every_secs: runtime.rpc_proxy_req_every_secs,
        me_reconnect_max_concurrent_per_dc: runtime.me_reconnect_max_concurrent_per_dc,
        me_reconnect_backoff_base_ms: runtime.me_reconnect_backoff_base_ms,
        me_reconnect_backoff_cap_ms: runtime.me_reconnect_backoff_cap_ms,
        me_reconnect_fast_retry_count: runtime.me_reconnect_fast_retry_count,
        me_pool_drain_ttl_secs: runtime.me_pool_drain_ttl_secs,
        me_pool_force_close_secs: runtime.me_pool_force_close_secs,
        me_pool_min_fresh_ratio: runtime.me_pool_min_fresh_ratio,
        me_bind_stale_mode: runtime.me_bind_stale_mode,
        me_bind_stale_ttl_secs: runtime.me_bind_stale_ttl_secs,
        me_single_endpoint_shadow_writers: runtime.me_single_endpoint_shadow_writers,
        me_single_endpoint_outage_mode_enabled: runtime.me_single_endpoint_outage_mode_enabled,
        me_single_endpoint_outage_disable_quarantine: runtime
            .me_single_endpoint_outage_disable_quarantine,
        me_single_endpoint_outage_backoff_min_ms: runtime.me_single_endpoint_outage_backoff_min_ms,
        me_single_endpoint_outage_backoff_max_ms: runtime.me_single_endpoint_outage_backoff_max_ms,
        me_single_endpoint_shadow_rotate_every_secs: runtime
            .me_single_endpoint_shadow_rotate_every_secs,
        me_deterministic_writer_sort: runtime.me_deterministic_writer_sort,
        me_writer_pick_mode: runtime.me_writer_pick_mode,
        me_writer_pick_sample_size: runtime.me_writer_pick_sample_size,
        me_socks_kdf_policy: runtime.me_socks_kdf_policy,
        quarantined_endpoints_total: runtime.quarantined_endpoints.len(),
        quarantined_endpoints: runtime
            .quarantined_endpoints
            .into_iter()
            .map(|entry| MinimalQuarantineData {
                endpoint: entry.endpoint.to_string(),
                remaining_ms: entry.remaining_ms,
            })
            .collect(),
    };
    let network_path = runtime
        .network_path
        .into_iter()
        .map(|entry| MinimalDcPathData {
            dc: entry.dc,
            ip_preference: entry.ip_preference,
            selected_addr_v4: entry.selected_addr_v4.map(|value| value.to_string()),
            selected_addr_v6: entry.selected_addr_v6.map(|value| value.to_string()),
        })
        .collect();

    let payload = MinimalAllPayload {
        me_writers,
        dcs,
        me_runtime: Some(me_runtime),
        network_path,
    };

    if cache_ttl_ms > 0 {
        let entry = MinimalCacheEntry {
            expires_at: Instant::now() + Duration::from_millis(cache_ttl_ms),
            payload: payload.clone(),
            generated_at_epoch_secs,
        };
        *shared.minimal_cache.lock().await = Some(entry);
    }

    Some((generated_at_epoch_secs, payload))
}

fn disabled_me_writers(now_epoch_secs: u64, reason: &'static str) -> MeWritersData {
    MeWritersData {
        middle_proxy_enabled: false,
        reason: Some(reason),
        generated_at_epoch_secs: now_epoch_secs,
        summary: MeWritersSummary {
            configured_dc_groups: 0,
            configured_endpoints: 0,
            available_endpoints: 0,
            available_pct: 0.0,
            required_writers: 0,
            alive_writers: 0,
            coverage_pct: 0.0,
            fresh_alive_writers: 0,
            fresh_coverage_pct: 0.0,
        },
        writers: Vec::new(),
    }
}

fn disabled_dcs(now_epoch_secs: u64, reason: &'static str) -> DcStatusData {
    DcStatusData {
        middle_proxy_enabled: false,
        reason: Some(reason),
        generated_at_epoch_secs: now_epoch_secs,
        dcs: Vec::new(),
    }
}

fn map_route_kind(value: UpstreamRouteKind) -> &'static str {
    match value {
        UpstreamRouteKind::Direct => "direct",
        UpstreamRouteKind::Socks4 => "socks4",
        UpstreamRouteKind::Socks5 => "socks5",
        UpstreamRouteKind::Shadowsocks => "shadowsocks",
    }
}

fn map_ip_preference(value: IpPreference) -> &'static str {
    match value {
        IpPreference::Unknown => "unknown",
        IpPreference::PreferV6 => "prefer_v6",
        IpPreference::PreferV4 => "prefer_v4",
        IpPreference::BothWork => "both_work",
        IpPreference::Unavailable => "unavailable",
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
