use super::*;

fn resolve_default_link_port(cfg: &ProxyConfig) -> u16 {
    cfg.server
        .listeners
        .first()
        .and_then(|listener| listener.port)
        .unwrap_or(cfg.server.port)
}

fn resolve_link_host(
    cfg: &ProxyConfig,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) -> String {
    if let Some(ref h) = cfg.general.links.public_host {
        return h.clone();
    }
    detected_ip_v4
        .or(detected_ip_v6)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| {
            warn!(
                "config reload: could not determine public IP for proxy links. \
                 Set [general.links] public_host in config."
            );
            "UNKNOWN".to_string()
        })
}

/// Print TG proxy links for a single user — mirrors print_proxy_links() in main.rs.
fn print_user_links(user: &str, secret: &str, host: &str, port: u16, cfg: &ProxyConfig) {
    info!(target: "telemt::links", "--- New user: {} ---", user);
    if cfg.general.modes.classic {
        info!(
            target: "telemt::links",
            "  Classic: tg://proxy?server={}&port={}&secret={}",
            host, port, secret
        );
    }
    if cfg.general.modes.secure {
        info!(
            target: "telemt::links",
            "  DD:      tg://proxy?server={}&port={}&secret=dd{}",
            host, port, secret
        );
    }
    if cfg.general.modes.tls {
        let mut domains = vec![cfg.censorship.tls_domain.clone()];
        for d in &cfg.censorship.tls_domains {
            if !domains.contains(d) {
                domains.push(d.clone());
            }
        }
        for domain in &domains {
            let domain_hex = hex::encode(domain.as_bytes());
            info!(
                target: "telemt::links",
                "  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                host, port, secret, domain_hex
            );
        }
    }
    info!(target: "telemt::links", "--------------------");
}

/// Log all detected changes and emit TG links for new users.
pub(super) fn log_changes(
    old_hot: &HotFields,
    new_hot: &HotFields,
    new_cfg: &ProxyConfig,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) {
    if old_hot.log_level != new_hot.log_level {
        info!(
            "config reload: log_level: '{}' → '{}'",
            old_hot.log_level, new_hot.log_level
        );
        log_tx.send(new_hot.log_level.clone()).ok();
    }

    if old_hot.user_ad_tags != new_hot.user_ad_tags {
        info!(
            "config reload: user_ad_tags updated ({} entries)",
            new_hot.user_ad_tags.len(),
        );
    }

    if old_hot.ad_tag != new_hot.ad_tag {
        info!("config reload: general.ad_tag updated (applied on next connection)");
    }

    if old_hot.dns_overrides != new_hot.dns_overrides {
        info!(
            "config reload: network.dns_overrides updated ({} entries)",
            new_hot.dns_overrides.len()
        );
    }

    if old_hot.desync_all_full != new_hot.desync_all_full {
        info!(
            "config reload: desync_all_full: {} → {}",
            old_hot.desync_all_full, new_hot.desync_all_full,
        );
    }

    if old_hot.update_every_secs != new_hot.update_every_secs {
        info!(
            "config reload: update_every(effective): {}s → {}s",
            old_hot.update_every_secs, new_hot.update_every_secs,
        );
    }
    if old_hot.me_reinit_every_secs != new_hot.me_reinit_every_secs
        || old_hot.me_reinit_singleflight != new_hot.me_reinit_singleflight
        || old_hot.me_reinit_max_concurrency != new_hot.me_reinit_max_concurrency
        || old_hot.me_reinit_coalesce_window_ms != new_hot.me_reinit_coalesce_window_ms
    {
        info!(
            "config reload: me_reinit: interval={}s singleflight={} max_concurrency={} coalesce={}ms",
            new_hot.me_reinit_every_secs,
            new_hot.me_reinit_singleflight,
            new_hot.me_reinit_max_concurrency,
            new_hot.me_reinit_coalesce_window_ms
        );
    }

    if old_hot.hardswap != new_hot.hardswap {
        info!(
            "config reload: hardswap: {} → {}",
            old_hot.hardswap, new_hot.hardswap,
        );
    }

    if old_hot.me_pool_drain_ttl_secs != new_hot.me_pool_drain_ttl_secs {
        info!(
            "config reload: me_pool_drain_ttl_secs: {}s → {}s",
            old_hot.me_pool_drain_ttl_secs, new_hot.me_pool_drain_ttl_secs,
        );
    }
    if old_hot.me_instadrain != new_hot.me_instadrain {
        info!(
            "config reload: me_instadrain: {} → {}",
            old_hot.me_instadrain, new_hot.me_instadrain,
        );
    }

    if old_hot.me_pool_drain_threshold != new_hot.me_pool_drain_threshold {
        info!(
            "config reload: me_pool_drain_threshold: {} → {}",
            old_hot.me_pool_drain_threshold, new_hot.me_pool_drain_threshold,
        );
    }

    if (old_hot.me_pool_min_fresh_ratio - new_hot.me_pool_min_fresh_ratio).abs() > f32::EPSILON {
        info!(
            "config reload: me_pool_min_fresh_ratio: {:.3} → {:.3}",
            old_hot.me_pool_min_fresh_ratio, new_hot.me_pool_min_fresh_ratio,
        );
    }

    if old_hot.me_reinit_drain_timeout_secs != new_hot.me_reinit_drain_timeout_secs {
        info!(
            "config reload: me_reinit_drain_timeout_secs: {}s → {}s",
            old_hot.me_reinit_drain_timeout_secs, new_hot.me_reinit_drain_timeout_secs,
        );
    }
    if old_hot.me_hardswap_warmup_delay_min_ms != new_hot.me_hardswap_warmup_delay_min_ms
        || old_hot.me_hardswap_warmup_delay_max_ms != new_hot.me_hardswap_warmup_delay_max_ms
        || old_hot.me_hardswap_warmup_extra_passes != new_hot.me_hardswap_warmup_extra_passes
        || old_hot.me_hardswap_warmup_pass_backoff_base_ms
            != new_hot.me_hardswap_warmup_pass_backoff_base_ms
    {
        info!(
            "config reload: me_hardswap_warmup: min={}ms max={}ms extra_passes={} pass_backoff={}ms",
            new_hot.me_hardswap_warmup_delay_min_ms,
            new_hot.me_hardswap_warmup_delay_max_ms,
            new_hot.me_hardswap_warmup_extra_passes,
            new_hot.me_hardswap_warmup_pass_backoff_base_ms
        );
    }
    if old_hot.me_bind_stale_mode != new_hot.me_bind_stale_mode
        || old_hot.me_bind_stale_ttl_secs != new_hot.me_bind_stale_ttl_secs
    {
        info!(
            "config reload: me_bind_stale: mode={:?} ttl={}s",
            new_hot.me_bind_stale_mode, new_hot.me_bind_stale_ttl_secs
        );
    }
    if old_hot.me_secret_atomic_snapshot != new_hot.me_secret_atomic_snapshot
        || old_hot.me_deterministic_writer_sort != new_hot.me_deterministic_writer_sort
        || old_hot.me_writer_pick_mode != new_hot.me_writer_pick_mode
        || old_hot.me_writer_pick_sample_size != new_hot.me_writer_pick_sample_size
    {
        info!(
            "config reload: me_runtime_flags: secret_atomic_snapshot={} deterministic_sort={} writer_pick_mode={:?} writer_pick_sample_size={}",
            new_hot.me_secret_atomic_snapshot,
            new_hot.me_deterministic_writer_sort,
            new_hot.me_writer_pick_mode,
            new_hot.me_writer_pick_sample_size,
        );
    }
    if old_hot.me_single_endpoint_shadow_writers != new_hot.me_single_endpoint_shadow_writers
        || old_hot.me_single_endpoint_outage_mode_enabled
            != new_hot.me_single_endpoint_outage_mode_enabled
        || old_hot.me_single_endpoint_outage_disable_quarantine
            != new_hot.me_single_endpoint_outage_disable_quarantine
        || old_hot.me_single_endpoint_outage_backoff_min_ms
            != new_hot.me_single_endpoint_outage_backoff_min_ms
        || old_hot.me_single_endpoint_outage_backoff_max_ms
            != new_hot.me_single_endpoint_outage_backoff_max_ms
        || old_hot.me_single_endpoint_shadow_rotate_every_secs
            != new_hot.me_single_endpoint_shadow_rotate_every_secs
    {
        info!(
            "config reload: me_single_endpoint: shadow={} outage_enabled={} disable_quarantine={} backoff=[{}..{}]ms rotate={}s",
            new_hot.me_single_endpoint_shadow_writers,
            new_hot.me_single_endpoint_outage_mode_enabled,
            new_hot.me_single_endpoint_outage_disable_quarantine,
            new_hot.me_single_endpoint_outage_backoff_min_ms,
            new_hot.me_single_endpoint_outage_backoff_max_ms,
            new_hot.me_single_endpoint_shadow_rotate_every_secs
        );
    }
    if old_hot.me_config_stable_snapshots != new_hot.me_config_stable_snapshots
        || old_hot.me_config_apply_cooldown_secs != new_hot.me_config_apply_cooldown_secs
        || old_hot.me_snapshot_require_http_2xx != new_hot.me_snapshot_require_http_2xx
        || old_hot.me_snapshot_reject_empty_map != new_hot.me_snapshot_reject_empty_map
        || old_hot.me_snapshot_min_proxy_for_lines != new_hot.me_snapshot_min_proxy_for_lines
    {
        info!(
            "config reload: me_snapshot_guard: stable={} cooldown={}s require_2xx={} reject_empty={} min_proxy_for={}",
            new_hot.me_config_stable_snapshots,
            new_hot.me_config_apply_cooldown_secs,
            new_hot.me_snapshot_require_http_2xx,
            new_hot.me_snapshot_reject_empty_map,
            new_hot.me_snapshot_min_proxy_for_lines
        );
    }
    if old_hot.proxy_secret_stable_snapshots != new_hot.proxy_secret_stable_snapshots
        || old_hot.proxy_secret_rotate_runtime != new_hot.proxy_secret_rotate_runtime
        || old_hot.proxy_secret_len_max != new_hot.proxy_secret_len_max
    {
        info!(
            "config reload: proxy_secret_runtime: stable={} rotate={} len_max={}",
            new_hot.proxy_secret_stable_snapshots,
            new_hot.proxy_secret_rotate_runtime,
            new_hot.proxy_secret_len_max
        );
    }

    if old_hot.telemetry_core_enabled != new_hot.telemetry_core_enabled
        || old_hot.telemetry_user_enabled != new_hot.telemetry_user_enabled
        || old_hot.telemetry_me_level != new_hot.telemetry_me_level
    {
        info!(
            "config reload: telemetry: core_enabled={} user_enabled={} me_level={}",
            new_hot.telemetry_core_enabled,
            new_hot.telemetry_user_enabled,
            new_hot.telemetry_me_level,
        );
    }

    if old_hot.me_socks_kdf_policy != new_hot.me_socks_kdf_policy {
        info!(
            "config reload: me_socks_kdf_policy: {:?} → {:?}",
            old_hot.me_socks_kdf_policy, new_hot.me_socks_kdf_policy,
        );
    }

    if old_hot.me_floor_mode != new_hot.me_floor_mode
        || old_hot.me_adaptive_floor_idle_secs != new_hot.me_adaptive_floor_idle_secs
        || old_hot.me_adaptive_floor_min_writers_single_endpoint
            != new_hot.me_adaptive_floor_min_writers_single_endpoint
        || old_hot.me_adaptive_floor_min_writers_multi_endpoint
            != new_hot.me_adaptive_floor_min_writers_multi_endpoint
        || old_hot.me_adaptive_floor_recover_grace_secs
            != new_hot.me_adaptive_floor_recover_grace_secs
        || old_hot.me_adaptive_floor_writers_per_core_total
            != new_hot.me_adaptive_floor_writers_per_core_total
        || old_hot.me_adaptive_floor_cpu_cores_override
            != new_hot.me_adaptive_floor_cpu_cores_override
        || old_hot.me_adaptive_floor_max_extra_writers_single_per_core
            != new_hot.me_adaptive_floor_max_extra_writers_single_per_core
        || old_hot.me_adaptive_floor_max_extra_writers_multi_per_core
            != new_hot.me_adaptive_floor_max_extra_writers_multi_per_core
        || old_hot.me_adaptive_floor_max_active_writers_per_core
            != new_hot.me_adaptive_floor_max_active_writers_per_core
        || old_hot.me_adaptive_floor_max_warm_writers_per_core
            != new_hot.me_adaptive_floor_max_warm_writers_per_core
        || old_hot.me_adaptive_floor_max_active_writers_global
            != new_hot.me_adaptive_floor_max_active_writers_global
        || old_hot.me_adaptive_floor_max_warm_writers_global
            != new_hot.me_adaptive_floor_max_warm_writers_global
    {
        info!(
            "config reload: me_floor: mode={:?} idle={}s min_single={} min_multi={} recover_grace={}s per_core_total={} cores_override={} extra_single_per_core={} extra_multi_per_core={} max_active_per_core={} max_warm_per_core={} max_active_global={} max_warm_global={}",
            new_hot.me_floor_mode,
            new_hot.me_adaptive_floor_idle_secs,
            new_hot.me_adaptive_floor_min_writers_single_endpoint,
            new_hot.me_adaptive_floor_min_writers_multi_endpoint,
            new_hot.me_adaptive_floor_recover_grace_secs,
            new_hot.me_adaptive_floor_writers_per_core_total,
            new_hot.me_adaptive_floor_cpu_cores_override,
            new_hot.me_adaptive_floor_max_extra_writers_single_per_core,
            new_hot.me_adaptive_floor_max_extra_writers_multi_per_core,
            new_hot.me_adaptive_floor_max_active_writers_per_core,
            new_hot.me_adaptive_floor_max_warm_writers_per_core,
            new_hot.me_adaptive_floor_max_active_writers_global,
            new_hot.me_adaptive_floor_max_warm_writers_global,
        );
    }

    if old_hot.me_route_backpressure_base_timeout_ms
        != new_hot.me_route_backpressure_base_timeout_ms
        || old_hot.me_route_backpressure_high_timeout_ms
            != new_hot.me_route_backpressure_high_timeout_ms
        || old_hot.me_route_backpressure_high_watermark_pct
            != new_hot.me_route_backpressure_high_watermark_pct
        || old_hot.me_route_backpressure_enabled != new_hot.me_route_backpressure_enabled
        || old_hot.me_route_fairshare_enabled != new_hot.me_route_fairshare_enabled
        || old_hot.me_reader_route_data_wait_ms != new_hot.me_reader_route_data_wait_ms
        || old_hot.me_health_interval_ms_unhealthy != new_hot.me_health_interval_ms_unhealthy
        || old_hot.me_health_interval_ms_healthy != new_hot.me_health_interval_ms_healthy
        || old_hot.me_admission_poll_ms != new_hot.me_admission_poll_ms
        || old_hot.me_warn_rate_limit_ms != new_hot.me_warn_rate_limit_ms
    {
        info!(
            "config reload: me_route_backpressure: enabled={} base={}ms high={}ms watermark={}%; me_route_fairshare_enabled={}; me_reader_route_data_wait_ms={}; me_health_interval: unhealthy={}ms healthy={}ms; me_admission_poll={}ms; me_warn_rate_limit={}ms",
            new_hot.me_route_backpressure_enabled,
            new_hot.me_route_backpressure_base_timeout_ms,
            new_hot.me_route_backpressure_high_timeout_ms,
            new_hot.me_route_backpressure_high_watermark_pct,
            new_hot.me_route_fairshare_enabled,
            new_hot.me_reader_route_data_wait_ms,
            new_hot.me_health_interval_ms_unhealthy,
            new_hot.me_health_interval_ms_healthy,
            new_hot.me_admission_poll_ms,
            new_hot.me_warn_rate_limit_ms,
        );
    }

    if old_hot.me_d2c_flush_batch_max_frames != new_hot.me_d2c_flush_batch_max_frames
        || old_hot.me_d2c_flush_batch_max_bytes != new_hot.me_d2c_flush_batch_max_bytes
        || old_hot.me_d2c_flush_batch_max_delay_us != new_hot.me_d2c_flush_batch_max_delay_us
        || old_hot.me_d2c_ack_flush_immediate != new_hot.me_d2c_ack_flush_immediate
        || old_hot.me_quota_soft_overshoot_bytes != new_hot.me_quota_soft_overshoot_bytes
        || old_hot.me_d2c_frame_buf_shrink_threshold_bytes
            != new_hot.me_d2c_frame_buf_shrink_threshold_bytes
        || old_hot.direct_relay_copy_buf_c2s_bytes != new_hot.direct_relay_copy_buf_c2s_bytes
        || old_hot.direct_relay_copy_buf_s2c_bytes != new_hot.direct_relay_copy_buf_s2c_bytes
    {
        info!(
            "config reload: relay_tuning: me_d2c_frames={} me_d2c_bytes={} me_d2c_delay_us={} me_ack_flush_immediate={} me_quota_soft_overshoot_bytes={} me_d2c_frame_buf_shrink_threshold_bytes={} direct_buf_c2s={} direct_buf_s2c={}",
            new_hot.me_d2c_flush_batch_max_frames,
            new_hot.me_d2c_flush_batch_max_bytes,
            new_hot.me_d2c_flush_batch_max_delay_us,
            new_hot.me_d2c_ack_flush_immediate,
            new_hot.me_quota_soft_overshoot_bytes,
            new_hot.me_d2c_frame_buf_shrink_threshold_bytes,
            new_hot.direct_relay_copy_buf_c2s_bytes,
            new_hot.direct_relay_copy_buf_s2c_bytes,
        );
    }

    if old_hot.users != new_hot.users {
        let mut added: Vec<&String> = new_hot
            .users
            .keys()
            .filter(|u| !old_hot.users.contains_key(*u))
            .collect();
        added.sort();

        let mut removed: Vec<&String> = old_hot
            .users
            .keys()
            .filter(|u| !new_hot.users.contains_key(*u))
            .collect();
        removed.sort();

        let mut changed: Vec<&String> = new_hot
            .users
            .keys()
            .filter(|u| {
                old_hot
                    .users
                    .get(*u)
                    .map(|s| s != &new_hot.users[*u])
                    .unwrap_or(false)
            })
            .collect();
        changed.sort();

        if !added.is_empty() {
            info!(
                "config reload: users added: [{}]",
                added
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let host = resolve_link_host(new_cfg, detected_ip_v4, detected_ip_v6);
            let port = new_cfg
                .general
                .links
                .public_port
                .unwrap_or(resolve_default_link_port(new_cfg));
            for user in &added {
                if let Some(secret) = new_hot.users.get(*user) {
                    print_user_links(user, secret, &host, port, new_cfg);
                }
            }
        }
        if !removed.is_empty() {
            info!(
                "config reload: users removed: [{}]",
                removed
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !changed.is_empty() {
            info!(
                "config reload: users secret changed: [{}]",
                changed
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    if old_hot.user_enabled != new_hot.user_enabled {
        info!(
            "config reload: user_enabled updated ({} disabled overrides)",
            new_hot
                .user_enabled
                .values()
                .filter(|enabled| !**enabled)
                .count()
        );
    }
    if old_hot.user_max_tcp_conns != new_hot.user_max_tcp_conns {
        info!(
            "config reload: user_max_tcp_conns updated ({} entries)",
            new_hot.user_max_tcp_conns.len()
        );
    }
    if old_hot.user_max_tcp_conns_global_each != new_hot.user_max_tcp_conns_global_each {
        info!(
            "config reload: user_max_tcp_conns policy global_each={}",
            new_hot.user_max_tcp_conns_global_each
        );
    }
    if old_hot.user_expirations != new_hot.user_expirations {
        info!(
            "config reload: user_expirations updated ({} entries)",
            new_hot.user_expirations.len()
        );
    }
    if old_hot.user_data_quota != new_hot.user_data_quota {
        info!(
            "config reload: user_data_quota updated ({} entries)",
            new_hot.user_data_quota.len()
        );
    }
    if old_hot.user_rate_limits != new_hot.user_rate_limits {
        info!(
            "config reload: user_rate_limits updated ({} entries)",
            new_hot.user_rate_limits.len()
        );
    }
    if old_hot.cidr_rate_limits != new_hot.cidr_rate_limits {
        info!(
            "config reload: cidr_rate_limits updated ({} entries)",
            new_hot.cidr_rate_limits.len()
        );
    }
    if old_hot.user_max_unique_ips != new_hot.user_max_unique_ips {
        info!(
            "config reload: user_max_unique_ips updated ({} entries)",
            new_hot.user_max_unique_ips.len()
        );
    }
    if old_hot.user_max_unique_ips_global_each != new_hot.user_max_unique_ips_global_each
        || old_hot.user_max_unique_ips_mode != new_hot.user_max_unique_ips_mode
        || old_hot.user_max_unique_ips_window_secs != new_hot.user_max_unique_ips_window_secs
    {
        info!(
            "config reload: user_max_unique_ips policy global_each={} mode={:?} window={}s",
            new_hot.user_max_unique_ips_global_each,
            new_hot.user_max_unique_ips_mode,
            new_hot.user_max_unique_ips_window_secs
        );
    }
    if old_hot.web_debug != new_hot.web_debug {
        info!(
            "config reload: web.debug updated: enabled={} body_capture={:?} window={}..={}s",
            new_hot.web_debug.enabled,
            new_hot.web_debug.body_capture,
            new_hot.web_debug.default_window_secs,
            new_hot.web_debug.max_window_secs,
        );
    }
}
