use super::*;

fn canonicalize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<(String, serde_json::Value)> =
                std::mem::take(map).into_iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, item) in pairs.iter_mut() {
                canonicalize_json(item);
            }
            for (key, item) in pairs {
                map.insert(key, item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize_json(item);
            }
        }
        _ => {}
    }
}

pub(super) fn config_equal(lhs: &ProxyConfig, rhs: &ProxyConfig) -> bool {
    let mut left = match serde_json::to_value(lhs) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut right = match serde_json::to_value(rhs) {
        Ok(value) => value,
        Err(_) => return false,
    };
    canonicalize_json(&mut left);
    canonicalize_json(&mut right);
    left == right
}

fn listeners_equal(
    lhs: &[crate::config::ListenerConfig],
    rhs: &[crate::config::ListenerConfig],
) -> bool {
    serde_json::to_value(lhs).ok() == serde_json::to_value(rhs).ok()
}

/// Warns when the requested snapshot contains fields that require restart.
pub(super) fn warn_non_hot_changes(old: &ProxyConfig, new: &ProxyConfig, non_hot_changed: bool) {
    let mut warned = false;
    if old.server.port != new.server.port {
        warned = true;
        warn!(
            "config reload: server.port changed ({} → {}); restart required",
            old.server.port, new.server.port
        );
    }
    if old.server.api.enabled != new.server.api.enabled
        || old.server.api.listen != new.server.api.listen
        || old.server.api.whitelist != new.server.api.whitelist
        || old.server.api.gray_action != new.server.api.gray_action
        || old.server.api.auth_header != new.server.api.auth_header
        || old.server.api.request_body_limit_bytes != new.server.api.request_body_limit_bytes
        || old.server.api.minimal_runtime_enabled != new.server.api.minimal_runtime_enabled
        || old.server.api.minimal_runtime_cache_ttl_ms
            != new.server.api.minimal_runtime_cache_ttl_ms
        || old.server.api.runtime_edge_enabled != new.server.api.runtime_edge_enabled
        || old.server.api.runtime_edge_cache_ttl_ms != new.server.api.runtime_edge_cache_ttl_ms
        || old.server.api.runtime_edge_top_n != new.server.api.runtime_edge_top_n
        || old.server.api.runtime_edge_events_capacity
            != new.server.api.runtime_edge_events_capacity
        || old.server.api.read_only != new.server.api.read_only
    {
        warned = true;
        warn!("config reload: server.api changed; restart required");
    }
    if old.server.proxy_protocol != new.server.proxy_protocol
        || !listeners_equal(&old.server.listeners, &new.server.listeners)
        || old.server.listen_backlog != new.server.listen_backlog
        || old.server.listen_addr_ipv4 != new.server.listen_addr_ipv4
        || old.server.listen_addr_ipv6 != new.server.listen_addr_ipv6
        || old.server.listen_tcp != new.server.listen_tcp
        || old.server.client_mss != new.server.client_mss
        || old.server.listen_unix_sock != new.server.listen_unix_sock
        || old.server.listen_unix_sock_perm != new.server.listen_unix_sock_perm
    {
        warned = true;
        warn!("config reload: server listener settings changed; restart required");
    }
    if old.web.allow_wildcard_hosts != new.web.allow_wildcard_hosts {
        warned = true;
        warn!("config reload: web.allow_wildcard_hosts changed; restart required");
    }
    if old.web.decoy_fasttrack_mode != new.web.decoy_fasttrack_mode {
        warned = true;
        warn!("config reload: web.decoy_fasttrack_mode changed; restart required");
    }
    if old.censorship.tls_domain != new.censorship.tls_domain
        || old.censorship.tls_domains != new.censorship.tls_domains
        || old.censorship.tls_fetch_scope != new.censorship.tls_fetch_scope
        || old.censorship.mask != new.censorship.mask
        || old.censorship.mask_dynamic != new.censorship.mask_dynamic
        || old.censorship.mask_host != new.censorship.mask_host
        || old.censorship.mask_port != new.censorship.mask_port
        || old.censorship.exclusive_mask != new.censorship.exclusive_mask
        || old.censorship.mask_unix_sock != new.censorship.mask_unix_sock
        || old.censorship.fake_cert_len != new.censorship.fake_cert_len
        || old.censorship.tls_emulation != new.censorship.tls_emulation
        || old.censorship.tls_front_dir != new.censorship.tls_front_dir
        || old.censorship.server_hello_delay_min_ms != new.censorship.server_hello_delay_min_ms
        || old.censorship.server_hello_delay_max_ms != new.censorship.server_hello_delay_max_ms
        || old.censorship.tls_new_session_tickets != new.censorship.tls_new_session_tickets
        || old.censorship.serverhello_compact != new.censorship.serverhello_compact
        || old.censorship.tls_full_cert_ttl_secs != new.censorship.tls_full_cert_ttl_secs
        || old.censorship.alpn_enforce != new.censorship.alpn_enforce
        || old.censorship.mask_proxy_protocol != new.censorship.mask_proxy_protocol
        || old.censorship.mask_shape_hardening != new.censorship.mask_shape_hardening
        || old.censorship.mask_shape_bucket_floor_bytes
            != new.censorship.mask_shape_bucket_floor_bytes
        || old.censorship.mask_shape_bucket_cap_bytes != new.censorship.mask_shape_bucket_cap_bytes
        || old.censorship.mask_shape_above_cap_blur != new.censorship.mask_shape_above_cap_blur
        || old.censorship.mask_shape_above_cap_blur_max_bytes
            != new.censorship.mask_shape_above_cap_blur_max_bytes
        || old.censorship.mask_relay_max_bytes != new.censorship.mask_relay_max_bytes
        || old.censorship.mask_relay_timeout_ms != new.censorship.mask_relay_timeout_ms
        || old.censorship.mask_relay_idle_timeout_ms != new.censorship.mask_relay_idle_timeout_ms
        || old.censorship.mask_classifier_prefetch_timeout_ms
            != new.censorship.mask_classifier_prefetch_timeout_ms
        || old.censorship.mask_timing_normalization_enabled
            != new.censorship.mask_timing_normalization_enabled
        || old.censorship.mask_timing_normalization_floor_ms
            != new.censorship.mask_timing_normalization_floor_ms
        || old.censorship.mask_timing_normalization_ceiling_ms
            != new.censorship.mask_timing_normalization_ceiling_ms
    {
        warned = true;
        warn!("config reload: censorship settings changed; restart required");
    }
    if old.censorship.tls_domain != new.censorship.tls_domain {
        warned = true;
        warn!(
            "config reload: censorship.tls_domain changed ('{}' → '{}'); restart required",
            old.censorship.tls_domain, new.censorship.tls_domain
        );
    }
    if old.network.ipv4 != new.network.ipv4 || old.network.ipv6 != new.network.ipv6 {
        warned = true;
        warn!("config reload: network.ipv4/ipv6 changed; restart required");
    }
    if old.network.prefer != new.network.prefer
        || old.network.multipath != new.network.multipath
        || old.network.stun_use != new.network.stun_use
        || old.network.stun_servers != new.network.stun_servers
        || old.network.stun_tcp_fallback != new.network.stun_tcp_fallback
        || old.network.http_ip_detect_urls != new.network.http_ip_detect_urls
        || old.network.cache_public_ip_path != new.network.cache_public_ip_path
    {
        warned = true;
        warn!("config reload: non-hot network settings changed; restart required");
    }
    if old.general.use_middle_proxy != new.general.use_middle_proxy {
        warned = true;
        warn!("config reload: use_middle_proxy changed; restart required");
    }
    if old.general.stun_nat_probe_concurrency != new.general.stun_nat_probe_concurrency {
        warned = true;
        warn!("config reload: general.stun_nat_probe_concurrency changed; restart required");
    }
    if old.general.middle_proxy_pool_size != new.general.middle_proxy_pool_size {
        warned = true;
        warn!("config reload: general.middle_proxy_pool_size changed; restart required");
    }
    if old.general.me_route_no_writer_mode != new.general.me_route_no_writer_mode
        || old.general.me_route_no_writer_wait_ms != new.general.me_route_no_writer_wait_ms
        || old.general.me_route_hybrid_max_wait_ms != new.general.me_route_hybrid_max_wait_ms
        || old.general.me_route_blocking_send_timeout_ms
            != new.general.me_route_blocking_send_timeout_ms
        || old.general.me_route_inline_recovery_attempts
            != new.general.me_route_inline_recovery_attempts
        || old.general.me_route_inline_recovery_wait_ms
            != new.general.me_route_inline_recovery_wait_ms
    {
        warned = true;
        warn!("config reload: general.me_route_no_writer_* changed; restart required");
    }
    if old.general.unknown_dc_log_path != new.general.unknown_dc_log_path
        || old.general.unknown_dc_file_log_enabled != new.general.unknown_dc_file_log_enabled
    {
        warned = true;
        warn!("config reload: general.unknown_dc_* changed; restart required");
    }
    if old.general.me_init_retry_attempts != new.general.me_init_retry_attempts {
        warned = true;
        warn!("config reload: general.me_init_retry_attempts changed; restart required");
    }
    if old.general.me2dc_fallback != new.general.me2dc_fallback
        || old.general.me2dc_fast != new.general.me2dc_fast
    {
        warned = true;
        warn!("config reload: general.me2dc_fallback/me2dc_fast changed; restart required");
    }
    if old.general.proxy_config_v4_cache_path != new.general.proxy_config_v4_cache_path
        || old.general.proxy_config_v6_cache_path != new.general.proxy_config_v6_cache_path
    {
        warned = true;
        warn!("config reload: general.proxy_config_*_cache_path changed; restart required");
    }
    if old.general.me_keepalive_enabled != new.general.me_keepalive_enabled
        || old.general.me_keepalive_interval_secs != new.general.me_keepalive_interval_secs
        || old.general.me_keepalive_jitter_secs != new.general.me_keepalive_jitter_secs
        || old.general.me_keepalive_payload_random != new.general.me_keepalive_payload_random
    {
        warned = true;
        warn!("config reload: general.me_keepalive_* changed; restart required");
    }
    if old.general.upstream_connect_retry_attempts != new.general.upstream_connect_retry_attempts
        || old.general.upstream_connect_retry_backoff_ms
            != new.general.upstream_connect_retry_backoff_ms
        || old.general.tg_connect != new.general.tg_connect
        || old.general.upstream_unhealthy_fail_threshold
            != new.general.upstream_unhealthy_fail_threshold
        || old.general.upstream_connect_failfast_hard_errors
            != new.general.upstream_connect_failfast_hard_errors
        || old.general.rpc_proxy_req_every != new.general.rpc_proxy_req_every
    {
        warned = true;
        warn!("config reload: general.upstream_* changed; restart required");
    }
    if non_hot_changed && !warned {
        warn!("config reload: one or more non-hot fields changed; restart required");
    }
}

/// Resolve the public host for link generation — mirrors the logic in main.rs.
///
/// Priority:
/// 1. `[general.links] public_host` — explicit override in config
/// 2. `detected_ip_v4` — from STUN/interface probe at startup
/// 3. `detected_ip_v6` — fallback
/// 4. `"UNKNOWN"` — warn the user to set `public_host`

/// Which top-level config sections changed and whether any require a restart.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ChangeClassification {
    pub changed: Vec<String>,
    pub restart_required: bool,
}

/// Classify old->new using Telemt's OWN reload rule: overlay the hot fields and
/// see if anything non-hot remains different. This guarantees `restart_required`
/// matches actual runtime behavior and never drifts as new fields are added.
pub fn classify_config_changes(old: &ProxyConfig, new: &ProxyConfig) -> ChangeClassification {
    let applied = overlay_hot_fields(old, new);
    let restart_required = !config_equal(&applied, new);
    ChangeClassification {
        changed: changed_sections(old, new),
        restart_required,
    }
}

/// Top-level config sections whose canonical serialized form differs between
/// old and new. Uses the same serialize+canonicalize path as `config_equal`.
fn changed_sections(old: &ProxyConfig, new: &ProxyConfig) -> Vec<String> {
    let mut lhs = serde_json::to_value(old).unwrap_or(serde_json::Value::Null);
    let mut rhs = serde_json::to_value(new).unwrap_or(serde_json::Value::Null);
    canonicalize_json(&mut lhs);
    canonicalize_json(&mut rhs);

    let mut out = Vec::new();
    if let (Some(lo), Some(ro)) = (lhs.as_object(), rhs.as_object()) {
        let mut keys: std::collections::BTreeSet<&String> = lo.keys().collect();
        keys.extend(ro.keys());
        for key in keys {
            if lo.get(key) != ro.get(key) {
                out.push(key.clone());
            }
        }
    }
    out
}
