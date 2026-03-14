#![allow(deprecated)]

use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use rand::Rng;
use tracing::warn;
use serde::{Serialize, Deserialize};

use crate::error::{ProxyError, Result};

use super::defaults::*;
use super::types::*;

// Reject absolute paths and any path component that traverses upward.
// This prevents config include directives from escaping the config directory.
fn is_safe_include_path(path_str: &str) -> bool {
    let p = std::path::Path::new(path_str);
    if p.is_absolute() {
        return false;
    }
    !p.components().any(|c| matches!(c, std::path::Component::ParentDir))
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedConfig {
    pub(crate) config: ProxyConfig,
    pub(crate) source_files: Vec<PathBuf>,
    pub(crate) rendered_hash: u64,
}

fn normalize_config_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn hash_rendered_snapshot(rendered: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    rendered.hash(&mut hasher);
    hasher.finish()
}

fn preprocess_includes(
    content: &str,
    base_dir: &Path,
    depth: u8,
    source_files: &mut BTreeSet<PathBuf>,
) -> Result<String> {
    if depth > 10 {
        return Err(ProxyError::Config("Include depth > 10".into()));
    }
    let mut output = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("include") {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let path_str = rest.trim().trim_matches('"');
                if !is_safe_include_path(path_str) {
                    return Err(ProxyError::Config(format!(
                        "Include path '{}' is disallowed: only relative paths without '..' are permitted",
                        path_str
                    )));
                }
                let resolved = base_dir.join(path_str);
                source_files.insert(normalize_config_path(&resolved));
                let included = std::fs::read_to_string(&resolved)
                    .map_err(|e| ProxyError::Config(e.to_string()))?;
                let included_dir = resolved.parent().unwrap_or(base_dir);
                output.push_str(&preprocess_includes(
                    &included,
                    included_dir,
                    depth + 1,
                    source_files,
                )?);
                output.push('\n');
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output)
}

fn validate_network_cfg(net: &mut NetworkConfig) -> Result<()> {
    if !net.ipv4 && matches!(net.ipv6, Some(false)) {
        return Err(ProxyError::Config(
            "Both ipv4 and ipv6 are disabled in [network]".to_string(),
        ));
    }

    if net.prefer != 4 && net.prefer != 6 {
        return Err(ProxyError::Config(
            "network.prefer must be 4 or 6".to_string(),
        ));
    }

    if !net.ipv4 && net.prefer == 4 {
        warn!("prefer=4 but ipv4=false; forcing prefer=6");
        net.prefer = 6;
    }

    if matches!(net.ipv6, Some(false)) && net.prefer == 6 {
        warn!("prefer=6 but ipv6=false; forcing prefer=4");
        net.prefer = 4;
    }

    Ok(())
}

fn push_unique_nonempty(target: &mut Vec<String>, value: String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    if !target.iter().any(|existing| existing == trimmed) {
        target.push(trimmed.to_string());
    }
}

fn is_valid_ad_tag(tag: &str) -> bool {
    tag.len() == 32 && tag.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn sanitize_ad_tag(ad_tag: &mut Option<String>) {
    let Some(tag) = ad_tag.as_ref() else {
        return;
    };

    if !is_valid_ad_tag(tag) {
        warn!(
            "Invalid general.ad_tag value, expected exactly 32 hex chars; ad_tag is disabled"
        );
        *ad_tag = None;
    }
}

// ============= Main Config =============

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub timeouts: TimeoutsConfig,

    #[serde(default)]
    pub censorship: AntiCensorshipConfig,

    #[serde(default)]
    pub access: AccessConfig,

    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,

    #[serde(default)]
    pub show_link: ShowLink,

    /// DC address overrides for non-standard DCs (CDN, media, test, etc.)
    /// Keys are DC indices as strings, values are one or more "ip:port" addresses.
    /// Matches the C implementation's `proxy_for <dc_id> <ip>:<port>` config directive.
    /// Example in config.toml:
///   [`dc_overrides`]
    ///   "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    #[serde(default, deserialize_with = "deserialize_dc_overrides")]
    pub dc_overrides: HashMap<String, Vec<String>>,

    /// Default DC index (1-5) for unmapped non-standard DCs.
    /// Matches the C implementation's `default <dc_id>` config directive.
    /// If not set, defaults to 2 (matching Telegram's official `default 2;` in proxy-multi.conf).
    #[serde(default)]
    pub default_dc: Option<u8>,
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_metadata(path).map(|loaded| loaded.config)
    }

    pub(crate) fn load_with_metadata<P: AsRef<Path>>(path: P) -> Result<LoadedConfig> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| ProxyError::Config(e.to_string()))?;
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let mut source_files = BTreeSet::new();
        source_files.insert(normalize_config_path(path));
        let processed = preprocess_includes(&content, base_dir, 0, &mut source_files)?;

        let parsed_toml: toml::Value =
            toml::from_str(&processed).map_err(|e| ProxyError::Config(e.to_string()))?;
        let general_table = parsed_toml
            .get("general")
            .and_then(|value| value.as_table());
        let network_table = parsed_toml
            .get("network")
            .and_then(|value| value.as_table());
        let update_every_is_explicit = general_table
            .map(|table| table.contains_key("update_every"))
            .unwrap_or(false);
        let legacy_secret_is_explicit = general_table
            .map(|table| table.contains_key("proxy_secret_auto_reload_secs"))
            .unwrap_or(false);
        let legacy_config_is_explicit = general_table
            .map(|table| table.contains_key("proxy_config_auto_reload_secs"))
            .unwrap_or(false);
        let stun_servers_is_explicit = network_table
            .map(|table| table.contains_key("stun_servers"))
            .unwrap_or(false);

        let mut config: Self =
            parsed_toml.try_into().map_err(|e| ProxyError::Config(e.to_string()))?;

        if !update_every_is_explicit && (legacy_secret_is_explicit || legacy_config_is_explicit) {
            config.general.update_every = None;
        }

        let legacy_nat_stun = config.general.middle_proxy_nat_stun.take();
        let legacy_nat_stun_servers = std::mem::take(&mut config.general.middle_proxy_nat_stun_servers);
        let legacy_nat_stun_used = legacy_nat_stun.is_some() || !legacy_nat_stun_servers.is_empty();
        if stun_servers_is_explicit {
            let mut explicit_stun_servers = Vec::new();
            for stun in std::mem::take(&mut config.network.stun_servers) {
                push_unique_nonempty(&mut explicit_stun_servers, stun);
            }
            config.network.stun_servers = explicit_stun_servers;

            if legacy_nat_stun_used {
                warn!("general.middle_proxy_nat_stun and general.middle_proxy_nat_stun_servers are ignored because network.stun_servers is explicitly set");
            }
        } else {
            // Keep the default STUN pool unless network.stun_servers is explicitly overridden.
            let mut unified_stun_servers = default_stun_servers();
            if let Some(stun) = legacy_nat_stun {
                push_unique_nonempty(&mut unified_stun_servers, stun);
            }
            for stun in legacy_nat_stun_servers {
                push_unique_nonempty(&mut unified_stun_servers, stun);
            }

            config.network.stun_servers = unified_stun_servers;

            if legacy_nat_stun_used {
                warn!("general.middle_proxy_nat_stun and general.middle_proxy_nat_stun_servers are deprecated; use network.stun_servers");
            }
        }

        sanitize_ad_tag(&mut config.general.ad_tag);

        if let Some(path) = &config.general.proxy_config_v4_cache_path
            && path.trim().is_empty()
        {
            return Err(ProxyError::Config(
                "general.proxy_config_v4_cache_path cannot be empty when provided".to_string(),
            ));
        }

        if let Some(path) = &config.general.proxy_config_v6_cache_path
            && path.trim().is_empty()
        {
            return Err(ProxyError::Config(
                "general.proxy_config_v6_cache_path cannot be empty when provided".to_string(),
            ));
        }

        if let Some(update_every) = config.general.update_every {
            if update_every == 0 {
                return Err(ProxyError::Config(
                    "general.update_every must be > 0".to_string(),
                ));
            }
        } else {
            let legacy_secret = config.general.proxy_secret_auto_reload_secs;
            let legacy_config = config.general.proxy_config_auto_reload_secs;
            let effective = legacy_secret.min(legacy_config);
            if effective == 0 {
                return Err(ProxyError::Config(
                    "legacy proxy_*_auto_reload_secs values must be > 0 when general.update_every is not set".to_string(),
                ));
            }

            if legacy_secret != default_proxy_secret_reload_secs()
                || legacy_config != default_proxy_config_reload_secs()
            {
                warn!(
                    proxy_secret_auto_reload_secs = legacy_secret,
                    proxy_config_auto_reload_secs = legacy_config,
                    effective_update_every_secs = effective,
                    "proxy_*_auto_reload_secs are deprecated; set general.update_every"
                );
            }
        }

        if config.general.stun_nat_probe_concurrency == 0 {
            return Err(ProxyError::Config(
                "general.stun_nat_probe_concurrency must be > 0".to_string(),
            ));
        }

        if config.general.me_init_retry_attempts > 1_000_000 {
            return Err(ProxyError::Config(
                "general.me_init_retry_attempts must be within [0, 1000000]".to_string(),
            ));
        }

        if config.general.me_init_retry_backoff_base_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_init_retry_backoff_base_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_init_retry_backoff_cap_ms < config.general.me_init_retry_backoff_base_ms {
            return Err(ProxyError::Config(
                "general.me_init_retry_backoff_cap_ms must be >= me_init_retry_backoff_base_ms".to_string(),
            ));
        }

        if config.server.max_connections == 0 {
            return Err(ProxyError::Config(
                "server.max_connections must be > 0".to_string(),
            ));
        }

        if config.general.upstream_connect_retry_attempts == 0 {
            return Err(ProxyError::Config(
                "general.upstream_connect_retry_attempts must be > 0".to_string(),
            ));
        }

        if config.general.upstream_connect_budget_ms == 0 {
            return Err(ProxyError::Config(
                "general.upstream_connect_budget_ms must be > 0".to_string(),
            ));
        }

        if config.general.upstream_unhealthy_fail_threshold == 0 {
            return Err(ProxyError::Config(
                "general.upstream_unhealthy_fail_threshold must be > 0".to_string(),
            ));
        }

        if config.general.rpc_proxy_req_every != 0
            && !(10..=300).contains(&config.general.rpc_proxy_req_every)
        {
            return Err(ProxyError::Config(
                "general.rpc_proxy_req_every must be 0 or within [10, 300]".to_string(),
            ));
        }

        if config.general.me_writer_cmd_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_writer_cmd_channel_capacity must be > 0".to_string(),
            ));
        }

        if config.general.me_route_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_route_channel_capacity must be > 0".to_string(),
            ));
        }

        if config.general.me_c2me_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_c2me_channel_capacity must be > 0".to_string(),
            ));
        }

        if config.general.me_reader_route_data_wait_ms > 20 {
            return Err(ProxyError::Config(
                "general.me_reader_route_data_wait_ms must be within [0, 20]".to_string(),
            ));
        }

        if !(1..=512).contains(&config.general.me_d2c_flush_batch_max_frames) {
            return Err(ProxyError::Config(
                "general.me_d2c_flush_batch_max_frames must be within [1, 512]".to_string(),
            ));
        }

        if !(4096..=2 * 1024 * 1024).contains(&config.general.me_d2c_flush_batch_max_bytes) {
            return Err(ProxyError::Config(
                "general.me_d2c_flush_batch_max_bytes must be within [4096, 2097152]".to_string(),
            ));
        }

        if config.general.me_d2c_flush_batch_max_delay_us > 5000 {
            return Err(ProxyError::Config(
                "general.me_d2c_flush_batch_max_delay_us must be within [0, 5000]".to_string(),
            ));
        }

        if !(4096..=1024 * 1024).contains(&config.general.direct_relay_copy_buf_c2s_bytes) {
            return Err(ProxyError::Config(
                "general.direct_relay_copy_buf_c2s_bytes must be within [4096, 1048576]".to_string(),
            ));
        }

        if !(8192..=2 * 1024 * 1024).contains(&config.general.direct_relay_copy_buf_s2c_bytes) {
            return Err(ProxyError::Config(
                "general.direct_relay_copy_buf_s2c_bytes must be within [8192, 2097152]".to_string(),
            ));
        }

        if config.general.me_health_interval_ms_unhealthy == 0 {
            return Err(ProxyError::Config(
                "general.me_health_interval_ms_unhealthy must be > 0".to_string(),
            ));
        }

        if config.general.me_health_interval_ms_healthy == 0 {
            return Err(ProxyError::Config(
                "general.me_health_interval_ms_healthy must be > 0".to_string(),
            ));
        }

        if config.general.me_admission_poll_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_admission_poll_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_warn_rate_limit_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_warn_rate_limit_ms must be > 0".to_string(),
            ));
        }

        if config.access.user_max_unique_ips_window_secs == 0 {
            return Err(ProxyError::Config(
                "access.user_max_unique_ips_window_secs must be > 0".to_string(),
            ));
        }

        if config.general.me_reinit_every_secs == 0 {
            return Err(ProxyError::Config(
                "general.me_reinit_every_secs must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_shadow_writers > 32 {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_shadow_writers must be within [0, 32]".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_min_writers_single_endpoint == 0
            || config.general.me_adaptive_floor_min_writers_single_endpoint > 32
        {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
                    .to_string(),
            ));
        }

        if config.general.me_adaptive_floor_min_writers_multi_endpoint == 0
            || config.general.me_adaptive_floor_min_writers_multi_endpoint > 32
        {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_min_writers_multi_endpoint must be within [1, 32]"
                    .to_string(),
            ));
        }

        if config.general.me_adaptive_floor_writers_per_core_total == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_writers_per_core_total must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_active_writers_per_core == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_active_writers_per_core must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_warm_writers_per_core == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_warm_writers_per_core must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_active_writers_global == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_active_writers_global must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_warm_writers_global == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_warm_writers_global must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_outage_backoff_min_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_outage_backoff_min_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_outage_backoff_max_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_outage_backoff_max_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_outage_backoff_min_ms
            > config.general.me_single_endpoint_outage_backoff_max_ms
        {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_outage_backoff_min_ms must be <= general.me_single_endpoint_outage_backoff_max_ms".to_string(),
            ));
        }

        if config.general.beobachten_minutes == 0 {
            return Err(ProxyError::Config(
                "general.beobachten_minutes must be > 0".to_string(),
            ));
        }

        if config.general.beobachten_flush_secs == 0 {
            return Err(ProxyError::Config(
                "general.beobachten_flush_secs must be > 0".to_string(),
            ));
        }

        if config.general.beobachten_file.trim().is_empty() {
            return Err(ProxyError::Config(
                "general.beobachten_file cannot be empty".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_delay_max_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_delay_max_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_delay_min_ms
            > config.general.me_hardswap_warmup_delay_max_ms
        {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_delay_min_ms must be <= general.me_hardswap_warmup_delay_max_ms".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_extra_passes > 10 {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_extra_passes must be within [0, 10]".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_pass_backoff_base_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_pass_backoff_base_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_config_stable_snapshots == 0 {
            return Err(ProxyError::Config(
                "general.me_config_stable_snapshots must be > 0".to_string(),
            ));
        }

        if config.general.me_snapshot_min_proxy_for_lines == 0 {
            return Err(ProxyError::Config(
                "general.me_snapshot_min_proxy_for_lines must be > 0".to_string(),
            ));
        }

        if config.general.proxy_secret_stable_snapshots == 0 {
            return Err(ProxyError::Config(
                "general.proxy_secret_stable_snapshots must be > 0".to_string(),
            ));
        }

        if config.general.me_reinit_trigger_channel == 0 {
            return Err(ProxyError::Config(
                "general.me_reinit_trigger_channel must be > 0".to_string(),
            ));
        }

        if !(32..=4096).contains(&config.general.proxy_secret_len_max) {
            return Err(ProxyError::Config(
                "general.proxy_secret_len_max must be within [32, 4096]".to_string(),
            ));
        }

        if !(0.0..=1.0).contains(&config.general.me_pool_min_fresh_ratio) {
            return Err(ProxyError::Config(
                "general.me_pool_min_fresh_ratio must be within [0.0, 1.0]".to_string(),
            ));
        }

        if config.general.me_route_backpressure_base_timeout_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_base_timeout_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_route_backpressure_high_timeout_ms
            < config.general.me_route_backpressure_base_timeout_ms
        {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_timeout_ms must be >= general.me_route_backpressure_base_timeout_ms".to_string(),
            ));
        }

        if !(1..=100).contains(&config.general.me_route_backpressure_high_watermark_pct) {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_watermark_pct must be within [1, 100]".to_string(),
            ));
        }

        if !(10..=5000).contains(&config.general.me_route_no_writer_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_no_writer_wait_ms must be within [10, 5000]".to_string(),
            ));
        }

        if !(2..=4).contains(&config.general.me_writer_pick_sample_size) {
            return Err(ProxyError::Config(
                "general.me_writer_pick_sample_size must be within [2, 4]".to_string(),
            ));
        }

        if config.general.me_route_inline_recovery_attempts == 0 {
            return Err(ProxyError::Config(
                "general.me_route_inline_recovery_attempts must be > 0".to_string(),
            ));
        }

        if !(10..=30000).contains(&config.general.me_route_inline_recovery_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_inline_recovery_wait_ms must be within [10, 30000]".to_string(),
            ));
        }

        if config.server.api.request_body_limit_bytes == 0 {
            return Err(ProxyError::Config(
                "server.api.request_body_limit_bytes must be > 0".to_string(),
            ));
        }

        if config.server.api.minimal_runtime_cache_ttl_ms > 60_000 {
            return Err(ProxyError::Config(
                "server.api.minimal_runtime_cache_ttl_ms must be within [0, 60000]".to_string(),
            ));
        }

        if config.server.api.runtime_edge_cache_ttl_ms > 60_000 {
            return Err(ProxyError::Config(
                "server.api.runtime_edge_cache_ttl_ms must be within [0, 60000]".to_string(),
            ));
        }

        if !(1..=1000).contains(&config.server.api.runtime_edge_top_n) {
            return Err(ProxyError::Config(
                "server.api.runtime_edge_top_n must be within [1, 1000]".to_string(),
            ));
        }

        if !(16..=4096).contains(&config.server.api.runtime_edge_events_capacity) {
            return Err(ProxyError::Config(
                "server.api.runtime_edge_events_capacity must be within [16, 4096]".to_string(),
            ));
        }

        if config.server.api.listen.parse::<SocketAddr>().is_err() {
            return Err(ProxyError::Config(
                "server.api.listen must be in IP:PORT format".to_string(),
            ));
        }

        if config.server.proxy_protocol_header_timeout_ms == 0 {
            return Err(ProxyError::Config(
                "server.proxy_protocol_header_timeout_ms must be > 0".to_string(),
            ));
        }

        if config.general.effective_me_pool_force_close_secs() > 0
            && config.general.effective_me_pool_force_close_secs()
                < config.general.me_pool_drain_ttl_secs
        {
            warn!(
                me_pool_drain_ttl_secs = config.general.me_pool_drain_ttl_secs,
                me_reinit_drain_timeout_secs = config.general.effective_me_pool_force_close_secs(),
                "force-close timeout is lower than drain TTL; bumping force-close timeout to TTL"
            );
            config.general.me_reinit_drain_timeout_secs = config.general.me_pool_drain_ttl_secs;
        }

        // Validate secrets.
        for (user, secret) in &config.access.users {
            if !secret.chars().all(|c| c.is_ascii_hexdigit()) || secret.len() != 32 {
                return Err(ProxyError::InvalidSecret {
                    user: user.clone(),
                    reason: "Must be 32 hex characters".to_string(),
                });
            }
        }

        // Validate tls_domain.
        if config.censorship.tls_domain.is_empty() {
            return Err(ProxyError::Config("tls_domain cannot be empty".to_string()));
        }

        // Validate mask_unix_sock.
        if let Some(ref sock_path) = config.censorship.mask_unix_sock {
            if sock_path.is_empty() {
                return Err(ProxyError::Config(
                    "mask_unix_sock cannot be empty".to_string(),
                ));
            }
            #[cfg(unix)]
            if sock_path.len() > 107 {
                return Err(ProxyError::Config(format!(
                    "mask_unix_sock path too long: {} bytes (max 107)",
                    sock_path.len()
                )));
            }
            #[cfg(not(unix))]
            return Err(ProxyError::Config(
                "mask_unix_sock is only supported on Unix platforms".to_string(),
            ));

            if config.censorship.mask_host.is_some() {
                return Err(ProxyError::Config(
                    "mask_unix_sock and mask_host are mutually exclusive".to_string(),
                ));
            }
        }

        // Default mask_host to tls_domain if not set and no unix socket configured.
        if config.censorship.mask_host.is_none() && config.censorship.mask_unix_sock.is_none() {
            config.censorship.mask_host = Some(config.censorship.tls_domain.clone());
        }

        // Merge primary + extra TLS domains, deduplicate (primary always first).
        if !config.censorship.tls_domains.is_empty() {
            let mut all = Vec::with_capacity(1 + config.censorship.tls_domains.len());
            all.push(config.censorship.tls_domain.clone());
            for d in std::mem::take(&mut config.censorship.tls_domains) {
                if !d.is_empty() && !all.contains(&d) {
                    all.push(d);
                }
            }
            // keep primary as tls_domain; store remaining back to tls_domains
            if all.len() > 1 {
                config.censorship.tls_domains = all[1..].to_vec();
            }
        }

        // Migration: prefer_ipv6 -> network.prefer.
        if config.general.prefer_ipv6 {
            if config.network.prefer == 4 {
                config.network.prefer = 6;
            }
            warn!("prefer_ipv6 is deprecated, use [network].prefer = 6");
        }

        if config.general.use_middle_proxy && !config.general.me_secret_atomic_snapshot {
            config.general.me_secret_atomic_snapshot = true;
            warn!(
                "Auto-enabled me_secret_atomic_snapshot for middle proxy mode to keep KDF key_selector/secret coherent"
            );
        }

        validate_network_cfg(&mut config.network)?;
        crate::network::dns_overrides::validate_entries(&config.network.dns_overrides)?;

        if config.general.use_middle_proxy && config.network.ipv6 == Some(true) {
            warn!("IPv6 with Middle Proxy is experimental and may cause KDF address mismatch; consider disabling IPv6 or ME");
        }

        // Random fake_cert_len only when default is in use.
        if !config.censorship.tls_emulation && config.censorship.fake_cert_len == default_fake_cert_len() {
            config.censorship.fake_cert_len = rand::rng().gen_range(1024..4096);
        }

        // Resolve listen_tcp: explicit value wins, otherwise auto-detect.
        // If unix socket is set → TCP only when listen_addr_ipv4 or listeners are explicitly provided.
        // If no unix socket → TCP always (backward compat).
        let listen_tcp = config.server.listen_tcp.unwrap_or_else(|| {
            if config.server.listen_unix_sock.is_some() {
                // Unix socket present: TCP only if user explicitly set addresses or listeners.
                config.server.listen_addr_ipv4.is_some()
                    || !config.server.listeners.is_empty()
            } else {
                true
            }
        });

        // Migration: Populate listeners if empty (skip when listen_tcp = false).
        if config.server.listeners.is_empty() && listen_tcp {
            let ipv4_str = config.server.listen_addr_ipv4
                .as_deref()
                .unwrap_or("0.0.0.0");
            if let Ok(ipv4) = ipv4_str.parse::<IpAddr>() {
                config.server.listeners.push(ListenerConfig {
                    ip: ipv4,
                    announce: None,
                    announce_ip: None,
                    proxy_protocol: None,
                    reuse_allow: false,
                });
            }
            if let Some(ipv6_str) = &config.server.listen_addr_ipv6
                && let Ok(ipv6) = ipv6_str.parse::<IpAddr>()
            {
                config.server.listeners.push(ListenerConfig {
                    ip: ipv6,
                    announce: None,
                    announce_ip: None,
                    proxy_protocol: None,
                    reuse_allow: false,
                });
            }
        }

        // Migration: announce_ip → announce for each listener.
        for listener in &mut config.server.listeners {
            if listener.announce.is_none()
                && let Some(ip) = listener.announce_ip.take()
            {
                listener.announce = Some(ip.to_string());
            }
        }

        // Migration: show_link (top-level) → general.links.show.
        if !config.show_link.is_empty() && config.general.links.show.is_empty() {
            config.general.links.show = config.show_link.clone();
        }

        // Migration: Populate upstreams if empty (Default Direct).
        if config.upstreams.is_empty() {
            config.upstreams.push(UpstreamConfig {
                upstream_type: UpstreamType::Direct { interface: None, bind_addresses: None },
                weight: 1,
                enabled: true,
                scopes: String::new(),
                selected_scope: String::new(),
            });
        }

        // Ensure default DC203 override is present.
        config
            .dc_overrides
            .entry("203".to_string())
            .or_insert_with(|| vec!["91.105.192.100:443".to_string()]);

        Ok(LoadedConfig {
            config,
            source_files: source_files.into_iter().collect(),
            rendered_hash: hash_rendered_snapshot(&processed),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.access.users.is_empty() {
            return Err(ProxyError::Config("No users configured".to_string()));
        }

        if !self.general.modes.classic && !self.general.modes.secure && !self.general.modes.tls {
            return Err(ProxyError::Config("No modes enabled".to_string()));
        }

        if self.censorship.tls_domain.contains(' ') || self.censorship.tls_domain.contains('/') {
            return Err(ProxyError::Config(format!(
                "Invalid tls_domain: '{}'. Must be a valid domain name",
                self.censorship.tls_domain
            )));
        }

        for (user, tag) in &self.access.user_ad_tags {
            let zeros = "00000000000000000000000000000000";
            if !is_valid_ad_tag(tag) {
                return Err(ProxyError::Config(format!(
                    "access.user_ad_tags['{}'] must be exactly 32 hex characters",
                    user
                )));
            }
            if tag == zeros {
                warn!(user = %user, "user ad_tag is all zeros; register a valid proxy tag via @MTProxybot to enable sponsored channel");
            }
        }

        for (user, secret) in &self.access.users {
            if secret == "00000000000000000000000000000000" {
                warn!(
                    "User '{}' has the default all-zero secret; replace before use in production",
                    user
                );
            }
        }
        crate::network::dns_overrides::validate_entries(&self.network.dns_overrides)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_defaults_remain_unchanged_for_present_sections() {
        let toml = r#"
            [network]
            [general]
            [server]
            [access]
        "#;
        let cfg_result: std::result::Result<ProxyConfig, _> = toml::from_str(toml);
        assert!(cfg_result.is_ok(), "Failed to deserialize test config");
        let cfg = if let Ok(cfg) = cfg_result { cfg } else { return };

        assert_eq!(cfg.network.ipv6, default_network_ipv6());
        assert_eq!(cfg.network.stun_use, default_true());
        assert_eq!(cfg.network.stun_tcp_fallback, default_stun_tcp_fallback());
        assert_eq!(
            cfg.general.middle_proxy_warm_standby,
            default_middle_proxy_warm_standby()
        );
        assert_eq!(
            cfg.general.me_reconnect_max_concurrent_per_dc,
            default_me_reconnect_max_concurrent_per_dc()
        );
        assert_eq!(
            cfg.general.me_reconnect_fast_retry_count,
            default_me_reconnect_fast_retry_count()
        );
        assert_eq!(
            cfg.general.me_init_retry_attempts,
            default_me_init_retry_attempts()
        );
        assert_eq!(
            cfg.general.me2dc_fallback,
            default_me2dc_fallback()
        );
        assert_eq!(
            cfg.general.proxy_config_v4_cache_path,
            default_proxy_config_v4_cache_path()
        );
        assert_eq!(
            cfg.general.proxy_config_v6_cache_path,
            default_proxy_config_v6_cache_path()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_shadow_writers,
            default_me_single_endpoint_shadow_writers()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_mode_enabled,
            default_me_single_endpoint_outage_mode_enabled()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_disable_quarantine,
            default_me_single_endpoint_outage_disable_quarantine()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_backoff_min_ms,
            default_me_single_endpoint_outage_backoff_min_ms()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_backoff_max_ms,
            default_me_single_endpoint_outage_backoff_max_ms()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_shadow_rotate_every_secs,
            default_me_single_endpoint_shadow_rotate_every_secs()
        );
        assert_eq!(cfg.general.me_floor_mode, MeFloorMode::default());
        assert_eq!(
            cfg.general.me_adaptive_floor_idle_secs,
            default_me_adaptive_floor_idle_secs()
        );
        assert_eq!(
            cfg.general.me_adaptive_floor_min_writers_single_endpoint,
            default_me_adaptive_floor_min_writers_single_endpoint()
        );
        assert_eq!(
            cfg.general.me_adaptive_floor_recover_grace_secs,
            default_me_adaptive_floor_recover_grace_secs()
        );
        assert_eq!(
            cfg.general.upstream_connect_retry_attempts,
            default_upstream_connect_retry_attempts()
        );
        assert_eq!(
            cfg.general.upstream_connect_retry_backoff_ms,
            default_upstream_connect_retry_backoff_ms()
        );
        assert_eq!(
            cfg.general.upstream_unhealthy_fail_threshold,
            default_upstream_unhealthy_fail_threshold()
        );
        assert_eq!(
            cfg.general.upstream_connect_failfast_hard_errors,
            default_upstream_connect_failfast_hard_errors()
        );
        assert_eq!(
            cfg.general.rpc_proxy_req_every,
            default_rpc_proxy_req_every()
        );
        assert_eq!(cfg.general.update_every, default_update_every());
        assert_eq!(cfg.server.listen_addr_ipv4, default_listen_addr_ipv4());
        assert_eq!(cfg.server.listen_addr_ipv6, default_listen_addr_ipv6_opt());
        assert_eq!(cfg.server.api.listen, default_api_listen());
        assert_eq!(cfg.server.api.whitelist, default_api_whitelist());
        assert_eq!(
            cfg.server.api.request_body_limit_bytes,
            default_api_request_body_limit_bytes()
        );
        assert_eq!(
            cfg.server.api.minimal_runtime_enabled,
            default_api_minimal_runtime_enabled()
        );
        assert_eq!(
            cfg.server.api.minimal_runtime_cache_ttl_ms,
            default_api_minimal_runtime_cache_ttl_ms()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_enabled,
            default_api_runtime_edge_enabled()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_cache_ttl_ms,
            default_api_runtime_edge_cache_ttl_ms()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_top_n,
            default_api_runtime_edge_top_n()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_events_capacity,
            default_api_runtime_edge_events_capacity()
        );
        assert_eq!(cfg.access.users, default_access_users());
        assert_eq!(
            cfg.access.user_max_unique_ips_mode,
            UserMaxUniqueIpsMode::default()
        );
        assert_eq!(
            cfg.access.user_max_unique_ips_window_secs,
            default_user_max_unique_ips_window_secs()
        );
    }

    #[test]
    fn impl_defaults_are_sourced_from_default_helpers() {
        let network = NetworkConfig::default();
        assert_eq!(network.ipv6, default_network_ipv6());
        assert_eq!(network.stun_use, default_true());
        assert_eq!(network.stun_tcp_fallback, default_stun_tcp_fallback());

        let general = GeneralConfig::default();
        assert_eq!(
            general.middle_proxy_warm_standby,
            default_middle_proxy_warm_standby()
        );
        assert_eq!(
            general.me_reconnect_max_concurrent_per_dc,
            default_me_reconnect_max_concurrent_per_dc()
        );
        assert_eq!(
            general.me_reconnect_fast_retry_count,
            default_me_reconnect_fast_retry_count()
        );
        assert_eq!(
            general.me_init_retry_attempts,
            default_me_init_retry_attempts()
        );
        assert_eq!(
            general.me_init_retry_backoff_base_ms,
            default_me_init_retry_backoff_base_ms()
        );
        assert_eq!(
            general.me_init_retry_backoff_cap_ms,
            default_me_init_retry_backoff_cap_ms()
        );
        assert_eq!(general.me2dc_fallback, default_me2dc_fallback());
        assert_eq!(
            general.proxy_config_v4_cache_path,
            default_proxy_config_v4_cache_path()
        );
        assert_eq!(
            general.proxy_config_v6_cache_path,
            default_proxy_config_v6_cache_path()
        );
        assert_eq!(
            general.me_single_endpoint_shadow_writers,
            default_me_single_endpoint_shadow_writers()
        );
        assert_eq!(
            general.me_single_endpoint_outage_mode_enabled,
            default_me_single_endpoint_outage_mode_enabled()
        );
        assert_eq!(
            general.me_single_endpoint_outage_disable_quarantine,
            default_me_single_endpoint_outage_disable_quarantine()
        );
        assert_eq!(
            general.me_single_endpoint_outage_backoff_min_ms,
            default_me_single_endpoint_outage_backoff_min_ms()
        );
        assert_eq!(
            general.me_single_endpoint_outage_backoff_max_ms,
            default_me_single_endpoint_outage_backoff_max_ms()
        );
        assert_eq!(
            general.me_single_endpoint_shadow_rotate_every_secs,
            default_me_single_endpoint_shadow_rotate_every_secs()
        );
        assert_eq!(general.me_floor_mode, MeFloorMode::default());
        assert_eq!(
            general.me_adaptive_floor_idle_secs,
            default_me_adaptive_floor_idle_secs()
        );
        assert_eq!(
            general.me_adaptive_floor_min_writers_single_endpoint,
            default_me_adaptive_floor_min_writers_single_endpoint()
        );
        assert_eq!(
            general.me_adaptive_floor_recover_grace_secs,
            default_me_adaptive_floor_recover_grace_secs()
        );
        assert_eq!(
            general.upstream_connect_retry_attempts,
            default_upstream_connect_retry_attempts()
        );
        assert_eq!(
            general.upstream_connect_retry_backoff_ms,
            default_upstream_connect_retry_backoff_ms()
        );
        assert_eq!(
            general.upstream_unhealthy_fail_threshold,
            default_upstream_unhealthy_fail_threshold()
        );
        assert_eq!(
            general.upstream_connect_failfast_hard_errors,
            default_upstream_connect_failfast_hard_errors()
        );
        assert_eq!(general.rpc_proxy_req_every, default_rpc_proxy_req_every());
        assert_eq!(general.update_every, default_update_every());

        let server = ServerConfig::default();
        assert_eq!(server.max_connections, default_max_connections());
        assert_eq!(server.listen_addr_ipv6, Some(default_listen_addr_ipv6()));
        assert_eq!(server.api.listen, default_api_listen());
        assert_eq!(server.api.whitelist, default_api_whitelist());
        assert_eq!(
            server.api.request_body_limit_bytes,
            default_api_request_body_limit_bytes()
        );
        assert_eq!(
            server.api.minimal_runtime_enabled,
            default_api_minimal_runtime_enabled()
        );
        assert_eq!(
            server.api.minimal_runtime_cache_ttl_ms,
            default_api_minimal_runtime_cache_ttl_ms()
        );
        assert_eq!(
            server.api.runtime_edge_enabled,
            default_api_runtime_edge_enabled()
        );
        assert_eq!(
            server.api.runtime_edge_cache_ttl_ms,
            default_api_runtime_edge_cache_ttl_ms()
        );
        assert_eq!(
            server.api.runtime_edge_top_n,
            default_api_runtime_edge_top_n()
        );
        assert_eq!(
            server.api.runtime_edge_events_capacity,
            default_api_runtime_edge_events_capacity()
        );

        let access = AccessConfig::default();
        assert_eq!(access.users, default_access_users());
    }

    #[test]
    fn dc_overrides_allow_string_and_array() {
        let toml = r#"
            [dc_overrides]
            "201" = "149.154.175.50:443"
            "202" = ["149.154.167.51:443", "149.154.175.100:443"]
        "#;
        let cfg: ProxyConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.dc_overrides["201"], vec!["149.154.175.50:443"]);
        assert_eq!(
            cfg.dc_overrides["202"],
            vec!["149.154.167.51:443", "149.154.175.100:443"]
        );
    }

    #[test]
    fn load_with_metadata_collects_include_files() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("telemt_load_metadata_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = dir.join("config.toml");
        let include_path = dir.join("included.toml");

        std::fs::write(
            &include_path,
            r#"
                [access.users]
                user = "00000000000000000000000000000000"
            "#,
        )
        .unwrap();
        std::fs::write(
            &main_path,
            r#"
                include = "included.toml"

                [censorship]
                tls_domain = "example.com"
            "#,
        )
        .unwrap();

        let loaded = ProxyConfig::load_with_metadata(&main_path).unwrap();
        let main_normalized = normalize_config_path(&main_path);
        let include_normalized = normalize_config_path(&include_path);

        assert!(loaded.source_files.contains(&main_normalized));
        assert!(loaded.source_files.contains(&include_normalized));

        let _ = std::fs::remove_file(main_path);
        let _ = std::fs::remove_file(include_path);
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn dc_overrides_inject_dc203_default() {
        let toml = r#"
            [general]
            use_middle_proxy = false

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_dc_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert!(cfg
            .dc_overrides
            .get("203")
            .map(|v| v.contains(&"91.105.192.100:443".to_string()))
            .unwrap_or(false));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_every_overrides_legacy_fields() {
        let toml = r#"
            [general]
            update_every = 123
            proxy_secret_auto_reload_secs = 700
            proxy_config_auto_reload_secs = 800

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_update_every_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.effective_update_every_secs(), 123);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_every_fallback_to_legacy_min() {
        let toml = r#"
            [general]
            proxy_secret_auto_reload_secs = 600
            proxy_config_auto_reload_secs = 120

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_update_every_legacy_min_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.update_every, None);
        assert_eq!(cfg.general.effective_update_every_secs(), 120);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_every_zero_is_rejected() {
        let toml = r#"
            [general]
            update_every = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_update_every_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.update_every must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stun_nat_probe_concurrency_zero_is_rejected() {
        let toml = r#"
            [general]
            stun_nat_probe_concurrency = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_stun_nat_probe_concurrency_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.stun_nat_probe_concurrency must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_reinit_every_default_is_set() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_reinit_every_default_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.me_reinit_every_secs,
            default_me_reinit_every_secs()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_reinit_every_zero_is_rejected() {
        let toml = r#"
            [general]
            me_reinit_every_secs = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_reinit_every_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_reinit_every_secs must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_single_endpoint_outage_backoff_range_is_validated() {
        let toml = r#"
            [general]
            me_single_endpoint_outage_backoff_min_ms = 4000
            me_single_endpoint_outage_backoff_max_ms = 3000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_single_endpoint_outage_backoff_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "general.me_single_endpoint_outage_backoff_min_ms must be <= general.me_single_endpoint_outage_backoff_max_ms"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_single_endpoint_shadow_writers_too_large_is_rejected() {
        let toml = r#"
            [general]
            me_single_endpoint_shadow_writers = 33

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_single_endpoint_shadow_writers_limit_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_single_endpoint_shadow_writers must be within [0, 32]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_adaptive_floor_min_writers_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_adaptive_floor_min_writers_single_endpoint = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_adaptive_floor_min_writers_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(
            err.contains(
                "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
            )
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_floor_mode_adaptive_is_parsed() {
        let toml = r#"
            [general]
            me_floor_mode = "adaptive"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_floor_mode_adaptive_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_floor_mode, MeFloorMode::Adaptive);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_adaptive_floor_max_active_writers_per_core_zero_is_rejected() {
        let toml = r#"
            [general]
            me_adaptive_floor_max_active_writers_per_core = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_adaptive_floor_max_active_per_core_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_adaptive_floor_max_active_writers_per_core must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_adaptive_floor_max_warm_writers_global_zero_is_rejected() {
        let toml = r#"
            [general]
            me_adaptive_floor_max_warm_writers_global = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_adaptive_floor_max_warm_global_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_adaptive_floor_max_warm_writers_global must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upstream_connect_retry_attempts_zero_is_rejected() {
        let toml = r#"
            [general]
            upstream_connect_retry_attempts = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_upstream_connect_retry_attempts_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.upstream_connect_retry_attempts must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upstream_unhealthy_fail_threshold_zero_is_rejected() {
        let toml = r#"
            [general]
            upstream_unhealthy_fail_threshold = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_upstream_unhealthy_fail_threshold_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.upstream_unhealthy_fail_threshold must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rpc_proxy_req_every_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            rpc_proxy_req_every = 9

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_rpc_proxy_req_every_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.rpc_proxy_req_every must be 0 or within [10, 300]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rpc_proxy_req_every_zero_and_valid_range_are_accepted() {
        let toml_zero = r#"
            [general]
            rpc_proxy_req_every = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path_zero = dir.join("telemt_rpc_proxy_req_every_zero_ok_test.toml");
        std::fs::write(&path_zero, toml_zero).unwrap();
        let cfg_zero = ProxyConfig::load(&path_zero).unwrap();
        assert_eq!(cfg_zero.general.rpc_proxy_req_every, 0);
        let _ = std::fs::remove_file(path_zero);

        let toml_valid = r#"
            [general]
            rpc_proxy_req_every = 40

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let path_valid = dir.join("telemt_rpc_proxy_req_every_valid_ok_test.toml");
        std::fs::write(&path_valid, toml_valid).unwrap();
        let cfg_valid = ProxyConfig::load(&path_valid).unwrap();
        assert_eq!(cfg_valid.general.rpc_proxy_req_every, 40);
        let _ = std::fs::remove_file(path_valid);
    }

    #[test]
    fn me_route_no_writer_wait_ms_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_route_no_writer_wait_ms = 5

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_no_writer_wait_ms_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_route_no_writer_wait_ms must be within [10, 5000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_route_no_writer_mode_is_parsed() {
        let toml = r#"
            [general]
            me_route_no_writer_mode = "inline_recovery_legacy"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_no_writer_mode_parse_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.me_route_no_writer_mode,
            crate::config::MeRouteNoWriterMode::InlineRecoveryLegacy
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_config_cache_paths_empty_are_rejected() {
        let toml = r#"
            [general]
            proxy_config_v4_cache_path = "   "

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_proxy_config_v4_cache_path_empty_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.proxy_config_v4_cache_path cannot be empty"));
        let _ = std::fs::remove_file(path);

        let toml_v6 = r#"
            [general]
            proxy_config_v6_cache_path = ""

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let path_v6 = dir.join("telemt_proxy_config_v6_cache_path_empty_test.toml");
        std::fs::write(&path_v6, toml_v6).unwrap();
        let err_v6 = ProxyConfig::load(&path_v6).unwrap_err().to_string();
        assert!(err_v6.contains("general.proxy_config_v6_cache_path cannot be empty"));
        let _ = std::fs::remove_file(path_v6);
    }

    #[test]
    fn me_hardswap_warmup_defaults_are_set() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_defaults_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.me_hardswap_warmup_delay_min_ms,
            default_me_hardswap_warmup_delay_min_ms()
        );
        assert_eq!(
            cfg.general.me_hardswap_warmup_delay_max_ms,
            default_me_hardswap_warmup_delay_max_ms()
        );
        assert_eq!(
            cfg.general.me_hardswap_warmup_extra_passes,
            default_me_hardswap_warmup_extra_passes()
        );
        assert_eq!(
            cfg.general.me_hardswap_warmup_pass_backoff_base_ms,
            default_me_hardswap_warmup_pass_backoff_base_ms()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_delay_range_is_validated() {
        let toml = r#"
            [general]
            me_hardswap_warmup_delay_min_ms = 2001
            me_hardswap_warmup_delay_max_ms = 2000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_delay_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "general.me_hardswap_warmup_delay_min_ms must be <= general.me_hardswap_warmup_delay_max_ms"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_delay_max_zero_is_rejected() {
        let toml = r#"
            [general]
            me_hardswap_warmup_delay_max_ms = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_delay_max_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_hardswap_warmup_delay_max_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_extra_passes_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_hardswap_warmup_extra_passes = 11

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_extra_passes_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_hardswap_warmup_extra_passes must be within [0, 10]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_pass_backoff_zero_is_rejected() {
        let toml = r#"
            [general]
            me_hardswap_warmup_pass_backoff_base_ms = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_backoff_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_hardswap_warmup_pass_backoff_base_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_config_stable_snapshots_zero_is_rejected() {
        let toml = r#"
            [general]
            me_config_stable_snapshots = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_config_stable_snapshots_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_config_stable_snapshots must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_secret_stable_snapshots_zero_is_rejected() {
        let toml = r#"
            [general]
            proxy_secret_stable_snapshots = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_proxy_secret_stable_snapshots_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.proxy_secret_stable_snapshots must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_secret_len_max_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            proxy_secret_len_max = 16

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_proxy_secret_len_max_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.proxy_secret_len_max must be within [32, 4096]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_pool_min_fresh_ratio_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_pool_min_fresh_ratio = 1.5

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_pool_min_ratio_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_pool_min_fresh_ratio must be within [0.0, 1.0]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_minimal_runtime_cache_ttl_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            minimal_runtime_cache_ttl_ms = 70000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_minimal_runtime_cache_ttl_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.minimal_runtime_cache_ttl_ms must be within [0, 60000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_runtime_edge_cache_ttl_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            runtime_edge_cache_ttl_ms = 70000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_runtime_edge_cache_ttl_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.runtime_edge_cache_ttl_ms must be within [0, 60000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_runtime_edge_top_n_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            runtime_edge_top_n = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_runtime_edge_top_n_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.runtime_edge_top_n must be within [1, 1000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_runtime_edge_events_capacity_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            runtime_edge_events_capacity = 8

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_runtime_edge_events_capacity_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.runtime_edge_events_capacity must be within [16, 4096]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn force_close_bumped_when_below_drain_ttl() {
        let toml = r#"
            [general]
            me_pool_drain_ttl_secs = 90
            me_reinit_drain_timeout_secs = 30

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_force_close_bump_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 90);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_ad_tag_is_disabled_during_load() {
        let toml = r#"
            [general]
            ad_tag = "not_hex"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_invalid_ad_tag_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert!(cfg.general.ad_tag.is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn valid_ad_tag_is_preserved_during_load() {
        let toml = r#"
            [general]
            ad_tag = "00112233445566778899aabbccddeeff"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_valid_ad_tag_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.ad_tag.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_user_ad_tag_reports_access_user_ad_tags_key() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            alice = "00000000000000000000000000000000"

            [access.user_ad_tags]
            alice = "not_hex"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_invalid_user_ad_tag_message_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("access.user_ad_tags['alice'] must be exactly 32 hex characters"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_dns_override_is_rejected() {
        let toml = r#"
            [network]
            dns_overrides = ["example.com:443:2001:db8::10"]

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_invalid_dns_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("must be bracketed"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn valid_dns_override_is_accepted() {
        let toml = r#"
            [network]
            dns_overrides = ["example.com:443:127.0.0.1", "example.net:443:[2001:db8::10]"]

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_valid_dns_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.network.dns_overrides.len(), 2);
        let _ = std::fs::remove_file(path);
    }

    // ============= Security / Adversarial Tests =============

    #[test]
    fn is_safe_include_path_blocks_parent_dir_traversal() {
        assert!(!is_safe_include_path("../etc/passwd"));
        assert!(!is_safe_include_path("../../etc/passwd"));
        assert!(!is_safe_include_path("subdir/../../../etc/shadow"));
        assert!(!is_safe_include_path(".."));
    }

    #[test]
    fn is_safe_include_path_blocks_absolute_paths() {
        assert!(!is_safe_include_path("/etc/passwd"));
        assert!(!is_safe_include_path("/root/.ssh/id_rsa"));
    }

    #[test]
    fn is_safe_include_path_allows_relative_safe_paths() {
        assert!(is_safe_include_path("config.toml"));
        assert!(is_safe_include_path("subdir/extra.toml"));
        assert!(is_safe_include_path("a/b/c/config.toml"));
    }

    #[test]
    fn preprocess_includes_rejects_traversal_path() {
        let dir = std::env::temp_dir();
        let main_path = dir.join("telemt_traversal_test_main.toml");
        std::fs::write(&main_path, "include = \"../../etc/passwd\"\n").unwrap();
        let result = ProxyConfig::load(&main_path);
        let _ = std::fs::remove_file(&main_path);
        assert!(result.is_err(), "Path traversal include must be rejected");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("disallowed") || err_str.contains("Include"),
            "Error must describe include restriction, got: {err_str}"
        );
    }

    #[test]
    fn preprocess_includes_rejects_absolute_path() {
        let dir = std::env::temp_dir();
        let main_path = dir.join("telemt_absolute_include_test.toml");
        std::fs::write(&main_path, "include = \"/etc/hostname\"\n").unwrap();
        let result = ProxyConfig::load(&main_path);
        let _ = std::fs::remove_file(&main_path);
        assert!(result.is_err(), "Absolute include path must be rejected");
    }

    #[test]
    fn preprocess_includes_depth_limit_enforced() {
        let dir = std::env::temp_dir();
        // 12-file chain: depth limit is 10, so this must fail.
        let files: Vec<_> = (0..12)
            .map(|i| dir.join(format!("telemt_depth_test_{i}.toml")))
            .collect();
        for i in 0..11 {
            let next = files[i + 1].file_name().unwrap().to_string_lossy().into_owned();
            std::fs::write(&files[i], format!("include = \"{next}\"\n")).unwrap();
        }
        std::fs::write(&files[11], "[general]\n").unwrap();
        let result = ProxyConfig::load(&files[0]);
        for f in &files {
            let _ = std::fs::remove_file(f);
        }
        assert!(result.is_err(), "Include depth > 10 must be rejected");
    }

    #[test]
    fn validate_warns_for_default_zero_secret_but_does_not_fail() {
        // The default AccessConfig ships with the all-zero secret.
        // validate() must warn but not reject, so deployments using a known
        // test value are not silently broken without an explicit hardening step.
        let cfg = ProxyConfig::default();
        assert!(
            cfg.validate().is_ok(),
            "validate() must not fail for the default all-zero secret (warn only)"
        );
    }

    #[test]
    fn load_rejects_non_hex_secret() {
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_nonhex_secret_test.toml");
        let toml = "[censorship]\ntls_domain = \"example.com\"\n[access.users]\nuser = \"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\"\n";
        std::fs::write(&path, toml).unwrap();
        let result = ProxyConfig::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "Non-hex secret must be rejected");
    }

    #[test]
    fn load_rejects_31_char_secret() {
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_short31_secret_test.toml");
        let toml = "[censorship]\ntls_domain = \"example.com\"\n[access.users]\nuser = \"0000000000000000000000000000000\"\n";
        std::fs::write(&path, toml).unwrap();
        let result = ProxyConfig::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "31-char secret must be rejected");
    }

    #[test]
    fn load_rejects_33_char_secret() {
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_long33_secret_test.toml");
        let toml = "[censorship]\ntls_domain = \"example.com\"\n[access.users]\nuser = \"000000000000000000000000000000000\"\n";
        std::fs::write(&path, toml).unwrap();
        let result = ProxyConfig::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "33-char secret must be rejected");
    }

    #[test]
    fn validate_rejects_tls_domain_with_spaces() {
        let mut cfg = ProxyConfig::default();
        cfg.access.users.clear();
        cfg.access.users.insert("u".into(), "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".into());
        cfg.censorship.tls_domain = "bad domain".into();
        assert!(cfg.validate().is_err(), "tls_domain with spaces must fail validate()");
    }

    #[test]
    fn validate_rejects_tls_domain_with_slash() {
        let mut cfg = ProxyConfig::default();
        cfg.access.users.clear();
        cfg.access.users.insert("u".into(), "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".into());
        cfg.censorship.tls_domain = "bad/domain".into();
        assert!(cfg.validate().is_err(), "tls_domain with '/' must fail validate()");
    }

    #[test]
    fn include_path_absolute_is_rejected() {
        // Absolute include paths break the containment guarantee — must always be rejected.
        assert!(!is_safe_include_path("/etc/passwd"));
        assert!(!is_safe_include_path("/absolute/path/to/file.toml"));
        assert!(!is_safe_include_path("//double-slash"));
    }

    #[test]
    fn include_path_parent_dir_traversal_is_rejected() {
        // Any path containing `..` as a component allows escape from the config directory.
        assert!(!is_safe_include_path("../sibling.toml"));
        assert!(!is_safe_include_path("../../escape.toml"));
        assert!(!is_safe_include_path("subdir/../../etc/passwd"));
        assert!(!is_safe_include_path("./sub/../../../escape"));
    }

    #[test]
    fn include_path_safe_relative_paths_are_accepted() {
        assert!(is_safe_include_path("extra.toml"));
        assert!(is_safe_include_path("subdir/nested.toml"));
        assert!(is_safe_include_path("a/b/c/deep.toml"));
    }

    #[test]
    fn include_depth_limit_blocks_excessive_nesting() {
        // Build a chain of 12 temp files (depth 0 → 11), triggering the depth > 10 guard.
        // file_0 includes file_1, file_1 includes file_2, ..., file_10 includes file_11.
        // The call with file_11 at depth=11 must return an error.
        let dir = std::env::temp_dir();
        let prefix = "telemt_include_depth_test_";

        for i in (0usize..=11).rev() {
            let content = if i == 11 {
                "[general]\n".to_string()
            } else {
                format!("include = \"{prefix}{}.toml\"\n", i + 1)
            };
            let path = dir.join(format!("{prefix}{i}.toml"));
            std::fs::write(&path, content).unwrap();
        }

        let root = dir.join(format!("{prefix}0.toml"));
        let root_content = std::fs::read_to_string(&root).unwrap();
        let mut sf = BTreeSet::new();
        let result = preprocess_includes(&root_content, &dir, 0, &mut sf);

        for i in 0usize..=11 {
            let _ = std::fs::remove_file(dir.join(format!("{prefix}{i}.toml")));
        }

        assert!(result.is_err(), "Include chain deeper than 10 levels must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("depth") || msg.contains("10"),
            "Error must mention depth limit, got: {msg}"
        );
    }

    #[test]
    fn include_depth_10_is_accepted_depth_11_is_rejected() {
        // Exactly 10 levels of nesting must succeed; 11 must fail.
        // Chain: root (depth 0) → file_1 → ... → file_10 (terminal, 10 includes deep).
        let dir = std::env::temp_dir();
        let prefix = "telemt_depth10_test_";

        for i in (0usize..=10).rev() {
            let content = if i == 10 {
                "[general]\n".to_string()
            } else {
                format!("include = \"{prefix}{}.toml\"\n", i + 1)
            };
            let path = dir.join(format!("{prefix}{i}.toml"));
            std::fs::write(&path, content).unwrap();
        }

        let root = dir.join(format!("{prefix}0.toml"));
        let root_content = std::fs::read_to_string(&root).unwrap();
        let mut sf = BTreeSet::new();
        let result = preprocess_includes(&root_content, &dir, 0, &mut sf);

        for i in 0usize..=10 {
            let _ = std::fs::remove_file(dir.join(format!("{prefix}{i}.toml")));
        }

        assert!(result.is_ok(), "Exactly 10 levels of nesting must be accepted, got: {:?}", result.err());
    }

    #[test]
    fn load_rejects_secret_with_uppercase_mixed_but_valid_hex() {
        // Mixed-case hex is valid for user secrets (is_ascii_hexdigit accepts A-F).
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_mixedcase_secret_test.toml");
        let toml = "[censorship]\ntls_domain = \"example.com\"\n[access.users]\nuser = \"AABBCCDDEEFF00112233445566778899\"\n";
        std::fs::write(&path, toml).unwrap();
        let result = ProxyConfig::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_ok(), "Valid 32-char mixed-case hex secret must be accepted");
    }

    #[test]
    fn load_rejects_secret_with_special_characters() {
        // Shell-injection or SQL-style characters in user secrets must be caught by hex validation.
        let dir = std::env::temp_dir();
        let cases = [
            ("semicolon", "0000000000000000000000000000000;"),
            ("quote",     "0000000000000000000000000000000'"),
            ("slash",     "0000000000000000000000000000000/"),
            ("null",      "00000000000000000000000000000000\x00"),
        ];
        for (name, secret) in cases {
            let path = dir.join(format!("telemt_special_secret_{name}_test.toml"));
            let toml = format!(
                "[censorship]\ntls_domain = \"example.com\"\n[access.users]\nuser = \"{secret}\"\n"
            );
            std::fs::write(&path, &toml).unwrap();
            let result = ProxyConfig::load(&path);
            let _ = std::fs::remove_file(&path);
            assert!(
                result.is_err(),
                "Secret with special char '{name}' must be rejected, but was accepted"
            );
        }
    }

    #[test]
    fn max_connections_zero_is_rejected() {
        let toml = r#"
            [server]
            max_connections = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_max_connections_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.max_connections must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn max_connections_nonzero_is_accepted() {
        let toml = r#"
            [server]
            max_connections = 1

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_max_connections_one_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.server.max_connections, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_init_retry_backoff_base_zero_is_rejected() {
        let toml = r#"
            [general]
            me_init_retry_backoff_base_ms = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_backoff_base_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_init_retry_backoff_base_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_init_retry_backoff_cap_less_than_base_is_rejected() {
        let toml = r#"
            [general]
            me_init_retry_backoff_base_ms = 5000
            me_init_retry_backoff_cap_ms = 3000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_backoff_cap_lt_base_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_init_retry_backoff_cap_ms must be >= me_init_retry_backoff_base_ms"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_init_retry_backoff_cap_equal_to_base_is_accepted() {
        // cap == base is valid: every retry waits exactly base milliseconds.
        let toml = r#"
            [general]
            me_init_retry_backoff_base_ms = 3000
            me_init_retry_backoff_cap_ms = 3000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_backoff_cap_eq_base_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_init_retry_backoff_base_ms, 3000);
        assert_eq!(cfg.general.me_init_retry_backoff_cap_ms, 3000);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_init_retry_backoff_defaults_are_valid() {
        let default_cfg = GeneralConfig::default();
        assert!(default_cfg.me_init_retry_backoff_base_ms > 0);
        assert!(default_cfg.me_init_retry_backoff_cap_ms >= default_cfg.me_init_retry_backoff_base_ms);
    }
}
