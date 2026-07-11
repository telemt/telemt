#![allow(deprecated)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngExt;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{ProxyError, Result};

use super::defaults::*;
use super::types::*;

// Domain names, mask targets, and legacy scalar normalization helpers.
mod normalize;
// Include preprocessing and rendered config metadata helpers.
mod includes;
// Strict-config unknown key detection and suggestions.
mod strict_keys;
// Precomputed user authentication data for handshake hot paths.
mod runtime_auth;
// Post-deserialization validation helpers.
mod validation;

use self::includes::{hash_rendered_snapshot, normalize_config_path, preprocess_includes};
use self::normalize::{
    is_valid_ad_tag, is_valid_tls_domain_name, normalize_domain_to_ascii,
    normalize_exclusive_mask_target, normalize_mask_host_to_ascii, parse_exclusive_mask_target,
    push_unique_nonempty, sanitize_ad_tag,
};
pub(crate) use self::runtime_auth::UserAuthSnapshot;
use self::strict_keys::handle_unknown_config_keys;
use self::validation::{
    normalize_upstream_family_policy, validate_logging_config, validate_network_cfg,
    validate_upstreams,
};

const MAX_ME_WRITER_CMD_CHANNEL_CAPACITY: usize = 16_384;
const MAX_ME_WRITER_BYTE_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const MAX_ME_ROUTE_CHANNEL_CAPACITY: usize = 8_192;
const MAX_ME_C2ME_CHANNEL_CAPACITY: usize = 8_192;
const MIN_DIRECT_RELAY_BUFFER_BUDGET_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIRECT_RELAY_BUFFER_BUDGET_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MIN_MAX_CLIENT_FRAME_BYTES: usize = 4 * 1024;
const MAX_MAX_CLIENT_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_API_REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct LoadedConfig {
    pub(crate) config: ProxyConfig,
    pub(crate) source_files: Vec<PathBuf>,
    pub(crate) rendered_hash: u64,
}

/// Main runtime configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    /// General runtime options shared across proxy subsystems.
    #[serde(default)]
    pub general: GeneralConfig,

    /// Runtime logging destination, rotation, and retention configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Network binding, routing, and socket-level configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Server-side listener, fallback, and API configuration.
    #[serde(default)]
    pub server: ServerConfig,

    /// Timeout values used by client, fallback, and upstream operations.
    #[serde(default)]
    pub timeouts: TimeoutsConfig,

    /// Anti-censorship behavior and traffic shaping configuration.
    #[serde(default)]
    pub censorship: AntiCensorshipConfig,

    /// User authentication secrets and admission policy.
    #[serde(default)]
    pub access: AccessConfig,

    /// Telegram upstream endpoint configuration.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,

    /// Optional proxy link rendering controls.
    #[serde(default)]
    pub show_link: ShowLink,

    /// DC address overrides for non-standard DCs (CDN, media, test, etc.)
    /// Keys are DC indices as strings, values are one or more "ip:port" addresses.
    /// Matches the C implementation's `proxy_for <dc_id> <ip>:<port>` config directive.
    /// Example in config.toml:
    ///   [dc_overrides]
    ///   "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    #[serde(default, deserialize_with = "deserialize_dc_overrides")]
    pub dc_overrides: HashMap<String, Vec<String>>,

    /// Default DC index (1-5) for unmapped non-standard DCs.
    /// Matches the C implementation's `default <dc_id>` config directive.
    /// If not set, defaults to 2 (matching Telegram's official `default 2;` in proxy-multi.conf).
    #[serde(default)]
    pub default_dc: Option<u8>,

    /// Precomputed authentication snapshot for handshake hot paths.
    #[serde(skip)]
    pub(crate) runtime_user_auth: Option<Arc<UserAuthSnapshot>>,
}

impl ProxyConfig {
    /// Loads runtime configuration from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_metadata(path).map(|loaded| loaded.config)
    }

    pub(crate) fn load_with_metadata<P: AsRef<Path>>(path: P) -> Result<LoadedConfig> {
        let path = path.as_ref();
        let content =
            std::fs::read_to_string(path).map_err(|e| ProxyError::Config(e.to_string()))?;
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let mut source_files = BTreeSet::new();
        source_files.insert(normalize_config_path(path));
        let processed = preprocess_includes(&content, base_dir, 0, &mut source_files)?;

        let parsed_toml: toml::Value =
            toml::from_str(&processed).map_err(|e| ProxyError::Config(e.to_string()))?;
        handle_unknown_config_keys(&parsed_toml)?;
        let general_table = parsed_toml
            .get("general")
            .and_then(|value| value.as_table());
        let network_table = parsed_toml
            .get("network")
            .and_then(|value| value.as_table());
        let server_table = parsed_toml.get("server").and_then(|value| value.as_table());
        let conntrack_control_table = server_table
            .and_then(|table| table.get("conntrack_control"))
            .and_then(|value| value.as_table());
        let update_every_is_explicit = general_table
            .map(|table| table.contains_key("update_every"))
            .unwrap_or(false);
        let beobachten_is_explicit = general_table
            .map(|table| table.contains_key("beobachten"))
            .unwrap_or(false);
        let beobachten_minutes_is_explicit = general_table
            .map(|table| table.contains_key("beobachten_minutes"))
            .unwrap_or(false);
        let beobachten_flush_secs_is_explicit = general_table
            .map(|table| table.contains_key("beobachten_flush_secs"))
            .unwrap_or(false);
        let beobachten_file_is_explicit = general_table
            .map(|table| table.contains_key("beobachten_file"))
            .unwrap_or(false);
        let legacy_secret_is_explicit = general_table
            .map(|table| table.contains_key("proxy_secret_auto_reload_secs"))
            .unwrap_or(false);
        let legacy_config_is_explicit = general_table
            .map(|table| table.contains_key("proxy_config_auto_reload_secs"))
            .unwrap_or(false);
        let legacy_top_level_beobachten = parsed_toml.get("beobachten").cloned();
        let legacy_top_level_beobachten_minutes = parsed_toml.get("beobachten_minutes").cloned();
        let legacy_top_level_beobachten_flush_secs =
            parsed_toml.get("beobachten_flush_secs").cloned();
        let legacy_top_level_beobachten_file = parsed_toml.get("beobachten_file").cloned();
        let stun_servers_is_explicit = network_table
            .map(|table| table.contains_key("stun_servers"))
            .unwrap_or(false);
        let inline_conntrack_control_is_explicit = conntrack_control_table
            .map(|table| table.contains_key("inline_conntrack_control"))
            .unwrap_or(false);

        let mut config: ProxyConfig = parsed_toml
            .try_into()
            .map_err(|e| ProxyError::Config(e.to_string()))?;
        config
            .server
            .conntrack_control
            .inline_conntrack_control_explicit = inline_conntrack_control_is_explicit;

        if !update_every_is_explicit && (legacy_secret_is_explicit || legacy_config_is_explicit) {
            config.general.update_every = None;
        }

        // Backward compatibility: legacy top-level beobachten* keys.
        // Prefer `[general].*` when both are present.
        let mut legacy_beobachten_applied = false;
        if !beobachten_is_explicit && let Some(value) = legacy_top_level_beobachten.as_ref() {
            let parsed = value.as_bool().ok_or_else(|| {
                ProxyError::Config("beobachten (top-level) must be a boolean".to_string())
            })?;
            config.general.beobachten = parsed;
            legacy_beobachten_applied = true;
        }
        if !beobachten_minutes_is_explicit
            && let Some(value) = legacy_top_level_beobachten_minutes.as_ref()
        {
            let raw = value.as_integer().ok_or_else(|| {
                ProxyError::Config("beobachten_minutes (top-level) must be an integer".to_string())
            })?;
            let parsed = u64::try_from(raw).map_err(|_| {
                ProxyError::Config(
                    "beobachten_minutes (top-level) must be within u64 range".to_string(),
                )
            })?;
            config.general.beobachten_minutes = parsed;
            legacy_beobachten_applied = true;
        }
        if !beobachten_flush_secs_is_explicit
            && let Some(value) = legacy_top_level_beobachten_flush_secs.as_ref()
        {
            let raw = value.as_integer().ok_or_else(|| {
                ProxyError::Config(
                    "beobachten_flush_secs (top-level) must be an integer".to_string(),
                )
            })?;
            let parsed = u64::try_from(raw).map_err(|_| {
                ProxyError::Config(
                    "beobachten_flush_secs (top-level) must be within u64 range".to_string(),
                )
            })?;
            config.general.beobachten_flush_secs = parsed;
            legacy_beobachten_applied = true;
        }
        if !beobachten_file_is_explicit
            && let Some(value) = legacy_top_level_beobachten_file.as_ref()
        {
            let parsed = value.as_str().ok_or_else(|| {
                ProxyError::Config("beobachten_file (top-level) must be a string".to_string())
            })?;
            config.general.beobachten_file = parsed.to_string();
            legacy_beobachten_applied = true;
        }
        if legacy_beobachten_applied {
            warn!("top-level beobachten* keys are deprecated; use general.beobachten* instead");
        }

        let legacy_nat_stun = config.general.middle_proxy_nat_stun.take();
        let legacy_nat_stun_servers =
            std::mem::take(&mut config.general.middle_proxy_nat_stun_servers);
        let legacy_nat_stun_used = legacy_nat_stun.is_some() || !legacy_nat_stun_servers.is_empty();
        if stun_servers_is_explicit {
            let mut explicit_stun_servers = Vec::new();
            for stun in std::mem::take(&mut config.network.stun_servers) {
                push_unique_nonempty(&mut explicit_stun_servers, stun);
            }
            config.network.stun_servers = explicit_stun_servers;

            if legacy_nat_stun_used {
                warn!(
                    "general.middle_proxy_nat_stun and general.middle_proxy_nat_stun_servers are ignored because network.stun_servers is explicitly set"
                );
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
                warn!(
                    "general.middle_proxy_nat_stun and general.middle_proxy_nat_stun_servers are deprecated; use network.stun_servers"
                );
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

        if config.general.tg_connect == 0 {
            return Err(ProxyError::Config(
                "general.tg_connect must be > 0".to_string(),
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

        if config.timeouts.client_handshake == 0 {
            return Err(ProxyError::Config(
                "timeouts.client_handshake must be > 0".to_string(),
            ));
        }

        let handshake_timeout_ms = config
            .timeouts
            .client_handshake
            .checked_mul(1000)
            .ok_or_else(|| {
                ProxyError::Config(
                    "timeouts.client_handshake is too large to validate milliseconds budget"
                        .to_string(),
                )
            })?;

        if config.censorship.server_hello_delay_max_ms >= handshake_timeout_ms {
            return Err(ProxyError::Config(
                "censorship.server_hello_delay_max_ms must be < timeouts.client_handshake * 1000"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_bucket_floor_bytes == 0 {
            return Err(ProxyError::Config(
                "censorship.mask_shape_bucket_floor_bytes must be > 0".to_string(),
            ));
        }

        if config.censorship.mask_shape_bucket_cap_bytes
            < config.censorship.mask_shape_bucket_floor_bytes
        {
            return Err(ProxyError::Config(
                "censorship.mask_shape_bucket_cap_bytes must be >= censorship.mask_shape_bucket_floor_bytes"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_above_cap_blur && !config.censorship.mask_shape_hardening {
            return Err(ProxyError::Config(
                "censorship.mask_shape_above_cap_blur requires censorship.mask_shape_hardening = true"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_hardening_aggressive_mode
            && !config.censorship.mask_shape_hardening
        {
            return Err(ProxyError::Config(
                "censorship.mask_shape_hardening_aggressive_mode requires censorship.mask_shape_hardening = true"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_above_cap_blur
            && config.censorship.mask_shape_above_cap_blur_max_bytes == 0
        {
            return Err(ProxyError::Config(
                "censorship.mask_shape_above_cap_blur_max_bytes must be > 0 when censorship.mask_shape_above_cap_blur is enabled"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_above_cap_blur_max_bytes > 1_048_576 {
            return Err(ProxyError::Config(
                "censorship.mask_shape_above_cap_blur_max_bytes must be <= 1048576".to_string(),
            ));
        }

        if config.censorship.mask_relay_max_bytes > 67_108_864 {
            return Err(ProxyError::Config(
                "censorship.mask_relay_max_bytes must be <= 67108864".to_string(),
            ));
        }

        if !(5..=50).contains(&config.censorship.mask_classifier_prefetch_timeout_ms) {
            return Err(ProxyError::Config(
                "censorship.mask_classifier_prefetch_timeout_ms must be within [5, 50]".to_string(),
            ));
        }

        if config.censorship.mask_timing_normalization_ceiling_ms
            < config.censorship.mask_timing_normalization_floor_ms
        {
            return Err(ProxyError::Config(
                "censorship.mask_timing_normalization_ceiling_ms must be >= censorship.mask_timing_normalization_floor_ms"
                    .to_string(),
            ));
        }

        if config.censorship.mask_timing_normalization_enabled
            && config.censorship.mask_timing_normalization_floor_ms == 0
        {
            return Err(ProxyError::Config(
                "censorship.mask_timing_normalization_floor_ms must be > 0 when censorship.mask_timing_normalization_enabled is true"
                    .to_string(),
            ));
        }

        if config.censorship.mask_timing_normalization_ceiling_ms > 60_000 {
            return Err(ProxyError::Config(
                "censorship.mask_timing_normalization_ceiling_ms must be <= 60000".to_string(),
            ));
        }

        if config.timeouts.relay_client_idle_soft_secs == 0 {
            return Err(ProxyError::Config(
                "timeouts.relay_client_idle_soft_secs must be > 0".to_string(),
            ));
        }

        if config.timeouts.relay_client_idle_hard_secs == 0 {
            return Err(ProxyError::Config(
                "timeouts.relay_client_idle_hard_secs must be > 0".to_string(),
            ));
        }

        if config.timeouts.relay_client_idle_hard_secs < config.timeouts.relay_client_idle_soft_secs
        {
            return Err(ProxyError::Config(
                "timeouts.relay_client_idle_hard_secs must be >= timeouts.relay_client_idle_soft_secs"
                    .to_string(),
            ));
        }

        if config
            .timeouts
            .relay_idle_grace_after_downstream_activity_secs
            > config.timeouts.relay_client_idle_hard_secs
        {
            return Err(ProxyError::Config(
                "timeouts.relay_idle_grace_after_downstream_activity_secs must be <= timeouts.relay_client_idle_hard_secs"
                    .to_string(),
            ));
        }

        if config.general.me_writer_cmd_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_writer_cmd_channel_capacity must be > 0".to_string(),
            ));
        }
        if config.general.me_writer_cmd_channel_capacity > MAX_ME_WRITER_CMD_CHANNEL_CAPACITY {
            return Err(ProxyError::Config(format!(
                "general.me_writer_cmd_channel_capacity must be within [1, {MAX_ME_WRITER_CMD_CHANNEL_CAPACITY}]"
            )));
        }

        if config.general.me_route_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_route_channel_capacity must be > 0".to_string(),
            ));
        }
        if config.general.me_route_channel_capacity > MAX_ME_ROUTE_CHANNEL_CAPACITY {
            return Err(ProxyError::Config(format!(
                "general.me_route_channel_capacity must be within [1, {MAX_ME_ROUTE_CHANNEL_CAPACITY}]"
            )));
        }

        if config.general.me_c2me_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_c2me_channel_capacity must be > 0".to_string(),
            ));
        }
        if config.general.me_c2me_channel_capacity > MAX_ME_C2ME_CHANNEL_CAPACITY {
            return Err(ProxyError::Config(format!(
                "general.me_c2me_channel_capacity must be within [1, {MAX_ME_C2ME_CHANNEL_CAPACITY}]"
            )));
        }

        if !(MIN_MAX_CLIENT_FRAME_BYTES..=MAX_MAX_CLIENT_FRAME_BYTES)
            .contains(&config.general.max_client_frame)
        {
            return Err(ProxyError::Config(format!(
                "general.max_client_frame must be within [{MIN_MAX_CLIENT_FRAME_BYTES}, {MAX_MAX_CLIENT_FRAME_BYTES}]"
            )));
        }

        let min_writer_byte_budget =
            minimum_me_writer_byte_budget_bytes(config.general.max_client_frame);
        if config.general.me_writer_byte_budget_bytes % ME_WRITER_BYTE_PERMIT_UNIT_BYTES != 0 {
            return Err(ProxyError::Config(format!(
                "general.me_writer_byte_budget_bytes must be a multiple of {ME_WRITER_BYTE_PERMIT_UNIT_BYTES}"
            )));
        }
        if !(min_writer_byte_budget..=MAX_ME_WRITER_BYTE_BUDGET_BYTES)
            .contains(&config.general.me_writer_byte_budget_bytes)
        {
            return Err(ProxyError::Config(format!(
                "general.me_writer_byte_budget_bytes must be within [{min_writer_byte_budget}, {MAX_ME_WRITER_BYTE_BUDGET_BYTES}] for general.max_client_frame={}",
                config.general.max_client_frame
            )));
        }

        if config.general.me_c2me_send_timeout_ms > 60_000 {
            return Err(ProxyError::Config(
                "general.me_c2me_send_timeout_ms must be within [0, 60000]".to_string(),
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

        if config.general.me_quota_soft_overshoot_bytes > 16 * 1024 * 1024 {
            return Err(ProxyError::Config(
                "general.me_quota_soft_overshoot_bytes must be within [0, 16777216]".to_string(),
            ));
        }

        if !(4096..=16 * 1024 * 1024)
            .contains(&config.general.me_d2c_frame_buf_shrink_threshold_bytes)
        {
            return Err(ProxyError::Config(
                "general.me_d2c_frame_buf_shrink_threshold_bytes must be within [4096, 16777216]"
                    .to_string(),
            ));
        }

        if !(4096..=1024 * 1024).contains(&config.general.direct_relay_copy_buf_c2s_bytes) {
            return Err(ProxyError::Config(
                "general.direct_relay_copy_buf_c2s_bytes must be within [4096, 1048576]"
                    .to_string(),
            ));
        }

        if !(8192..=2 * 1024 * 1024).contains(&config.general.direct_relay_copy_buf_s2c_bytes) {
            return Err(ProxyError::Config(
                "general.direct_relay_copy_buf_s2c_bytes must be within [8192, 2097152]"
                    .to_string(),
            ));
        }

        if config.general.direct_relay_buffer_budget_max_bytes != 0 {
            if config.general.direct_relay_buffer_budget_max_bytes
                % DIRECT_RELAY_BUFFER_BUDGET_UNIT_BYTES
                != 0
            {
                return Err(ProxyError::Config(format!(
                    "general.direct_relay_buffer_budget_max_bytes must be 0 or a multiple of {DIRECT_RELAY_BUFFER_BUDGET_UNIT_BYTES}"
                )));
            }
            if !(MIN_DIRECT_RELAY_BUFFER_BUDGET_BYTES..=MAX_DIRECT_RELAY_BUFFER_BUDGET_BYTES)
                .contains(&config.general.direct_relay_buffer_budget_max_bytes)
            {
                return Err(ProxyError::Config(format!(
                    "general.direct_relay_buffer_budget_max_bytes must be 0 or within [{MIN_DIRECT_RELAY_BUFFER_BUDGET_BYTES}, {MAX_DIRECT_RELAY_BUFFER_BUDGET_BYTES}]"
                )));
            }
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

        if config.general.me_pool_drain_soft_evict_grace_secs > 3600 {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_grace_secs must be within [0, 3600]".to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_per_writer == 0
            || config.general.me_pool_drain_soft_evict_per_writer > 16
        {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_per_writer must be within [1, 16]".to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_budget_per_core == 0
            || config.general.me_pool_drain_soft_evict_budget_per_core > 64
        {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_budget_per_core must be within [1, 64]"
                    .to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_cooldown_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_cooldown_ms must be > 0".to_string(),
            ));
        }

        if config.access.user_max_unique_ips_window_secs == 0 {
            return Err(ProxyError::Config(
                "access.user_max_unique_ips_window_secs must be > 0".to_string(),
            ));
        }

        for (user, limit) in &config.access.user_rate_limits {
            if limit.up_bps == 0 && limit.down_bps == 0 {
                return Err(ProxyError::Config(format!(
                    "access.user_rate_limits.{user} must set at least one non-zero direction"
                )));
            }
        }

        for (cidr, limit) in &config.access.cidr_rate_limits {
            if limit.up_bps == 0 && limit.down_bps == 0 {
                return Err(ProxyError::Config(format!(
                    "access.cidr_rate_limits.{cidr} must set at least one non-zero direction"
                )));
            }
        }
        let mut cidr_auto_templates = HashSet::new();
        for cidr in config.access.cidr_rate_limits.keys() {
            for template in cidr.auto_templates().into_iter().flatten() {
                if !cidr_auto_templates.insert(template) {
                    return Err(ProxyError::Config(format!(
                        "access.cidr_rate_limits.{cidr} duplicates normalized auto-template {template}"
                    )));
                }
            }
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
        if config.general.me_route_backpressure_base_timeout_ms > 5000 {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_base_timeout_ms must be within [1, 5000]"
                    .to_string(),
            ));
        }

        if config.general.me_route_backpressure_high_timeout_ms
            < config.general.me_route_backpressure_base_timeout_ms
        {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_timeout_ms must be >= general.me_route_backpressure_base_timeout_ms".to_string(),
            ));
        }
        if config.general.me_route_backpressure_high_timeout_ms > 5000 {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_timeout_ms must be within [1, 5000]"
                    .to_string(),
            ));
        }

        if !(1..=100).contains(&config.general.me_route_backpressure_high_watermark_pct) {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_watermark_pct must be within [1, 100]"
                    .to_string(),
            ));
        }

        if !(10..=5000).contains(&config.general.me_route_no_writer_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_no_writer_wait_ms must be within [10, 5000]".to_string(),
            ));
        }

        if !(50..=60_000).contains(&config.general.me_route_hybrid_max_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_hybrid_max_wait_ms must be within [50, 60000]".to_string(),
            ));
        }

        if !(1..=5000).contains(&config.general.me_route_blocking_send_timeout_ms) {
            return Err(ProxyError::Config(
                "general.me_route_blocking_send_timeout_ms must be within [1, 5000]".to_string(),
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

        if !(1..=MAX_API_REQUEST_BODY_LIMIT_BYTES)
            .contains(&config.server.api.request_body_limit_bytes)
        {
            return Err(ProxyError::Config(
                "server.api.request_body_limit_bytes must be within [1, 1048576]".to_string(),
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

        if config.server.listen_backlog == 0 || config.server.listen_backlog > i32::MAX as u32 {
            return Err(ProxyError::Config(format!(
                "server.listen_backlog must be within [1, {}]",
                i32::MAX
            )));
        }

        config
            .server
            .client_mss_value()
            .map_err(|error| ProxyError::Config(format!("server.client_mss {error}")))?;
        config
            .server
            .client_mss_bulk_value()
            .map_err(|error| ProxyError::Config(format!("server.client_mss_bulk {error}")))?;
        for (idx, listener) in config.server.listeners.iter().enumerate() {
            if listener.client_mss.is_some() {
                listener
                    .effective_client_mss(&config.server)
                    .map_err(|error| {
                        ProxyError::Config(format!("server.listeners[{idx}].client_mss {error}"))
                    })?;
            }
            if listener.synlimit_seconds == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_seconds must be > 0"
                )));
            }
            if listener.synlimit_hitcount == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_hitcount must be > 0"
                )));
            }
            if listener.synlimit_burst == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_burst must be > 0"
                )));
            }
            if listener.synlimit_ios_seconds == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_ios_seconds must be > 0"
                )));
            }
            if listener.synlimit_ios_hitcount == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_ios_hitcount must be > 0"
                )));
            }
            if listener.synlimit_ios_burst == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_ios_burst must be > 0"
                )));
            }
            if listener.synlimit_hashlimit_expire_ms == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_hashlimit_expire_ms must be > 0"
                )));
            }
            if listener.synlimit_hashlimit_size == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_hashlimit_size must be > 0"
                )));
            }
        }

        if config.server.accept_permit_timeout_ms > 60_000 {
            return Err(ProxyError::Config(
                "server.accept_permit_timeout_ms must be within [0, 60000]".to_string(),
            ));
        }

        if config.server.conntrack_control.pressure_high_watermark_pct == 0
            || config.server.conntrack_control.pressure_high_watermark_pct > 100
        {
            return Err(ProxyError::Config(
                "server.conntrack_control.pressure_high_watermark_pct must be within [1, 100]"
                    .to_string(),
            ));
        }

        if config.server.conntrack_control.pressure_low_watermark_pct
            >= config.server.conntrack_control.pressure_high_watermark_pct
        {
            return Err(ProxyError::Config(
                "server.conntrack_control.pressure_low_watermark_pct must be < pressure_high_watermark_pct"
                    .to_string(),
            ));
        }

        if config.server.conntrack_control.delete_budget_per_sec == 0 {
            return Err(ProxyError::Config(
                "server.conntrack_control.delete_budget_per_sec must be > 0".to_string(),
            ));
        }

        if matches!(config.server.conntrack_control.mode, ConntrackMode::Hybrid)
            && config
                .server
                .conntrack_control
                .hybrid_listener_ips
                .is_empty()
        {
            return Err(ProxyError::Config(
                "server.conntrack_control.hybrid_listener_ips must be non-empty in mode=hybrid"
                    .to_string(),
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

        config.censorship.tls_domain =
            normalize_domain_to_ascii(&config.censorship.tls_domain, "censorship.tls_domain")?;

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

        if let Some(mask_host) = config.censorship.mask_host.as_mut() {
            *mask_host = normalize_mask_host_to_ascii(mask_host, "censorship.mask_host")?;
        }

        for (domain, target) in &config.censorship.exclusive_mask {
            if !is_valid_tls_domain_name(domain) {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask domain: '{}'. Must be a valid domain name",
                    domain
                )));
            }
            if parse_exclusive_mask_target(target).is_none() {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                    domain, target
                )));
            }
        }

        // Normalize optional TLS fetch scope: whitespace-only values disable scoped routing.
        config.censorship.tls_fetch_scope = config.censorship.tls_fetch_scope.trim().to_string();

        if config.censorship.tls_fetch.profiles.is_empty() {
            config.censorship.tls_fetch.profiles = TlsFetchConfig::default().profiles;
        } else {
            let mut seen = HashSet::new();
            config
                .censorship
                .tls_fetch
                .profiles
                .retain(|profile| seen.insert(*profile));
        }

        if config.censorship.tls_fetch.attempt_timeout_ms == 0 {
            return Err(ProxyError::Config(
                "censorship.tls_fetch.attempt_timeout_ms must be > 0".to_string(),
            ));
        }
        if config.censorship.tls_fetch.total_budget_ms == 0 {
            return Err(ProxyError::Config(
                "censorship.tls_fetch.total_budget_ms must be > 0".to_string(),
            ));
        }

        // Merge primary + extra TLS domains, deduplicate (primary always first).
        if !config.censorship.tls_domains.is_empty() {
            let mut all = Vec::with_capacity(1 + config.censorship.tls_domains.len());
            all.push(config.censorship.tls_domain.clone());
            for d in std::mem::take(&mut config.censorship.tls_domains) {
                if !d.is_empty() {
                    let domain = normalize_domain_to_ascii(&d, "censorship.tls_domains entry")?;
                    if !all.contains(&domain) {
                        all.push(domain);
                    }
                }
            }
            // keep primary as tls_domain; store remaining back to tls_domains
            if all.len() > 1 {
                config.censorship.tls_domains = all[1..].to_vec();
            }
        }

        let mut exclusive_mask = HashMap::with_capacity(config.censorship.exclusive_mask.len());
        let mut exclusive_mask_targets =
            HashMap::with_capacity(config.censorship.exclusive_mask.len());
        for (domain, target) in std::mem::take(&mut config.censorship.exclusive_mask) {
            let domain = normalize_domain_to_ascii(&domain, "censorship.exclusive_mask domain")?;
            let target =
                normalize_exclusive_mask_target(&target, "censorship.exclusive_mask target")?;
            let Some((host, port)) = parse_exclusive_mask_target(&target) else {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                    domain, target
                )));
            };
            exclusive_mask_targets.insert(
                domain.clone(),
                ExclusiveMaskTarget {
                    host: host.to_string(),
                    port,
                },
            );
            exclusive_mask.insert(domain, target);
        }
        config.censorship.exclusive_mask = exclusive_mask;
        config.censorship.exclusive_mask_targets = exclusive_mask_targets;

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
            warn!(
                "IPv6 with Middle Proxy is experimental and may cause KDF address mismatch; consider disabling IPv6 or ME"
            );
        }

        // Random fake_cert_len only when default is in use.
        if !config.censorship.tls_emulation
            && config.censorship.fake_cert_len == default_fake_cert_len()
        {
            config.censorship.fake_cert_len = rand::rng().random_range(1024..4096);
        }

        // Resolve listen_tcp: explicit value wins, otherwise auto-detect.
        // If unix socket is set → TCP only when listen_addr_ipv4 or listeners are explicitly provided.
        // If no unix socket → TCP always (backward compat).
        let listen_tcp = config.server.listen_tcp.unwrap_or_else(|| {
            if config.server.listen_unix_sock.is_some() {
                // Unix socket present: TCP only if user explicitly set addresses or listeners.
                config.server.listen_addr_ipv4.is_some() || !config.server.listeners.is_empty()
            } else {
                true
            }
        });

        // Migration: Populate listeners if empty (skip when listen_tcp = false).
        if config.server.listeners.is_empty() && listen_tcp {
            let ipv4_str = config
                .server
                .listen_addr_ipv4
                .as_deref()
                .unwrap_or("0.0.0.0");
            if let Ok(ipv4) = ipv4_str.parse::<IpAddr>() {
                config.server.listeners.push(ListenerConfig {
                    ip: ipv4,
                    port: Some(config.server.port),
                    client_mss: None,
                    synlimit: SynLimitMode::default(),
                    synlimit_seconds: default_synlimit_seconds(),
                    synlimit_hitcount: default_synlimit_hitcount(),
                    synlimit_burst: default_synlimit_burst(),
                    synlimit_ios_seconds: default_synlimit_ios_seconds(),
                    synlimit_ios_hitcount: default_synlimit_ios_hitcount(),
                    synlimit_ios_burst: default_synlimit_ios_burst(),
                    synlimit_hashlimit_expire_ms: default_synlimit_hashlimit_expire_ms(),
                    synlimit_hashlimit_size: default_synlimit_hashlimit_size(),
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
                    port: Some(config.server.port),
                    client_mss: None,
                    synlimit: SynLimitMode::default(),
                    synlimit_seconds: default_synlimit_seconds(),
                    synlimit_hitcount: default_synlimit_hitcount(),
                    synlimit_burst: default_synlimit_burst(),
                    synlimit_ios_seconds: default_synlimit_ios_seconds(),
                    synlimit_ios_hitcount: default_synlimit_ios_hitcount(),
                    synlimit_ios_burst: default_synlimit_ios_burst(),
                    synlimit_hashlimit_expire_ms: default_synlimit_hashlimit_expire_ms(),
                    synlimit_hashlimit_size: default_synlimit_hashlimit_size(),
                    announce: None,
                    announce_ip: None,
                    proxy_protocol: None,
                    reuse_allow: false,
                });
            }
        }

        // Migration: listeners[].port fallback to legacy server.port.
        for listener in &mut config.server.listeners {
            if listener.port.is_none() {
                listener.port = Some(config.server.port);
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
                upstream_type: UpstreamType::Direct {
                    interface: None,
                    bind_addresses: None,
                    bindtodevice: None,
                },
                weight: 1,
                enabled: true,
                scopes: String::new(),
                selected_scope: String::new(),
                ipv4: None,
                ipv6: None,
                prefer: None,
            });
        }
        normalize_upstream_family_policy(&mut config);

        // Ensure default DC203 override is present.
        config
            .dc_overrides
            .entry("203".to_string())
            .or_insert_with(|| vec!["91.105.192.100:443".to_string()]);

        validate_logging_config(&config.logging)?;
        validate_upstreams(&config)?;
        config.rebuild_runtime_user_auth()?;

        Ok(LoadedConfig {
            config,
            source_files: source_files.into_iter().collect(),
            rendered_hash: hash_rendered_snapshot(&processed),
        })
    }

    pub(crate) fn rebuild_runtime_user_auth(&mut self) -> Result<()> {
        let snapshot = UserAuthSnapshot::from_users(&self.access.users)?;
        self.runtime_user_auth = Some(Arc::new(snapshot));
        Ok(())
    }

    pub(crate) fn runtime_user_auth(&self) -> Option<&UserAuthSnapshot> {
        self.runtime_user_auth.as_deref()
    }

    /// Validates cross-field configuration invariants after deserialization.
    pub fn validate(&self) -> Result<()> {
        if self.access.users.is_empty() {
            return Err(ProxyError::Config("No users configured".to_string()));
        }

        validate_logging_config(&self.logging)?;

        if !self.general.modes.classic && !self.general.modes.secure && !self.general.modes.tls {
            return Err(ProxyError::Config("No modes enabled".to_string()));
        }

        if !is_valid_tls_domain_name(&self.censorship.tls_domain) {
            return Err(ProxyError::Config(format!(
                "Invalid tls_domain: '{}'. Must be a valid domain name",
                self.censorship.tls_domain
            )));
        }

        for domain in &self.censorship.tls_domains {
            if !is_valid_tls_domain_name(domain) {
                return Err(ProxyError::Config(format!(
                    "Invalid tls_domains entry: '{}'. Must be a valid domain name",
                    domain
                )));
            }
        }

        for (domain, target) in &self.censorship.exclusive_mask {
            if !is_valid_tls_domain_name(domain) {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask domain: '{}'. Must be a valid domain name",
                    domain
                )));
            }
            if parse_exclusive_mask_target(target).is_none() {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                    domain, target
                )));
            }
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

        crate::network::dns_overrides::validate_entries(&self.network.dns_overrides)?;

        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/load_idle_policy_tests.rs"]
mod load_idle_policy_tests;

#[cfg(test)]
#[path = "tests/load_security_tests.rs"]
mod load_security_tests;

#[cfg(test)]
#[path = "tests/load_mask_shape_security_tests.rs"]
mod load_mask_shape_security_tests;

#[cfg(test)]
#[path = "tests/load_mask_classifier_prefetch_timeout_security_tests.rs"]
mod load_mask_classifier_prefetch_timeout_security_tests;

#[cfg(test)]
#[path = "tests/load_memory_envelope_tests.rs"]
mod load_memory_envelope_tests;

#[cfg(test)]
#[path = "tests/load_basic_tests.rs"]
mod tests;
