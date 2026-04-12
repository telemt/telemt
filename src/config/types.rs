use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use super::defaults::*;

// ============= Log Level =============

/// Logging verbosity level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// All messages including trace (trace + debug + info + warn + error).
    Debug,
    /// Detailed operational logs (debug + info + warn + error).
    Verbose,
    /// Standard operational logs (info + warn + error).
    #[default]
    Normal,
    /// Minimal output: only warnings and errors (warn + error).
    /// Startup messages (config, DC connectivity, proxy links) are always shown
    /// via info! before the filter is applied.
    Silent,
}

impl LogLevel {
    /// Convert to tracing EnvFilter directive string.
    pub fn to_filter_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "trace",
            LogLevel::Verbose => "debug",
            LogLevel::Normal => "info",
            LogLevel::Silent => "warn",
        }
    }

    /// Parse from a loose string (CLI argument).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" | "trace" => LogLevel::Debug,
            "verbose" => LogLevel::Verbose,
            "normal" | "info" => LogLevel::Normal,
            "silent" | "quiet" | "error" | "warn" => LogLevel::Silent,
            _ => LogLevel::Normal,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Verbose => write!(f, "verbose"),
            LogLevel::Normal => write!(f, "normal"),
            LogLevel::Silent => write!(f, "silent"),
        }
    }
}

/// Middle-End telemetry verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeTelemetryLevel {
    #[default]
    Normal,
    Silent,
    Debug,
}

impl MeTelemetryLevel {
    pub fn as_u8(self) -> u8 {
        match self {
            MeTelemetryLevel::Silent => 0,
            MeTelemetryLevel::Normal => 1,
            MeTelemetryLevel::Debug => 2,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeTelemetryLevel::Silent,
            2 => MeTelemetryLevel::Debug,
            _ => MeTelemetryLevel::Normal,
        }
    }

    pub fn allows_normal(self) -> bool {
        !matches!(self, MeTelemetryLevel::Silent)
    }

    pub fn allows_debug(self) -> bool {
        matches!(self, MeTelemetryLevel::Debug)
    }
}

impl std::fmt::Display for MeTelemetryLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeTelemetryLevel::Silent => write!(f, "silent"),
            MeTelemetryLevel::Normal => write!(f, "normal"),
            MeTelemetryLevel::Debug => write!(f, "debug"),
        }
    }
}

/// Middle-End SOCKS KDF fallback policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeSocksKdfPolicy {
    #[default]
    Strict,
    Compat,
}

impl MeSocksKdfPolicy {
    pub fn as_u8(self) -> u8 {
        match self {
            MeSocksKdfPolicy::Strict => 0,
            MeSocksKdfPolicy::Compat => 1,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            1 => MeSocksKdfPolicy::Compat,
            _ => MeSocksKdfPolicy::Strict,
        }
    }
}

/// Stale ME writer bind policy during drain window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeBindStaleMode {
    #[default]
    Never,
    Ttl,
    Always,
}

impl MeBindStaleMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeBindStaleMode::Never => 0,
            MeBindStaleMode::Ttl => 1,
            MeBindStaleMode::Always => 2,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeBindStaleMode::Never,
            2 => MeBindStaleMode::Always,
            _ => MeBindStaleMode::Ttl,
        }
    }
}

/// RST-on-close mode for accepted client sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RstOnCloseMode {
    /// Normal FIN on all closes (default, no behaviour change).
    #[default]
    Off,
    /// SO_LINGER(0) on accept; cleared after successful auth.
    /// Pre-handshake failures (scanners, DPI, timeouts) send RST;
    /// authenticated relay sessions close gracefully with FIN.
    Errors,
    /// SO_LINGER(0) on accept, never cleared — all closes send RST.
    Always,
}

/// Middle-End writer floor policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeFloorMode {
    Static,
    #[default]
    Adaptive,
}

impl MeFloorMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeFloorMode::Static => 0,
            MeFloorMode::Adaptive => 1,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            1 => MeFloorMode::Adaptive,
            _ => MeFloorMode::Static,
        }
    }
}

/// Middle-End route behavior when no writer is immediately available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeRouteNoWriterMode {
    AsyncRecoveryFailfast,
    InlineRecoveryLegacy,
    #[default]
    HybridAsyncPersistent,
}

impl MeRouteNoWriterMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeRouteNoWriterMode::AsyncRecoveryFailfast => 0,
            MeRouteNoWriterMode::InlineRecoveryLegacy => 1,
            MeRouteNoWriterMode::HybridAsyncPersistent => 2,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeRouteNoWriterMode::AsyncRecoveryFailfast,
            1 => MeRouteNoWriterMode::InlineRecoveryLegacy,
            2 => MeRouteNoWriterMode::HybridAsyncPersistent,
            _ => MeRouteNoWriterMode::HybridAsyncPersistent,
        }
    }
}

/// Middle-End writer selection mode for new client bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeWriterPickMode {
    SortedRr,
    #[default]
    P2c,
}

impl MeWriterPickMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeWriterPickMode::SortedRr => 0,
            MeWriterPickMode::P2c => 1,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeWriterPickMode::SortedRr,
            1 => MeWriterPickMode::P2c,
            _ => MeWriterPickMode::P2c,
        }
    }
}

/// Per-user unique source IP limit mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserMaxUniqueIpsMode {
    /// Count only currently active source IPs.
    #[default]
    ActiveWindow,
    /// Count source IPs seen within the recent time window.
    TimeWindow,
    /// Enforce both active and recent-window limits at the same time.
    Combined,
}

/// Telemetry controls for hot-path counters and ME diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_true")]
    pub core_enabled: bool,
    #[serde(default = "default_true")]
    pub user_enabled: bool,
    #[serde(default)]
    pub me_level: MeTelemetryLevel,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            core_enabled: default_true(),
            user_enabled: default_true(),
            me_level: MeTelemetryLevel::Normal,
        }
    }
}

// ============= Sub-Configs =============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyModes {
    #[serde(default)]
    pub classic: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
}

impl Default for ProxyModes {
    fn default() -> Self {
        Self {
            classic: false,
            secure: false,
            tls: default_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_true")]
    pub ipv4: bool,

    /// None = auto-detect IPv6 availability.
    #[serde(default = "default_network_ipv6")]
    pub ipv6: Option<bool>,

    /// 4 or 6.
    #[serde(default = "default_prefer_4")]
    pub prefer: u8,

    #[serde(default)]
    pub multipath: bool,

    /// Global switch for STUN probing.
    /// When false, STUN is fully disabled and only non-STUN detection remains.
    #[serde(default = "default_true")]
    pub stun_use: bool,

    /// STUN servers list for public IP discovery.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,

    /// Enable TCP STUN fallback when UDP is blocked.
    #[serde(default = "default_stun_tcp_fallback")]
    pub stun_tcp_fallback: bool,

    /// HTTP-based public IP detection endpoints (fallback after STUN).
    #[serde(default = "default_http_ip_detect_urls")]
    pub http_ip_detect_urls: Vec<String>,

    /// Cache file path for detected public IP.
    #[serde(default = "default_cache_public_ip_path")]
    pub cache_public_ip_path: String,

    /// Runtime DNS overrides in `host:port:ip` format.
    /// IPv6 IP values must be bracketed: `[2001:db8::1]`.
    #[serde(default)]
    pub dns_overrides: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv4: default_true(),
            ipv6: default_network_ipv6(),
            prefer: default_prefer_4(),
            multipath: false,
            stun_use: default_true(),
            stun_servers: default_stun_servers(),
            stun_tcp_fallback: default_stun_tcp_fallback(),
            http_ip_detect_urls: default_http_ip_detect_urls(),
            cache_public_ip_path: default_cache_public_ip_path(),
            dns_overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default)]
    pub data_path: Option<PathBuf>,

    #[serde(default)]
    pub modes: ProxyModes,

    #[serde(default)]
    pub prefer_ipv6: bool,

    #[serde(default = "default_true")]
    pub fast_mode: bool,

    #[serde(default = "default_true")]
    pub use_middle_proxy: bool,

    /// Path to proxy-secret binary file (auto-downloaded if absent).
    /// Infrastructure secret from https://core.telegram.org/getProxySecret.
    #[serde(default = "default_proxy_secret_path")]
    pub proxy_secret_path: Option<String>,

    /// Optional path to cache raw getProxyConfig (IPv4) snapshot for startup fallback.
    #[serde(default = "default_proxy_config_v4_cache_path")]
    pub proxy_config_v4_cache_path: Option<String>,

    /// Optional path to cache raw getProxyConfigV6 snapshot for startup fallback.
    #[serde(default = "default_proxy_config_v6_cache_path")]
    pub proxy_config_v6_cache_path: Option<String>,

    /// Global ad_tag (32 hex chars from @MTProxybot). Fallback when user has no per-user tag in access.user_ad_tags.
    #[serde(default)]
    pub ad_tag: Option<String>,

    /// Public IP override for middle-proxy NAT environments.
    /// When set, this IP is used in ME key derivation and RPC_PROXY_REQ "our_addr".
    #[serde(default)]
    pub middle_proxy_nat_ip: Option<IpAddr>,

    /// Enable STUN-based NAT probing to discover public IP:port for ME KDF.
    #[serde(default = "default_true")]
    pub middle_proxy_nat_probe: bool,

    /// Deprecated legacy single STUN server for NAT probing.
    /// Use `network.stun_servers` instead.
    #[serde(default = "default_middle_proxy_nat_stun")]
    pub middle_proxy_nat_stun: Option<String>,

    /// Deprecated legacy STUN list for NAT probing fallback.
    /// Use `network.stun_servers` instead.
    #[serde(default = "default_middle_proxy_nat_stun_servers")]
    pub middle_proxy_nat_stun_servers: Vec<String>,

    /// Maximum number of concurrent STUN probes during NAT detection.
    #[serde(default = "default_stun_nat_probe_concurrency")]
    pub stun_nat_probe_concurrency: usize,

    /// Desired size of active Middle-Proxy writer pool.
    #[serde(default = "default_pool_size")]
    pub middle_proxy_pool_size: usize,

    /// Number of warm standby ME connections kept pre-initialized.
    #[serde(default = "default_middle_proxy_warm_standby")]
    pub middle_proxy_warm_standby: usize,

    /// Startup retries for Middle-End pool initialization before ME→Direct fallback.
    /// 0 means unlimited retries.
    #[serde(default = "default_me_init_retry_attempts")]
    pub me_init_retry_attempts: u32,

    /// Allow fallback from Middle-End mode to direct DC when ME startup cannot be initialized.
    #[serde(default = "default_me2dc_fallback")]
    pub me2dc_fallback: bool,

    /// Fast ME->Direct fallback mode for new sessions.
    /// Active only when both `use_middle_proxy=true` and `me2dc_fallback=true`.
    #[serde(default = "default_me2dc_fast")]
    pub me2dc_fast: bool,

    /// Enable ME keepalive padding frames.
    #[serde(default = "default_true")]
    pub me_keepalive_enabled: bool,

    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval")]
    pub me_keepalive_interval_secs: u64,

    /// Keepalive jitter in seconds.
    #[serde(default = "default_keepalive_jitter")]
    pub me_keepalive_jitter_secs: u64,

    /// Keepalive payload randomized (4 bytes); otherwise zeros.
    #[serde(default = "default_true")]
    pub me_keepalive_payload_random: bool,

    /// Interval in seconds for service RPC_PROXY_REQ activity signals to ME.
    /// 0 disables service activity signals.
    #[serde(default = "default_rpc_proxy_req_every")]
    pub rpc_proxy_req_every: u64,

    /// Capacity of per-ME writer command channel.
    #[serde(default = "default_me_writer_cmd_channel_capacity")]
    pub me_writer_cmd_channel_capacity: usize,

    /// Capacity of per-connection ME response route channel.
    #[serde(default = "default_me_route_channel_capacity")]
    pub me_route_channel_capacity: usize,

    /// Capacity of per-client command queue from client reader to ME sender task.
    #[serde(default = "default_me_c2me_channel_capacity")]
    pub me_c2me_channel_capacity: usize,

    /// Maximum wait in milliseconds for enqueueing C2ME commands when the queue is full.
    /// `0` keeps legacy unbounded wait behavior.
    #[serde(default = "default_me_c2me_send_timeout_ms")]
    pub me_c2me_send_timeout_ms: u64,

    /// Bounded wait in milliseconds for routing ME DATA to per-connection queue.
    /// `0` keeps non-blocking routing; values >0 enable bounded wait for compatibility.
    #[serde(default = "default_me_reader_route_data_wait_ms")]
    pub me_reader_route_data_wait_ms: u64,

    /// Maximum number of ME->Client responses coalesced before flush.
    #[serde(default = "default_me_d2c_flush_batch_max_frames")]
    pub me_d2c_flush_batch_max_frames: usize,

    /// Maximum total payload bytes coalesced before flush.
    #[serde(default = "default_me_d2c_flush_batch_max_bytes")]
    pub me_d2c_flush_batch_max_bytes: usize,

    /// Maximum wait in microseconds to coalesce additional ME->Client responses.
    /// `0` disables timed coalescing.
    #[serde(default = "default_me_d2c_flush_batch_max_delay_us")]
    pub me_d2c_flush_batch_max_delay_us: u64,

    /// Flush client writer immediately after quick-ack write.
    #[serde(default = "default_me_d2c_ack_flush_immediate")]
    pub me_d2c_ack_flush_immediate: bool,

    /// Additional bytes above strict per-user quota allowed in hot-path soft mode.
    #[serde(default = "default_me_quota_soft_overshoot_bytes")]
    pub me_quota_soft_overshoot_bytes: u64,

    /// Shrink threshold for reusable ME->Client frame assembly buffer.
    #[serde(default = "default_me_d2c_frame_buf_shrink_threshold_bytes")]
    pub me_d2c_frame_buf_shrink_threshold_bytes: usize,

    /// Copy buffer size for client->DC direction in direct relay.
    #[serde(default = "default_direct_relay_copy_buf_c2s_bytes")]
    pub direct_relay_copy_buf_c2s_bytes: usize,

    /// Copy buffer size for DC->client direction in direct relay.
    #[serde(default = "default_direct_relay_copy_buf_s2c_bytes")]
    pub direct_relay_copy_buf_s2c_bytes: usize,

    /// Max pending ciphertext buffer per client writer (bytes).
    /// Controls FakeTLS backpressure vs throughput.
    #[serde(default = "default_crypto_pending_buffer")]
    pub crypto_pending_buffer: usize,

    /// Maximum allowed client MTProto frame size (bytes).
    #[serde(default = "default_max_client_frame")]
    pub max_client_frame: usize,

    /// Emit full crypto-desync forensic logs for every event.
    /// When false, full forensic details are emitted once per key window.
    #[serde(default = "default_desync_all_full")]
    pub desync_all_full: bool,

    /// Enable per-IP forensic observation buckets for scanners and handshake failures.
    #[serde(default = "default_true")]
    pub beobachten: bool,

    /// Observation retention window in minutes for per-IP forensic buckets.
    #[serde(default = "default_beobachten_minutes")]
    pub beobachten_minutes: u64,

    /// Snapshot flush interval in seconds for beob output file.
    #[serde(default = "default_beobachten_flush_secs")]
    pub beobachten_flush_secs: u64,

    /// Snapshot file path for beob output.
    #[serde(default = "default_beobachten_file")]
    pub beobachten_file: String,

    /// Enable C-like hard-swap for ME pool generations.
    /// When true, Telemt prewarms a new generation and switches once full coverage is reached.
    #[serde(default = "default_hardswap")]
    pub hardswap: bool,

    /// Enable staggered warmup of extra ME writers.
    #[serde(default = "default_true")]
    pub me_warmup_stagger_enabled: bool,

    /// Base delay between warmup connections in ms.
    #[serde(default = "default_warmup_step_delay_ms")]
    pub me_warmup_step_delay_ms: u64,

    /// Jitter for warmup delay in ms.
    #[serde(default = "default_warmup_step_jitter_ms")]
    pub me_warmup_step_jitter_ms: u64,

    /// Max concurrent reconnect attempts per DC.
    #[serde(default = "default_me_reconnect_max_concurrent_per_dc")]
    pub me_reconnect_max_concurrent_per_dc: u32,

    /// Base backoff in ms for reconnect.
    #[serde(default = "default_reconnect_backoff_base_ms")]
    pub me_reconnect_backoff_base_ms: u64,

    /// Cap backoff in ms for reconnect.
    #[serde(default = "default_reconnect_backoff_cap_ms")]
    pub me_reconnect_backoff_cap_ms: u64,

    /// Fast retry attempts before backoff.
    #[serde(default = "default_me_reconnect_fast_retry_count")]
    pub me_reconnect_fast_retry_count: u32,

    /// Number of additional reserve writers for DC groups with exactly one endpoint.
    #[serde(default = "default_me_single_endpoint_shadow_writers")]
    pub me_single_endpoint_shadow_writers: u8,

    /// Enable aggressive outage recovery mode for single-endpoint DC groups.
    #[serde(default = "default_me_single_endpoint_outage_mode_enabled")]
    pub me_single_endpoint_outage_mode_enabled: bool,

    /// Ignore endpoint quarantine while in single-endpoint outage mode.
    #[serde(default = "default_me_single_endpoint_outage_disable_quarantine")]
    pub me_single_endpoint_outage_disable_quarantine: bool,

    /// Minimum reconnect backoff in ms for single-endpoint outage mode.
    #[serde(default = "default_me_single_endpoint_outage_backoff_min_ms")]
    pub me_single_endpoint_outage_backoff_min_ms: u64,

    /// Maximum reconnect backoff in ms for single-endpoint outage mode.
    #[serde(default = "default_me_single_endpoint_outage_backoff_max_ms")]
    pub me_single_endpoint_outage_backoff_max_ms: u64,

    /// Periodic shadow writer rotation interval in seconds for single-endpoint DC groups.
    /// Set to 0 to disable periodic shadow rotation.
    #[serde(default = "default_me_single_endpoint_shadow_rotate_every_secs")]
    pub me_single_endpoint_shadow_rotate_every_secs: u64,

    /// Floor policy mode for ME writer targets.
    #[serde(default)]
    pub me_floor_mode: MeFloorMode,

    /// Idle time in seconds before adaptive floor can reduce single-endpoint writer target.
    #[serde(default = "default_me_adaptive_floor_idle_secs")]
    pub me_adaptive_floor_idle_secs: u64,

    /// Minimum writer target for single-endpoint DC groups in adaptive floor mode.
    #[serde(default = "default_me_adaptive_floor_min_writers_single_endpoint")]
    pub me_adaptive_floor_min_writers_single_endpoint: u8,

    /// Minimum writer target for multi-endpoint DC groups in adaptive floor mode.
    #[serde(default = "default_me_adaptive_floor_min_writers_multi_endpoint")]
    pub me_adaptive_floor_min_writers_multi_endpoint: u8,

    /// Grace period in seconds to hold static floor after activity in adaptive mode.
    #[serde(default = "default_me_adaptive_floor_recover_grace_secs")]
    pub me_adaptive_floor_recover_grace_secs: u64,

    /// Global ME writer budget per logical CPU core in adaptive mode.
    #[serde(default = "default_me_adaptive_floor_writers_per_core_total")]
    pub me_adaptive_floor_writers_per_core_total: u16,

    /// Override logical CPU core count for adaptive floor calculations.
    /// Set to 0 to use runtime auto-detection.
    #[serde(default = "default_me_adaptive_floor_cpu_cores_override")]
    pub me_adaptive_floor_cpu_cores_override: u16,

    /// Per-core max extra writers above base required floor for single-endpoint DC groups.
    #[serde(default = "default_me_adaptive_floor_max_extra_writers_single_per_core")]
    pub me_adaptive_floor_max_extra_writers_single_per_core: u16,

    /// Per-core max extra writers above base required floor for multi-endpoint DC groups.
    #[serde(default = "default_me_adaptive_floor_max_extra_writers_multi_per_core")]
    pub me_adaptive_floor_max_extra_writers_multi_per_core: u16,

    /// Hard cap for active ME writers per logical CPU core.
    #[serde(default = "default_me_adaptive_floor_max_active_writers_per_core")]
    pub me_adaptive_floor_max_active_writers_per_core: u16,

    /// Hard cap for warm ME writers per logical CPU core.
    #[serde(default = "default_me_adaptive_floor_max_warm_writers_per_core")]
    pub me_adaptive_floor_max_warm_writers_per_core: u16,

    /// Hard global cap for active ME writers.
    #[serde(default = "default_me_adaptive_floor_max_active_writers_global")]
    pub me_adaptive_floor_max_active_writers_global: u32,

    /// Hard global cap for warm ME writers.
    #[serde(default = "default_me_adaptive_floor_max_warm_writers_global")]
    pub me_adaptive_floor_max_warm_writers_global: u32,

    /// Connect attempts for the selected upstream before returning error/fallback.
    #[serde(default = "default_upstream_connect_retry_attempts")]
    pub upstream_connect_retry_attempts: u32,

    /// Delay in milliseconds between upstream connect attempts.
    #[serde(default = "default_upstream_connect_retry_backoff_ms")]
    pub upstream_connect_retry_backoff_ms: u64,

    /// Total wall-clock budget in milliseconds for one upstream connect request across retries.
    #[serde(default = "default_upstream_connect_budget_ms")]
    pub upstream_connect_budget_ms: u64,

    /// Per-attempt TCP connect timeout to Telegram DC (seconds).
    #[serde(default = "default_connect_timeout")]
    pub tg_connect: u64,

    /// Consecutive failed requests before upstream is marked unhealthy.
    #[serde(default = "default_upstream_unhealthy_fail_threshold")]
    pub upstream_unhealthy_fail_threshold: u32,

    /// Skip additional retries for hard non-transient upstream connect errors.
    #[serde(default = "default_upstream_connect_failfast_hard_errors")]
    pub upstream_connect_failfast_hard_errors: bool,

    /// Ignore STUN/interface IP mismatch (keep using Middle Proxy even if NAT detected).
    #[serde(default)]
    pub stun_iface_mismatch_ignore: bool,

    /// Log unknown (non-standard) DC requests to a file (default: unknown-dc.txt). Set to null to disable.
    #[serde(default = "default_unknown_dc_log_path")]
    pub unknown_dc_log_path: Option<String>,

    /// Enable unknown-DC file logging.
    #[serde(default = "default_unknown_dc_file_log_enabled")]
    pub unknown_dc_file_log_enabled: bool,

    #[serde(default)]
    pub log_level: LogLevel,

    /// Disable colored output in logs (useful for files/systemd).
    #[serde(default)]
    pub disable_colors: bool,

    /// Runtime telemetry controls for counters/metrics in hot paths.
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// SOCKS-bound KDF policy for Middle-End handshake.
    #[serde(default)]
    pub me_socks_kdf_policy: MeSocksKdfPolicy,

    /// Base backpressure timeout in milliseconds for ME route channel send.
    #[serde(default = "default_me_route_backpressure_base_timeout_ms")]
    pub me_route_backpressure_base_timeout_ms: u64,

    /// High backpressure timeout in milliseconds when queue occupancy is above watermark.
    #[serde(default = "default_me_route_backpressure_high_timeout_ms")]
    pub me_route_backpressure_high_timeout_ms: u64,

    /// Queue occupancy percent threshold for high backpressure timeout.
    #[serde(default = "default_me_route_backpressure_high_watermark_pct")]
    pub me_route_backpressure_high_watermark_pct: u8,

    /// Health monitor interval in milliseconds while writer coverage is degraded.
    #[serde(default = "default_me_health_interval_ms_unhealthy")]
    pub me_health_interval_ms_unhealthy: u64,

    /// Health monitor interval in milliseconds while writer coverage is stable.
    #[serde(default = "default_me_health_interval_ms_healthy")]
    pub me_health_interval_ms_healthy: u64,

    /// Poll interval in milliseconds for conditional-admission state checks.
    #[serde(default = "default_me_admission_poll_ms")]
    pub me_admission_poll_ms: u64,

    /// Cooldown for repetitive ME warning logs in milliseconds.
    #[serde(default = "default_me_warn_rate_limit_ms")]
    pub me_warn_rate_limit_ms: u64,

    /// ME route behavior when no writer is immediately available.
    #[serde(default)]
    pub me_route_no_writer_mode: MeRouteNoWriterMode,

    /// Maximum wait time in milliseconds for async-recovery failfast mode.
    #[serde(default = "default_me_route_no_writer_wait_ms")]
    pub me_route_no_writer_wait_ms: u64,

    /// Maximum cumulative wait in milliseconds for hybrid no-writer mode before failfast.
    #[serde(default = "default_me_route_hybrid_max_wait_ms")]
    pub me_route_hybrid_max_wait_ms: u64,

    /// Maximum wait in milliseconds for blocking ME writer channel send fallback.
    /// `0` keeps legacy unbounded wait behavior.
    #[serde(default = "default_me_route_blocking_send_timeout_ms")]
    pub me_route_blocking_send_timeout_ms: u64,

    /// Number of inline recovery attempts in legacy mode.
    #[serde(default = "default_me_route_inline_recovery_attempts")]
    pub me_route_inline_recovery_attempts: u32,

    /// Maximum wait time in milliseconds for inline recovery in legacy mode.
    #[serde(default = "default_me_route_inline_recovery_wait_ms")]
    pub me_route_inline_recovery_wait_ms: u64,

    /// [general.links] — proxy link generation overrides.
    #[serde(default)]
    pub links: LinksConfig,

    /// Minimum TLS record size when fast_mode coalescing is enabled (0 = disabled).
    #[serde(default = "default_fast_mode_min_tls_record")]
    pub fast_mode_min_tls_record: usize,

    /// Unified ME updater interval in seconds for getProxyConfig/getProxyConfigV6/getProxySecret.
    /// When omitted, effective value falls back to legacy proxy_*_auto_reload_secs fields.
    #[serde(default = "default_update_every")]
    pub update_every: Option<u64>,

    /// Periodic ME pool reinitialization interval in seconds.
    #[serde(default = "default_me_reinit_every_secs")]
    pub me_reinit_every_secs: u64,

    /// Minimum delay in ms between hardswap warmup connect attempts.
    #[serde(default = "default_me_hardswap_warmup_delay_min_ms")]
    pub me_hardswap_warmup_delay_min_ms: u64,

    /// Maximum delay in ms between hardswap warmup connect attempts.
    #[serde(default = "default_me_hardswap_warmup_delay_max_ms")]
    pub me_hardswap_warmup_delay_max_ms: u64,

    /// Additional warmup passes in the same hardswap cycle after the base pass.
    #[serde(default = "default_me_hardswap_warmup_extra_passes")]
    pub me_hardswap_warmup_extra_passes: u8,

    /// Base backoff in ms between hardswap warmup passes when floor is still incomplete.
    #[serde(default = "default_me_hardswap_warmup_pass_backoff_base_ms")]
    pub me_hardswap_warmup_pass_backoff_base_ms: u64,

    /// Number of identical getProxyConfig snapshots required before applying ME map updates.
    #[serde(default = "default_me_config_stable_snapshots")]
    pub me_config_stable_snapshots: u8,

    /// Cooldown in seconds between applied ME map updates.
    #[serde(default = "default_me_config_apply_cooldown_secs")]
    pub me_config_apply_cooldown_secs: u64,

    /// Ensure getProxyConfig snapshots are applied only for 2xx HTTP responses.
    #[serde(default = "default_me_snapshot_require_http_2xx")]
    pub me_snapshot_require_http_2xx: bool,

    /// Reject empty getProxyConfig snapshots instead of marking them applied.
    #[serde(default = "default_me_snapshot_reject_empty_map")]
    pub me_snapshot_reject_empty_map: bool,

    /// Minimum parsed `proxy_for` rows required to accept a snapshot.
    #[serde(default = "default_me_snapshot_min_proxy_for_lines")]
    pub me_snapshot_min_proxy_for_lines: u32,

    /// Number of identical getProxySecret snapshots required before runtime secret rotation.
    #[serde(default = "default_proxy_secret_stable_snapshots")]
    pub proxy_secret_stable_snapshots: u8,

    /// Enable runtime proxy-secret rotation from getProxySecret.
    #[serde(default = "default_proxy_secret_rotate_runtime")]
    pub proxy_secret_rotate_runtime: bool,

    /// Keep key-selector and secret bytes from one snapshot during ME handshake.
    #[serde(default = "default_me_secret_atomic_snapshot")]
    pub me_secret_atomic_snapshot: bool,

    /// Maximum allowed proxy-secret length in bytes for startup and runtime refresh.
    #[serde(default = "default_proxy_secret_len_max")]
    pub proxy_secret_len_max: usize,

    /// Drain-TTL in seconds for stale ME writers after endpoint map changes.
    /// During TTL, stale writers may be used only as fallback for new bindings.
    #[serde(default = "default_me_pool_drain_ttl_secs")]
    pub me_pool_drain_ttl_secs: u64,

    /// Force-remove any draining writer on the next cleanup tick, regardless of age/deadline.
    #[serde(default = "default_me_instadrain")]
    pub me_instadrain: bool,

    /// Maximum allowed number of draining ME writers before oldest ones are force-closed in batches.
    /// Set to 0 to disable threshold-based draining cleanup and keep timeout-only behavior.
    #[serde(default = "default_me_pool_drain_threshold")]
    pub me_pool_drain_threshold: u64,

    /// Enable staged client eviction for draining ME writers that remain non-empty past TTL.
    #[serde(default = "default_me_pool_drain_soft_evict_enabled")]
    pub me_pool_drain_soft_evict_enabled: bool,

    /// Extra grace in seconds after drain TTL before soft-eviction stage starts.
    #[serde(default = "default_me_pool_drain_soft_evict_grace_secs")]
    pub me_pool_drain_soft_evict_grace_secs: u64,

    /// Maximum number of client sessions to evict from one draining writer per health tick.
    #[serde(default = "default_me_pool_drain_soft_evict_per_writer")]
    pub me_pool_drain_soft_evict_per_writer: u8,

    /// Soft-eviction budget per CPU core for one health tick.
    #[serde(default = "default_me_pool_drain_soft_evict_budget_per_core")]
    pub me_pool_drain_soft_evict_budget_per_core: u16,

    /// Cooldown for repetitive soft-eviction on the same writer in milliseconds.
    #[serde(default = "default_me_pool_drain_soft_evict_cooldown_ms")]
    pub me_pool_drain_soft_evict_cooldown_ms: u64,

    /// Policy for new binds on stale draining writers.
    #[serde(default)]
    pub me_bind_stale_mode: MeBindStaleMode,

    /// TTL for stale bind allowance when `me_bind_stale_mode = \"ttl\"`.
    #[serde(default = "default_me_bind_stale_ttl_secs")]
    pub me_bind_stale_ttl_secs: u64,

    /// Minimum desired-DC coverage ratio required before draining stale writers.
    /// Range: 0.0..=1.0.
    #[serde(default = "default_me_pool_min_fresh_ratio")]
    pub me_pool_min_fresh_ratio: f32,

    /// Drain timeout in seconds for stale ME writers after endpoint map changes.
    /// Set to 0 to use the runtime safety fallback timeout.
    #[serde(default = "default_me_reinit_drain_timeout_secs")]
    pub me_reinit_drain_timeout_secs: u64,

    /// Deprecated legacy setting; kept for backward compatibility fallback.
    /// Use `update_every` instead.
    #[serde(default = "default_proxy_secret_reload_secs")]
    pub proxy_secret_auto_reload_secs: u64,

    /// Deprecated legacy setting; kept for backward compatibility fallback.
    /// Use `update_every` instead.
    #[serde(default = "default_proxy_config_reload_secs")]
    pub proxy_config_auto_reload_secs: u64,

    /// Serialize ME reinit cycles across all trigger sources.
    #[serde(default = "default_me_reinit_singleflight")]
    pub me_reinit_singleflight: bool,

    /// Trigger queue capacity for reinit scheduler.
    #[serde(default = "default_me_reinit_trigger_channel")]
    pub me_reinit_trigger_channel: usize,

    /// Trigger coalescing window before starting a reinit cycle.
    #[serde(default = "default_me_reinit_coalesce_window_ms")]
    pub me_reinit_coalesce_window_ms: u64,

    /// Deterministic candidate sort for ME writer binding path.
    #[serde(default = "default_me_deterministic_writer_sort")]
    pub me_deterministic_writer_sort: bool,

    /// Writer selection mode for ME route bind path.
    #[serde(default)]
    pub me_writer_pick_mode: MeWriterPickMode,

    /// Number of candidates sampled by writer picker in `p2c` mode.
    #[serde(default = "default_me_writer_pick_sample_size")]
    pub me_writer_pick_sample_size: u8,

    /// Enable NTP drift check at startup.
    #[serde(default = "default_ntp_check")]
    pub ntp_check: bool,

    /// NTP servers for drift check.
    #[serde(default = "default_ntp_servers")]
    pub ntp_servers: Vec<String>,

    /// Enable auto-degradation from ME to Direct-DC.
    #[serde(default = "default_true")]
    pub auto_degradation_enabled: bool,

    /// Minimum unavailable ME DC groups before degrading.
    #[serde(default = "default_degradation_min_unavailable_dc_groups")]
    pub degradation_min_unavailable_dc_groups: u8,

    /// RST-on-close mode for accepted client sockets.
    /// `off`    — normal FIN on all closes (default).
    /// `errors` — SO_LINGER(0) on accept, cleared after successful auth;
    ///            pre-handshake failures send RST, relayed sessions close gracefully.
    /// `always` — SO_LINGER(0) on accept, never cleared; all closes send RST.
    #[serde(default)]
    pub rst_on_close: RstOnCloseMode,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            data_path: None,
            modes: ProxyModes::default(),
            prefer_ipv6: false,
            fast_mode: default_true(),
            use_middle_proxy: default_true(),
            ad_tag: None,
            proxy_secret_path: default_proxy_secret_path(),
            proxy_config_v4_cache_path: default_proxy_config_v4_cache_path(),
            proxy_config_v6_cache_path: default_proxy_config_v6_cache_path(),
            middle_proxy_nat_ip: None,
            middle_proxy_nat_probe: default_true(),
            middle_proxy_nat_stun: default_middle_proxy_nat_stun(),
            middle_proxy_nat_stun_servers: default_middle_proxy_nat_stun_servers(),
            stun_nat_probe_concurrency: default_stun_nat_probe_concurrency(),
            middle_proxy_pool_size: default_pool_size(),
            middle_proxy_warm_standby: default_middle_proxy_warm_standby(),
            me_init_retry_attempts: default_me_init_retry_attempts(),
            me2dc_fallback: default_me2dc_fallback(),
            me2dc_fast: default_me2dc_fast(),
            me_keepalive_enabled: default_true(),
            me_keepalive_interval_secs: default_keepalive_interval(),
            me_keepalive_jitter_secs: default_keepalive_jitter(),
            me_keepalive_payload_random: default_true(),
            rpc_proxy_req_every: default_rpc_proxy_req_every(),
            me_writer_cmd_channel_capacity: default_me_writer_cmd_channel_capacity(),
            me_route_channel_capacity: default_me_route_channel_capacity(),
            me_c2me_channel_capacity: default_me_c2me_channel_capacity(),
            me_c2me_send_timeout_ms: default_me_c2me_send_timeout_ms(),
            me_reader_route_data_wait_ms: default_me_reader_route_data_wait_ms(),
            me_d2c_flush_batch_max_frames: default_me_d2c_flush_batch_max_frames(),
            me_d2c_flush_batch_max_bytes: default_me_d2c_flush_batch_max_bytes(),
            me_d2c_flush_batch_max_delay_us: default_me_d2c_flush_batch_max_delay_us(),
            me_d2c_ack_flush_immediate: default_me_d2c_ack_flush_immediate(),
            me_quota_soft_overshoot_bytes: default_me_quota_soft_overshoot_bytes(),
            me_d2c_frame_buf_shrink_threshold_bytes:
                default_me_d2c_frame_buf_shrink_threshold_bytes(),
            direct_relay_copy_buf_c2s_bytes: default_direct_relay_copy_buf_c2s_bytes(),
            direct_relay_copy_buf_s2c_bytes: default_direct_relay_copy_buf_s2c_bytes(),
            me_warmup_stagger_enabled: default_true(),
            me_warmup_step_delay_ms: default_warmup_step_delay_ms(),
            me_warmup_step_jitter_ms: default_warmup_step_jitter_ms(),
            me_reconnect_max_concurrent_per_dc: default_me_reconnect_max_concurrent_per_dc(),
            me_reconnect_backoff_base_ms: default_reconnect_backoff_base_ms(),
            me_reconnect_backoff_cap_ms: default_reconnect_backoff_cap_ms(),
            me_reconnect_fast_retry_count: default_me_reconnect_fast_retry_count(),
            me_single_endpoint_shadow_writers: default_me_single_endpoint_shadow_writers(),
            me_single_endpoint_outage_mode_enabled: default_me_single_endpoint_outage_mode_enabled(
            ),
            me_single_endpoint_outage_disable_quarantine:
                default_me_single_endpoint_outage_disable_quarantine(),
            me_single_endpoint_outage_backoff_min_ms:
                default_me_single_endpoint_outage_backoff_min_ms(),
            me_single_endpoint_outage_backoff_max_ms:
                default_me_single_endpoint_outage_backoff_max_ms(),
            me_single_endpoint_shadow_rotate_every_secs:
                default_me_single_endpoint_shadow_rotate_every_secs(),
            me_floor_mode: MeFloorMode::default(),
            me_adaptive_floor_idle_secs: default_me_adaptive_floor_idle_secs(),
            me_adaptive_floor_min_writers_single_endpoint:
                default_me_adaptive_floor_min_writers_single_endpoint(),
            me_adaptive_floor_min_writers_multi_endpoint:
                default_me_adaptive_floor_min_writers_multi_endpoint(),
            me_adaptive_floor_recover_grace_secs: default_me_adaptive_floor_recover_grace_secs(),
            me_adaptive_floor_writers_per_core_total:
                default_me_adaptive_floor_writers_per_core_total(),
            me_adaptive_floor_cpu_cores_override: default_me_adaptive_floor_cpu_cores_override(),
            me_adaptive_floor_max_extra_writers_single_per_core:
                default_me_adaptive_floor_max_extra_writers_single_per_core(),
            me_adaptive_floor_max_extra_writers_multi_per_core:
                default_me_adaptive_floor_max_extra_writers_multi_per_core(),
            me_adaptive_floor_max_active_writers_per_core:
                default_me_adaptive_floor_max_active_writers_per_core(),
            me_adaptive_floor_max_warm_writers_per_core:
                default_me_adaptive_floor_max_warm_writers_per_core(),
            me_adaptive_floor_max_active_writers_global:
                default_me_adaptive_floor_max_active_writers_global(),
            me_adaptive_floor_max_warm_writers_global:
                default_me_adaptive_floor_max_warm_writers_global(),
            upstream_connect_retry_attempts: default_upstream_connect_retry_attempts(),
            upstream_connect_retry_backoff_ms: default_upstream_connect_retry_backoff_ms(),
            upstream_connect_budget_ms: default_upstream_connect_budget_ms(),
            tg_connect: default_connect_timeout(),
            upstream_unhealthy_fail_threshold: default_upstream_unhealthy_fail_threshold(),
            upstream_connect_failfast_hard_errors: default_upstream_connect_failfast_hard_errors(),
            stun_iface_mismatch_ignore: false,
            unknown_dc_log_path: default_unknown_dc_log_path(),
            unknown_dc_file_log_enabled: default_unknown_dc_file_log_enabled(),
            log_level: LogLevel::Normal,
            disable_colors: false,
            telemetry: TelemetryConfig::default(),
            me_socks_kdf_policy: MeSocksKdfPolicy::Strict,
            me_route_backpressure_base_timeout_ms: default_me_route_backpressure_base_timeout_ms(),
            me_route_backpressure_high_timeout_ms: default_me_route_backpressure_high_timeout_ms(),
            me_route_backpressure_high_watermark_pct:
                default_me_route_backpressure_high_watermark_pct(),
            me_health_interval_ms_unhealthy: default_me_health_interval_ms_unhealthy(),
            me_health_interval_ms_healthy: default_me_health_interval_ms_healthy(),
            me_admission_poll_ms: default_me_admission_poll_ms(),
            me_warn_rate_limit_ms: default_me_warn_rate_limit_ms(),
            me_route_no_writer_mode: MeRouteNoWriterMode::default(),
            me_route_no_writer_wait_ms: default_me_route_no_writer_wait_ms(),
            me_route_hybrid_max_wait_ms: default_me_route_hybrid_max_wait_ms(),
            me_route_blocking_send_timeout_ms: default_me_route_blocking_send_timeout_ms(),
            me_route_inline_recovery_attempts: default_me_route_inline_recovery_attempts(),
            me_route_inline_recovery_wait_ms: default_me_route_inline_recovery_wait_ms(),
            links: LinksConfig::default(),
            crypto_pending_buffer: default_crypto_pending_buffer(),
            max_client_frame: default_max_client_frame(),
            desync_all_full: default_desync_all_full(),
            beobachten: default_true(),
            beobachten_minutes: default_beobachten_minutes(),
            beobachten_flush_secs: default_beobachten_flush_secs(),
            beobachten_file: default_beobachten_file(),
            hardswap: default_hardswap(),
            fast_mode_min_tls_record: default_fast_mode_min_tls_record(),
            update_every: default_update_every(),
            me_reinit_every_secs: default_me_reinit_every_secs(),
            me_hardswap_warmup_delay_min_ms: default_me_hardswap_warmup_delay_min_ms(),
            me_hardswap_warmup_delay_max_ms: default_me_hardswap_warmup_delay_max_ms(),
            me_hardswap_warmup_extra_passes: default_me_hardswap_warmup_extra_passes(),
            me_hardswap_warmup_pass_backoff_base_ms:
                default_me_hardswap_warmup_pass_backoff_base_ms(),
            me_config_stable_snapshots: default_me_config_stable_snapshots(),
            me_config_apply_cooldown_secs: default_me_config_apply_cooldown_secs(),
            me_snapshot_require_http_2xx: default_me_snapshot_require_http_2xx(),
            me_snapshot_reject_empty_map: default_me_snapshot_reject_empty_map(),
            me_snapshot_min_proxy_for_lines: default_me_snapshot_min_proxy_for_lines(),
            proxy_secret_stable_snapshots: default_proxy_secret_stable_snapshots(),
            proxy_secret_rotate_runtime: default_proxy_secret_rotate_runtime(),
            me_secret_atomic_snapshot: default_me_secret_atomic_snapshot(),
            proxy_secret_len_max: default_proxy_secret_len_max(),
            me_pool_drain_ttl_secs: default_me_pool_drain_ttl_secs(),
            me_instadrain: default_me_instadrain(),
            me_pool_drain_threshold: default_me_pool_drain_threshold(),
            me_pool_drain_soft_evict_enabled: default_me_pool_drain_soft_evict_enabled(),
            me_pool_drain_soft_evict_grace_secs: default_me_pool_drain_soft_evict_grace_secs(),
            me_pool_drain_soft_evict_per_writer: default_me_pool_drain_soft_evict_per_writer(),
            me_pool_drain_soft_evict_budget_per_core:
                default_me_pool_drain_soft_evict_budget_per_core(),
            me_pool_drain_soft_evict_cooldown_ms: default_me_pool_drain_soft_evict_cooldown_ms(),
            me_bind_stale_mode: MeBindStaleMode::default(),
            me_bind_stale_ttl_secs: default_me_bind_stale_ttl_secs(),
            me_pool_min_fresh_ratio: default_me_pool_min_fresh_ratio(),
            me_reinit_drain_timeout_secs: default_me_reinit_drain_timeout_secs(),
            proxy_secret_auto_reload_secs: default_proxy_secret_reload_secs(),
            proxy_config_auto_reload_secs: default_proxy_config_reload_secs(),
            me_reinit_singleflight: default_me_reinit_singleflight(),
            me_reinit_trigger_channel: default_me_reinit_trigger_channel(),
            me_reinit_coalesce_window_ms: default_me_reinit_coalesce_window_ms(),
            me_deterministic_writer_sort: default_me_deterministic_writer_sort(),
            me_writer_pick_mode: MeWriterPickMode::default(),
            me_writer_pick_sample_size: default_me_writer_pick_sample_size(),
            ntp_check: default_ntp_check(),
            ntp_servers: default_ntp_servers(),
            auto_degradation_enabled: default_true(),
            degradation_min_unavailable_dc_groups: default_degradation_min_unavailable_dc_groups(),
            rst_on_close: RstOnCloseMode::default(),
        }
    }
}

impl GeneralConfig {
    /// Resolve the active updater interval for ME infrastructure refresh tasks.
    /// `update_every` has priority, otherwise legacy proxy_*_auto_reload_secs are used.
    pub fn effective_update_every_secs(&self) -> u64 {
        self.update_every.unwrap_or_else(|| {
            self.proxy_secret_auto_reload_secs
                .min(self.proxy_config_auto_reload_secs)
        })
    }

    /// Resolve periodic zero-downtime reinit interval for ME writers.
    pub fn effective_me_reinit_every_secs(&self) -> u64 {
        self.me_reinit_every_secs
    }

    /// Resolve force-close timeout for stale writers.
    /// `me_reinit_drain_timeout_secs` remains backward-compatible alias.
    /// A configured `0` uses the runtime safety fallback (300s).
    pub fn effective_me_pool_force_close_secs(&self) -> u64 {
        if self.me_reinit_drain_timeout_secs == 0 {
            300
        } else {
            self.me_reinit_drain_timeout_secs
        }
    }
}

/// `[general.links]` — proxy link generation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinksConfig {
    /// List of usernames whose tg:// links to display at startup.
    /// `"*"` = all users, `["alice", "bob"]` = specific users.
    #[serde(default = "default_links_show")]
    pub show: ShowLink,

    /// Public hostname/IP for tg:// link generation (overrides detected IP).
    #[serde(default)]
    pub public_host: Option<String>,

    /// Public port for tg:// link generation (overrides server.port).
    #[serde(default)]
    pub public_port: Option<u16>,
}

impl Default for LinksConfig {
    fn default() -> Self {
        Self {
            show: default_links_show(),
            public_host: None,
            public_port: None,
        }
    }
}

/// API settings for control-plane endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiConfig {
    /// Enable or disable REST API.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Listen address for API in `IP:PORT` format.
    #[serde(default = "default_api_listen")]
    pub listen: String,

    /// CIDR whitelist allowed to access API.
    #[serde(default = "default_api_whitelist")]
    pub whitelist: Vec<IpNetwork>,

    /// Optional static value for `Authorization` header validation.
    /// Empty string disables header auth.
    #[serde(default)]
    pub auth_header: String,

    /// Maximum accepted HTTP request body size in bytes.
    #[serde(default = "default_api_request_body_limit_bytes")]
    pub request_body_limit_bytes: usize,

    /// Enable runtime snapshots that require read-lock aggregation on API request path.
    #[serde(default = "default_api_minimal_runtime_enabled")]
    pub minimal_runtime_enabled: bool,

    /// Cache TTL for minimal runtime snapshots in milliseconds (0 disables caching).
    #[serde(default = "default_api_minimal_runtime_cache_ttl_ms")]
    pub minimal_runtime_cache_ttl_ms: u64,

    /// Enables runtime edge endpoints with optional cached aggregation.
    #[serde(default = "default_api_runtime_edge_enabled")]
    pub runtime_edge_enabled: bool,

    /// Cache TTL for runtime edge aggregation payloads in milliseconds.
    #[serde(default = "default_api_runtime_edge_cache_ttl_ms")]
    pub runtime_edge_cache_ttl_ms: u64,

    /// Top-N limit for edge connection leaderboard payloads.
    #[serde(default = "default_api_runtime_edge_top_n")]
    pub runtime_edge_top_n: usize,

    /// Ring-buffer capacity for runtime edge control-plane events.
    #[serde(default = "default_api_runtime_edge_events_capacity")]
    pub runtime_edge_events_capacity: usize,

    /// Read-only mode: mutating endpoints are rejected.
    #[serde(default)]
    pub read_only: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            listen: default_api_listen(),
            whitelist: default_api_whitelist(),
            auth_header: String::new(),
            request_body_limit_bytes: default_api_request_body_limit_bytes(),
            minimal_runtime_enabled: default_api_minimal_runtime_enabled(),
            minimal_runtime_cache_ttl_ms: default_api_minimal_runtime_cache_ttl_ms(),
            runtime_edge_enabled: default_api_runtime_edge_enabled(),
            runtime_edge_cache_ttl_ms: default_api_runtime_edge_cache_ttl_ms(),
            runtime_edge_top_n: default_api_runtime_edge_top_n(),
            runtime_edge_events_capacity: default_api_runtime_edge_events_capacity(),
            read_only: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConntrackMode {
    #[default]
    Tracked,
    Notrack,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConntrackBackend {
    #[default]
    Auto,
    Nftables,
    Iptables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConntrackPressureProfile {
    Conservative,
    #[default]
    Balanced,
    Aggressive,
}

impl ConntrackPressureProfile {
    pub fn client_first_byte_idle_cap_secs(self) -> u64 {
        match self {
            Self::Conservative => 30,
            Self::Balanced => 20,
            Self::Aggressive => 10,
        }
    }

    pub fn direct_activity_timeout_secs(self) -> u64 {
        match self {
            Self::Conservative => 180,
            Self::Balanced => 120,
            Self::Aggressive => 60,
        }
    }

    pub fn middle_soft_idle_cap_secs(self) -> u64 {
        match self {
            Self::Conservative => 60,
            Self::Balanced => 30,
            Self::Aggressive => 20,
        }
    }

    pub fn middle_hard_idle_cap_secs(self) -> u64 {
        match self {
            Self::Conservative => 180,
            Self::Balanced => 90,
            Self::Aggressive => 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConntrackControlConfig {
    /// Enables runtime conntrack-control worker for pressure mitigation.
    #[serde(default = "default_conntrack_control_enabled")]
    pub inline_conntrack_control: bool,

    /// Conntrack mode for listener ingress traffic.
    #[serde(default)]
    pub mode: ConntrackMode,

    /// Netfilter backend used to reconcile notrack rules.
    #[serde(default)]
    pub backend: ConntrackBackend,

    /// Pressure profile for timeout caps under resource saturation.
    #[serde(default)]
    pub profile: ConntrackPressureProfile,

    /// Listener IP allow-list for hybrid mode.
    /// Ignored in tracked/notrack mode.
    #[serde(default)]
    pub hybrid_listener_ips: Vec<IpAddr>,

    /// Pressure high watermark as percentage.
    #[serde(default = "default_conntrack_pressure_high_watermark_pct")]
    pub pressure_high_watermark_pct: u8,

    /// Pressure low watermark as percentage.
    #[serde(default = "default_conntrack_pressure_low_watermark_pct")]
    pub pressure_low_watermark_pct: u8,

    /// Maximum conntrack delete operations per second.
    #[serde(default = "default_conntrack_delete_budget_per_sec")]
    pub delete_budget_per_sec: u64,
}

impl Default for ConntrackControlConfig {
    fn default() -> Self {
        Self {
            inline_conntrack_control: default_conntrack_control_enabled(),
            mode: ConntrackMode::default(),
            backend: ConntrackBackend::default(),
            profile: ConntrackPressureProfile::default(),
            hybrid_listener_ips: Vec::new(),
            pressure_high_watermark_pct: default_conntrack_pressure_high_watermark_pct(),
            pressure_low_watermark_pct: default_conntrack_pressure_low_watermark_pct(),
            delete_budget_per_sec: default_conntrack_delete_budget_per_sec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_listen_addr_ipv4")]
    pub listen_addr_ipv4: Option<String>,

    #[serde(default = "default_listen_addr_ipv6_opt")]
    pub listen_addr_ipv6: Option<String>,

    #[serde(default)]
    pub listen_unix_sock: Option<String>,

    /// Unix socket file permissions (octal, e.g. "0666" or "0777").
    /// Applied via chmod after bind. Default: no change (inherits umask).
    #[serde(default)]
    pub listen_unix_sock_perm: Option<String>,

    /// Enable TCP listening. Default: true when no unix socket, false when
    /// listen_unix_sock is set. Set explicitly to override auto-detection.
    #[serde(default)]
    pub listen_tcp: Option<bool>,

    /// Accept HAProxy PROXY protocol headers on incoming connections.
    /// When enabled, real client IPs are extracted from PROXY v1/v2 headers.
    #[serde(default)]
    pub proxy_protocol: bool,

    /// Timeout in milliseconds for reading and parsing PROXY protocol headers.
    #[serde(default = "default_proxy_protocol_header_timeout_ms")]
    pub proxy_protocol_header_timeout_ms: u64,

    /// Trusted source CIDRs allowed to send incoming PROXY protocol headers.
    ///
    /// If this field is omitted in config, it defaults to trust-all CIDRs
    /// (`0.0.0.0/0` and `::/0`). If it is explicitly set to an empty list,
    /// all PROXY protocol headers are rejected.
    #[serde(default = "default_proxy_protocol_trusted_cidrs")]
    pub proxy_protocol_trusted_cidrs: Vec<IpNetwork>,

    /// Port for the Prometheus-compatible metrics endpoint.
    /// Enables metrics when set; binds on all interfaces (dual-stack) by default.
    #[serde(default)]
    pub metrics_port: Option<u16>,

    /// Listen address for metrics in `IP:PORT` format (e.g. `"127.0.0.1:9090"`).
    /// When set, takes precedence over `metrics_port` and binds on the specified address only.
    #[serde(default)]
    pub metrics_listen: Option<String>,

    /// CIDR whitelist for the metrics endpoint.
    #[serde(default = "default_metrics_whitelist")]
    pub metrics_whitelist: Vec<IpNetwork>,

    #[serde(default, alias = "admin_api")]
    pub api: ApiConfig,

    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// TCP `listen(2)` backlog for client-facing sockets (also used for the metrics HTTP listener).
    /// The effective queue is capped by the kernel (for example `somaxconn` on Linux).
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: u32,

    /// Maximum number of concurrent client connections.
    /// 0 means unlimited.
    #[serde(default = "default_server_max_connections")]
    pub max_connections: u32,

    /// Maximum wait in milliseconds while acquiring a connection slot permit.
    /// `0` keeps legacy unbounded wait behavior.
    #[serde(default = "default_accept_permit_timeout_ms")]
    pub accept_permit_timeout_ms: u64,

    /// Runtime conntrack control and pressure policy.
    #[serde(default)]
    pub conntrack_control: ConntrackControlConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            listen_addr_ipv4: default_listen_addr_ipv4(),
            listen_addr_ipv6: default_listen_addr_ipv6_opt(),
            listen_unix_sock: None,
            listen_unix_sock_perm: None,
            listen_tcp: None,
            proxy_protocol: false,
            proxy_protocol_header_timeout_ms: default_proxy_protocol_header_timeout_ms(),
            proxy_protocol_trusted_cidrs: default_proxy_protocol_trusted_cidrs(),
            metrics_port: None,
            metrics_listen: None,
            metrics_whitelist: default_metrics_whitelist(),
            api: ApiConfig::default(),
            listeners: Vec::new(),
            listen_backlog: default_listen_backlog(),
            max_connections: default_server_max_connections(),
            accept_permit_timeout_ms: default_accept_permit_timeout_ms(),
            conntrack_control: ConntrackControlConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutsConfig {
    /// Maximum idle wait in seconds for the first client byte before handshake parsing starts.
    /// `0` disables the separate idle phase and keeps legacy timeout behavior.
    #[serde(default = "default_client_first_byte_idle_secs")]
    pub client_first_byte_idle_secs: u64,

    /// Maximum active handshake duration in seconds after the first client byte is received.
    #[serde(default = "default_handshake_timeout")]
    pub client_handshake: u64,

    /// Enables soft/hard relay client idle policy for middle-relay sessions.
    #[serde(default = "default_relay_idle_policy_v2_enabled")]
    pub relay_idle_policy_v2_enabled: bool,

    /// Soft idle threshold for middle-relay client uplink activity in seconds.
    /// Hitting this threshold marks the session as idle-candidate, but does not close it.
    #[serde(default = "default_relay_client_idle_soft_secs")]
    pub relay_client_idle_soft_secs: u64,

    /// Hard idle threshold for middle-relay client uplink activity in seconds.
    /// Hitting this threshold closes the session.
    #[serde(default = "default_relay_client_idle_hard_secs")]
    pub relay_client_idle_hard_secs: u64,

    /// Additional grace in seconds added to hard idle window after recent downstream activity.
    #[serde(default = "default_relay_idle_grace_after_downstream_activity_secs")]
    pub relay_idle_grace_after_downstream_activity_secs: u64,

    #[serde(default = "default_keepalive")]
    pub client_keepalive: u64,

    #[serde(default = "default_ack_timeout")]
    pub client_ack: u64,

    /// Number of quick ME reconnect attempts for single-address DC.
    #[serde(default = "default_me_one_retry")]
    pub me_one_retry: u8,

    /// Timeout per quick attempt in milliseconds for single-address DC.
    #[serde(default = "default_me_one_timeout")]
    pub me_one_timeout_ms: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            client_first_byte_idle_secs: default_client_first_byte_idle_secs(),
            client_handshake: default_handshake_timeout(),
            relay_idle_policy_v2_enabled: default_relay_idle_policy_v2_enabled(),
            relay_client_idle_soft_secs: default_relay_client_idle_soft_secs(),
            relay_client_idle_hard_secs: default_relay_client_idle_hard_secs(),
            relay_idle_grace_after_downstream_activity_secs:
                default_relay_idle_grace_after_downstream_activity_secs(),
            client_keepalive: default_keepalive(),
            client_ack: default_ack_timeout(),
            me_one_retry: default_me_one_retry(),
            me_one_timeout_ms: default_me_one_timeout(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UnknownSniAction {
    #[default]
    Drop,
    Mask,
    Accept,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsFetchProfile {
    ModernChromeLike,
    ModernFirefoxLike,
    CompatTls12,
    LegacyMinimal,
}

impl TlsFetchProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsFetchProfile::ModernChromeLike => "modern_chrome_like",
            TlsFetchProfile::ModernFirefoxLike => "modern_firefox_like",
            TlsFetchProfile::CompatTls12 => "compat_tls12",
            TlsFetchProfile::LegacyMinimal => "legacy_minimal",
        }
    }
}

fn default_tls_fetch_profiles() -> Vec<TlsFetchProfile> {
    vec![
        TlsFetchProfile::ModernChromeLike,
        TlsFetchProfile::ModernFirefoxLike,
        TlsFetchProfile::CompatTls12,
        TlsFetchProfile::LegacyMinimal,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFetchConfig {
    /// Ordered list of ClientHello profiles used for adaptive fallback.
    #[serde(default = "default_tls_fetch_profiles")]
    pub profiles: Vec<TlsFetchProfile>,

    /// When true and upstream route is configured, TLS fetch fails closed on
    /// upstream connect errors and does not fallback to direct TCP.
    #[serde(default = "default_tls_fetch_strict_route")]
    pub strict_route: bool,

    /// Timeout per one profile attempt in milliseconds.
    #[serde(default = "default_tls_fetch_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,

    /// Total wall-clock budget in milliseconds across all profile attempts.
    #[serde(default = "default_tls_fetch_total_budget_ms")]
    pub total_budget_ms: u64,

    /// Adds GREASE-style values into selected ClientHello extensions.
    #[serde(default)]
    pub grease_enabled: bool,

    /// Produces deterministic ClientHello randomness for debugging/tests.
    #[serde(default)]
    pub deterministic: bool,

    /// TTL for winner-profile cache entries in seconds.
    /// Set to 0 to disable profile cache.
    #[serde(default = "default_tls_fetch_profile_cache_ttl_secs")]
    pub profile_cache_ttl_secs: u64,
}

impl Default for TlsFetchConfig {
    fn default() -> Self {
        Self {
            profiles: default_tls_fetch_profiles(),
            strict_route: default_tls_fetch_strict_route(),
            attempt_timeout_ms: default_tls_fetch_attempt_timeout_ms(),
            total_budget_ms: default_tls_fetch_total_budget_ms(),
            grease_enabled: false,
            deterministic: false,
            profile_cache_ttl_secs: default_tls_fetch_profile_cache_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCensorshipConfig {
    #[serde(default = "default_tls_domain")]
    pub tls_domain: String,

    /// Additional TLS domains for generating multiple proxy links.
    #[serde(default)]
    pub tls_domains: Vec<String>,

    /// Policy for TLS ClientHello with unknown (non-configured) SNI.
    #[serde(default)]
    pub unknown_sni_action: UnknownSniAction,

    /// Upstream scope used for TLS front metadata fetches.
    /// Empty value keeps default upstream routing behavior.
    #[serde(default = "default_tls_fetch_scope")]
    pub tls_fetch_scope: String,

    /// Fetch strategy for TLS front metadata bootstrap and periodic refresh.
    #[serde(default)]
    pub tls_fetch: TlsFetchConfig,

    #[serde(default = "default_true")]
    pub mask: bool,

    #[serde(default)]
    pub mask_host: Option<String>,

    #[serde(default = "default_mask_port")]
    pub mask_port: u16,

    #[serde(default)]
    pub mask_unix_sock: Option<String>,

    #[serde(default = "default_fake_cert_len")]
    pub fake_cert_len: usize,

    /// Enable TLS certificate emulation using cached real certificates.
    #[serde(default = "default_true")]
    pub tls_emulation: bool,

    /// Directory to store TLS front cache (on disk).
    #[serde(default = "default_tls_front_dir")]
    pub tls_front_dir: String,

    /// Minimum server_hello delay in milliseconds (anti-fingerprint).
    #[serde(default = "default_server_hello_delay_min_ms")]
    pub server_hello_delay_min_ms: u64,

    /// Maximum server_hello delay in milliseconds.
    #[serde(default = "default_server_hello_delay_max_ms")]
    pub server_hello_delay_max_ms: u64,

    /// Number of NewSessionTicket messages to emit post-handshake.
    #[serde(default = "default_tls_new_session_tickets")]
    pub tls_new_session_tickets: u8,

    /// TTL in seconds for sending full certificate payload per client IP.
    /// First client connection per (SNI domain, client IP) gets full cert payload.
    /// Subsequent handshakes within TTL use compact cert metadata payload.
    #[serde(default = "default_tls_full_cert_ttl_secs")]
    pub tls_full_cert_ttl_secs: u64,

    /// Enforce ALPN echo of client preference.
    #[serde(default = "default_alpn_enforce")]
    pub alpn_enforce: bool,

    /// Send PROXY protocol header when connecting to mask_host.
    /// 0 = disabled, 1 = v1 (text), 2 = v2 (binary).
    /// Allows the backend to see the real client IP.
    #[serde(default)]
    pub mask_proxy_protocol: u8,

    /// Enable shape-channel hardening on mask backend path by padding
    /// client->mask stream tail to configured buckets on stream end.
    #[serde(default = "default_mask_shape_hardening")]
    pub mask_shape_hardening: bool,

    /// Opt-in aggressive shape hardening mode.
    /// When enabled, masking may shape some backend-silent timeout paths and
    /// enforces strictly positive above-cap blur when blur is enabled.
    #[serde(default = "default_mask_shape_hardening_aggressive_mode")]
    pub mask_shape_hardening_aggressive_mode: bool,

    /// Minimum bucket size for mask shape hardening padding.
    #[serde(default = "default_mask_shape_bucket_floor_bytes")]
    pub mask_shape_bucket_floor_bytes: usize,

    /// Maximum bucket size for mask shape hardening padding.
    #[serde(default = "default_mask_shape_bucket_cap_bytes")]
    pub mask_shape_bucket_cap_bytes: usize,

    /// Add bounded random tail bytes even when total bytes already exceed
    /// mask_shape_bucket_cap_bytes.
    #[serde(default = "default_mask_shape_above_cap_blur")]
    pub mask_shape_above_cap_blur: bool,

    /// Maximum random bytes appended above cap when above-cap blur is enabled.
    #[serde(default = "default_mask_shape_above_cap_blur_max_bytes")]
    pub mask_shape_above_cap_blur_max_bytes: usize,

    /// Maximum bytes relayed per direction on unauthenticated masking fallback paths.
    #[serde(default = "default_mask_relay_max_bytes")]
    pub mask_relay_max_bytes: usize,

    /// Wall-clock cap for the full masking relay on non-MTProto fallback paths.
    /// Raise when the mask target is a long-lived service (e.g. WebSocket).
    /// Default: 60 000 ms (60 s).
    #[serde(default = "default_mask_relay_timeout_ms")]
    pub mask_relay_timeout_ms: u64,

    /// Per-read idle timeout on masking relay and drain paths.
    /// Limits resource consumption by slow-loris attacks and port scanners.
    /// A read call stalling beyond this is treated as an abandoned connection.
    /// Default: 5 000 ms (5 s).
    #[serde(default = "default_mask_relay_idle_timeout_ms")]
    pub mask_relay_idle_timeout_ms: u64,

    /// Prefetch timeout (ms) for extending fragmented masking classifier window.
    #[serde(default = "default_mask_classifier_prefetch_timeout_ms")]
    pub mask_classifier_prefetch_timeout_ms: u64,

    /// Enable outcome-time normalization envelope for masking fallback.
    #[serde(default = "default_mask_timing_normalization_enabled")]
    pub mask_timing_normalization_enabled: bool,

    /// Lower bound (ms) for masking outcome timing envelope.
    #[serde(default = "default_mask_timing_normalization_floor_ms")]
    pub mask_timing_normalization_floor_ms: u64,

    /// Upper bound (ms) for masking outcome timing envelope.
    #[serde(default = "default_mask_timing_normalization_ceiling_ms")]
    pub mask_timing_normalization_ceiling_ms: u64,
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        Self {
            tls_domain: default_tls_domain(),
            tls_domains: Vec::new(),
            unknown_sni_action: UnknownSniAction::Drop,
            tls_fetch_scope: default_tls_fetch_scope(),
            tls_fetch: TlsFetchConfig::default(),
            mask: default_true(),
            mask_host: None,
            mask_port: default_mask_port(),
            mask_unix_sock: None,
            fake_cert_len: default_fake_cert_len(),
            tls_emulation: true,
            tls_front_dir: default_tls_front_dir(),
            server_hello_delay_min_ms: default_server_hello_delay_min_ms(),
            server_hello_delay_max_ms: default_server_hello_delay_max_ms(),
            tls_new_session_tickets: default_tls_new_session_tickets(),
            tls_full_cert_ttl_secs: default_tls_full_cert_ttl_secs(),
            alpn_enforce: default_alpn_enforce(),
            mask_proxy_protocol: 0,
            mask_shape_hardening: default_mask_shape_hardening(),
            mask_shape_hardening_aggressive_mode: default_mask_shape_hardening_aggressive_mode(),
            mask_shape_bucket_floor_bytes: default_mask_shape_bucket_floor_bytes(),
            mask_shape_bucket_cap_bytes: default_mask_shape_bucket_cap_bytes(),
            mask_shape_above_cap_blur: default_mask_shape_above_cap_blur(),
            mask_shape_above_cap_blur_max_bytes: default_mask_shape_above_cap_blur_max_bytes(),
            mask_relay_max_bytes: default_mask_relay_max_bytes(),
            mask_relay_timeout_ms: default_mask_relay_timeout_ms(),
            mask_relay_idle_timeout_ms: default_mask_relay_idle_timeout_ms(),
            mask_classifier_prefetch_timeout_ms: default_mask_classifier_prefetch_timeout_ms(),
            mask_timing_normalization_enabled: default_mask_timing_normalization_enabled(),
            mask_timing_normalization_floor_ms: default_mask_timing_normalization_floor_ms(),
            mask_timing_normalization_ceiling_ms: default_mask_timing_normalization_ceiling_ms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(default = "default_access_users")]
    pub users: HashMap<String, String>,

    /// Per-user ad_tag (32 hex chars from @MTProxybot).
    #[serde(default)]
    pub user_ad_tags: HashMap<String, String>,

    #[serde(default)]
    pub user_max_tcp_conns: HashMap<String, usize>,

    /// Global per-user TCP connection limit applied when a user has no
    /// positive individual override.
    /// `0` disables the inherited limit.
    #[serde(default = "default_user_max_tcp_conns_global_each")]
    pub user_max_tcp_conns_global_each: usize,

    #[serde(default)]
    pub user_expirations: HashMap<String, DateTime<Utc>>,

    #[serde(default)]
    pub user_data_quota: HashMap<String, u64>,

    #[serde(default)]
    pub user_max_unique_ips: HashMap<String, usize>,

    /// Global per-user unique IP limit applied when a user has no individual override.
    /// `0` disables the inherited limit.
    #[serde(default = "default_user_max_unique_ips_global_each")]
    pub user_max_unique_ips_global_each: usize,

    #[serde(default)]
    pub user_max_unique_ips_mode: UserMaxUniqueIpsMode,

    #[serde(default = "default_user_max_unique_ips_window_secs")]
    pub user_max_unique_ips_window_secs: u64,

    #[serde(default = "default_replay_check_len")]
    pub replay_check_len: usize,

    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: u64,

    #[serde(default)]
    pub ignore_time_skew: bool,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            users: default_access_users(),
            user_ad_tags: HashMap::new(),
            user_max_tcp_conns: HashMap::new(),
            user_max_tcp_conns_global_each: default_user_max_tcp_conns_global_each(),
            user_expirations: HashMap::new(),
            user_data_quota: HashMap::new(),
            user_max_unique_ips: HashMap::new(),
            user_max_unique_ips_global_each: default_user_max_unique_ips_global_each(),
            user_max_unique_ips_mode: UserMaxUniqueIpsMode::default(),
            user_max_unique_ips_window_secs: default_user_max_unique_ips_window_secs(),
            replay_check_len: default_replay_check_len(),
            replay_window_secs: default_replay_window_secs(),
            ignore_time_skew: false,
        }
    }
}

// ============= Aux Structures =============

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UpstreamType {
    Direct {
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        bind_addresses: Option<Vec<String>>,
    },
    Socks4 {
        address: String,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        user_id: Option<String>,
    },
    Socks5 {
        address: String,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Shadowsocks {
        url: String,
        #[serde(default)]
        interface: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(flatten)]
    pub upstream_type: UpstreamType,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scopes: String,
    #[serde(skip)]
    pub selected_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub ip: IpAddr,
    /// IP address or hostname to announce in proxy links.
    /// Takes precedence over `announce_ip` if both are set.
    #[serde(default)]
    pub announce: Option<String>,
    /// Deprecated: Use `announce` instead. IP address to announce in proxy links.
    /// Migrated to `announce` automatically if `announce` is not set.
    #[serde(default)]
    pub announce_ip: Option<IpAddr>,
    /// Per-listener PROXY protocol override. When set, overrides global server.proxy_protocol.
    #[serde(default)]
    pub proxy_protocol: Option<bool>,
    /// Allow multiple telemt instances to listen on the same IP:port (SO_REUSEPORT).
    /// Default is false for safety.
    #[serde(default)]
    pub reuse_allow: bool,
}

// ============= ShowLink =============

/// Controls which users' proxy links are displayed at startup.
///
/// In TOML, this can be:
/// - `show_link = "*"`          — show links for all users
/// - `show_link = ["a", "b"]`   — show links for specific users
/// - omitted                    — default depends on the owning config field
#[derive(Debug, Clone, Default)]
pub enum ShowLink {
    /// Don't show any links (default when omitted).
    #[default]
    None,
    /// Show links for all configured users.
    All,
    /// Show links for specific users.
    Specific(Vec<String>),
}

fn default_links_show() -> ShowLink {
    ShowLink::All
}

impl ShowLink {
    /// Returns true if no links should be shown.
    pub fn is_empty(&self) -> bool {
        matches!(self, ShowLink::None) || matches!(self, ShowLink::Specific(v) if v.is_empty())
    }

    /// Resolve the list of user names to display, given all configured users.
    pub fn resolve_users<'a>(&'a self, all_users: &'a HashMap<String, String>) -> Vec<&'a String> {
        match self {
            ShowLink::None => vec![],
            ShowLink::All => {
                let mut names: Vec<&String> = all_users.keys().collect();
                names.sort();
                names
            }
            ShowLink::Specific(names) => names.iter().collect(),
        }
    }
}

impl Serialize for ShowLink {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            ShowLink::None => Vec::<String>::new().serialize(serializer),
            ShowLink::All => serializer.serialize_str("*"),
            ShowLink::Specific(v) => v.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ShowLink {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de;

        struct ShowLinkVisitor;

        impl<'de> de::Visitor<'de> for ShowLinkVisitor {
            type Value = ShowLink;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#""*" or an array of user names"#)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<ShowLink, E> {
                if v == "*" {
                    Ok(ShowLink::All)
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(v), &r#""*""#))
                }
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<ShowLink, A::Error> {
                let mut names = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    names.push(name);
                }
                if names.is_empty() {
                    Ok(ShowLink::None)
                } else {
                    Ok(ShowLink::Specific(names))
                }
            }
        }

        deserializer.deserialize_any(ShowLinkVisitor)
    }
}
