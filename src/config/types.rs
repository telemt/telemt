use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

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
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv4: default_true(),
            ipv6: default_network_ipv6(),
            prefer: default_prefer_4(),
            multipath: false,
            stun_servers: default_stun_servers(),
            stun_tcp_fallback: default_stun_tcp_fallback(),
            http_ip_detect_urls: default_http_ip_detect_urls(),
            cache_public_ip_path: default_cache_public_ip_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default)]
    pub modes: ProxyModes,

    #[serde(default)]
    pub prefer_ipv6: bool,

    #[serde(default = "default_true")]
    pub fast_mode: bool,

    #[serde(default = "default_true")]
    pub use_middle_proxy: bool,

    #[serde(default)]
    pub ad_tag: Option<String>,

    /// Path to proxy-secret binary file (auto-downloaded if absent).
    /// Infrastructure secret from https://core.telegram.org/getProxySecret.
    #[serde(default = "default_proxy_secret_path")]
    pub proxy_secret_path: Option<String>,

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

    /// Ignore STUN/interface IP mismatch (keep using Middle Proxy even if NAT detected).
    #[serde(default)]
    pub stun_iface_mismatch_ignore: bool,

    /// Log unknown (non-standard) DC requests to a file (default: unknown-dc.txt). Set to null to disable.
    #[serde(default = "default_unknown_dc_log_path")]
    pub unknown_dc_log_path: Option<String>,

    #[serde(default)]
    pub log_level: LogLevel,

    /// Disable colored output in logs (useful for files/systemd).
    #[serde(default)]
    pub disable_colors: bool,

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

    /// Number of identical getProxySecret snapshots required before runtime secret rotation.
    #[serde(default = "default_proxy_secret_stable_snapshots")]
    pub proxy_secret_stable_snapshots: u8,

    /// Enable runtime proxy-secret rotation from getProxySecret.
    #[serde(default = "default_proxy_secret_rotate_runtime")]
    pub proxy_secret_rotate_runtime: bool,

    /// Maximum allowed proxy-secret length in bytes for startup and runtime refresh.
    #[serde(default = "default_proxy_secret_len_max")]
    pub proxy_secret_len_max: usize,

    /// Drain-TTL in seconds for stale ME writers after endpoint map changes.
    /// During TTL, stale writers may be used only as fallback for new bindings.
    #[serde(default = "default_me_pool_drain_ttl_secs")]
    pub me_pool_drain_ttl_secs: u64,

    /// Minimum desired-DC coverage ratio required before draining stale writers.
    /// Range: 0.0..=1.0.
    #[serde(default = "default_me_pool_min_fresh_ratio")]
    pub me_pool_min_fresh_ratio: f32,

    /// Drain timeout in seconds for stale ME writers after endpoint map changes.
    /// Set to 0 to keep stale writers draining indefinitely (no force-close).
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
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            modes: ProxyModes::default(),
            prefer_ipv6: false,
            fast_mode: default_true(),
            use_middle_proxy: default_true(),
            ad_tag: None,
            proxy_secret_path: default_proxy_secret_path(),
            middle_proxy_nat_ip: None,
            middle_proxy_nat_probe: default_true(),
            middle_proxy_nat_stun: default_middle_proxy_nat_stun(),
            middle_proxy_nat_stun_servers: default_middle_proxy_nat_stun_servers(),
            stun_nat_probe_concurrency: default_stun_nat_probe_concurrency(),
            middle_proxy_pool_size: default_pool_size(),
            middle_proxy_warm_standby: default_middle_proxy_warm_standby(),
            me_keepalive_enabled: default_true(),
            me_keepalive_interval_secs: default_keepalive_interval(),
            me_keepalive_jitter_secs: default_keepalive_jitter(),
            me_keepalive_payload_random: default_true(),
            me_warmup_stagger_enabled: default_true(),
            me_warmup_step_delay_ms: default_warmup_step_delay_ms(),
            me_warmup_step_jitter_ms: default_warmup_step_jitter_ms(),
            me_reconnect_max_concurrent_per_dc: default_me_reconnect_max_concurrent_per_dc(),
            me_reconnect_backoff_base_ms: default_reconnect_backoff_base_ms(),
            me_reconnect_backoff_cap_ms: default_reconnect_backoff_cap_ms(),
            me_reconnect_fast_retry_count: default_me_reconnect_fast_retry_count(),
            stun_iface_mismatch_ignore: false,
            unknown_dc_log_path: default_unknown_dc_log_path(),
            log_level: LogLevel::Normal,
            disable_colors: false,
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
            me_hardswap_warmup_pass_backoff_base_ms: default_me_hardswap_warmup_pass_backoff_base_ms(),
            me_config_stable_snapshots: default_me_config_stable_snapshots(),
            me_config_apply_cooldown_secs: default_me_config_apply_cooldown_secs(),
            proxy_secret_stable_snapshots: default_proxy_secret_stable_snapshots(),
            proxy_secret_rotate_runtime: default_proxy_secret_rotate_runtime(),
            proxy_secret_len_max: default_proxy_secret_len_max(),
            me_pool_drain_ttl_secs: default_me_pool_drain_ttl_secs(),
            me_pool_min_fresh_ratio: default_me_pool_min_fresh_ratio(),
            me_reinit_drain_timeout_secs: default_me_reinit_drain_timeout_secs(),
            proxy_secret_auto_reload_secs: default_proxy_secret_reload_secs(),
            proxy_config_auto_reload_secs: default_proxy_config_reload_secs(),
            ntp_check: default_ntp_check(),
            ntp_servers: default_ntp_servers(),
            auto_degradation_enabled: default_true(),
            degradation_min_unavailable_dc_groups: default_degradation_min_unavailable_dc_groups(),
        }
    }
}

impl GeneralConfig {
    /// Resolve the active updater interval for ME infrastructure refresh tasks.
    /// `update_every` has priority, otherwise legacy proxy_*_auto_reload_secs are used.
    pub fn effective_update_every_secs(&self) -> u64 {
        self.update_every
            .unwrap_or_else(|| self.proxy_secret_auto_reload_secs.min(self.proxy_config_auto_reload_secs))
    }

    /// Resolve periodic zero-downtime reinit interval for ME writers.
    pub fn effective_me_reinit_every_secs(&self) -> u64 {
        self.me_reinit_every_secs
    }

    /// Resolve force-close timeout for stale writers.
    /// `me_reinit_drain_timeout_secs` remains backward-compatible alias.
    pub fn effective_me_pool_force_close_secs(&self) -> u64 {
        self.me_reinit_drain_timeout_secs
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

    #[serde(default)]
    pub metrics_port: Option<u16>,

    #[serde(default = "default_metrics_whitelist")]
    pub metrics_whitelist: Vec<IpNetwork>,

    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
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
            metrics_port: None,
            metrics_whitelist: default_metrics_whitelist(),
            listeners: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutsConfig {
    #[serde(default = "default_handshake_timeout")]
    pub client_handshake: u64,

    #[serde(default = "default_connect_timeout")]
    pub tg_connect: u64,

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
            client_handshake: default_handshake_timeout(),
            tg_connect: default_connect_timeout(),
            client_keepalive: default_keepalive(),
            client_ack: default_ack_timeout(),
            me_one_retry: default_me_one_retry(),
            me_one_timeout_ms: default_me_one_timeout(),
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
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        Self {
            tls_domain: default_tls_domain(),
            tls_domains: Vec::new(),
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(default = "default_access_users")]
    pub users: HashMap<String, String>,

    #[serde(default)]
    pub user_max_tcp_conns: HashMap<String, usize>,

    #[serde(default)]
    pub user_expirations: HashMap<String, DateTime<Utc>>,

    #[serde(default)]
    pub user_data_quota: HashMap<String, u64>,

    #[serde(default)]
    pub user_max_unique_ips: HashMap<String, usize>,

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
            user_max_tcp_conns: HashMap::new(),
            user_expirations: HashMap::new(),
            user_data_quota: HashMap::new(),
            user_max_unique_ips: HashMap::new(),
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
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            ShowLink::None => Vec::<String>::new().serialize(serializer),
            ShowLink::All => serializer.serialize_str("*"),
            ShowLink::Specific(v) => v.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ShowLink {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
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
                    Err(de::Error::invalid_value(
                        de::Unexpected::Str(v),
                        &r#""*""#,
                    ))
                }
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<ShowLink, A::Error> {
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
