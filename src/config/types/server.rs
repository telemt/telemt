use super::*;

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

/// Per-listener SYN limiter mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SynLimitMode {
    /// Disable SYN limiting for this listener.
    #[default]
    Off,
    /// Use iptables/ip6tables two-tier SYN-fix rules with the hashlimit match.
    Iptables,
    /// Use nftables two-tier SYN-fix rules with per-source token-bucket meters.
    Nftables,
    /// Use FreeBSD PF source tracking with connection-rate state limits.
    Pf,
}

/// Application protocol accepted by one process-owned TCP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListenerTransport {
    /// Existing MTProxy TCP listener behavior.
    #[default]
    Mtproxy,
    /// Plain HTTP WEB gateway behind a trusted TLS terminator.
    Web,
}

/// Trusted L7 source used to recover a WEB client's identity address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WebClientIpSource {
    /// Use one parseable `X-Forwarded-For` address or the trusted direct peer.
    #[default]
    XForwardedFor,
}

impl Serialize for SynLimitMode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Off => serializer.serialize_bool(false),
            Self::Iptables => serializer.serialize_str("iptables"),
            Self::Nftables => serializer.serialize_str("nftables"),
            Self::Pf => serializer.serialize_str("pf"),
        }
    }
}

impl<'de> Deserialize<'de> for SynLimitMode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SynLimitModeVisitor;

        impl<'de> serde::de::Visitor<'de> for SynLimitModeVisitor {
            type Value = SynLimitMode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("false, iptables, nftables, or pf")
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value {
                    Err(E::custom(
                        "synlimit=true is ambiguous; use \"iptables\", \"nftables\", or \"pf\"",
                    ))
                } else {
                    Ok(SynLimitMode::Off)
                }
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.trim().to_ascii_lowercase().as_str() {
                    "false" | "off" | "disabled" | "none" => Ok(SynLimitMode::Off),
                    "iptables" => Ok(SynLimitMode::Iptables),
                    "nftables" => Ok(SynLimitMode::Nftables),
                    "pf" => Ok(SynLimitMode::Pf),
                    _ => Err(E::custom(
                        "synlimit must be false, \"iptables\", \"nftables\", or \"pf\"",
                    )),
                }
            }
        }

        deserializer.deserialize_any(SynLimitModeVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConntrackControlConfig {
    /// Enables runtime conntrack-control worker for pressure mitigation.
    #[serde(default = "default_conntrack_control_enabled")]
    pub inline_conntrack_control: bool,

    /// Tracks whether inline_conntrack_control was explicitly set in config.
    #[serde(skip)]
    pub inline_conntrack_control_explicit: bool,

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
            inline_conntrack_control_explicit: false,
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
    /// Legacy listener port used for backward compatibility.
    /// For new configs prefer `[[server.listeners]].port`.
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

    /// Client-facing TCP MSS preset or custom value for all TCP listeners.
    /// Empty string or omitted value keeps the kernel default.
    #[serde(default)]
    pub client_mss: Option<String>,

    /// Experimental Linux-only bulk MSS used with best-effort userspace
    /// chunking of the authenticated FakeTLS response. TCP offloads, loss, and
    /// retransmission may coalesce write boundaries. Empty or omitted keeps
    /// `client_mss` connection-wide. Uses the same preset/integer grammar as
    /// `client_mss`.
    #[serde(default)]
    pub client_mss_bulk: Option<String>,

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

    /// Maximum number of concurrent unauthenticated handshakes from one client
    /// IP address. A slot is held only while the handshake is in progress and
    /// is released on success, failure, timeout or masking fallback, so
    /// authenticated sessions are never counted. `0` disables the limit.
    #[serde(default = "default_max_pending_handshakes_per_ip")]
    pub max_pending_handshakes_per_ip: u32,

    /// Observe `max_pending_handshakes_per_ip` without enforcing it: excess
    /// handshakes are admitted and only counted in metrics.
    #[serde(default)]
    pub pending_handshakes_per_ip_dry_run: bool,

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
            client_mss: None,
            client_mss_bulk: None,
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
            max_pending_handshakes_per_ip: default_max_pending_handshakes_per_ip(),
            pending_handshakes_per_ip_dry_run: false,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub ip: IpAddr,
    /// Application protocol accepted by this listener.
    #[serde(default)]
    pub transport: ListenerTransport,
    /// Per-listener TCP port. If omitted, falls back to legacy `server.port`.
    #[serde(default)]
    pub port: Option<u16>,
    /// Per-listener client-facing TCP MSS preset or custom value.
    /// Empty string disables MSS shaping for this listener.
    #[serde(default)]
    pub client_mss: Option<String>,
    /// Per-listener SYN limiter mode.
    #[serde(default)]
    pub synlimit: SynLimitMode,
    /// Generic SYN-fix token-bucket rate interval.
    #[serde(default = "default_synlimit_seconds")]
    pub synlimit_seconds: u32,
    /// Generic SYN-fix token-bucket rate amount.
    #[serde(default = "default_synlimit_hitcount")]
    pub synlimit_hitcount: u32,
    /// Generic SYN-fix token-bucket burst size.
    #[serde(default = "default_synlimit_burst")]
    pub synlimit_burst: u32,
    /// iOS-like SYN-fix token-bucket rate interval.
    #[serde(default = "default_synlimit_ios_seconds")]
    pub synlimit_ios_seconds: u32,
    /// iOS-like SYN-fix token-bucket rate amount.
    #[serde(default = "default_synlimit_ios_hitcount")]
    pub synlimit_ios_hitcount: u32,
    /// iOS-like SYN-fix token-bucket burst size.
    #[serde(default = "default_synlimit_ios_burst")]
    pub synlimit_ios_burst: u32,
    /// Hashlimit entry expiration in milliseconds for iptables/ip6tables rules.
    #[serde(default = "default_synlimit_hashlimit_expire_ms")]
    pub synlimit_hashlimit_expire_ms: u32,
    /// Hashlimit table size for iptables/ip6tables rules.
    #[serde(default = "default_synlimit_hashlimit_size")]
    pub synlimit_hashlimit_size: u32,
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
    /// L7 header policy used only by WEB listeners.
    #[serde(default)]
    pub web_client_ip_source: WebClientIpSource,
    /// Immediate socket peers allowed to provide the WEB client identity header.
    #[serde(default)]
    pub web_trusted_proxy_cidrs: Vec<IpNetwork>,
}

/// Client-facing TCP MSS preset for extreme-low fragmentation profiles.
pub const CLIENT_MSS_EXTREME_LOW: u16 = 88;
/// Client-facing TCP MSS preset matching TSPU-oriented deployments.
pub const CLIENT_MSS_TSPU: u16 = 92;
/// Client-facing TCP MSS preset for 2-in-8 segment shaping.
pub const CLIENT_MSS_2IN8: u16 = 256;
/// Minimum accepted custom client-facing TCP MSS value.
pub const CLIENT_MSS_MIN: u16 = CLIENT_MSS_EXTREME_LOW;
/// Maximum accepted custom client-facing TCP MSS value.
pub const CLIENT_MSS_MAX: u16 = 4096;

impl ServerConfig {
    /// Resolves the global client-facing TCP MSS setting.
    pub fn client_mss_value(&self) -> std::result::Result<Option<u16>, String> {
        parse_client_mss(self.client_mss.as_deref())
    }

    /// Resolves the bulk-transfer client MSS, if configured.
    pub fn client_mss_bulk_value(&self) -> std::result::Result<Option<u16>, String> {
        parse_client_mss(self.client_mss_bulk.as_deref())
    }
}

impl ListenerConfig {
    /// Resolves the listener MSS override, falling back to the global server value.
    pub fn effective_client_mss(
        &self,
        server: &ServerConfig,
    ) -> std::result::Result<Option<u16>, String> {
        match self.client_mss.as_deref() {
            Some(value) => parse_client_mss(Some(value)),
            None => server.client_mss_value(),
        }
    }
}

fn parse_client_mss(raw: Option<&str>) -> std::result::Result<Option<u16>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }

    match value.to_ascii_lowercase().as_str() {
        "extreme-low" => return Ok(Some(CLIENT_MSS_EXTREME_LOW)),
        "tspu" => return Ok(Some(CLIENT_MSS_TSPU)),
        "2in8" => return Ok(Some(CLIENT_MSS_2IN8)),
        _ => {}
    }

    let parsed = value
        .parse::<u16>()
        .map_err(|_| "must be \"\", extreme-low, tspu, 2in8, or a decimal value".to_string())?;
    if !(CLIENT_MSS_MIN..=CLIENT_MSS_MAX).contains(&parsed) {
        return Err(format!(
            "custom value must be within [{CLIENT_MSS_MIN}, {CLIENT_MSS_MAX}]"
        ));
    }
    Ok(Some(parsed))
}
