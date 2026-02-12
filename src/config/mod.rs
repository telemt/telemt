//! Configuration

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::error::{ProxyError, Result};

// ============= Helper Defaults =============

fn default_true() -> bool { true }
fn default_port() -> u16 { 443 }
fn default_tls_domain() -> String { "www.google.com".to_string() }
fn default_mask_port() -> u16 { 443 }
fn default_replay_check_len() -> usize { 65536 }
fn default_replay_window_secs() -> u64 { 1800 }
fn default_handshake_timeout() -> u64 { 15 }
fn default_connect_timeout() -> u64 { 10 }
fn default_keepalive() -> u64 { 60 }
fn default_ack_timeout() -> u64 { 300 }
fn default_listen_addr() -> String { "0.0.0.0".to_string() }
fn default_fake_cert_len() -> usize { 2048 }
fn default_weight() -> u16 { 1 }
fn default_metrics_whitelist() -> Vec<IpAddr> {
    vec![
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
    ]
}

// ============= Log Level =============

/// Logging verbosity level
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// All messages including trace (trace + debug + info + warn + error)
    Debug,
    /// Detailed operational logs (debug + info + warn + error)
    Verbose,
    /// Standard operational logs (info + warn + error)
    #[default]
    Normal,
    /// Minimal output: only warnings and errors (warn + error).
    /// Startup messages (config, DC connectivity, proxy links) are always shown
    /// via info! before the filter is applied.
    Silent,
}

impl LogLevel {
    /// Convert to tracing EnvFilter directive string
    pub fn to_filter_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "trace",
            LogLevel::Verbose => "debug",
            LogLevel::Normal => "info",
            LogLevel::Silent => "warn",
        }
    }

    /// Parse from a loose string (CLI argument)
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
        Self { classic: true, secure: true, tls: true }
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
    
    #[serde(default)]
    pub use_middle_proxy: bool,

    #[serde(default)]
    pub ad_tag: Option<String>,
    
    #[serde(default)]
    pub log_level: LogLevel,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            modes: ProxyModes::default(),
            prefer_ipv6: false,
            fast_mode: true,
            use_middle_proxy: false,
            ad_tag: None,
            log_level: LogLevel::Normal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_listen_addr")]
    pub listen_addr_ipv4: String,
    
    #[serde(default)]
    pub listen_addr_ipv6: Option<String>,
    
    #[serde(default)]
    pub listen_unix_sock: Option<String>,
    
    #[serde(default)]
    pub metrics_port: Option<u16>,
    
    #[serde(default = "default_metrics_whitelist")]
    pub metrics_whitelist: Vec<IpAddr>,

    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            listen_addr_ipv4: default_listen_addr(),
            listen_addr_ipv6: Some("::".to_string()),
            listen_unix_sock: None,
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
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            client_handshake: default_handshake_timeout(),
            tg_connect: default_connect_timeout(),
            client_keepalive: default_keepalive(),
            client_ack: default_ack_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCensorshipConfig {
    #[serde(default = "default_tls_domain")]
    pub tls_domain: String,
    
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
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        Self {
            tls_domain: default_tls_domain(),
            mask: true,
            mask_host: None,
            mask_port: default_mask_port(),
            mask_unix_sock: None,
            fake_cert_len: default_fake_cert_len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(default)]
    pub users: HashMap<String, String>,

    #[serde(default)]
    pub user_max_tcp_conns: HashMap<String, usize>,
    
    #[serde(default)]
    pub user_expirations: HashMap<String, DateTime<Utc>>,
    
    #[serde(default)]
    pub user_data_quota: HashMap<String, u64>,

    #[serde(default = "default_replay_check_len")]
    pub replay_check_len: usize,
    
    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: u64,
    
    #[serde(default)]
    pub ignore_time_skew: bool,
}

impl Default for AccessConfig {
    fn default() -> Self {
        let mut users = HashMap::new();
        users.insert("default".to_string(), "00000000000000000000000000000000".to_string());
        Self {
            users,
            user_max_tcp_conns: HashMap::new(),
            user_expirations: HashMap::new(),
            user_data_quota: HashMap::new(),
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub ip: IpAddr,
    #[serde(default)]
    pub announce_ip: Option<IpAddr>,
}

// ============= Main Config =============

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub general: GeneralConfig,

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
    pub show_link: Vec<String>,

    /// DC address overrides for non-standard DCs (CDN, media, test, etc.)
    /// Keys are DC indices as strings, values are "ip:port" addresses.
    /// Matches the C implementation's `proxy_for <dc_id> <ip>:<port>` config directive.
    /// Example in config.toml:
    ///   [dc_overrides]
    ///   "203" = "149.154.175.100:443"
    #[serde(default)]
    pub dc_overrides: HashMap<String, String>,

    /// Default DC index (1-5) for unmapped non-standard DCs.
    /// Matches the C implementation's `default <dc_id>` config directive.
    /// If not set, defaults to 2 (matching Telegram's official `default 2;` in proxy-multi.conf).
    #[serde(default)]
    pub default_dc: Option<u8>,
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(e.to_string()))?;
        
        let mut config: ProxyConfig = toml::from_str(&content)
            .map_err(|e| ProxyError::Config(e.to_string()))?;
        
        // Validate secrets
        for (user, secret) in &config.access.users {
            if !secret.chars().all(|c| c.is_ascii_hexdigit()) || secret.len() != 32 {
                return Err(ProxyError::InvalidSecret {
                    user: user.clone(),
                    reason: "Must be 32 hex characters".to_string(),
                });
            }
        }
        
        // Validate tls_domain
        if config.censorship.tls_domain.is_empty() {
            return Err(ProxyError::Config("tls_domain cannot be empty".to_string()));
        }
        
        // Validate mask_unix_sock
        if let Some(ref sock_path) = config.censorship.mask_unix_sock {
            if sock_path.is_empty() {
                return Err(ProxyError::Config(
                    "mask_unix_sock cannot be empty".to_string()
                ));
            }
            #[cfg(unix)]
            if sock_path.len() > 107 {
                return Err(ProxyError::Config(
                    format!("mask_unix_sock path too long: {} bytes (max 107)", sock_path.len())
                ));
            }
            #[cfg(not(unix))]
            return Err(ProxyError::Config(
                "mask_unix_sock is only supported on Unix platforms".to_string()
            ));

            if config.censorship.mask_host.is_some() {
                return Err(ProxyError::Config(
                    "mask_unix_sock and mask_host are mutually exclusive".to_string()
                ));
            }
        }

        // Default mask_host to tls_domain if not set and no unix socket configured
        if config.censorship.mask_host.is_none() && config.censorship.mask_unix_sock.is_none() {
            config.censorship.mask_host = Some(config.censorship.tls_domain.clone());
        }
        
        // Random fake_cert_len
        use rand::Rng;
        config.censorship.fake_cert_len = rand::rng().gen_range(1024..4096);
        
        // Migration: Populate listeners if empty
        if config.server.listeners.is_empty() {
            if let Ok(ipv4) = config.server.listen_addr_ipv4.parse::<IpAddr>() {
                config.server.listeners.push(ListenerConfig {
                    ip: ipv4,
                    announce_ip: None,
                });
            }
            if let Some(ipv6_str) = &config.server.listen_addr_ipv6 {
                 if let Ok(ipv6) = ipv6_str.parse::<IpAddr>() {
                    config.server.listeners.push(ListenerConfig {
                        ip: ipv6,
                        announce_ip: None,
                    });
                }
            }
        }

        // Migration: Populate upstreams if empty (Default Direct)
        if config.upstreams.is_empty() {
             config.upstreams.push(UpstreamConfig {
                upstream_type: UpstreamType::Direct { interface: None },
                weight: 1,
                enabled: true,
            });
        }
        
        Ok(config)
    }
    
    pub fn validate(&self) -> Result<()> {
        if self.access.users.is_empty() {
            return Err(ProxyError::Config("No users configured".to_string()));
        }
        
        if !self.general.modes.classic && !self.general.modes.secure && !self.general.modes.tls {
            return Err(ProxyError::Config("No modes enabled".to_string()));
        }
        
        if self.censorship.tls_domain.contains(' ') || self.censorship.tls_domain.contains('/') {
            return Err(ProxyError::Config(
                format!("Invalid tls_domain: '{}'. Must be a valid domain name", self.censorship.tls_domain)
            ));
        }

        Ok(())
    }
}