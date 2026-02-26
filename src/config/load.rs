#![allow(deprecated)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use rand::Rng;
use tracing::warn;
use serde::{Serialize, Deserialize};

use crate::error::{ProxyError, Result};

use super::defaults::*;
use super::types::*;

fn preprocess_includes(content: &str, base_dir: &Path, depth: u8) -> Result<String> {
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
                let resolved = base_dir.join(path_str);
                let included = std::fs::read_to_string(&resolved)
                    .map_err(|e| ProxyError::Config(e.to_string()))?;
                let included_dir = resolved.parent().unwrap_or(base_dir);
                output.push_str(&preprocess_includes(&included, included_dir, depth + 1)?);
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
    ///   [dc_overrides]
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
        let content =
            std::fs::read_to_string(&path).map_err(|e| ProxyError::Config(e.to_string()))?;
        let base_dir = path.as_ref().parent().unwrap_or(Path::new("."));
        let processed = preprocess_includes(&content, base_dir, 0)?;

        let mut config: ProxyConfig =
            toml::from_str(&processed).map_err(|e| ProxyError::Config(e.to_string()))?;

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

        if config.general.me_reinit_every_secs == 0 {
            return Err(ProxyError::Config(
                "general.me_reinit_every_secs must be > 0".to_string(),
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

        if config.general.proxy_secret_stable_snapshots == 0 {
            return Err(ProxyError::Config(
                "general.proxy_secret_stable_snapshots must be > 0".to_string(),
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

        // Auto-enable NAT probe when Middle Proxy is requested.
        if config.general.use_middle_proxy && !config.general.middle_proxy_nat_probe {
            config.general.middle_proxy_nat_probe = true;
            warn!("Auto-enabled middle_proxy_nat_probe for middle proxy mode");
        }

        validate_network_cfg(&mut config.network)?;

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
            return Err(ProxyError::Config(format!(
                "Invalid tls_domain: '{}'. Must be a valid domain name",
                self.censorship.tls_domain
            )));
        }

        if let Some(tag) = &self.general.ad_tag {
            let zeros = "00000000000000000000000000000000";
            if tag == zeros {
                warn!("ad_tag is all zeros; register a valid proxy tag via @MTProxybot to enable sponsored channel");
            }
            if tag.len() != 32 || tag.chars().any(|c| !c.is_ascii_hexdigit()) {
                warn!("ad_tag is not a 32-char hex string; ensure you use value issued by @MTProxybot");
            }
        }

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
        let cfg: ProxyConfig = toml::from_str(toml).unwrap();

        assert_eq!(cfg.network.ipv6, None);
        assert!(!cfg.network.stun_tcp_fallback);
        assert_eq!(cfg.general.middle_proxy_warm_standby, 0);
        assert_eq!(cfg.general.me_reconnect_max_concurrent_per_dc, 0);
        assert_eq!(cfg.general.me_reconnect_fast_retry_count, 0);
        assert_eq!(cfg.general.update_every, None);
        assert_eq!(cfg.server.listen_addr_ipv4, None);
        assert_eq!(cfg.server.listen_addr_ipv6, None);
        assert!(cfg.access.users.is_empty());
    }

    #[test]
    fn impl_defaults_are_sourced_from_default_helpers() {
        let network = NetworkConfig::default();
        assert_eq!(network.ipv6, default_network_ipv6());
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
        assert_eq!(general.update_every, default_update_every());

        let server = ServerConfig::default();
        assert_eq!(server.listen_addr_ipv6, Some(default_listen_addr_ipv6()));

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
}
