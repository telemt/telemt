use super::*;

/// Highest rate that fits one packed 20 ms shaping epoch.
pub(crate) const MAX_RATE_LIMIT_BPS: u64 = 100_000_000_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(default = "default_access_users")]
    pub users: HashMap<String, String>,

    #[serde(default)]
    pub user_enabled: HashMap<String, bool>,

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

    /// Optional UTC calendar for users with a positive data quota.
    #[serde(default)]
    pub user_quota_periods: HashMap<String, UserQuotaPeriod>,

    /// Per-user transport rate limits in bits-per-second.
    ///
    /// Each entry supports independent upload (`up_bps`) and download
    /// (`down_bps`) ceilings. A value of `0` in one direction means
    /// "unlimited" for that direction. Limits are amortized: a relay quantum
    /// may pass as a bounded burst, and the limiter applies the resulting wait
    /// before later traffic in the same direction proceeds.
    #[serde(default)]
    pub user_rate_limits: HashMap<String, RateLimitBps>,

    /// Per-CIDR aggregate transport rate limits in bits-per-second.
    ///
    /// Explicit CIDR keys use longest-prefix-wins semantics. Auto-template
    /// keys (`*4/N`, `*6/N`, `*/N`) lazily create per-source-subnet buckets
    /// after explicit CIDR matching misses. A value of `0` in one direction
    /// means "unlimited" for that direction. Limits are amortized with the
    /// same bounded-burst contract as per-user rate limits.
    #[serde(default)]
    pub cidr_rate_limits: HashMap<CidrRateLimitKey, RateLimitBps>,

    /// Per-username client source IP/CIDR deny list. Checked after successful
    /// authentication; matching IPs get the same rejection path as invalid auth
    /// (handshake fails closed for that connection).
    #[serde(default)]
    pub user_source_deny: HashMap<String, Vec<IpNetwork>>,

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
            user_enabled: HashMap::new(),
            user_ad_tags: HashMap::new(),
            user_max_tcp_conns: HashMap::new(),
            user_max_tcp_conns_global_each: default_user_max_tcp_conns_global_each(),
            user_expirations: HashMap::new(),
            user_data_quota: HashMap::new(),
            user_quota_periods: HashMap::new(),
            user_rate_limits: HashMap::new(),
            cidr_rate_limits: HashMap::new(),
            user_source_deny: HashMap::new(),
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

impl AccessConfig {
    /// Validates the opt-in calendar against the bounded durable quota inventory.
    pub(crate) fn validate_quota_periods(&self) -> crate::error::Result<()> {
        if !self.user_quota_periods.is_empty() && self.users.len() > 65_536 {
            return Err(crate::error::ProxyError::Config(
                "quota periods support at most 65536 configured users".to_string(),
            ));
        }
        for user in self.user_quota_periods.keys() {
            if !self.users.contains_key(user)
                || !self
                    .user_data_quota
                    .get(user)
                    .is_some_and(|quota| *quota > 0)
            {
                return Err(crate::error::ProxyError::Config(format!(
                    "access.user_quota_periods.{user} requires an existing user with a positive data quota"
                )));
            }
        }
        Ok(())
    }

    pub fn is_user_enabled(&self, username: &str) -> bool {
        self.user_enabled.get(username).copied().unwrap_or(true)
    }

    /// Returns true if `ip` is contained in any CIDR listed for `username` under `user_source_deny`.
    pub fn is_user_source_ip_denied(&self, username: &str, ip: IpAddr) -> bool {
        self.user_source_deny
            .get(username)
            .is_some_and(|nets| nets.iter().any(|n| n.contains(ip)))
    }
}

/// Key used by `access.cidr_rate_limits`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CidrRateLimitKey {
    /// Explicit source CIDR rule.
    Network(IpNetwork),
    /// IPv4 auto-template that creates one bucket for each matching `/N`.
    AutoV4(u8),
    /// IPv6 auto-template that creates one bucket for each matching `/N`.
    AutoV6(u8),
    /// Dual-stack auto-template; IPv4 uses `/N`, IPv6 uses `/(N * 4)`.
    AutoDual(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CidrAutoTemplateFamily {
    V4,
    V6,
}

impl CidrAutoTemplateFamily {
    pub(crate) fn marker(self) -> &'static str {
        match self {
            Self::V4 => "*4",
            Self::V6 => "*6",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CidrAutoTemplate {
    pub(crate) family: CidrAutoTemplateFamily,
    pub(crate) prefix_len: u8,
}

impl fmt::Display for CidrAutoTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.family.marker(), self.prefix_len)
    }
}

impl CidrRateLimitKey {
    pub(crate) fn auto_templates(&self) -> [Option<CidrAutoTemplate>; 2] {
        match *self {
            Self::Network(_) => [None, None],
            Self::AutoV4(prefix_len) => [
                Some(CidrAutoTemplate {
                    family: CidrAutoTemplateFamily::V4,
                    prefix_len,
                }),
                None,
            ],
            Self::AutoV6(prefix_len) => [
                Some(CidrAutoTemplate {
                    family: CidrAutoTemplateFamily::V6,
                    prefix_len,
                }),
                None,
            ],
            Self::AutoDual(prefix_len) => [
                Some(CidrAutoTemplate {
                    family: CidrAutoTemplateFamily::V4,
                    prefix_len,
                }),
                Some(CidrAutoTemplate {
                    family: CidrAutoTemplateFamily::V6,
                    prefix_len: prefix_len.saturating_mul(4),
                }),
            ],
        }
    }
}

impl fmt::Display for CidrRateLimitKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(cidr) => write!(formatter, "{cidr}"),
            Self::AutoV4(prefix_len) => write!(formatter, "*4/{prefix_len}"),
            Self::AutoV6(prefix_len) => write!(formatter, "*6/{prefix_len}"),
            Self::AutoDual(prefix_len) => write!(formatter, "*/{prefix_len}"),
        }
    }
}

impl Serialize for CidrRateLimitKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CidrRateLimitKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_cidr_rate_limit_key(&value).map_err(serde::de::Error::custom)
    }
}

fn parse_cidr_rate_limit_key(value: &str) -> std::result::Result<CidrRateLimitKey, String> {
    if let Some(prefix) = value.strip_prefix("*4/") {
        return parse_cidr_auto_prefix(value, prefix, 32).map(CidrRateLimitKey::AutoV4);
    }
    if let Some(prefix) = value.strip_prefix("*6/") {
        return parse_cidr_auto_prefix(value, prefix, 128).map(CidrRateLimitKey::AutoV6);
    }
    if let Some(prefix) = value.strip_prefix("*/") {
        return parse_cidr_auto_prefix(value, prefix, 32).map(CidrRateLimitKey::AutoDual);
    }
    if value.starts_with('*') {
        return Err(format!(
            "invalid CIDR rate limit key {value:?}; expected CIDR, *4/N, *6/N, or */N"
        ));
    }
    value
        .parse::<IpNetwork>()
        .map(CidrRateLimitKey::Network)
        .map_err(|error| {
            format!(
                "invalid CIDR rate limit key {value:?}: {error}; expected CIDR, *4/N, *6/N, or */N"
            )
        })
}

fn parse_cidr_auto_prefix(
    key: &str,
    prefix: &str,
    max_prefix: u8,
) -> std::result::Result<u8, String> {
    let prefix = prefix.parse::<u8>().map_err(|_| {
        format!("invalid CIDR auto-template key {key:?}; prefix must be within 0..={max_prefix}")
    })?;
    if prefix > max_prefix {
        return Err(format!(
            "invalid CIDR auto-template key {key:?}; prefix must be within 0..={max_prefix}"
        ));
    }
    Ok(prefix)
}

/// Transport rate limit in bits-per-second.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitBps {
    /// Upload limit in bits-per-second within `0..=100_000_000_000`; `0` means unlimited.
    #[serde(default)]
    pub up_bps: u64,
    /// Download limit in bits-per-second within `0..=100_000_000_000`; `0` means unlimited.
    #[serde(default)]
    pub down_bps: u64,
}
