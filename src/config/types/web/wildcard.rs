use serde::{Deserialize, Serialize};

/// Process-frozen bounds for automatic wildcard hostname handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebWildcardLimitsConfig {
    /// Maximum suffix and catch-all selectors across all source groups.
    pub max_rules: usize,
    /// Maximum complete profile scan and cold derivation cost for one request.
    pub max_profiles_per_request: usize,
    /// Maximum positively authenticated hosts retained; zero disables retention.
    pub cache_hosts: usize,
    /// Maximum charged bytes, including entries still borrowed after eviction.
    pub cache_bytes: usize,
    /// Sustained process-wide HMAC evaluation budget per minute.
    pub cold_hmac_per_minute: u32,
    /// Atomic cold-derivation burst measured in HMAC evaluations.
    pub cold_hmac_burst: u32,
}

impl Default for WebWildcardLimitsConfig {
    fn default() -> Self {
        Self {
            max_rules: 32,
            max_profiles_per_request: 256,
            cache_hosts: 256,
            cache_bytes: 8_388_608,
            cold_hmac_per_minute: 1_000_000,
            cold_hmac_burst: 65_536,
        }
    }
}
