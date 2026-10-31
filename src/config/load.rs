#![allow(deprecated)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngExt;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::crypto::sha256;
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
// Validated immutable WEB configuration and static-site snapshots.
mod runtime_web;
// Post-deserialization validation helpers.
mod decode;
mod effective;
mod pipeline;
// Candidate-owned DNS preparation is separate from pure runtime reconstruction.
mod decoy_dns;
mod validate_core;
mod validate_me;
mod validate_runtime;
mod validate_server;
mod validate_web;
mod validation;

#[cfg(test)]
use self::includes::normalize_config_path;
use self::includes::{
    hash_rendered_snapshot, preprocess_includes, read_config_source,
};
use self::normalize::{
    is_valid_ad_tag, is_valid_tls_domain_name, normalize_domain_to_ascii,
    normalize_exclusive_mask_target, normalize_mask_host_to_ascii, parse_exclusive_mask_target,
    push_unique_nonempty, sanitize_ad_tag,
};
pub(crate) use self::runtime_auth::UserAuthSnapshot;
use self::strict_keys::handle_unknown_config_keys;
use self::validation::{
    normalize_upstream_family_policy, validate_listener_runtime_profiles, validate_logging_config,
    validate_network_cfg, validate_upstreams,
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
/// Validated config plus the exact recursive source snapshot used to build it.
pub(crate) struct LoadedConfig {
    /// Validated and normalized effective configuration.
    pub(crate) config: ProxyConfig,
    /// Normalized absolute paths participating in the recursive include graph.
    pub(crate) source_files: Vec<PathBuf>,
    /// Raw source bytes keyed by normalized absolute source path.
    pub(crate) source_contents: BTreeMap<PathBuf, String>,
    /// Legacy hash of the include-expanded rendered snapshot.
    pub(crate) rendered_hash: u64,
}

/// Normalized source configuration that has not acquired runtime DNS or static snapshots.
#[derive(Debug, Clone)]
pub(crate) struct ParsedConfigSource {
    /// Source-only configuration; must be prepared before runtime publication.
    pub(crate) config: ProxyConfig,
    /// Normalized paths in the captured include graph.
    pub(crate) source_files: Vec<PathBuf>,
    /// Exact source documents used for revisions and atomic mutation checks.
    pub(crate) source_contents: BTreeMap<PathBuf, String>,
    /// Source-only hash, independent of DNS answers.
    pub(crate) rendered_hash: u64,
}

/// Raw recursive source graph captured before typed deserialization.
#[derive(Debug, Clone)]
pub(crate) struct ConfigSourceGraph {
    /// Raw source bytes keyed by normalized absolute source path.
    pub(crate) source_contents: BTreeMap<PathBuf, String>,
    /// Include-expanded TOML used for typed deserialization.
    pub(crate) rendered: String,
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

    /// WEB carrier ingress and public-site fallback configuration.
    #[serde(default)]
    pub web: WebConfig,

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

    /// Monotonic start of source acquisition, used only for cold quota policy fencing.
    #[serde(skip)]
    pub(crate) quota_source_read_at: Option<std::time::Instant>,

    /// Precomputed authentication snapshot for handshake hot paths.
    #[serde(skip)]
    pub(crate) runtime_user_auth: Option<Arc<UserAuthSnapshot>>,
}

impl ProxyConfig {
    /// Loads runtime configuration from a TOML file.
    #[cfg(test)]
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_metadata(path).map(|loaded| loaded.config)
    }

    /// Loads typed configuration together with its source and rendered metadata.
    #[cfg(test)]
    pub(crate) fn load_with_metadata<P: AsRef<Path>>(path: P) -> Result<LoadedConfig> {
        Self::load_with_source_overrides(path, &BTreeMap::new())
    }

    /// Loads a typed snapshot while replacing selected captured source documents.
    #[cfg(test)]
    pub(crate) fn load_with_source_overrides<P: AsRef<Path>>(
        path: P,
        source_overrides: &BTreeMap<PathBuf, String>,
    ) -> Result<LoadedConfig> {
        let read_at = std::time::Instant::now();
        let graph = Self::read_source_graph_with_overrides(path, source_overrides)?;
        let mut loaded = Self::load_source_graph(graph)?;
        loaded.config.quota_source_read_at = Some(read_at);
        Ok(loaded)
    }

    /// Captures the raw include graph without requiring typed config validity.
    pub(crate) fn read_source_graph<P: AsRef<Path>>(path: P) -> Result<ConfigSourceGraph> {
        Self::read_source_graph_with_overrides(path, &BTreeMap::new())
    }

    /// Captures a raw include graph with in-memory source replacements.
    pub(crate) fn read_source_graph_with_overrides<P: AsRef<Path>>(
        path: P,
        source_overrides: &BTreeMap<PathBuf, String>,
    ) -> Result<ConfigSourceGraph> {
        let path = path.as_ref();
        let mut previous = Self::capture_source_graph(path, source_overrides)?;
        for _ in 0..2 {
            let current = Self::capture_source_graph(path, source_overrides)?;
            if current.source_contents == previous.source_contents
                && current.rendered == previous.rendered
            {
                return Ok(current);
            }
            previous = current;
        }
        Err(ProxyError::Config(
            "config source graph changed repeatedly while it was read".to_string(),
        ))
    }

    fn capture_source_graph(
        path: &Path,
        source_overrides: &BTreeMap<PathBuf, String>,
    ) -> Result<ConfigSourceGraph> {
        let path = path.as_ref();
        let (normalized_path, disk_content) = read_config_source(path)?;
        let content = source_overrides
            .get(&normalized_path)
            .cloned()
            .unwrap_or(disk_content);
        let base_dir = normalized_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let mut source_files = BTreeSet::new();
        source_files.insert(normalized_path.clone());
        let mut source_contents = BTreeMap::new();
        source_contents.insert(normalized_path, content.clone());
        let processed = preprocess_includes(
            &content,
            &base_dir,
            0,
            &mut source_files,
            &mut source_contents,
            source_overrides,
        )?;

        Ok(ConfigSourceGraph {
            source_contents,
            rendered: processed,
        })
    }

    #[cfg(test)]
    fn load_source_graph(graph: ConfigSourceGraph) -> Result<LoadedConfig> {
        pipeline::load_source_graph(graph)
    }

    /// Parses source without resolving decoys or creating runtime WEB snapshots.
    pub(crate) fn parse_source<P: AsRef<Path>>(path: P) -> Result<ParsedConfigSource> {
        Self::parse_source_with_overrides(path, &BTreeMap::new())
    }

    /// Checks decoy mode-specific keys before a source or API patch loses unknown fields.
    pub(crate) fn validate_decoy_source_keys(document: &toml::Value) -> Result<()> {
        decoy_dns::validate_mode_keys(document)
    }

    /// Parses an atomic mutation candidate without performing DNS.
    pub(crate) fn parse_source_with_overrides<P: AsRef<Path>>(
        path: P,
        overrides: &BTreeMap<PathBuf, String>,
    ) -> Result<ParsedConfigSource> {
        let read_at = std::time::Instant::now();
        let mut parsed =
            pipeline::parse_source_graph(Self::read_source_graph_with_overrides(path, overrides)?)?;
        parsed.config.quota_source_read_at = Some(read_at);
        Ok(parsed)
    }

    /// Loads and prepares a complete runtime candidate without blocking async workers.
    pub(crate) async fn load_prepared(path: PathBuf) -> Result<LoadedConfig> {
        let parsed = tokio::task::spawn_blocking(move || Self::parse_source(path))
            .await
            .map_err(|error| ProxyError::Config(format!("config reader failed: {error}")))??;
        parsed.prepare().await
    }

    /// Rebuilds immutable credential lookup data for this configuration.
    pub(crate) fn rebuild_runtime_user_auth(&mut self) -> Result<()> {
        let snapshot = UserAuthSnapshot::from_users(&self.access.users)?;
        self.runtime_user_auth = Some(Arc::new(snapshot));
        Ok(())
    }

    /// Rebuilds validated WEB capabilities and immutable decoy snapshots.
    pub(crate) fn rebuild_runtime_web(&mut self) -> Result<()> {
        runtime_web::rebuild(self)
    }

    /// Validates the mixed effective WEB snapshot after restart fields are retained.
    pub(crate) fn validate_effective_web(&mut self) -> Result<()> {
        validate_web::validate(self)
    }

    /// Revalidates decoy separation after restart-only listener fields are resolved.
    pub(crate) fn validate_web_decoy_listener_separation(&self) -> Result<()> {
        validate_web::validate_decoy_listener_separation(self)
    }

    /// Returns authentication data owned by this configuration generation.
    pub(crate) fn runtime_user_auth(&self) -> Option<&UserAuthSnapshot> {
        self.runtime_user_auth.as_deref()
    }

    /// Returns the credential identity frozen into this runtime snapshot.
    pub(crate) fn runtime_user_credential_id(&self, user: &str) -> Option<[u8; 16]> {
        self.runtime_user_auth()
            .and_then(|snapshot| snapshot.credential_id_by_name(user))
            .or_else(|| {
                self.access
                    .users
                    .get(user)
                    .and_then(|secret| hex::decode(secret).ok())
                    .and_then(|secret| <[u8; 16]>::try_from(secret).ok())
                    .map(|secret| {
                        let digest = sha256(&secret);
                        let mut credential_id = [0; 16];
                        credential_id.copy_from_slice(&digest[..16]);
                        credential_id
                    })
            })
    }

    /// Validates cross-field configuration invariants after deserialization.
    pub fn validate(&self) -> Result<()> {
        self.access.validate_quota_periods()?;
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
        validate_listener_runtime_profiles(self)?;

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
