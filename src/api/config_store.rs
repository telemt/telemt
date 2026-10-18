use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hyper::header::IF_MATCH;
use sha2::{Digest, Sha256};

use crate::config::{ConfigSourceGraph, LoadedConfig, ParsedConfigSource, ProxyConfig};

use super::model::ApiFailure;

// Source-preserving TOML rendering and atomic persistence helpers.
mod persistence;
// Compare-and-replace file persistence and metadata preservation.
mod atomic;

pub(in crate::api) use atomic::{write_atomic, write_atomic_if_unchanged};
#[cfg(test)]
use persistence::{find_toml_table_bounds, render_access_section, save_sections_to_disk};
pub(in crate::api) use persistence::{
    render_server_listeners, render_top_level_section, save_access_sections_to_disk,
    save_access_sections_to_disk_if_revision, upsert_toml_table,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessSection {
    Users,
    UserEnabled,
    UserAdTags,
    UserMaxTcpConns,
    UserExpirations,
    UserDataQuota,
    /// Per-user recurring UTC calendar settings.
    UserQuotaPeriods,
    UserRateLimits,
    UserMaxUniqueIps,
}

impl AccessSection {
    fn table_name(self) -> &'static str {
        match self {
            Self::Users => "access.users",
            Self::UserEnabled => "access.user_enabled",
            Self::UserAdTags => "access.user_ad_tags",
            Self::UserMaxTcpConns => "access.user_max_tcp_conns",
            Self::UserExpirations => "access.user_expirations",
            Self::UserDataQuota => "access.user_data_quota",
            Self::UserQuotaPeriods => "access.user_quota_periods",
            Self::UserRateLimits => "access.user_rate_limits",
            Self::UserMaxUniqueIps => "access.user_max_unique_ips",
        }
    }
}

pub(super) fn parse_if_match(headers: &hyper::HeaderMap) -> Option<String> {
    headers
        .get(IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_matches('"').to_string())
}

/// Loads one mutation base and validates its revision from the same source snapshot.
pub(super) async fn load_config_for_mutation(
    config_path: &Path,
    expected_revision: Option<&str>,
) -> Result<(ProxyConfig, String), ApiFailure> {
    let loaded = load_config_snapshot(config_path, false).await?;
    let revision = compute_snapshot_revision(&loaded.source_contents);
    if expected_revision.is_some_and(|expected| expected != revision) {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "revision_conflict",
            "Config revision mismatch",
        ));
    }
    Ok((loaded.config, revision))
}

pub(super) async fn current_revision(config_path: &Path) -> Result<String, ApiFailure> {
    let config_path = config_path.to_path_buf();
    let graph = tokio::task::spawn_blocking(move || ProxyConfig::read_source_graph(config_path))
        .await
        .map_err(|error| ApiFailure::internal(format!("failed to join config reader: {error}")))?
        .map_err(|error| ApiFailure::internal(format!("failed to read config graph: {error}")))?;
    Ok(compute_source_revision(&graph))
}

pub(crate) async fn current_revision_for_maestro(config_path: &Path) -> Result<String, String> {
    let config_path = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || ProxyConfig::read_source_graph(config_path))
        .await
        .map_err(|error| format!("failed to join config reader: {error}"))?
        .map(|graph| compute_source_revision(&graph))
        .map_err(|error| error.to_string())
}

pub(super) fn compute_revision(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hashes source documents only; prepared DNS answers never change a revision.
pub(super) fn compute_snapshot_revision(source_contents: &BTreeMap<PathBuf, String>) -> String {
    compute_source_revision(&ConfigSourceGraph {
        source_contents: source_contents.clone(),
        rendered: String::new(),
    })
}

pub(super) fn compute_source_revision(graph: &ConfigSourceGraph) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"telemt-config-manifest-v1\0");
    for (path, content) in &graph.source_contents {
        let path = path.as_os_str().as_encoded_bytes();
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Reads a normalized source snapshot without resolving decoys or loading static assets.
pub(super) async fn load_config_snapshot(
    config_path: &Path,
    invalid_is_bad_request: bool,
) -> Result<ParsedConfigSource, ApiFailure> {
    let config_path = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || ProxyConfig::parse_source(config_path))
        .await
        .map_err(|error| ApiFailure::internal(format!("failed to join config loader: {error}")))?
        .map_err(|error| {
            if invalid_is_bad_request {
                ApiFailure::bad_request(format!("invalid runtime config: {error}"))
            } else {
                ApiFailure::internal(format!("failed to load config: {error}"))
            }
        })
}

/// Selects the single writable source document owning all requested sections.
pub(super) fn resolve_single_source_owner(
    loaded: &ParsedConfigSource,
    config_path: &Path,
    targets: &[&str],
) -> Result<PathBuf, ApiFailure> {
    let root = normalize_source_path(config_path);
    let mut mutation_owners = BTreeSet::new();

    if loaded
        .source_contents
        .values()
        .any(|content| has_include_inside_table(content))
    {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "config_patch_not_atomic",
            "config includes nested inside a TOML table cannot be mutated atomically",
        ));
    }

    for target in targets {
        let mut owners = BTreeSet::new();
        for (path, content) in &loaded.source_contents {
            let parsed: toml::Value = toml::from_str(content).map_err(|error| {
                ApiFailure::new(
                    hyper::StatusCode::CONFLICT,
                    "config_patch_not_atomic",
                    format!(
                        "config source {} is not independently writable: {error}",
                        path.display()
                    ),
                )
            })?;
            if toml_path_exists(&parsed, target) {
                owners.insert(path.clone());
            }
        }
        match owners.len() {
            0 => {
                mutation_owners.insert(root.clone());
            }
            1 => {
                mutation_owners.extend(owners);
            }
            _ => {
                return Err(ApiFailure::new(
                    hyper::StatusCode::CONFLICT,
                    "config_patch_not_atomic",
                    format!("config section {target} is owned by multiple source files"),
                ));
            }
        }
    }

    if mutation_owners.len() != 1 {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "config_patch_not_atomic",
            "one mutation may update only one config source file",
        ));
    }
    mutation_owners
        .into_iter()
        .next()
        .ok_or_else(|| ApiFailure::bad_request("empty mutation: no owned config sections"))
}

fn toml_path_exists(value: &toml::Value, target: &str) -> bool {
    target
        .split('.')
        .try_fold(value, |current, part| current.get(part))
        .is_some()
}

fn has_include_inside_table(content: &str) -> bool {
    let mut inside_table = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside_table = true;
        }
        if inside_table
            && trimmed
                .strip_prefix("include")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        {
            return true;
        }
    }
    false
}

/// Prepares the entire mutation candidate before any source file may be replaced.
pub(super) async fn load_candidate_snapshot(
    config_path: &Path,
    base_sources: &BTreeMap<PathBuf, String>,
    owner_path: PathBuf,
    owner_contents: String,
) -> Result<LoadedConfig, ApiFailure> {
    let config_path = config_path.to_path_buf();
    let mut overrides = base_sources.clone();
    overrides.insert(owner_path, owner_contents);
    let parsed = tokio::task::spawn_blocking(move || {
        ProxyConfig::parse_source_with_overrides(config_path, &overrides)
    })
    .await
    .map_err(|error| ApiFailure::internal(format!("failed to join config loader: {error}")))?
    .map_err(|error| ApiFailure::bad_request(format!("invalid patched config: {error}")))?;
    parsed
        .prepare()
        .await
        .map_err(|error| ApiFailure::bad_request(format!("invalid patched config: {error}")))
}

fn normalize_source_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

/// Reads desired user and quota policy without acquiring runtime decoy state.
pub(super) async fn load_config_from_disk(config_path: &Path) -> Result<ProxyConfig, ApiFailure> {
    load_config_snapshot(config_path, false)
        .await
        .map(|source| source.config)
}

/// Acquires fresh decoy evidence for an explicit API reload, even at the same revision.
pub(super) async fn load_config_for_reload(
    config_path: &Path,
) -> Result<(ProxyConfig, String), ApiFailure> {
    let loaded = load_config_snapshot(config_path, true).await?;
    let revision = compute_snapshot_revision(&loaded.source_contents);
    let loaded = loaded
        .prepare()
        .await
        .map_err(|error| ApiFailure::bad_request(format!("invalid runtime config: {error}")))?;
    Ok((loaded.config, revision))
}

#[allow(dead_code)]
pub(super) async fn save_config_to_disk(
    config_path: &Path,
    cfg: &ProxyConfig,
) -> Result<String, ApiFailure> {
    let serialized = toml::to_string_pretty(cfg)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize config: {}", e)))?;
    write_atomic(config_path.to_path_buf(), serialized.clone()).await?;
    Ok(compute_revision(&serialized))
}

/// Top-level config tables that may be edited via the config API.
///
/// Intentionally excluded (defense-in-depth, enforces the spec's per-node
/// identity invariant at the Telemt layer too):
///
///   - `access`    : owned by the users API.
///   - `network`   : carries per-node identity (`ipv4`/`ipv6`).
///   - `show_link` : legacy top-level scalar/array (not a `[table]`), superseded
///                   by the editable `general.links.show` sub-table. The
///                   section-upsert machinery here only handles `[table]` /
///                   `[[array-of-tables]]` blocks; a bare top-level key cannot be
///                   located or replaced safely, so it is edited via `general`.
///
/// `server` is partially editable: only the nested fields listed in
/// [`EDITABLE_SERVER_FIELDS`] (currently `listeners`) may appear in GET/PATCH.
/// Secrets and bind identity (`api`/`admin_api`, `port`, unix sockets, …) stay
/// blocked. See also the field-level allowlist note below for `network.*`.
///
/// A future field-level allowlist can re-admit specific safe fields
/// (e.g. `network.dns_overrides`) without opening the whole section.
pub(super) const EDITABLE_SECTIONS: &[&str] = &[
    "general",
    "timeouts",
    "censorship",
    "upstreams",
    "dc_overrides",
    "web",
];

/// Nested fields under `[server]` that may be read/patched via the config API.
///
/// Arrays (e.g. `listeners`) replace wholesale on PATCH, matching the existing
/// merge semantics for non-table values.
pub(super) const EDITABLE_SERVER_FIELDS: &[&str] = &["listeners"];

/// Whether `key` is an allowed top-level PATCH/GET section name.
///
/// Fully editable sections from [`EDITABLE_SECTIONS`], plus `server` which is
/// further restricted by [`EDITABLE_SERVER_FIELDS`].
pub(super) fn is_editable_section(key: &str) -> bool {
    EDITABLE_SECTIONS.contains(&key) || key == "server"
}

#[cfg(test)]
#[path = "config_store/tests.rs"]
mod tests;
