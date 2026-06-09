use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hyper::header::IF_MATCH;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{ProxyConfig, RateLimitBps};

use super::model::ApiFailure;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessSection {
    Users,
    UserEnabled,
    UserAdTags,
    UserMaxTcpConns,
    UserExpirations,
    UserDataQuota,
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

pub(super) async fn ensure_expected_revision(
    config_path: &Path,
    expected_revision: Option<&str>,
) -> Result<(), ApiFailure> {
    let Some(expected) = expected_revision else {
        return Ok(());
    };
    let current = current_revision(config_path).await?;
    if current != expected {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "revision_conflict",
            "Config revision mismatch",
        ));
    }
    Ok(())
}

pub(super) async fn current_revision(config_path: &Path) -> Result<String, ApiFailure> {
    let content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {}", e)))?;
    Ok(compute_revision(&content))
}

pub(super) fn compute_revision(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) async fn load_config_from_disk(config_path: &Path) -> Result<ProxyConfig, ApiFailure> {
    let config_path = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || ProxyConfig::load(config_path))
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to join config loader: {}", e)))?
        .map_err(|e| ApiFailure::internal(format!("failed to load config: {}", e)))
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
///   - `access`  : owned by the users API.
///   - `server`  : carries per-node identity (`port`, `api`/`api_bind`, listeners).
///   - `network` : carries per-node identity (`ipv4`/`ipv6`).
///
/// A future field-level allowlist can re-admit specific safe fields
/// (e.g. `network.dns_overrides`) without opening the whole section.
pub(super) const EDITABLE_SECTIONS: &[&str] = &[
    "general",
    "timeouts",
    "censorship",
    "upstreams",
    "show_link",
    "dc_overrides",
];

/// Re-render the given top-level tables from `cfg` and upsert each into the
/// on-disk file, preserving every untouched section (and its comments).
pub(super) async fn save_sections_to_disk(
    config_path: &Path,
    cfg: &ProxyConfig,
    sections: &[&str],
) -> Result<String, ApiFailure> {
    let mut content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {}", e)))?;

    for section in sections {
        let rendered = render_top_level_section(cfg, section)?;
        content = upsert_toml_table(&content, section, &rendered);
    }

    write_atomic(config_path.to_path_buf(), content.clone()).await?;
    Ok(compute_revision(&content))
}

/// Render one top-level table as `[section]\n...\n` (or `[[upstreams]]` array
/// of tables) from the typed `cfg`. Serializes via the `toml` crate so the
/// output matches the canonical format Telemt parses.
fn render_top_level_section(cfg: &ProxyConfig, section: &str) -> Result<String, ApiFailure> {
    let value = toml::Value::try_from(cfg)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize config: {}", e)))?;
    let table = value
        .get(section)
        .ok_or_else(|| ApiFailure::internal(format!("unknown section: {}", section)))?;

    // upstreams is an array-of-tables -> render as [[upstreams]] blocks.
    if let toml::Value::Array(items) = table {
        let mut out = String::new();
        for item in items {
            out.push_str(&format!("[[{}]]\n", section));
            out.push_str(&toml::to_string(item).map_err(|e| {
                ApiFailure::internal(format!("failed to serialize {}: {}", section, e))
            })?);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
        return Ok(out);
    }

    let body = toml::to_string(table)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize {}: {}", section, e)))?;
    let mut out = format!("[{}]\n", section);
    out.push_str(&body);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

pub(super) async fn save_access_sections_to_disk(
    config_path: &Path,
    cfg: &ProxyConfig,
    sections: &[AccessSection],
) -> Result<String, ApiFailure> {
    let mut content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {}", e)))?;

    let mut applied = Vec::new();
    for section in sections {
        if applied.contains(section) {
            continue;
        }
        if find_toml_table_bounds(&content, section.table_name()).is_none()
            && access_section_is_empty(cfg, *section)
        {
            applied.push(*section);
            continue;
        }
        let rendered = render_access_section(cfg, *section)?;
        content = upsert_toml_table(&content, section.table_name(), &rendered);
        applied.push(*section);
    }

    write_atomic(config_path.to_path_buf(), content.clone()).await?;
    Ok(compute_revision(&content))
}

fn render_access_section(cfg: &ProxyConfig, section: AccessSection) -> Result<String, ApiFailure> {
    let body = match section {
        AccessSection::Users => {
            let rows: BTreeMap<String, String> = cfg
                .access
                .users
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            serialize_table_body(&rows)?
        }
        AccessSection::UserEnabled => {
            let rows: BTreeMap<String, bool> = cfg
                .access
                .user_enabled
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect();
            serialize_table_body(&rows)?
        }
        AccessSection::UserAdTags => {
            let rows: BTreeMap<String, String> = cfg
                .access
                .user_ad_tags
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            serialize_table_body(&rows)?
        }
        AccessSection::UserMaxTcpConns => {
            let rows: BTreeMap<String, usize> = cfg
                .access
                .user_max_tcp_conns
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect();
            serialize_table_body(&rows)?
        }
        AccessSection::UserExpirations => {
            let rows: BTreeMap<String, DateTime<Utc>> = cfg
                .access
                .user_expirations
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect();
            serialize_table_body(&rows)?
        }
        AccessSection::UserDataQuota => {
            let rows: BTreeMap<String, u64> = cfg
                .access
                .user_data_quota
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect();
            serialize_table_body(&rows)?
        }
        AccessSection::UserRateLimits => {
            let rows: BTreeMap<String, RateLimitBps> = cfg
                .access
                .user_rate_limits
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect();
            serialize_rate_limit_body(&rows)?
        }
        AccessSection::UserMaxUniqueIps => {
            let rows: BTreeMap<String, usize> = cfg
                .access
                .user_max_unique_ips
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect();
            serialize_table_body(&rows)?
        }
    };

    let mut out = format!("[{}]\n", section.table_name());
    if !body.is_empty() {
        out.push_str(&body);
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn access_section_is_empty(cfg: &ProxyConfig, section: AccessSection) -> bool {
    match section {
        AccessSection::Users => cfg.access.users.is_empty(),
        AccessSection::UserEnabled => cfg.access.user_enabled.is_empty(),
        AccessSection::UserAdTags => cfg.access.user_ad_tags.is_empty(),
        AccessSection::UserMaxTcpConns => cfg.access.user_max_tcp_conns.is_empty(),
        AccessSection::UserExpirations => cfg.access.user_expirations.is_empty(),
        AccessSection::UserDataQuota => cfg.access.user_data_quota.is_empty(),
        AccessSection::UserRateLimits => cfg.access.user_rate_limits.is_empty(),
        AccessSection::UserMaxUniqueIps => cfg.access.user_max_unique_ips.is_empty(),
    }
}

fn serialize_table_body<T: Serialize>(value: &T) -> Result<String, ApiFailure> {
    toml::to_string(value)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize access section: {}", e)))
}

fn serialize_rate_limit_body(rows: &BTreeMap<String, RateLimitBps>) -> Result<String, ApiFailure> {
    let mut out = String::new();
    for (key, value) in rows {
        let key = serialize_toml_key(key)?;
        out.push_str(&format!(
            "{key} = {{ up_bps = {}, down_bps = {} }}\n",
            value.up_bps, value.down_bps
        ));
    }
    Ok(out)
}

fn serialize_toml_key(key: &str) -> Result<String, ApiFailure> {
    let mut row = BTreeMap::new();
    row.insert(key.to_string(), 0_u8);
    let rendered = serialize_table_body(&row)?;
    rendered
        .split_once(" = ")
        .map(|(key, _)| key.to_string())
        .ok_or_else(|| ApiFailure::internal("failed to serialize TOML key"))
}

fn upsert_toml_table(source: &str, table_name: &str, replacement: &str) -> String {
    if let Some((start, end)) = find_toml_table_bounds(source, table_name) {
        let mut out = String::with_capacity(source.len() + replacement.len());
        out.push_str(&source[..start]);
        out.push_str(replacement);
        out.push_str(&source[end..]);
        return out;
    }

    let mut out = source.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(replacement);
    out
}

fn find_toml_table_bounds(source: &str, table_name: &str) -> Option<(usize, usize)> {
    let single = format!("[{}]", table_name);
    let array = format!("[[{}]]", table_name);
    let mut offset = 0usize;
    let mut start = None;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(start_offset) = start {
            let is_same_array = trimmed == array;
            let is_new_header = trimmed.starts_with('[');
            if is_new_header && !is_same_array {
                return Some((start_offset, offset));
            }
        } else if trimmed == single || trimmed == array {
            start = Some(offset);
        }
        offset = offset.saturating_add(line.len());
    }

    start.map(|start_offset| (start_offset, source.len()))
}

async fn write_atomic(path: PathBuf, contents: String) -> Result<(), ApiFailure> {
    tokio::task::spawn_blocking(move || write_atomic_sync(&path, &contents))
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to join writer: {}", e)))?
        .map_err(|e| ApiFailure::internal(format!("failed to write config: {}", e)))
}

fn write_atomic_sync(path: &Path, contents: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let tmp_name = format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config.toml"),
        rand::random::<u64>()
    );
    let tmp_path = parent.join(tmp_name);

    let write_result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn save_sections_preserves_other_tables_and_comments() {
        let dir = std::env::temp_dir().join(format!("cfgtest-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "# top comment\n[censorship]\ntls_domain = \"old.example\"\n\n[server]\nport = 443\n",
        )
        .unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.censorship.tls_domain = "new.example".to_string();
        cfg.server.port = 443;

        let rev = save_sections_to_disk(&path, &cfg, &["censorship"])
            .await
            .unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("tls_domain = \"new.example\""));
        assert!(written.contains("# top comment")); // untouched comment kept
        assert!(written.contains("[server]\nport = 443")); // untouched table kept
        assert_eq!(rev, compute_revision(&written));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_bounds_matches_array_of_tables() {
        let src =
            "[server]\nport = 1\n\n[[upstreams]]\nkind = \"a\"\n\n[[upstreams]]\nkind = \"b\"\n";
        let bounds = find_toml_table_bounds(src, "upstreams");
        assert!(bounds.is_some(), "should locate [[upstreams]] block start");
        let (start, end) = bounds.unwrap();
        let slice = &src[start..end];
        assert!(slice.starts_with("[[upstreams]]"));
        assert!(slice.contains("kind = \"b\"")); // spans through the last upstream block
    }

    #[test]
    fn render_user_rate_limits_section() {
        let mut cfg = ProxyConfig::default();
        cfg.access.user_rate_limits.insert(
            "alice".to_string(),
            RateLimitBps {
                up_bps: 1024,
                down_bps: 2048,
            },
        );

        let rendered = render_access_section(&cfg, AccessSection::UserRateLimits)
            .expect("section must render");

        assert!(rendered.starts_with("[access.user_rate_limits]\n"));
        assert!(rendered.contains("alice = { up_bps = 1024, down_bps = 2048 }"));
    }
}
