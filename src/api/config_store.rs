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
    let target = format!("[{}]", table_name);
    let mut offset = 0usize;
    let mut start = None;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(start_offset) = start {
            if trimmed.starts_with('[') {
                return Some((start_offset, offset));
            }
        } else if trimmed == target {
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

    #[test]
    fn find_toml_table_bounds_finds_existing_section() {
        let src = "[general]\nfoo = 1\n[server]\nbar = 2\n";
        let (start, end) = find_toml_table_bounds(src, "server").unwrap();
        assert_eq!(&src[start..end], "[server]\nbar = 2\n");
    }

    #[test]
    fn find_toml_table_bounds_returns_none_for_missing() {
        let src = "[general]\nfoo = 1\n";
        assert!(find_toml_table_bounds(src, "server").is_none());
    }

    #[test]
    fn find_toml_table_bounds_section_at_end_of_file() {
        let src = "[general]\nfoo = 1\n[access.users]\nadmin = \"secret\"";
        let (start, end) = find_toml_table_bounds(src, "access.users").unwrap();
        assert_eq!(&src[start..end], "[access.users]\nadmin = \"secret\"");
        assert_eq!(end, src.len());
    }

    #[test]
    fn find_toml_table_bounds_handles_multi_line_body() {
        let src = "[general]\nfoo = 1\nbar = 2\nbaz = 3\n[server]\nport = 443\n";
        let (start, end) = find_toml_table_bounds(src, "general").unwrap();
        assert!(src[start..end].contains("foo = 1"));
        assert!(src[start..end].contains("baz = 3"));
    }

    #[test]
    fn upsert_toml_table_inserts_new_section_when_missing() {
        let src = "[general]\nfoo = 1\n";
        let replacement = "[server]\nport = 443\n";
        let result = upsert_toml_table(src, "server", replacement);
        assert!(result.contains("[general]\nfoo = 1"));
        assert!(result.contains("[server]\nport = 443"));
    }

    #[test]
    fn upsert_toml_table_replaces_existing_section() {
        let src = "[general]\nfoo = 1\n[server]\nport = 80\n";
        let replacement = "[server]\nport = 443\n";
        let result = upsert_toml_table(src, "server", replacement);
        assert!(result.contains("[general]\nfoo = 1"));
        assert!(result.contains("[server]\nport = 443"));
        assert!(!result.contains("port = 80"));
    }

    #[test]
    fn upsert_toml_table_preserves_surrounding_content() {
        let src = "[general]\nfoo = 1\n[server]\nport = 80\n[network]\nipv4 = true\n";
        let replacement = "[server]\nport = 443\n";
        let result = upsert_toml_table(src, "server", replacement);
        assert!(result.contains("[general]\nfoo = 1"));
        assert!(result.contains("[network]\nipv4 = true"));
        assert!(result.contains("[server]\nport = 443"));
    }

    #[test]
    fn upsert_toml_table_handles_no_trailing_newline() {
        let src = "[general]\nfoo = 1";
        let replacement = "[server]\nport = 443\n";
        let result = upsert_toml_table(src, "server", replacement);
        assert!(result.ends_with(&replacement));
    }

    #[test]
    fn serialize_table_body_produces_parseable_toml() {
        let mut map = BTreeMap::new();
        map.insert("admin".to_string(), "secret123".to_string());
        map.insert("user".to_string(), "abc456".to_string());
        let body = serialize_table_body(&map).unwrap();
        let parsed: BTreeMap<String, String> = toml::from_str(&body).unwrap();
        assert_eq!(parsed.get("admin").unwrap(), "secret123");
        assert_eq!(parsed.get("user").unwrap(), "abc456");
    }

    #[test]
    fn compute_revision_is_deterministic() {
        let content = "hello world";
        assert_eq!(compute_revision(content), compute_revision(content));
    }

    #[test]
    fn compute_revision_differs_for_different_content() {
        assert_ne!(compute_revision("a"), compute_revision("b"));
    }

    #[test]
    fn parse_if_match_extracts_quoted_value() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(IF_MATCH, "\"rev123\"".parse().unwrap());
        assert_eq!(parse_if_match(&headers), Some("rev123".to_string()));
    }

    #[test]
    fn parse_if_match_returns_none_when_missing() {
        let headers = hyper::HeaderMap::new();
        assert!(parse_if_match(&headers).is_none());
    }

    #[test]
    fn access_section_is_empty_default_users_not_empty() {
        let config = ProxyConfig::default();
        assert!(!access_section_is_empty(&config, AccessSection::Users));
        assert!(access_section_is_empty(&config, AccessSection::UserAdTags));
        assert!(access_section_is_empty(&config, AccessSection::UserMaxTcpConns));
        assert!(access_section_is_empty(&config, AccessSection::UserExpirations));
        assert!(access_section_is_empty(&config, AccessSection::UserDataQuota));
        assert!(access_section_is_empty(&config, AccessSection::UserMaxUniqueIps));
    }

    #[test]
    fn access_section_is_empty_users_false_after_insert() {
        let mut config = ProxyConfig::default();
        config.access.users.insert("admin".to_string(), "secret".to_string());
        assert!(!access_section_is_empty(&config, AccessSection::Users));
    }

    #[test]
    fn access_section_is_empty_user_ad_tags_false_after_insert() {
        let mut config = ProxyConfig::default();
        config.access.user_ad_tags.insert("admin".to_string(), "tag1".to_string());
        assert!(!access_section_is_empty(&config, AccessSection::UserAdTags));
    }

    #[test]
    fn access_section_is_empty_user_max_tcp_conns_false_after_insert() {
        let mut config = ProxyConfig::default();
        config.access.user_max_tcp_conns.insert("admin".to_string(), 5);
        assert!(!access_section_is_empty(&config, AccessSection::UserMaxTcpConns));
    }

    #[test]
    fn access_section_is_empty_user_data_quota_false_after_insert() {
        let mut config = ProxyConfig::default();
        config.access.user_data_quota.insert("admin".to_string(), 1024);
        assert!(!access_section_is_empty(&config, AccessSection::UserDataQuota));
    }

    #[test]
    fn access_section_is_empty_user_max_unique_ips_false_after_insert() {
        let mut config = ProxyConfig::default();
        config.access.user_max_unique_ips.insert("admin".to_string(), 3);
        assert!(!access_section_is_empty(&config, AccessSection::UserMaxUniqueIps));
    }

    #[test]
    fn render_access_section_users_round_trips_via_toml() {
        let mut config = ProxyConfig::default();
        config.access.users.insert("alice".to_string(), "key1".to_string());
        config.access.users.insert("bob".to_string(), "key2".to_string());
        let rendered = render_access_section(&config, AccessSection::Users).unwrap();
        assert!(rendered.starts_with("[access.users]\n"));
        let body = rendered.trim_start_matches("[access.users]\n");
        let parsed: BTreeMap<String, String> = toml::from_str(body).unwrap();
        assert_eq!(parsed.get("alice").unwrap(), "key1");
        assert_eq!(parsed.get("bob").unwrap(), "key2");
    }

    #[test]
    fn render_access_section_user_max_tcp_conns_round_trips_via_toml() {
        let mut config = ProxyConfig::default();
        config.access.user_max_tcp_conns.insert("alice".to_string(), 10);
        let rendered = render_access_section(&config, AccessSection::UserMaxTcpConns).unwrap();
        assert!(rendered.starts_with("[access.user_max_tcp_conns]\n"));
        let body = rendered.trim_start_matches("[access.user_max_tcp_conns]\n");
        let parsed: BTreeMap<String, usize> = toml::from_str(body).unwrap();
        assert_eq!(parsed.get("alice").unwrap(), &10);
    }

    #[test]
    fn render_access_section_user_data_quota_round_trips_via_toml() {
        let mut config = ProxyConfig::default();
        config.access.user_data_quota.insert("alice".to_string(), 4096);
        let rendered = render_access_section(&config, AccessSection::UserDataQuota).unwrap();
        assert!(rendered.starts_with("[access.user_data_quota]\n"));
        let body = rendered.trim_start_matches("[access.user_data_quota]\n");
        let parsed: BTreeMap<String, u64> = toml::from_str(body).unwrap();
        assert_eq!(parsed.get("alice").unwrap(), &4096);
    }

    #[test]
    fn render_access_section_user_max_unique_ips_round_trips_via_toml() {
        let mut config = ProxyConfig::default();
        config.access.user_max_unique_ips.insert("alice".to_string(), 5);
        let rendered = render_access_section(&config, AccessSection::UserMaxUniqueIps).unwrap();
        assert!(rendered.starts_with("[access.user_max_unique_ips]\n"));
        let body = rendered.trim_start_matches("[access.user_max_unique_ips]\n");
        let parsed: BTreeMap<String, usize> = toml::from_str(body).unwrap();
        assert_eq!(parsed.get("alice").unwrap(), &5);
    }

    #[test]
    fn render_access_section_default_users_has_entry() {
        let config = ProxyConfig::default();
        let rendered = render_access_section(&config, AccessSection::Users).unwrap();
        assert!(rendered.starts_with("[access.users]\n"));
        assert!(rendered.contains("default"));
    }
}
