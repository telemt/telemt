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

pub(crate) async fn current_revision_for_maestro(config_path: &Path) -> Result<String, String> {
    let content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|error| format!("failed to read config: {}", error))?;
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

pub(super) async fn load_config_for_reload(config_path: &Path) -> Result<ProxyConfig, ApiFailure> {
    let config_path = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || ProxyConfig::load(config_path))
        .await
        .map_err(|error| ApiFailure::internal(format!("failed to join config loader: {}", error)))?
        .map_err(|error| ApiFailure::bad_request(format!("invalid runtime config: {}", error)))
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

    // Serialize the table *inside a wrapper keyed by `section`* so the `toml`
    // crate emits correctly dotted headers for nested sub-tables, e.g.
    // `[general]` + `[general.modes]` + `[general.links]`. Serializing the
    // inner table alone would render bare `[modes]`/`[links]` headers, which
    // would leak as duplicate top-level tables and break config load.
    let mut wrapper = toml::value::Table::new();
    wrapper.insert(section.to_string(), table.clone());
    let mut out = toml::to_string(&toml::Value::Table(wrapper))
        .map_err(|e| ApiFailure::internal(format!("failed to serialize {}: {}", section, e)))?;
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
    let blocks = find_all_table_blocks(source, table_name);
    if let Some(&(first_start, first_end)) = blocks.first() {
        // Replace the first block in place and delete any further blocks that
        // also belong to this table. Telemt writes a section's sub-tables
        // contiguously, but a hand-edited config may scatter them; dropping the
        // extras here prevents the duplicate-table corruption that would
        // otherwise break config load.
        let mut out = String::with_capacity(source.len() + replacement.len());
        out.push_str(&source[..first_start]);
        out.push_str(replacement);
        let mut cursor = first_end;
        for &(start, end) in &blocks[1..] {
            out.push_str(&source[cursor..start]);
            cursor = end;
        }
        out.push_str(&source[cursor..]);
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

/// Whether a (comment-stripped, trimmed) TOML header line belongs to
/// `table_name`: the table itself (`[X]` / `[[X]]`) or any of its nested
/// sub-tables (`[X.…]` / `[[X.…]]`). The trailing dot guards against sibling
/// prefixes — `access.users` must not match `access.user_enabled`.
fn header_belongs_to(header: &str, table_name: &str) -> bool {
    let body = match header.strip_prefix("[[").and_then(|h| h.strip_suffix("]]")) {
        Some(body) => body,
        None => match header.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(body) => body,
            None => return false,
        },
    };
    let body = body.trim();
    body == table_name
        || body
            .strip_prefix(table_name)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Locate the first contiguous byte range covering `table_name` and the nested
/// sub-tables immediately following it. Used for existence checks; see
/// [`find_all_table_blocks`] for the full set of (possibly scattered) blocks.
fn find_toml_table_bounds(source: &str, table_name: &str) -> Option<(usize, usize)> {
    find_all_table_blocks(source, table_name).into_iter().next()
}

/// Locate every byte range that belongs to `table_name`: the table header and
/// its nested sub-tables. Returns one range per contiguous run, so a config
/// where a section's sub-tables are scattered (e.g. hand-edited) yields several
/// ranges — letting the caller collapse them into a single rendered block.
fn find_all_table_blocks(source: &str, table_name: &str) -> Vec<(usize, usize)> {
    let mut blocks = Vec::new();
    let mut offset = 0usize;
    let mut start: Option<usize> = None;

    for line in source.split_inclusive('\n') {
        // Drop any inline comment so a hand-edited header like
        // `[censorship] # note` still matches. Section names never contain `#`.
        let header = line.trim().split('#').next().unwrap_or("").trim();
        let is_header = header.starts_with('[');
        if let Some(start_offset) = start {
            if is_header && !header_belongs_to(header, table_name) {
                blocks.push((start_offset, offset));
                start = None;
            }
        }
        if start.is_none() && header_belongs_to(header, table_name) {
            start = Some(offset);
        }
        offset = offset.saturating_add(line.len());
    }

    if let Some(start_offset) = start {
        blocks.push((start_offset, source.len()));
    }
    blocks
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
    fn find_bounds_matches_header_with_inline_comment() {
        let src = "[censorship] # notes\ntls_domain = \"a\"\n\n[server]\nport = 1\n";
        let bounds = find_toml_table_bounds(src, "censorship");
        assert!(bounds.is_some(), "commented header must still match");
        let (start, end) = bounds.unwrap();
        let slice = &src[start..end];
        assert!(slice.starts_with("[censorship] # notes"));
        assert!(slice.contains("tls_domain"));
        assert!(!slice.contains("[server]")); // terminates at the next header
    }

    #[tokio::test]
    async fn save_general_section_keeps_subtables_dotted_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        tokio::fs::write(
            &path,
            "[general]\nprefer_ipv6 = false\n\n[general.modes]\ntls = true\n\n\
             [general.links]\npublic_host = \"old.example\"\n\n[server]\nport = 443\n",
        )
        .await
        .unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.general.prefer_ipv6 = true;

        save_sections_to_disk(&path, &cfg, &["general"])
            .await
            .unwrap();

        let written = tokio::fs::read_to_string(&path).await.unwrap();

        // No bare top-level [modes] / [links] headers leaked.
        for line in written.lines() {
            let header = line.trim();
            assert_ne!(header, "[modes]", "leaked top-level [modes]:\n{written}");
            assert_ne!(header, "[links]", "leaked top-level [links]:\n{written}");
        }

        // Sub-tables kept their dotted prefix exactly once each.
        assert_eq!(
            written.matches("[general.modes]").count(),
            1,
            "[general.modes] must appear exactly once:\n{written}"
        );
        assert_eq!(
            written.matches("[general.links]").count(),
            1,
            "[general.links] must appear exactly once:\n{written}"
        );

        // Result parses (duplicate tables would error here).
        toml::from_str::<toml::Value>(&written)
            .unwrap_or_else(|e| panic!("written config must parse: {e}\n{written}"));

        assert!(written.contains("[server]\nport = 443")); // untouched table kept
    }

    #[tokio::test]
    async fn save_general_section_is_idempotent_across_repeated_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        tokio::fs::write(
            &path,
            "[general]\nprefer_ipv6 = false\n\n[general.modes]\ntls = true\n\n\
             [general.links]\npublic_host = \"old.example\"\n",
        )
        .await
        .unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.general.prefer_ipv6 = true;

        save_sections_to_disk(&path, &cfg, &["general"])
            .await
            .unwrap();
        save_sections_to_disk(&path, &cfg, &["general"])
            .await
            .unwrap();

        let written = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(written.matches("[general.modes]").count(), 1, "{written}");
        assert_eq!(written.matches("[general.links]").count(), 1, "{written}");
        assert_eq!(written.matches("[general]").count(), 1, "{written}");
        toml::from_str::<toml::Value>(&written)
            .unwrap_or_else(|e| panic!("written config must parse: {e}\n{written}"));
    }

    #[test]
    fn find_bounds_spans_dotted_subtables() {
        let src = "[general]\nprefer_ipv6 = false\n\n[general.modes]\ntls = true\n\n\
                   [general.links]\npublic_host = \"a\"\n\n[server]\nport = 1\n";
        let bounds = find_toml_table_bounds(src, "general");
        assert!(bounds.is_some(), "should locate [general] block");
        let (start, end) = bounds.unwrap();
        let slice = &src[start..end];
        assert!(slice.starts_with("[general]"));
        assert!(slice.contains("[general.modes]")); // spans nested sub-tables
        assert!(slice.contains("[general.links]"));
        assert!(!slice.contains("[server]")); // terminates at the next unrelated header
    }

    #[test]
    fn find_bounds_does_not_overrun_sibling_prefix() {
        // access.users must not swallow access.user_enabled (dot guards the prefix).
        let src = "[access.users]\nalice = \"x\"\n\n[access.user_enabled]\nalice = true\n";
        let bounds = find_toml_table_bounds(src, "access.users").unwrap();
        let slice = &src[bounds.0..bounds.1];
        assert!(slice.starts_with("[access.users]"));
        assert!(!slice.contains("[access.user_enabled]"));
    }

    #[tokio::test]
    async fn save_general_handles_non_contiguous_subtables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Hand-edited layout: [general.modes] sits AFTER an unrelated [server].
        tokio::fs::write(
            &path,
            "[general]\nprefer_ipv6 = false\n\n[server]\nport = 443\n\n\
             [general.modes]\ntls = true\n",
        )
        .await
        .unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.general.prefer_ipv6 = true;

        save_sections_to_disk(&path, &cfg, &["general"])
            .await
            .unwrap();

        let written = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            written.matches("[general.modes]").count(),
            1,
            "non-contiguous [general.modes] must not duplicate:\n{written}"
        );
        toml::from_str::<toml::Value>(&written)
            .unwrap_or_else(|e| panic!("written config must parse: {e}\n{written}"));
        assert!(written.contains("[server]")); // unrelated section preserved
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
