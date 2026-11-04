use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::{ProxyConfig, RateLimitBps};

#[cfg(test)]
use super::atomic::write_atomic;
use super::atomic::write_atomic_if_unchanged;
#[cfg(test)]
use super::compute_revision;
use super::{
    AccessSection, compute_snapshot_revision, load_candidate_snapshot, load_config_snapshot,
    resolve_single_source_owner, toml_path_exists,
};
use crate::api::model::ApiFailure;

/// Re-render the given top-level tables from `cfg` and upsert each into the
/// on-disk file, preserving every untouched section (and its comments).
#[cfg(test)]
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
pub(in crate::api) fn render_top_level_section(
    cfg: &ProxyConfig,
    section: &str,
) -> Result<String, ApiFailure> {
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

/// Renders normalized listener entries as nested array-of-table blocks.
pub(in crate::api) fn render_server_listeners(cfg: &ProxyConfig) -> Result<String, ApiFailure> {
    let mut out = String::new();
    for listener in &cfg.server.listeners {
        out.push_str("[[server.listeners]]\n");
        out.push_str(&toml::to_string(listener).map_err(|error| {
            ApiFailure::internal(format!("failed to serialize server.listeners: {error}"))
        })?);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

/// Validates and atomically writes access tables to their single source owner.
#[cfg(test)]
pub(in crate::api) async fn save_access_sections_to_disk(
    config_path: &Path,
    cfg: &ProxyConfig,
    sections: &[AccessSection],
) -> Result<String, ApiFailure> {
    save_access_sections_to_disk_if_revision(config_path, cfg, sections, None).await
}

/// Persists access tables only while the complete source graph remains unchanged.
pub(in crate::api) async fn save_access_sections_to_disk_if_revision(
    config_path: &Path,
    cfg: &ProxyConfig,
    sections: &[AccessSection],
    expected_revision: Option<&str>,
) -> Result<String, ApiFailure> {
    let loaded = load_config_snapshot(config_path, false).await?;
    let loaded_revision = compute_snapshot_revision(&loaded.source_contents);
    if expected_revision.is_some_and(|expected| expected != loaded_revision) {
        return Err(revision_conflict());
    }
    let mut applied = Vec::new();
    for section in sections {
        if applied.contains(section) {
            continue;
        }
        applied.push(*section);
    }
    applied.retain(|section| {
        !access_section_is_empty(cfg, *section)
            || loaded.source_contents.values().any(|contents| {
                toml::from_str::<toml::Value>(contents)
                    .ok()
                    .is_some_and(|value| toml_path_exists(&value, section.table_name()))
            })
    });
    if applied.is_empty() {
        return Ok(loaded_revision);
    }

    let targets = applied
        .iter()
        .map(|section| section.table_name())
        .collect::<Vec<_>>();
    let owner_path = resolve_single_source_owner(&loaded, config_path, &targets)?;
    let mut owner_contents = loaded
        .source_contents
        .get(&owner_path)
        .cloned()
        .ok_or_else(|| ApiFailure::internal("config source owner is missing from snapshot"))?;
    let expected_owner_contents = owner_contents.clone();
    for section in applied {
        let rendered = render_access_section(cfg, section)?;
        owner_contents = upsert_toml_table(&owner_contents, section.table_name(), &rendered);
    }

    let candidate = load_candidate_snapshot(
        config_path,
        &loaded.source_contents,
        owner_path.clone(),
        owner_contents.clone(),
    )
    .await?;
    let _candidate_revision = compute_snapshot_revision(&candidate.source_contents);
    let revision = write_atomic_if_unchanged(
        config_path.to_path_buf(),
        loaded_revision,
        owner_path,
        expected_owner_contents,
        owner_contents,
    )
    .await?;
    Ok(revision)
}

/// Renders one access-control table for persistence tests and user mutations.
pub(super) fn render_access_section(
    cfg: &ProxyConfig,
    section: AccessSection,
) -> Result<String, ApiFailure> {
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
        AccessSection::UserQuotaPeriods => {
            let rows: BTreeMap<_, _> = cfg.access.user_quota_periods.iter().collect();
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
        AccessSection::UserQuotaPeriods => cfg.access.user_quota_periods.is_empty(),
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

/// Replaces all blocks owned by one semantic TOML table with one rendering.
pub(in crate::api) fn upsert_toml_table(
    source: &str,
    table_name: &str,
    replacement: &str,
) -> String {
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
/// Locates one complete TOML table block in source text.
#[cfg(test)]
pub(super) fn find_toml_table_bounds(source: &str, table_name: &str) -> Option<(usize, usize)> {
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

fn revision_conflict() -> ApiFailure {
    ApiFailure::new(
        hyper::StatusCode::CONFLICT,
        "revision_conflict",
        "Config revision changed before persistence",
    )
}
