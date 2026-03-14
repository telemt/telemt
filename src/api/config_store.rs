use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hyper::header::IF_MATCH;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::ProxyConfig;

use super::model::ApiFailure;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessSection {
    Users,
    UserAdTags,
    UserMaxTcpConns,
    UserExpirations,
    UserDataQuota,
    UserMaxUniqueIps,
}

impl AccessSection {
    const fn table_name(self) -> &'static str {
        match self {
            Self::Users => "access.users",
            Self::UserAdTags => "access.user_ad_tags",
            Self::UserMaxTcpConns => "access.user_max_tcp_conns",
            Self::UserExpirations => "access.user_expirations",
            Self::UserDataQuota => "access.user_data_quota",
            Self::UserMaxUniqueIps => "access.user_max_unique_ips",
        }
    }
}

pub(super) fn parse_if_match(headers: &hyper::HeaderMap) -> Option<String> {
    let raw = headers.get(IF_MATCH)?.to_str().ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip exactly one outer pair of double-quotes (RFC 9110 §8.8.3 strong entity-tag).
    // trim_matches('"') over-strips: inputs '"' and '""' both collapse to an empty
    // string. ensure_expected_revision receiving Some("") then compares "" against the
    // real SHA-256 revision and unconditionally returns 409 Conflict, blocking all
    // mutations from any caller who sends a malformed ETag.
    let stripped = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return None;
    }
    Some(stripped.to_string())
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
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {e}")))?;
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
        .map_err(|e| ApiFailure::internal(format!("failed to join config loader: {e}")))?
        .map_err(|e| ApiFailure::internal(format!("failed to load config: {e}")))
}

// Retained for potential future use; patch_user previously used this to
// rewrite the full config, but save_access_sections_to_disk is preferred
// because it preserves TOML comments and structure outside the changed sections.
#[allow(dead_code)]
pub(super) async fn save_config_to_disk(
    config_path: &Path,
    cfg: &ProxyConfig,
) -> Result<String, ApiFailure> {
    let serialized = toml::to_string_pretty(cfg)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize config: {e}")))?;
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
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {e}")))?;

    let mut applied = Vec::new();
    for section in sections {
        if applied.contains(section) {
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

fn serialize_table_body<T: Serialize>(value: &T) -> Result<String, ApiFailure> {
    toml::to_string(value)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize access section: {e}")))
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
    let target = format!("[{table_name}]");
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
        .map_err(|e| ApiFailure::internal(format!("failed to join writer: {e}")))?
        .map_err(|e| ApiFailure::internal(format!("failed to write config: {e}")))
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
    use hyper::HeaderMap;
    use hyper::header::IF_MATCH;

    use super::{compute_revision, find_toml_table_bounds, parse_if_match, upsert_toml_table};

    fn header_with_if_match(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(IF_MATCH, value.parse().unwrap());
        map
    }

    // ── parse_if_match ───────────────────────────────────────────────────────

    #[test]
    fn parse_if_match_returns_none_when_header_absent() {
        assert!(parse_if_match(&HeaderMap::new()).is_none());
    }

    #[test]
    fn parse_if_match_strips_outer_quotes_from_etag() {
        let map = header_with_if_match("\"abc123\"");
        assert_eq!(parse_if_match(&map).as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_if_match_accepts_unquoted_etag() {
        let map = header_with_if_match("abc123");
        assert_eq!(parse_if_match(&map).as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_if_match_returns_none_for_whitespace_only_value() {
        let map = header_with_if_match("   ");
        assert!(parse_if_match(&map).is_none());
    }

    #[test]
    fn parse_if_match_trims_surrounding_whitespace_before_stripping_quotes() {
        let map = header_with_if_match("  \"abc123\"  ");
        assert_eq!(parse_if_match(&map).as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_if_match_sha256_hex_revision_survives_round_trip() {
        let rev = "a".repeat(64);
        let quoted = format!("\"{rev}\"");
        let map = header_with_if_match(&quoted);
        assert_eq!(parse_if_match(&map).as_deref(), Some(rev.as_str()));
    }

    // ── compute_revision ─────────────────────────────────────────────────────

    #[test]
    fn compute_revision_is_deterministic_for_same_content() {
        let content = "[access.users]\nalice = \"secret\"\n";
        assert_eq!(compute_revision(content), compute_revision(content));
    }

    #[test]
    fn compute_revision_differs_for_distinct_content() {
        assert_ne!(compute_revision("a = 1\n"), compute_revision("a = 2\n"));
    }

    #[test]
    fn compute_revision_returns_lowercase_hex_sha256() {
        let rev = compute_revision("test");
        assert_eq!(rev.len(), 64, "SHA-256 hex digest must be 64 characters");
        assert!(rev.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn compute_revision_changes_on_single_byte_difference() {
        let r1 = compute_revision("key = \"a\"\n");
        let r2 = compute_revision("key = \"b\"\n");
        assert_ne!(r1, r2);
    }

    // ── find_toml_table_bounds ───────────────────────────────────────────────

    #[test]
    fn find_toml_table_bounds_locates_section_in_middle_of_file() {
        let src = "[first]\nk = 1\n\n[target]\nk = 2\n\n[last]\nk = 3\n";
        let (start, end) = find_toml_table_bounds(src, "target").expect("must find section");
        assert_eq!(&src[start..end], "[target]\nk = 2\n\n");
    }

    #[test]
    fn find_toml_table_bounds_locates_section_at_end_of_file() {
        let src = "[first]\nk = 1\n\n[last]\nk = 2\n";
        let (start, end) = find_toml_table_bounds(src, "last").expect("must find section");
        assert_eq!(end, src.len());
        assert!(src[start..].starts_with("[last]"));
    }

    #[test]
    fn find_toml_table_bounds_locates_section_at_start_of_file() {
        let src = "[first]\nk = 1\n\n[second]\nk = 2\n";
        let (start, end) = find_toml_table_bounds(src, "first").expect("must find section");
        assert_eq!(start, 0);
        assert_eq!(&src[start..end], "[first]\nk = 1\n\n");
    }

    #[test]
    fn find_toml_table_bounds_returns_none_when_section_absent() {
        let src = "[existing]\nk = 1\n";
        assert!(find_toml_table_bounds(src, "missing").is_none());
    }

    #[test]
    fn find_toml_table_bounds_does_not_match_substring_table_names() {
        // [access.users] must not accidentally match when searching for [access].
        let src = "[access.users]\nalice = \"s\"\n";
        assert!(
            find_toml_table_bounds(src, "access").is_none(),
            "partial name match must not be recognised as the target section"
        );
    }

    // Known limitation: table headers with trailing inline comments are not
    // matched because the trimmed line contains extra characters. The upsert
    // function will append a new section block instead of replacing in place.
    // Auto-generated config files never produce headers with inline comments.
    #[test]
    fn find_toml_table_bounds_does_not_match_header_with_inline_comment() {
        let src = "[access.users] # admin-only\nalice = \"s1\"\n";
        assert!(
            find_toml_table_bounds(src, "access.users").is_none(),
            "inline comment on table header is a known limitation: section is not matched"
        );
    }

    #[test]
    fn find_toml_table_bounds_handles_dotted_section_names_without_false_positives() {
        // Ensure [access.users] and [access.user_ad_tags] are independently located.
        let src = "[access.users]\nalice = \"s1\"\n\n[access.user_ad_tags]\nalice = \"tag\"\n";

        let (start_u, end_u) = find_toml_table_bounds(src, "access.users").unwrap();
        assert_eq!(&src[start_u..end_u], "[access.users]\nalice = \"s1\"\n\n");

        let (start_t, _end_t) = find_toml_table_bounds(src, "access.user_ad_tags").unwrap();
        assert!(src[start_t..].starts_with("[access.user_ad_tags]"));
    }

    // ── upsert_toml_table ────────────────────────────────────────────────────

    #[test]
    fn upsert_toml_table_replaces_existing_section_content() {
        let src = "[access.users]\nalice = \"old\"\n\n[other]\nk = 1\n";
        let replacement = "[access.users]\nalice = \"new\"\n";
        let result = upsert_toml_table(src, "access.users", replacement);
        assert!(result.contains("alice = \"new\""));
        assert!(!result.contains("alice = \"old\""));
        assert!(result.contains("[other]"), "adjacent section must be preserved");
    }

    #[test]
    fn upsert_toml_table_preserves_content_following_replaced_section() {
        let src = "[access.users]\nalice = \"old\"\n\n[other.section]\nkey = \"preserved\"\n";
        let replacement = "[access.users]\nalice = \"new\"\n";
        let result = upsert_toml_table(src, "access.users", replacement);
        assert!(result.contains("key = \"preserved\""));
        assert!(result.contains("alice = \"new\""));
        assert!(!result.contains("alice = \"old\""));
    }

    #[test]
    fn upsert_toml_table_appends_new_section_when_not_found() {
        let src = "[other]\nk = 1\n";
        let replacement = "[access.users]\nalice = \"secret\"\n";
        let result = upsert_toml_table(src, "access.users", replacement);
        assert!(result.starts_with("[other]"), "existing content must be preserved at start");
        assert!(result.contains("[access.users]"));
        assert!(result.contains("alice = \"secret\""));
    }

    #[test]
    fn upsert_toml_table_handles_empty_source_by_writing_replacement_directly() {
        let replacement = "[access.users]\nalice = \"secret\"\n";
        let result = upsert_toml_table("", "access.users", replacement);
        assert_eq!(result, replacement);
    }

    #[test]
    fn upsert_toml_table_replaces_last_section_in_file() {
        let src = "[first]\nk = 1\n\n[access.users]\nalice = \"old\"\n";
        let replacement = "[access.users]\nalice = \"new\"\n";
        let result = upsert_toml_table(src, "access.users", replacement);
        assert!(result.contains("alice = \"new\""));
        assert!(!result.contains("alice = \"old\""));
        assert!(result.contains("[first]"));
    }

    #[test]
    fn upsert_toml_table_does_not_corrupt_adjacent_dotted_sections() {
        // Replacing [access.users] must not touch [access.user_ad_tags].
        let src = "[access.users]\nalice = \"old\"\n\n[access.user_ad_tags]\nalice = \"tag\"\n";
        let replacement = "[access.users]\nalice = \"new\"\n";
        let result = upsert_toml_table(src, "access.users", replacement);
        assert!(result.contains("[access.user_ad_tags]"));
        assert!(result.contains("alice = \"tag\""), "ad_tags section must be untouched");
        assert!(result.contains("alice = \"new\""));
        assert!(!result.contains("alice = \"old\""));
    }

    #[test]
    fn upsert_toml_table_round_trips_sha256_secret_as_value() {
        let secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        let src = "[access.users]\nalice = \"old_secret\"\n";
        let replacement = format!("[access.users]\nalice = \"{secret}\"\n");
        let result = upsert_toml_table(src, "access.users", &replacement);
        assert!(result.contains(secret));
    }

    // ── parse_if_match security edge cases ──────────────────────────────────

    // Regression: trim_matches('"') over-strips '""' to "", producing Some("")
    // which ensures_expected_revision compares "" != sha256hex → always 409 Conflict.
    // After the fix, '""' is treated as absent (no revision check requested).
    #[test]
    fn parse_if_match_returns_none_for_empty_quoted_etag() {
        let map = header_with_if_match("\"\"");
        assert!(
            parse_if_match(&map).is_none(),
            "empty quoted ETag '\"\"' must be treated as absent to prevent spurious 409 Conflicts"
        );
    }

    // Regression: trim_matches('"') turns '"""abc"""' into 'abc' (strips all outer
    // quotes). The correct behaviour strips exactly one outer pair, preserving the
    // inner quotes so the value cannot accidentally match a real SHA-256 revision.
    #[test]
    fn parse_if_match_does_not_over_strip_multiple_outer_quotes() {
        let map = header_with_if_match("\"\"\"abc\"\"\"");
        let result = parse_if_match(&map).expect("non-empty triple-quoted input must return Some");
        assert_eq!(result, "\"\"abc\"\"");
        assert_ne!(result, "abc", "over-stripping must not produce the bare inner value");
    }

    // A lone '"' char cannot form a matched pair; the raw value is returned unchanged
    // so the revision check receives a non-empty non-matching string and returns 409.
    // Before the fix, trim_matches produced Some("") for this input.
    #[test]
    fn parse_if_match_single_quote_does_not_produce_empty_value() {
        let map = header_with_if_match("\"");
        let result = parse_if_match(&map);
        assert!(result.is_some(), "malformed single-quote ETag must not be silently dropped");
        assert_ne!(
            result.as_deref(),
            Some(""),
            "single-quote ETag must not collapse to empty string"
        );
    }

    // ── find_toml_table_bounds additional edge cases ─────────────────────────

    #[test]
    fn find_toml_table_bounds_returns_none_for_empty_source() {
        assert!(find_toml_table_bounds("", "access.users").is_none());
    }

    #[test]
    fn find_toml_table_bounds_whole_file_is_single_section() {
        let src = "[access.users]\nalice = \"s\"\n";
        let (start, end) = find_toml_table_bounds(src, "access.users").expect("must match");
        assert_eq!(start, 0);
        assert_eq!(end, src.len());
    }
}
