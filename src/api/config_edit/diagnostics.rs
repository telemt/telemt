use std::collections::BTreeSet;

use super::*;
use crate::api::model::FieldIssue;

pub(super) const MAX_PATHS: usize = 4096;

pub(super) fn issue(
    path: impl Into<String>,
    code: &'static str,
    message: impl Into<String>,
) -> FieldIssue {
    FieldIssue {
        path: path.into(),
        code,
        message: message.into(),
    }
}

/// Raw validators can quote credentials, origins and source excerpts. Only known
/// metadata paths and fixed explanations are projected into an API error.
pub(super) fn validation_error(
    code: &'static str,
    fallback: &str,
    error: impl std::fmt::Display,
) -> ApiFailure {
    let text = error.to_string();
    let canonical = regex::Regex::new(r"\[\d+\]")
        .map(|pattern| pattern.replace_all(&text, "[]").into_owned())
        .unwrap_or_default();
    let path = crate::api::discovery::config_field_paths()
        .unwrap_or_default()
        .into_iter()
        .filter(|path| canonical.contains(path))
        .max_by_key(|path| path.len())
        .unwrap_or(fallback);
    let explanation = if text.contains("overlaps WEB listener") {
        "Decoy origin overlaps WEB listener"
    } else if text.contains("only valid for mode=http_upstream") {
        "Field is only valid for mode=http_upstream"
    } else if text.contains("allow_wildcard_hosts") {
        "Wildcard selectors require web.allow_wildcard_hosts=true in the active process"
    } else {
        match code {
            "source_load_failed" => "Cannot load the desired configuration source",
            "deserialization_failed" => "Value has an invalid type or enum variant",
            "preparation_failed" => "DNS or static-asset preparation failed",
            "effective_config_invalid" => {
                "Candidate is incompatible with retained process configuration"
            }
            _ => "Value violates configuration or dependent-field constraints",
        }
    };
    let message = format!("{path}: {explanation}");
    let mut failure = if code == "source_load_failed" {
        // Preserve PATCH's existing server-error status for an unreadable or
        // invalid current source, while keeping its raw excerpt private.
        ApiFailure::internal(message)
    } else {
        ApiFailure::bad_request(message)
    };
    failure.details.push(issue(path, code, explanation));
    failure
}

/// This document carries key structure only. Null members must be checked even
/// though normal PATCH merging omits them; values never enter key diagnostics.
fn key_document(value: &Json) -> Toml {
    match value {
        Json::Object(object) => Toml::Table(
            object
                .iter()
                .map(|(key, value)| {
                    let key = if key.len() > 128 {
                        "{unknown}".to_owned()
                    } else {
                        key.clone()
                    };
                    (key, key_document(value))
                })
                .collect(),
        ),
        Json::Array(items) => Toml::Array(items.iter().map(key_document).collect()),
        _ => Toml::Boolean(false),
    }
}

pub(super) fn reject_unknown(patch: &Json) -> Result<(), ApiFailure> {
    let paths = ProxyConfig::unknown_source_paths(&key_document(patch));
    if paths.is_empty() {
        return Ok(());
    }
    let mut error = ApiFailure::bad_request("Unknown configuration fields");
    error.details = paths
        .into_iter()
        .take(64)
        .map(|path| {
            let path = if path.len() <= 256
                && path
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.[]".contains(c))
            {
                path
            } else {
                "$".to_owned()
            };
            issue(
                path,
                "unknown_field",
                "Field is not part of the configuration contract",
            )
        })
        .collect();
    Err(error)
}

/// Paths only: no before/after values or dynamic keys are returned. Arrays use
/// indices, open maps use their documented placeholder to avoid leaking identities.
pub(super) fn changed_paths(old: &Json, new: &Json) -> Vec<String> {
    fn walk(old: Option<&Json>, new: Option<&Json>, path: &str, out: &mut BTreeSet<String>) {
        if old == new {
            return;
        }
        if out.len() > MAX_PATHS {
            return;
        }
        let map_key = if path == "dc_overrides" {
            Some("{dc}")
        } else if path == "censorship.exclusive_mask" {
            Some("{hostname}")
        } else if path.starts_with("access.") {
            Some("{entry}")
        } else {
            None
        };
        match (old, new) {
            (Some(Json::Object(_)), _) | (_, Some(Json::Object(_))) => {
                let a = old.and_then(Json::as_object);
                let b = new.and_then(Json::as_object);
                let keys: BTreeSet<_> = a
                    .into_iter()
                    .flat_map(|v| v.keys())
                    .chain(b.into_iter().flat_map(|v| v.keys()))
                    .collect();
                if keys.is_empty() {
                    out.insert(path.to_string());
                }
                for key in keys {
                    let key_path = map_key.unwrap_or(key);
                    let next = if path.is_empty() {
                        key_path.to_string()
                    } else {
                        format!("{path}.{key_path}")
                    };
                    walk(
                        a.and_then(|v| v.get(key)),
                        b.and_then(|v| v.get(key)),
                        &next,
                        out,
                    );
                }
            }
            (Some(Json::Array(_)), _) | (_, Some(Json::Array(_))) => {
                let a = old
                    .and_then(Json::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let b = new
                    .and_then(Json::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                if a.is_empty() && b.is_empty() {
                    out.insert(path.to_string());
                }
                for index in 0..a.len().max(b.len()) {
                    walk(a.get(index), b.get(index), &format!("{path}[{index}]"), out);
                }
            }
            _ => {
                out.insert(path.to_string());
            }
        }
    }
    let mut paths = BTreeSet::new();
    walk(Some(old), Some(new), "", &mut paths);
    paths.into_iter().collect()
}

#[derive(Debug, Serialize)]
pub(in crate::api) struct NormalizationEffect {
    pub(super) path: String,
    pub(super) code: &'static str,
}

pub(super) fn source_conflict(mut error: ApiFailure) -> ApiFailure {
    error.message = "Patch requires one independently writable config source".into();
    error.details.push(issue(
        "$",
        "source_ownership_conflict",
        error.message.clone(),
    ));
    error
}

pub(super) fn canonicalize_aliases(
    patch: &mut Toml,
) -> Result<Vec<NormalizationEffect>, ApiFailure> {
    let mut effects = Vec::new();
    if let Some(vhosts) = patch
        .get("web")
        .and_then(|web| web.get("vhosts"))
        .and_then(Toml::as_array)
    {
        for (index, vhost) in vhosts.iter().enumerate() {
            let Some(decoy) = vhost.get("decoy").and_then(Toml::as_table) else {
                continue;
            };
            let allowed: &[&str] = match decoy.get("mode").and_then(Toml::as_str) {
                Some("http_upstream") => &["mode", "upstream", "resolve"],
                Some("static_directory") => &["mode", "directory", "index"],
                _ => continue,
            };
            for key in decoy.keys().filter(|key| !allowed.contains(&key.as_str())) {
                let message = if key == "resolve" {
                    "Field is only valid for mode=http_upstream"
                } else {
                    "Field does not apply to the selected decoy mode"
                };
                let mut error = ApiFailure::bad_request(message);
                error.details.push(issue(
                    format!("web.vhosts[{index}].decoy.{key}"),
                    "field_not_applicable",
                    message,
                ));
                return Err(error);
            }
        }
    }
    if let Some(upstreams) = patch.get_mut("upstreams").and_then(Toml::as_array_mut) {
        for (index, upstream) in upstreams.iter_mut().enumerate() {
            let Some(table) = upstream.as_table_mut() else {
                continue;
            };
            if let Some(value) = table.remove("force_bind") {
                if table.contains_key("bindtodevice") {
                    let mut error = ApiFailure::bad_request(
                        "Alias and canonical field cannot be supplied together",
                    );
                    error.details.push(issue(
                        format!("upstreams[{index}].bindtodevice"),
                        "duplicate_alias",
                        error.message.clone(),
                    ));
                    return Err(error);
                }
                table.insert("bindtodevice".into(), value);
                effects.push(NormalizationEffect {
                    path: format!("upstreams[{index}].bindtodevice"),
                    code: "alias_canonicalized",
                });
            }
            let variant_fields: &[&str] = match table.get("type").and_then(Toml::as_str) {
                Some("direct") => &["interface", "bind_addresses", "bindtodevice"],
                Some("socks4") => &["address", "interface", "user_id"],
                Some("socks5") => &["address", "interface", "username", "password"],
                Some("shadowsocks") => &["url", "interface"],
                _ => continue,
            };
            for key in table.keys() {
                if ![
                    "type", "weight", "enabled", "scopes", "ipv4", "ipv6", "prefer",
                ]
                .contains(&key.as_str())
                    && !variant_fields.contains(&key.as_str())
                {
                    let mut error = ApiFailure::bad_request(
                        "Field does not apply to the selected upstream type",
                    );
                    error.details.push(issue(
                        format!("upstreams[{index}].{key}"),
                        "field_not_applicable",
                        error.message.clone(),
                    ));
                    return Err(error);
                }
            }
        }
    }
    Ok(effects)
}

pub(super) fn normalization(
    patch: &Json,
    requested: &ProxyConfig,
    candidate: &ProxyConfig,
) -> Result<Vec<NormalizationEffect>, ApiFailure> {
    let before = serde_json::to_value(requested)
        .map_err(|_| ApiFailure::internal("Cannot project candidate fields"))?;
    let after = serde_json::to_value(candidate)
        .map_err(|_| ApiFailure::internal("Cannot project candidate fields"))?;
    let mut effects: Vec<_> = changed_paths(&before, &after)
        .into_iter()
        .map(|path| NormalizationEffect {
            path,
            code: "normalized",
        })
        .collect();
    fn ignored(value: &Json, path: &str, effects: &mut Vec<NormalizationEffect>) {
        if effects.len() > MAX_PATHS {
            return;
        }
        match value {
            Json::Object(object) => {
                for (key, value) in object {
                    let key = if path == "dc_overrides" {
                        "{dc}"
                    } else if path == "censorship.exclusive_mask" {
                        "{hostname}"
                    } else {
                        key.as_str()
                    };
                    let next = if path.is_empty() {
                        key.to_string()
                    } else {
                        format!("{path}.{key}")
                    };
                    if value.is_null() {
                        effects.push(NormalizationEffect {
                            path: next,
                            code: "null_ignored",
                        });
                    } else {
                        ignored(value, &next, effects);
                    }
                }
            }
            Json::Array(array) => {
                for (index, value) in array.iter().enumerate() {
                    ignored(value, &format!("{path}[{index}]"), effects);
                }
            }
            _ => {}
        }
    }
    ignored(patch, "", &mut effects);
    Ok(effects)
}
