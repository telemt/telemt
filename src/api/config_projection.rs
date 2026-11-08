//! Shared value-free differences and conservative read-only config projections.

use serde::Serialize;
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;

use super::model::ApiFailure;
use crate::config::{ProxyConfig, observation::ConfigProvenance};

pub(super) const MAX_PATHS: usize = 4096;

pub(super) const SECTIONS: &[&str] = &[
    "general",
    "network",
    "server",
    "timeouts",
    "censorship",
    "upstreams",
    "dc_overrides",
    "web",
    "access",
    "logging",
    "root",
];
const MAX_FIELDS: usize = 1024;

pub(super) fn selected(path: &str, sections: &BTreeSet<String>) -> bool {
    let root = path.split(['.', '[']).next().unwrap_or_default();
    sections.contains(if SECTIONS.contains(&root) {
        root
    } else {
        "root"
    })
}

pub(super) fn retain_sections(value: &mut Json, sections: &BTreeSet<String>) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|key, _| selected(key, sections));
    }
}

struct Rule {
    public: bool,
    schema: Json,
    default: Option<Json>,
}
fn rules() -> Result<&'static BTreeMap<String, Rule>, ApiFailure> {
    static RULES: OnceLock<Result<BTreeMap<String, Rule>, String>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            super::discovery::projection_rules()
                .map(|fields| {
                    fields
                        .into_iter()
                        .map(|(path, public, schema, default)| {
                            (
                                path,
                                Rule {
                                    public,
                                    schema,
                                    default,
                                },
                            )
                        })
                        .collect()
                })
                .map_err(|_| "Cannot load configuration projection policy".to_owned())
        })
        .as_ref()
        .map_err(|error| ApiFailure::internal(error.clone()))
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FieldProjection {
    pub(super) path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Json>,
    redacted: bool,
    present: bool,
    entries: Option<usize>,
    differs: Option<bool>,
    origin: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    inherited_from: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Projection {
    pub(super) fields: Vec<FieldProjection>,
    pub(super) truncated: bool,
    provenance: &'static str,
    /// Input provenance only; this is deliberately not named applied_revision.
    source_revision: Option<String>,
    source_count: Option<usize>,
}

pub(super) fn project(
    config: &ProxyConfig,
    value: &Json,
    other: Option<&Json>,
    sections: &BTreeSet<String>,
    desired: bool,
) -> Result<Projection, ApiFailure> {
    let rules = rules()?;
    let (provenance, source_revision, source_count) = match &config.provenance {
        ConfigProvenance::Source(source) => (
            "normalized_source",
            Some(source.revision.clone()),
            Some(source.source_count),
        ),
        ConfigProvenance::Mixed => ("mixed_publication", None, None),
        ConfigProvenance::Unknown => ("unknown", None, None),
    };
    let mut output = Projection {
        fields: Vec::new(),
        truncated: false,
        provenance,
        source_revision,
        source_count,
    };
    struct Walk<'a> {
        config: &'a ProxyConfig,
        rules: &'a BTreeMap<String, Rule>,
        desired: bool,
        comparing: bool,
    }
    impl Walk<'_> {
        fn visit(
            &self,
            value: &Json,
            other: Option<&Json>,
            path: &str,
            canonical: &str,
            output: &mut Projection,
        ) {
            if output.fields.len() >= MAX_FIELDS || path.len() > 256 {
                output.truncated = true;
                return;
            }
            let rule = self.rules.get(canonical);
            let public = rule.is_some_and(|rule| rule.public);
            let open_map = rule.is_some_and(|rule| {
                rule.schema
                    .get("additionalProperties")
                    .is_some_and(|value| value != &Json::Bool(false))
            }) || path == "dc_overrides"
                || path == "censorship.exclusive_mask";
            if public
                && !open_map
                && let Some(object) = value.as_object()
            {
                if !object.is_empty() {
                    for (key, child) in object {
                        self.visit(
                            child,
                            other.and_then(|value| value.get(key)),
                            &format!("{path}.{key}"),
                            &format!("{canonical}.{key}"),
                            output,
                        );
                    }
                    return;
                }
            }
            if public
                && let Some(array) = value.as_array()
                && rule.is_some_and(|rule| rule.schema["items"]["type"] == "object")
            {
                if !array.is_empty() {
                    for (index, child) in array.iter().enumerate() {
                        if let Some(object) = child.as_object() {
                            for (key, field) in object {
                                self.visit(
                                    field,
                                    other.and_then(|v| v.get(index)).and_then(|v| v.get(key)),
                                    &format!("{path}[{index}].{key}"),
                                    &format!("{canonical}[].{key}"),
                                    output,
                                );
                            }
                        }
                    }
                    return;
                }
            }
            // Arbitrary strings and all dynamic identities are private, including
            // URL userinfo in a field whose static metadata says "public".
            let safe_scalar = |value: &Json, schema: &Json| {
                value.is_null()
                    || value.is_boolean()
                    || value.is_number()
                    || schema
                        .get("enum")
                        .and_then(Json::as_array)
                        .is_some_and(|allowed| allowed.contains(value))
            };
            let runtime_derived = path == "censorship.fake_cert_len"
                && matches!(&self.config.provenance, ConfigProvenance::Source(source) if source.generated_fake_cert_len);
            let generated = self.desired && runtime_derived;
            let visible = public
                && !open_map
                && !generated
                && rule.is_some_and(|rule| {
                    safe_scalar(value, &rule.schema)
                        || value.as_array().is_some_and(|array| {
                            array.len() <= 32
                                && array
                                    .iter()
                                    .all(|item| safe_scalar(item, &rule.schema["items"]))
                        })
                });
            let (origin, inherited_from) = if runtime_derived {
                ("runtime_derived", None)
            } else if canonical == "upstreams[].prefer" && value.is_null() {
                ("inherited", Some("network.prefer"))
            } else {
                (
                    match &self.config.provenance {
                        ConfigProvenance::Source(source)
                            if source.explicit_paths.contains(path) =>
                        {
                            "source"
                        }
                        ConfigProvenance::Source(source) if !source.complete => "unknown",
                        ConfigProvenance::Source(_)
                            if rule.and_then(|rule| rule.default.as_ref()) == Some(value) =>
                        {
                            "type_default"
                        }
                        ConfigProvenance::Source(_) => "default_or_derived",
                        ConfigProvenance::Mixed => "mixed_unknown",
                        ConfigProvenance::Unknown => "unknown",
                    },
                    None,
                )
            };
            let present = !value.is_null()
                && value.as_str().is_none_or(|v| !v.is_empty())
                && value.as_object().is_none_or(|v| !v.is_empty())
                && value.as_array().is_none_or(|v| !v.is_empty());
            output.fields.push(FieldProjection {
                path: path.to_owned(),
                value: visible.then(|| value.clone()),
                redacted: !visible,
                present,
                entries: value
                    .as_object()
                    .map(|v| v.len())
                    .or_else(|| value.as_array().map(Vec::len)),
                differs: (self.comparing && !runtime_derived).then(|| other != Some(value)),
                origin,
                inherited_from,
            });
        }
    }
    let walk = Walk {
        config,
        rules,
        desired,
        comparing: other.is_some(),
    };
    if let Some(object) = value.as_object() {
        for (key, child) in object {
            if selected(key, sections) {
                walk.visit(
                    child,
                    other.and_then(|value| value.get(key)),
                    key,
                    key,
                    &mut output,
                );
            }
        }
    }
    Ok(output)
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
