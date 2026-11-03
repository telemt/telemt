//! Checked metadata projection over unconfigured, typed configuration defaults.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::config_store::{EDITABLE_SECTIONS, EDITABLE_SERVER_FIELDS};
use super::super::model::ApiFailure;
use super::SCHEMA_VERSION;

mod defaults;
#[cfg(test)]
mod inventory_tests;
#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FieldSpec {
    pub(super) path: String,
    pub(super) value: Value,
    pub(super) default_kind: DefaultKind,
    pub(super) sensitivity: String,
    pub(super) description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) unit: Option<String>,
    pub(super) apply: ApplyPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) constraints: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DefaultKind {
    TypeDefault,
    Unset,
    Required,
    NestedFields,
    MapEntry,
    Redacted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyPolicy {
    pub(super) watcher: String,
    pub(super) reload: String,
    pub(super) effect: String,
}

#[derive(Serialize)]
pub(in crate::api) struct ConfigSchemaData {
    schema_version: u32,
    value_schema_dialect: &'static str,
    defaults_scope: &'static str,
    validation_scope: &'static str,
    path_notation: &'static str,
    config_patch: ConfigPatchSemantics,
    fields: Vec<FieldMetadata>,
}

#[derive(Serialize)]
struct ConfigPatchSemantics {
    objects: &'static str,
    arrays: &'static str,
    object_null_members: &'static str,
    reset: &'static str,
    source_ownership: &'static str,
    if_match: &'static str,
}

#[derive(Serialize)]
struct FieldMetadata {
    #[serde(flatten)]
    spec: FieldSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<Value>,
    api: FieldApi,
}

#[derive(Serialize)]
struct FieldApi {
    config_read: bool,
    config_write: bool,
    read_routes: Vec<&'static str>,
    write_routes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_editable_reason: Option<&'static str>,
    null_behavior: &'static str,
}

pub(in crate::api) fn config_schema() -> Result<&'static ConfigSchemaData, ApiFailure> {
    static SCHEMA: OnceLock<Result<ConfigSchemaData, String>> = OnceLock::new();
    SCHEMA
        .get_or_init(build_schema)
        .as_ref()
        .map_err(|error| ApiFailure::internal(error.clone()))
}

pub(super) fn field_paths() -> Result<Vec<&'static str>, ApiFailure> {
    Ok(config_schema()?
        .fields
        .iter()
        .map(|field| field.spec.path.as_str())
        .collect())
}

pub(in crate::api) fn projection_rules()
-> Result<Vec<(String, bool, Value, Option<Value>)>, ApiFailure> {
    Ok(config_schema()?
        .fields
        .iter()
        .map(|field| {
            (
                field.spec.path.clone(),
                field.spec.sensitivity == "public",
                field.spec.value.clone(),
                field.default.clone(),
            )
        })
        .collect())
}

fn field_specs() -> Result<Vec<FieldSpec>, String> {
    serde_json::from_str(include_str!("fields.json"))
        .map_err(|error| format!("invalid compiled config field catalog: {error}"))
}

fn build_schema() -> Result<ConfigSchemaData, String> {
    let defaults = defaults::typed_defaults()?;
    let specs = field_specs()?;
    let mut fields = Vec::with_capacity(specs.len());
    for spec in specs {
        let default = match spec.default_kind {
            DefaultKind::TypeDefault if spec.path == "web.vhosts[].profiles" => {
                Some(Value::Array(Vec::new()))
            }
            DefaultKind::TypeDefault => Some(
                default_at(
                    if spec.path.contains("[]") {
                        &defaults["_elements"]
                    } else {
                        &defaults
                    },
                    &spec.path,
                )
                .ok_or_else(|| format!("compiled config default missing: {}", spec.path))?
                .clone(),
            ),
            DefaultKind::Unset => Some(Value::Null),
            _ => None,
        };
        let api = field_api(&spec.path);
        fields.push(FieldMetadata { spec, default, api });
    }
    Ok(ConfigSchemaData {
        schema_version: SCHEMA_VERSION,
        value_schema_dialect: "https://json-schema.org/draft/2020-12/schema",
        defaults_scope: "unconfigured_type_defaults_before_loader_normalization",
        validation_scope: "value_constraints_are_not_a_substitute_for_full_config_validation",
        path_notation: "dot_members; []=array_element; {name}=dynamic_map_key",
        config_patch: ConfigPatchSemantics {
            objects: "recursive_merge",
            arrays: "replace_whole_array",
            object_null_members: "ignored_before_candidate_validation",
            reset: "not_supported",
            source_ownership: "one_independently_writable_source_per_mutation",
            if_match: "optional_source_manifest_revision",
        },
        fields,
    })
}

fn default_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    fn walk<'a>(value: &'a Value, segments: &[&str]) -> Option<&'a Value> {
        let Some((segment, rest)) = segments.split_first() else {
            return Some(value);
        };
        if let Some(key) = segment.strip_suffix("[]") {
            value
                .get(key)?
                .as_array()?
                .iter()
                .find_map(|item| walk(item, rest))
        } else {
            walk(value.get(*segment)?, rest)
        }
    }
    walk(value, &path.split('.').collect::<Vec<_>>())
}

fn field_api(path: &str) -> FieldApi {
    let top = path.split(['.', '[']).next().unwrap_or("");
    let config_editable = EDITABLE_SECTIONS.contains(&top)
        || (top == "server"
            && EDITABLE_SERVER_FIELDS.iter().any(|field| {
                let prefix = format!("server.{field}");
                path == prefix
                    || path.starts_with(&format!("{prefix}["))
                    || path.starts_with(&format!("{prefix}."))
            }));
    let user_field = path
        .strip_prefix("access.")
        .and_then(|path| path.split('.').next())
        .and_then(|field| match field {
            "users" => Some("secret"),
            "user_enabled" => Some("enabled"),
            "user_ad_tags" => Some("user_ad_tag"),
            "user_max_tcp_conns" => Some("max_tcp_conns"),
            "user_expirations" => Some("expiration_rfc3339"),
            "user_data_quota" => Some("data_quota_bytes"),
            "user_quota_periods" => Some("quota_period"),
            "user_max_unique_ips" => Some("max_unique_ips"),
            "user_rate_limits" if path.ends_with(".up_bps") => Some("rate_limit_up_bps"),
            "user_rate_limits" if path.ends_with(".down_bps") => Some("rate_limit_down_bps"),
            _ => None,
        });
    let mut api = FieldApi {
        config_read: config_editable,
        config_write: config_editable,
        read_routes: Vec::new(),
        write_routes: Vec::new(),
        request_field: user_field,
        non_editable_reason: None,
        null_behavior: "not_editable",
    };
    if config_editable {
        api.read_routes.push("GET /v1/config");
        api.write_routes.push("PATCH /v1/config");
        api.null_behavior = "ignored_member_then_validate_candidate";
    } else if let Some(field) = user_field {
        api.read_routes.push("GET /v1/users/{username}");
        api.write_routes
            .extend(["POST /v1/users", "PATCH /v1/users/{username}"]);
        api.null_behavior = if field == "secret" {
            "unchanged_on_user_patch"
        } else {
            "remove_user_override_on_patch"
        };
        api.non_editable_reason = Some("managed_via_users_api");
    } else {
        api.non_editable_reason = Some(match top {
            "access" => "access_policy_is_file_only",
            "network" => "network_section_is_file_only",
            "server" => "server_field_not_in_config_api_allowlist",
            "logging" => "logging_section_is_file_only",
            "show_link" => "use_general_links_show",
            "include" => "source_graph_is_file_only",
            _ => "root_field_not_in_config_api_allowlist",
        });
    }
    if path.starts_with("access.user_max_unique_ips_")
        || path == "access.user_max_tcp_conns_global_each"
    {
        api.read_routes.push("GET /v1/limits/effective");
    }
    if path == "server.api.whitelist" {
        api.read_routes.push("GET /v1/security/whitelist");
    }
    api
}
