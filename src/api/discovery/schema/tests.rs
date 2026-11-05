use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::*;
use crate::config::ProxyConfig;

fn field<'a>(schema: &'a ConfigSchemaData, path: &str) -> &'a FieldMetadata {
    schema
        .fields
        .iter()
        .find(|field| field.spec.path == path)
        .unwrap_or_else(|| panic!("missing field {path}"))
}

#[test]
fn schema_defaults_and_collection_templates_are_typed_and_secret_free() {
    let schema = config_schema().unwrap();
    let defaults = ProxyConfig::default();
    assert_eq!(
        field(schema, "general.me_keepalive_interval_secs").default,
        Some(json!(defaults.general.me_keepalive_interval_secs))
    );
    assert_eq!(
        field(schema, "server.api.gray_action").default,
        Some(json!("drop"))
    );
    assert_eq!(
        field(schema, "server.listeners[].synlimit").default,
        Some(json!(false))
    );
    assert_eq!(
        field(schema, "web.vhosts[].profiles").default,
        Some(json!([]))
    );
    assert_eq!(
        field(schema, "web.vhosts[].host").default,
        Some(Value::Null)
    );
    assert_eq!(
        field(schema, "web.vhosts[].decoy.index").default,
        Some(json!("index.html"))
    );
    assert!(field(schema, "web.vhosts[].public_addr").default.is_none());
    assert!(field(schema, "upstreams[].address").default.is_none());
    for path in [
        "access.users",
        "access.users.{username}",
        "server.api.auth_header",
        "upstreams[].password",
        "upstreams[].url",
    ] {
        let field = field(schema, path);
        assert_eq!(field.spec.sensitivity, "credential");
        assert!(field.default.is_none());
    }
}

fn serialized_paths(value: &Value, path: &str, paths: &mut BTreeSet<String>) {
    if !path.is_empty() {
        paths.insert(path.to_string());
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "_elements" {
                    continue;
                }
                let key = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                serialized_paths(value, &key, paths);
            }
        }
        Value::Array(array) => {
            for item in array {
                if let Some(object) = item.as_object() {
                    for (key, value) in object {
                        serialized_paths(value, &format!("{path}[].{key}"), paths);
                    }
                }
            }
        }
        _ => {}
    }
}

#[test]
fn every_serialized_field_has_metadata_including_all_collection_variants() {
    let schema = config_schema().unwrap();
    let mut actual = BTreeSet::new();
    let values = defaults::typed_defaults().unwrap();
    serialized_paths(&values, "", &mut actual);
    serialized_paths(&values["_elements"], "", &mut actual);
    let catalog: BTreeSet<_> = schema
        .fields
        .iter()
        .map(|field| field.spec.path.clone())
        .collect();
    assert_eq!(catalog.len(), schema.fields.len(), "duplicate config path");
    let missing: Vec<_> = actual.difference(&catalog).collect();
    assert!(
        missing.is_empty(),
        "unclassified serialized fields: {missing:?}"
    );
    // Omitted Options and dynamic maps are part of the contract too.
    for path in [
        "web.vhosts[].host",
        "web.vhosts[].hosts",
        "web.retry_jitter.peak_ms",
        "access.users.{username}",
        "access.user_rate_limits.{username}.up_bps",
        "access.cidr_rate_limits.{cidr}.down_bps",
        "dc_overrides.{dc}",
    ] {
        assert!(catalog.contains(path), "missing {path}");
    }
    for entry in &schema.fields {
        if !entry.api.config_write && entry.api.write_routes.is_empty() {
            assert!(
                entry.api.non_editable_reason.is_some(),
                "{}",
                entry.spec.path
            );
        }
    }
}

#[test]
fn api_ownership_aliases_and_null_contracts_match_existing_surfaces() {
    let schema = config_schema().unwrap();
    assert!(field(schema, "web.vhosts[].base_path").api.config_write);
    assert!(field(schema, "server.listeners[].port").api.config_write);
    assert!(
        !field(schema, "server.api.runtime_edge_enabled")
            .api
            .config_write
    );
    assert!(field(schema, "network.dns_overrides").api.config_read);
    assert!(field(schema, "network.dns_overrides").api.config_write);
    assert_eq!(
        field(schema, "network.dns_overrides")
            .api
            .non_editable_reason,
        None
    );
    for path in [
        "network",
        "network.ipv4",
        "network.ipv6",
        "network.prefer",
        "network.stun_servers",
    ] {
        assert!(!field(schema, path).api.config_read);
        assert!(!field(schema, path).api.config_write);
        assert_eq!(
            field(schema, path).api.non_editable_reason,
            Some("network_field_not_in_config_api_allowlist")
        );
    }
    assert_eq!(
        field(schema, "access.user_rate_limits.{username}.up_bps")
            .api
            .request_field,
        Some("rate_limit_up_bps")
    );
    assert_eq!(
        field(schema, "access.user_quota_periods.{username}")
            .api
            .null_behavior,
        "remove_user_override_on_patch"
    );
    assert!(
        field(schema, "access.user_source_deny")
            .api
            .write_routes
            .is_empty()
    );
    assert!(
        field(schema, "server.api.listen")
            .spec
            .aliases
            .contains(&"server.admin_api.listen".into())
    );
    assert!(
        field(schema, "upstreams[].bindtodevice")
            .spec
            .aliases
            .contains(&"upstreams[].force_bind".into())
    );
    assert_eq!(
        field(schema, "network.dns_overrides").spec.apply.watcher,
        "supported"
    );
    assert_eq!(
        field(schema, "web.debug.body_capture").spec.apply.reload,
        "conditional"
    );
    assert_eq!(
        field(schema, "web.limits.max_sessions_global")
            .spec
            .apply
            .reload,
        "process_restart"
    );
    assert_eq!(
        schema.config_patch.object_null_members,
        "ignored_before_candidate_validation"
    );
}

fn accepts(schema: &Value, value: &Value) -> bool {
    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        return options
            .iter()
            .filter(|option| accepts(option, value))
            .count()
            == 1;
    }
    if let Some(expected) = schema.get("const") {
        return value == expected;
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(value) {
            return false;
        }
    }
    let correct_type = match schema["type"].as_str() {
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_u64() || value.is_i64(),
        Some("number") => value.is_number(),
        Some("array") => value.is_array(),
        Some("object") => value.is_object(),
        None => true,
        other => panic!("unsupported value schema type: {other:?}"),
    };
    if !correct_type {
        return false;
    }
    if let Some(number) = value.as_f64() {
        if schema
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|min| number < min)
            || schema
                .get("maximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| number > max)
        {
            return false;
        }
    }
    if let Some(array) = value.as_array() {
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|min| array.len() < min as usize)
            || schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|max| array.len() > max as usize)
        {
            return false;
        }
        if let Some(items) = schema.get("items") {
            return array.iter().all(|value| accepts(items, value));
        }
    }
    true
}

#[test]
fn declared_value_types_enums_and_ranges_accept_typed_defaults() {
    for field in &config_schema().unwrap().fields {
        if let Some(default) = &field.default {
            if !default.is_null() {
                assert!(
                    accepts(&field.spec.value, default),
                    "{}: {default} violates {}",
                    field.spec.path,
                    field.spec.value
                );
            }
        }
    }
}

fn alternative(field: &FieldMetadata, current: &Value) -> Option<Value> {
    if let Some(values) = field.spec.value.get("enum").and_then(Value::as_array) {
        return values.iter().find(|value| *value != current).cloned();
    }
    if let Some(boolean) = current.as_bool() {
        return Some(json!(!boolean));
    }
    if let Some(number) = current.as_u64() {
        return number.checked_add(1).map(|number| json!(number));
    }
    if let Some(number) = current.as_f64() {
        return Some(json!(number + 0.01));
    }
    None
}

#[test]
fn application_metadata_matches_watcher_and_process_resolver() {
    let base = ProxyConfig::default();
    let baseline = serde_json::to_value(&base).unwrap();
    let schema = config_schema().unwrap();
    let mut watched = 0;
    let mut resolved = 0;
    let mut mismatches = Vec::new();
    for field in &schema.fields {
        let path = &field.spec.path;
        if path.contains('[') || path.contains('{') {
            continue;
        }
        let pointer = format!("/{}", path.replace('.', "/"));
        let Some(current) = baseline.pointer(&pointer) else {
            continue;
        };
        let Some(next) = alternative(field, current) else {
            continue;
        };
        let mut candidate = baseline.clone();
        *candidate.pointer_mut(&pointer).unwrap() = next;
        let Ok(candidate) = serde_json::from_value::<ProxyConfig>(candidate) else {
            continue;
        };
        let class = crate::config::hot_reload::classify_config_changes(&base, &candidate);
        match field.spec.apply.watcher.as_str() {
            "supported" => {
                if class.restart_required {
                    mismatches.push(format!("watcher unexpectedly requires restart: {path}"));
                }
                watched += 1;
            }
            "unsupported" => {
                if !class.restart_required {
                    mismatches.push(format!("watcher unexpectedly supports: {path}"));
                }
                watched += 1;
            }
            _ => {}
        }
        // Independent runtime validation can reject a deliberately single-field
        // perturbation; only valid candidates classify the actual reload effect.
        if let Ok(effect) = crate::maestro::runtime_build::resolve_reload_config(&base, &candidate)
        {
            match field.spec.apply.reload.as_str() {
                "process_restart" => {
                    if effect.deferred_process_fields.is_empty() {
                        mismatches.push(format!("reload unexpectedly applies: {path}"));
                    }
                }
                "supported" => {
                    if !effect.deferred_process_fields.is_empty() {
                        mismatches.push(format!("reload unexpectedly defers: {path}"));
                    }
                }
                _ => continue,
            }
            resolved += 1;
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert!(
        watched > 150,
        "only {watched} fields checked against watcher"
    );
    assert!(
        resolved > 150,
        "only {resolved} fields checked against runtime resolver"
    );
}

#[test]
fn field_enums_round_trip_through_real_deserializers() {
    let baseline = defaults::typed_defaults().unwrap();
    let mut checked = BTreeMap::new();
    for field in &config_schema().unwrap().fields {
        let path = &field.spec.path;
        if path.contains('[') || path.contains('{') {
            continue;
        }
        let Some(variants) = field.spec.value.get("enum").and_then(Value::as_array) else {
            continue;
        };
        let pointer = format!("/{}", path.replace('.', "/"));
        for variant in variants {
            let mut candidate = baseline.clone();
            *candidate.pointer_mut(&pointer).unwrap() = variant.clone();
            let config: ProxyConfig = serde_json::from_value(candidate)
                .unwrap_or_else(|error| panic!("{path}={variant}: {error}"));
            let serialized = serde_json::to_value(config).unwrap();
            assert_eq!(serialized.pointer(&pointer), Some(variant), "{path}");
        }
        checked.insert(path, variants.len());
    }
    assert!(checked.len() >= 15);
}
