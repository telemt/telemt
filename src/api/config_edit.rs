//! Config-editing API: read managed sections and apply sparse field patches.
//! `access.*` is intentionally not editable here (owned by the users API).

use serde_json::Value as Json;
use toml::Value as Toml;

use super::ApiShared;
use super::config_store::{
    EDITABLE_SECTIONS, compute_revision, current_revision, load_config_from_disk,
    save_sections_to_disk,
};
use super::model::ApiFailure;
use crate::config::ProxyConfig;
use crate::config::hot_reload::classify_config_changes;
use crate::maestro::reload::{ReloadAccepted, ReloadRequest, ReloadSubmitError};
use crate::maestro::runtime_build::deferred_process_fields;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub(super) struct PatchConfigResponse {
    pub revision: String,
    pub restart_required: bool,
    pub runtime_reload_required: bool,
    pub process_restart_required: bool,
    pub deferred_process_fields: Vec<String>,
    pub changed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reload: Option<ReloadAccepted>,
}

/// Shared-state wrapper around [`apply_patch_to_path`]: serializes config
/// mutations behind `mutation_lock`, then records a runtime event. The route
/// handler calls this; the core logic stays decoupled for unit tests.
pub(super) async fn patch_config(
    patch_json: Json,
    expected_revision: Option<String>,
    reload_request: Option<ReloadRequest>,
    shared: &ApiShared,
) -> Result<PatchConfigResponse, ApiFailure> {
    let _guard = shared.mutation_lock.lock().await;
    if reload_request.is_some()
        && let Some(reload_id) = shared.reload_control.in_progress().await
    {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "reload_in_progress",
            format!("Reload {} is already in progress", reload_id),
        ));
    }
    let mut resp = apply_patch_to_path(&shared.config_path, &patch_json, expected_revision).await?;
    if let Some(request) = reload_request {
        let config = Arc::new(load_config_from_disk(&shared.config_path).await?);
        let accepted = shared
            .reload_control
            .submit(config, resp.revision.clone(), request)
            .await
            .map_err(|error| match error {
                ReloadSubmitError::InProgress(reload_id) => ApiFailure::new(
                    hyper::StatusCode::CONFLICT,
                    "reload_in_progress",
                    format!("Reload {} is already in progress", reload_id),
                ),
                ReloadSubmitError::MaestroUnavailable => ApiFailure::new(
                    hyper::StatusCode::SERVICE_UNAVAILABLE,
                    "maestro_unavailable",
                    "Maestro reload coordinator is unavailable",
                ),
            })?;
        resp.reload = Some(accepted);
    }
    drop(_guard);
    shared
        .runtime_events
        .record("api.config.patch.ok", format!("changed={:?}", resp.changed));
    Ok(resp)
}

/// Core patch logic, decoupled from hyper/shared-state so it is unit-testable
/// against a temp file. The route handler holds `mutation_lock` while calling this.
pub(super) async fn apply_patch_to_path(
    config_path: &Path,
    patch_json: &Json,
    expected_revision: Option<String>,
) -> Result<PatchConfigResponse, ApiFailure> {
    // 1. optimistic concurrency
    let current = current_revision(config_path).await?;
    if expected_revision.is_some_and(|expected| expected != current) {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "revision_conflict",
            "Config revision mismatch",
        ));
    }

    // 2. convert + reject access / unknown sections
    let patch_toml = json_to_toml(patch_json)
        .map_err(|e| ApiFailure::bad_request(format!("invalid patch: {}", e)))?;
    let patch_table = patch_toml
        .as_table()
        .ok_or_else(|| ApiFailure::bad_request("patch must be a JSON object"))?;
    if patch_table.contains_key("access") {
        return Err(ApiFailure::new(
            hyper::StatusCode::BAD_REQUEST,
            "access_not_editable",
            "access.* is managed via the users API, not editable here",
        ));
    }
    for key in patch_table.keys() {
        if !EDITABLE_SECTIONS.contains(&key.as_str()) {
            return Err(ApiFailure::new(
                hyper::StatusCode::BAD_REQUEST,
                "section_not_editable",
                format!("section not editable: {}", key),
            ));
        }
    }
    let touched: Vec<&str> = patch_table
        .keys()
        .map(|k| k.as_str())
        .filter(|k| EDITABLE_SECTIONS.contains(k))
        .collect();
    if touched.is_empty() {
        return Err(ApiFailure::bad_request("empty patch: no editable sections"));
    }

    // 3. Parse old + merged from the SAME deserialize path so the classifier
    //    sees only the delta this patch introduces. `ProxyConfig::load` applies
    //    include-expansion / legacy-compat / normalization that a bare
    //    `try_into` does not; mixing the two paths would make unrelated fields
    //    compare unequal and spuriously force `restart_required`.
    let original = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {}", e)))?;
    let original_toml: Toml = toml::from_str(&original)
        .map_err(|e| ApiFailure::internal(format!("failed to parse config: {}", e)))?;
    let old_cfg: ProxyConfig = original_toml
        .clone()
        .try_into()
        .map_err(|e| ApiFailure::internal(format!("config does not deserialize: {}", e)))?;

    let mut merged = original_toml;
    deep_merge(&mut merged, &patch_toml);

    let new_cfg: ProxyConfig = merged
        .clone()
        .try_into()
        .map_err(|e| ApiFailure::bad_request(format!("config does not deserialize: {}", e)))?;
    new_cfg
        .validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;

    // 4. classify changes (Telemt's own hot/restart rule)
    let class = classify_config_changes(&old_cfg, &new_cfg);
    let deferred_process_fields = deferred_process_fields(&old_cfg, &new_cfg);

    // 5. write only the touched top-level sections
    let revision = save_sections_to_disk(config_path, &new_cfg, &touched).await?;

    Ok(PatchConfigResponse {
        revision,
        restart_required: class.restart_required,
        runtime_reload_required: class.restart_required,
        process_restart_required: !deferred_process_fields.is_empty(),
        deferred_process_fields,
        changed: class.changed,
        reload: None,
    })
}

/// Return only the editable config sections + current revision.
pub(super) async fn read_managed_config(config_path: &Path) -> Result<(Toml, String), ApiFailure> {
    let original = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| ApiFailure::internal(format!("failed to read config: {}", e)))?;
    let parsed: Toml = toml::from_str(&original)
        .map_err(|e| ApiFailure::internal(format!("failed to parse config: {}", e)))?;

    let parsed_table = parsed
        .as_table()
        .cloned()
        .unwrap_or_else(toml::value::Table::new);
    // Whitelist: return ONLY the editable sections. A blacklist (just removing
    // `access`) would leak `server` (carries the API `auth_header` + per-node
    // identity) and `network` (per-node addresses). Mirror the PATCH contract.
    let mut table = toml::value::Table::new();
    for section in EDITABLE_SECTIONS {
        if let Some(value) = parsed_table.get(*section) {
            table.insert((*section).to_string(), value.clone());
        }
    }

    let revision = compute_revision(&original);
    Ok((Toml::Table(table), revision))
}

/// Convert a serde_json value to a toml value. `null` is dropped from objects
/// (a patch never sets a key to TOML-null). Numbers become integers when exact,
/// otherwise floats.
fn json_to_toml(j: &Json) -> Result<Toml, String> {
    Ok(match j {
        Json::Null => return Err("null is not representable in TOML".into()),
        Json::Bool(b) => Toml::Boolean(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Toml::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Toml::Float(f)
            } else {
                return Err(format!("unrepresentable number: {}", n));
            }
        }
        Json::String(s) => Toml::String(s.clone()),
        Json::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_toml(item)?);
            }
            Toml::Array(out)
        }
        Json::Object(map) => {
            let mut table = toml::value::Table::new();
            for (k, v) in map {
                if v.is_null() {
                    continue; // skip nulls instead of erroring at object level
                }
                table.insert(k.clone(), json_to_toml(v)?);
            }
            Toml::Table(table)
        }
    })
}

/// Recursively overlay `patch` onto `base`. Tables merge key-by-key; every
/// other value type (scalars, arrays) replaces wholesale.
fn deep_merge(base: &mut Toml, patch: &Toml) {
    match (base, patch) {
        (Toml::Table(b), Toml::Table(p)) => {
            for (k, pv) in p {
                match b.get_mut(k) {
                    Some(bv) => deep_merge(bv, pv),
                    None => {
                        b.insert(k.clone(), pv.clone());
                    }
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_object_converts_to_toml_table() {
        let j: Json = serde_json::json!({"censorship": {"tls_domain": "a.com"}, "default_dc": 2});
        let t = json_to_toml(&j).expect("convertible");
        let table = t.as_table().unwrap();
        assert_eq!(table["censorship"]["tls_domain"].as_str(), Some("a.com"));
        assert_eq!(table["default_dc"].as_integer(), Some(2));
    }

    #[test]
    fn deep_merge_overlays_tables_and_replaces_scalars() {
        let mut base: Toml =
            toml::from_str("[censorship]\ntls_domain = \"old\"\nfake_cert_len = 100\n").unwrap();
        let patch: Toml = toml::from_str("[censorship]\ntls_domain = \"new\"\n").unwrap();

        deep_merge(&mut base, &patch);

        let cens = base["censorship"].as_table().unwrap();
        assert_eq!(cens["tls_domain"].as_str(), Some("new")); // overlaid
        assert_eq!(cens["fake_cert_len"].as_integer(), Some(100)); // preserved
    }

    use std::path::PathBuf;

    fn temp_config(body: &str) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).unwrap();
        (path, dir)
    }

    #[tokio::test]
    async fn patch_rejects_access_section() {
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"access": {"users": {"x": "y"}}});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.code, "access_not_editable");
    }

    #[tokio::test]
    async fn patch_revision_conflict() {
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"censorship": {"tls_domain": "b"}});
        let err = apply_patch_to_path(&path, &patch, Some("deadbeef".into()))
            .await
            .unwrap_err();
        assert_eq!(err.code, "revision_conflict");
    }

    #[tokio::test]
    async fn patch_sni_reports_restart_required() {
        let (path, _d) =
            temp_config("[censorship]\ntls_domain = \"a.com\"\n[server]\nport = 443\n");
        let patch: Json = serde_json::json!({"censorship": {"tls_domain": "b.com"}});
        let resp = apply_patch_to_path(&path, &patch, None).await.unwrap();
        assert!(resp.restart_required);
        assert!(resp.runtime_reload_required);
        assert!(!resp.process_restart_required);
        assert!(resp.deferred_process_fields.is_empty());
        assert!(resp.changed.iter().any(|c| c == "censorship"));
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("tls_domain = \"b.com\""));
        assert_eq!(
            resp.revision,
            crate::api::config_store::compute_revision(&written)
        );
    }

    #[tokio::test]
    async fn read_managed_config_strips_access() {
        let (path, _d) = temp_config(
            "[censorship]\ntls_domain = \"a.com\"\n[access.users]\nbob = \"deadbeef\"\n",
        );
        let (value, revision) = read_managed_config(&path).await.unwrap();
        let table = value.as_table().unwrap();
        assert!(table.contains_key("censorship"));
        assert!(!table.contains_key("access")); // secrets never leave the box here
        assert_eq!(revision, current_revision(&path).await.unwrap());
    }

    #[tokio::test]
    async fn read_managed_config_returns_only_editable_sections() {
        // server carries the API auth_header + per-node identity; network carries
        // per-node addresses. Neither must be exposed by GET /v1/config.
        let (path, _d) = temp_config(concat!(
            "[censorship]\ntls_domain = \"a\"\n",
            "[server]\nport = 443\n[server.api]\nauth_header = \"SECRET\"\n",
            "[network]\nipv4 = \"1.2.3.4\"\n",
            "[access.users]\nbob = \"deadbeef\"\n",
        ));
        let (value, _rev) = read_managed_config(&path).await.unwrap();
        let table = value.as_table().unwrap();
        assert!(table.contains_key("censorship"));
        assert!(!table.contains_key("server")); // no API auth_header / identity leak
        assert!(!table.contains_key("network")); // no per-node identity leak
        assert!(!table.contains_key("access")); // no users/secrets
    }

    #[tokio::test]
    async fn patch_rejects_server_section() {
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"server": {"port": 1}});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.code, "section_not_editable");
    }

    #[tokio::test]
    async fn patch_rejects_show_link_section() {
        // show_link is a legacy top-level scalar/array (not a [table]); it cannot
        // be upserted safely and is superseded by the editable general.links.show.
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"show_link": "*"});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.code, "section_not_editable");
    }

    #[tokio::test]
    async fn patch_general_links_show_is_editable() {
        // The supported replacement path: edit show via the general.links sub-table.
        let (path, _d) = temp_config(
            "[general]\nprefer_ipv6 = false\n[general.links]\nshow = \"*\"\n\
             [censorship]\ntls_domain = \"a\"\n",
        );
        let patch: Json = serde_json::json!({"general": {"links": {"show": ["alice"]}}});
        let resp = apply_patch_to_path(&path, &patch, None).await.unwrap();
        assert!(resp.changed.iter().any(|c| c == "general"));
        let written = tokio::fs::read_to_string(&path).await.unwrap();
        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert_eq!(
            parsed["general"]["links"]["show"][0].as_str(),
            Some("alice"),
            "{written}"
        );
        // No leaked top-level [links]/[modes] and no duplicate sub-tables.
        assert_eq!(written.matches("[general.links]").count(), 1, "{written}");
    }

    #[tokio::test]
    async fn patch_links_public_port_written_as_integer_not_float_or_string() {
        // A JSON integer must land on disk as a bare TOML integer (443), never
        // 443.0 nor "443". The write re-renders from the typed config, so the
        // u16 field dictates the output format regardless of JSON quirks.
        let (path, _d) = temp_config("[general]\nprefer_ipv6 = false\n");
        let patch: Json = serde_json::json!({"general": {"links": {"public_port": 443}}});
        apply_patch_to_path(&path, &patch, None).await.unwrap();

        let written = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(written.contains("public_port = 443"), "{written}");
        assert!(
            !written.contains("443.0"),
            "must not be a float:\n{written}"
        );
        assert!(
            !written.contains("\"443\""),
            "must not be a string:\n{written}"
        );

        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert_eq!(
            parsed["general"]["links"]["public_port"].as_integer(),
            Some(443),
            "{written}"
        );
    }

    #[tokio::test]
    async fn patch_links_public_port_rejects_float() {
        // 443.0 cannot deserialize into u16 -> rejected, not silently coerced.
        let (path, _d) = temp_config("[general]\nprefer_ipv6 = false\n");
        let patch: Json = serde_json::json!({"general": {"links": {"public_port": 443.0}}});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.status, hyper::StatusCode::BAD_REQUEST, "{:?}", err);
    }

    #[tokio::test]
    async fn patch_links_public_port_rejects_string() {
        // "443" is a string, not a u16 -> rejected.
        let (path, _d) = temp_config("[general]\nprefer_ipv6 = false\n");
        let patch: Json = serde_json::json!({"general": {"links": {"public_port": "443"}}});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.status, hyper::StatusCode::BAD_REQUEST, "{:?}", err);
    }

    #[tokio::test]
    async fn patch_empty_is_rejected() {
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({});
        assert!(apply_patch_to_path(&path, &patch, None).await.is_err());
    }

    #[tokio::test]
    async fn patch_log_level_is_hot() {
        // general.log_level is hot-reloadable -> a patch changing only it must
        // report restart_required = false (exercises the full apply path, not
        // just the classifier). Default LogLevel is Normal; patch to "debug".
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"general": {"log_level": "debug"}});
        let resp = apply_patch_to_path(&path, &patch, None).await.unwrap();
        assert!(!resp.restart_required);
        assert!(!resp.runtime_reload_required);
        assert!(!resp.process_restart_required);
        assert!(resp.changed.iter().any(|c| c == "general"));
    }
}
