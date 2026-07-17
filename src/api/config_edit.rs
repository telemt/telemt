//! Config-editing API: read managed sections and apply sparse field patches.
//! `access.*` is intentionally not editable here (owned by the users API).
//! `[server]` is only partially editable — see [`EDITABLE_SERVER_FIELDS`].

use serde_json::Value as Json;
use toml::Value as Toml;

use super::ApiShared;
use super::config_store::{
    EDITABLE_SECTIONS, EDITABLE_SERVER_FIELDS, compute_revision, current_revision,
    is_editable_section, save_sections_to_disk,
};
use super::model::ApiFailure;
use crate::config::ProxyConfig;
use crate::config::hot_reload::classify_config_changes;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub(super) struct PatchConfigResponse {
    pub revision: String,
    pub restart_required: bool,
    pub changed: Vec<String>,
}

/// Shared-state wrapper around [`apply_patch_to_path`]: serializes config
/// mutations behind `mutation_lock`, then records a runtime event. The route
/// handler calls this; the core logic stays decoupled for unit tests.
pub(super) async fn patch_config(
    patch_json: Json,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<PatchConfigResponse, ApiFailure> {
    let _guard = shared.mutation_lock.lock().await;
    let resp = apply_patch_to_path(&shared.config_path, &patch_json, expected_revision).await?;
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

    // 2. convert + reject access / unknown sections / forbidden server fields
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
    for (key, value) in patch_table {
        if !is_editable_section(key.as_str()) {
            return Err(ApiFailure::new(
                hyper::StatusCode::BAD_REQUEST,
                "section_not_editable",
                format!("section not editable: {}", key),
            ));
        }
        if key == "server" {
            validate_server_patch(value)?;
        }
    }
    let touched: Vec<&str> = patch_table
        .keys()
        .map(|k| k.as_str())
        .filter(|k| is_editable_section(k))
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

    // 5. write only the touched top-level sections
    let revision = save_sections_to_disk(config_path, &new_cfg, &touched).await?;

    Ok(PatchConfigResponse {
        revision,
        restart_required: class.restart_required,
        changed: class.changed,
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
    // `access`) would leak `server.api` (auth_header) and `network` (per-node
    // addresses). Mirror the PATCH contract, including the nested server
    // field-level allowlist.
    let mut table = toml::value::Table::new();
    for section in EDITABLE_SECTIONS {
        if let Some(value) = parsed_table.get(*section) {
            table.insert((*section).to_string(), value.clone());
        }
    }
    if let Some(server) = parsed_table.get("server") {
        if let Some(filtered) = filter_server_for_read(server) {
            table.insert("server".to_string(), filtered);
        }
    }

    let revision = compute_revision(&original);
    Ok((Toml::Table(table), revision))
}

/// Keep only [`EDITABLE_SERVER_FIELDS`] from a `[server]` table for GET.
fn filter_server_for_read(server: &Toml) -> Option<Toml> {
    let Some(src) = server.as_table() else {
        return None;
    };
    let mut out = toml::value::Table::new();
    for field in EDITABLE_SERVER_FIELDS {
        if let Some(value) = src.get(*field) {
            // Skip empty listeners arrays so absent-vs-empty stays consistent
            // with other optional sections.
            if *field == "listeners" {
                if let Some(arr) = value.as_array() {
                    if arr.is_empty() {
                        continue;
                    }
                }
            }
            out.insert((*field).to_string(), value.clone());
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Toml::Table(out))
    }
}

/// Reject any `[server]` patch keys outside [`EDITABLE_SERVER_FIELDS`].
fn validate_server_patch(server: &Toml) -> Result<(), ApiFailure> {
    let Some(table) = server.as_table() else {
        return Err(ApiFailure::new(
            hyper::StatusCode::BAD_REQUEST,
            "section_not_editable",
            "server patch must be a JSON object",
        ));
    };
    if table.is_empty() {
        return Err(ApiFailure::bad_request(
            "empty server patch: provide at least one editable field \
             (currently: listeners)",
        ));
    }
    for key in table.keys() {
        if !EDITABLE_SERVER_FIELDS.contains(&key.as_str()) {
            return Err(ApiFailure::new(
                hyper::StatusCode::BAD_REQUEST,
                "field_not_editable",
                format!(
                    "server.{} is not editable via the config API; allowed server fields: {}",
                    key,
                    EDITABLE_SERVER_FIELDS.join(", ")
                ),
            ));
        }
    }
    Ok(())
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
        // Full server (api/port) and network must not leak. Listeners-only server
        // is returned via the nested allowlist (covered in a dedicated test).
        let (path, _d) = temp_config(concat!(
            "[censorship]\ntls_domain = \"a\"\n",
            "[server]\nport = 443\n[server.api]\nauth_header = \"SECRET\"\n",
            "[network]\nipv4 = \"1.2.3.4\"\n",
            "[access.users]\nbob = \"deadbeef\"\n",
        ));
        let (value, _rev) = read_managed_config(&path).await.unwrap();
        let table = value.as_table().unwrap();
        assert!(table.contains_key("censorship"));
        assert!(!table.contains_key("server")); // no listeners → omit whole server
        assert!(!table.contains_key("network")); // no per-node identity leak
        assert!(!table.contains_key("access")); // no users/secrets
    }

    #[tokio::test]
    async fn read_managed_config_returns_server_listeners_only() {
        let (path, _d) = temp_config(concat!(
            "[censorship]\ntls_domain = \"a\"\n",
            "[server]\nport = 443\n",
            "[server.api]\nauth_header = \"SECRET\"\n",
            "[[server.listeners]]\nip = \"0.0.0.0\"\nport = 443\n",
        ));
        let (value, _rev) = read_managed_config(&path).await.unwrap();
        let table = value.as_table().unwrap();
        let server = table
            .get("server")
            .expect("server.listeners present")
            .as_table()
            .unwrap();
        assert!(server.contains_key("listeners"));
        assert!(!server.contains_key("api"));
        assert!(!server.contains_key("port"));
        let listeners = server["listeners"].as_array().unwrap();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0]["port"].as_integer(), Some(443));
    }

    #[tokio::test]
    async fn patch_rejects_forbidden_server_fields() {
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"server": {"port": 1}});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.code, "field_not_editable");
    }

    #[tokio::test]
    async fn patch_rejects_server_api_field() {
        let (path, _d) = temp_config("[censorship]\ntls_domain = \"a\"\n");
        let patch: Json = serde_json::json!({"server": {"api": {"enabled": false}}});
        let err = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(err.code, "field_not_editable");
    }

    #[tokio::test]
    async fn patch_server_listeners_preserves_api() {
        let (path, _d) = temp_config(concat!(
            "[censorship]\ntls_domain = \"a\"\n",
            "[server]\nport = 443\n",
            "[server.api]\nenabled = true\nauth_header = \"SECRET\"\n",
            "[[server.listeners]]\nip = \"0.0.0.0\"\nport = 443\n",
        ));
        let patch: Json = serde_json::json!({
            "server": {
                "listeners": [
                    {"ip": "0.0.0.0", "port": 8443, "client_mss": "92"}
                ]
            }
        });
        let resp = apply_patch_to_path(&path, &patch, None).await.unwrap();
        assert!(resp.changed.iter().any(|c| c == "server"));
        let written = tokio::fs::read_to_string(&path).await.unwrap();
        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert_eq!(
            parsed["server"]["api"]["auth_header"].as_str(),
            Some("SECRET"),
            "{written}"
        );
        let listeners = parsed["server"]["listeners"].as_array().unwrap();
        assert_eq!(listeners.len(), 1, "{written}");
        assert_eq!(listeners[0]["port"].as_integer(), Some(8443), "{written}");
        assert_eq!(listeners[0]["client_mss"].as_str(), Some("92"), "{written}");
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
        assert!(resp.changed.iter().any(|c| c == "general"));
    }
}
