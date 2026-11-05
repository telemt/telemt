use super::*;

#[tokio::test]
async fn carrier_method_api_defaults_and_patches_are_hot() {
    let (path, _directory) = temp_config("[web]\nenabled = false\n");
    let (value, _) = read_managed_config(&path).await.unwrap();
    assert_eq!(value["web"]["carrier_method"].as_str(), Some("post"));
    for token in ["put", "post"] {
        let active = ProxyConfig::load(&path).unwrap();
        let patch = serde_json::json!({"web": {"carrier_method": token}});
        let mut response = apply_patch_to_path(&path, &patch, None).await.unwrap();
        let desired = ProxyConfig::load(&path).unwrap();
        reconcile_runtime_effect(&mut response, &active, &desired).unwrap();
        assert!(!response.restart_required);
        assert!(response.runtime_reload_required);
        assert!(!response.process_restart_required);
        assert!(response.deferred_process_fields.is_empty());
        let (value, revision) = read_managed_config(&path).await.unwrap();
        assert_eq!(value["web"]["carrier_method"].as_str(), Some(token));
        assert_eq!(revision, response.revision);
        let written = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(written.contains(&format!("carrier_method = \"{token}\"")));
    }
}

#[tokio::test]
async fn carrier_method_api_rejects_invalid_values_without_writing() {
    let (path, _directory) = temp_config("[web]\ncarrier_method = \"put\"\n");
    let original = tokio::fs::read(&path).await.unwrap();
    let revision = crate::api::config_store::current_revision(&path)
        .await
        .unwrap();
    for value in [
        serde_json::json!("PUT"),
        serde_json::json!("patch"),
        serde_json::json!(true),
        serde_json::json!(42),
    ] {
        let patch = serde_json::json!({"web": {"carrier_method": value}});
        let error = apply_patch_to_path(&path, &patch, None).await.unwrap_err();
        assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(tokio::fs::read(&path).await.unwrap(), original);
        assert_eq!(
            crate::api::config_store::current_revision(&path)
                .await
                .unwrap(),
            revision
        );
    }
}

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
    assert_eq!(cens["tls_domain"].as_str(), Some("new"));
    assert_eq!(cens["fake_cert_len"].as_integer(), Some(100));
}

use std::path::PathBuf;

pub(super) fn temp_config(body: &str) -> (PathBuf, tempfile::TempDir) {
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
    let (path, _d) = temp_config("[censorship]\ntls_domain = \"a.com\"\n[server]\nport = 443\n");
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
        crate::api::config_store::current_revision(&path)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn read_managed_config_strips_access() {
    let (path, _d) = temp_config(
        "[censorship]\ntls_domain = \"a.com\"\n[access.users]\nbob = \"00000000000000000000000000000000\"\n",
    );
    let (value, revision) = read_managed_config(&path).await.unwrap();
    let table = value.as_table().unwrap();
    assert!(table.contains_key("censorship"));
    // Secrets never leave the box through this endpoint.
    assert!(!table.contains_key("access"));
    assert_eq!(
        revision,
        crate::api::config_store::current_revision(&path)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn read_managed_config_exposes_web_without_runtime_or_access_secrets() {
    let (path, _directory) = temp_config(concat!(
        "[web]\nenabled = false\ncarrier = \"https\"\n",
        "[web.debug]\nenabled = true\ndefault_window_secs = 180\n",
        "[access.users]\nbob = \"00000000000000000000000000000000\"\n",
    ));

    let (value, _revision) = read_managed_config(&path).await.unwrap();
    let table = value.as_table().unwrap();

    assert!(table.contains_key("web"));
    assert!(table["web"].get("debug").is_some());
    assert!(table["web"].get("runtime").is_none());
    assert!(!table.contains_key("access"));
}

#[tokio::test]
async fn patch_web_debug_is_hot_and_limits_are_process_deferred() {
    let (path, _directory) = temp_config("[web]\nenabled = false\n");
    let active = ProxyConfig::load(&path).unwrap();
    let debug_patch: Json = serde_json::json!({
        "web": {"debug": {
            "enabled": true,
            "sideband": true,
            "capture_headers": false
        }}
    });
    let mut debug = apply_patch_to_path(&path, &debug_patch, None)
        .await
        .unwrap();
    let desired = ProxyConfig::load(&path).unwrap();
    reconcile_runtime_effect(&mut debug, &active, &desired).unwrap();
    assert!(!debug.restart_required);
    assert!(debug.runtime_reload_required);
    assert!(!debug.process_restart_required);
    assert!(debug.changed.iter().any(|section| section == "web"));
    assert!(desired.web.debug.sideband);

    let limits_patch: Json = serde_json::json!({
        // Extra HTTP heads must fit alongside the default-on conveyor metadata reservation.
        "web": {"limits": {"max_http_connections": 2049, "memory_envelope_bytes": 1610612736u64}}
    });
    let limits = apply_patch_to_path(&path, &limits_patch, None)
        .await
        .unwrap();
    assert!(limits.process_restart_required);
    assert!(
        limits
            .deferred_process_fields
            .iter()
            .any(|field| field == "web.limits")
    );
}

#[tokio::test]
async fn patch_web_decoy_fasttrack_requires_only_process_restart() {
    let (path, _directory) = temp_config("[web]\nenabled = false\n");
    let active = ProxyConfig::load(&path).unwrap();
    let patch: Json = serde_json::json!({
        "web": {"decoy_fasttrack_mode": "shadow"}
    });

    let mut prepared = prepare_patch_to_path(&path, &patch, None).await.unwrap();
    reconcile_runtime_effect(&mut prepared.response, &active, &prepared.desired_config).unwrap();
    let response = prepared.response;

    assert!(response.restart_required);
    assert!(!response.runtime_reload_required);
    assert!(response.process_restart_required);
    assert_eq!(
        response.deferred_process_fields,
        vec!["web.decoy_fasttrack_mode".to_string()]
    );
}

#[tokio::test]
async fn invalid_web_patch_does_not_modify_the_source() {
    let (path, _directory) = temp_config("[web]\nenabled = false\n");
    let original = tokio::fs::read_to_string(&path).await.unwrap();
    let patch: Json = serde_json::json!({
        "web": {"debug": {"default_window_secs": 181, "max_window_secs": 180}}
    });

    let error = apply_patch_to_path(&path, &patch, None).await.unwrap_err();

    assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
    assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), original);
}

#[tokio::test]
async fn read_managed_config_returns_only_editable_sections() {
    // Server identity and network siblings must not leak. Listeners-only server
    // is returned via the nested allowlist (covered in a dedicated test).
    let (path, _d) = temp_config(concat!(
        "[censorship]\ntls_domain = \"a\"\n",
        "[server]\nport = 443\n[server.api]\nauth_header = \"SECRET\"\n",
        "[network]\nipv4 = true\n",
        "[access.users]\nbob = \"00000000000000000000000000000000\"\n",
    ));
    let (value, _rev) = read_managed_config(&path).await.unwrap();
    let table = value.as_table().unwrap();
    assert!(table.contains_key("censorship"));
    let server = table["server"].as_table().unwrap();
    assert!(server.contains_key("listeners"));
    assert!(!server.contains_key("api"));
    assert!(!server.contains_key("port"));
    assert_eq!(
        serde_json::to_value(&table["network"]).unwrap(),
        serde_json::json!({"dns_overrides": []})
    );
    assert!(!table.contains_key("access"));
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
async fn patch_writes_the_included_section_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let included = dir.path().join("censorship.toml");
    let root_body = "include = \"censorship.toml\"\n[server]\nport = 443\n";
    let included_body = "[censorship]\ntls_domain = \"old.example\"\n";
    tokio::fs::write(&root, root_body).await.unwrap();
    tokio::fs::write(&included, included_body).await.unwrap();
    let patch: Json = serde_json::json!({
        "censorship": {"tls_domain": "new.example"}
    });

    let response = apply_patch_to_path(&root, &patch, None).await.unwrap();

    assert_eq!(tokio::fs::read_to_string(&root).await.unwrap(), root_body);
    let written = tokio::fs::read_to_string(&included).await.unwrap();
    assert!(written.contains("tls_domain = \"new.example\""));
    assert_eq!(
        response.revision,
        crate::api::config_store::current_revision(&root)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn prepared_patch_rejects_external_edit_before_commit() {
    let (path, _directory) = temp_config("[censorship]\ntls_domain = \"old.example\"\n");
    let patch: Json = serde_json::json!({
        "censorship": {"tls_domain": "api.example"}
    });
    let prepared = prepare_patch_to_path(&path, &patch, None).await.unwrap();
    let external = "[censorship]\ntls_domain = \"external.example\"\n";
    tokio::fs::write(&path, external).await.unwrap();

    let error = write_atomic_if_unchanged(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, "revision_conflict");
    assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), external);
}

#[tokio::test]
async fn patch_rejects_multiple_source_owners_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let included = dir.path().join("censorship.toml");
    let root_body = concat!(
        "include = \"censorship.toml\"\n",
        "[general]\nprefer_ipv6 = false\n"
    );
    let included_body = "[censorship]\ntls_domain = \"old.example\"\n";
    tokio::fs::write(&root, root_body).await.unwrap();
    tokio::fs::write(&included, included_body).await.unwrap();
    let patch: Json = serde_json::json!({
        "general": {"prefer_ipv6": true},
        "censorship": {"tls_domain": "new.example"}
    });

    let error = apply_patch_to_path(&root, &patch, None).await.unwrap_err();

    assert_eq!(error.code, "config_patch_not_atomic");
    assert_eq!(tokio::fs::read_to_string(&root).await.unwrap(), root_body);
    assert_eq!(
        tokio::fs::read_to_string(&included).await.unwrap(),
        included_body
    );
}

#[tokio::test]
async fn unavailable_reload_coordinator_is_detected_before_config_write() {
    let (path, _dir) = temp_config("[censorship]\ntls_domain = \"old.example\"\n");
    let original = tokio::fs::read_to_string(&path).await.unwrap();
    let patch: Json = serde_json::json!({
        "censorship": {"tls_domain": "new.example"}
    });
    let prepared = prepare_patch_to_path(&path, &patch, None).await.unwrap();
    let (control, receiver) = crate::maestro::reload::ReloadControl::channel(1);
    drop(receiver);

    let error = match control
        .reserve(prepared.response.revision.clone(), ReloadRequest::default())
        .await
    {
        Ok(_) => panic!("closed reload coordinator must reject the reservation"),
        Err(error) => error,
    };

    assert_eq!(error, ReloadSubmitError::MaestroUnavailable);
    assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), original);
}

#[tokio::test]
async fn failed_config_write_releases_reload_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let (control, _receiver) = crate::maestro::reload::ReloadControl::channel(1);
    let reservation = control
        .reserve("candidate-revision".to_string(), ReloadRequest::default())
        .await
        .unwrap();

    let result = write_atomic(dir.path().to_path_buf(), "invalid target".to_string()).await;
    drop(reservation);

    assert!(result.is_err());
    assert_eq!(control.in_progress().await, None);
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
