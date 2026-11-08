use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::config::hot_reload::spawn_config_watcher;
use crate::maestro::{generation::test_runtime_generation, reload::ReloadControl};
use serde_json::json;
use std::time::Duration;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const API: &str = "[server.api] # keep API perimeter\nenabled=true\nlisten='127.0.0.1:9092'\nread_only=false\nauth_header='Bearer discovery-test' # keep secret\nwhitelist=['127.0.0.1/32']\ngray_action='api'\nrequest_body_limit_bytes=4096\nruntime_edge_events_capacity=64\nminimal_runtime_enabled=false\nruntime_edge_enabled=false\n";

fn patch(fields: Json) -> Json {
    json!({"server": {"api": fields}})
}

#[tokio::test]
async fn get_exposes_exactly_five_settings_and_defaults_without_api_secrets() {
    for source in ["", API] {
        let (path, _directory) = tests::temp_config(source);
        let (managed, _) = read_managed_config(&path).await.unwrap();
        let fields = managed["server"]["api"].as_table().unwrap();
        let config = ProxyConfig::load(&path).unwrap();
        let typed = toml::Value::try_from(&config.server.api).unwrap();
        assert_eq!(fields.len(), 5);
        for (key, value) in fields {
            assert!(EDITABLE_SERVER_API_FIELDS.contains(&key.as_str()));
            assert_eq!(*value, typed[key]);
        }
        assert!(!managed.to_string().contains("discovery-test"));
    }
}

#[tokio::test]
async fn every_forbidden_api_sibling_and_alias_is_rejected_even_when_null() {
    let (path, _directory) = tests::temp_config(API);
    let original = std::fs::read(&path).unwrap();
    let api = serde_json::to_value(ProxyConfig::default().server.api).unwrap();
    for (key, value) in api.as_object().unwrap() {
        if EDITABLE_SERVER_API_FIELDS.contains(&key.as_str()) {
            continue;
        }
        for value in [value.clone(), Json::Null] {
            let error = apply_patch_to_path(
                &path,
                &patch(json!({key: value, "runtime_edge_enabled": true})),
                None,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "field_not_editable", "{key}: {error:?}");
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }
    for body in [
        patch(json!({"typo": null, "runtime_edge_enabled": true})),
        json!({"server": {"admin_api": null, "api": {"runtime_edge_enabled": true}}}),
        json!({"server": {"port": null, "api": {"runtime_edge_enabled": true}}}),
    ] {
        assert_eq!(
            apply_patch_to_path(&path, &body, None)
                .await
                .unwrap_err()
                .code,
            "field_not_editable"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[tokio::test]
async fn observability_bounds_and_types_are_checked_before_persistence() {
    let (path, _directory) = tests::temp_config(API);
    for (key, good, bad) in [
        (
            "minimal_runtime_cache_ttl_ms",
            vec![json!(0), json!(60_000)],
            vec![json!(-1), json!(60_001), json!(1.5), json!(false)],
        ),
        (
            "runtime_edge_cache_ttl_ms",
            vec![json!(0), json!(60_000)],
            vec![json!(-1), json!(60_001), json!("0")],
        ),
        (
            "runtime_edge_top_n",
            vec![json!(1), json!(1000)],
            vec![json!(0), json!(1001), json!(-1), json!([])],
        ),
        (
            "minimal_runtime_enabled",
            vec![json!(true), json!(false)],
            vec![json!(0), json!("true")],
        ),
        (
            "runtime_edge_enabled",
            vec![json!(true), json!(false)],
            vec![json!(1), json!({})],
        ),
    ] {
        for value in good {
            apply_patch_to_path(&path, &patch(json!({key: value})), None)
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(ProxyConfig::load(&path).unwrap().server.api).unwrap()[key],
                value
            );
        }
        let original = std::fs::read(&path).unwrap();
        for value in bad {
            let error = apply_patch_to_path(&path, &patch(json!({key: value})), None)
                .await
                .unwrap_err();
            assert_eq!(
                error.status,
                hyper::StatusCode::BAD_REQUEST,
                "{key}: {error:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }
    let original = std::fs::read(&path).unwrap();
    for value in [
        json!(null),
        json!({}),
        json!([]),
        json!(false),
        json!({"runtime_edge_top_n": null}),
    ] {
        assert!(
            apply_patch_to_path(&path, &patch(value), None)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[tokio::test]
async fn sparse_observability_patch_preserves_perimeter_listeners_and_comments() {
    let source = format!("{API}\n[[server.listeners]]\nip='127.0.0.1'\nport=443\n");
    let (path, _directory) = tests::temp_config(&source);
    let before = ProxyConfig::load(&path).unwrap();
    let mut response = apply_patch_to_path(
        &path,
        &patch(json!({
            "minimal_runtime_enabled": true, "minimal_runtime_cache_ttl_ms": 0,
            "runtime_edge_enabled": true, "runtime_edge_cache_ttl_ms": 60_000,
            "runtime_edge_top_n": 1,
        })),
        None,
    )
    .await
    .unwrap();
    let after = ProxyConfig::load(&path).unwrap();
    reconcile_runtime_effect(&mut response, &before, &after).unwrap();
    assert!(response.restart_required);
    assert!(response.runtime_reload_required);
    assert!(!response.process_restart_required);
    assert!(response.deferred_process_fields.is_empty());
    assert_eq!(response.changed_paths.len(), 5);
    let mut restored = after.clone();
    for field in EDITABLE_SERVER_API_FIELDS {
        let mut api = serde_json::to_value(&restored.server.api).unwrap();
        api[*field] = serde_json::to_value(&before.server.api).unwrap()[*field].clone();
        restored.server.api = serde_json::from_value(api).unwrap();
    }
    assert_eq!(
        serde_json::to_value(restored).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    let written = std::fs::read_to_string(&path).unwrap();
    for line in source.lines().filter(|line| {
        !line.starts_with("minimal_runtime_enabled=") && !line.starts_with("runtime_edge_enabled=")
    }) {
        assert!(written.contains(line), "{line}: {written}");
    }
    let response = apply_patch_to_path(
        &path,
        &patch(json!({"runtime_edge_top_n": 2, "runtime_edge_enabled": null})),
        None,
    )
    .await
    .unwrap();
    assert_eq!(response.changed_paths, ["server.api.runtime_edge_top_n"]);
    assert!(
        ProxyConfig::load(&path)
            .unwrap()
            .server
            .api
            .runtime_edge_enabled
    );
}

#[tokio::test]
async fn precise_api_edits_preserve_inline_dotted_quoted_and_legacy_source_shapes() {
    for source in [
        "server = { api = { auth_header = 'secret', runtime_edge_top_n = 10 } }\n",
        "server.api.auth_header = 'secret'\nserver.api.runtime_edge_top_n = 10\n",
        "['server'.'api']\nauth_header='secret'\nruntime_edge_top_n=10 # retain\n",
        "[server.admin_api]\nauth_header='secret'\nruntime_edge_top_n=10 # retain\n",
    ] {
        let (path, _directory) = tests::temp_config(source);
        let before = ProxyConfig::load(&path).unwrap();
        apply_patch_to_path(
            &path,
            &patch(json!({"runtime_edge_top_n": 3, "minimal_runtime_cache_ttl_ms": 0})),
            None,
        )
        .await
        .unwrap();
        let after = ProxyConfig::load(&path).unwrap();
        assert_eq!(after.server.api.auth_header, before.server.api.auth_header);
        assert_eq!(after.server.api.runtime_edge_top_n, 3);
        assert_eq!(after.server.api.minimal_runtime_cache_ttl_ms, 0);
        let written = std::fs::read_to_string(&path).unwrap();
        if source.contains("admin_api") {
            assert!(written.contains("[server.admin_api]"));
            assert!(!written.contains("[server.api]"));
        }
        if source.contains("# retain") {
            assert!(written.contains("# retain"));
        }
    }
}

#[tokio::test]
async fn included_api_owner_is_updated_and_multiple_owners_are_rejected_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("config.toml");
    let included = directory.path().join("api.toml");
    let root_text = "include=\"api.toml\"\n[general]\nlog_level='normal'\n[server]\nport=443\n";
    std::fs::write(&root, root_text).unwrap();
    std::fs::write(&included, API).unwrap();
    apply_patch_to_path(&root, &patch(json!({"runtime_edge_top_n": 3})), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&root).unwrap(), root_text);
    assert_eq!(
        ProxyConfig::load(&root)
            .unwrap()
            .server
            .api
            .runtime_edge_top_n,
        3
    );
    for (root_text, included_text, body) in [
        (
            root_text.to_owned(),
            std::fs::read_to_string(&included).unwrap(),
            json!({"server":{"api":{"runtime_edge_top_n": 4}}, "general":{"log_level":"debug"}}),
        ),
        (
            "include=\"api.toml\"\nserver.api.minimal_runtime_enabled=false\n".to_owned(),
            "server.api.runtime_edge_enabled=false\n".to_owned(),
            patch(json!({"minimal_runtime_enabled":true,"runtime_edge_enabled":true})),
        ),
        (
            "include=\"api.toml\"\nserver.api.minimal_runtime_enabled=false\n".to_owned(),
            "server.api.runtime_edge_enabled=false\n".to_owned(),
            patch(json!({"runtime_edge_top_n":3})),
        ),
    ] {
        std::fs::write(&root, &root_text).unwrap();
        std::fs::write(&included, &included_text).unwrap();
        let error = apply_patch_to_path(&root, &body, None).await.unwrap_err();
        assert_eq!(error.code, "config_patch_not_atomic", "{error:?}");
        assert_eq!(std::fs::read_to_string(&root).unwrap(), root_text);
        assert_eq!(std::fs::read_to_string(&included).unwrap(), included_text);
    }
}

#[tokio::test]
async fn http_preview_watcher_and_reload_keep_diagnostics_pending_until_activation() {
    let mut fixture = Fixture::new(false);
    std::fs::write(
        &fixture.shared.config_path,
        format!("[general]\nlog_level='normal'\n{API}"),
    )
    .unwrap();
    let config = Arc::new(ProxyConfig::load(&fixture.shared.config_path).unwrap());
    let (control, mut commands) = ReloadControl::channel(1);
    Arc::get_mut(&mut fixture.shared).unwrap().reload_control = control;
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let (activation, activated) = watch::channel(false);
    let (mut receiver, _log_receiver, watcher) = spawn_config_watcher(
        fixture.shared.config_path.clone(),
        config.clone(),
        None,
        None,
        cancellation.clone(),
        None,
        Some(activated),
        Some(fixture.shared.mutation_lock.clone()),
        None,
    );
    let mut runtime = test_runtime_generation(1, (*config).clone());
    Arc::get_mut(&mut runtime).unwrap().config_rx = receiver.clone();
    fixture.shared.active_runtime.store(runtime);
    let task = tokio::spawn(watcher);
    let body = json!({"general": {"log_level": "debug"}, "server": {"api": {
        "minimal_runtime_enabled":true, "runtime_edge_enabled":true,
        "minimal_runtime_cache_ttl_ms":0, "runtime_edge_cache_ttl_ms":0, "runtime_edge_top_n":1,
    }}});
    let original = std::fs::read(&fixture.shared.config_path).unwrap();
    let preview = fixture
        .request_body("POST", "/v1/config/validate", true, Some(&body), &[])
        .await;
    assert_eq!(preview.0, 200, "{}", preview.2);
    let data = &preview.2["data"];
    assert_eq!(data["apply"]["watcher_paths"], json!(["general.log_level"]));
    assert_eq!(
        data["apply"]["generation_paths"].as_array().unwrap().len(),
        5
    );
    assert_eq!(data["apply"]["process_restart_paths"], json!([]));
    assert_eq!(
        std::fs::read(&fixture.shared.config_path).unwrap(),
        original
    );
    assert_eq!(
        fixture
            .request_body("PATCH", "/v1/config", false, Some(&body), &[])
            .await
            .0,
        401
    );
    let response = fixture
        .request_body(
            "PATCH",
            "/v1/config",
            true,
            Some(&body),
            &[
                ("If-Match", data["base_revision"].as_str().unwrap()),
                (
                    "If-Runtime-Match",
                    data["runtime"]["runtime_match"].as_str().unwrap(),
                ),
            ],
        )
        .await;
    assert_eq!(response.0, 200, "{}", response.2);
    assert_eq!(response.2["data"]["runtime_reload_required"], true);
    assert_eq!(response.2["data"]["process_restart_required"], false);
    activation.send_replace(true);
    tokio::time::timeout(
        Duration::from_secs(5),
        receiver.wait_for(|cfg| cfg.general.log_level == crate::config::LogLevel::Debug),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(receiver.borrow().server.api, config.server.api);
    assert_diagnostics(&fixture, false).await;

    // Even an unchanged desired patch can explicitly request the pending reload.
    let accepted = fixture
        .request_body(
            "PATCH",
            "/v1/config?reload=instant",
            true,
            Some(&patch(body["server"]["api"].clone())),
            &[],
        )
        .await;
    assert_eq!(accepted.0, 202, "{}", accepted.2);
    let command = tokio::time::timeout(Duration::from_secs(5), commands.recv())
        .await
        .unwrap()
        .unwrap();
    assert_diagnostics(&fixture, false).await;
    let resolved = resolve_reload_config(&config, &command.config).unwrap();
    assert_eq!(
        resolved.effective.server.api.listen,
        config.server.api.listen
    );
    assert_eq!(
        resolved.effective.server.api.runtime_edge_events_capacity,
        64
    );
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(2, resolved.effective));
    assert_diagnostics(&fixture, true).await;
    assert_eq!(
        fixture
            .request("GET", "/v1/runtime/events/recent", true)
            .await
            .2["data"]["data"]["capacity"],
        64
    );
    fixture
        .shared
        .reload_control
        .fail(command.reload_id, "fixture completed")
        .await;
    let disabled = patch(json!({"minimal_runtime_enabled": false, "runtime_edge_enabled": false}));
    let accepted = fixture
        .request_body(
            "PATCH",
            "/v1/config?reload=drain&timeout_secs=30",
            true,
            Some(&disabled),
            &[],
        )
        .await;
    assert_eq!(accepted.0, 202, "{}", accepted.2);
    assert_diagnostics(&fixture, true).await;
    let command = commands.recv().await.unwrap();
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(3, (*command.config).clone()));
    assert_diagnostics(&fixture, false).await;
    assert_eq!(fixture.request("GET", "/v1/health", true).await.0, 200);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

async fn assert_diagnostics(fixture: &Fixture, enabled: bool) {
    for path in [
        "/v1/stats/minimal/all",
        "/v1/runtime/connections/summary",
        "/v1/runtime/events/recent",
    ] {
        let (status, _, body) = fixture.request("GET", path, true).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["data"]["enabled"], enabled, "{body}");
        if !enabled {
            assert_eq!(body["data"]["reason"], "feature_disabled");
        }
    }
    let (_, _, caps) = fixture.request("GET", "/v1/capabilities", true).await;
    for path in ["/v1/stats/minimal/all", "/v1/runtime/connections/summary"] {
        let operation = caps["data"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["path"] == path)
            .unwrap();
        assert_eq!(operation["enabled"], enabled);
    }
}

#[tokio::test]
async fn observability_patch_obeys_read_only_and_source_revision_fences() {
    let fixture = Fixture::new(false);
    let body = patch(json!({"runtime_edge_enabled": true}));
    let original = std::fs::read(&fixture.shared.config_path).unwrap();
    let preview = fixture
        .request_body("POST", "/v1/config/validate", true, Some(&body), &[])
        .await;
    assert_eq!(preview.0, 200, "{}", preview.2);
    let rejected = fixture
        .request_body("PATCH", "/v1/config", true, Some(&body), &[])
        .await;
    assert_eq!(rejected.0, 403);
    assert_eq!(rejected.2["error"]["code"], "read_only");
    assert_eq!(
        std::fs::read(&fixture.shared.config_path).unwrap(),
        original
    );
    let prepared = prepare_patch_to_path(&fixture.shared.config_path, &body, None)
        .await
        .unwrap();
    let external = "# external source change\n";
    std::fs::write(&fixture.shared.config_path, external).unwrap();
    let conflict = write_atomic_if_unchanged(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
    )
    .await
    .unwrap_err();
    assert_eq!(conflict.code, "revision_conflict");
    assert_eq!(
        std::fs::read_to_string(&fixture.shared.config_path).unwrap(),
        external
    );
}

#[tokio::test]
async fn listeners_and_observability_in_one_owner_preserve_each_other() {
    let (path, _directory) = tests::temp_config(API);
    apply_patch_to_path(
        &path,
        &json!({"server": {
            "listeners": [{"ip": "127.0.0.1", "port": 8443}],
            "api": {"runtime_edge_enabled": true},
        }}),
        None,
    )
    .await
    .unwrap();
    let config = ProxyConfig::load(&path).unwrap();
    assert_eq!(config.server.listeners.len(), 1);
    assert_eq!(config.server.listeners[0].port, Some(8443));
    assert!(config.server.api.runtime_edge_enabled);
    assert_eq!(config.server.api.auth_header, "Bearer discovery-test");
}
