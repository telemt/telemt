use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::maestro::generation::test_runtime_generation;
use serde_json::json;
use tokio::sync::watch;

async fn fixture(source: &str, read_only: bool) -> (Fixture, watch::Sender<Arc<ProxyConfig>>) {
    let fixture = Fixture::new(false);
    std::fs::write(&fixture.shared.config_path, format!("{source}\n[server.api]\nenabled = true\nread_only = {read_only}\nauth_header = \"Bearer discovery-test\"\n")).unwrap();
    let config = ProxyConfig::load_prepared(fixture.shared.config_path.clone())
        .await
        .unwrap()
        .config;
    let mut runtime = test_runtime_generation(1, config);
    let (sender, receiver) = watch::channel(runtime.config());
    Arc::get_mut(&mut runtime).unwrap().config_rx = receiver;
    fixture.shared.active_runtime.store(runtime);
    (fixture, sender)
}

fn files(fixture: &Fixture) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    std::fs::read_dir(fixture.shared.config_path.parent().unwrap())
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

async fn preview(fixture: &Fixture, patch: Json) -> preflight::ValidationResponse {
    validate_config(patch, None, None, None, &fixture.shared)
        .await
        .unwrap()
}

#[tokio::test]
async fn unknown_nested_patch_key_is_rejected_before_serde_discards_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let source = "[general]\nconfig_strict = true\n";
    std::fs::write(&path, source).unwrap();
    let result = apply_patch_to_path(
        &path,
        &serde_json::json!({"general": {"me_keepalive_enabld": true}}),
        None,
    )
    .await;
    assert!(
        result.is_err(),
        "unknown nested key must not become a successful write"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
}

#[tokio::test]
async fn preflight_http_auth_read_only_queries_and_no_side_effects() {
    let (fixture, _sender) = fixture("", true).await;
    let before = files(&fixture);
    let active = fixture.shared.active_runtime.load_full();
    let patch = json!({"general":{"log_level":"debug"}});
    for (method, path, authorized, status, code) in [
        ("POST", "/v1/config/validate", false, 401, "unauthorized"),
        (
            "GET",
            "/v1/config/validate",
            true,
            405,
            "method_not_allowed",
        ),
        (
            "POST",
            "/v1/config/validate?timeout_secs=1",
            true,
            400,
            "bad_request",
        ),
        (
            "POST",
            "/v1/config/validate?reload=drain",
            true,
            400,
            "bad_request",
        ),
        ("PATCH", "/v1/config", true, 403, "read_only"),
    ] {
        let response = fixture
            .request_body(method, path, authorized, Some(&patch), &[])
            .await;
        assert_eq!(response.0, status, "{}", response.2);
        assert_eq!(response.2["error"]["code"], code);
        if status == 405 {
            assert_eq!(response.1, "POST");
        }
    }
    let response = fixture
        .request_body(
            "POST",
            "/v1/config/validate?reload=drain&timeout_secs=10",
            true,
            Some(&patch),
            &[],
        )
        .await;
    assert_eq!(response.0, 200, "{}", response.2);
    assert_eq!(response.2["data"]["valid"], true);
    assert_eq!(response.2["data"]["reload"]["mode"], "drain");
    assert_eq!(response.2["revision"], response.2["data"]["base_revision"]);
    assert_eq!(files(&fixture), before);
    assert!(Arc::ptr_eq(
        &fixture.shared.active_runtime.load_full(),
        &active
    ));
    assert!(Arc::ptr_eq(
        &fixture.shared.active_runtime.load().config(),
        &active.config()
    ));
    assert!(fixture.shared.reload_control.in_progress().await.is_none());
    assert!(fixture.shared.reload_control.status(1).await.is_none());
    assert!(fixture.shared.runtime_events.snapshot(64).events.is_empty());
    let denied = Fixture::new(true);
    assert_eq!(
        denied
            .request_body("POST", "/v1/config/validate", true, Some(&patch), &[])
            .await
            .0,
        403
    );
    let caps = fixture.request("GET", "/v1/capabilities", true).await.2;
    let operation = caps["data"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["id"] == "config_validate")
        .unwrap();
    assert_eq!(operation["mutable"], false);
    assert_eq!(operation["available"], true);
    assert!(operation["mutation_blocked_reason"].is_null());
}

#[tokio::test]
async fn preflight_commit_parity_for_hot_generation_and_process_changes() {
    let (fixture, _sender) = fixture("", false).await;
    let active = fixture.shared.active_runtime.load().config();
    let patch = json!({"general":{
        "log_level":"debug", "me_keepalive_interval_secs":active.general.me_keepalive_interval_secs + 5,
        "disable_colors":!active.general.disable_colors
    }});
    let before = files(&fixture);
    let response = preview(&fixture, patch.clone()).await;
    assert_eq!(response.apply.watcher_paths, ["general.log_level"]);
    assert_eq!(
        response.apply.generation_paths,
        ["general.me_keepalive_interval_secs"]
    );
    assert_eq!(
        response.apply.process_restart_paths,
        ["general.disable_colors"]
    );
    assert_eq!(
        response.apply.deferred_process_fields,
        ["general.disable_colors"]
    );
    assert_eq!(files(&fixture), before);
    let committed = fixture
        .request_body(
            "PATCH",
            "/v1/config",
            true,
            Some(&patch),
            &[
                ("If-Match", &response.base_revision),
                ("If-Runtime-Match", &response.runtime.runtime_match),
            ],
        )
        .await;
    assert_eq!(committed.0, 200, "{}", committed.2);
    let data = &committed.2["data"];
    assert_eq!(data["revision"], response.candidate_revision);
    assert_eq!(data["changed_paths"], json!(response.changed_paths));
    assert_eq!(data["restart_required"], response.apply.restart_required);
    assert_eq!(
        data["runtime_reload_required"],
        response.apply.runtime_reload_required
    );
    assert_eq!(
        data["process_restart_required"],
        response.apply.process_restart_required
    );
    assert_eq!(data["changed"], json!(["general"]));
    assert_eq!(
        data["deferred_process_fields"],
        json!(response.apply.deferred_process_fields)
    );
    assert!(Arc::ptr_eq(
        &fixture.shared.active_runtime.load().config(),
        &active
    ));
}

#[tokio::test]
async fn preflight_stale_source_and_runtime_tokens_reject_without_writes() {
    let (fixture, sender) = fixture("", false).await;
    let patch = json!({"general":{"log_level":"debug"}});
    let response = preview(&fixture, patch.clone()).await;
    let before = files(&fixture);
    for method in ["POST", "PATCH"] {
        let path = if method == "POST" {
            "/v1/config/validate"
        } else {
            "/v1/config"
        };
        let rejected = fixture
            .request_body(method, path, true, Some(&patch), &[("If-Match", "stale")])
            .await;
        assert_eq!(rejected.0, 409);
        assert_eq!(rejected.2["error"]["code"], "revision_conflict");
        let rejected = fixture
            .request_body(
                method,
                path,
                true,
                Some(&patch),
                &[("If-Runtime-Match", "invalid token")],
            )
            .await;
        assert_eq!(rejected.0, 400);
    }
    // A -> B -> A retains the same generation and source bytes, but not its epoch.
    let original = (*sender.borrow()).as_ref().clone();
    let mut hot = original.clone();
    hot.general.log_level = crate::config::LogLevel::Verbose;
    sender.send(Arc::new(hot.with_publication_epoch())).unwrap();
    sender
        .send(Arc::new(original.with_publication_epoch()))
        .unwrap();
    for method in ["POST", "PATCH"] {
        let path = if method == "POST" {
            "/v1/config/validate"
        } else {
            "/v1/config"
        };
        let rejected = fixture
            .request_body(
                method,
                path,
                true,
                Some(&patch),
                &[
                    ("If-Match", &response.base_revision),
                    ("If-Runtime-Match", &response.runtime.runtime_match),
                ],
            )
            .await;
        assert_eq!(rejected.0, 409, "{}", rejected.2);
        assert_eq!(rejected.2["error"]["code"], "runtime_conflict");
    }
    let fresh = preview(&fixture, patch.clone()).await;
    assert_eq!(
        fresh.runtime.active_generation,
        response.runtime.active_generation
    );
    assert!(fresh.runtime.config_epoch > response.runtime.config_epoch);
    let config = fixture.shared.active_runtime.load().config();
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(2, (*config).clone()));
    assert_eq!(
        validate_config(
            patch,
            None,
            Some(fresh.runtime.runtime_match),
            None,
            &fixture.shared
        )
        .await
        .unwrap_err()
        .code,
        "runtime_conflict"
    );
    assert_eq!(files(&fixture), before);
}

#[tokio::test]
async fn unknown_nested_and_variant_fields_never_silently_disappear() {
    let (fixture, _sender) = fixture("[general]\nconfig_strict = false\n", false).await;
    let before = files(&fixture);
    for (patch, expected) in [
        (
            json!({"general":{"me_keepalive_enabld":null,"log_level":"debug"}}),
            "general.me_keepalive_enabld",
        ),
        (
            json!({"web":{"limits":{"max_boddy_bytes":123}}}),
            "web.limits.max_boddy_bytes",
        ),
        (
            json!({"web":{"vhosts":[{"profiles":[{"unknwon":true}]}]}}),
            "web.vhosts[0].profiles[0].unknwon",
        ),
        (
            json!({"upstreams":[{"type":"direct","password":"synthetic-credential"}]}),
            "upstreams[0].password",
        ),
        (
            json!({"web":{"vhosts":[{"decoy":{"mode":"http_upstream","directory":"synthetic-credential"}}]}}),
            "web.vhosts[0].decoy.directory",
        ),
    ] {
        for method in ["POST", "PATCH"] {
            let path = if method == "POST" {
                "/v1/config/validate"
            } else {
                "/v1/config"
            };
            let response = fixture
                .request_body(method, path, true, Some(&patch), &[])
                .await;
            assert_eq!(response.0, 400, "{}", response.2);
            assert_eq!(response.2["error"]["details"][0]["path"], expected);
            assert!(!response.2.to_string().contains("synthetic-credential"));
        }
        assert_eq!(files(&fixture), before);
    }
}

#[tokio::test]
async fn preflight_aliases_open_maps_nulls_and_credentials_are_redacted() {
    let (fixture, _sender) = fixture("", false).await;
    let patch = json!({
        "upstreams":[{"type":"direct","force_bind":"lo"}],
        "general":{"log_level":null},
        "dc_overrides":{"2":["149.154.167.50:443"]},
        "censorship":{"exclusive_mask":{"private-sentinel.example":"private-origin.example:443"}}
    });
    let response = preview(&fixture, patch.clone()).await;
    let encoded = serde_json::to_value(&response).unwrap();
    assert!(
        encoded["normalization_effects"]
            .as_array()
            .unwrap()
            .contains(&json!({"path":"upstreams[0].bindtodevice","code":"alias_canonicalized"}))
    );
    assert!(
        encoded["normalization_effects"]
            .as_array()
            .unwrap()
            .contains(&json!({"path":"general.log_level","code":"null_ignored"}))
    );
    assert!(
        response
            .changed_paths
            .contains(&"dc_overrides.{dc}[0]".into())
    );
    assert!(
        response
            .changed_paths
            .contains(&"censorship.exclusive_mask.{hostname}".into())
    );
    assert!(!encoded.to_string().contains("private-"));
    let credential_change = preview(
        &fixture,
        json!({"upstreams":[{
            "type":"socks5", "address":"127.0.0.1:1080", "password":"synthetic-diff-credential"
        }]}),
    )
    .await;
    assert!(
        credential_change
            .changed_paths
            .contains(&"upstreams[0].password".into())
    );
    assert!(
        !serde_json::to_string(&credential_change)
            .unwrap()
            .contains("synthetic-diff-credential")
    );
    // The strict-key facade must leave open user maps to their owner API.
    let open_users: Toml =
        toml::from_str("[access.users]\n'arbitrary.user-name' = 'synthetic-user-secret'\n")
            .unwrap();
    assert!(ProxyConfig::unknown_source_paths(&open_users).is_empty());
    let committed = patch_config(
        patch,
        Some(response.base_revision),
        None,
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    assert_eq!(committed.revision, response.candidate_revision);
    assert!(
        std::fs::read_to_string(&fixture.shared.config_path)
            .unwrap()
            .contains("bindtodevice")
    );
    for patch in [
        json!({"general":{"me_writer_pick_mode":"synthetic-credential"}}),
        json!({"upstreams":[{"type":"shadowsocks","url":"ss://synthetic-credential@private-sentinel.example"}]}),
        json!({"web":{"carrier_method":"synthetic-credential"}}),
    ] {
        let error = validate_config(patch, None, None, None, &fixture.shared)
            .await
            .unwrap_err();
        let public = format!(
            "{} {}",
            error.message,
            serde_json::to_string(&error.details).unwrap()
        );
        assert!(!public.contains("synthetic-credential"), "{public}");
        assert!(!public.contains("private-sentinel"));
        assert!(!error.details.is_empty());
    }
}

#[tokio::test]
async fn preflight_multi_source_conflict_and_conditional_web_capacity() {
    let (fixture, _sender) = fixture("", false).await;
    let path = &fixture.shared.config_path;
    let old = std::fs::read_to_string(path).unwrap();
    std::fs::write(path, format!("include = \"censorship.toml\"\n{old}")).unwrap();
    std::fs::write(
        path.parent().unwrap().join("censorship.toml"),
        "[censorship]\ntls_domain = \"old.example\"\n",
    )
    .unwrap();
    let before = files(&fixture);
    let patch = json!({"general":{"log_level":"debug"},"censorship":{"tls_domain":"new.example"}});
    for commit in [false, true] {
        let error = if commit {
            patch_config(patch.clone(), None, None, None, &fixture.shared)
                .await
                .err()
                .unwrap()
        } else {
            validate_config(patch.clone(), None, None, None, &fixture.shared)
                .await
                .unwrap_err()
        };
        assert_eq!(error.code, "config_patch_not_atomic");
        assert_eq!(error.details[0].code, "source_ownership_conflict");
        assert_eq!(files(&fixture), before);
    }
    let (fixture, _sender) =
        self::fixture("[web.limits]\ndebug_bytes_global = 4096\n", false).await;
    let hot = preview(&fixture, json!({"web":{"debug":{"body_prefix_bytes":128}}})).await;
    assert!(
        hot.apply
            .watcher_paths
            .contains(&"web.debug.body_prefix_bytes".into())
    );
    let deferred = preview(
        &fixture,
        json!({"web":{"limits":{"debug_bytes_global":8192},"debug":{"body_prefix_bytes":6144}}}),
    )
    .await;
    assert!(
        !deferred
            .apply
            .watcher_paths
            .contains(&"web.debug.body_prefix_bytes".into())
    );
    assert!(
        deferred
            .apply
            .process_restart_paths
            .contains(&"web.debug.body_prefix_bytes".into())
    );
    assert!(
        deferred
            .apply
            .deferred_process_fields
            .contains(&"web.debug".into())
    );
    let result = patch_config(
        json!({"web":{"limits":{"debug_bytes_global":8192},"debug":{"body_prefix_bytes":6144}}}),
        Some(deferred.base_revision),
        None,
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    assert_eq!(
        result.deferred_process_fields,
        deferred.apply.deferred_process_fields
    );
}

#[tokio::test]
async fn preflight_runtime_fence_rejects_at_atomic_persistence_and_removes_staging_file() {
    let (fixture, sender) = fixture("", false).await;
    let fence = preflight::RuntimeFence::capture(&fixture.shared, None).unwrap();
    let patch = json!({"general":{"log_level":"debug"}});
    let prepared = prepare_patch_to_path(&fixture.shared.config_path, &patch, None)
        .await
        .unwrap();
    let before = std::fs::read(&fixture.shared.config_path).unwrap();
    let mut changed = (*fence.config).clone();
    changed.general.log_level = crate::config::LogLevel::Verbose;
    sender
        .send(Arc::new(changed.with_publication_epoch()))
        .unwrap();
    let error = crate::api::config_store::write_atomic_with_runtime_check(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
        Some(fence.commit_check()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "runtime_conflict");
    assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
    assert!(
        files(&fixture)
            .keys()
            .all(|path| path.ends_with("config.toml") || path.ends_with("config.toml.lock"))
    );
}

#[tokio::test]
async fn preflight_concurrency_budget_does_not_block_or_reserve_reload() {
    let (fixture, _sender) = fixture("", false).await;
    let permits = fixture
        .shared
        .config_preflight_slots
        .clone()
        .acquire_many_owned(2)
        .await
        .unwrap();
    let response = fixture
        .request_body(
            "POST",
            "/v1/config/validate",
            true,
            Some(&json!({"general":{"log_level":"debug"}})),
            &[],
        )
        .await;
    assert_eq!(response.0, 429);
    assert_eq!(response.2["error"]["code"], "config_preflight_busy");
    drop(permits);
    let _ = preview(&fixture, json!({"general":{"log_level":"debug"}})).await;
    assert!(fixture.shared.reload_control.in_progress().await.is_none());
}

fn abandoned_preflight_retains_budget(timeout: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (fixture, _sender) = fixture("", false).await;
        let before = files(&fixture);
        let active = fixture.shared.active_runtime.load().config();
        let (release, wait) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        });
        ready.await.unwrap();
        tokio::time::pause();
        let shared = fixture.shared.clone();
        let task = tokio::spawn(async move {
            validate_config(
                json!({"general":{"log_level":"debug"}}),
                None,
                None,
                Some(ReloadRequest::default()),
                &shared,
            )
            .await
        });
        // The only blocking thread is occupied; candidate parsing is queued.
        while fixture.shared.config_preflight_slots.available_permits() == 2 {
            tokio::task::yield_now().await;
        }
        if timeout {
            tokio::time::advance(std::time::Duration::from_secs(31)).await;
            let error = task.await.unwrap().unwrap_err();
            assert_eq!(error.status, hyper::StatusCode::GATEWAY_TIMEOUT);
            assert_eq!(error.code, "config_preflight_timeout");
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(fixture.shared.config_preflight_slots.available_permits(), 1);
        tokio::time::resume();
        release.send(()).unwrap();
        blocker.await.unwrap();
        let _permits = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture
                .shared
                .config_preflight_slots
                .clone()
                .acquire_many_owned(2),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(files(&fixture), before);
        assert!(Arc::ptr_eq(
            &fixture.shared.active_runtime.load().config(),
            &active
        ));
        assert!(fixture.shared.reload_control.status(1).await.is_none());
        assert!(fixture.shared.runtime_events.snapshot(64).events.is_empty());
    });
}

#[test]
fn preflight_cancellation_retains_budget_until_abandoned_worker_finishes() {
    abandoned_preflight_retains_budget(false);
}

#[test]
fn preflight_timeout_retains_budget_until_abandoned_worker_finishes() {
    abandoned_preflight_retains_budget(true);
}

#[tokio::test]
async fn preflight_dns_failure_and_normalization_share_commit_preparation() {
    let source = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[web]
enabled = true
[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#;
    let (fixture, _sender) = fixture(source, false).await;
    let mut vhosts =
        serde_json::to_value(&fixture.shared.active_runtime.load().config().web.vhosts).unwrap();
    vhosts[0]["host"] = json!("MixedCase.Example.COM");
    let patch = json!({"web":{"vhosts":vhosts}});
    let normalized = preview(&fixture, patch.clone()).await;
    assert!(
        normalized
            .normalization_effects
            .iter()
            .any(|effect| effect.path == "web.vhosts[0].host" && effect.code == "normalized")
    );
    let committed = patch_config(
        patch,
        Some(normalized.base_revision),
        None,
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    assert_eq!(committed.revision, normalized.candidate_revision);
    let before = files(&fixture);
    // The reserved .invalid TLD cannot yield a usable decoy origin. DNS itself
    // remains bounded by the configured one-second preparation timeout.
    vhosts[0]["decoy"] = json!({"mode":"http_upstream", "upstream":"http://preflight-unresolvable.invalid:18081", "resolve":"startup"});
    let patch = json!({"web":{"vhosts":vhosts,"timeouts":{"decoy_resolve_secs":1}}});
    for commit in [false, true] {
        let error = if commit {
            patch_config(patch.clone(), None, None, None, &fixture.shared)
                .await
                .err()
                .unwrap()
        } else {
            validate_config(patch.clone(), None, None, None, &fixture.shared)
                .await
                .unwrap_err()
        };
        assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(error.details[0].code, "preparation_failed");
        assert!(!error.message.contains("preflight-unresolvable"));
        assert_eq!(files(&fixture), before);
    }
}

#[tokio::test]
async fn preflight_invalid_current_source_preserves_status_and_hides_source_excerpt() {
    let (fixture, _sender) = fixture("", false).await;
    std::fs::write(
        &fixture.shared.config_path,
        "[general]\nme_writer_pick_mode = 'synthetic-source-credential'\n",
    )
    .unwrap();
    let before = files(&fixture);
    for method in ["POST", "PATCH"] {
        let path = if method == "POST" {
            "/v1/config/validate"
        } else {
            "/v1/config"
        };
        let response = fixture
            .request_body(
                method,
                path,
                true,
                Some(&json!({"general":{"log_level":"debug"}})),
                &[],
            )
            .await;
        assert_eq!(response.0, 500);
        assert_eq!(response.2["error"]["code"], "internal_error");
        assert_eq!(
            response.2["error"]["details"][0]["code"],
            "source_load_failed"
        );
        assert!(
            !response
                .2
                .to_string()
                .contains("synthetic-source-credential")
        );
        assert_eq!(files(&fixture), before);
    }
}
