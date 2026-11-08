use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::config::observation::WatchObservation;
use crate::maestro::generation::test_runtime_generation;
use crate::maestro::reload::{ReloadControl, ReloadPhase, ReloadRequest};
use serde_json::json;
use tokio::sync::watch;

#[path = "bounds_tests.rs"]
mod bounds;

#[path = "preparation_tests.rs"]
mod preparation;

fn source(fixture: &Fixture, text: &str, read_only: bool) {
    std::fs::write(&fixture.shared.config_path, format!("{text}\n[server.api]\nenabled = true\nread_only = {read_only}\nauth_header = \"Bearer discovery-test\"\n")).unwrap();
}

async fn fixture(text: &str, read_only: bool) -> (Fixture, watch::Sender<Arc<ProxyConfig>>) {
    let fixture = Fixture::new(false);
    source(&fixture, text, read_only);
    let mut config = ProxyConfig::load_prepared(fixture.shared.config_path.clone())
        .await
        .unwrap()
        .config;
    config.watcher_observation = Some(Arc::new(WatchObservation::default()));
    let mut runtime = test_runtime_generation(1, config);
    let (sender, receiver) = watch::channel(runtime.config());
    Arc::get_mut(&mut runtime).unwrap().config_rx = receiver;
    fixture.shared.active_runtime.store(runtime);
    (fixture, sender)
}

async fn inspect(fixture: &Fixture, query: Option<&str>) -> Json {
    serde_json::to_value(state(&fixture.shared, query).await.unwrap()).unwrap()
}

fn field<'a>(data: &'a Json, projection: &str, path: &str) -> &'a Json {
    data[projection]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["path"] == path)
        .unwrap_or_else(|| panic!("missing {projection} field {path}"))
}

#[tokio::test]
async fn state_http_auth_scope_queries_read_only_and_no_mutation() {
    let (fixture, _sender) = fixture("", true).await;
    let bytes = std::fs::read(&fixture.shared.config_path).unwrap();
    let active = fixture.shared.active_runtime.load_full();
    for (method, path, authorized, expected) in [
        ("GET", "/v1/config/state", false, 401),
        ("POST", "/v1/config/state", true, 405),
        (
            "GET",
            "/v1/config/state?sections=general,general",
            true,
            400,
        ),
        ("GET", "/v1/config/state?sections=", true, 400),
        ("GET", "/v1/config/state?sections=unknown", true, 400),
        (
            "GET",
            "/v1/config/state?sections=general&sections=web",
            true,
            400,
        ),
        ("GET", "/v1/config/state?debug=true", true, 400),
    ] {
        let (status, allow, _) = fixture.request(method, path, authorized).await;
        assert_eq!(status, expected, "{method} {path}");
        if status == 405 {
            assert_eq!(allow, "GET");
        }
    }
    assert!(sections(Some(&format!("sections={}", "a".repeat(256)))).is_err());
    let (status, _, response) = fixture
        .request("GET", "/v1/config/state?sections=general,access", true)
        .await;
    assert_eq!(status, 200, "{response}");
    let data = &response["data"];
    assert_eq!(response["revision"], data["desired_revision"]);
    assert_eq!(data["sections"], json!(["access", "general"]));
    assert_eq!(data["comparison"]["status"], "published_match");
    assert_eq!(data["runtime"]["active_generation"], 1);
    assert_eq!(data["runtime_sample_current"], true);
    assert_eq!(data["subsystem_convergence"], "unknown");
    assert!(
        data["effective"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| {
                let path = field["path"].as_str().unwrap();
                path.starts_with("general.") || path.starts_with("access.")
            })
    );
    assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), bytes);
    assert!(Arc::ptr_eq(
        &active,
        &fixture.shared.active_runtime.load_full()
    ));
    assert!(fixture.shared.reload_control.status(1).await.is_none());
    assert!(fixture.shared.runtime_events.snapshot(64).events.is_empty());
    let denied = Fixture::new(true);
    assert_eq!(denied.request("GET", "/v1/config/state", true).await.0, 403);
    let caps = fixture.request("GET", "/v1/capabilities", true).await.2;
    let operation = caps["data"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["id"] == "config_state")
        .unwrap();
    assert_eq!(operation["available"], true);
    assert_eq!(operation["mutable"], false);
}

#[tokio::test]
async fn invalid_or_unreadable_desired_preserves_effective_and_hides_errors() {
    let (fixture, _sender) = fixture("[general]\nlog_level='debug'", true).await;
    let epoch = fixture
        .shared
        .active_runtime
        .load()
        .config()
        .runtime_config_epoch;
    for invalid in [
        "[general]\nme_writer_pick_mode='synthetic-private-value'",
        "[broken synthetic-private-value",
    ] {
        std::fs::write(&fixture.shared.config_path, invalid).unwrap();
        let (status, _, response) = fixture.request("GET", "/v1/config/state", true).await;
        assert_eq!(status, 200);
        let data = &response["data"];
        assert_eq!(data["desired_status"], "invalid");
        assert!(response["revision"].is_string());
        assert_eq!(data["desired_error"]["code"], "desired_config_invalid");
        assert_eq!(data["runtime"]["config_epoch"], epoch);
        assert_eq!(
            field(data, "effective", "general.log_level")["value"],
            "debug"
        );
        assert!(data["desired"].is_null());
        assert_eq!(data["comparison"]["status"], "unknown");
        assert!(!response.to_string().contains("synthetic-private-value"));
    }
    std::fs::remove_file(&fixture.shared.config_path).unwrap();
    let response = fixture.request("GET", "/v1/config/state", true).await.2;
    assert!(response["revision"].is_null());
    assert_eq!(response["data"]["desired_status"], "unreadable");
    assert!(!response["data"]["effective"].is_null());
    assert!(
        !response
            .to_string()
            .contains(fixture.shared.config_path.to_str().unwrap())
    );
}

#[tokio::test]
async fn secret_rotation_stays_pending_until_publication_and_never_claims_convergence() {
    const OLD: &str = "000102030405060708090a0b0c0d0e0f";
    const NEW: &str = "f0e0d0c0b0a090807060504030201000";
    let (fixture, sender) =
        fixture(&format!("[access.users]\nprivate_account='{OLD}'"), false).await;
    let before = inspect(&fixture, None).await;
    let (status, _, response) = fixture
        .request_body(
            "POST",
            "/v1/users/private_account/rotate-secret",
            true,
            Some(&json!({"secret": NEW})),
            &[],
        )
        .await;
    assert_eq!(status, 200, "{response}");
    let pending = inspect(&fixture, None).await;
    assert_ne!(pending["desired_revision"], before["desired_revision"]);
    assert_eq!(pending["runtime"], before["runtime"]);
    assert_eq!(pending["comparison"]["status"], "pending_publication");
    assert!(
        pending["comparison"]["watcher_pending_paths"]
            .as_array()
            .unwrap()
            .contains(&json!("access.users.{entry}"))
    );
    let users = field(&pending, "effective", "access.users");
    assert_eq!(users["differs"], true);
    assert_eq!(users["present"], true);
    assert_eq!(users["entries"], 1);
    assert_eq!(users["redacted"], true);
    assert!(users.get("value").is_none());
    for private in [OLD, NEW, "private_account", "Bearer discovery-test"] {
        assert!(!pending.to_string().contains(private));
    }
    let mut published = ProxyConfig::load_prepared(fixture.shared.config_path.clone())
        .await
        .unwrap()
        .config
        .with_publication_epoch();
    published.watcher_observation = sender.borrow().watcher_observation.clone();
    published.watcher_observation.as_ref().unwrap().record(
        "published",
        published.provenance.revision().map(str::to_owned),
        Some(published.runtime_config_epoch),
        None,
    );
    sender.send(Arc::new(published)).unwrap();
    let after = inspect(&fixture, None).await;
    assert_eq!(after["comparison"]["status"], "published_match");
    assert_ne!(
        after["runtime"]["config_epoch"],
        before["runtime"]["config_epoch"]
    );
    assert_eq!(after["watcher_matches_desired"], true);
    assert_eq!(after["subsystem_convergence"], "unknown");
    assert_eq!(field(&after, "effective", "access.users")["differs"], false);
}

#[tokio::test]
async fn hot_generation_and_process_changes_have_distinct_paths() {
    let (fixture, _sender) = fixture("", true).await;
    source(
        &fixture,
        "[general]\nlog_level='debug'\ndisable_colors=true\n[network]\nipv6=true",
        true,
    );
    let data = inspect(&fixture, None).await;
    let comparison = &data["comparison"];
    assert!(
        comparison["watcher_pending_paths"]
            .as_array()
            .unwrap()
            .contains(&json!("general.log_level"))
    );
    assert!(
        comparison["generation_pending_paths"]
            .as_array()
            .unwrap()
            .contains(&json!("network.ipv6"))
    );
    assert!(
        comparison["process_deferred_paths"]
            .as_array()
            .unwrap()
            .contains(&json!("general.disable_colors"))
    );
    source(&fixture, "[general]\ndisable_colors=true", true);
    let data = inspect(&fixture, None).await;
    assert_eq!(data["comparison"]["status"], "process_deferred");
    assert_eq!(
        data["comparison"]["deferred_process_fields"],
        json!(["general.disable_colors"])
    );
    let scoped = inspect(&fixture, Some("sections=network")).await;
    assert_eq!(scoped["comparison"]["status"], "published_match");
}

#[tokio::test]
async fn known_source_default_inheritance_and_runtime_derived_provenance() {
    let text = "[general]\nlog_level='debug'\n[[upstreams]]\ntype='direct'\n[censorship]\ntls_emulation=false";
    let (fixture, _sender) = fixture(text, true).await;
    let data = inspect(&fixture, None).await;
    assert_eq!(
        field(&data, "desired", "general.log_level")["origin"],
        "source"
    );
    assert_eq!(
        field(&data, "desired", "general.disable_colors")["origin"],
        "type_default"
    );
    assert_eq!(
        field(&data, "desired", "upstreams[0].prefer")["origin"],
        "inherited"
    );
    assert_eq!(
        field(&data, "desired", "upstreams[0].prefer")["inherited_from"],
        "network.prefer"
    );
    assert_eq!(
        field(&data, "desired", "censorship.fake_cert_len")["origin"],
        "runtime_derived"
    );
    assert!(
        field(&data, "desired", "censorship.fake_cert_len")
            .get("value")
            .is_none()
    );
    assert_eq!(data["comparison"]["status"], "published_match");
    assert_eq!(
        data["comparison"]["runtime_derived_paths"],
        json!(["censorship.fake_cert_len"])
    );
    assert_eq!(data["desired"]["source_revision"], data["desired_revision"]);
    assert_eq!(data["desired"]["source_count"], 1);
}

#[tokio::test]
async fn reload_metadata_distinguishes_acceptance_failure_and_rollback_without_raw_errors() {
    let (mut fixture, _sender) = fixture("", true).await;
    let (control, mut commands) = ReloadControl::channel(1);
    Arc::get_mut(&mut fixture.shared).unwrap().reload_control = control.clone();
    let revision = inspect(&fixture, None).await["desired_revision"]
        .as_str()
        .unwrap()
        .to_owned();
    for terminal in [ReloadPhase::Failed, ReloadPhase::RolledBack] {
        let accepted = control
            .submit(
                fixture.shared.active_runtime.load().config(),
                revision.clone(),
                ReloadRequest::default(),
            )
            .await
            .unwrap();
        let _ = commands.recv().await.unwrap();
        let data = inspect(&fixture, None).await;
        assert_eq!(data["reload"]["phase"], "accepted");
        assert_eq!(data["reload_matches_desired"], true);
        assert!(data["reload"]["activated_generation"].is_null());
        control.record_source_generation(accepted.reload_id, 1);
        control
            .mark_phase(accepted.reload_id, ReloadPhase::Preparing)
            .await;
        control
            .add_warning(accepted.reload_id, "synthetic-private-warning")
            .await;
        match terminal {
            ReloadPhase::Failed => {
                control
                    .fail(accepted.reload_id, "synthetic-private-error")
                    .await
            }
            ReloadPhase::RolledBack => {
                control
                    .rolled_back(accepted.reload_id, "synthetic-private-error")
                    .await
            }
            _ => unreachable!(),
        }
        let data = inspect(&fixture, None).await;
        assert_eq!(
            data["reload"]["phase"],
            serde_json::to_value(terminal).unwrap()
        );
        assert_eq!(data["reload"]["source_generation"], 1);
        assert_eq!(data["reload"]["error_present"], true);
        assert_eq!(data["reload"]["warning_count"], 1);
        assert!(data["reload"]["retiring_generation"].is_null());
        assert!(!data.to_string().contains("synthetic-private"));
    }
}
