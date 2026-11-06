use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::maestro::generation::test_runtime_generation;
use serde_json::{Value, json};
use std::sync::Arc;

const USERS: &str = "[general]\nconfig_strict=true\n[access.users]\nalice='0123456789abcdef0123456789abcdef'\nbob='abcdef0123456789abcdef0123456789'\n";

fn fixture(extra: &str) -> Fixture {
    let fixture = Fixture::new(false);
    std::fs::write(&fixture.shared.config_path, format!("{USERS}{extra}")).unwrap();
    publish(&fixture, 1);
    fixture
}

fn publish(fixture: &Fixture, generation: u64) {
    let mut config = ProxyConfig::load(&fixture.shared.config_path).unwrap();
    config.server.api = fixture
        .shared
        .active_runtime
        .load()
        .config()
        .server
        .api
        .clone();
    config.server.api.read_only = false;
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(generation, config));
}

async fn patch(fixture: &Fixture, username: &str, body: Value) -> Value {
    let (status, _, result) = fixture
        .request_body(
            "PATCH",
            &format!("/v1/users/{username}"),
            true,
            Some(&body),
            &[],
        )
        .await;
    assert!([200, 202].contains(&status), "{result}");
    result
}

#[tokio::test]
async fn source_deny_strict_create_get_replace_clear_and_reload_status() {
    let fixture = fixture("");
    let (status, _, created) = fixture
        .request_body(
            "POST",
            "/v1/users",
            true,
            Some(&json!({
        "username":"alice.two", "source_deny":["192.0.2.0/24","2001:db8::/32"]})),
            &[],
        )
        .await;
    assert_eq!(status, 202, "{created}");
    assert_eq!(
        created["data"]["user"]["source_deny_status"]["runtime_reload_required"],
        true
    );
    assert_eq!(
        created["data"]["user"]["source_deny_status"]["reload_endpoint"],
        "POST /v1/system/reload"
    );
    let (_, _, get) = fixture.request("GET", "/v1/users/alice.two", true).await;
    assert_eq!(
        get["data"]["source_deny"],
        json!(["192.0.2.0/24", "2001:db8::/32"])
    );
    let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
    assert!(
        cfg.access
            .is_user_source_ip_denied("alice.two", "192.0.2.12".parse().unwrap())
    );
    assert!(
        cfg.access
            .is_user_source_ip_denied("alice.two", "2001:db8::12".parse().unwrap())
    );
    assert!(
        !cfg.access
            .is_user_source_ip_denied("alice.two", "198.51.100.12".parse().unwrap())
    );
    publish(&fixture, 2);
    let (_, _, get) = fixture.request("GET", "/v1/users/alice.two", true).await;
    assert_eq!(
        get["data"]["source_deny_status"]["runtime_reload_required"],
        false
    );
    for value in [json!(["203.0.113.0/24"]), json!([]), Value::Null] {
        let body = patch(&fixture, "alice.two", json!({"source_deny":value})).await;
        assert_eq!(
            body["data"]["source_deny_status"]["runtime_reload_required"],
            true
        );
        let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
        assert_eq!(
            cfg.access.user_source_deny.contains_key("alice.two"),
            !value.is_null()
        );
        assert_eq!(
            body["data"]["source_deny"],
            if value.is_null() { json!([]) } else { value }
        );
    }
}

#[tokio::test]
async fn source_deny_delete_retains_rules_and_recreation_can_remove_them_explicitly() {
    let fixture = fixture(
        "[access.user_source_deny]\nalice=['192.0.2.0/24']\nbob=['2001:db8::/32'] # retain bob\n",
    );
    for clear in [false, true] {
        let (status, _, deleted) = fixture.request("DELETE", "/v1/users/alice", true).await;
        assert!([200, 202].contains(&status), "{deleted}");
        let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
        assert_eq!(cfg.access.user_source_deny["alice"].len(), 1);
        let mut body = json!({"username":"alice"});
        if clear {
            body["source_deny"] = Value::Null;
        }
        let (status, _, created) = fixture
            .request_body("POST", "/v1/users", true, Some(&body), &[])
            .await;
        assert!([201, 202].contains(&status), "{created}");
        let user = &created["data"]["user"];
        assert_eq!(
            user["source_deny"],
            if clear {
                json!([])
            } else {
                json!(["192.0.2.0/24"])
            }
        );
        assert_eq!(user["source_deny_status"]["runtime_reload_required"], clear);
        assert!(
            std::fs::read_to_string(&fixture.shared.config_path)
                .unwrap()
                .contains("bob=['2001:db8::/32'] # retain bob")
        );
    }
}

#[tokio::test]
async fn source_deny_edits_exact_included_owner_and_rejects_cross_file_user_patch() {
    let fixture = fixture("");
    let root = &fixture.shared.config_path;
    let include = root.with_file_name("deny.toml");
    let root_text = format!("include = \"deny.toml\"\n{USERS}");
    let include_text = "[access.user_source_deny]\nalice=['192.0.2.0/24']\n'bob'= ['2001:db8::/32'] # keep literal\n";
    std::fs::write(root, &root_text).unwrap();
    std::fs::write(&include, include_text).unwrap();
    patch(
        &fixture,
        "alice",
        json!({"source_deny":["198.51.100.0/24"]}),
    )
    .await;
    assert_eq!(std::fs::read_to_string(root).unwrap(), root_text);
    assert!(
        std::fs::read_to_string(&include)
            .unwrap()
            .contains("'bob'= ['2001:db8::/32'] # keep literal")
    );
    let before = std::fs::read(&include).unwrap();
    let (status, _, error) = fixture
        .request_body(
            "PATCH",
            "/v1/users/alice",
            true,
            Some(&json!({"secret":"11111111111111111111111111111111","source_deny":null})),
            &[],
        )
        .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["error"]["code"], "config_patch_not_atomic");
    assert_eq!(std::fs::read(root).unwrap(), root_text.as_bytes());
    assert_eq!(std::fs::read(&include).unwrap(), before);
    patch(&fixture, "alice", json!({"source_deny":null})).await;
    assert!(
        !ProxyConfig::load(root)
            .unwrap()
            .access
            .user_source_deny
            .contains_key("alice")
    );
    assert!(
        ProxyConfig::load(root)
            .unwrap()
            .access
            .user_source_deny
            .contains_key("bob")
    );
}

#[tokio::test]
async fn source_deny_literal_username_supports_inline_dotted_and_quoted_sources() {
    for declaration in [
        "access.user_source_deny = { 'alice.two'=['192.0.2.0/24'], bob=['2001:db8::/32'] } # keep\n",
        "access.user_source_deny.'alice.two'=['192.0.2.0/24']\naccess.user_source_deny.bob=['2001:db8::/32'] # keep\n",
        "[access.user_source_deny]\n'alice.two'=['192.0.2.0/24']\nbob=['2001:db8::/32'] # keep\n",
    ] {
        let fixture = fixture("");
        let text = format!("{declaration}{}", USERS.replace("alice=", "'alice.two'="));
        std::fs::write(&fixture.shared.config_path, text).unwrap();
        patch(
            &fixture,
            "alice.two",
            json!({"source_deny":["203.0.113.0/24"]}),
        )
        .await;
        let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
        assert_eq!(cfg.access.user_source_deny.len(), 2);
        assert_eq!(
            cfg.access.user_source_deny["alice.two"][0].to_string(),
            "203.0.113.0/24"
        );
        patch(&fixture, "alice.two", json!({"source_deny":null})).await;
        let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
        assert_eq!(cfg.access.user_source_deny.len(), 1);
        assert_eq!(
            cfg.access.user_source_deny["bob"][0].to_string(),
            "2001:db8::/32"
        );
        assert!(
            std::fs::read_to_string(&fixture.shared.config_path)
                .unwrap()
                .contains("# keep")
        );
    }
}

#[tokio::test]
async fn source_deny_invalid_values_and_stale_revision_leave_source_unchanged() {
    let fixture = fixture("");
    let before = std::fs::read(&fixture.shared.config_path).unwrap();
    for value in [
        json!("192.0.2.0/24"),
        json!([1]),
        json!(["192.0.2.0/33"]),
        json!(["2001:db8::/129"]),
        json!(["bad"]),
        json!([null]),
    ] {
        let (status, _, error) = fixture
            .request_body(
                "PATCH",
                "/v1/users/alice",
                true,
                Some(&json!({"source_deny":value})),
                &[],
            )
            .await;
        assert_eq!(status, 400, "{error}");
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
    }
    let (status, _, error) = fixture
        .request_body(
            "PATCH",
            "/v1/users/alice",
            true,
            Some(&json!({"source_deny":[]})),
            &[("If-Match", "stale")],
        )
        .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["error"]["code"], "revision_conflict");
    assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
}

#[tokio::test]
async fn source_deny_prepared_reload_retains_old_rules_until_a_later_generation() {
    let fixture = fixture("");
    let (control, mut commands) = crate::maestro::reload::ReloadControl::channel(1);
    let (accepted, _) = crate::api::submit_reload_from_disk(
        &fixture.shared.config_path,
        &fixture.shared.mutation_lock,
        &control,
        None,
        crate::maestro::reload::ReloadRequest::default(),
    )
    .await
    .unwrap();
    let captured_for_reload = (*commands.recv().await.unwrap().config).clone();
    let old_runtime = fixture.shared.active_runtime.load_full();
    let admission = old_runtime.proxy_shared.clone();
    let credential = credential_id_from_hex(&captured_for_reload.access.users["alice"]).unwrap();
    let incarnation = admission
        .stage_user_credential("alice", credential, true)
        .incarnation;
    let registration = admission
        .register_authenticated_user_session("alice", credential)
        .unwrap();
    // The generation being prepared has already captured source before the API write.
    let written = patch(&fixture, "alice", json!({"source_deny":["192.0.2.0/24"]})).await;
    assert_ne!(written["revision"], accepted.config_revision);
    assert!(!registration.is_cancelled());
    assert_eq!(registration.incarnation(), incarnation);
    let mut intermediate = captured_for_reload;
    intermediate.server.api = old_runtime.config().server.api.clone();
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(2, intermediate));
    let (_, _, view) = fixture.request("GET", "/v1/users/alice", true).await;
    assert_eq!(view["data"]["source_deny_status"]["effective"], json!([]));
    assert_eq!(
        view["data"]["source_deny_status"]["runtime_reload_required"],
        true
    );
    publish(&fixture, 3);
    let (_, _, view) = fixture.request("GET", "/v1/users/alice", true).await;
    assert_eq!(
        view["data"]["source_deny_status"]["runtime_reload_required"],
        false
    );
    assert!(
        !old_runtime
            .config()
            .access
            .is_user_source_ip_denied("alice", "192.0.2.1".parse().unwrap())
    );
    assert!(!registration.is_cancelled());
}

#[tokio::test]
async fn source_deny_watcher_retains_rules_and_preserves_quota_usage() {
    use crate::config::hot_reload::spawn_config_watcher;
    use std::time::Duration;
    use tokio::sync::watch;
    let mut fixture = fixture(
        "[server.api]\nenabled=true\nread_only=false\nauth_header='Bearer discovery-test'\n",
    );
    let config = fixture.shared.active_runtime.load().config();
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let (activation, activated) = watch::channel(false);
    let (mut receiver, _, watcher) = spawn_config_watcher(
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
    runtime.stats.load_user_quota_state("alice", 12345, 6789);
    let stats = runtime.stats.clone();
    let quota_path = fixture.shared.quota_state.path().to_path_buf();
    Arc::get_mut(&mut fixture.shared).unwrap().quota_state =
        crate::quota_state::QuotaStateOwner::new(quota_path.clone(), stats.quota_store());
    let checkpoint_before = std::fs::read(&quota_path).ok();
    fixture.shared.active_runtime.store(runtime);
    let task = tokio::spawn(watcher);
    patch(
        &fixture,
        "alice",
        json!({"source_deny":["192.0.2.0/24"],"max_tcp_conns":7}),
    )
    .await;
    activation.send_replace(true);
    tokio::time::timeout(
        Duration::from_secs(5),
        receiver.wait_for(|cfg| cfg.access.user_max_tcp_conns.get("alice") == Some(&7)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(receiver.borrow().access.user_source_deny.is_empty());
    let (_, _, view) = fixture.request("GET", "/v1/users/alice", true).await;
    assert_eq!(
        view["data"]["source_deny_status"]["runtime_reload_required"],
        true
    );
    assert_eq!(stats.get_user_quota_used("alice"), 12345);
    assert_eq!(
        stats.user_quota_snapshot()["alice"].last_reset_epoch_secs,
        6789
    );
    assert_eq!(std::fs::read(&quota_path).ok(), checkpoint_before);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
