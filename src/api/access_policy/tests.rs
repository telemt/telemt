use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::maestro::generation::test_runtime_generation;
use serde_json::{Value, json};

const ROUTE: &str = "/v1/access/policy";

pub(in crate::api) fn fixture(source: &str) -> Fixture {
    let fixture = Fixture::new(false);
    std::fs::write(&fixture.shared.config_path, source).unwrap();
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
        .store(test_runtime_generation(1, config));
    fixture
}

async fn write(fixture: &Fixture, body: Value) -> (u16, Value) {
    let (status, _, data) = fixture
        .request_body("PATCH", ROUTE, true, Some(&body), &[])
        .await;
    (status, data)
}

#[tokio::test]
async fn policy_http_gates_methods_queries_and_secret_exclusion() {
    let fixture = Fixture::new(false);
    for method in ["GET", "PATCH"] {
        assert_eq!(fixture.request(method, ROUTE, false).await.0, 401);
    }
    assert_eq!(
        write(&fixture, json!({"user_max_tcp_conns_global_each": 2}))
            .await
            .0,
        403
    );
    let (status, allow, _) = fixture.request("POST", ROUTE, true).await;
    assert_eq!((status, allow.as_str()), (405, "GET, PATCH"));
    assert_eq!(
        fixture
            .request("GET", "/v1/access/policy?reload=instant", true)
            .await
            .0,
        400
    );
    let denied = Fixture::new(true);
    assert_eq!(denied.request("GET", ROUTE, true).await.0, 403);
    let (status, _, data) = fixture.request("GET", ROUTE, true).await;
    assert_eq!(status, 200);
    assert_eq!(
        data["data"]["desired"].as_object().unwrap().len(),
        FIELDS.len()
    );
    assert_eq!(data["data"]["effective_scope"], "active_config_snapshot");
    assert_eq!(data["data"]["subsystem_convergence"], "unknown");
    assert!(!data.to_string().contains("discovery-test"));
}

#[tokio::test]
async fn scalar_defaults_reset_and_revision_runtime_fences() {
    let fixture = fixture("# preserve comment\n");
    let (_, _, before) = fixture.request("GET", ROUTE, true).await;
    let body = json!({"user_max_tcp_conns_global_each": 7, "user_max_unique_ips_global_each": 3,
        "user_max_unique_ips_mode": "time_window", "user_max_unique_ips_window_secs": 91});
    let (status, _, after) = fixture
        .request_body(
            "PATCH",
            ROUTE,
            true,
            Some(&body),
            &[
                ("If-Match", before["revision"].as_str().unwrap()),
                (
                    "If-Runtime-Match",
                    before["data"]["runtime"]["runtime_match"].as_str().unwrap(),
                ),
            ],
        )
        .await;
    assert_eq!(status, 200, "{after}");
    assert_eq!(
        after["data"]["desired"]["user_max_tcp_conns_global_each"],
        7
    );
    assert_eq!(
        after["data"]["effective"]["user_max_tcp_conns_global_each"],
        0
    );
    assert_eq!(after["data"]["published_match"], false);
    let source = std::fs::read(&fixture.shared.config_path).unwrap();
    for (header, token, code) in [
        (
            "If-Match",
            before["revision"].as_str().unwrap(),
            "revision_conflict",
        ),
        ("If-Runtime-Match", "dead:1:1", "runtime_conflict"),
    ] {
        let (status, _, error) = fixture
            .request_body("PATCH", ROUTE, true, Some(&body), &[(header, token)])
            .await;
        assert_eq!(status, 409);
        assert_eq!(error["error"]["code"], code);
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), source);
    }
    let (status, after) = write(
        &fixture,
        json!({"user_max_tcp_conns_global_each": null,
        "user_max_unique_ips_global_each": null, "user_max_unique_ips_mode": null,
        "user_max_unique_ips_window_secs": null}),
    )
    .await;
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["data"]["desired"], before["data"]["desired"]);
    let text = std::fs::read_to_string(&fixture.shared.config_path).unwrap();
    assert!(!text.contains("user_max_"));
    assert!(text.contains("# preserve comment"));
}

#[tokio::test]
async fn cidr_map_updates_replace_rows_and_null_removes_or_clears() {
    let fixture = fixture("[access.cidr_rate_limits]\n'192.0.2.0/24'={up_bps=123, down_bps=456}\n");
    let (status, body) = write(
        &fixture,
        json!({"cidr_rate_limits": {
        "192.0.2.0/24": {"up_bps": 8000}, "2001:db8::/32": {"down_bps": 9000},
        "*4/16": {"up_bps": 80}, "*6/64": {"down_bps": 160}, "*/24": {"up_bps": 320}}}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let rates = &body["data"]["desired"]["cidr_rate_limits"];
    assert_eq!(rates.as_object().unwrap().len(), 5);
    assert_eq!(rates["192.0.2.0/24"], json!({"up_bps": 8000,"down_bps": 0}));
    let (status, body) = write(
        &fixture,
        json!({"cidr_rate_limits": {"192.0.2.0/24": null,"*4/16": null,"203.0.113.0/24": null}}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["data"]["desired"]["cidr_rate_limits"]
            .as_object()
            .unwrap()
            .len(),
        3
    );
    let (status, body) = write(&fixture, json!({"cidr_rate_limits": null})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["desired"]["cidr_rate_limits"], json!({}));
    assert!(
        !std::fs::read_to_string(&fixture.shared.config_path)
            .unwrap()
            .contains("cidr_rate_limits")
    );
}

#[tokio::test]
async fn invalid_and_non_policy_patches_never_write() {
    let fixture = fixture("");
    let before = std::fs::read(&fixture.shared.config_path).unwrap();
    for body in [
        json!({}),
        json!({"users": null}),
        json!({"replay_check": false}),
        json!({"user_max_unique_ips_window_secs":0}),
        json!({"user_max_unique_ips_mode":"other"}),
        json!({"user_max_tcp_conns_global_each":-1}),
        json!({"user_max_tcp_conns_global_each":u64::MAX}),
        json!({"cidr_rate_limits":[]}),
        json!({"cidr_rate_limits":{"invalid":{"up_bps":1}}}),
        json!({"cidr_rate_limits":{"*4/33":{"up_bps":1}}}),
        json!({"cidr_rate_limits":{"*6/129":{"up_bps":1}}}),
        json!({"cidr_rate_limits":{"*/33":{"up_bps":1}}}),
        json!({"cidr_rate_limits":{"*/24":{"up_bps":1},"*4/24":{"up_bps":2}}}),
        json!({"cidr_rate_limits":{"192.0.2.0/24":{}}}),
        json!({"cidr_rate_limits":{"192.0.2.0/24":{"up_bps":100_000_000_001_u64}}}),
        json!({"cidr_rate_limits":{"192.0.2.0/24":{"up_bps":1,"typo":null}}}),
    ] {
        let (status, error) = write(&fixture, body.clone()).await;
        assert_eq!(status, 400, "{body}: {error}");
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
    }
}

#[tokio::test]
async fn structural_edits_preserve_unrelated_values_and_literal_keys() {
    for source in [
        "access = { user_max_tcp_conns_global_each=4, ignore_time_skew=false } # keep\n",
        "access.user_max_tcp_conns_global_each=4\naccess.ignore_time_skew=false # keep\n",
        "['access']\nuser_max_tcp_conns_global_each=4\nignore_time_skew=false # keep\n",
    ] {
        let fixture = fixture(source);
        let (status, result) = write(
            &fixture,
            json!({"user_max_tcp_conns_global_each": null,
            "cidr_rate_limits":{"192.0.2.0/24":{"up_bps":8000}}}),
        )
        .await;
        assert_eq!(status, 200, "{result}");
        let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
        assert!(!cfg.access.ignore_time_skew);
        assert_eq!(cfg.access.cidr_rate_limits.len(), 1);
        assert!(
            std::fs::read_to_string(&fixture.shared.config_path)
                .unwrap()
                .contains("# keep")
        );
    }
}

#[tokio::test]
async fn include_owner_selection_and_cross_source_rejection() {
    let fixture = fixture("");
    let root = &fixture.shared.config_path;
    let include = root.with_file_name("policy.toml");
    let root_text = "include=\"policy.toml\"\n[access]\nuser_max_tcp_conns_global_each=5\n";
    let include_text = "[access.cidr_rate_limits]\n'192.0.2.0/24'={up_bps=8000}\n";
    std::fs::write(root, root_text).unwrap();
    std::fs::write(&include, include_text).unwrap();
    let (status, body) = write(
        &fixture,
        json!({"user_max_tcp_conns_global_each":null,"cidr_rate_limits":null}),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "config_patch_not_atomic");
    assert_eq!(std::fs::read_to_string(root).unwrap(), root_text);
    assert_eq!(std::fs::read_to_string(&include).unwrap(), include_text);
    let (status, body) = write(
        &fixture,
        json!({"cidr_rate_limits":{"2001:db8::/32":{"up_bps":16000}}}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(std::fs::read_to_string(root).unwrap(), root_text);
    assert!(
        std::fs::read_to_string(include)
            .unwrap()
            .contains("2001:db8::/32")
    );
}

#[tokio::test]
async fn concurrent_policy_writers_with_same_revision_have_one_winner() {
    let fixture = fixture("");
    let (_, revision) = read(&fixture.shared).await.unwrap();
    let one = patch(
        serde_json::from_value(json!({"user_max_tcp_conns_global_each":7})).unwrap(),
        Some(revision.clone()),
        None,
        &fixture.shared,
    );
    let two = patch(
        serde_json::from_value(json!({"user_max_unique_ips_global_each":3})).unwrap(),
        Some(revision),
        None,
        &fixture.shared,
    );
    let (one, two) = tokio::join!(one, two);
    assert_ne!(one.is_ok(), two.is_ok());
    let error = one.err().or(two.err()).unwrap();
    assert_eq!(error.code, "revision_conflict");
}

#[tokio::test]
async fn user_limit_origins_separate_desired_from_published_values() {
    let fixture = fixture(
        "[access]\nuser_max_tcp_conns_global_each=7\nuser_max_unique_ips_global_each=3\n[access.users]\nalice='0123456789abcdef0123456789abcdef'\n",
    );
    for (override_value, origin, value) in [
        (json!(9), "user_override", json!(9)),
        (json!(0), "global_default", json!(7)),
        (Value::Null, "global_default", json!(7)),
    ] {
        let (status, _, body) = fixture
            .request_body(
                "PATCH",
                "/v1/users/alice",
                true,
                Some(&json!({"max_tcp_conns":override_value,"max_unique_ips":override_value})),
                &[],
            )
            .await;
        assert!([200, 202].contains(&status), "{body}");
        let desired = &body["data"]["limits"]["desired"]["max_tcp_conns"];
        assert_eq!(desired["origin"], origin);
        assert_eq!(desired["value"], value);
        assert_eq!(desired["configured_override"], override_value);
        let ips = &body["data"]["limits"]["desired"]["max_unique_ips"];
        assert_eq!(ips["origin"], origin);
        assert_eq!(ips["configured_override"], override_value);
        assert_eq!(
            ips["value"],
            if origin == "user_override" {
                json!(9)
            } else {
                json!(3)
            }
        );
        assert_eq!(
            body["data"]["limits"]["effective"]["max_unique_ips"]["value"],
            3
        );
        assert_eq!(
            body["data"]["limits"]["effective"]["max_tcp_conns"]["value"],
            7
        );
    }
    assert_eq!(
        write(&fixture, json!({"user_max_tcp_conns_global_each":0}))
            .await
            .0,
        200
    );
    let (_, _, body) = fixture.request("GET", "/v1/users/alice", true).await;
    assert_eq!(
        body["data"]["limits"]["desired"]["max_tcp_conns"]["origin"],
        "unlimited"
    );
    assert_eq!(
        body["data"]["limits"]["desired"]["max_tcp_conns"]["value"],
        Value::Null
    );
    assert_eq!(
        body["data"]["limits"]["effective"]["max_tcp_conns"]["value"],
        7
    );
}

#[tokio::test]
async fn persisted_cidr_policy_retains_precedence_units_and_unlimited_direction() {
    use crate::proxy::traffic_limiter::{RateDirection, TrafficLimiter};
    let fixture = fixture("");
    let (status, body) = write(
        &fixture,
        json!({"cidr_rate_limits":{
            "192.0.2.0/24":{"up_bps":8000}, "192.0.2.7/32":{"up_bps":16000},
            "2001:db8::/32":{"up_bps":24000}, "2001:db8:1::/48":{"up_bps":32000},
            "*4/32":{"up_bps":40000}, "*6/64":{"up_bps":48000}, "*/8":{"up_bps":56000}
        }}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
    // A fresh bucket grants exactly one 20 ms epoch, expressed in bytes.
    for (ip, grant) in [
        ("192.0.2.1", 20),
        ("192.0.2.7", 40),
        ("2001:db8::1", 60),
        ("2001:db8:1::1", 80),
        ("203.0.113.1", 100),
        ("2001:db9::1", 120),
    ] {
        let limiter = TrafficLimiter::new();
        limiter.apply_policy(HashMap::new(), cfg.access.cidr_rate_limits.clone());
        let lease = limiter.acquire_lease("alice", ip.parse().unwrap()).unwrap();
        assert_eq!(
            lease
                .try_reserve(RateDirection::Up, 10_000)
                .result()
                .granted,
            grant,
            "{ip}"
        );
        assert_eq!(
            lease
                .try_reserve(RateDirection::Down, 10_000)
                .result()
                .granted,
            10_000,
            "{ip}"
        );
    }
    assert_eq!(
        write(
            &fixture,
            json!({"cidr_rate_limits":{"*4/32":null,"*6/64":null}})
        )
        .await
        .0,
        200
    );
    let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
    for ip in ["203.0.113.1", "2001:db9::1"] {
        let limiter = TrafficLimiter::new();
        limiter.apply_policy(HashMap::new(), cfg.access.cidr_rate_limits.clone());
        let lease = limiter.acquire_lease("alice", ip.parse().unwrap()).unwrap();
        assert_eq!(
            lease
                .try_reserve(RateDirection::Up, 10_000)
                .result()
                .granted,
            140
        );
    }
}

#[tokio::test]
async fn watcher_publishes_policy_without_quota_reset_or_session_cancellation() {
    use crate::config::hot_reload::spawn_config_watcher;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::watch;
    let mut fixture = fixture(
        "[server.api]\nenabled=true\nread_only=false\nauth_header='Bearer discovery-test'\n[access.users]\nalice='0123456789abcdef0123456789abcdef'\n",
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
    runtime.stats.increment_user_curr_connects("alice");
    let stats = runtime.stats.clone();
    let quota_path = fixture.shared.quota_state.path().to_path_buf();
    Arc::get_mut(&mut fixture.shared).unwrap().quota_state =
        crate::quota_state::QuotaStateOwner::new(quota_path.clone(), stats.quota_store());
    let checkpoint_before = std::fs::read(&quota_path).ok();
    fixture.shared.active_runtime.store(runtime);
    let task = tokio::spawn(watcher);
    for limit in [7, 2, 0] {
        let (status, body) = write(
            &fixture,
            json!({"user_max_tcp_conns_global_each":limit,"user_max_unique_ips_global_each":limit}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        activation.send_replace(true);
        tokio::time::timeout(
            Duration::from_secs(5),
            receiver.wait_for(|cfg| cfg.access.user_max_tcp_conns_global_each == limit),
        )
        .await
        .unwrap()
        .unwrap();
        let (_, _, body) = fixture.request("GET", ROUTE, true).await;
        assert_eq!(body["data"]["published_match"], true);
        assert_eq!(
            body["data"]["effective"]["user_max_unique_ips_global_each"],
            limit
        );
        assert_eq!(stats.get_user_quota_used("alice"), 12345);
        assert_eq!(
            stats.user_quota_snapshot()["alice"].last_reset_epoch_secs,
            6789
        );
        assert_eq!(stats.get_user_curr_connects("alice"), 1);
    }
    assert_eq!(std::fs::read(&quota_path).ok(), checkpoint_before);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn prepared_policy_write_rechecks_external_source_and_runtime_publications() {
    for runtime_change in [false, true] {
        let fixture = fixture("");
        let fence = RuntimeFence::capture(&fixture.shared, None).unwrap();
        let loaded = ProxyConfig::parse_source(&fixture.shared.config_path).unwrap();
        let revision = compute_snapshot_revision(&loaded.source_contents);
        let (_, edits) = apply(
            &loaded,
            serde_json::from_value(json!({"user_max_tcp_conns_global_each":7})).unwrap(),
        )
        .unwrap();
        let owned = prepare_field_edits(&loaded, &fixture.shared.config_path, &edits)
            .unwrap()
            .unwrap();
        if runtime_change {
            fixture
                .shared
                .active_runtime
                .store(test_runtime_generation(2, (*fence.config).clone()));
        } else {
            std::fs::write(&fixture.shared.config_path, "# external operator edit\n").unwrap();
        }
        let before = std::fs::read(&fixture.shared.config_path).unwrap();
        let error = write_atomic_with_runtime_check(
            fixture.shared.config_path.clone(),
            revision,
            owned.owner_path,
            owned.expected_owner_contents,
            owned.owner_contents,
            Some(fence.commit_check()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.code,
            if runtime_change {
                "runtime_conflict"
            } else {
                "revision_conflict"
            }
        );
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
    }
}

#[tokio::test]
async fn unreadable_policy_source_does_not_echo_credentials_or_source_excerpts() {
    let fixture = fixture("");
    let secret = "private-source-credential";
    std::fs::write(
        &fixture.shared.config_path,
        format!("[access]\nuser_max_tcp_conns_global_each='{secret}'\n"),
    )
    .unwrap();
    for method in ["GET", "PATCH"] {
        let (status, _, body) = fixture
            .request_body(
                method,
                ROUTE,
                true,
                Some(&json!({"user_max_tcp_conns_global_each":1})),
                &[],
            )
            .await;
        assert_eq!(status, 500);
        assert!(!body.to_string().contains(secret));
    }
}
