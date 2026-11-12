use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::config::hot_reload::spawn_config_watcher;
use crate::maestro::generation::test_runtime_generation;
use crate::network::dns_overrides::GenerationDnsResolver;
use serde_json::json;
use std::time::Duration;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const OLD: &str = "old.example:443:192.0.2.1";
const NEW: &str = "new.example:443:192.0.2.2";

fn patch(entries: Json) -> Json {
    json!({"network": {"dns_overrides": entries}})
}

#[tokio::test]
async fn get_exposes_only_dns_overrides_including_the_empty_default() {
    for entries in [vec![], vec![OLD.to_owned()]] {
        let source = format!(
            "[network]\nipv4 = true\ncache_public_ip_path = 'private-path'\ndns_overrides = {}\n",
            json!(entries)
        );
        let (path, _directory) = tests::temp_config(&source);
        let (managed, _) = read_managed_config(&path).await.unwrap();
        assert_eq!(
            serde_json::to_value(&managed["network"]).unwrap(),
            patch(json!(entries))["network"]
        );
        assert!(
            !serde_json::to_string(&managed)
                .unwrap()
                .contains("private-path")
        );
    }
    let (path, _directory) = tests::temp_config("");
    let (managed, _) = read_managed_config(&path).await.unwrap();
    assert_eq!(
        serde_json::to_value(&managed["network"]).unwrap(),
        json!({"dns_overrides": []})
    );
}

#[tokio::test]
async fn every_network_sibling_is_rejected_even_as_null_without_writing() {
    let (path, _directory) = tests::temp_config("[network]\nipv4 = true\n");
    let original = std::fs::read(&path).unwrap();
    let network = serde_json::to_value(ProxyConfig::default().network).unwrap();
    for (key, value) in network.as_object().unwrap() {
        if key == "dns_overrides" {
            continue;
        }
        for value in [value.clone(), Json::Null] {
            let body = json!({"network": {key: value, "dns_overrides": [NEW]}});
            let error = apply_patch_to_path(&path, &body, None).await.unwrap_err();
            assert_eq!(error.code, "field_not_editable", "{key}: {error:?}");
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }
    for value in [
        json!([]),
        json!("bad"),
        json!({}),
        json!({"dns_overrides": null}),
        json!({"typo": []}),
    ] {
        assert!(
            apply_patch_to_path(&path, &json!({"network": value}), None)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[tokio::test]
async fn malformed_dns_arrays_never_change_source_or_revision() {
    let (path, _directory) = tests::temp_config(&format!("[network]\ndns_overrides = ['{OLD}']\n"));
    let original = std::fs::read(&path).unwrap();
    let revision = super::super::config_store::current_revision(&path)
        .await
        .unwrap();
    for entries in [
        json!(NEW),
        json!([12]),
        json!([""]),
        json!(["host:443:bad-ip"]),
        json!(["host:65536:192.0.2.1"]),
        json!([":443:192.0.2.1"]),
        json!(["host:443:2001:db8::1"]),
        json!([null]),
        json!(vec![OLD; 4097]),
    ] {
        let error = apply_patch_to_path(&path, &patch(entries), None)
            .await
            .unwrap_err();
        assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            super::super::config_store::current_revision(&path)
                .await
                .unwrap(),
            revision
        );
    }
}

#[tokio::test]
async fn add_replace_and_clear_preserve_unrelated_source_bytes() {
    let sources = [
        "# root without network\n[general]\nlog_level = 'normal'\n".to_owned(),
        "[network] # identity\nipv4 = true # keep\n[general]\nlog_level = 'normal'\n".to_owned(),
        "network = { ipv4 = true } # keep\n[general]\nlog_level = 'normal'\n".to_owned(),
        "network = {}\n".to_owned(),
        "network.ipv4 = true # keep\n[general]\nlog_level = 'normal'\n".to_owned(),
        "['network'] # quoted\nipv4 = true\n".to_owned(),
        "[network] # no final newline".to_owned(),
        "[network]\r\nipv4 = true # keep\r\n".to_owned(),
    ];
    for source in sources {
        let (path, _directory) = tests::temp_config(&source);
        let initial_network = ProxyConfig::load(&path).unwrap().network;
        for entries in [
            json!([OLD, "v6.example:8443:[2001:db8::1]"]),
            json!([NEW]),
            json!([]),
        ] {
            let (before, revision) = read_managed_config(&path).await.unwrap();
            let response = apply_patch_to_path(&path, &patch(entries.clone()), Some(revision))
                .await
                .unwrap();
            assert!(!response.restart_required);
            assert!(!response.process_restart_required);
            assert_eq!(response.changed, ["network"]);
            let expected_paths = if entries == json!([]) {
                vec!["network.dns_overrides[0]"]
            } else {
                vec!["network.dns_overrides[0]", "network.dns_overrides[1]"]
            };
            assert_eq!(response.changed_paths, expected_paths);
            let (managed, revision) = read_managed_config(&path).await.unwrap();
            assert_eq!(
                serde_json::to_value(&managed["network"]["dns_overrides"]).unwrap(),
                entries
            );
            assert_eq!(response.revision, revision);
            assert_eq!(managed["general"], before["general"]);
            let mut network = ProxyConfig::load(&path).unwrap().network;
            network.dns_overrides = initial_network.dns_overrides.clone();
            assert_eq!(
                serde_json::to_value(network).unwrap(),
                serde_json::to_value(&initial_network).unwrap()
            );
        }
        let written = std::fs::read_to_string(&path).unwrap();
        // New declarations can be inserted, but every original line survives.
        for line in source.lines() {
            if line.starts_with("network = {") {
                assert!(
                    written.contains(&line.replace("{", "{dns_overrides = [], "))
                        || written.contains(&line.replace("{}", "{dns_overrides = []}")),
                    "{written}"
                );
            } else {
                assert!(written.contains(line), "{source:?}: {written}");
            }
        }
    }
}

#[tokio::test]
async fn replacement_uses_parser_spans_for_multiline_dotted_and_inline_values() {
    let old_value = format!("[\n  '{OLD}', # replace only this value\n]");
    for (prefix, value, suffix) in [
        (
            "# Unicode: ü\n[network]\n\"dns_overrides\" = ",
            old_value.as_str(),
            " # trailing\nipv4=true\n",
        ),
        (
            "network = { ipv4=true, dns_overrides=",
            "['old.example:443:192.0.2.1']",
            " } # trailing\n",
        ),
        (
            "'network'.'dns_overrides' = ",
            "['old.example:443:192.0.2.1']",
            "\nnetwork.ipv4=true\n",
        ),
    ] {
        let source = format!("{prefix}{value}{suffix}");
        let (path, _directory) = tests::temp_config(&source);
        apply_patch_to_path(&path, &patch(json!([NEW])), None)
            .await
            .unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, format!("{prefix}[\"{NEW}\"]{suffix}"));
    }
}

#[tokio::test]
async fn included_parent_owns_new_dns_key_and_leaf_owner_precedes_other_network_fields() {
    for existing in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("config.toml");
        let included = directory.path().join("network.toml");
        let root_text = if existing {
            "include = \"network.toml\"\nnetwork.ipv4 = true # keep root identity\n[general]\nlog_level='normal'\n"
        } else {
            "include = \"network.toml\"\n[general]\nlog_level='normal'\n"
        };
        let included_text = if existing {
            format!("network.dns_overrides = ['{OLD}'] # retain\n")
        } else {
            "[network] # retain\nipv4 = true # identity\n".to_owned()
        };
        std::fs::write(&root, root_text).unwrap();
        std::fs::write(&included, &included_text).unwrap();
        for entries in [json!([NEW]), json!([])] {
            apply_patch_to_path(&root, &patch(entries.clone()), None)
                .await
                .unwrap();
            assert_eq!(std::fs::read_to_string(&root).unwrap(), root_text);
            assert_eq!(
                serde_json::to_value(ProxyConfig::load(&root).unwrap().network.dns_overrides)
                    .unwrap(),
                entries
            );
            let written = std::fs::read_to_string(&included).unwrap();
            assert!(written.contains("# retain"));
            if !existing {
                assert!(written.contains("ipv4 = true # identity"));
            }
        }
    }
}

#[tokio::test]
async fn cross_source_and_ambiguous_parent_edits_are_atomic_rejections() {
    for (root_text, included_text, body) in [
        (
            "include = \"network.toml\"\n[censorship]\ntls_domain='old.example'\n".to_owned(),
            format!("[network]\ndns_overrides=['{OLD}']\n"),
            json!({"network":{"dns_overrides":[NEW]},"censorship":{"tls_domain":"new.example"}}),
        ),
        (
            "include = \"network.toml\"\nnetwork.ipv4 = true\n".to_owned(),
            "network.stun_use = false\n".to_owned(),
            patch(json!([NEW])),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("config.toml");
        let included = directory.path().join("network.toml");
        std::fs::write(&root, &root_text).unwrap();
        std::fs::write(&included, &included_text).unwrap();
        let error = apply_patch_to_path(&root, &body, None).await.unwrap_err();
        assert_eq!(error.code, "config_patch_not_atomic");
        assert_eq!(std::fs::read_to_string(&root).unwrap(), root_text);
        assert_eq!(std::fs::read_to_string(&included).unwrap(), included_text);
    }
}

#[tokio::test]
async fn prepared_dns_patch_retains_source_revision_fencing() {
    let (path, _directory) = tests::temp_config(&format!("[network]\ndns_overrides=['{OLD}']\n"));
    let prepared = prepare_patch_to_path(&path, &patch(json!([NEW])), None)
        .await
        .unwrap();
    let external = "[network]\ndns_overrides=[]\n# external edit\n";
    std::fs::write(&path, external).unwrap();
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
    assert_eq!(std::fs::read_to_string(&path).unwrap(), external);
}

#[tokio::test]
async fn http_preflight_commit_and_watcher_update_future_generation_resolutions() {
    let fixture = Fixture::new(false);
    let source = "[network]\nipv4 = true # retain\n[server.api]\nenabled=true\nread_only=false\nauth_header='Bearer discovery-test'\n";
    std::fs::write(&fixture.shared.config_path, source).unwrap();
    let config = Arc::new(
        ProxyConfig::load_prepared(fixture.shared.config_path.clone())
            .await
            .unwrap()
            .config,
    );
    let resolver = Arc::new(GenerationDnsResolver::from_entries(&[]).unwrap());
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let (activation, activated) = watch::channel(false);
    let (mut receiver, _log_receiver, watcher) = spawn_config_watcher(
        fixture.shared.config_path.clone(),
        config.clone(),
        None,
        None,
        cancellation.clone(),
        Some(resolver.clone()),
        Some(activated),
        Some(fixture.shared.mutation_lock.clone()),
        None,
    );
    let mut runtime = test_runtime_generation(1, (*config).clone());
    Arc::get_mut(&mut runtime).unwrap().config_rx = receiver.clone();
    fixture.shared.active_runtime.store(runtime);
    let task = tokio::spawn(watcher);

    for entries in [
        json!([OLD]),
        json!([NEW, "v6.example:8443:[2001:db8::1]"]),
        json!([]),
    ] {
        let body = patch(entries.clone());
        let before = std::fs::read(&fixture.shared.config_path).unwrap();
        let preview = fixture
            .request_body("POST", "/v1/config/validate", true, Some(&body), &[])
            .await;
        assert_eq!(preview.0, 200, "{}", preview.2);
        let data = &preview.2["data"];
        let expected_paths = if entries == json!([OLD]) {
            json!(["network.dns_overrides[0]"])
        } else {
            json!(["network.dns_overrides[0]", "network.dns_overrides[1]"])
        };
        assert_eq!(data["apply"]["watcher_paths"], expected_paths);
        assert_eq!(data["changed_paths"], expected_paths);
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
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
        assert_eq!(response.2["data"]["restart_required"], false);
        assert_eq!(response.2["data"]["process_restart_required"], false);
        activation.send_replace(true);
        let wanted: Vec<String> = serde_json::from_value(entries.clone()).unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            receiver.wait_for(|config| config.network.dns_overrides == wanted),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            resolver.resolve_socket_addr("OLD.EXAMPLE", 443),
            if entries == json!([OLD]) {
                Some("192.0.2.1:443".parse().unwrap())
            } else {
                None
            }
        );
        assert_eq!(
            resolver.resolve_socket_addr("new.example", 443),
            if wanted.iter().any(|entry| entry == NEW) {
                Some("192.0.2.2:443".parse().unwrap())
            } else {
                None
            }
        );
        assert_eq!(
            resolver.resolve_socket_addr("v6.example", 8443),
            if wanted.len() == 2 {
                Some("[2001:db8::1]:8443".parse().unwrap())
            } else {
                None
            }
        );
        assert!(resolver.resolve_socket_addr("new.example", 444).is_none());
        let get = fixture.request("GET", "/v1/config", true).await;
        assert_eq!(get.0, 200);
        assert_eq!(get.2["data"]["network"], body["network"]);
        assert!(fixture.shared.reload_control.in_progress().await.is_none());
        let current = std::fs::read(&fixture.shared.config_path).unwrap();
        for invalid in [
            patch(json!(["invalid"])),
            json!({"network":{"ipv4":false,"dns_overrides":[]}}),
        ] {
            for method in ["POST", "PATCH"] {
                let route = if method == "POST" {
                    "/v1/config/validate"
                } else {
                    "/v1/config"
                };
                assert_eq!(
                    fixture
                        .request_body(method, route, true, Some(&invalid), &[])
                        .await
                        .0,
                    400
                );
                assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), current);
            }
        }
    }
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
