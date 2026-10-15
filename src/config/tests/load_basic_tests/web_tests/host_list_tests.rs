use super::*;

#[test]
fn exact_host_list_builds_distinct_host_bound_capabilities() {
    let source = WEB_CONFIG.replace(
        "host = \"Proxy.Example.COM\"",
        "hosts = [\"Proxy.Example.COM\", \"second.example.com\"]",
    );
    let config = load_config_from_temp_toml(&source);
    let runtime = config.web.runtime.as_ref().unwrap();
    assert_eq!(runtime.vhosts.len(), 2);
    assert_eq!(runtime.profiles.len(), 2);
    assert_eq!(runtime.capabilities.len(), 2);
    assert_ne!(runtime.capabilities[0], runtime.capabilities[1]);
    for host in ["proxy.example.com", "second.example.com"] {
        let legacy = load_config_from_temp_toml(&WEB_CONFIG.replace("Proxy.Example.COM", host));
        assert_eq!(
            runtime.vhosts[host].capabilities,
            legacy.web.runtime.as_ref().unwrap().vhosts[host].capabilities,
        );
    }
}

#[test]
fn grouped_profiles_share_policy_but_match_legacy_bindings() {
    for mode in ["plain", "dd"] {
        for base in ["", "MixedCase/path"] {
            let source = WEB_CONFIG
                .replace("secret_mode = \"dd\"", &format!("secret_mode = \"{mode}\""))
                .replace(
                    "public_addr =",
                    &format!("base_path = \"{base}\"\npublic_addr ="),
                );
            let grouped = load_config_from_temp_toml(&source.replace(
                "host = \"Proxy.Example.COM\"",
                "hosts = [\"Proxy.Example.COM\", \"second.example.com\"]",
            ));
            let runtime = grouped.web.runtime.as_ref().unwrap();
            let first = &runtime.vhosts["proxy.example.com"];
            let second = &runtime.vhosts["second.example.com"];
            assert!(Arc::ptr_eq(&first.decoy, &second.decoy));
            assert!(Arc::ptr_eq(
                &first.profiles[0].shared,
                &second.profiles[0].shared
            ));
            for host in ["proxy.example.com", "second.example.com"] {
                let legacy = load_config_from_temp_toml(&source.replace("Proxy.Example.COM", host));
                let expected = &legacy.web.runtime.as_ref().unwrap().vhosts[host];
                let actual = &runtime.vhosts[host];
                assert_eq!(actual.base, expected.base);
                assert_eq!(actual.capabilities, expected.capabilities);
                assert_eq!(actual.profiles[0].host, host);
                let actual = &actual.profiles[0].shared;
                let expected = &expected.profiles[0].shared;
                assert_eq!(actual.user, expected.user);
                assert_eq!(actual.credential_id, expected.credential_id);
                assert_eq!(actual.key_fingerprint, expected.key_fingerprint);
                assert_eq!(actual.public_addr, expected.public_addr);
                assert_eq!(actual.carriers, expected.carriers);
                assert_eq!(actual.max_sessions, expected.max_sessions);
                assert_eq!(actual.max_streams, expected.max_streams);
                assert_eq!(
                    actual.max_streams_per_session,
                    expected.max_streams_per_session
                );
            }
        }
    }
}

#[test]
fn host_selectors_reject_ambiguity_and_canonical_collisions() {
    for selector in [
        "",
        "host = \"\"",
        "hosts = []",
        "hosts = [\"\"]",
        "host = \"a.example.com\"\nhosts = []",
        "host = \"a.example.com\"\nhosts = [\"b.example.com\"]",
        "hosts = [\"a.example.com\", \"A.EXAMPLE.COM\"]",
        "hosts = [\"BÜCHER.example\", \"xn--bcher-kva.example\"]",
        "hosts = [\"*.example.com\"]",
        "hosts = [\"*\"]",
        "hosts = [\"127.0.0.1\"]",
        "hosts = [\"a.example.com:443\"]",
        "hosts = [\"a.example.com.\"]",
        "hosts = [\"a.example.com/path\"]",
    ] {
        let error = load_config_error_from_temp_toml(
            &WEB_CONFIG.replace("host = \"Proxy.Example.COM\"", selector),
        );
        assert!(error.contains("web.vhosts[0]"), "{selector}: {error}");
    }
    let group = WEB_CONFIG.replace(
        "host = \"Proxy.Example.COM\"",
        "hosts = [\"a.example.com\", \"proxy.example.com\"]",
    );
    let (_, legacy_vhost) = WEB_CONFIG.split_once("[[web.vhosts]]").unwrap();
    let error = load_config_error_from_temp_toml(&format!("{group}\n[[web.vhosts]]{legacy_vhost}"));
    assert!(error.contains("duplicate WEB vhost host `proxy.example.com` at web.vhosts[1].host"));
}

#[test]
fn host_selectors_round_trip_without_expanding_the_source() {
    for selector in [
        "host = \"Proxy.Example.COM\"",
        "hosts = [\"Proxy.Example.COM\"]",
        "hosts = [\"Proxy.Example.COM\", \"BÜCHER.example\"]",
    ] {
        let config = load_config_from_temp_toml(&format!(
            "[general]\nconfig_strict = true\n{}",
            WEB_CONFIG.replace("host = \"Proxy.Example.COM\"", selector),
        ));
        let value = serde_json::to_value(&config.web).unwrap();
        let vhosts = value["vhosts"].as_array().unwrap();
        assert_eq!(vhosts.len(), 1);
        if selector.starts_with("host =") {
            assert_eq!(vhosts[0]["host"], "proxy.example.com");
            assert!(vhosts[0].get("hosts").is_none());
        } else {
            assert!(vhosts[0].get("host").is_none());
            assert_eq!(vhosts[0]["hosts"][0], "proxy.example.com");
            if vhosts[0]["hosts"].as_array().unwrap().len() == 2 {
                assert_eq!(vhosts[0]["hosts"][1], "xn--bcher-kva.example");
            }
        }
        assert!(value.get("runtime").is_none());
        let mut document = toml::map::Map::new();
        document.insert(
            "web".to_string(),
            toml::Value::try_from(&config.web).unwrap(),
        );
        let prefix = WEB_CONFIG.split_once("[web]").unwrap().0;
        let round_trip = load_config_from_temp_toml(&format!(
            "[general]\nconfig_strict = true\n{prefix}{}",
            toml::to_string(&document).unwrap(),
        ));
        assert_eq!(round_trip.web.vhosts, config.web.vhosts);
    }
}

#[test]
fn expanded_host_profile_limits_apply_before_runtime_preparation() {
    let source = WEB_CONFIG.replace(
        "host = \"Proxy.Example.COM\"",
        "hosts = [\"a.example.com\", \"b.example.com\"]",
    );
    let source = format!(
        "{source}\n[[web.vhosts.profiles]]\nuser = \"alice\"\nsecret_mode = \"plain\"\n[web.limits]\nmax_vhosts = 2\nmax_profiles = 4\n"
    );
    let config = load_config_from_temp_toml(&source);
    let runtime = config.web.runtime.as_ref().unwrap();
    assert_eq!(runtime.vhosts.len(), 2);
    assert_eq!(runtime.profiles.len(), 4);
    assert_eq!(runtime.capabilities.len(), 4);
    assert_eq!(
        runtime
            .profiles
            .iter()
            .map(|profile| profile.host.as_str())
            .collect::<Vec<_>>(),
        [
            "a.example.com",
            "a.example.com",
            "b.example.com",
            "b.example.com"
        ]
    );
    assert!(!Arc::ptr_eq(
        &runtime.profiles[0].shared,
        &runtime.profiles[1].shared
    ));
    assert!(
        load_config_error_from_temp_toml(&source.replace("max_vhosts = 2", "max_vhosts = 1"))
            .contains("max_vhosts")
    );
    assert!(
        load_config_error_from_temp_toml(&source.replace("max_profiles = 4", "max_profiles = 3"))
            .contains("max_profiles")
    );
    let invalid_origin = source.replace("http://127.0.0.1:18081", "http://example.com:18081");
    assert!(
        load_config_error_from_temp_toml(
            &invalid_origin.replace("max_profiles = 4", "max_profiles = 3")
        )
        .contains("max_profiles")
    );
}

#[test]
fn grouped_static_snapshot_is_loaded_and_charged_once() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("index.html"), b"hello").unwrap();
    let source = WEB_CONFIG
        .replace(
            "host = \"Proxy.Example.COM\"",
            "hosts = [\"a.example.com\", \"b.example.com\"]",
        )
        .replace(
            "mode = \"http_upstream\"\nupstream = \"http://127.0.0.1:18081\"",
            &format!(
                "mode = \"static_directory\"\ndirectory = {:?}",
                directory.path()
            ),
        );
    let limits =
        "\n[web.limits]\nmax_static_files = 1\nmax_static_file_bytes = 5\nmax_static_bytes = 5\n";
    let config = load_config_from_temp_toml(&format!("{source}{limits}"));
    let runtime = config.web.runtime.as_ref().unwrap();
    let a = &runtime.vhosts["a.example.com"];
    let b = &runtime.vhosts["b.example.com"];
    assert!(Arc::ptr_eq(&a.decoy, &b.decoy));
    let WebRuntimeDecoy::StaticDirectory(site) = a.decoy.as_ref() else {
        panic!("static decoy");
    };
    assert_eq!(site.assets["/index.html"].body.as_ref(), b"hello");
    let (prefix, group) = source.split_once("[[web.vhosts]]").unwrap();
    let selector = "hosts = [\"a.example.com\", \"b.example.com\"]";
    let separate = format!(
        "{prefix}[[web.vhosts]]{}\n[[web.vhosts]]{}{limits}",
        group.replace(selector, "host = \"a.example.com\""),
        group.replace(selector, "host = \"b.example.com\"")
    );
    assert!(load_config_error_from_temp_toml(&separate).contains("max_static"));
    let expanded = load_config_from_temp_toml(
        &separate
            .replace("max_static_files = 1", "max_static_files = 2")
            .replace("max_static_bytes = 5", "max_static_bytes = 10"),
    );
    let expanded = expanded.web.runtime.as_ref().unwrap();
    assert!(!Arc::ptr_eq(
        &expanded.vhosts["a.example.com"].decoy,
        &expanded.vhosts["b.example.com"].decoy
    ));
    assert!(!Arc::ptr_eq(
        &expanded.profiles[0].shared,
        &expanded.profiles[1].shared
    ));
    std::fs::write(directory.path().join("index.html"), b"longer").unwrap();
    assert!(load_config_error_from_temp_toml(&format!("{source}{limits}")).contains("max_static"));
}
