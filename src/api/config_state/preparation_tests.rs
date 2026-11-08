use super::*;

const WEB: &str = r#"
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

#[tokio::test]
async fn inspection_does_not_acquire_decoy_dns_or_static_files() {
    let (fixture, _sender) = fixture(WEB, true).await;
    source(
        &fixture,
        &WEB.replace(
            "http://127.0.0.1:18081",
            "http://unresolvable.invalid:18081",
        )
        .replace(
            "[[web.vhosts.profiles]]",
            "resolve = 'startup'\n[[web.vhosts.profiles]]",
        ),
        true,
    );
    let data = inspect(&fixture, Some("sections=web")).await;
    assert_eq!(data["desired_status"], "valid");
    assert_eq!(
        field(&data, "desired", "web.vhosts[0].decoy.upstream")["redacted"],
        true
    );
    assert_eq!(data["comparison"]["status"], "pending_publication");

    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("index.html"),
        "private synthetic asset",
    )
    .unwrap();
    let static_source = WEB.replace(
        "mode = \"http_upstream\"\nupstream = \"http://127.0.0.1:18081\"",
        &format!(
            "mode = 'static_directory'\ndirectory = '{}'\nindex = 'index.html'",
            directory.path().display()
        ),
    );
    let (fixture, _sender) = self::fixture(&static_source, true).await;
    directory.close().unwrap();
    assert!(
        ProxyConfig::load_prepared(fixture.shared.config_path.clone())
            .await
            .is_err()
    );
    let data = inspect(&fixture, None).await;
    assert_eq!(data["desired_status"], "valid");
    assert_eq!(data["comparison"]["status"], "published_match");
    assert_eq!(data["subsystem_convergence"], "unknown");
    assert!(!data.to_string().contains("private synthetic asset"));
}

#[tokio::test]
async fn conditional_web_capacity_and_includes_preserve_source_evidence() {
    let (fixture, _sender) = fixture("[web.limits]\ndebug_bytes_global=4096", true).await;
    source(
        &fixture,
        "[web.limits]\ndebug_bytes_global=8192\n[web.debug]\nbody_prefix_bytes=6144",
        true,
    );
    let data = inspect(&fixture, Some("sections=web")).await;
    assert_eq!(data["comparison"]["status"], "process_deferred");
    assert!(
        data["comparison"]["process_deferred_paths"]
            .as_array()
            .unwrap()
            .contains(&json!("web.debug.body_prefix_bytes"))
    );
    assert!(
        data["comparison"]["deferred_process_fields"]
            .as_array()
            .unwrap()
            .contains(&json!("web.debug"))
    );
    source(&fixture, "include = \"extra.toml\"", true);
    std::fs::write(
        fixture
            .shared
            .config_path
            .parent()
            .unwrap()
            .join("extra.toml"),
        "[general]\nlog_level='debug'",
    )
    .unwrap();
    let data = inspect(&fixture, Some("sections=general")).await;
    assert_eq!(data["desired"]["source_count"], 2);
    assert_eq!(
        field(&data, "desired", "general.log_level")["origin"],
        "source"
    );
    assert!(!data.to_string().contains("extra.toml"));
}

#[test]
fn projection_fails_closed_for_arbitrary_strings_unknown_fields_and_private_maps() {
    let config = ProxyConfig::default();
    let raw = json!({"general":{"proxy_secret_url":"https://private-user:private-pass@example.invalid/key", "unknown_field":"private-value"},
        "access":{"user_rate_limits":{"private-name":{"up_bps":12345}}},
        "dc_overrides":{"private-dc":{"address":"private-value"}}});
    let scope = sections(None).unwrap();
    let projection = projection::project(&config, &raw, Some(&json!({})), &scope, false).unwrap();
    let result = serde_json::to_value(projection).unwrap();
    for value in [
        "private-user",
        "private-pass",
        "example.invalid",
        "private-value",
        "private-name",
        "private-dc",
        "12345",
    ] {
        assert!(!result.to_string().contains(value));
    }
    assert!(
        result["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| field["redacted"] == true && field.get("value").is_none())
    );
}
