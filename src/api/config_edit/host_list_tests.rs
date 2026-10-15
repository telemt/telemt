use super::*;

fn source() -> &'static str {
    r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[web]
enabled = true
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[[web.vhosts]]
host = "a.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#
}

fn patch(hosts: &[&str]) -> Json {
    serde_json::json!({"web": {"vhosts": [{
        "hosts": hosts,
        "public_addr": "203.0.113.10:443",
        "base_path": "MixedCase/path",
        "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:18081"},
        "profiles": [{"user": "alice", "secret_mode": "dd"}]
    }]}})
}

#[tokio::test]
async fn grouped_hosts_patch_preserves_source_shape_and_revision_guards() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, source()).unwrap();
    let initial = ProxyConfig::load(&path).unwrap();
    let (legacy, revision) = read_managed_config(&path).await.unwrap();
    assert_eq!(
        legacy["web"]["vhosts"][0]["host"].as_str(),
        Some("a.example.com")
    );
    assert!(legacy["web"]["vhosts"][0].get("hosts").is_none());
    let mut response = apply_patch_to_path(
        &path,
        &patch(&["A.Example.COM", "b.example.com"]),
        Some(revision.clone()),
    )
    .await
    .unwrap();
    let desired = ProxyConfig::load(&path).unwrap();
    let resolved = reconcile_runtime_effect(&mut response, &initial, &desired).unwrap();
    assert!(resolved.runtime_changed);
    assert!(response.runtime_reload_required);
    assert!(!response.process_restart_required);
    assert_eq!(
        resolved
            .effective
            .web
            .runtime
            .as_ref()
            .unwrap()
            .profiles
            .len(),
        2
    );
    let (managed, after_revision) = read_managed_config(&path).await.unwrap();
    assert_eq!(managed["web"]["vhosts"].as_array().unwrap().len(), 1);
    let group = &managed["web"]["vhosts"][0];
    assert!(group.get("host").is_none());
    assert_eq!(group["hosts"][0].as_str(), Some("a.example.com"));
    assert_eq!(group["hosts"][1].as_str(), Some("b.example.com"));
    assert!(managed["web"].get("runtime").is_none());
    assert!(!toml::to_string(&managed).unwrap().contains("shared"));
    assert!(managed.get("access").is_none());
    let before = std::fs::read(&path).unwrap();
    for hosts in [vec![], vec!["a.example.com", "A.example.com"], vec!["*"]] {
        let error = apply_patch_to_path(&path, &patch(&hosts), Some(after_revision.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(read_managed_config(&path).await.unwrap().1, after_revision);
    }
    let conflict = apply_patch_to_path(&path, &patch(&["c.example.com"]), Some(revision))
        .await
        .unwrap_err();
    assert_eq!(conflict.code, "revision_conflict");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    apply_patch_to_path(&path, &patch(&["b.example.com"]), Some(after_revision))
        .await
        .unwrap();
    let replaced = ProxyConfig::load(&path).unwrap();
    let runtime = replaced.web.runtime.as_ref().unwrap();
    assert_eq!(runtime.vhosts.len(), 1);
    assert!(!runtime.vhosts.contains_key("a.example.com"));
}

#[tokio::test]
async fn grouped_hosts_cannot_bypass_frozen_process_limits() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "{}\n[web.limits]\nmax_vhosts = 1\nmax_profiles = 1\n",
            source()
        ),
    )
    .unwrap();
    let active = ProxyConfig::load(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    for (hosts, host_limit, profile_limit, error_field) in [
        (vec!["a.example.com", "b.example.com"], 2, 2, "max_vhosts"),
        (vec!["a.example.com"], 1, 2, "max_profiles"),
    ] {
        let mut candidate = patch(&hosts);
        candidate["web"]["limits"] =
            serde_json::json!({"max_vhosts": host_limit, "max_profiles": profile_limit});
        if hosts.len() == 1 {
            candidate["web"]["vhosts"][0]["profiles"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"user": "alice", "secret_mode": "plain"}));
        }
        let error = prepare_patch_to_path(&path, &candidate, None)
            .await
            .err()
            .expect("expanded config must respect active process limits");
        assert!(error.message.contains(error_field), "{error:?}");
        assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    assert_eq!(active.web.runtime.as_ref().unwrap().vhosts.len(), 1);
}
