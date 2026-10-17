use super::*;

#[tokio::test]
async fn wildcard_api_stages_restart_and_rejects_patterns_atomically_until_enabled() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, source()).unwrap();
    let active = ProxyConfig::load(&path).unwrap();
    let enable = serde_json::json!({"web": {"allow_wildcard_hosts": true,
        "limits": {"memory_envelope_bytes": 1610612736u64}}});
    let mut prepared = prepare_patch_to_path(&path, &enable, None).await.unwrap();
    let resolved =
        reconcile_runtime_effect(&mut prepared.response, &active, &prepared.desired_config)
            .unwrap();
    assert!(prepared.response.process_restart_required);
    assert!(
        prepared
            .response
            .deferred_process_fields
            .iter()
            .any(|field| field == "web.allow_wildcard_hosts")
    );
    assert!(!resolved.effective.web.allow_wildcard_hosts);
    write_atomic_if_unchanged(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
    )
    .await
    .unwrap();
    let staged = ProxyConfig::load(&path).unwrap();
    assert!(staged.web.allow_wildcard_hosts);
    let before = std::fs::read(&path).unwrap();
    let revision = read_managed_config(&path).await.unwrap().1;
    let mut prepared =
        prepare_patch_to_path(&path, &patch(&["*.example.com"]), Some(revision.clone()))
            .await
            .unwrap();
    let rejected =
        reconcile_runtime_effect(&mut prepared.response, &active, &prepared.desired_config)
            .err()
            .unwrap();
    assert_eq!(rejected.status, hyper::StatusCode::BAD_REQUEST);
    assert!(rejected.message.contains("allow_wildcard_hosts"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(read_managed_config(&path).await.unwrap().1, revision);
    // The same reviewed candidate becomes reloadable after the staged process restart.
    let resolved =
        reconcile_runtime_effect(&mut prepared.response, &staged, &prepared.desired_config)
            .unwrap();
    assert!(resolved.runtime_changed);
    assert!(!prepared.response.process_restart_required);
    assert!(
        resolved
            .effective
            .web
            .runtime
            .as_ref()
            .unwrap()
            .wildcards
            .contains_key("example.com")
    );
    write_atomic_if_unchanged(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
    )
    .await
    .unwrap();
    assert!(
        ProxyConfig::load(&path)
            .unwrap()
            .web
            .runtime
            .as_ref()
            .unwrap()
            .vhosts
            .is_empty()
    );
}
