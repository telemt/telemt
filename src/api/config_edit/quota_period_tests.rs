use super::*;

#[tokio::test]
async fn quota_periods_do_not_enable_access_mutation_through_generic_config_patch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let body = "[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n";
    std::fs::write(&path, body).unwrap();
    let error = apply_patch_to_path(
        &path,
        &serde_json::json!({"access":{"user_quota_periods":{"alice":"daily"}}}),
        None,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.code, "access_not_editable");
    assert_eq!(std::fs::read_to_string(path).unwrap(), body);
}
