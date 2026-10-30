use super::*;

#[test]
fn quota_period_reload_is_hot_and_invalid_candidates_preserve_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let source = "[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n[access.user_data_quota]\nalice = 1024\n";
    std::fs::write(&path, source).unwrap();
    let initial = Arc::new(ProxyConfig::load(&path).unwrap());
    let (config_tx, _config_rx) = watch::channel(initial.clone());
    let (log_tx, _log_rx) = watch::channel(initial.general.log_level.clone());
    let mut state = ReloadState::new(None);
    for (period, valid) in [
        (Some("daily"), true),
        (Some("monthly"), true),
        (Some("yearly"), false),
        (None, true),
    ] {
        let suffix = period
            .map(|p| format!("[access.user_quota_periods]\nalice = '{p}'\n"))
            .unwrap_or_default();
        std::fs::write(&path, format!("{source}{suffix}")).unwrap();
        let before = config_tx.borrow().clone();
        reload_config(&path, &config_tx, &log_tx, None, None, &mut state);
        let after = config_tx.borrow().clone();
        if valid {
            let json = serde_json::to_value(after.access.user_quota_periods.get("alice")).unwrap();
            assert_eq!(json, serde_json::to_value(period).unwrap());
        } else {
            assert!(Arc::ptr_eq(&before, &after));
        }
    }
}
