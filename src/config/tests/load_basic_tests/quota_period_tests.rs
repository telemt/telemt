use super::*;

#[test]
fn quota_period_configuration_survives_round_trip() {
    let cfg: ProxyConfig = toml::from_str(
        r#"
        [access.users]
        alice = "0123456789abcdef0123456789abcdef"
        [access.user_data_quota]
        alice = 1024
        [access.user_quota_periods]
        alice = "monthly"
    "#,
    )
    .unwrap();
    let encoded = serde_json::to_value(&cfg).unwrap();
    assert_eq!(encoded["access"]["user_quota_periods"]["alice"], "monthly");
}

#[test]
fn quota_period_requires_a_configured_positive_quota_in_both_validation_paths() {
    for tail in [
        "[access.user_quota_periods]\nghost = 'daily'\n",
        "[access.user_quota_periods]\nalice = 'daily'\n",
        "[access.user_data_quota]\nalice = 0\n[access.user_quota_periods]\nalice = 'daily'\n",
    ] {
        let source = format!("[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n{tail}");
        let cfg: ProxyConfig = toml::from_str(&source).unwrap();
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("user_quota_periods")
        );
        assert!(load_config_error_from_temp_toml(&source).contains("user_quota_periods"));
    }
    for period in ["daily", "weekly", "monthly"] {
        let source = format!(
            "[general]\nconfig_strict = true\n[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n[access.user_data_quota]\nalice = 1024\n[access.user_quota_periods]\nalice = '{period}'\n"
        );
        assert_eq!(
            load_config_from_temp_toml(&source)
                .access
                .user_quota_periods
                .len(),
            1
        );
    }
}

#[test]
fn quota_period_tokens_are_strict_and_inventory_is_bounded() {
    for token in ["'Daily'", "'yearly'", "42", "true"] {
        assert!(
            toml::from_str::<ProxyConfig>(&format!("[access.user_quota_periods]\nalice = {token}"))
                .is_err()
        );
    }
    let mut cfg = ProxyConfig::default();
    assert!(cfg.access.user_quota_periods.is_empty());
    cfg.access.users = (0..65_537)
        .map(|n| (format!("u{n}"), "0123456789abcdef0123456789abcdef".into()))
        .collect();
    cfg.access.user_data_quota.insert("u0".into(), 1);
    cfg.access
        .user_quota_periods
        .insert("u0".into(), crate::config::UserQuotaPeriod::Daily);
    assert!(cfg.validate().unwrap_err().to_string().contains("65536"));
}
