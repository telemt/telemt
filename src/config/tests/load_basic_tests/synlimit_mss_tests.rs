use super::*;

#[cfg(target_os = "linux")]
#[test]
fn synlimit_synfix_defaults_are_loaded_for_listener() {
    let cfg = load_config_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[server.listeners]]
            ip = "0.0.0.0"
            port = 443
            synlimit = "iptables"
        "#,
    );

    let listener = &cfg.server.listeners[0];
    assert_eq!(listener.synlimit_seconds, 60);
    assert_eq!(listener.synlimit_hitcount, 48);
    assert_eq!(listener.synlimit_burst, 24);
    assert_eq!(listener.synlimit_ios_seconds, 1);
    assert_eq!(listener.synlimit_ios_hitcount, 12);
    assert_eq!(listener.synlimit_ios_burst, 24);
    assert_eq!(listener.synlimit_hashlimit_expire_ms, 60_000);
    assert_eq!(listener.synlimit_hashlimit_size, 32_768);
}

#[cfg(target_os = "freebsd")]
#[test]
fn synlimit_pf_mode_is_loaded_for_listener() {
    let cfg = load_config_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[server.listeners]]
            ip = "0.0.0.0"
            port = 443
            synlimit = "pf"
        "#,
    );

    assert_eq!(cfg.server.listeners[0].synlimit, SynLimitMode::Pf);
}

#[cfg(not(target_os = "freebsd"))]
#[test]
fn synlimit_pf_mode_is_rejected_off_freebsd() {
    let toml = r#"
        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"

        [[server.listeners]]
        ip = "0.0.0.0"
        port = 443
        synlimit = "pf"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_synlimit_pf_unsupported_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(err.contains("backend pf is unsupported on this platform"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn synlimit_synfix_zero_values_are_rejected() {
    for (field, expected) in [
        (
            "synlimit_ios_seconds",
            "server.listeners[0].synlimit_ios_seconds must be > 0",
        ),
        (
            "synlimit_ios_hitcount",
            "server.listeners[0].synlimit_ios_hitcount must be > 0",
        ),
        (
            "synlimit_ios_burst",
            "server.listeners[0].synlimit_ios_burst must be > 0",
        ),
        (
            "synlimit_hashlimit_expire_ms",
            "server.listeners[0].synlimit_hashlimit_expire_ms must be > 0",
        ),
        (
            "synlimit_hashlimit_size",
            "server.listeners[0].synlimit_hashlimit_size must be > 0",
        ),
    ] {
        let toml = format!(
            r#"
                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"

                [[server.listeners]]
                ip = "0.0.0.0"
                port = 443
                synlimit = "iptables"
                {field} = 0
            "#
        );
        let error = load_config_error_from_temp_toml(&toml);
        assert!(error.contains(expected), "{field}: {error}");
    }
}

#[test]
fn client_mss_presets_and_listener_override_are_resolved() {
    let toml = r#"
        [server]
        client_mss = "tspu"

        [[server.listeners]]
        ip = "127.0.0.1"
        port = 1443

        [[server.listeners]]
        ip = "127.0.0.2"
        port = 1444
        client_mss = "2in8"

        [[server.listeners]]
        ip = "127.0.0.3"
        port = 1445
        client_mss = ""

        [[server.listeners]]
        ip = "127.0.0.4"
        port = 1446
        client_mss = "extreme-low"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_client_mss_valid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();

    assert_eq!(cfg.server.client_mss_value(), Ok(Some(92)));
    assert_eq!(
        cfg.server.listeners[0].effective_client_mss(&cfg.server),
        Ok(Some(92))
    );
    assert_eq!(
        cfg.server.listeners[1].effective_client_mss(&cfg.server),
        Ok(Some(256))
    );
    assert_eq!(
        cfg.server.listeners[2].effective_client_mss(&cfg.server),
        Ok(None)
    );
    assert_eq!(
        cfg.server.listeners[3].effective_client_mss(&cfg.server),
        Ok(Some(88))
    );
    let _ = std::fs::remove_file(path);
}

#[cfg(target_os = "linux")]
#[test]
fn client_mss_custom_value_is_accepted() {
    let toml = r#"
        [server]
        client_mss = "92"
        client_mss_bulk = "1400"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_client_mss_custom_valid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();

    assert_eq!(cfg.server.client_mss_value(), Ok(Some(92)));
    assert_eq!(cfg.server.client_mss_bulk_value(), Ok(Some(1400)));
    let _ = std::fs::remove_file(path);
}

#[cfg(target_os = "linux")]
#[test]
fn client_mss_bulk_requires_a_larger_bulk_profile_and_handshake_participant() {
    for (name, server, expected) in [
        (
            "without_handshake",
            "client_mss_bulk = \"1400\"",
            "requires an effective client_mss",
        ),
        (
            "equal",
            "client_mss = \"1400\"\nclient_mss_bulk = \"1400\"",
            "must be greater than the effective handshake MSS",
        ),
        (
            "inverted",
            "client_mss = \"1500\"\nclient_mss_bulk = \"1400\"",
            "must be greater than the effective handshake MSS",
        ),
    ] {
        let toml = format!(
            "[server]\n{server}\n\n[censorship]\ntls_domain = \"example.com\"\n\n[access.users]\nuser = \"00000000000000000000000000000000\"\n"
        );
        let dir = std::env::temp_dir();
        let path = dir.join(format!("telemt_client_mss_bulk_{name}_test.toml"));
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains(expected), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn client_mss_bulk_allows_explicit_listener_opt_out() {
    let toml = r#"
        [server]
        client_mss = "92"
        client_mss_bulk = "1400"

        [[server.listeners]]
        ip = "0.0.0.0"
        port = 443

        [[server.listeners]]
        ip = "::"
        port = 443
        client_mss = ""

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_client_mss_bulk_listener_opt_out_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();

    assert_eq!(
        cfg.server.listeners[0].effective_client_mss(&cfg.server),
        Ok(Some(92))
    );
    assert_eq!(
        cfg.server.listeners[1].effective_client_mss(&cfg.server),
        Ok(None)
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn client_mss_out_of_range_is_rejected() {
    for value in ["87", "4097"] {
        let toml = format!(
            r#"
            [server]
            client_mss = "{value}"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#
        );
        let dir = std::env::temp_dir();
        let path = dir.join(format!("telemt_client_mss_out_of_range_{value}_test.toml"));
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("server.client_mss custom value must be within [88, 4096]"));
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn client_mss_bulk_out_of_range_is_rejected() {
    for value in ["87", "4097"] {
        let toml = format!(
            r#"
            [server]
            client_mss_bulk = "{value}"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#
        );
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "telemt_client_mss_bulk_out_of_range_{value}_test.toml"
        ));
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("server.client_mss_bulk custom value must be within [88, 4096]"));
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn client_mss_unquoted_number_is_rejected() {
    let toml = r#"
        [server]
        client_mss = 256

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_client_mss_unquoted_number_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(err.contains("client_mss"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn listener_client_mss_invalid_preset_is_rejected() {
    let toml = r#"
        [[server.listeners]]
        ip = "127.0.0.1"
        port = 1443
        client_mss = "tiny"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_listener_client_mss_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(err.contains("server.listeners[0].client_mss"));
    assert!(err.contains("must be \"\", extreme-low, tspu, 2in8"));
    let _ = std::fs::remove_file(path);
}
