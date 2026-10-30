use super::*;

#[test]
fn wildcard_opt_in_accepts_shared_pattern_without_exact_expansion() {
    let source = WEB_CONFIG
        .replace("[web]", "[web]\nallow_wildcard_hosts = true")
        .replace("Proxy.Example.COM", "*.Example.COM")
        .replace(
            "[[web.vhosts]]",
            "[web.limits]\nmemory_envelope_bytes = 1610612736\n[[web.vhosts]]",
        );
    let config = load_config_from_temp_toml(&source);
    assert_eq!(config.web.vhosts[0].host.as_deref(), Some("*.example.com"));
    let runtime = config.web.runtime.as_ref().unwrap();
    assert!(runtime.vhosts.is_empty());
    assert!(runtime.profiles.is_empty());
    assert!(runtime.capabilities.is_empty());
}

fn wildcard_source(selector: &str) -> String {
    WEB_CONFIG
        .replace("[web]", "[web]\nallow_wildcard_hosts = true")
        .replace("host = \"Proxy.Example.COM\"", selector)
        .replace(
            "[[web.vhosts]]",
            "[web.limits]\nmemory_envelope_bytes = 1610612736\n[[web.vhosts]]",
        )
}

#[test]
fn wildcard_selector_bounds_precedence_and_shared_inventory() {
    let source = wildcard_source(
        "hosts = [\"*.Example.COM\", \"*.deep.example.com\", \"exact.example.com\", \"*\"]",
    );
    let config = load_config_from_temp_toml(&source);
    let runtime = config.web.runtime.as_ref().unwrap();
    assert_eq!(runtime.vhosts.len(), 1);
    assert_eq!(runtime.profiles.len(), 1);
    assert_eq!(runtime.wildcards.len(), 2);
    assert!(std::sync::Arc::ptr_eq(
        &runtime.wildcards["example.com"],
        &runtime.wildcards["deep.example.com"]
    ));
    assert!(
        runtime
            .route("exact.example.com")
            .unwrap()
            .wildcard
            .is_none()
    );
    assert!(std::sync::Arc::ptr_eq(
        runtime.route("a.deep.example.com").unwrap(),
        &runtime.wildcards["deep.example.com"]
    ));
    assert!(std::sync::Arc::ptr_eq(
        runtime.route("example.com").unwrap(),
        runtime.catch_all.as_ref().unwrap()
    ));
    let repeated = load_config_from_temp_toml(&source);
    assert_ne!(
        runtime.snapshot_id,
        repeated.web.runtime.as_ref().unwrap().snapshot_id
    );
    // Exact bindings plus one common wildcard profile set consume two slots.
    let bounded = source.replace(
        "memory_envelope_bytes = 1610612736",
        "memory_envelope_bytes = 1610612736\nmax_vhosts = 1\nmax_profiles = 2",
    );
    load_config_from_temp_toml(&bounded);
    assert!(
        load_config_error_from_temp_toml(&bounded.replace("max_profiles = 2", "max_profiles = 1"))
            .contains("max_profiles")
    );
}

#[test]
fn wildcard_configuration_rejects_ambiguous_selectors_and_resource_exhaustion() {
    for selector in [
        "foo*.example.com",
        "**.example.com",
        "*.127.0.0.1",
        "*.example.com.",
        "*.example.com:443",
        "*.*.example.com",
    ] {
        assert!(
            !load_config_error_from_temp_toml(&wildcard_source(&format!("host = \"{selector}\"")))
                .is_empty()
        );
    }
    assert!(
        load_config_error_from_temp_toml(&wildcard_source(
            "hosts = [\"*.EXAMPLE.com\", \"*.example.com\"]"
        ))
        .contains("duplicate")
    );
    assert!(
        load_config_error_from_temp_toml(&wildcard_source("host = \"*.example.com\"").replace(
            "allow_wildcard_hosts = true",
            "allow_wildcard_hosts = false"
        ))
        .contains("allow_wildcard_hosts")
    );
    for limits in [
        "max_rules = 0",
        "max_rules = 9223372036854775807",
        "max_profiles_per_request = 0",
        "cache_bytes = 0",
        "cold_hmac_per_minute = 0",
        "cold_hmac_burst = 255",
        "max_profiles_per_request = 9223372036854775807",
    ] {
        let source = format!(
            "{}\n[web.limits.wildcard]\n{limits}\n",
            wildcard_source("host = \"*.example.com\"")
        );
        assert!(
            load_config_error_from_temp_toml(&source).contains("wildcard"),
            "{limits}"
        );
    }
    let source = format!(
        "[general]\nconfig_strict = true\n{}\n[web.limits.wildcard]\ncache_hosts = 0\n",
        wildcard_source("host = \"*.example.com\"")
    );
    load_config_from_temp_toml(&source);
    assert!(
        load_config_error_from_temp_toml(&source.replace("cache_hosts", "cache_hostz"))
            .contains("cache_hostz")
    );
}

#[test]
fn wildcard_context_matches_exact_protocol_and_fences_reload_changes() {
    let source = wildcard_source("hosts = [\"proxy.example.com\", \"*.example.com\"]");
    let config = load_config_from_temp_toml(&source);
    let runtime = config.web.runtime.as_ref().unwrap();
    let template = &runtime.wildcards["example.com"];
    assert_eq!(
        config
            .wildcard_capabilities(template, "proxy.example.com")
            .unwrap()[0],
        runtime.profiles[0].capability
    );
    let context = template.wildcard.as_ref().unwrap().profiles[0].derivation_context;
    for changed in [
        source.replace("secret_mode = \"dd\"", "secret_mode = \"plain\""),
        source.replace("public_addr =", "base_path = \"relay\"\npublic_addr ="),
        source.replace(
            "000102030405060708090a0b0c0d0e0f",
            "100102030405060708090a0b0c0d0e0f",
        ),
    ] {
        let changed = load_config_from_temp_toml(&changed);
        let changed_context = changed.web.runtime.as_ref().unwrap().wildcards["example.com"]
            .wildcard
            .as_ref()
            .unwrap()
            .profiles[0]
            .derivation_context;
        assert_ne!(context, changed_context);
    }
    let changed =
        load_config_from_temp_toml(&source.replace("max_sessions = 4", "max_sessions = 5"));
    assert_eq!(
        context,
        changed.web.runtime.as_ref().unwrap().profiles[0]
            .shared
            .derivation_context
    );
}
