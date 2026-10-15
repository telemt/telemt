use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const SOURCE: &str = r#"
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
upstream = "http://Example.COM:18081"
resolve = "startup"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#;

fn source(text: &str) -> ParsedConfigSource {
    pipeline::parse_source_graph(ConfigSourceGraph {
        rendered: text.to_string(),
        source_contents: BTreeMap::new(),
    })
    .unwrap()
}

async fn prepared(answers: &[&str]) -> LoadedConfig {
    let mut parsed = source(SOURCE);
    let answers: Vec<SocketAddr> = answers.iter().map(|addr| addr.parse().unwrap()).collect();
    prepare(&mut parsed.config, |_, _| {
        std::future::ready(Ok(answers.clone()))
    })
    .await
    .unwrap();
    pipeline::finish(parsed).unwrap()
}

fn endpoint(config: &ProxyConfig) -> (SocketAddr, &str) {
    let runtime = config.web.runtime.as_ref().unwrap();
    match runtime.vhosts["proxy.example.com"].decoy.as_ref() {
        WebRuntimeDecoy::HttpUpstream { addr, authority } => (*addr, authority),
        _ => panic!("expected HTTP decoy"),
    }
}

#[tokio::test]
async fn decoy_dns_snapshot_deduplicates_normalized_origins_and_preserves_order() {
    let mut parsed = source(SOURCE);
    let mut second = parsed.config.web.vhosts[0].clone();
    second.host = Some("bsi.bund.de".to_string());
    second.decoy = WebDecoyConfig::HttpUpstream {
        upstream: "http://example.com:18081/".to_string(),
        resolve: WebDecoyResolve::Startup,
    };
    parsed.config.web.vhosts.push(second);
    let calls = AtomicUsize::new(0);
    prepare(&mut parsed.config, |host, port| {
        assert_eq!((host.as_str(), port), ("example.com", 18081));
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(vec![
            "[fd00::2]:18081".parse().unwrap(),
            "10.0.0.2:18081".parse().unwrap(),
        ]))
    })
    .await
    .unwrap();
    let mut loaded = pipeline::finish(parsed).unwrap();
    for _ in 0..3 {
        loaded.config.validate_effective_web().unwrap();
        loaded.config.rebuild_runtime_web().unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        endpoint(&loaded.config),
        ("[fd00::2]:18081".parse().unwrap(), "example.com:18081")
    );
    assert_eq!(
        loaded
            .config
            .web
            .decoy_dns
            .origins
            .values()
            .next()
            .unwrap()
            .len(),
        2
    );
    assert!(
        !serde_json::to_string(&loaded.config)
            .unwrap()
            .contains("fd00::2")
    );
}

#[tokio::test]
async fn decoy_dns_rejects_every_public_answer_including_non_selected() {
    for disallowed in [
        "8.8.8.8:18081",
        "[2001:4860:4860::8888]:18081",
        "[::ffff:127.0.0.1]:18081",
    ] {
        let mut parsed = source(SOURCE);
        let error = prepare(&mut parsed.config, |_, _| {
            std::future::ready(Ok(vec![
                "127.0.0.2:18081".parse().unwrap(),
                disallowed.parse().unwrap(),
            ]))
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("must remain inside"));
        assert!(parsed.config.web.runtime.is_none());
    }
}

#[tokio::test]
async fn decoy_dns_rejects_non_selected_direct_and_wildcard_listener_loops() {
    for listener in ["127.0.0.1", "0.0.0.0"] {
        let mut parsed = source(&SOURCE.replace("Example.COM:18081", "example.com:18080"));
        parsed.config.server.listeners[0].ip = listener.parse().unwrap();
        let error = prepare(&mut parsed.config, |_, _| {
            std::future::ready(Ok(vec![
                "[fd00::2]:18080".parse().unwrap(),
                "127.0.0.1:18080".parse().unwrap(),
            ]))
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("overlaps WEB listener"));
    }
}

#[tokio::test]
async fn decoy_dns_empty_answers_and_resolver_errors_fail_closed() {
    let mut parsed = source(SOURCE);
    let error = prepare(&mut parsed.config, |_, _| {
        std::future::ready(Ok(Vec::new()))
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("returned no addresses"));
    let error = prepare(&mut parsed.config, |_, _| {
        std::future::ready(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "test resolver failure",
        )))
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("DNS resolution failed"));
}

#[tokio::test]
async fn decoy_dns_timeout_is_bounded() {
    let mut parsed = source(SOURCE);
    parsed.config.web.timeouts.decoy_resolve_secs = 1;
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        prepare(&mut parsed.config, |_, _| {
            std::future::pending::<std::io::Result<Vec<SocketAddr>>>()
        }),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("timed out after 1 seconds"));
}

#[tokio::test]
async fn decoy_dns_literal_startup_never_looks_up_and_keeps_ipv6_authority() {
    let mut parsed = source(&SOURCE.replace("Example.COM:18081", "[::1]:18081"));
    prepare(&mut parsed.config, |_, _| {
        std::future::ready(Err(std::io::Error::other("IP literals must not reach DNS")))
    })
    .await
    .unwrap();
    let loaded = pipeline::finish(parsed).unwrap();
    assert_eq!(
        endpoint(&loaded.config),
        ("[::1]:18081".parse().unwrap(), "[::1]:18081")
    );
}

#[test]
fn decoy_dns_source_parse_is_not_a_prepared_runtime() {
    let parsed = source(SOURCE);
    assert!(parsed.config.web.runtime.is_none());
    assert!(parsed.config.web.decoy_dns.origins.is_empty());
    assert!(
        pipeline::finish(parsed)
            .unwrap_err()
            .to_string()
            .contains("requires async preparation")
    );
}

#[tokio::test]
async fn decoy_dns_evidence_is_bound_to_origin_and_port() {
    let loaded = prepared(&["10.0.0.2:18081"]).await;
    for changed in ["http://telekom.com:18081", "http://example.com:18082"] {
        let mut config = loaded.config.clone();
        config.web.vhosts[0].decoy = WebDecoyConfig::HttpUpstream {
            upstream: changed.to_string(),
            resolve: WebDecoyResolve::Startup,
        };
        assert!(
            config
                .validate_effective_web()
                .unwrap_err()
                .to_string()
                .contains("requires async preparation")
        );
        assert!(config.rebuild_runtime_web().is_err());
    }
}

#[tokio::test]
async fn decoy_dns_reload_pins_old_generation_and_detects_dns_only_changes() {
    let old = prepared(&["10.0.0.2:18081"]).await;
    let new = prepared(&["10.0.0.3:18081"]).await;
    assert_eq!(old.rendered_hash, new.rendered_hash);
    assert_eq!(
        serde_json::to_value(&old.config).unwrap(),
        serde_json::to_value(&new.config).unwrap()
    );
    let resolved =
        crate::maestro::runtime_build::resolve_reload_config(&old.config, &new.config).unwrap();
    assert!(resolved.runtime_changed);
    assert!(!old.config.web_decoy_endpoints_equal(&new.config));
    assert_eq!(endpoint(&old.config).0, "10.0.0.2:18081".parse().unwrap());
    let same = prepared(&["10.0.0.3:18081", "10.0.0.4:18081"]).await;
    assert!(same.config.web_decoy_endpoints_equal(&new.config));
}

#[tokio::test]
async fn decoy_dns_effective_listener_overlay_rechecks_every_answer() {
    let old = prepared(&["10.0.0.2:18081"]).await;
    let mut parsed = source(SOURCE);
    parsed.config.server.listeners[0].port = Some(18082);
    parsed.config.web.vhosts[0].decoy = WebDecoyConfig::HttpUpstream {
        upstream: "http://example.com:18080".to_string(),
        resolve: WebDecoyResolve::Startup,
    };
    prepare(&mut parsed.config, |_, _| {
        std::future::ready(Ok(vec![
            "10.0.0.2:18080".parse().unwrap(),
            "127.0.0.1:18080".parse().unwrap(),
        ]))
    })
    .await
    .unwrap();
    let desired = pipeline::finish(parsed).unwrap();
    assert!(
        crate::maestro::runtime_build::resolve_reload_config(&old.config, &desired.config)
            .err()
            .unwrap()
            .contains("overlaps WEB listener")
    );
}

#[tokio::test]
async fn decoy_dns_rejects_ipv6_direct_and_wildcard_listener_loops() {
    for listener in ["::1", "::"] {
        let mut parsed = source(&SOURCE.replace("Example.COM:18081", "example.com:18080"));
        parsed.config.network.ipv6 = Some(true);
        parsed.config.server.listeners[0].ip = listener.parse().unwrap();
        let error = prepare(&mut parsed.config, |_, _| {
            std::future::ready(Ok(vec![
                "10.0.0.2:18080".parse().unwrap(),
                "[::1]:18080".parse().unwrap(),
            ]))
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("overlaps WEB listener"));
    }
}

#[test]
fn decoy_dns_startup_does_not_relax_origin_url_rules() {
    for url in [
        "https://example.com",
        "http://user@example.com",
        "http://user:pass@example.com",
        "http://example.com/path",
        "http://example.com/?q=1",
        "http://example.com/#fragment",
        "http://example.com:0",
    ] {
        assert!(
            parse_origin(0, url, WebDecoyResolve::Startup).is_err(),
            "accepted {url}"
        );
    }
}

#[tokio::test]
async fn decoy_dns_default_port_authority_and_evidence_port_fence() {
    let mut parsed = source(&SOURCE.replace("Example.COM:18081", "example.com"));
    prepare(&mut parsed.config, |_, port| {
        assert_eq!(port, 80);
        std::future::ready(Ok(vec!["127.0.0.2:80".parse().unwrap()]))
    })
    .await
    .unwrap();
    let loaded = pipeline::finish(parsed).unwrap();
    assert_eq!(endpoint(&loaded.config).1, "example.com");
    let mut config = loaded.config.clone();
    Arc::make_mut(&mut config.web.decoy_dns).origins.insert(
        ("example.com".to_string(), 80),
        vec!["127.0.0.2:81".parse().unwrap()],
    );
    assert!(
        config
            .validate_effective_web()
            .unwrap_err()
            .to_string()
            .contains("port mismatch")
    );
    assert!(config.rebuild_runtime_web().is_err());
}

#[tokio::test]
async fn grouped_hosts_share_one_resolved_origin_and_endpoint_inventory() {
    let mut parsed = source(&SOURCE.replace(
        "host = \"proxy.example.com\"",
        "hosts = [\"proxy.example.com\", \"other.example.com\"]",
    ));
    let calls = AtomicUsize::new(0);
    prepare(&mut parsed.config, |_, _| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(vec!["127.0.0.2:18081".parse().unwrap()]))
    })
    .await
    .unwrap();
    let loaded = pipeline::finish(parsed).unwrap();
    let runtime = loaded.config.web.runtime.as_ref().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(
        &runtime.vhosts["proxy.example.com"].decoy,
        &runtime.vhosts["other.example.com"].decoy
    ));
    let mut reordered = loaded.config.clone();
    reordered.web.vhosts[0].hosts.as_mut().unwrap().reverse();
    reordered.rebuild_runtime_web().unwrap();
    assert!(loaded.config.web_decoy_endpoints_equal(&reordered));
    reordered.web.vhosts[0].hosts.as_mut().unwrap().pop();
    reordered.rebuild_runtime_web().unwrap();
    assert!(!loaded.config.web_decoy_endpoints_equal(&reordered));
}
