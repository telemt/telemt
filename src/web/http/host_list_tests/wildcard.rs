use super::*;
use std::time::Duration;

fn wildcard_source(selector: &str, origin: std::net::SocketAddr) -> String {
    source(selector, origin).replace("[web]", "[web]\nallow_wildcard_hosts = true")
        + "\n[web.limits]\nmemory_envelope_bytes = 1610612736\n"
}

fn capability(config: &ProxyConfig, host: &str) -> String {
    // Independent reference derivation uses the client wire contract, not the cache.
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap())
            .unwrap();
    mac.update(b"tdesktop-web-proxy-bridge-v2\n");
    mac.update(host.as_bytes());
    mac.update(b"\nrelay");
    let encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    assert!(config.web.runtime.as_ref().unwrap().route(host).is_some());
    encoded
}

async fn bridge(listener: &TcpListener, runtime: &Arc<WebProcessRuntime>, host: &str) -> String {
    let cap = capability(&runtime.active_generation().config(), host);
    let response = request(
        listener,
        runtime,
        raw_request("GET", &format!("/relay/?bridge={cap}"), host, "", &[]),
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    std::str::from_utf8(split_response(&response).1)
        .unwrap()
        .split_once("bootstrap=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_string()
}

#[tokio::test]
async fn wildcard_cold_containment_canonical_host_and_positive_cache_in_all_modes() {
    for mode in ["off", "shadow", "enforce"] {
        let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let text = wildcard_source(
            "hosts = [\"*.example.com\", \"exact.example.com\"]",
            site.local_addr().unwrap(),
        )
        .replace(
            "enabled = true",
            &format!("enabled = true\ndecoy_fasttrack_mode = \"{mode}\""),
        );
        let generation = generation(1, &text);
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = "a.deep.example.com";
        let cap = capability(&generation.config(), host);
        let encoded = cap
            .bytes()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
        for (path, headers) in [
            (format!("/wrong/{cap}"), String::new()),
            (format!("/wrong/{encoded}"), String::new()),
            ("/wrong".to_string(), format!("Cookie: opaque={cap}\r\n")),
            ("/relay/".to_string(), format!("User-Agent: {encoded}\r\n")),
        ] {
            assert_private(
                &request(
                    &listener,
                    &runtime,
                    raw_request("GET", &path, host, &headers, &[]),
                )
                .await,
            );
        }
        assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats().0, 0);
        let before = runtime.wildcard.as_ref().unwrap().test_stats().2;
        let response = request(
            &listener,
            &runtime,
            raw_request(
                "GET",
                &format!("/relay/?bridge={cap}"),
                "A.DEEP.EXAMPLE.COM:443",
                "",
                &[],
            ),
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let cache = runtime.wildcard.as_ref().unwrap();
        assert_eq!(cache.test_stats().0, 1);
        assert_eq!(cache.test_stats().2, before + 1);
        bridge(&listener, &runtime, host).await;
        assert_eq!(cache.test_stats().2, before + 1);
        for foreign in ["b.example.com", "exact.example.com"] {
            assert_private(
                &request(
                    &listener,
                    &runtime,
                    raw_request("GET", &format!("/wrong/{cap}"), foreign, "", &[]),
                )
                .await,
            );
        }
        for invalid in [
            "example.com",
            "127.0.0.1",
            "a.example.com:0443",
            "a.example.com:80",
            "a..example.com",
            "a.example.com.",
            "a.example.com\r\nHost: b.example.com",
        ] {
            assert!(
                request(
                    &listener,
                    &runtime,
                    raw_request("GET", "/relay/", invalid, "", &[])
                )
                .await
                .starts_with(b"HTTP/1.1 404")
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), site.accept())
                .await
                .is_err()
        );
        stop(runtime, &[generation]).await;
    }
}

#[tokio::test]
async fn wildcard_budget_exhaustion_does_not_break_warm_bootstraps_or_authenticated_carriers() {
    let text = wildcard_source(
        "host = \"*.example.com\"",
        "127.0.0.1:18081".parse().unwrap(),
    ) + "\n[web.limits.wildcard]\nmax_profiles_per_request = 1\ncold_hmac_burst = 1\ncold_hmac_per_minute = 1\n";
    let generation = generation(1, &text);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = bridge(&listener, &runtime, HOSTS[0]).await;
    let session = create(&runtime, HOSTS[0], &bootstrap).unwrap();
    let cap = capability(&generation.config(), HOSTS[1]);
    assert!(
        request(
            &listener,
            &runtime,
            raw_request("GET", &format!("/relay/?bridge={cap}"), HOSTS[1], "", &[])
        )
        .await
        .starts_with(b"HTTP/1.1 503")
    );
    bridge(&listener, &runtime, HOSTS[0]).await;
    let auth = format!(
        "Authorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n"
    );
    let response = request(
        &listener,
        &runtime,
        raw_request(
            "POST",
            "/relay/api/v1/up",
            HOSTS[0],
            &auth,
            &frame::encode(FrameType::Pong, 0, &[]),
        ),
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 204"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_private(
        &request(
            &listener,
            &runtime,
            raw_request(
                "POST",
                "/relay/api/v1/up",
                HOSTS[1],
                &auth,
                &frame::encode(FrameType::Pong, 0, &[]),
            ),
        )
        .await,
    );
    assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats().2, 1);
    stop(runtime, &[generation]).await;
}

#[tokio::test]
async fn wildcard_cache_eviction_never_resets_host_quotas_and_recovery_uses_actual_host() {
    let text = wildcard_source(
        "host = \"*.example.com\"",
        "127.0.0.1:18081".parse().unwrap(),
    ) + "\n[web.limits.wildcard]\ncache_hosts = 1\n";
    let generation = generation(1, &text);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = create(
        &runtime,
        HOSTS[0],
        &bridge(&listener, &runtime, HOSTS[0]).await,
    )
    .unwrap();
    create(
        &runtime,
        HOSTS[1],
        &bridge(&listener, &runtime, HOSTS[1]).await,
    )
    .unwrap();
    assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats().0, 1);
    assert_eq!(
        create(
            &runtime,
            HOSTS[0],
            &bridge(&listener, &runtime, HOSTS[0]).await
        ),
        Err(ManagerError::Limit)
    );
    let cap = capability(&generation.config(), HOSTS[0]);
    let response = request(
        &listener,
        &runtime,
        raw_request(
            "GET",
            &format!("/relay/?bridge={cap}"),
            HOSTS[0],
            &format!(
                "Accept: application/vnd.telemt.web-recovery+json\r\nAuthorization: Bearer {a}\r\n"
            ),
            &[],
        ),
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let doc: serde_json::Value = serde_json::from_slice(split_response(&response).1).unwrap();
    assert!(doc["bootstrap"].as_str().is_some());
    stop(runtime, &[generation]).await;
}

// Same-generation replacement and public decoy compatibility are independent regressions.
#[path = "wildcard/decoy.rs"]
mod decoy;
#[path = "wildcard/reload.rs"]
mod reload;

// Matched loopback measurements are opt-in and never run in the normal suite.
#[path = "wildcard/benchmarks.rs"]
mod benchmarks;

// Upgrade authentication must remain independent of cold-host admission pressure.
#[path = "wildcard/websocket.rs"]
mod websocket;
