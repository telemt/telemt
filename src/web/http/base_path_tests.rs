use super::*;

#[path = "base_path_tests/credentials.rs"]
mod credentials;
#[path = "base_path_tests/reload.rs"]
mod reload;
#[path = "base_path_tests/routing.rs"]
mod routing;

fn bridge_request(path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn bridge_token(body: &[u8]) -> String {
    std::str::from_utf8(body)
        .unwrap()
        .split_once("bootstrap=\"")
        .and_then(|(_, suffix)| suffix.split_once('"'))
        .map(|(token, _)| token.to_string())
        .unwrap()
}

async fn request_without_body(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    request_head: &[u8],
) -> Vec<u8> {
    let addr = listener.local_addr().unwrap();
    let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let permit = runtime.try_http_connection().unwrap();
    let task = tokio::spawn(serve_connection(
        server,
        peer,
        WebClientIpSource::XForwardedFor,
        Arc::from(["127.0.0.1/32".parse().unwrap()]),
        Arc::clone(runtime),
        CancellationToken::new(),
        permit,
    ));
    client.write_all(request_head).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await
    .expect("private rejection waited for the request body")
    .unwrap();
    task.await.unwrap();
    response
}

#[tokio::test]
async fn base_path_routes_only_the_exact_prefixed_contract() {
    let capability = [21u8; 32];
    let config = runtime_config_with_base(capability, WebCarrier::Https, "/dobry-cola/");
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);

    let response = request(
        &listener,
        &runtime,
        bridge_request(&format!("/dobry-cola/?bridge={encoded}")),
    )
    .await;
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    assert!(
        std::str::from_utf8(body)
            .unwrap()
            .contains("relayBase=relayOrigin+'/dobry-cola'")
    );

    for path in [
        format!("/?bridge={encoded}"),
        format!("/dobry-cola?bridge={encoded}"),
        format!("/dobry-cola/nested/?bridge={encoded}"),
    ] {
        let response = request(&listener, &runtime, bridge_request(&path)).await;
        let (headers, body) = split_response(&response);
        assert!(headers.starts_with(b"HTTP/1.1 404"));
        assert_eq!(response_header(headers, "cache-control"), "no-store");
        assert_eq!(body, b"not found\n");
    }

    for path in [
        "/",
        "/api/v1/session",
        "/dobry-cola/unknown?q=1",
        "/dobry-cola//api/v1/up",
        "/dobry-cola%2Fapi/v1/up",
    ] {
        let response = request(&listener, &runtime, bridge_request(path)).await;
        let (_, body) = split_response(&response);
        assert_eq!(body, b"<!doctype html><title>decoy</title>");
    }

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn prefixed_https_carrier_creates_uses_and_closes_a_session() {
    let capability = [22u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/nested/");
    config.web.timeouts.long_poll_secs = 1;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);

    let bridge = request(
        &listener,
        &runtime,
        bridge_request(&format!("/relay/nested/?bridge={encoded}")),
    )
    .await;
    let bootstrap = bridge_token(split_response(&bridge).1);
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /relay/nested/api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let created = request(&listener, &runtime, create).await;
    let (headers, _) = split_response(&created);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    let session = response_header(headers, "x-session-token").to_string();

    let misplaced = format!(
        "GET /wrong HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer {session}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let misplaced = request(&listener, &runtime, misplaced).await;
    let (headers, body) = split_response(&misplaced);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");

    let pong = frame::encode(FrameType::Pong, 0, &[]);
    let mut uplink = format!(
        "POST /relay/nested/api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pong.len()
    )
    .into_bytes();
    uplink.extend_from_slice(&pong);
    assert!(
        request(&listener, &runtime, uplink)
            .await
            .starts_with(b"HTTP/1.1 204")
    );

    let downlink = format!(
        "POST /relay/nested/api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    assert!(
        request(&listener, &runtime, downlink)
            .await
            .starts_with(b"HTTP/1.1 204")
    );

    let close = format!(
        "DELETE /relay/nested/api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    assert!(
        request(&listener, &runtime, close)
            .await
            .starts_with(b"HTTP/1.1 204")
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn authentic_credentials_never_reach_the_decoy() {
    let capability = [23u8; 32];
    let config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bridge = request(
        &listener,
        &runtime,
        bridge_request(&format!("/relay/?bridge={encoded}")),
    )
    .await;
    let bootstrap = bridge_token(split_response(&bridge).1);
    let escaped = format!("%{:02X}{}", bootstrap.as_bytes()[0], &bootstrap[1..]);

    for raw in [
        format!(
            "GET /wrong/{bootstrap} HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n"
        ),
        format!(
            "GET /wrong/{escaped} HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n"
        ),
        format!(
            "GET /wrong HTTP/1.1\r\nHost: proxy.example.com\r\nCookie: opaque={bootstrap}\r\nConnection: close\r\n\r\n"
        ),
        format!(
            "GET /wrong HTTP/1.1\r\nHost: proxy.example.com\r\nReferer: https://example.invalid/{encoded}\r\nConnection: close\r\n\r\n"
        ),
    ] {
        let response = request(&listener, &runtime, raw.into_bytes()).await;
        let (headers, body) = split_response(&response);
        assert!(headers.starts_with(b"HTTP/1.1 404"));
        assert_eq!(response_header(headers, "cache-control"), "no-store");
        assert_eq!(body, b"not found\n");
    }

    let mut forged = bootstrap.into_bytes();
    forged[0] = if forged[0] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(forged).unwrap();
    let response = request(
        &listener,
        &runtime,
        bridge_request(&format!("/wrong/{forged}")),
    )
    .await;
    assert_eq!(
        split_response(&response).1,
        b"<!doctype html><title>decoy</title>"
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn misplaced_process_token_is_rejected_without_reading_the_body() {
    let capability = [24u8; 32];
    let config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bridge = request(
        &listener,
        &runtime,
        bridge_request(&format!("/relay/?bridge={encoded}")),
    )
    .await;
    let bootstrap = bridge_token(split_response(&bridge).1);
    let head = format!(
        "POST /wrong HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer {bootstrap}\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n"
    );

    let response = request_without_body(&listener, &runtime, head.as_bytes()).await;
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn process_token_provenance_survives_registry_expiry() {
    let capability = [25u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    config.web.timeouts.bootstrap_lifetime_secs = 1;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bridge = request(
        &listener,
        &runtime,
        bridge_request(&format!("/relay/?bridge={encoded}")),
    )
    .await;
    let bootstrap = bridge_token(split_response(&bridge).1);

    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        loop {
            let status = serde_json::to_value(runtime.try_status()).unwrap();
            if status["manager"]["bootstraps"] == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("bootstrap registry entry did not expire");

    let response = request(
        &listener,
        &runtime,
        bridge_request(&format!("/wrong/{bootstrap}")),
    )
    .await;
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn generation_swap_switches_base_path_and_capability_together() {
    let initial_capability = [26u8; 32];
    let mut initial = runtime_config_with_base(initial_capability, WebCarrier::Https, "/old-path/");
    initial.web.limits.max_bootstraps_per_ip = 2;
    let generation = test_runtime_generation(1, initial);
    let active = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let initial_encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(initial_capability);

    let old_bridge = request(
        &listener,
        &runtime,
        bridge_request(&format!("/old-path/?bridge={initial_encoded}")),
    )
    .await;
    assert!(old_bridge.starts_with(b"HTTP/1.1 200"));

    let replacement_capability = [27u8; 32];
    let replacement = test_runtime_generation(
        2,
        runtime_config_with_base(replacement_capability, WebCarrier::Https, "/new-path/"),
    );
    active.store(Arc::clone(&replacement));
    let stale = request(
        &listener,
        &runtime,
        bridge_request(&format!("/old-path/?bridge={initial_encoded}")),
    )
    .await;
    assert_eq!(
        split_response(&stale).1,
        b"<!doctype html><title>decoy</title>"
    );

    let replacement_encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(replacement_capability);
    let current = request(
        &listener,
        &runtime,
        bridge_request(&format!("/new-path/?bridge={replacement_encoded}")),
    )
    .await;
    let (headers, body) = split_response(&current);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    assert!(
        std::str::from_utf8(body)
            .unwrap()
            .contains("relayBase=relayOrigin+'/new-path'")
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
    replacement.stop_sessions().await;
    replacement.stop_background_tasks().await;
}

#[tokio::test]
async fn prefixed_decoy_request_keeps_its_original_path_and_query() {
    let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let site_addr = site.local_addr().unwrap();
    let site_task = tokio::spawn(async move {
        let (mut stream, _) = site.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let read = stream.read(&mut request).await.unwrap();
        request.truncate(read);
        stream
            .write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsite",
            )
            .await
            .unwrap();
        request
    });

    let capability = [28u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    let profile = Arc::clone(&config.web.runtime.as_ref().unwrap().profiles[0]);
    let vhost = Arc::new(WebRuntimeVhost {
        host: "proxy.example.com".to_string(),
        base: "/relay/".to_string(),
        decoy_fasttrack_mode: WebDecoyFastTrackMode::Off,
        decoy: Arc::new(WebRuntimeDecoy::HttpUpstream {
            addr: site_addr,
            authority: "decoy.internal".to_string(),
        }),
        decoy_header_secs: 1,
        profiles: vec![Arc::clone(&profile)],
        capabilities: vec![capability].into_boxed_slice(),
    });
    let mut vhosts = BTreeMap::new();
    vhosts.insert("proxy.example.com".to_string(), vhost);
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts,
        profiles: vec![profile],
        capabilities: vec![capability].into_boxed_slice(),
    }));
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let response = request(&listener, &runtime, bridge_request("/relay/ordinary?q=1")).await;
    assert!(response.starts_with(b"HTTP/1.1 404"));
    assert_eq!(split_response(&response).1, b"site");
    let forwarded = site_task.await.unwrap();
    assert!(forwarded.starts_with(b"GET /relay/ordinary?q=1 HTTP/1.1\r\n"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
