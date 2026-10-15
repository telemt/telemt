use super::*;

const RECOVERY_TYPE: &str = "application/vnd.telemt.web-recovery+json";

async fn issue_bootstrap(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    path: &str,
    capability: [u8; 32],
) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let response = request(
        listener,
        runtime,
        bridge_request(&format!("{path}?bridge={encoded}")),
    )
    .await;
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    bridge_token(body)
}

async fn create_session(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    path: &str,
    bootstrap: &str,
) -> String {
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut request_bytes = format!(
        "POST {path} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    request_bytes.extend_from_slice(&hello);
    let response = request(listener, runtime, request_bytes).await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    response_header(headers, "x-session-token").to_string()
}

fn assert_private_not_found(response: &[u8]) {
    let (headers, body) = split_response(response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");
}

fn down_request(path: &str, session: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn session_token_distinguishes_the_exact_route_from_every_path_alias() {
    let capability = [81u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    config.web.timeouts.long_poll_secs = 1;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&listener, &runtime, "/relay/", capability).await;
    let session = create_session(&listener, &runtime, "/relay/api/v1/session", &bootstrap).await;

    let exact = request(
        &listener,
        &runtime,
        down_request("/relay/api/v1/down", &session),
    )
    .await;
    assert!(exact.starts_with(b"HTTP/1.1 204"));

    for alias in [
        "/api/v1/down",
        "/Relay/api/v1/down",
        "/relayx/api/v1/down",
        "/relay//api/v1/down",
        "/relay%2Fapi/v1/down",
        "/relay/api%2Fv1/down",
        "/relay/api/v1/down/",
        "/relay/api/v1/down?q=1",
    ] {
        let response = request(&listener, &runtime, down_request(alias, &session)).await;
        assert_private_not_found(&response);
    }

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn inactive_capabilities_remain_decoy_and_the_active_path_is_case_sensitive() {
    let active_capability = [82u8; 32];
    let inactive_capability = [83u8; 32];
    let generation = test_runtime_generation(
        1,
        runtime_config_with_base(
            active_capability,
            WebCarrier::Https,
            "/Dobry-Cola/super_app/",
        ),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let active = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(active_capability);
    let inactive = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inactive_capability);

    let exact = request(
        &listener,
        &runtime,
        bridge_request(&format!("/Dobry-Cola/super_app/?bridge={active}")),
    )
    .await;
    assert!(exact.starts_with(b"HTTP/1.1 200"));

    for path in [
        format!("/dobry-cola/super_app/?bridge={active}"),
        format!("/Dobry-Cola/super_app?bridge={active}"),
        format!("/Dobry-Cola/super_app/nested?bridge={active}"),
    ] {
        assert_private_not_found(&request(&listener, &runtime, bridge_request(&path)).await);
    }

    let decoy = request(
        &listener,
        &runtime,
        bridge_request(&format!("/Dobry-Cola/super_app/?bridge={inactive}")),
    )
    .await;
    assert_eq!(
        split_response(&decoy).1,
        b"<!doctype html><title>decoy</title>"
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn decoy_forwarding_preserves_every_reference_request_target() {
    let targets = [
        "/relay/",
        "/relay/whatever?q=1",
        "/relay/api/v1/session",
        "/relay",
        "/api/v1/ws",
        "/relay//api/v1/up",
        "/relay%2Fapi/v1/up",
        "/Relay/api/v1/down",
    ];
    let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let site_addr = site.local_addr().unwrap();
    let site_task = tokio::spawn(async move {
        let mut request_targets = Vec::new();
        for _ in 0..targets.len() {
            let (mut stream, _) = site.accept().await.unwrap();
            let mut received = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..read]);
                if received.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let line = std::str::from_utf8(&received)
                .unwrap()
                .split("\r\n")
                .next()
                .unwrap()
                .to_string();
            request_targets.push(line);
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsite",
                )
                .await
                .unwrap();
        }
        request_targets
    });

    let capability = [84u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    let runtime_config = config.web.runtime.as_ref().unwrap();
    let mut vhosts = runtime_config.vhosts.clone();
    let previous = &runtime_config.vhosts["proxy.example.com"];
    vhosts.insert(
        "proxy.example.com".to_string(),
        Arc::new(WebRuntimeVhost {
            host: previous.host.clone(),
            base: previous.base.clone(),
            decoy_fasttrack_mode: previous.decoy_fasttrack_mode,
            decoy: Arc::new(WebRuntimeDecoy::HttpUpstream {
                addr: site_addr,
                authority: "decoy.internal".to_string(),
            }),
            decoy_header_secs: 1,
            profiles: previous.profiles.clone(),
            capabilities: previous.capabilities.clone(),
        }),
    );
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts,
        profiles: runtime_config.profiles.clone(),
        capabilities: runtime_config.capabilities.clone(),
    }));
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    for target in targets {
        let response = request(&listener, &runtime, bridge_request(target)).await;
        assert_eq!(split_response(&response).1, b"site");
    }
    let forwarded = site_task.await.unwrap();
    let expected = targets
        .into_iter()
        .map(|target| format!("GET {target} HTTP/1.1"))
        .collect::<Vec<_>>();
    assert_eq!(forwarded, expected);

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn diagnostic_and_recovery_use_only_the_exact_prefixed_root() {
    let capability = [85u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    config.web.debug.enabled = true;
    config.web.debug.sideband = true;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bootstrap = issue_bootstrap(&listener, &runtime, "/relay/", capability).await;

    let body = br#"{"v":1,"event":"runtime_started"}"#;
    let mut diagnostic = format!(
        "POST /relay/api/v1/diagnostic HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    diagnostic.extend_from_slice(body);
    assert!(
        request(&listener, &runtime, diagnostic)
            .await
            .starts_with(b"HTTP/1.1 204")
    );

    let root_diagnostic = format!(
        "POST /api/v1/diagnostic HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer {bootstrap}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    assert_private_not_found(&request(&listener, &runtime, root_diagnostic).await);

    let session = create_session(&listener, &runtime, "/relay/api/v1/session", &bootstrap).await;
    let recovery_request = |path: &str| {
        format!(
            "GET {path}?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAccept: {RECOVERY_TYPE}\r\nAuthorization: Bearer {session}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    };
    assert_private_not_found(&request(&listener, &runtime, recovery_request("/")).await);
    let recovered = request(&listener, &runtime, recovery_request("/relay/")).await;
    let (headers, body) = split_response(&recovered);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(headers, "content-type"), RECOVERY_TYPE);
    let document: serde_json::Value = serde_json::from_slice(body).unwrap();
    let recovery_bootstrap = document["bootstrap"].as_str().unwrap();
    create_session(
        &listener,
        &runtime,
        "/relay/api/v1/session",
        recovery_bootstrap,
    )
    .await;

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
