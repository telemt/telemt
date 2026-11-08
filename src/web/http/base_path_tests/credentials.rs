use super::*;

fn assert_private_not_found(response: &[u8]) {
    let (headers, body) = split_response(response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .enumerate()
        .map(|(index, byte)| {
            if index % 2 == 0 {
                format!("%{byte:02x}")
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

async fn issue_session_credentials(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    capability: [u8; 32],
) -> (String, String) {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bridge = request(
        listener,
        runtime,
        bridge_request(&format!("/relay/?bridge={encoded}")),
    )
    .await;
    let bootstrap = bridge_token(split_response(&bridge).1);
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /relay/api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let created = request(listener, runtime, create).await;
    let (headers, _) = split_response(&created);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    (
        bootstrap,
        response_header(headers, "x-session-token").to_string(),
    )
}

#[tokio::test]
async fn every_authentic_credential_placement_stays_out_of_the_upstream() {
    let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let site_addr = site.local_addr().unwrap();
    let capability = [91u8; 32];
    let mut config = runtime_config_with_base(capability, WebCarrier::Https, "/relay/");
    config.web.limits.max_bootstraps_per_ip = 2;
    let runtime_config = config.web.runtime.as_ref().unwrap();
    let profile = runtime_config.profiles[0].clone();
    let mut vhosts = BTreeMap::new();
    vhosts.insert(
        "proxy.example.com".to_string(),
        Arc::new(WebRuntimeVhost {
            wildcard: None,
            host: "proxy.example.com".to_string(),
            base: "/relay/".to_string(),
            decoy_fasttrack_mode: WebDecoyFastTrackMode::Off,
            decoy: Arc::new(WebRuntimeDecoy::HttpUpstream {
                addr: site_addr,
                authority: "decoy.internal".to_string(),
            }),
            decoy_header_secs: 1,
            profiles: vec![profile.clone()],
            capabilities: vec![capability].into_boxed_slice(),
        }),
    );
    vhosts.insert(
        "other.example.com".to_string(),
        Arc::new(WebRuntimeVhost {
            wildcard: None,
            host: "other.example.com".to_string(),
            base: "/other/".to_string(),
            decoy_fasttrack_mode: WebDecoyFastTrackMode::Off,
            decoy: Arc::new(WebRuntimeDecoy::HttpUpstream {
                addr: site_addr,
                authority: "decoy.internal".to_string(),
            }),
            decoy_header_secs: 1,
            profiles: Vec::new(),
            capabilities: Vec::new().into_boxed_slice(),
        }),
    );
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        snapshot_id: 0,
        wildcards: Default::default(),
        catch_all: None,
        vhosts,
        profiles: vec![profile],
        capabilities: vec![capability].into_boxed_slice(),
    }));
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded_capability = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let (bootstrap, session) = issue_session_credentials(&listener, &runtime, capability).await;

    for secret in [&encoded_capability, &bootstrap, &session] {
        for raw in [
            format!(
                "GET /wrong/{secret} HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n"
            ),
            format!(
                "GET /wrong/{} HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n",
                percent_encode(secret)
            ),
            format!(
                "GET /?bridge={secret}&extra=1 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n"
            ),
            format!(
                "POST /wrong HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer {secret}\r\nCookie: opaque={secret}\r\nReferer: https://example.invalid/{secret}\r\nX-Unexpected: random,{secret}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            format!(
                "GET /api/v1/ws HTTP/1.1\r\nHost: proxy.example.com\r\nSec-WebSocket-Protocol: chat, tproxy-v1.{secret}\r\nConnection: close\r\n\r\n"
            ),
            format!(
                "GET /other/wrong HTTP/1.1\r\nHost: other.example.com\r\nX-Unexpected: {secret}\r\nConnection: close\r\n\r\n"
            ),
        ] {
            assert_private_not_found(&request(&listener, &runtime, raw.into_bytes()).await);
        }
    }

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), site.accept())
            .await
            .is_err()
    );

    let site_task = tokio::spawn(async move {
        let (mut stream, _) = site.accept().await.unwrap();
        let mut received = [0; 1024];
        let _ = stream.read(&mut received).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsite",
            )
            .await
            .unwrap();
    });
    let mut forged = bootstrap.into_bytes();
    forged[0] = if forged[0] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(forged).unwrap();
    let response = request(
        &listener,
        &runtime,
        bridge_request(&format!("/wrong/{forged}")),
    )
    .await;
    assert_eq!(split_response(&response).1, b"site");
    site_task.await.unwrap();

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
