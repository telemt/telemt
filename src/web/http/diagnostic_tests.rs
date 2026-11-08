use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine as _;
use tokio::net::TcpListener;

use super::{request, response_header, runtime_config, split_response};
use crate::config::{WebCarrier, WebDebugBodyCapture};
use crate::maestro::generation::test_runtime_generation;
use crate::web::frame::{self, FrameType};
use crate::web::manager::WebProcessRuntime;
use crate::web::trace::{TraceLifecycleEvent, TraceRecordKind, TraceRoute};

fn diagnostic_request(
    method: &str,
    path: &str,
    host: &str,
    token: Option<&str>,
    content_type: Option<&str>,
    extra_headers: &str,
    body: &[u8],
) -> Vec<u8> {
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let content_type = content_type
        .map(|content_type| format!("Content-Type: {content_type}\r\n"))
        .unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 192.0.2.10\r\n{authorization}{content_type}{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

fn bootstrap_from_response(response: &[u8]) -> String {
    let (_, body) = split_response(response);
    std::str::from_utf8(body)
        .unwrap()
        .split_once("bootstrap=\"")
        .and_then(|(_, suffix)| suffix.split_once('"'))
        .map(|(token, _)| token)
        .unwrap()
        .to_string()
}

async fn issue_bootstrap(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    capability: [u8; 32],
) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    bootstrap_from_response(&request(listener, runtime, root).await)
}

#[tokio::test]
async fn bridge_diagnostic_does_not_consume_the_bootstrap() {
    let capability = [31u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Websocket);
    config.web.debug.enabled = true;
    config.web.debug.sideband = true;
    config.web.debug.body_capture = WebDebugBodyCapture::Full;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    assert!(
        std::str::from_utf8(split_response(&root_response).1)
            .unwrap()
            .contains("/api/v1/diagnostic")
    );
    let bootstrap = bootstrap_from_response(&root_response);

    let body = br#"{"v":1,"event":"runtime_started"}"#;
    let diagnostic = diagnostic_request(
        "POST",
        "/api/v1/diagnostic",
        "proxy.example.com",
        Some(&bootstrap),
        Some("application/json"),
        "",
        body,
    );
    let duplicate = diagnostic.clone();
    let diagnostic_response = request(&listener, &runtime, diagnostic).await;
    assert!(diagnostic_response.starts_with(b"HTTP/1.1 204"));
    let (diagnostic_headers, diagnostic_body) = split_response(&diagnostic_response);
    assert_eq!(
        response_header(diagnostic_headers, "cache-control"),
        "no-store"
    );
    assert!(diagnostic_body.is_empty());
    let duplicate_response = request(&listener, &runtime, duplicate).await;
    assert!(duplicate_response.starts_with(b"HTTP/1.1 204"));

    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    assert!(create_response.starts_with(b"HTTP/1.1 200"));

    let hello_report = diagnostic_request(
        "POST",
        "/api/v1/diagnostic",
        "proxy.example.com",
        Some(&bootstrap),
        Some("application/json"),
        "",
        br#"{"v":1,"event":"hello_received"}"#,
    );
    let hello_report_response = request(&listener, &runtime, hello_report).await;
    assert!(hello_report_response.starts_with(b"HTTP/1.1 204"));

    let lifecycle = runtime.trace().snapshot_matching(|record| {
        matches!(
            &record.kind,
            TraceRecordKind::Lifecycle(event)
                if matches!(
                    event.event,
                    TraceLifecycleEvent::BridgeIssued | TraceLifecycleEvent::BridgeDiagnostic
                )
        )
    });
    let bridge_session_id = lifecycle
        .iter()
        .find_map(|record| match &record.record.kind {
            TraceRecordKind::Lifecycle(event)
                if event.event == TraceLifecycleEvent::BridgeIssued =>
            {
                record.record.identity.session_id
            }
            _ => None,
        })
        .unwrap();
    let diagnostics = lifecycle
        .iter()
        .filter_map(|record| match &record.record.kind {
            TraceRecordKind::Lifecycle(event)
                if event.event == TraceLifecycleEvent::BridgeDiagnostic =>
            {
                Some((record.record.identity.session_id, event.reason))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 2);
    assert!(diagnostics.contains(&(Some(bridge_session_id), Some("runtime_started"))));
    assert!(diagnostics.contains(&(Some(bridge_session_id), Some("hello_received"))));

    let diagnostic_http = runtime.trace().snapshot_matching(|record| {
        matches!(
            &record.kind,
            TraceRecordKind::Http(http) if http.route == TraceRoute::Diagnostic
        )
    });
    assert_eq!(diagnostic_http.len(), 3);
    let TraceRecordKind::Http(http) = &diagnostic_http[0].record.kind else {
        panic!("expected diagnostic HTTP trace");
    };
    assert!(
        http.request_headers
            .iter()
            .any(|header| { header.name == "authorization" && header.value.is_none() })
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn malformed_bridge_diagnostics_follow_the_sanitized_decoy_path() {
    let capability = [33u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Websocket);
    config.web.debug.enabled = true;
    config.web.debug.sideband = true;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&listener, &runtime, capability).await;
    let canonical = br#"{"v":1,"event":"runtime_started"}"#;
    let oversized = [b'x'; 65];
    let wrong_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let cases = vec![
        diagnostic_request(
            "GET",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic?debug=1",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "Cookie: value=1\r\n",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            None,
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json; charset=utf-8"),
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "Content-Type: application/json\r\n",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            None,
            Some("application/json"),
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(wrong_token),
            Some("application/json"),
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "other.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            canonical,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            b"",
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            &oversized,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            br#"{"event":"runtime_started","v":1}"#,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            br#"{"v":1,"event":"runtime_started","detail":"x"}"#,
        ),
        diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            br#"{"v":1,"event":"unknown"}"#,
        ),
    ];

    for request_bytes in cases {
        let response = request(&listener, &runtime, request_bytes).await;
        assert!(response.starts_with(b"HTTP/1.1 404"));
    }
    assert!(
        runtime
            .trace()
            .snapshot_matching(|record| {
                matches!(
                    &record.kind,
                    TraceRecordKind::Lifecycle(event)
                        if event.event == TraceLifecycleEvent::BridgeDiagnostic
                )
            })
            .is_empty()
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn expired_bridge_bootstrap_cannot_report_diagnostics() {
    let capability = [38u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Https);
    config.web.debug.enabled = true;
    config.web.debug.sideband = true;
    config.web.timeouts.bootstrap_lifetime_secs = 0;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&listener, &runtime, capability).await;
    let report = diagnostic_request(
        "POST",
        "/api/v1/diagnostic",
        "proxy.example.com",
        Some(&bootstrap),
        Some("application/json"),
        "",
        br#"{"v":1,"event":"runtime_started"}"#,
    );

    let response = request(&listener, &runtime, report).await;
    assert!(response.starts_with(b"HTTP/1.1 404"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn diagnostic_body_pressure_does_not_claim_the_event() {
    let capability = [39u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Websocket);
    config.web.debug.enabled = true;
    config.web.debug.sideband = true;
    config.web.limits.max_body_readers = 1;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&listener, &runtime, capability).await;
    let report = diagnostic_request(
        "POST",
        "/api/v1/diagnostic",
        "proxy.example.com",
        Some(&bootstrap),
        Some("application/json"),
        "",
        br#"{"v":1,"event":"runtime_started"}"#,
    );
    let retry = report.clone();
    let held = runtime.try_body_budget(1).unwrap();

    let saturated = request(&listener, &runtime, report).await;
    assert!(saturated.starts_with(b"HTTP/1.1 503"));
    assert_eq!(
        response_header(split_response(&saturated).0, "retry-after"),
        "1"
    );
    assert_eq!(
        response_header(split_response(&saturated).0, "x-telemt-retry-after-ms"),
        "250"
    );
    drop(held);

    let accepted = request(&listener, &runtime, retry).await;
    assert!(accepted.starts_with(b"HTTP/1.1 204"));
    assert_eq!(
        runtime
            .trace()
            .snapshot_matching(|record| {
                matches!(
                    &record.kind,
                    TraceRecordKind::Lifecycle(event)
                        if event.event == TraceLifecycleEvent::BridgeDiagnostic
                )
            })
            .len(),
        1
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn bridge_diagnostic_sideband_is_carrier_independent() {
    for (marker, carrier) in [
        (34, WebCarrier::Https),
        (35, WebCarrier::HttpsLanes),
        (36, WebCarrier::Websocket),
        (37, WebCarrier::WebsocketLanes),
    ] {
        let capability = [marker; 32];
        let mut config = runtime_config(capability, carrier);
        config.web.debug.enabled = true;
        config.web.debug.sideband = true;
        let generation = test_runtime_generation(1, config);
        let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
        let runtime = WebProcessRuntime::start(active_runtime);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bootstrap = issue_bootstrap(&listener, &runtime, capability).await;
        let report = diagnostic_request(
            "POST",
            "/api/v1/diagnostic",
            "proxy.example.com",
            Some(&bootstrap),
            Some("application/json"),
            "",
            br#"{"v":1,"event":"status_posted"}"#,
        );

        let response = request(&listener, &runtime, report).await;
        assert!(response.starts_with(b"HTTP/1.1 204"));

        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn disabled_bridge_diagnostic_is_acknowledged_without_recording() {
    let capability = [32u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Https);
    config.web.debug.enabled = true;
    config.web.limits.max_bootstraps_per_ip = 2;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active_runtime));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    assert!(
        !std::str::from_utf8(split_response(&root_response).1)
            .unwrap()
            .contains("/api/v1/diagnostic")
    );
    let bootstrap = bootstrap_from_response(&root_response);
    let mut enabled_config = runtime_config(capability, WebCarrier::Https);
    enabled_config.web.debug.enabled = true;
    enabled_config.web.debug.sideband = true;
    let enabled_generation = test_runtime_generation(2, enabled_config);
    active_runtime.store(Arc::clone(&enabled_generation));
    let report = diagnostic_request(
        "POST",
        "/api/v1/diagnostic",
        "proxy.example.com",
        Some(&bootstrap),
        Some("application/json"),
        "",
        br#"{"v":1,"event":"runtime_started"}"#,
    );

    let response = request(&listener, &runtime, report).await;
    assert!(response.starts_with(b"HTTP/1.1 204"));
    assert!(
        runtime
            .trace()
            .snapshot_matching(|record| {
                matches!(
                    &record.kind,
                    TraceRecordKind::Lifecycle(event)
                        if event.event == TraceLifecycleEvent::BridgeDiagnostic
                )
            })
            .is_empty()
    );

    let current_gate_bootstrap = issue_bootstrap(&listener, &runtime, capability).await;
    let mut disabled_config = runtime_config(capability, WebCarrier::Https);
    disabled_config.web.debug.enabled = true;
    let disabled_generation = test_runtime_generation(3, disabled_config);
    active_runtime.store(Arc::clone(&disabled_generation));
    let current_gate_report = diagnostic_request(
        "POST",
        "/api/v1/diagnostic",
        "proxy.example.com",
        Some(&current_gate_bootstrap),
        Some("application/json"),
        "",
        br#"{"v":1,"event":"runtime_started"}"#,
    );
    let response = request(&listener, &runtime, current_gate_report).await;
    assert!(response.starts_with(b"HTTP/1.1 204"));
    let diagnostics = runtime.trace().snapshot_matching(|record| {
        matches!(
            &record.kind,
            TraceRecordKind::Lifecycle(event)
                if event.event == TraceLifecycleEvent::BridgeDiagnostic
        )
    });
    assert!(diagnostics.is_empty());

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
    enabled_generation.stop_sessions().await;
    enabled_generation.stop_background_tasks().await;
    disabled_generation.stop_sessions().await;
    disabled_generation.stop_background_tasks().await;
}
