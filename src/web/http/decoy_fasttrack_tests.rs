use super::*;

use crate::config::WebDecoyFastTrackMode;
use crate::web::telemetry::WebDecoyFastTrackDisposition;

const RECOVERY_TYPE: &str = "application/vnd.telemt.web-recovery+json";
const ORIGIN_DATE: &str = "Thu, 15 Oct 2026 00:00:00 GMT";

struct Observation {
    response: Vec<u8>,
    counters: [u64; WebDecoyFastTrackDisposition::ALL.len()],
}

fn runtime_config_with_fasttrack(
    capability: [u8; 32],
    carrier: WebCarrier,
    mode: WebDecoyFastTrackMode,
) -> ProxyConfig {
    let mut config = runtime_config(capability, carrier);
    config.web.decoy_fasttrack_mode = mode;
    let runtime = Arc::get_mut(config.web.runtime.as_mut().unwrap()).unwrap();
    for vhost in runtime.vhosts.values_mut() {
        Arc::get_mut(vhost).unwrap().decoy_fasttrack_mode = mode;
    }
    config
}

async fn capture_origin_request(listener: &TcpListener) -> Vec<u8> {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut captured = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(
            read, 0,
            "decoy origin connection closed before the request completed"
        );
        captured.extend_from_slice(&buffer[..read]);
        let Some(header_end) = captured.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&captured[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        if captured.len() >= header_end + 4 + content_length {
            break;
        }
    }
    // Keep the origin response stable across modes and wall-clock seconds.
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nDate: {ORIGIN_DATE}\r\n\r\norigin"
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    captured
}

async fn observe_http_origin(
    mode: WebDecoyFastTrackMode,
    capability: [u8; 32],
    request_bytes: Vec<u8>,
    origin: &TcpListener,
) -> (Observation, Vec<u8>) {
    let mut config = runtime_config_with_fasttrack(capability, WebCarrier::Https, mode);
    let runtime_config = Arc::get_mut(config.web.runtime.as_mut().unwrap()).unwrap();
    let vhost = Arc::get_mut(runtime_config.vhosts.get_mut("proxy.example.com").unwrap()).unwrap();
    vhost.decoy = WebRuntimeDecoy::HttpUpstream {
        addr: origin.local_addr().unwrap(),
        authority: "decoy.example".to_string(),
    };
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (response, captured) = tokio::join!(
        request(&listener, &runtime, request_bytes),
        capture_origin_request(origin)
    );
    let (headers, body) = split_response(&response);
    assert_eq!(response_header(headers, "date"), ORIGIN_DATE);
    assert_eq!(body, b"origin");
    let counters = WebDecoyFastTrackDisposition::ALL
        .map(|disposition| runtime.telemetry().decoy_fasttrack_total(disposition));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;

    (Observation { response, counters }, captured)
}

async fn observe(
    mode: WebDecoyFastTrackMode,
    capability: [u8; 32],
    request_bytes: Vec<u8>,
) -> Observation {
    let generation = test_runtime_generation(
        1,
        runtime_config_with_fasttrack(capability, WebCarrier::Https, mode),
    );
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response = request(&listener, &runtime, request_bytes).await;
    let counters = WebDecoyFastTrackDisposition::ALL
        .map(|disposition| runtime.telemetry().decoy_fasttrack_total(disposition));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;

    Observation { response, counters }
}

fn root_request(method: &str, query: &str) -> Vec<u8> {
    format!(
        "{method} /{query} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.90\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn impossible_root_shapes_preserve_decoy_bytes_and_follow_the_selected_mode() {
    let capability = [70u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    for request_bytes in [
        root_request("GET", ""),
        root_request("GET", "?bridge=not-canonical"),
        root_request("HEAD", &format!("?bridge={encoded}")),
    ] {
        let off = observe(
            WebDecoyFastTrackMode::Off,
            capability,
            request_bytes.clone(),
        )
        .await;
        let shadow = observe(
            WebDecoyFastTrackMode::Shadow,
            capability,
            request_bytes.clone(),
        )
        .await;
        let enforce = observe(WebDecoyFastTrackMode::Enforce, capability, request_bytes).await;

        assert_eq!(shadow.response, off.response);
        assert_eq!(enforce.response, off.response);
        assert_eq!(off.counters, [0, 0, 0, 0]);
        assert_eq!(shadow.counters, [1, 0, 0, 0]);
        assert_eq!(enforce.counters, [0, 0, 1, 0]);
    }
}

#[tokio::test]
async fn canonical_hit_and_miss_always_retain_the_full_scan() {
    let capability = [71u8; 32];
    for candidate in [capability, [72u8; 32]] {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(candidate);
        let request_bytes = root_request("GET", &format!("?bridge={encoded}"));

        for (mode, expected_counters) in [
            (WebDecoyFastTrackMode::Off, [0, 0, 0, 0]),
            (WebDecoyFastTrackMode::Shadow, [0, 1, 0, 0]),
            (WebDecoyFastTrackMode::Enforce, [0, 0, 0, 1]),
        ] {
            let observation = observe(mode, capability, request_bytes.clone()).await;
            assert!(observation.response.starts_with(b"HTTP/1.1 200"));
            assert_eq!(observation.counters, expected_counters);
            if candidate == capability {
                assert!(
                    observation
                        .response
                        .windows(b"bootstrap=\"".len())
                        .any(|window| window == b"bootstrap=\"")
                );
            } else {
                let (_, body) = split_response(&observation.response);
                assert_eq!(body, b"<!doctype html><title>decoy</title>");
            }
        }
    }
}

#[tokio::test]
async fn recovery_sanitization_precedes_fasttrack_classification() {
    let capability = [73u8; 32];
    let request_bytes = format!(
        "GET /?bridge=not-canonical HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.90\r\nAccept: {RECOVERY_TYPE}\r\nAuthorization: Bearer {}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
        "U".repeat(43)
    )
    .into_bytes();

    let off = observe(
        WebDecoyFastTrackMode::Off,
        capability,
        request_bytes.clone(),
    )
    .await;
    let shadow = observe(
        WebDecoyFastTrackMode::Shadow,
        capability,
        request_bytes.clone(),
    )
    .await;
    let enforce = observe(WebDecoyFastTrackMode::Enforce, capability, request_bytes).await;

    assert_eq!(shadow.response, off.response);
    assert_eq!(enforce.response, off.response);
    assert_eq!(
        response_header(split_response(&off.response).0, "cache-control"),
        "no-store"
    );
    assert_eq!(off.counters, [0, 0, 0, 0]);
    assert_eq!(shadow.counters, [1, 0, 0, 0]);
    assert_eq!(enforce.counters, [0, 0, 1, 0]);
}

#[tokio::test]
async fn canonical_recovery_hit_and_miss_always_retain_the_full_scan() {
    let capability = [77u8; 32];
    let bearer = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([78u8; 32]);
    for candidate in [capability, [79u8; 32]] {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(candidate);
        let request_bytes = format!(
            "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.90\r\nAccept: {RECOVERY_TYPE}\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();

        for (mode, expected_counters) in [
            (WebDecoyFastTrackMode::Off, [0, 0, 0, 0]),
            (WebDecoyFastTrackMode::Shadow, [0, 1, 0, 0]),
            (WebDecoyFastTrackMode::Enforce, [0, 0, 0, 1]),
        ] {
            let observation = observe(mode, capability, request_bytes.clone()).await;
            let (headers, body) = split_response(&observation.response);
            assert_eq!(observation.counters, expected_counters);
            if candidate == capability {
                assert_eq!(response_header(headers, "content-type"), RECOVERY_TYPE);
                assert!(serde_json::from_slice::<serde_json::Value>(body).is_ok());
            } else {
                assert_eq!(body, b"<!doctype html><title>decoy</title>");
            }
        }
    }
}

#[tokio::test]
async fn http_origin_forwarding_is_identical_across_modes() {
    let capability = [74u8; 32];
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut request_bytes = b"GET /?bridge=not-canonical HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.90\r\nX-Ordinary: preserved\r\nContent-Length: 4\r\nConnection: close\r\n\r\n".to_vec();
    request_bytes.extend_from_slice(b"body");

    let (off, off_upstream) = observe_http_origin(
        WebDecoyFastTrackMode::Off,
        capability,
        request_bytes.clone(),
        &origin,
    )
    .await;
    let (shadow, shadow_upstream) = observe_http_origin(
        WebDecoyFastTrackMode::Shadow,
        capability,
        request_bytes.clone(),
        &origin,
    )
    .await;
    let (enforce, enforce_upstream) = observe_http_origin(
        WebDecoyFastTrackMode::Enforce,
        capability,
        request_bytes,
        &origin,
    )
    .await;

    assert_eq!(shadow.response, off.response);
    assert_eq!(enforce.response, off.response);
    assert_eq!(shadow_upstream, off_upstream);
    assert_eq!(enforce_upstream, off_upstream);
    assert!(off_upstream.starts_with(b"GET /?bridge=not-canonical HTTP/1.1\r\n"));
    assert!(
        off_upstream
            .windows(21)
            .any(|window| window == b"x-ordinary: preserved")
    );
    assert!(off_upstream.ends_with(b"\r\n\r\nbody"));
}

#[tokio::test]
async fn http_origin_recovery_sanitization_is_identical_across_modes() {
    let capability = [75u8; 32];
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let request_bytes = format!(
        "GET /?bridge=not-canonical HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.90\r\nAccept: {RECOVERY_TYPE}\r\nAuthorization: Bearer {}\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nX-Up-Seq: 9\r\nConnection: close\r\n\r\nbody",
        "U".repeat(43)
    )
    .into_bytes();

    let (off, off_upstream) = observe_http_origin(
        WebDecoyFastTrackMode::Off,
        capability,
        request_bytes.clone(),
        &origin,
    )
    .await;
    let (shadow, shadow_upstream) = observe_http_origin(
        WebDecoyFastTrackMode::Shadow,
        capability,
        request_bytes.clone(),
        &origin,
    )
    .await;
    let (enforce, enforce_upstream) = observe_http_origin(
        WebDecoyFastTrackMode::Enforce,
        capability,
        request_bytes,
        &origin,
    )
    .await;

    assert_eq!(shadow.response, off.response);
    assert_eq!(enforce.response, off.response);
    assert_eq!(shadow_upstream, off_upstream);
    assert_eq!(enforce_upstream, off_upstream);
    assert!(off_upstream.starts_with(b"GET / HTTP/1.1\r\n"));
    let lowercase = String::from_utf8_lossy(&off_upstream).to_ascii_lowercase();
    for forbidden in [
        "authorization:",
        "accept:",
        "content-type:",
        "content-length:",
        "x-up-seq:",
    ] {
        assert!(!lowercase.contains(forbidden));
    }
    assert!(off_upstream.ends_with(b"\r\n\r\n"));
}

#[tokio::test]
async fn fasttrack_counters_remain_process_owned_across_generation_swap() {
    let capability = [76u8; 32];
    let initial = test_runtime_generation(
        1,
        runtime_config_with_fasttrack(capability, WebCarrier::Https, WebDecoyFastTrackMode::Shadow),
    );
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&initial)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active_runtime));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let first = request(&listener, &runtime, root_request("GET", "")).await;
    assert!(first.starts_with(b"HTTP/1.1 200"));
    let replacement = test_runtime_generation(
        2,
        runtime_config_with_fasttrack(capability, WebCarrier::Https, WebDecoyFastTrackMode::Shadow),
    );
    active_runtime.store(Arc::clone(&replacement));
    let second = request(&listener, &runtime, root_request("GET", "")).await;
    assert!(second.starts_with(b"HTTP/1.1 200"));

    assert_eq!(
        runtime
            .telemetry()
            .decoy_fasttrack_total(WebDecoyFastTrackDisposition::ShadowWouldFastTrack),
        2
    );

    runtime.shutdown().await;
    initial.stop_sessions().await;
    initial.stop_background_tasks().await;
    replacement.stop_sessions().await;
    replacement.stop_background_tasks().await;
}
