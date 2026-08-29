use super::*;

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::web::manager::{ManagerError, OperatorLifecycleError};

fn create_request(bootstrap: &str, hello: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    request.extend_from_slice(hello);
    request
}

fn negotiated_request(
    bootstrap: &str,
    hello: &[u8],
    attempt: u8,
    failure: Option<&str>,
) -> Vec<u8> {
    let failure = failure
        .map(|failure| format!("X-Carrier-Failure: {failure}\r\n"))
        .unwrap_or_default();
    let mut request = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nX-Carrier-Capabilities: https,https-lanes,websocket,websocket-lanes\r\nX-Carrier-Attempt: {attempt}\r\n{failure}Content-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    request.extend_from_slice(hello);
    request
}

fn token_hash(token: &str) -> crate::web::manager::TokenHash {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .unwrap();
    Sha256::digest(raw).into()
}

async fn live_runtime() -> (
    Arc<WebProcessRuntime>,
    Arc<crate::maestro::generation::RuntimeGeneration>,
    TcpListener,
) {
    let generation = test_runtime_generation(1, runtime_config([71; 32], WebCarrier::Https));
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (runtime, generation, listener)
}

fn issue_bootstrap(runtime: &Arc<WebProcessRuntime>) -> String {
    let profile = runtime
        .active_generation()
        .config()
        .web
        .runtime
        .as_ref()
        .unwrap()
        .profiles[0]
        .clone();
    runtime
        .issue_bootstrap(profile, "192.0.2.10".parse().unwrap())
        .unwrap()
        .token
}

async fn create_session(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    bootstrap: &str,
) -> (Vec<u8>, String) {
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let response = request(listener, runtime, create_request(bootstrap, &hello)).await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    let token = response_header(headers, "x-session-token").to_string();
    (hello.to_vec(), token)
}

async fn stop_runtime(
    runtime: Arc<WebProcessRuntime>,
    generation: Arc<crate::maestro::generation::RuntimeGeneration>,
) {
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn pause_preserves_decoy_retry_and_exact_session_replay() {
    let (runtime, generation, listener) = live_runtime().await;
    let bootstrap = issue_bootstrap(&runtime);
    let hello = frame::encode(FrameType::Hello, 0, &[1]);

    runtime.pause_operator().await.unwrap();
    let paused_create = request(&listener, &runtime, create_request(&bootstrap, &hello)).await;
    let (paused_headers, _) = split_response(&paused_create);
    assert!(paused_headers.starts_with(b"HTTP/1.1 503"));
    assert_eq!(response_header(paused_headers, "retry-after"), "1");

    let profile = runtime
        .active_generation()
        .config()
        .web
        .runtime
        .as_ref()
        .unwrap()
        .profiles[0]
        .clone();
    assert!(matches!(
        runtime.issue_bootstrap(profile, "192.0.2.11".parse().unwrap()),
        Err(ManagerError::AdmissionPaused)
    ));
    let bridge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([71; 32]);
    let decoy = format!(
        "GET /?bridge={bridge} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.11\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let decoy = request(&listener, &runtime, decoy).await;
    let (decoy_headers, decoy_body) = split_response(&decoy);
    assert!(decoy_headers.starts_with(b"HTTP/1.1 200"));
    assert!(
        !decoy_body
            .windows(11)
            .any(|window| window == b"bootstrap=\"")
    );

    runtime.resume_operator().await.unwrap();
    let created = request(&listener, &runtime, create_request(&bootstrap, &hello)).await;
    let (created_headers, _) = split_response(&created);
    assert!(created_headers.starts_with(b"HTTP/1.1 200"));
    let token = response_header(created_headers, "x-session-token").to_string();

    runtime.pause_operator().await.unwrap();
    let replay = request(&listener, &runtime, create_request(&bootstrap, &hello)).await;
    let (replay_headers, _) = split_response(&replay);
    assert!(replay_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(replay_headers, "x-session-token"), token);

    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn paused_open_is_stream_local_and_does_not_charge_limit_hits() {
    let (runtime, generation, listener) = live_runtime().await;
    let bootstrap = issue_bootstrap(&runtime);
    let (_, token) = create_session(&listener, &runtime, &bootstrap).await;
    let before = serde_json::to_value(runtime.try_status()).unwrap();
    let limit_hits = before["limit_hits"].as_u64().unwrap();
    let streams_rejected = before["streams_rejected"].as_u64().unwrap();

    runtime.pause_operator().await.unwrap();
    let open = frame::encode(FrameType::Open, 7, &[]);
    let mut uplink = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        open.len()
    )
    .into_bytes();
    uplink.extend_from_slice(&open);
    let rejected = request(&listener, &runtime, uplink).await;
    assert!(rejected.starts_with(b"HTTP/1.1 204"));

    let after = serde_json::to_value(runtime.try_status()).unwrap();
    assert_eq!(after["limit_hits"].as_u64(), Some(limit_hits));
    assert_eq!(
        after["streams_rejected"].as_u64(),
        Some(streams_rejected + 1)
    );
    assert_eq!(after["streams"]["live"].as_u64(), Some(0));
    assert!(
        runtime
            .get_session(token_hash(&token), "proxy.example.com")
            .is_ok()
    );

    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn paused_replacement_preserves_old_session_and_attempt_replay() {
    let generation = test_runtime_generation(
        1,
        negotiation_runtime_config(
            [72; 32],
            WebCarrier::Https,
            false,
            Arc::from([WebCarrier::Https, WebCarrier::HttpsLanes]),
        ),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&runtime);
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let first_request = negotiated_request(&bootstrap, &hello, 1, None);
    let first = request(&listener, &runtime, first_request.clone()).await;
    let (first_headers, _) = split_response(&first);
    assert!(first_headers.starts_with(b"HTTP/1.1 200"));
    let first_token = response_header(first_headers, "x-session-token").to_string();

    runtime.pause_operator().await.unwrap();
    let replacement_request = negotiated_request(&bootstrap, &hello, 2, Some("timeout"));
    let rejected = request(&listener, &runtime, replacement_request.clone()).await;
    let (rejected_headers, _) = split_response(&rejected);
    assert!(rejected_headers.starts_with(b"HTTP/1.1 503"));
    assert_eq!(response_header(rejected_headers, "retry-after"), "1");
    assert!(
        runtime
            .get_session(token_hash(&first_token), "proxy.example.com")
            .is_ok()
    );

    let replay = request(&listener, &runtime, first_request).await;
    let (replay_headers, _) = split_response(&replay);
    assert!(replay_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        response_header(replay_headers, "x-session-token"),
        first_token
    );

    runtime.resume_operator().await.unwrap();
    let replacement = request(&listener, &runtime, replacement_request).await;
    let (replacement_headers, _) = split_response(&replacement);
    assert!(replacement_headers.starts_with(b"HTTP/1.1 200"));
    assert_ne!(
        response_header(replacement_headers, "x-session-token"),
        first_token
    );

    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn client_delete_during_drain_completes_naturally() {
    let (runtime, generation, listener) = live_runtime().await;
    let bootstrap = issue_bootstrap(&runtime);
    let (_, token) = create_session(&listener, &runtime, &bootstrap).await;
    runtime
        .drain_operator(Duration::from_secs(30))
        .await
        .unwrap();

    let delete = format!(
        "DELETE /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let deleted = request(&listener, &runtime, delete).await;
    assert!(deleted.starts_with(b"HTTP/1.1 204"));

    let completed = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let status = runtime.operator_lifecycle_status();
            if serde_json::to_value(&status).unwrap()["state"] == "drained" {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let completed = serde_json::to_value(&completed).unwrap();
    assert_eq!(completed["drain"]["outcome"], "graceful");
    assert_eq!(completed["drain"]["force_close_signalled"], false);
    stop_runtime(runtime, generation).await;
}

#[tokio::test(start_paused = true)]
async fn deadline_force_closes_all_sessions_and_requires_explicit_resume() {
    let (runtime, generation, listener) = live_runtime().await;
    let bootstrap = issue_bootstrap(&runtime);
    let (_, token) = create_session(&listener, &runtime, &bootstrap).await;

    let accepted = runtime
        .drain_operator(Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&accepted).unwrap()["state"],
        "draining"
    );
    assert!(matches!(
        runtime.drain_operator(Duration::from_secs(30)).await,
        Err(OperatorLifecycleError::OperationInProgress)
    ));
    tokio::time::advance(Duration::from_secs(30)).await;
    let completed = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let status = runtime.operator_lifecycle_status();
            if serde_json::to_value(&status).unwrap()["state"] == "drained" {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let completed = serde_json::to_value(&completed).unwrap();
    assert_eq!(completed["drain"]["state"], "completed");
    assert_eq!(completed["drain"]["outcome"], "forced");
    assert_eq!(completed["drain"]["force_close_signalled"], true);
    assert_eq!(completed["admission_open"], false);
    assert!(
        runtime
            .get_session(token_hash(&token), "proxy.example.com")
            .is_err()
    );

    let resumed = runtime.resume_operator().await.unwrap();
    let resumed = serde_json::to_value(&resumed).unwrap();
    assert_eq!(resumed["state"], "running");
    assert_eq!(resumed["admission_open"], true);
    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn resume_before_deadline_cancels_drain_without_closing_existing_session() {
    let (runtime, generation, listener) = live_runtime().await;
    let bootstrap = issue_bootstrap(&runtime);
    let (_, token) = create_session(&listener, &runtime, &bootstrap).await;

    runtime
        .drain_operator(Duration::from_secs(30))
        .await
        .unwrap();
    let still_draining = runtime.pause_operator().await.unwrap();
    assert_eq!(
        serde_json::to_value(&still_draining).unwrap()["state"],
        "draining"
    );
    let resumed = runtime.resume_operator().await.unwrap();
    let resumed = serde_json::to_value(&resumed).unwrap();
    assert_eq!(resumed["state"], "running");
    assert_eq!(resumed["drain"]["state"], "cancelled");
    assert_eq!(resumed["drain"]["outcome"], "cancelled");
    assert_eq!(resumed["drain"]["force_close_signalled"], false);
    assert!(
        runtime
            .get_session(token_hash(&token), "proxy.example.com")
            .is_ok()
    );

    stop_runtime(runtime, generation).await;
}
