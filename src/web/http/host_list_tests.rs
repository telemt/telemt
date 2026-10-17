use super::*;
use crate::maestro::generation::RuntimeGeneration;
use crate::web::manager::{BridgeDiagnosticEvent, CarrierRequest, ManagerError, TokenHash};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// Admission and generation identity use the same parsed configuration as HTTP routing.
#[path = "host_list_tests/sessions.rs"]
mod sessions;

const HOSTS: [&str; 2] = ["a.example.com", "b.example.com"];
const SELECTOR: &str = "hosts = [\"a.example.com\", \"b.example.com\"]";

fn source(selector: &str, origin: std::net::SocketAddr) -> String {
    format!(
        r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[web]
enabled = true
carrier = "https"
[[web.vhosts]]
{selector}
base_path = "relay"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://{origin}"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
max_sessions = 1
max_streams = 1
max_streams_per_session = 1
"#
    )
}

fn generation(id: u64, text: &str) -> Arc<RuntimeGeneration> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    let generation = test_runtime_generation(id, ProxyConfig::load(&path).unwrap());
    generation
        .proxy_shared
        .apply_user_config(&generation.config().access.users, &HashMap::new());
    generation
}

fn profile(runtime: &WebProcessRuntime, host: &str) -> Arc<WebRuntimeProfile> {
    runtime
        .active_generation()
        .config()
        .web
        .runtime
        .as_ref()
        .unwrap()
        .vhosts[host]
        .profiles[0]
        .clone()
}

fn token_hash(token: &str) -> TokenHash {
    Sha256::digest(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .unwrap(),
    )
    .into()
}

fn raw_request(method: &str, path: &str, host: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 192.0.2.10\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()
    ).into_bytes();
    raw.extend_from_slice(body);
    raw
}

fn bootstrap(runtime: &Arc<WebProcessRuntime>, host: &str) -> String {
    runtime
        .issue_bootstrap(profile(runtime, host), "192.0.2.10".parse().unwrap())
        .unwrap()
        .token
}

fn create(
    runtime: &Arc<WebProcessRuntime>,
    host: &str,
    bootstrap: &str,
) -> Result<String, ManagerError> {
    runtime
        .create_session(
            token_hash(bootstrap),
            host,
            "192.0.2.10".parse().unwrap(),
            &frame::encode(FrameType::Hello, 0, &[1]),
            CarrierRequest::legacy([0; 32]),
            false,
        )
        .map(|created| created.token)
}

fn assert_private(response: &[u8]) {
    let (headers, body) = split_response(response);
    assert!(
        headers.starts_with(b"HTTP/1.1 404"),
        "{}",
        String::from_utf8_lossy(response)
    );
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");
}

async fn stop(runtime: Arc<WebProcessRuntime>, generations: &[Arc<RuntimeGeneration>]) {
    runtime.shutdown().await;
    for generation in generations {
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn grouped_hosts_contain_credentials_in_every_fasttrack_mode() {
    for mode in ["off", "shadow", "enforce"] {
        let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let text = source(SELECTOR, site.local_addr().unwrap()).replace(
            "enabled = true",
            &format!("enabled = true\ndecoy_fasttrack_mode = \"{mode}\""),
        );
        let generation = generation(1, &text);
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for (owner, other) in [(HOSTS[0], HOSTS[1]), (HOSTS[1], HOSTS[0])] {
            let capability = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(profile(&runtime, owner).capability);
            let response = request(
                &listener,
                &runtime,
                raw_request(
                    "GET",
                    &format!("/relay/?bridge={capability}"),
                    owner,
                    "",
                    &[],
                ),
            )
            .await;
            assert!(response.starts_with(b"HTTP/1.1 200"));
            let body = std::str::from_utf8(split_response(&response).1).unwrap();
            let bootstrap = body
                .split_once("bootstrap=\"")
                .unwrap()
                .1
                .split_once('"')
                .unwrap()
                .0
                .to_string();
            let hello = frame::encode(FrameType::Hello, 0, &[1]);
            let auth = format!(
                "Authorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\n"
            );
            assert_private(
                &request(
                    &listener,
                    &runtime,
                    raw_request("POST", "/relay/api/v1/session", other, &auth, &hello),
                )
                .await,
            );
            let response = request(
                &listener,
                &runtime,
                raw_request("POST", "/relay/api/v1/session", owner, &auth, &hello),
            )
            .await;
            assert!(response.starts_with(b"HTTP/1.1 200"));
            let session =
                response_header(split_response(&response).0, "x-session-token").to_string();
            assert!(matches!(
                runtime.get_session(token_hash(&session), other),
                Err(ManagerError::Authentication)
            ));
            assert_eq!(
                runtime.close_token(token_hash(&session), other, None),
                Err(ManagerError::Authentication)
            );
            assert!(
                runtime
                    .bootstrap_trace_identity(token_hash(&bootstrap), other)
                    .is_none()
            );
            assert_eq!(
                runtime.claim_bridge_diagnostic(
                    token_hash(&bootstrap),
                    other,
                    BridgeDiagnosticEvent::RuntimeStarted
                ),
                Err(ManagerError::Authentication)
            );
            for secret in [&capability, &bootstrap, &session] {
                let encoded = secret
                    .bytes()
                    .map(|byte| format!("%{byte:02X}"))
                    .collect::<String>();
                for path in [
                    format!("/relay/?bridge={secret}"),
                    format!("/wrong/{secret}"),
                    format!("/wrong/{encoded}"),
                    format!("/wrong?opaque={secret}"),
                ] {
                    assert_private(
                        &request(
                            &listener,
                            &runtime,
                            raw_request("GET", &path, other, "", &[]),
                        )
                        .await,
                    );
                }
                let head = request(
                    &listener,
                    &runtime,
                    raw_request(
                        "HEAD",
                        "/relay/",
                        other,
                        &format!("X-Opaque: {secret}\r\n"),
                        &[],
                    ),
                )
                .await;
                assert!(head.starts_with(b"HTTP/1.1 404"));
                assert_eq!(
                    response_header(split_response(&head).0, "cache-control"),
                    "no-store"
                );
            }
            for (method, path, headers, body) in [
                (
                    "POST",
                    "/relay/api/v1/up",
                    "X-Up-Seq: 0\r\n",
                    hello.as_ref(),
                ),
                (
                    "POST",
                    "/relay/api/v1/down",
                    "X-Down-Cursor: 0\r\n",
                    &[][..],
                ),
                ("DELETE", "/relay/api/v1/session", "", &[][..]),
                (
                    "POST",
                    "/relay/api/v1/diagnostic",
                    "Content-Type: application/json\r\n",
                    b"{}".as_ref(),
                ),
            ] {
                let auth = format!("Authorization: Bearer {session}\r\n{headers}");
                assert_private(
                    &request(
                        &listener,
                        &runtime,
                        raw_request(method, path, other, &auth, body),
                    )
                    .await,
                );
            }
        }
        for host in ["unknown.example.com", "A.EXAMPLE.COM", "a.example.com:444"] {
            let response =
                request(&listener, &runtime, raw_request("GET", "/", host, "", &[])).await;
            assert!(response.starts_with(b"HTTP/1.1 404"));
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), site.accept())
                .await
                .is_err()
        );
        // A positive control ensures the origin would observe an actual fallback request.
        let site_task = tokio::spawn(async move {
            let (mut socket, _) = site.accept().await.unwrap();
            let mut head = [0; 2048];
            let read = socket.read(&mut head).await.unwrap();
            assert!(
                std::str::from_utf8(&head[..read])
                    .unwrap()
                    .contains("/ordinary")
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsite")
                .await
                .unwrap();
        });
        let ordinary = request(
            &listener,
            &runtime,
            raw_request("GET", "/ordinary", HOSTS[0], "", &[]),
        )
        .await;
        assert_eq!(split_response(&ordinary).1, b"site");
        site_task.await.unwrap();
        stop(runtime, &[generation]).await;
    }
}

#[tokio::test]
async fn alias_recovery_cannot_retire_a_foreign_session() {
    let generation = generation(1, &source(SELECTOR, "127.0.0.1:18081".parse().unwrap()));
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = create(&runtime, HOSTS[0], &bootstrap(&runtime, HOSTS[0])).unwrap();
    let cap = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(profile(&runtime, HOSTS[1]).capability);
    let response = request(
        &listener,
        &runtime,
        raw_request(
            "GET",
            &format!("/relay/?bridge={cap}"),
            HOSTS[1],
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
    let value: serde_json::Value = serde_json::from_slice(split_response(&response).1).unwrap();
    let recovered = value["bootstrap"].as_str().unwrap();
    assert_eq!(
        create(&runtime, HOSTS[0], recovered),
        Err(ManagerError::Authentication)
    );
    let b = create(&runtime, HOSTS[1], recovered).unwrap();
    assert!(runtime.get_session(token_hash(&a), HOSTS[0]).is_ok());
    assert!(runtime.get_session(token_hash(&b), HOSTS[1]).is_ok());
    stop(runtime, &[generation]).await;
}

// Automatic hosts share policies but retain exact-host authentication and quotas.
#[path = "host_list_tests/wildcard.rs"]
mod wildcard;
