use super::*;

mod capacity;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_util::sync::CancellationToken;

use crate::maestro::generation::{RuntimeGeneration, test_runtime_generation};
use crate::web::frame::{self, FrameType};
use crate::web::http::tests::{negotiation_runtime_config, runtime_config};
use crate::web::manager::{
    CarrierCapabilities, CarrierClientClass, CarrierFailure, CarrierRequest, WebProcessRuntime,
};

fn request(protocol: &str) -> Request<()> {
    Request::builder()
        .method(Method::GET)
        .uri("/api/v1/ws")
        .header(header::CONNECTION, "keep-alive, Upgrade")
        .header(header::UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", protocol)
        .body(())
        .unwrap()
}

#[test]
fn canonical_multiplex_and_lane_protocols_are_accepted() {
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    let multiplex = parse_upgrade(&request(&format!("tproxy-v1.{token}"))).unwrap();
    assert!(matches!(multiplex.carrier, ParsedCarrier::Multiplex));
    assert_eq!(multiplex.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

    let lane = parse_upgrade(&request(&format!("tproxy-lane-v1.{token}.16777215"))).unwrap();
    assert!(matches!(lane.carrier, ParsedCarrier::Lane(16_777_215)));

    let automatic = parse_upgrade(&request(&format!("tproxy-auto-v1.{token}"))).unwrap();
    assert!(automatic.acknowledge_commit);
    let automatic_lane =
        parse_upgrade(&request(&format!("tproxy-auto-lane-v1.{token}.7"))).unwrap();
    assert!(matches!(automatic_lane.carrier, ParsedCarrier::Lane(7)));
    assert!(automatic_lane.acknowledge_commit);
    assert!(!multiplex.acknowledge_commit);
}

#[test]
fn aliases_authorization_and_request_bodies_are_rejected_before_upgrade() {
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    assert!(parse_upgrade(&request(&format!("tproxy-lane-v1.{token}.01"))).is_none());
    assert!(parse_upgrade(&request(&format!("tproxy-lane-v1.{token}.0"))).is_none());

    let with_authorization = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/ws")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::AUTHORIZATION, "Bearer hidden")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", format!("tproxy-v1.{token}"))
        .body(())
        .unwrap();
    assert!(parse_upgrade(&with_authorization).is_none());

    let with_body = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/ws")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::CONTENT_LENGTH, "1")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", format!("tproxy-v1.{token}"))
        .body(())
        .unwrap();
    assert!(parse_upgrade(&with_body).is_none());
}

struct LiveRuntime {
    runtime: Arc<WebProcessRuntime>,
    generation: Arc<RuntimeGeneration>,
}

impl LiveRuntime {
    async fn shutdown(self) {
        self.runtime.shutdown().await;
        self.generation.stop_sessions().await;
        self.generation.stop_background_tasks().await;
    }
}

fn live_runtime(carrier: WebCarrier) -> LiveRuntime {
    live_runtime_with_long_poll(carrier, 1)
}

fn live_runtime_with_long_poll(carrier: WebCarrier, long_poll_secs: u64) -> LiveRuntime {
    live_runtime_from_config(runtime_config([31; 32], carrier), long_poll_secs)
}

fn live_negotiation_runtime(carrier: WebCarrier, carriers: Arc<[WebCarrier]>) -> LiveRuntime {
    live_runtime_from_config(
        negotiation_runtime_config([31; 32], carrier, false, carriers),
        1,
    )
}

fn live_runtime_from_config(
    mut config: crate::config::ProxyConfig,
    long_poll_secs: u64,
) -> LiveRuntime {
    config.web.timeouts.long_poll_secs = long_poll_secs;
    config.web.timeouts.websocket_write_secs = 2;
    config.web.timeouts.websocket_backpressure_secs = 2;
    config.web.timeouts.websocket_eviction_secs = 1;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    LiveRuntime {
        runtime,
        generation,
    }
}

fn create_automatic_session(
    runtime: &Arc<WebProcessRuntime>,
) -> (TokenHash, Bytes, String, TokenHash) {
    let profile = runtime
        .active_generation()
        .config()
        .web
        .runtime
        .as_ref()
        .unwrap()
        .profiles[0]
        .clone();
    let client_ip = "192.0.2.10".parse().unwrap();
    let bootstrap = runtime.issue_bootstrap(profile, client_ip).unwrap().token;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&bootstrap)
        .unwrap();
    let bootstrap_hash = Sha256::digest(raw).into();
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let session = runtime
        .create_session(
            bootstrap_hash,
            "proxy.example.com",
            client_ip,
            &hello,
            CarrierRequest::automatic(
                CarrierClientClass::Bridge,
                CarrierCapabilities::all(),
                1,
                None,
                [9; 32],
            ),
            false,
        )
        .unwrap()
        .token;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&session)
        .unwrap();
    let session_hash = Sha256::digest(raw).into();
    (bootstrap_hash, hello, session, session_hash)
}

fn create_session(runtime: &Arc<WebProcessRuntime>) -> (String, TokenHash) {
    let profile = runtime
        .active_generation()
        .config()
        .web
        .runtime
        .as_ref()
        .unwrap()
        .profiles[0]
        .clone();
    let client_ip = "192.0.2.10".parse().unwrap();
    let bootstrap = runtime.issue_bootstrap(profile, client_ip).unwrap().token;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&bootstrap)
        .unwrap();
    let bootstrap_hash = Sha256::digest(raw).into();
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let session = runtime
        .create_session(
            bootstrap_hash,
            "proxy.example.com",
            client_ip,
            &hello,
            CarrierRequest::legacy([0; 32]),
            false,
        )
        .unwrap()
        .token;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&session)
        .unwrap();
    let session_hash = Sha256::digest(raw).into();
    (session, session_hash)
}

async fn upgrade(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    protocol: &str,
) -> WebSocketStream<TcpStream> {
    let addr = listener.local_addr().unwrap();
    let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let permit = runtime.try_http_connection().unwrap();
    tokio::spawn(super::super::serve_connection(
        server,
        peer,
        WebClientIpSource::XForwardedFor,
        Arc::from(["127.0.0.1/32".parse().unwrap()]),
        Arc::clone(runtime),
        CancellationToken::new(),
        permit,
    ));
    let request = format!(
        "GET /api/v1/ws HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: {protocol}\r\nCookie: browser-state=allowed\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let byte = client.read_u8().await.unwrap();
        response.push(byte);
        assert!(response.len() <= 16 * 1024);
    }
    assert!(response.starts_with(b"HTTP/1.1 101"));
    assert!(
        std::str::from_utf8(&response)
            .unwrap()
            .contains(&format!("sec-websocket-protocol: {protocol}"))
    );
    WebSocketStream::from_raw_socket(client, Role::Client, None).await
}

fn masked_message(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    masked_frame(true, opcode, payload, mask)
}

fn masked_frame(finished: bool, opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mut encoded = Vec::with_capacity(payload.len() + 6);
    encoded.push(u8::from(finished) << 7 | opcode);
    encoded.push(0x80 | payload.len() as u8);
    encoded.extend_from_slice(&mask);
    encoded.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, value)| value ^ mask[index % mask.len()]),
    );
    encoded
}

#[tokio::test]
async fn multiplex_upgrade_relays_binary_and_transport_control_messages() {
    let live = live_runtime(WebCarrier::Websocket);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&live.runtime);
    let protocol = format!("tproxy-v1.{session}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;

    socket
        .send(Message::Binary(frame::encode(FrameType::Pong, 0, &[])))
        .await
        .unwrap();
    socket
        .send(Message::Ping(Bytes::from_static(b"live")))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, Message::Pong(Bytes::from_static(b"live")));

    let _ = socket.close(None).await;
    live.shutdown().await;
}

#[tokio::test]
async fn coalesced_websocket_messages_do_not_wait_for_new_tcp_readiness() {
    let live = live_runtime_with_long_poll(WebCarrier::Websocket, 10);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&live.runtime);
    let protocol = format!("tproxy-v1.{session}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    let mut wire = masked_message(0x02, &frame::encode(FrameType::Pong, 0, &[]), [1, 2, 3, 4]);
    wire.extend_from_slice(&masked_message(0x09, b"coalesced", [5, 6, 7, 8]));
    socket.get_mut().write_all(&wire).await.unwrap();

    let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, Message::Pong(Bytes::from_static(b"coalesced")));

    let _ = socket.close(None).await;
    live.shutdown().await;
}

#[tokio::test]
async fn fragmented_message_budget_survives_interleaved_control_frames() {
    let live = live_runtime_with_long_poll(WebCarrier::Websocket, 10);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&live.runtime);
    let protocol = format!("tproxy-v1.{session}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    let body = frame::encode(FrameType::Pong, 0, &[]);
    let mut wire = masked_frame(false, 0x02, &body[..4], [1, 2, 3, 4]);
    wire.extend_from_slice(&masked_message(0x09, b"mid", [5, 6, 7, 8]));
    wire.extend_from_slice(&masked_frame(true, 0x00, &body[4..], [9, 10, 11, 12]));
    wire.extend_from_slice(&masked_message(0x09, b"after", [13, 14, 15, 16]));
    socket.get_mut().write_all(&wire).await.unwrap();

    for expected in [b"mid".as_slice(), b"after".as_slice()] {
        let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response, Message::Pong(Bytes::copy_from_slice(expected)));
    }

    let _ = socket.close(None).await;
    live.shutdown().await;
}

#[tokio::test]
async fn malformed_websocket_lane_closes_only_that_lane() {
    let live = live_runtime(WebCarrier::WebsocketLanes);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, session_hash) = create_session(&live.runtime);
    let first_protocol = format!("tproxy-lane-v1.{session}.7");
    let mut first = upgrade(&listener, &live.runtime, &first_protocol).await;
    first
        .send(Message::Binary(frame::encode(FrameType::Data, 7, &[1])))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), first.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(closed, Message::Close(_)));
    assert!(
        live.runtime
            .get_session(session_hash, "proxy.example.com")
            .is_ok()
    );

    let second_protocol = format!("tproxy-lane-v1.{session}.8");
    let mut second = upgrade(&listener, &live.runtime, &second_protocol).await;
    second
        .send(Message::Binary(frame::encode(FrameType::Open, 8, &[])))
        .await
        .unwrap();
    second
        .send(Message::Ping(Bytes::from_static(b"lane")))
        .await
        .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(2), second.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(pong, Message::Pong(Bytes::from_static(b"lane")));

    let _ = second.close(None).await;
    live.shutdown().await;
}

#[tokio::test]
async fn automatic_websocket_carriers_commit_after_acknowledged_peer_progress() {
    for carrier in [WebCarrier::Websocket, WebCarrier::WebsocketLanes] {
        let live = live_negotiation_runtime(carrier, Arc::from([carrier]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_, _, session, session_hash) = create_automatic_session(&live.runtime);
        let protocol = match carrier {
            WebCarrier::Websocket => format!("tproxy-auto-v1.{session}"),
            WebCarrier::WebsocketLanes => format!("tproxy-auto-lane-v1.{session}.7"),
            _ => unreachable!(),
        };
        let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
        socket
            .send(Message::Binary(frame::encode(FrameType::Open, 7, &[])))
            .await
            .unwrap();
        let acknowledgement = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(acknowledgement, Message::Binary(Bytes::new()));
        assert!(
            live.runtime
                .get_session(session_hash, "proxy.example.com")
                .unwrap()
                .is_carrier_committed()
        );
        socket
            .send(Message::Binary(frame::encode(
                FrameType::Window,
                7,
                &frame::window_payload(1),
            )))
            .await
            .unwrap();
        socket
            .send(Message::Ping(Bytes::from_static(b"commit")))
            .await
            .unwrap();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if message == Message::Pong(Bytes::from_static(b"commit")) {
                break;
            }
        }
        assert!(
            live.runtime
                .get_session(session_hash, "proxy.example.com")
                .unwrap()
                .is_carrier_committed()
        );

        let _ = socket.close(None).await;
        live.shutdown().await;
    }
}

#[tokio::test]
async fn failed_automatic_multiplex_socket_remains_supersedable() {
    let live = live_negotiation_runtime(
        WebCarrier::Https,
        Arc::from([WebCarrier::Websocket, WebCarrier::Https]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (bootstrap_hash, hello, session, session_hash) = create_automatic_session(&live.runtime);
    let protocol = format!("tproxy-auto-v1.{session}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    socket.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        live.runtime
            .get_session(session_hash, "proxy.example.com")
            .is_ok()
    );

    let replacement = live
        .runtime
        .create_session(
            bootstrap_hash,
            "proxy.example.com",
            "192.0.2.10".parse().unwrap(),
            &hello,
            CarrierRequest::automatic(
                CarrierClientClass::Bridge,
                CarrierCapabilities::all(),
                2,
                Some(CarrierFailure::Upgrade),
                [9; 32],
            ),
            false,
        )
        .unwrap();
    assert_eq!(replacement.carrier, WebCarrier::Https);
    assert_eq!(replacement.attempt, Some(2));

    live.shutdown().await;
}
