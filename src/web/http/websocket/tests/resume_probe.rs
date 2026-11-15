use super::*;
use crate::web::session::SessionCloseReason;

async fn assert_no_binary_until_terminal(socket: &mut WebSocketStream<TcpStream>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match tokio::time::timeout_at(deadline, socket.next())
            .await
            .expect("socket did not terminate within the negative-case deadline")
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
            Some(Ok(Message::Binary(body))) => {
                panic!("unexpected binary proof or ACK before close: {body:?}");
            }
            Some(Ok(_)) => {}
        }
    }
}

async fn try_upgrade(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    protocol: &str,
) -> (TcpStream, Vec<u8>) {
    let addr = listener.local_addr().unwrap();
    let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let permit = runtime.try_http_connection().unwrap();
    tokio::spawn(crate::web::http::serve_connection(
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
        response.push(client.read_u8().await.unwrap());
        assert!(response.len() <= 16 * 1024);
    }
    (client, response)
}

#[tokio::test]
async fn committed_websocket_echoes_exact_resume_probe_without_consuming_sequence() {
    for (carrier, carriers, protocol) in [
        (
            WebCarrier::Https,
            Arc::from([WebCarrier::Websocket, WebCarrier::Https]),
            0,
        ),
        (
            WebCarrier::HttpsLanes,
            Arc::from([WebCarrier::WebsocketLanes, WebCarrier::HttpsLanes]),
            7,
        ),
    ] {
        let live = live_negotiation_runtime(carrier, carriers);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_bootstrap_hash, _hello, session, session_hash) =
            create_automatic_session(&live.runtime);
        let subprotocol = if protocol == 0 {
            format!("tproxy-auto-v1.{session}")
        } else {
            format!("tproxy-auto-lane-v1.{session}.{protocol}")
        };
        let mut socket = upgrade(&listener, &live.runtime, &subprotocol).await;
        let stream = if protocol == 0 { 1 } else { protocol };
        socket
            .send(Message::Binary(frame::encode(FrameType::Open, stream, &[])))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::Binary(Bytes::new())
        );
        assert!(
            live.runtime
                .get_session(session_hash, "proxy.example.com")
                .unwrap()
                .is_carrier_committed()
        );

        let nonce = [0xA5; 16];
        socket
            .send(Message::Binary(frame::encode(FrameType::Ping, 0, &nonce)))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::Binary(frame::encode(FrameType::Pong, 0, &nonce))
        );

        socket
            .send(Message::Binary(frame::encode(
                FrameType::Window,
                stream,
                &frame::window_payload(1),
            )))
            .await
            .unwrap();
        socket
            .send(Message::Ping(Bytes::from_static(b"resume-sequence")))
            .await
            .unwrap();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if message == Message::Pong(Bytes::from_static(b"resume-sequence")) {
                break;
            }
        }
        let _ = socket.close(None).await;
        live.shutdown().await;
    }
}

#[tokio::test]
async fn uncommitted_socket_cannot_answer_resume_probe_or_commit() {
    let live = live_negotiation_runtime(
        WebCarrier::Https,
        Arc::from([WebCarrier::Websocket, WebCarrier::Https]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_bootstrap_hash, _hello, session_token, session_hash) =
        create_automatic_session(&live.runtime);
    let protocol = format!("tproxy-auto-v1.{session_token}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    let session = live
        .runtime
        .get_session(session_hash, "proxy.example.com")
        .unwrap();
    socket
        .send(Message::Binary(frame::encode(
            FrameType::Ping,
            0,
            &[0xB1; 16],
        )))
        .await
        .unwrap();
    assert_no_binary_until_terminal(&mut socket).await;
    assert!(!session.is_carrier_committed());
    live.shutdown().await;
}

#[tokio::test]
async fn changed_generation_cannot_answer_committed_resume_probe() {
    let live = live_negotiation_runtime(
        WebCarrier::Https,
        Arc::from([WebCarrier::Websocket, WebCarrier::Https]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_bootstrap_hash, _hello, session_token, session_hash) =
        create_automatic_session(&live.runtime);
    let protocol = format!("tproxy-auto-v1.{session_token}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    socket
        .send(Message::Binary(frame::encode(FrameType::Open, 7, &[])))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Binary(Bytes::new())
    );
    let session = live
        .runtime
        .get_session(session_hash, "proxy.example.com")
        .unwrap();
    let next_generation = test_runtime_generation(2, (*live.generation.config()).clone());
    let replaced = live
        .runtime
        .activate_generation(Arc::clone(&next_generation));
    assert_eq!(replaced.id, 1);
    socket
        .send(Message::Binary(frame::encode(
            FrameType::Ping,
            0,
            &[0xC2; 16],
        )))
        .await
        .unwrap();
    assert_no_binary_until_terminal(&mut socket).await;
    assert!(!session.current_generation_matches());
    live.runtime.shutdown().await;
    live.generation.stop_sessions().await;
    live.generation.stop_background_tasks().await;
    next_generation.stop_sessions().await;
    next_generation.stop_background_tasks().await;
}

#[tokio::test]
async fn replacement_attempt_keeps_its_issuing_generation_after_profile_removal() {
    let live = live_negotiation_runtime(
        WebCarrier::Https,
        Arc::from([WebCarrier::Https, WebCarrier::Websocket]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (bootstrap_hash, hello, _, _) = create_automatic_session(&live.runtime);

    let next_generation = test_runtime_generation(
        2,
        negotiation_runtime_config(
            [31; 32],
            WebCarrier::Https,
            false,
            Arc::from([WebCarrier::Https]),
        ),
    );
    let replaced = live
        .runtime
        .activate_generation(Arc::clone(&next_generation));
    assert_eq!(replaced.id, 1);

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
                Some(CarrierFailure::Network),
                [9; 32],
            ),
            false,
        )
        .unwrap();
    assert_eq!(replacement.carrier, WebCarrier::Websocket);
    assert_eq!(replacement.attempt, Some(2));
    let session_hash = Sha256::digest(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&replacement.token)
            .unwrap(),
    )
    .into();
    let session = live
        .runtime
        .get_session(session_hash, "proxy.example.com")
        .unwrap();
    assert_eq!(session.generation_id(), 1);
    assert!(!session.current_generation_matches());

    let protocol = format!("tproxy-auto-v1.{}", replacement.token);
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    socket
        .send(Message::Binary(frame::encode(FrameType::Open, 7, &[])))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Binary(Bytes::new())
    );
    socket
        .send(Message::Binary(frame::encode(
            FrameType::Ping,
            0,
            &[0xD7; 16],
        )))
        .await
        .unwrap();
    assert_no_binary_until_terminal(&mut socket).await;

    live.runtime.shutdown().await;
    live.generation.stop_sessions().await;
    live.generation.stop_background_tasks().await;
    next_generation.stop_sessions().await;
    next_generation.stop_background_tasks().await;
}

#[tokio::test]
async fn old_generation_selected_before_websocket_construction_cannot_prove_resume() {
    let live = live_negotiation_runtime(
        WebCarrier::Https,
        Arc::from([WebCarrier::Websocket, WebCarrier::Https]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_bootstrap_hash, _hello, session_token, session_hash) =
        create_automatic_session(&live.runtime);
    let session = live
        .runtime
        .get_session(session_hash, "proxy.example.com")
        .unwrap();
    let next_generation = test_runtime_generation(2, (*live.generation.config()).clone());
    let replaced = live
        .runtime
        .activate_generation(Arc::clone(&next_generation));
    assert_eq!(replaced.id, 1);
    assert!(!session.current_generation_matches());

    let protocol = format!("tproxy-auto-v1.{session_token}");
    let (client, response) = try_upgrade(&listener, &live.runtime, &protocol).await;
    if response.starts_with(b"HTTP/1.1 101") {
        let mut socket = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        socket
            .send(Message::Binary(frame::encode(FrameType::Open, 7, &[])))
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap();
        let committed = match first {
            Some(Ok(Message::Binary(body))) if body.is_empty() => true,
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => false,
            other => panic!("unexpected stale-generation OPEN response: {other:?}"),
        };
        if committed {
            socket
                .send(Message::Binary(frame::encode(
                    FrameType::Ping,
                    0,
                    &[0xC3; 16],
                )))
                .await
                .unwrap();
            assert_no_binary_until_terminal(&mut socket).await;
        }
    } else {
        assert!(!response.starts_with(b"HTTP/1.1 101"));
    }
    assert!(!session.current_generation_matches());
    live.runtime.shutdown().await;
    live.generation.stop_sessions().await;
    live.generation.stop_background_tasks().await;
    next_generation.stop_sessions().await;
    next_generation.stop_background_tasks().await;
}

#[tokio::test]
async fn cancelled_committed_session_cannot_answer_resume_probe() {
    let live = live_negotiation_runtime(
        WebCarrier::Https,
        Arc::from([WebCarrier::Websocket, WebCarrier::Https]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_bootstrap_hash, _hello, session_token, session_hash) =
        create_automatic_session(&live.runtime);
    let protocol = format!("tproxy-auto-v1.{session_token}");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    socket
        .send(Message::Binary(frame::encode(FrameType::Open, 7, &[])))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Binary(Bytes::new())
    );
    let session = live
        .runtime
        .get_session(session_hash, "proxy.example.com")
        .unwrap();
    assert!(session.is_resume_probe_eligible());
    session.close(SessionCloseReason::ApiClose);
    assert!(!session.is_resume_probe_eligible());
    let _ = socket
        .send(Message::Binary(frame::encode(
            FrameType::Ping,
            0,
            &[0xD4; 16],
        )))
        .await;
    assert_no_binary_until_terminal(&mut socket).await;
    live.shutdown().await;
}

#[tokio::test]
async fn mixed_resume_challenge_and_data_never_get_a_proof_reply() {
    let live = live_negotiation_runtime(
        WebCarrier::HttpsLanes,
        Arc::from([WebCarrier::WebsocketLanes, WebCarrier::HttpsLanes]),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_bootstrap_hash, _hello, session_token, _session_hash) =
        create_automatic_session(&live.runtime);
    let protocol = format!("tproxy-auto-lane-v1.{session_token}.7");
    let mut socket = upgrade(&listener, &live.runtime, &protocol).await;
    socket
        .send(Message::Binary(frame::encode(FrameType::Open, 7, &[])))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Binary(Bytes::new())
    );
    let mut mixed = frame::encode(FrameType::Ping, 0, &[0xD3; 16]).to_vec();
    mixed.extend_from_slice(&frame::encode(FrameType::Data, 7, &[1]));
    socket.send(Message::Binary(mixed.into())).await.unwrap();
    assert_no_binary_until_terminal(&mut socket).await;
    let _ = socket.close(None).await;
    live.shutdown().await;
}
