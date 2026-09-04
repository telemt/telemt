use super::*;

async fn observed_budget(runtime: &WebProcessRuntime) -> u64 {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = serde_json::to_value(runtime.try_status()).unwrap();
            if let Some(bytes) = status["budget"]["websocket_bytes"].as_u64() {
                return bytes;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("WEB budget snapshot remained unavailable")
}

async fn wait_budget(runtime: &WebProcessRuntime, expected: u64) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if observed_budget(runtime).await == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("WEB budget did not settle at {expected} bytes"));
}

async fn assert_stable_budget(runtime: &WebProcessRuntime, expected: u64) {
    // Exclude the transient release between consecutive driver iterations.
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(observed_budget(runtime).await, expected);
    }
}

async fn expect_pong(socket: &mut WebSocketStream<TcpStream>, expected: &[u8]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Pong(payload) if payload.as_ref() == expected => return,
                Message::Ping(_) => {
                    socket.flush().await.unwrap();
                }
                other => panic!("expected matching Pong, received {other:?}"),
            }
        }
    })
    .await
    .expect("WebSocket Pong timed out");
}

#[tokio::test]
async fn idle_websocket_does_not_reserve_maximum_message_budget() {
    let live = live_runtime_with_long_poll(WebCarrier::Websocket, 10);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&live.runtime);
    let mut socket = upgrade(&listener, &live.runtime, &format!("tproxy-v1.{session}")).await;
    socket
        .send(Message::Ping(Bytes::from_static(b"idle-budget")))
        .await
        .unwrap();
    expect_pong(&mut socket, b"idle-budget").await;
    let base = BASE_BUDGET_BYTES as u64;
    wait_budget(&live.runtime, base).await;
    assert_stable_budget(&live.runtime, base).await;
    let _ = socket.close(None).await;
    live.shutdown().await;
}

#[tokio::test]
async fn partial_header_retains_budget_until_message_completes() {
    let live = live_runtime_with_long_poll(WebCarrier::Websocket, 10);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&live.runtime);
    let maximum = live
        .runtime
        .active_generation()
        .config()
        .web
        .limits
        .carrier_batch_bytes as u64;
    let base = BASE_BUDGET_BYTES as u64;
    let mut socket = upgrade(&listener, &live.runtime, &format!("tproxy-v1.{session}")).await;
    let body = frame::encode(FrameType::Pong, 0, &[]);
    let wire = masked_message(0x02, &body, [1, 2, 3, 4]);

    socket.get_mut().write_all(&wire[..1]).await.unwrap();
    wait_budget(&live.runtime, base + maximum).await;
    assert_stable_budget(&live.runtime, base + maximum).await;

    let mut tail = wire[1..].to_vec();
    tail.extend_from_slice(&masked_message(0x09, b"header-complete", [5, 6, 7, 8]));
    socket.get_mut().write_all(&tail).await.unwrap();
    expect_pong(&mut socket, b"header-complete").await;
    wait_budget(&live.runtime, base).await;
    assert_stable_budget(&live.runtime, base).await;
    let _ = socket.close(None).await;
    live.shutdown().await;
}

#[tokio::test]
async fn fragmented_budget_survives_cancelled_read_and_control_frames() {
    let live = live_runtime_with_long_poll(WebCarrier::Websocket, 1);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&live.runtime);
    let maximum = live
        .runtime
        .active_generation()
        .config()
        .web
        .limits
        .carrier_batch_bytes as u64;
    let base = BASE_BUDGET_BYTES as u64;
    let mut socket = upgrade(&listener, &live.runtime, &format!("tproxy-v1.{session}")).await;
    let body = frame::encode(FrameType::Pong, 0, &[]);
    let first = masked_frame(false, 0x02, &body[..4], [1, 2, 3, 4]);
    socket.get_mut().write_all(&first).await.unwrap();
    wait_budget(&live.runtime, base + maximum).await;

    // The outgoing liveness Ping cancels the pending outer select read branch.
    let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("server did not send its liveness Ping")
        .unwrap()
        .unwrap();
    assert!(matches!(message, Message::Ping(_)));
    socket.flush().await.unwrap();
    assert_stable_budget(&live.runtime, base + maximum).await;

    let middle_ping = masked_message(0x09, b"fragment-mid", [5, 6, 7, 8]);
    socket.get_mut().write_all(&middle_ping).await.unwrap();
    expect_pong(&mut socket, b"fragment-mid").await;
    assert_stable_budget(&live.runtime, base + maximum).await;

    let mut tail = masked_frame(true, 0x00, &body[4..], [9, 10, 11, 12]);
    tail.extend_from_slice(&masked_message(
        0x09,
        b"fragment-complete",
        [13, 14, 15, 16],
    ));
    socket.get_mut().write_all(&tail).await.unwrap();
    expect_pong(&mut socket, b"fragment-complete").await;
    wait_budget(&live.runtime, base).await;
    assert_stable_budget(&live.runtime, base).await;
    let _ = socket.close(None).await;
    live.shutdown().await;
}
