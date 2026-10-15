use super::*;

#[tokio::test]
async fn automatic_websocket_accepts_queued_control_after_open_before_ack_read() {
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
        socket
            .send(Message::Binary(frame::encode(
                FrameType::Window,
                7,
                &frame::window_payload(1),
            )))
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
            .send(Message::Ping(Bytes::from_static(b"pre-ack")))
            .await
            .unwrap();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if message == Message::Pong(Bytes::from_static(b"pre-ack")) {
                break;
            }
        }

        let _ = socket.close(None).await;
        live.shutdown().await;
    }
}
