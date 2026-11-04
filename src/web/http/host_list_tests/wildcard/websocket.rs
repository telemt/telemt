use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn wildcard_websocket_upgrade_uses_actual_host_without_cold_derivation() {
    let text = wildcard_source(
        "host = \"*.example.com\"",
        "127.0.0.1:18081".parse().unwrap(),
    )
    .replace("carrier = \"https\"", "carrier = \"websocket\"")
        + "\n[web.limits.wildcard]\nmax_profiles_per_request = 1\ncold_hmac_burst = 1\ncold_hmac_per_minute = 1\ncache_hosts = 0\n";
    let generation = generation(1, &text);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = bridge(&listener, &runtime, HOSTS[0]).await;
    let session = create(&runtime, HOSTS[0], &bootstrap).unwrap();
    for (host, status) in [(HOSTS[1], b"HTTP/1.1 404"), (HOSTS[0], b"HTTP/1.1 101")] {
        let (accepted, client) = tokio::join!(
            listener.accept(),
            TcpStream::connect(listener.local_addr().unwrap())
        );
        let (server, peer) = accepted.unwrap();
        let mut client = client.unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(crate::web::http::serve_connection(
            server,
            peer,
            crate::config::WebClientIpSource::XForwardedFor,
            Arc::from(["127.0.0.1/32".parse().unwrap()]),
            runtime.clone(),
            cancel.clone(),
            runtime.try_http_connection().unwrap(),
        ));
        client.write_all(format!("GET /relay/api/v1/ws HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: tproxy-v1.{session}\r\nCookie: ordinary=allowed\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(
                tokio::time::timeout(Duration::from_secs(2), client.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert!(response.len() < 16 * 1024);
        }
        assert!(
            response.starts_with(status),
            "{}",
            String::from_utf8_lossy(&response)
        );
        drop(client);
        cancel.cancel();
        task.await.unwrap();
    }
    assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats(), (0, 0, 1));
    stop(runtime, &[generation]).await;
}
