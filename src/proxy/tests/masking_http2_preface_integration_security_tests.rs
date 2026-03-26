use super::*;
use tokio::net::TcpListener;
use tokio::time::Duration;

#[tokio::test]
async fn http2_preface_is_forwarded_and_recorded_as_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let preface = preface.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; preface.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, preface);
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "198.51.100.130:54130".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let (client_reader, _client_writer) = tokio::io::duplex(512);
    let (_client_visible_reader, client_visible_writer) = tokio::io::duplex(512);
    let beobachten = BeobachtenStore::new();

    handle_bad_client(
        client_reader,
        client_visible_writer,
        &preface,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[HTTP]"));
    assert!(snapshot.contains("198.51.100.130-1"));
}
