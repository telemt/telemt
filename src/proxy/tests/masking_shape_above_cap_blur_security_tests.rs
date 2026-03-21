use super::*;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Duration;

async fn capture_forwarded_len(
    body_sent: usize,
    shape_hardening: bool,
    above_cap_blur: bool,
    above_cap_blur_max_bytes: usize,
) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = shape_hardening;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;
    config.censorship.mask_shape_above_cap_blur = above_cap_blur;
    config.censorship.mask_shape_above_cap_blur_max_bytes = above_cap_blur_max_bytes;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got.len()
    });

    let (server_reader, mut client_writer) = duplex(64 * 1024);
    let (_client_visible_reader, client_visible_writer) = duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.220:57120".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&7000u16.to_be_bytes());
    probe[5..].fill(0x5A);

    let fallback = tokio::spawn(async move {
        handle_bad_client(
            server_reader,
            client_visible_writer,
            &probe,
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(4), fallback)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn above_cap_blur_disabled_keeps_exact_above_cap_length() {
    let body_sent = 5000usize;
    let observed = capture_forwarded_len(body_sent, true, false, 0).await;
    assert_eq!(observed, 5 + body_sent);
}

#[tokio::test]
async fn above_cap_blur_enabled_adds_bounded_random_tail() {
    let body_sent = 5000usize;
    let base = 5 + body_sent;
    let max_extra = 64usize;

    let mut saw_extra = false;
    for _ in 0..20 {
        let observed = capture_forwarded_len(body_sent, true, true, max_extra).await;
        assert!(observed >= base, "observed={observed} base={base}");
        assert!(
            observed <= base + max_extra,
            "observed={observed} base={} max_extra={max_extra}",
            base
        );
        if observed > base {
            saw_extra = true;
        }
    }

    assert!(
        saw_extra,
        "at least one run should produce above-cap blur bytes under randomization"
    );
}
