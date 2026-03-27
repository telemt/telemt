use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::Duration;

async fn capture_forwarded_len_with_mode(
    body_sent: usize,
    close_client_after_write: bool,
    aggressive_mode: bool,
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
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_hardening_aggressive_mode = aggressive_mode;
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
    let peer: SocketAddr = "198.51.100.248:57248".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&7000u16.to_be_bytes());
    probe[5..].fill(0x31);

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

    if close_client_after_write {
        client_writer.shutdown().await.unwrap();
    } else {
        client_writer.write_all(b"keepalive").await.unwrap();
        tokio::time::sleep(Duration::from_millis(170)).await;
        drop(client_writer);
    }

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
async fn aggressive_mode_shapes_backend_silent_non_eof_path() {
    let body_sent = 17usize;
    let floor = 512usize;

    let legacy = capture_forwarded_len_with_mode(body_sent, false, false, false, 0).await;
    let aggressive = capture_forwarded_len_with_mode(body_sent, false, true, false, 0).await;

    assert!(
        legacy < floor,
        "legacy mode should keep timeout path unshaped"
    );
    assert!(
        aggressive >= floor,
        "aggressive mode must shape backend-silent non-EOF paths (aggressive={aggressive}, floor={floor})"
    );
}

#[tokio::test]
async fn aggressive_mode_enforces_positive_above_cap_blur() {
    let body_sent = 5000usize;
    let base = 5 + body_sent;

    for _ in 0..48 {
        let observed = capture_forwarded_len_with_mode(body_sent, true, true, true, 1).await;
        assert!(
            observed > base,
            "aggressive mode must not emit exact base length when blur is enabled (observed={observed}, base={base})"
        );
    }
}
