use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::Duration;

async fn capture_forwarded_len_with_optional_eof(
    body_sent: usize,
    shape_hardening: bool,
    above_cap_blur: bool,
    above_cap_blur_max_bytes: usize,
    close_client_after_write: bool,
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
    let peer: SocketAddr = "198.51.100.241:57241".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&7000u16.to_be_bytes());
    probe[5..].fill(0x73);

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
#[ignore = "red-team detector: shaping on non-EOF timeout path is disabled by design to prevent post-timeout tail leaks"]
async fn security_shape_padding_applies_without_client_eof_when_backend_silent() {
    let body_sent = 17usize;
    let hardened_floor = 512usize;

    let with_eof = capture_forwarded_len_with_optional_eof(body_sent, true, false, 0, true).await;
    let without_eof =
        capture_forwarded_len_with_optional_eof(body_sent, true, false, 0, false).await;

    assert!(
        with_eof >= hardened_floor,
        "EOF path should be shaped to floor (with_eof={with_eof}, floor={hardened_floor})"
    );
    assert!(
        without_eof >= hardened_floor,
        "non-EOF path should also be shaped when backend is silent (without_eof={without_eof}, floor={hardened_floor})"
    );
}

#[tokio::test]
#[ignore = "red-team detector: blur currently allows zero-extra sample by design within [0..=max] bound"]
async fn security_above_cap_blur_never_emits_exact_base_length() {
    let body_sent = 5000usize;
    let base = 5 + body_sent;
    let max_blur = 1usize;

    for _ in 0..64 {
        let observed =
            capture_forwarded_len_with_optional_eof(body_sent, true, true, max_blur, true).await;
        assert!(
            observed > base,
            "above-cap blur must add at least one byte when enabled (observed={observed}, base={base})"
        );
    }
}

#[tokio::test]
#[ignore = "red-team detector: shape padding currently depends on EOF, enabling idle-timeout bypass probes"]
async fn redteam_detector_shape_padding_must_not_depend_on_client_eof() {
    let body_sent = 17usize;
    let hardened_floor = 512usize;

    let with_eof = capture_forwarded_len_with_optional_eof(body_sent, true, false, 0, true).await;
    let without_eof =
        capture_forwarded_len_with_optional_eof(body_sent, true, false, 0, false).await;

    assert!(
        with_eof >= hardened_floor,
        "sanity check failed: EOF path should be shaped to floor (with_eof={with_eof}, floor={hardened_floor})"
    );

    assert!(
        without_eof >= hardened_floor,
        "strict anti-probing model expects shaping even without EOF; observed without_eof={without_eof}, floor={hardened_floor}"
    );
}

#[tokio::test]
#[ignore = "red-team detector: zero-extra above-cap blur samples leak exact class boundary"]
async fn redteam_detector_above_cap_blur_must_never_emit_exact_base_length() {
    let body_sent = 5000usize;
    let base = 5 + body_sent;
    let mut saw_exact_base = false;
    let max_blur = 1usize;

    for _ in 0..96 {
        let observed =
            capture_forwarded_len_with_optional_eof(body_sent, true, true, max_blur, true).await;
        if observed == base {
            saw_exact_base = true;
            break;
        }
    }

    assert!(
        !saw_exact_base,
        "strict anti-classifier model expects >0 blur always; observed exact base length leaks class"
    );
}

#[tokio::test]
#[ignore = "red-team detector: disjoint above-cap ranges enable near-perfect size-class classification"]
async fn redteam_detector_above_cap_blur_ranges_for_far_classes_should_overlap() {
    let mut a_min = usize::MAX;
    let mut a_max = 0usize;
    let mut b_min = usize::MAX;
    let mut b_max = 0usize;

    for _ in 0..48 {
        let a = capture_forwarded_len_with_optional_eof(5000, true, true, 64, true).await;
        let b = capture_forwarded_len_with_optional_eof(7000, true, true, 64, true).await;
        a_min = a_min.min(a);
        a_max = a_max.max(a);
        b_min = b_min.min(b);
        b_max = b_max.max(b);
    }

    let overlap = a_min <= b_max && b_min <= a_max;
    assert!(
        overlap,
        "strict anti-classifier model expects overlapping output bands; class_a=[{a_min},{a_max}] class_b=[{b_min},{b_max}]"
    );
}
