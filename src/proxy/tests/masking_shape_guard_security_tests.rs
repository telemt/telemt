use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn shape_guard_empty_initial_data_keeps_transparent_length_on_clean_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let client_payload = vec![0x7A; 64];

    let accept_task = tokio::spawn({
        let expected = client_payload.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            assert_eq!(
                got, expected,
                "empty initial_data path must not inject shape padding"
            );
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;

    let peer: SocketAddr = "203.0.113.90:52001".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (mut client_writer, client_reader) = duplex(2048);
    let (_client_visible_reader, client_visible_writer) = duplex(2048);

    let relay_task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            b"",
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.write_all(&client_payload).await.unwrap();
    client_writer.shutdown().await.unwrap();

    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shape_guard_timeout_exit_does_not_append_padding_after_initial_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let initial = b"GET /timeout-shape-guard HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let initial = initial.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut observed = vec![0u8; initial.len()];
            stream.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed, initial);

            let mut one = [0u8; 1];
            let read_res = timeout(Duration::from_millis(220), stream.read_exact(&mut one)).await;
            assert!(
                read_res.is_err() || read_res.unwrap().is_err(),
                "idle-timeout path must not append shape padding after initial probe"
            );
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;

    let peer: SocketAddr = "203.0.113.91:52002".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (_client_reader_side, client_reader) = duplex(2048);
    let (_client_visible_reader, client_visible_writer) = duplex(2048);

    handle_bad_client(
        client_reader,
        client_visible_writer,
        &initial,
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shape_guard_clean_eof_with_nonempty_initial_still_applies_bucket_padding() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let initial = b"GET /shape-bucket HTTP/1.1\r\n".to_vec();
    let extra = vec![0x41; 31];

    let accept_task = tokio::spawn({
        let initial = initial.clone();
        let extra = extra.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();

            let expected_prefix_len = initial.len() + extra.len();
            assert_eq!(&got[..initial.len()], initial.as_slice());
            assert_eq!(&got[initial.len()..expected_prefix_len], extra.as_slice());
            assert_eq!(
                got.len(),
                512,
                "clean EOF path should still shape to floor bucket"
            );
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;

    let peer: SocketAddr = "203.0.113.92:52003".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (mut client_writer, client_reader) = duplex(4096);
    let (_client_visible_reader, client_visible_writer) = duplex(4096);

    let relay_task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            &initial,
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.write_all(&extra).await.unwrap();
    client_writer.shutdown().await.unwrap();

    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
}
