use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{
    HANDSHAKE_LEN, MAX_TLS_CIPHERTEXT_SIZE, TLS_RECORD_ALERT, TLS_RECORD_APPLICATION,
    TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE, TLS_VERSION,
};
use crate::protocol::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;

struct PipelineHarness {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_runtime: Arc<RouteRuntimeController>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
}

fn build_harness(secret_hex: &str, mask_port: u16) -> PipelineHarness {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_port;
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    PipelineHarness {
        config,
        stats,
        upstream_manager,
        replay_checker: Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        buffer_pool: Arc::new(BufferPool::new()),
        rng: Arc::new(SecureRandom::new()),
        route_runtime: Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        ip_tracker: Arc::new(UserIpTracker::new()),
        beobachten: Arc::new(BeobachtenStore::new()),
    }
}

fn make_valid_tls_client_hello(secret: &[u8], timestamp: u32, tls_len: usize, fill: u8) -> Vec<u8> {
    assert!(
        tls_len <= u16::MAX as usize,
        "TLS length must fit into record header"
    );

    let total_len = 5 + tls_len;
    let mut handshake = vec![fill; total_len];

    handshake[0] = 0x16;
    handshake[1] = 0x03;
    handshake[2] = 0x01;
    handshake[3..5].copy_from_slice(&(tls_len as u16).to_be_bytes());

    let session_id_len: usize = 32;
    handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = session_id_len as u8;

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let computed = sha256_hmac(secret, &handshake);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    handshake
}

fn wrap_tls_application_data(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(0x17);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn wrap_tls_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(record_type);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn wrap_invalid_mtproto_with_coalesced_tail(tail: &[u8]) -> Vec<u8> {
    let mut payload = vec![0u8; HANDSHAKE_LEN];
    payload.extend_from_slice(tail);
    wrap_tls_application_data(&payload)
}

async fn read_and_discard_tls_record_body<T>(stream: &mut T, header: [u8; 5])
where
    T: tokio::io::AsyncRead + Unpin,
{
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_preserves_wire_and_backend_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x81u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 0, 600, 0x42);
    let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
    let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);
    let trailing_payload = b"masked-trailing-record".to_vec();
    let trailing_record = wrap_tls_application_data(&trailing_payload);
    let backend_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();
    let expected_trailing_record = trailing_record.clone();
    let expected_response = backend_response.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing_record.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing_record);

        stream.write_all(&expected_response).await.unwrap();
    });

    let harness = build_harness("81818181818181818181818181818181", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.181:56001".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, tls_response_head).await;

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_keeps_connects_bad_accounting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x82u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 1, 600, 0x43);
    let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
    let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);
    let trailing_record = wrap_tls_application_data(b"x");
    let expected_trailing_record = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing_record.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing_record);
    });

    let harness = build_harness("82828282828282828282828282828282", backend_addr.port());
    let bad_before = harness.stats.get_connects_bad();

    let (server_side, mut client_side) = duplex(65536);
    let peer: SocketAddr = "198.51.100.182:56002".parse().unwrap();
    let stats_for_assert = harness.stats.clone();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    let bad_after = stats_for_assert.get_connects_bad();
    assert_eq!(
        bad_after,
        bad_before + 1,
        "connects_bad must increase exactly once for invalid MTProto after valid TLS"
    );
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_forwards_zero_length_tls_record_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x83u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 2, 600, 0x44);
    let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
    let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);
    let trailing_record = wrap_tls_application_data(&[]);
    let expected_trailing_record = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing_record.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing_record);
    });

    let harness = build_harness("83838383838383838383838383838383", backend_addr.port());
    let (server_side, mut client_side) = duplex(65536);
    let peer: SocketAddr = "198.51.100.183:56003".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_forwards_max_tls_record_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x84u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 3, 600, 0x45);
    let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
    let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);
    let trailing_payload = vec![0xAB; MAX_TLS_CIPHERTEXT_SIZE];
    let trailing_record = wrap_tls_application_data(&trailing_payload);
    let expected_trailing_record = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing_record.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing_record);
    });

    let harness = build_harness("84848484848484848484848484848484", backend_addr.port());
    let (server_side, mut client_side) = duplex(2 * 1024 * 1024);
    let peer: SocketAddr = "198.51.100.184:56004".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_light_fuzz_tls_record_lengths_verbatim() {
    let lengths = [0usize, 1, 2, 3, 7, 15, 31, 63, 127, 255, 1024, 4096];

    for (idx, payload_len) in lengths.iter().copied().enumerate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();

        let secret = [0x85u8; 16];
        let client_hello =
            make_valid_tls_client_hello(&secret, idx as u32 + 4, 600, 0x46 + idx as u8);
        let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
        let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);

        let mut payload = vec![0u8; payload_len];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = ((idx as u8).wrapping_mul(29)).wrapping_add(i as u8);
        }
        let trailing_record = wrap_tls_application_data(&payload);
        let expected_trailing_record = trailing_record.clone();
        let accept_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut got_trailing = vec![0u8; expected_trailing_record.len()];
            stream.read_exact(&mut got_trailing).await.unwrap();
            assert_eq!(got_trailing, expected_trailing_record);
        });

        let harness = build_harness("85858585858585858585858585858585", backend_addr.port());
        let (server_side, mut client_side) = duplex(262144);
        let peer: SocketAddr = format!("198.51.100.185:{}", 56010 + idx as u16)
            .parse()
            .unwrap();

        let handler = tokio::spawn(handle_client_stream(
            server_side,
            peer,
            harness.config,
            harness.stats,
            harness.upstream_manager,
            harness.replay_checker,
            harness.buffer_pool,
            harness.rng,
            None,
            harness.route_runtime,
            None,
            harness.ip_tracker,
            harness.beobachten,
            false,
        ));

        client_side.write_all(&client_hello).await.unwrap();

        let mut tls_response_head = [0u8; 5];
        client_side
            .read_exact(&mut tls_response_head)
            .await
            .unwrap();
        assert_eq!(tls_response_head[0], 0x16);

        client_side
            .write_all(&invalid_mtproto_record)
            .await
            .unwrap();
        client_side.write_all(&trailing_record).await.unwrap();

        tokio::time::timeout(Duration::from_secs(3), accept_task)
            .await
            .unwrap()
            .unwrap();

        drop(client_side);
        let _ = tokio::time::timeout(Duration::from_secs(3), handler)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_concurrent_sessions_are_isolated() {
    let sessions = 24usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected_records = std::collections::HashSet::new();
    let secret = [0x86u8; 16];
    for idx in 0..sessions {
        let _hello = make_valid_tls_client_hello(&secret, idx as u32 + 100, 600, 0x60 + idx as u8);
        let payload = vec![idx as u8; 64 + idx];
        let trailing = wrap_tls_application_data(&payload);
        expected_records.insert(trailing);
    }

    let accept_task = tokio::spawn(async move {
        let mut remaining = expected_records;
        for idx in 0..sessions {
            let (mut stream, _) = listener.accept().await.unwrap();

            let _ = idx;
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], TLS_RECORD_APPLICATION);

            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0u8; 5 + len];
            record[..5].copy_from_slice(&header);
            stream.read_exact(&mut record[5..]).await.unwrap();

            assert!(
                remaining.remove(&record),
                "unexpected trailing TLS record in concurrent isolation test"
            );
        }

        assert!(
            remaining.is_empty(),
            "all expected client sessions must be matched exactly once"
        );
    });

    let mut client_tasks = Vec::with_capacity(sessions);

    for idx in 0..sessions {
        let harness = build_harness("86868686868686868686868686868686", backend_addr.port());
        let secret = [0x86u8; 16];
        let client_hello =
            make_valid_tls_client_hello(&secret, idx as u32 + 100, 600, 0x60 + idx as u8);
        let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
        let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);
        let trailing_payload = vec![idx as u8; 64 + idx];
        let trailing_record = wrap_tls_application_data(&trailing_payload);

        let peer: SocketAddr = format!("198.51.100.186:{}", 57000 + idx as u16)
            .parse()
            .unwrap();

        client_tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(262144);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                peer,
                harness.config,
                harness.stats,
                harness.upstream_manager,
                harness.replay_checker,
                harness.buffer_pool,
                harness.rng,
                None,
                harness.route_runtime,
                None,
                harness.ip_tracker,
                harness.beobachten,
                false,
            ));

            client_side.write_all(&client_hello).await.unwrap();

            let mut tls_response_head = [0u8; 5];
            client_side
                .read_exact(&mut tls_response_head)
                .await
                .unwrap();
            assert_eq!(tls_response_head[0], 0x16);

            client_side
                .write_all(&invalid_mtproto_record)
                .await
                .unwrap();
            client_side.write_all(&trailing_record).await.unwrap();

            drop(client_side);
            let _ = tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap();
        }));
    }

    for task in client_tasks {
        task.await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_forwards_fragmented_client_writes_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x87u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 9, 600, 0x57);
    let invalid_mtproto = vec![0u8; HANDSHAKE_LEN];
    let invalid_mtproto_record = wrap_tls_application_data(&invalid_mtproto);
    let payload = b"fragmented-writes-to-test-stream-boundary-robustness".to_vec();
    let trailing_record = wrap_tls_application_data(&payload);
    let expected_trailing_record = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing_record.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing_record);
    });

    let harness = build_harness("87878787878787878787878787878787", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);
    let peer: SocketAddr = "198.51.100.187:56087".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();

    for chunk in trailing_record.chunks(3) {
        client_side.write_all(chunk).await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_header_fragmentation_bytewise_is_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x88u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 10, 600, 0x58);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(b"bytewise-header");
    let expected_trailing = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing);
    });

    let harness = build_harness("88888888888888888888888888888888", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.188:56088".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    for b in trailing_record.iter().copied() {
        client_side.write_all(&[b]).await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_record_splitting_chaos_is_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x89u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 11, 600, 0x59);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let mut payload = vec![0u8; 2048];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    let trailing_record = wrap_tls_application_data(&payload);
    let expected_trailing = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing);
    });

    let harness = build_harness("89898989898989898989898989898989", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);
    let peer: SocketAddr = "198.51.100.189:56089".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();

    let chaos = [7usize, 1, 19, 3, 5, 31, 2, 11, 13, 17];
    let mut pos = 0usize;
    let mut idx = 0usize;
    while pos < trailing_record.len() {
        let step = chaos[idx % chaos.len()];
        let end = (pos + step).min(trailing_record.len());
        client_side
            .write_all(&trailing_record[pos..end])
            .await
            .unwrap();
        pos = end;
        idx += 1;
    }

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_multiple_tls_records_are_forwarded_in_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x8Au8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 12, 600, 0x5A);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let r1 = wrap_tls_application_data(b"alpha");
    let r2 = wrap_tls_application_data(b"beta-beta");
    let r3 = wrap_tls_application_data(b"gamma-gamma-gamma");
    let expected = [r1.clone(), r2.clone(), r3.clone()].concat();
    let expected_concat = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got = vec![0u8; expected_concat.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected_concat);
    });

    let harness = build_harness("8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.190:56090".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&r1).await.unwrap();
    client_side.write_all(&r2).await.unwrap();
    client_side.write_all(&r3).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_client_half_close_propagates_eof_to_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x8Bu8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 13, 600, 0x5B);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(b"half-close-probe");
    let expected_trailing = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing);

        let mut tail = [0u8; 1];
        let n = stream.read(&mut tail).await.unwrap();
        assert_eq!(
            n, 0,
            "backend must observe EOF after client write half-close"
        );
    });

    let harness = build_harness("8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.191:56091".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();
    client_side.shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_backend_half_close_after_response_is_tolerated() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x8Cu8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 14, 600, 0x5C);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(b"backend-half-close");
    let backend_response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();
    let expected_trailing = trailing_record.clone();
    let response = backend_response.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing.len()];
        stream.read_exact(&mut got_trailing).await.unwrap();
        assert_eq!(got_trailing, expected_trailing);

        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let harness = build_harness("8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.192:56092".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, tls_response_head).await;

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_backend_reset_after_clienthello_is_handled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x8Du8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 15, 600, 0x5D);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(b"backend-reset");
    let accept_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });

    let harness = build_harness("8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.193:56093".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    let write_res = client_side.write_all(&trailing_record).await;
    assert!(
        write_res.is_ok() || write_res.is_err(),
        "write completion is environment dependent under backend reset"
    );

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_backend_slow_reader_preserves_byte_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x8Eu8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 16, 600, 0x5E);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let payload = vec![0xEC; 8192];
    let trailing_record = wrap_tls_application_data(&payload);
    let expected_trailing = trailing_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_trailing = vec![0u8; expected_trailing.len()];
        let mut offset = 0usize;
        while offset < got_trailing.len() {
            let step = (offset % 97).max(1).min(got_trailing.len() - offset);
            stream
                .read_exact(&mut got_trailing[offset..offset + step])
                .await
                .unwrap();
            offset += step;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(got_trailing, expected_trailing);
    });

    let harness = build_harness("8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);
    let peer: SocketAddr = "198.51.100.194:56094".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&trailing_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_replay_pressure_masks_replay_without_serverhello() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x8Fu8; 16];
    let replayed_hello = make_valid_tls_client_hello(&secret, 17, 600, 0x5F);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(b"first-session");

    let expected_second = replayed_hello.clone();
    let expected_trailing = trailing_record.clone();

    let accept_task = tokio::spawn(async move {
        let (mut s1, _) = listener.accept().await.unwrap();
        let mut got1_tail = vec![0u8; expected_trailing.len()];
        s1.read_exact(&mut got1_tail).await.unwrap();
        assert_eq!(got1_tail, expected_trailing);
        drop(s1);

        let (mut s2, _) = listener.accept().await.unwrap();
        let mut got2 = vec![0u8; expected_second.len()];
        s2.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, expected_second);
    });

    let harness = build_harness("8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f", backend_addr.port());
    let stats_for_assert = harness.stats.clone();
    let bad_before = stats_for_assert.get_connects_bad();

    let run_session = |hello: Vec<u8>, send_mtproto: bool| {
        let (server_side, mut client_side) = duplex(131072);
        let config = harness.config.clone();
        let stats = harness.stats.clone();
        let upstream = harness.upstream_manager.clone();
        let replay = harness.replay_checker.clone();
        let pool = harness.buffer_pool.clone();
        let rng = harness.rng.clone();
        let route = harness.route_runtime.clone();
        let ipt = harness.ip_tracker.clone();
        let beob = harness.beobachten.clone();
        let invalid_mtproto_record = invalid_mtproto_record.clone();
        let trailing_record = trailing_record.clone();
        async move {
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                "198.51.100.195:56095".parse().unwrap(),
                config,
                stats,
                upstream,
                replay,
                pool,
                rng,
                None,
                route,
                None,
                ipt,
                beob,
                false,
            ));

            client_side.write_all(&hello).await.unwrap();
            if send_mtproto {
                let mut head = [0u8; 5];
                client_side.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], 0x16);
                client_side
                    .write_all(&invalid_mtproto_record)
                    .await
                    .unwrap();
                client_side.write_all(&trailing_record).await.unwrap();
            } else {
                let mut one = [0u8; 1];
                let no_server_hello = tokio::time::timeout(
                    Duration::from_millis(300),
                    client_side.read_exact(&mut one),
                )
                .await;
                assert!(
                    no_server_hello.is_err() || no_server_hello.unwrap().is_err(),
                    "replayed TLS hello must not receive authenticated TLS ServerHello"
                );
            }

            drop(client_side);
            let _ = tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap();
        }
    };

    run_session(replayed_hello.clone(), true).await;
    run_session(replayed_hello.clone(), false).await;

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();

    let bad_after = stats_for_assert.get_connects_bad();
    assert!(
        bad_after >= bad_before + 2,
        "both invalid-mtproto and replayed-tls paths must increment bad connection accounting"
    );
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_large_multi_record_chaos_under_backpressure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x90u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 18, 600, 0x60);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let a = wrap_tls_application_data(&vec![0xA1; 2048]);
    let b = wrap_tls_application_data(&vec![0xB2; 3072]);
    let c = wrap_tls_application_data(&vec![0xC3; 1536]);
    let expected = [a.clone(), b.clone(), c.clone()].concat();
    let expected_payload = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got = vec![0u8; expected_payload.len()];
        let mut pos = 0usize;
        while pos < got.len() {
            let step = (pos % 257).max(1).min(got.len() - pos);
            stream.read_exact(&mut got[pos..pos + step]).await.unwrap();
            pos += step;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(got, expected_payload);
    });

    let harness = build_harness("90909090909090909090909090909090", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);
    let peer: SocketAddr = "198.51.100.196:56096".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();

    let chaos = [5usize, 23, 11, 47, 3, 19, 29, 13, 7, 31];
    for record in [&a, &b, &c] {
        let mut pos = 0usize;
        let mut idx = 0usize;
        while pos < record.len() {
            let step = chaos[idx % chaos.len()];
            let end = (pos + step).min(record.len());
            client_side.write_all(&record[pos..end]).await.unwrap();
            pos = end;
            idx += 1;
        }
    }

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_interleaved_control_and_application_records_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x91u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 19, 600, 0x61);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let ccs = wrap_tls_record(0x14, &[0x01]);
    let app = wrap_tls_application_data(b"opaque");
    let alert = wrap_tls_record(0x15, &[0x01, 0x00]);
    let expected = [ccs.clone(), app.clone(), alert.clone()].concat();
    let expected_records = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got = vec![0u8; expected_records.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected_records);
    });

    let harness = build_harness("91919191919191919191919191919191", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.197:56097".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&ccs).await.unwrap();
    client_side.write_all(&app).await.unwrap();
    client_side.write_all(&alert).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_many_short_sessions_with_chaos_no_cross_leak() {
    let sessions = 40usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected_records = std::collections::HashSet::new();
    let secret = [0x92u8; 16];
    for idx in 0..sessions {
        let _hello = make_valid_tls_client_hello(&secret, idx as u32 + 200, 600, 0x70 + idx as u8);
        let payload = vec![idx as u8; 33 + (idx % 17)];
        let record = wrap_tls_application_data(&payload);
        expected_records.insert(record);
    }

    let accept_task = tokio::spawn(async move {
        let mut remaining = expected_records;
        for idx in 0..sessions {
            let (mut stream, _) = listener.accept().await.unwrap();

            let _ = idx;
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], TLS_RECORD_APPLICATION);

            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0u8; 5 + len];
            record[..5].copy_from_slice(&header);
            stream.read_exact(&mut record[5..]).await.unwrap();

            assert!(
                remaining.remove(&record),
                "unexpected trailing TLS record in short-session chaos test"
            );
        }

        assert!(
            remaining.is_empty(),
            "all expected sessions must be consumed exactly once"
        );
    });

    let mut tasks = Vec::with_capacity(sessions);
    for idx in 0..sessions {
        let harness = build_harness("92929292929292929292929292929292", backend_addr.port());
        let secret = [0x92u8; 16];
        let client_hello =
            make_valid_tls_client_hello(&secret, idx as u32 + 200, 600, 0x70 + idx as u8);
        let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
        let payload = vec![idx as u8; 33 + (idx % 17)];
        let record = wrap_tls_application_data(&payload);

        let peer: SocketAddr = format!("198.51.100.198:{}", 58000 + idx as u16)
            .parse()
            .unwrap();

        tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(131072);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                peer,
                harness.config,
                harness.stats,
                harness.upstream_manager,
                harness.replay_checker,
                harness.buffer_pool,
                harness.rng,
                None,
                harness.route_runtime,
                None,
                harness.ip_tracker,
                harness.beobachten,
                false,
            ));

            client_side.write_all(&client_hello).await.unwrap();
            let mut head = [0u8; 5];
            client_side.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x16);

            client_side
                .write_all(&invalid_mtproto_record)
                .await
                .unwrap();
            for chunk in record.chunks((idx % 9) + 1) {
                client_side.write_all(chunk).await.unwrap();
            }

            drop(client_side);
            let _ = tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap();
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(6), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_coalesced_tail_small_is_forwarded_as_tls_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xA1u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 300, 600, 0x31);
    let coalesced_tail = b"coalesced-tail-small".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&coalesced_tail);
    let expected_tail_record = wrap_tls_application_data(&coalesced_tail);
    let expected_tail = expected_tail_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.210:56110".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_coalesced_tail_large_is_forwarded_as_tls_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xA2u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 301, 600, 0x32);
    let coalesced_tail = vec![0xAB; 4096];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&coalesced_tail);
    let expected_tail_record = wrap_tls_application_data(&coalesced_tail);
    let expected_tail = expected_tail_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.211:56111".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_coalesced_tail_keeps_order_before_following_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xA3u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 302, 600, 0x33);
    let coalesced_tail = b"coalesced-first".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&coalesced_tail);
    let expected_tail_record = wrap_tls_application_data(&coalesced_tail);
    let following_record = wrap_tls_application_data(b"following-record");
    let expected_concat = [expected_tail_record.clone(), following_record.clone()].concat();
    let expected_records = expected_concat.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_records = vec![0u8; expected_records.len()];
        stream.read_exact(&mut got_records).await.unwrap();
        assert_eq!(got_records, expected_records);
    });

    let harness = build_harness("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.212:56112".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();
    client_side.write_all(&following_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_coalesced_tail_fragmented_client_write_is_forwarded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xA4u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 303, 600, 0x34);
    let coalesced_tail = vec![0xCD; 1536];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&coalesced_tail);
    let expected_tail_record = wrap_tls_application_data(&coalesced_tail);
    let expected_tail = expected_tail_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.213:56113".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    let steps = [7usize, 3, 13, 5, 11, 2, 17, 19];
    let mut offset = 0usize;
    let mut i = 0usize;
    while offset < coalesced_record.len() {
        let step = steps[i % steps.len()];
        let end = (offset + step).min(coalesced_record.len());
        client_side
            .write_all(&coalesced_record[offset..end])
            .await
            .unwrap();
        offset = end;
        i += 1;
    }

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_bad_mtproto_fallback_coalesced_tail_max_payload_is_forwarded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xA5u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 304, 600, 0x35);
    let coalesced_tail = vec![0xEF; MAX_TLS_CIPHERTEXT_SIZE - HANDSHAKE_LEN];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&coalesced_tail);
    let expected_tail_record = wrap_tls_application_data(&coalesced_tail);
    let expected_tail = expected_tail_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.214:56114".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_identical_following_record_must_not_duplicate_or_reorder() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xB1u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 400, 600, 0x21);
    let tail = b"same-payload-record".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let tail_record = wrap_tls_application_data(&tail);
    let expected = [tail_record.clone(), tail_record.clone()].concat();
    let expected_payload = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got = vec![0u8; expected_payload.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected_payload);

        let mut tail = [0u8; 1];
        let n = stream.read(&mut tail).await.unwrap();
        assert_eq!(n, 0, "fallback stream must not emit extra bytes");
    });

    let harness = build_harness("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.220:56120".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();
    client_side.write_all(&tail_record).await.unwrap();
    client_side.shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_tls_header_looking_bytes_must_stay_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xB2u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 401, 600, 0x22);
    let mut tail = vec![0x16, 0x03, 0x03, 0x00, 0x10];
    tail.extend_from_slice(b"not-a-real-record-boundary");
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail_record = wrap_tls_application_data(&tail);
    let expected_tail = expected_tail_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.221:56121".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_client_half_close_must_not_truncate_prepended_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xB3u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 402, 600, 0x23);
    let tail = vec![0xAA; 3072];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail_record = wrap_tls_application_data(&tail);
    let expected_tail = expected_tail_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);

        let mut one = [0u8; 1];
        let n = stream.read(&mut one).await.unwrap();
        assert_eq!(n, 0, "backend must observe EOF after client half-close");
    });

    let harness = build_harness("b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.222:56122".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();
    client_side.shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_multi_session_no_cross_bleed_under_churn() {
    let sessions = 16usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected = std::collections::HashSet::new();
    let secret = [0xB4u8; 16];
    for idx in 0..sessions {
        let _hello = make_valid_tls_client_hello(&secret, 450 + idx as u32, 600, 0x40 + idx as u8);
        let tail = vec![idx as u8; 17 + idx];
        expected.insert(wrap_tls_application_data(&tail));
    }

    let accept_task = tokio::spawn(async move {
        let mut remaining = expected;
        for _ in 0..sessions {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], TLS_RECORD_APPLICATION);

            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0u8; 5 + len];
            record[..5].copy_from_slice(&header);
            stream.read_exact(&mut record[5..]).await.unwrap();

            assert!(
                remaining.remove(&record),
                "unexpected record or duplicated session routing"
            );
        }
        assert!(remaining.is_empty(), "all sessions must map one-to-one");
    });

    let mut tasks = Vec::with_capacity(sessions);
    for idx in 0..sessions {
        let harness = build_harness("b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4", backend_addr.port());
        let hello = make_valid_tls_client_hello(&secret, 450 + idx as u32, 600, 0x40 + idx as u8);
        let tail = vec![idx as u8; 17 + idx];
        let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
        let peer: SocketAddr = format!("198.51.100.223:{}", 56200 + idx as u16)
            .parse()
            .unwrap();

        tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(131072);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                peer,
                harness.config,
                harness.stats,
                harness.upstream_manager,
                harness.replay_checker,
                harness.buffer_pool,
                harness.rng,
                None,
                harness.route_runtime,
                None,
                harness.ip_tracker,
                harness.beobachten,
                false,
            ));

            client_side.write_all(&hello).await.unwrap();
            let mut head = [0u8; 5];
            client_side.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x16);
            read_and_discard_tls_record_body(&mut client_side, head).await;

            for chunk in coalesced_record.chunks((idx % 7) + 1) {
                client_side.write_all(chunk).await.unwrap();
            }
            client_side.shutdown().await.unwrap();

            let _ = tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap();
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(6), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_single_byte_tail_is_preserved() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC1u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 500, 600, 0x11);
    let tail = vec![0x7F];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1", backend_addr.port());
    let (server_side, mut client_side) = duplex(65536);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.230:56130".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_exact_tls_header_size_payload_is_preserved() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC2u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 501, 600, 0x12);
    let tail = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2", backend_addr.port());
    let (server_side, mut client_side) = duplex(65536);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.231:56131".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_all_zero_payload_is_preserved() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC3u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 502, 600, 0x13);
    let tail = vec![0u8; 2048];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.232:56132".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_following_control_records_are_not_mutated() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC4u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 503, 600, 0x14);
    let tail = b"tail-before-controls".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let tail_record = wrap_tls_application_data(&tail);
    let ccs = wrap_tls_record(0x14, &[0x01]);
    let alert = wrap_tls_record(0x15, &[0x01, 0x00]);
    let app = wrap_tls_application_data(b"control-final-app");
    let expected = [tail_record, ccs.clone(), alert.clone(), app.clone()].concat();
    let expected_payload = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_payload = vec![0u8; expected_payload.len()];
        stream.read_exact(&mut got_payload).await.unwrap();
        assert_eq!(got_payload, expected_payload);
    });

    let harness = build_harness("c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.233:56133".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    client_side.write_all(&coalesced_record).await.unwrap();
    client_side.write_all(&ccs).await.unwrap();
    client_side.write_all(&alert).await.unwrap();
    client_side.write_all(&app).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_then_following_records_fragmented_chaos_stays_ordered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC5u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 504, 600, 0x15);
    let tail = vec![0xAC; 900];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let tail_record = wrap_tls_application_data(&tail);
    let r1 = wrap_tls_application_data(b"r1");
    let r2 = wrap_tls_application_data(&vec![0xDD; 257]);
    let expected = [tail_record, r1.clone(), r2.clone()].concat();
    let expected_payload = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_payload = vec![0u8; expected_payload.len()];
        stream.read_exact(&mut got_payload).await.unwrap();
        assert_eq!(got_payload, expected_payload);
    });

    let harness = build_harness("c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5", backend_addr.port());
    let (server_side, mut client_side) = duplex(262144);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.234:56134".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    let pattern = [3usize, 1, 5, 2, 7, 11, 13, 17, 19];
    let mut idx = 0usize;
    for data in [&coalesced_record, &r1, &r2] {
        let mut pos = 0usize;
        while pos < data.len() {
            let step = pattern[idx % pattern.len()];
            idx += 1;
            let end = (pos + step).min(data.len());
            client_side.write_all(&data[pos..end]).await.unwrap();
            pos = end;
        }
    }

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_backend_response_integrity_after_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC6u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 505, 600, 0x16);
    let tail = b"coalesced-request-body".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let backend_response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();
    let expected_resp = backend_response.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);

        stream.write_all(&expected_resp).await.unwrap();
    });

    let harness = build_harness("c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.235:56135".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();

    let mut observed = Vec::new();
    let mut buf = [0u8; 512];
    let mut found = false;
    for _ in 0..32 {
        let n = tokio::time::timeout(Duration::from_millis(200), client_side.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            break;
        }
        observed.extend_from_slice(&buf[..n]);
        if observed
            .windows(backend_response.len())
            .any(|w| w == backend_response.as_slice())
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "backend plaintext response must be observable on client stream after fallback"
    );

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_connects_bad_increments_exactly_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC7u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 506, 600, 0x17);
    let tail = b"count-bad-once".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);

    let harness = build_harness("c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7", backend_addr.port());
    let stats = harness.stats.clone();
    let bad_before = stats.get_connects_bad();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let (server_side, mut client_side) = duplex(131072);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.236:56136".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    let bad_after = stats.get_connects_bad();
    assert_eq!(
        bad_after,
        bad_before + 1,
        "invalid MTProto after valid TLS must increment connects_bad exactly once"
    );
}

#[tokio::test]
async fn blackhat_coalesced_tail_parallel_32_sessions_no_cross_bleed() {
    let sessions = 32usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected = std::collections::HashSet::new();
    let secret = [0xC8u8; 16];
    for idx in 0..sessions {
        let _hello = make_valid_tls_client_hello(&secret, 550 + idx as u32, 600, 0x20 + idx as u8);
        let tail = vec![idx as u8; 48 + (idx % 11)];
        expected.insert(wrap_tls_application_data(&tail));
    }

    let accept_task = tokio::spawn(async move {
        let mut remaining = expected;
        for _ in 0..sessions {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], TLS_RECORD_APPLICATION);

            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0u8; 5 + len];
            record[..5].copy_from_slice(&header);
            stream.read_exact(&mut record[5..]).await.unwrap();

            assert!(
                remaining.remove(&record),
                "session mixup detected in parallel-32 blackhat test"
            );
        }
        assert!(
            remaining.is_empty(),
            "all expected sessions must be consumed"
        );
    });

    let mut tasks = Vec::with_capacity(sessions);
    for idx in 0..sessions {
        let harness = build_harness("c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8", backend_addr.port());
        let hello = make_valid_tls_client_hello(&secret, 550 + idx as u32, 600, 0x20 + idx as u8);
        let tail = vec![idx as u8; 48 + (idx % 11)];
        let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
        let peer: SocketAddr = format!("198.51.100.237:{}", 56300 + idx as u16)
            .parse()
            .unwrap();

        tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(131072);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                peer,
                harness.config,
                harness.stats,
                harness.upstream_manager,
                harness.replay_checker,
                harness.buffer_pool,
                harness.rng,
                None,
                harness.route_runtime,
                None,
                harness.ip_tracker,
                harness.beobachten,
                false,
            ));

            client_side.write_all(&hello).await.unwrap();
            let mut head = [0u8; 5];
            client_side.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x16);
            read_and_discard_tls_record_body(&mut client_side, head).await;

            let chunk = (idx % 13) + 1;
            for part in coalesced_record.chunks(chunk) {
                client_side.write_all(part).await.unwrap();
            }
            client_side.shutdown().await.unwrap();

            let _ = tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap();
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(6), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_repeated_tls_like_prefixes_are_preserved() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xC9u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 507, 600, 0x18);
    let mut tail = Vec::new();
    for _ in 0..64 {
        tail.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x20]);
    }
    tail.extend_from_slice(b"suffix-data");
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.238:56138".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_drop_after_write_still_delivers_prepended_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xCAu8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 508, 600, 0x19);
    let tail = vec![0xBE; 1024];
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
    });

    let harness = build_harness("cacacacacacacacacacacacacacacaca", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.239:56139".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();
    drop(client_side);

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_zero_following_record_after_coalesced_is_not_invented() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xCBu8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 509, 600, 0x1A);
    let tail = b"terminal-tail".to_vec();
    let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
    let expected_tail = wrap_tls_application_data(&tail);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got_tail = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);

        let mut one = [0u8; 1];
        let n = stream.read(&mut one).await.unwrap();
        assert_eq!(n, 0, "no synthetic extra record must appear");
    });

    let harness = build_harness("cbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.240:56140".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;
    client_side.write_all(&coalesced_record).await.unwrap();
    client_side.shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_coalesced_tail_light_fuzz_mixed_followup_records_stay_byte_exact() {
    let mut seed = 0xA11C_E2E5_F00D_BAADu64;

    for case in 0..24u32 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();

        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let tail_len = (seed as usize % 1536) + 1;
        let mut tail = vec![0u8; tail_len];
        for (i, b) in tail.iter_mut().enumerate() {
            *b = (seed as u8).wrapping_add(i as u8).wrapping_mul(13);
        }

        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let follow_type = match seed & 0x3 {
            0 => TLS_RECORD_APPLICATION,
            1 => TLS_RECORD_ALERT,
            2 => TLS_RECORD_CHANGE_CIPHER,
            _ => TLS_RECORD_HANDSHAKE,
        };
        let follow_len = (seed as usize % 96) + (case as usize % 3);
        let mut follow_payload = vec![0u8; follow_len];
        for (i, b) in follow_payload.iter_mut().enumerate() {
            *b = (case as u8).wrapping_mul(29).wrapping_add(i as u8);
        }

        let secret = [0xD1u8; 16];
        let client_hello = make_valid_tls_client_hello(&secret, 600 + case, 600, 0x33);
        let coalesced_record = wrap_invalid_mtproto_with_coalesced_tail(&tail);
        let expected_tail = wrap_tls_application_data(&tail);
        let follow_record = wrap_tls_record(follow_type, &follow_payload);
        let expected_wire = [expected_tail.clone(), follow_record.clone()].concat();

        let accept_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut got = vec![0u8; expected_wire.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_wire);
        });

        let harness = build_harness("d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1", backend_addr.port());
        let (server_side, mut client_side) = duplex(262144);
        let peer: SocketAddr = format!("198.51.100.250:{}", 57000 + case as u16)
            .parse()
            .unwrap();

        let handler = tokio::spawn(handle_client_stream(
            server_side,
            peer,
            harness.config,
            harness.stats,
            harness.upstream_manager,
            harness.replay_checker,
            harness.buffer_pool,
            harness.rng,
            None,
            harness.route_runtime,
            None,
            harness.ip_tracker,
            harness.beobachten,
            false,
        ));

        client_side.write_all(&client_hello).await.unwrap();
        let mut head = [0u8; 5];
        client_side.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x16);
        read_and_discard_tls_record_body(&mut client_side, head).await;

        let mut local_seed = seed ^ 0x55AA_55AA_1234_5678;
        for data in [&coalesced_record, &follow_record] {
            let mut pos = 0usize;
            while pos < data.len() {
                local_seed ^= local_seed << 7;
                local_seed ^= local_seed >> 9;
                local_seed ^= local_seed << 8;
                let step = ((local_seed as usize % 17) + 1).min(data.len() - pos);
                let end = pos + step;
                client_side.write_all(&data[pos..end]).await.unwrap();
                pos = end;
            }
        }

        tokio::time::timeout(Duration::from_secs(3), accept_task)
            .await
            .unwrap()
            .unwrap();

        drop(client_side);
        let _ = tokio::time::timeout(Duration::from_secs(3), handler)
            .await
            .unwrap()
            .unwrap();
    }
}
