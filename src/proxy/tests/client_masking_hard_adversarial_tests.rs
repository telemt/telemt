use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_RECORD_APPLICATION, TLS_VERSION};
use crate::protocol::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

struct Harness {
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

fn new_upstream_manager(stats: Arc<Stats>) -> Arc<UpstreamManager> {
    Arc::new(UpstreamManager::new(
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
        stats,
    ))
}

fn build_harness(secret_hex: &str, mask_port: u16) -> Harness {
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

    Harness {
        config,
        stats: stats.clone(),
        upstream_manager: new_upstream_manager(stats),
        replay_checker: Arc::new(ReplayChecker::new(512, Duration::from_secs(60))),
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
    record.push(TLS_RECORD_APPLICATION);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn read_tls_record_body<T>(stream: &mut T, header: [u8; 5])
where
    T: tokio::io::AsyncRead + Unpin,
{
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
}

async fn run_tls_success_mtproto_fail_capture(
    secret_hex: &str,
    secret: [u8; 16],
    timestamp: u32,
    trailing_records: Vec<Vec<u8>>,
) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let expected_len = trailing_records.iter().map(Vec::len).sum::<usize>();
    let expected_concat = trailing_records.concat();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; expected_len];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let harness = build_harness(secret_hex, backend_addr.port());
    let client_hello = make_valid_tls_client_hello(&secret, timestamp, 600, 0x42);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let (server_side, mut client_side) = duplex(262144);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.210:56010".parse().unwrap(),
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
    read_tls_record_body(&mut client_side, tls_response_head).await;

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    for record in trailing_records {
        client_side.write_all(&record).await.unwrap();
    }

    let got = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, expected_concat);

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    got
}

#[tokio::test]
async fn masking_budget_survives_zero_handshake_timeout_with_delay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.timeouts.client_handshake = 0;
    cfg.censorship.server_hello_delay_min_ms = 720;
    cfg.censorship.server_hello_delay_max_ms = 720;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; 605];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.211:56011".parse().unwrap(),
        config,
        stats.clone(),
        new_upstream_manager(stats.clone()),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let mut invalid_hello = vec![0u8; 605];
    invalid_hello[0] = 0x16;
    invalid_hello[1] = 0x03;
    invalid_hello[2] = 0x01;
    invalid_hello[3..5].copy_from_slice(&600u16.to_be_bytes());
    invalid_hello[5..].fill(0xA1);

    let started = Instant::now();
    client_side.write_all(&invalid_hello).await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    client_side.shutdown().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    assert!(result.is_ok());
    assert_eq!(stats.get_handshake_timeouts(), 0);
    assert!(started.elapsed() >= Duration::from_millis(680));
}

#[tokio::test]
async fn tls_mtproto_fail_forwards_only_trailing_record() {
    let tail = wrap_tls_application_data(b"tail-only");
    let got = run_tls_success_mtproto_fail_capture(
        "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
        [0xC1; 16],
        1,
        vec![tail.clone()],
    )
    .await;
    assert_eq!(got, tail);
}

#[tokio::test]
async fn replayed_tls_hello_gets_no_serverhello_and_is_masked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let harness = build_harness("c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2", backend_addr.port());
    let secret = [0xC2u8; 16];
    let hello = make_valid_tls_client_hello(&secret, 2, 600, 0x41);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let first_tail = wrap_tls_application_data(b"seed");

    let expected_hello = hello.clone();
    let expected_tail = first_tail.clone();

    let accept_task = tokio::spawn(async move {
        let (mut s1, _) = listener.accept().await.unwrap();
        let mut got_tail = vec![0u8; expected_tail.len()];
        s1.read_exact(&mut got_tail).await.unwrap();
        assert_eq!(got_tail, expected_tail);
        drop(s1);

        let (mut s2, _) = listener.accept().await.unwrap();
        let mut got_hello = vec![0u8; expected_hello.len()];
        s2.read_exact(&mut got_hello).await.unwrap();
        assert_eq!(got_hello, expected_hello);
    });

    let run_session = |send_mtproto: bool| {
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
        let hello = hello.clone();
        let invalid_mtproto_record = invalid_mtproto_record.clone();
        let first_tail = first_tail.clone();

        async move {
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                "198.51.100.212:56012".parse().unwrap(),
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
                read_tls_record_body(&mut client_side, head).await;
                client_side
                    .write_all(&invalid_mtproto_record)
                    .await
                    .unwrap();
                client_side.write_all(&first_tail).await.unwrap();
            } else {
                let mut one = [0u8; 1];
                let no_server_hello = tokio::time::timeout(
                    Duration::from_millis(300),
                    client_side.read_exact(&mut one),
                )
                .await;
                assert!(no_server_hello.is_err() || no_server_hello.unwrap().is_err());
            }

            client_side.shutdown().await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap();
        }
    };

    run_session(true).await;
    run_session(false).await;

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn connects_bad_increments_once_per_invalid_mtproto() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let harness = build_harness("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", backend_addr.port());
    let stats = harness.stats.clone();
    let bad_before = stats.get_connects_bad();

    let tail = wrap_tls_application_data(b"accounting");
    let expected_tail = tail.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; expected_tail.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected_tail);
    });

    let hello = make_valid_tls_client_hello(&[0xC3; 16], 3, 600, 0x42);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);

    let (server_side, mut client_side) = duplex(131072);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.213:56013".parse().unwrap(),
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
    read_tls_record_body(&mut client_side, head).await;
    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side.write_all(&tail).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    client_side.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(stats.get_connects_bad(), bad_before + 1);
}

#[tokio::test]
async fn truncated_clienthello_forwards_only_seen_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_unix_sock = None;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let expected_prefix_len = 5 + 17;
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; expected_prefix_len];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.214:56014".parse().unwrap(),
        config,
        stats,
        new_upstream_manager(Arc::new(Stats::new())),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let mut hello = vec![0u8; 5 + 17];
    hello[0] = 0x16;
    hello[1] = 0x03;
    hello[2] = 0x01;
    hello[3..5].copy_from_slice(&600u16.to_be_bytes());
    hello[5..].fill(0x55);

    client_side.write_all(&hello).await.unwrap();
    client_side.shutdown().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, hello);

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn out_of_bounds_tls_len_forwards_header_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_unix_sock = None;

    let config = Arc::new(cfg);

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(8192);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.215:56015".parse().unwrap(),
        config,
        Arc::new(Stats::new()),
        new_upstream_manager(Arc::new(Stats::new())),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let hdr = [0x16, 0x03, 0x01, 0x42, 0x69];
    client_side.write_all(&hdr).await.unwrap();
    client_side.shutdown().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, hdr);

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn non_tls_with_modes_disabled_is_masked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_unix_sock = None;
    cfg.general.modes.classic = false;
    cfg.general.modes.secure = false;

    let config = Arc::new(cfg);
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(8192);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.216:56016".parse().unwrap(),
        config,
        Arc::new(Stats::new()),
        new_upstream_manager(Arc::new(Stats::new())),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let probe = *b"HELLO";
    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, probe);

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn concurrent_tls_mtproto_fail_sessions_are_isolated() {
    let sessions = 12usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected = std::collections::HashSet::new();
    for idx in 0..sessions {
        let payload = vec![idx as u8; 32 + idx];
        expected.insert(wrap_tls_application_data(&payload));
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
            assert!(remaining.remove(&record));
        }
        assert!(remaining.is_empty());
    });

    let mut tasks = Vec::with_capacity(sessions);
    for idx in 0..sessions {
        let secret_hex = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        let harness = build_harness(secret_hex, backend_addr.port());
        let hello =
            make_valid_tls_client_hello(&[0xC4; 16], 20 + idx as u32, 600, 0x40 + idx as u8);
        let invalid_mtproto = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
        let trailing = wrap_tls_application_data(&vec![idx as u8; 32 + idx]);
        let peer: SocketAddr = format!("198.51.100.217:{}", 56100 + idx as u16)
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
            read_tls_record_body(&mut client_side, head).await;
            client_side.write_all(&invalid_mtproto).await.unwrap();
            client_side.write_all(&trailing).await.unwrap();
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

macro_rules! tail_length_case {
    ($name:ident, $hex:expr, $secret:expr, $ts:expr, $len:expr) => {
        #[tokio::test]
        async fn $name() {
            let mut payload = vec![0u8; $len];
            for (i, b) in payload.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17).wrapping_add(5);
            }
            let record = wrap_tls_application_data(&payload);
            let got =
                run_tls_success_mtproto_fail_capture($hex, $secret, $ts, vec![record.clone()])
                    .await;
            assert_eq!(got, record);
        }
    };
}

tail_length_case!(
    tail_len_1_preserved,
    "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1",
    [0xD1; 16],
    30,
    1
);
tail_length_case!(
    tail_len_2_preserved,
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
    [0xD2; 16],
    31,
    2
);
tail_length_case!(
    tail_len_3_preserved,
    "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3",
    [0xD3; 16],
    32,
    3
);
tail_length_case!(
    tail_len_7_preserved,
    "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
    [0xD4; 16],
    33,
    7
);
tail_length_case!(
    tail_len_31_preserved,
    "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
    [0xD5; 16],
    34,
    31
);
tail_length_case!(
    tail_len_127_preserved,
    "d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6",
    [0xD6; 16],
    35,
    127
);
tail_length_case!(
    tail_len_511_preserved,
    "d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7",
    [0xD7; 16],
    36,
    511
);
tail_length_case!(
    tail_len_1023_preserved,
    "d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8",
    [0xD8; 16],
    37,
    1023
);
