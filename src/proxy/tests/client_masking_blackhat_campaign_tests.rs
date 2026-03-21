use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{
    HANDSHAKE_LEN,
    MAX_TLS_PLAINTEXT_SIZE,
    MIN_TLS_CLIENT_HELLO_SIZE,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
};
use crate::protocol::tls;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

struct CampaignHarness {
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

fn build_mask_harness(secret_hex: &str, mask_port: u16) -> CampaignHarness {
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

    CampaignHarness {
        config,
        stats: stats.clone(),
        upstream_manager: new_upstream_manager(stats),
        replay_checker: Arc::new(ReplayChecker::new(1024, Duration::from_secs(60))),
        buffer_pool: Arc::new(BufferPool::new()),
        rng: Arc::new(SecureRandom::new()),
        route_runtime: Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        ip_tracker: Arc::new(UserIpTracker::new()),
        beobachten: Arc::new(BeobachtenStore::new()),
    }
}

fn make_valid_tls_client_hello(secret: &[u8], timestamp: u32, tls_len: usize, fill: u8) -> Vec<u8> {
    assert!(tls_len <= u16::MAX as usize, "TLS length must fit into record header");

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

fn wrap_tls_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(record_type);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn wrap_tls_application_data(payload: &[u8]) -> Vec<u8> {
    wrap_tls_record(TLS_RECORD_APPLICATION, payload)
}

async fn read_and_discard_tls_record_body<T>(stream: &mut T, header: [u8; 5])
where
    T: tokio::io::AsyncRead + Unpin,
{
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
}

async fn run_tls_success_mtproto_fail_capture(
    harness: CampaignHarness,
    peer: SocketAddr,
    client_hello: Vec<u8>,
    bad_mtproto_record: Vec<u8>,
    trailing_records: Vec<Vec<u8>>,
    expected_forward: Vec<u8>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = (*harness.config).clone();
    cfg.censorship.mask_port = backend_addr.port();
    let cfg = Arc::new(cfg);

    let expected = expected_forward.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; expected.len()];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(262144);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        cfg,
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
    client_side.read_exact(&mut tls_response_head).await.unwrap();
    assert_eq!(tls_response_head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, tls_response_head).await;

    client_side.write_all(&bad_mtproto_record).await.unwrap();
    for record in trailing_records {
        client_side.write_all(&record).await.unwrap();
    }

    let got = tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, expected_forward);

    client_side.shutdown().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

async fn run_invalid_tls_capture(config: Arc<ProxyConfig>, payload: Vec<u8>, expected: Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = (*config).clone();
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    let cfg = Arc::new(cfg);

    let expected_probe = expected.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; expected_probe.len()];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let stats = Arc::new(Stats::new());
    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.77:45001".parse().unwrap(),
        cfg,
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

    client_side.write_all(&payload).await.unwrap();
    client_side.shutdown().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, expected);

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn blackhat_campaign_01_tail_only_record_is_forwarded_after_tls_success_mtproto_fail() {
    let secret = [0xA1u8; 16];
    let harness = build_mask_harness("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 1);
    let client_hello = make_valid_tls_client_hello(&secret, 11, 600, 0x41);
    let bad_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let tail = wrap_tls_application_data(b"blackhat-tail-01");

    run_tls_success_mtproto_fail_capture(
        harness,
        "198.51.100.1:55001".parse().unwrap(),
        client_hello,
        bad_record,
        vec![tail.clone()],
        tail,
    )
    .await;
}

#[tokio::test]
async fn blackhat_campaign_02_two_ordered_records_preserved_after_fallback() {
    let secret = [0xA2u8; 16];
    let harness = build_mask_harness("a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", 1);
    let client_hello = make_valid_tls_client_hello(&secret, 12, 600, 0x42);
    let bad_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let r1 = wrap_tls_application_data(b"first");
    let r2 = wrap_tls_application_data(b"second");
    let expected = [r1.clone(), r2.clone()].concat();

    run_tls_success_mtproto_fail_capture(
        harness,
        "198.51.100.2:55002".parse().unwrap(),
        client_hello,
        bad_record,
        vec![r1, r2],
        expected,
    )
    .await;
}

#[tokio::test]
async fn blackhat_campaign_03_large_tls_application_record_survives_fallback() {
    let secret = [0xA3u8; 16];
    let harness = build_mask_harness("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", 1);
    let client_hello = make_valid_tls_client_hello(&secret, 13, 600, 0x43);
    let bad_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let big_payload = vec![0x5Au8; MAX_TLS_PLAINTEXT_SIZE];
    let big_record = wrap_tls_application_data(&big_payload);

    run_tls_success_mtproto_fail_capture(
        harness,
        "198.51.100.3:55003".parse().unwrap(),
        client_hello,
        bad_record,
        vec![big_record.clone()],
        big_record,
    )
    .await;
}

#[tokio::test]
async fn blackhat_campaign_04_coalesced_tail_in_failed_record_is_reframed_and_forwarded() {
    let secret = [0xA4u8; 16];
    let harness = build_mask_harness("a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4", 1);
    let client_hello = make_valid_tls_client_hello(&secret, 14, 600, 0x44);

    let coalesced_tail = b"coalesced-tail-blackhat".to_vec();
    let mut bad_payload = vec![0u8; HANDSHAKE_LEN];
    bad_payload.extend_from_slice(&coalesced_tail);
    let bad_record = wrap_tls_application_data(&bad_payload);
    let expected = wrap_tls_application_data(&coalesced_tail);

    run_tls_success_mtproto_fail_capture(
        harness,
        "198.51.100.4:55004".parse().unwrap(),
        client_hello,
        bad_record,
        Vec::new(),
        expected,
    )
    .await;
}

#[tokio::test]
async fn blackhat_campaign_05_coalesced_tail_plus_next_record_keep_wire_order() {
    let secret = [0xA5u8; 16];
    let harness = build_mask_harness("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", 1);
    let client_hello = make_valid_tls_client_hello(&secret, 15, 600, 0x45);

    let coalesced_tail = b"inline-tail".to_vec();
    let mut bad_payload = vec![0u8; HANDSHAKE_LEN];
    bad_payload.extend_from_slice(&coalesced_tail);
    let bad_record = wrap_tls_application_data(&bad_payload);
    let next_record = wrap_tls_application_data(b"next-record");

    let expected = [
        wrap_tls_application_data(&coalesced_tail),
        next_record.clone(),
    ]
    .concat();

    run_tls_success_mtproto_fail_capture(
        harness,
        "198.51.100.5:55005".parse().unwrap(),
        client_hello,
        bad_record,
        vec![next_record],
        expected,
    )
    .await;
}

#[tokio::test]
async fn blackhat_campaign_06_replayed_tls_hello_is_masked_without_serverhello() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let harness = build_mask_harness("a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6", backend_addr.port());
    let replay_checker = harness.replay_checker.clone();
    let client_hello = make_valid_tls_client_hello(&[0xA6; 16], 16, 600, 0x46);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let first_tail = wrap_tls_application_data(b"seed-tail");

    let expected_hello = client_hello.clone();
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
        got_hello
    });

    let run_one = |checker: Arc<ReplayChecker>, send_mtproto: bool| {
        let mut cfg = (*harness.config).clone();
        cfg.censorship.mask_port = backend_addr.port();
        let cfg = Arc::new(cfg);
        let hello = client_hello.clone();
        let invalid_mtproto_record = invalid_mtproto_record.clone();
        let first_tail = first_tail.clone();
        let stats = harness.stats.clone();
        let upstream = harness.upstream_manager.clone();
        let pool = harness.buffer_pool.clone();
        let rng = harness.rng.clone();
        let route = harness.route_runtime.clone();
        let ipt = harness.ip_tracker.clone();
        let beob = harness.beobachten.clone();

        async move {
            let (server_side, mut client_side) = duplex(131072);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                "198.51.100.6:55006".parse().unwrap(),
                cfg,
                stats,
                upstream,
                checker,
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
                read_and_discard_tls_record_body(&mut client_side, head).await;
                client_side.write_all(&invalid_mtproto_record).await.unwrap();
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
            let result = tokio::time::timeout(Duration::from_secs(4), handler)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_ok());
        }
    };

    run_one(replay_checker.clone(), true).await;
    run_one(replay_checker, false).await;

    let got = tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, client_hello);
}

#[tokio::test]
async fn blackhat_campaign_07_truncated_clienthello_exact_prefix_is_forwarded() {
    let mut payload = vec![0u8; 5 + 37];
    payload[0] = 0x16;
    payload[1] = 0x03;
    payload[2] = 0x01;
    payload[3..5].copy_from_slice(&600u16.to_be_bytes());
    payload[5..].fill(0x71);

    run_invalid_tls_capture(Arc::new(ProxyConfig::default()), payload.clone(), payload).await;
}

#[tokio::test]
async fn blackhat_campaign_08_out_of_bounds_len_forwards_header_only() {
    let header = vec![0x16, 0x03, 0x01, 0xFF, 0xFF];
    run_invalid_tls_capture(Arc::new(ProxyConfig::default()), header.clone(), header).await;
}

#[tokio::test]
async fn blackhat_campaign_09_fragmented_header_then_partial_body_masks_seen_bytes_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_unix_sock = None;

    let expected = {
        let mut x = vec![0u8; 5 + 11];
        x[0] = 0x16;
        x[1] = 0x03;
        x[2] = 0x01;
        x[3..5].copy_from_slice(&600u16.to_be_bytes());
        x[5..].fill(0xCC);
        x
    };

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; expected.len()];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.9:55009".parse().unwrap(),
        Arc::new(cfg),
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

    client_side.write_all(&[0x16, 0x03]).await.unwrap();
    client_side.write_all(&[0x01, 0x02, 0x58]).await.unwrap();
    client_side.write_all(&vec![0xCC; 11]).await.unwrap();
    client_side.shutdown().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), 16);

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn blackhat_campaign_10_zero_handshake_timeout_with_delay_still_avoids_timeout_counter() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.timeouts.client_handshake = 0;
    cfg.censorship.server_hello_delay_min_ms = 700;
    cfg.censorship.server_hello_delay_max_ms = 700;

    let stats = Arc::new(Stats::new());
    let (server_side, mut client_side) = duplex(4096);
    let started = Instant::now();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.10:55010".parse().unwrap(),
        Arc::new(cfg),
        stats.clone(),
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

    let mut invalid = vec![0u8; 5 + 700];
    invalid[0] = 0x16;
    invalid[1] = 0x03;
    invalid[2] = 0x01;
    invalid[3..5].copy_from_slice(&700u16.to_be_bytes());
    invalid[5..].fill(0x66);

    client_side.write_all(&invalid).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(stats.get_handshake_timeouts(), 0);
    assert!(started.elapsed() >= Duration::from_millis(650));
}

#[tokio::test]
async fn blackhat_campaign_11_parallel_bad_tls_probes_all_masked_without_timeouts() {
    let n = 24usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_port = backend_addr.port();

    let stats = Arc::new(Stats::new());
    let accept_task = tokio::spawn(async move {
        let mut seen = HashSet::new();
        for _ in 0..n {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 5];
            stream.read_exact(&mut hdr).await.unwrap();
            seen.insert(hdr.to_vec());
        }
        seen
    });

    let mut tasks = Vec::new();
    for i in 0..n {
        let mut hdr = [0u8; 5];
        hdr[0] = 0x16;
        hdr[1] = 0x03;
        hdr[2] = 0x01;
        hdr[3] = 0xFF;
        hdr[4] = i as u8;

        let cfg = Arc::new(cfg.clone());
        let stats = stats.clone();
        tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(4096);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                format!("198.51.100.11:{}", 56000 + i).parse().unwrap(),
                cfg,
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
            client_side.write_all(&hdr).await.unwrap();
            client_side.shutdown().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(4), handler)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_ok());
            hdr.to_vec()
        }));
    }

    let mut expected = HashSet::new();
    for t in tasks {
        expected.insert(t.await.unwrap());
    }

    let seen = tokio::time::timeout(Duration::from_secs(6), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen, expected);
    assert_eq!(stats.get_handshake_timeouts(), 0);
}

#[tokio::test]
async fn blackhat_campaign_12_parallel_tls_success_mtproto_fail_sessions_keep_isolation() {
    let sessions = 16usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected = HashSet::new();
    for i in 0..sessions {
        let rec = wrap_tls_application_data(&vec![i as u8; 8 + i]);
        expected.insert(rec);
    }

    let accept_task = tokio::spawn(async move {
        let mut got_set = HashSet::new();
        for _ in 0..sessions {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).await.unwrap();
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            let mut rec = vec![0u8; 5 + len];
            rec[..5].copy_from_slice(&head);
            stream.read_exact(&mut rec[5..]).await.unwrap();
            got_set.insert(rec);
        }
        got_set
    });

    let mut tasks = Vec::new();
    for i in 0..sessions {
        let mut harness = build_mask_harness("abababababababababababababababab", backend_addr.port());
        let mut cfg = (*harness.config).clone();
        cfg.censorship.mask_port = backend_addr.port();
        harness.config = Arc::new(cfg);
        tasks.push(tokio::spawn(async move {
            let secret = [0xABu8; 16];
            let hello = make_valid_tls_client_hello(&secret, 100 + i as u32, 600, 0x40 + (i as u8 % 10));
            let bad = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
            let tail = wrap_tls_application_data(&vec![i as u8; 8 + i]);
            let (server_side, mut client_side) = duplex(131072);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                format!("198.51.100.12:{}", 56100 + i).parse().unwrap(),
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
            read_and_discard_tls_record_body(&mut client_side, head).await;
            client_side.write_all(&bad).await.unwrap();
            client_side.write_all(&tail).await.unwrap();
            client_side.shutdown().await.unwrap();

            let result = tokio::time::timeout(Duration::from_secs(5), handler)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_ok());
            tail
        }));
    }

    let mut produced = HashSet::new();
    for t in tasks {
        produced.insert(t.await.unwrap());
    }

    let observed = tokio::time::timeout(Duration::from_secs(8), accept_task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(produced, expected);
    assert_eq!(observed, expected);
}

#[tokio::test]
async fn blackhat_campaign_13_backend_down_does_not_escalate_to_handshake_timeout() {
    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.timeouts.client_handshake = 1;

    let stats = Arc::new(Stats::new());
    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.13:55013".parse().unwrap(),
        Arc::new(cfg),
        stats.clone(),
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

    let bad = vec![0x16, 0x03, 0x01, 0xFF, 0x00];
    client_side.write_all(&bad).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(stats.get_handshake_timeouts(), 0);
}

#[tokio::test]
async fn blackhat_campaign_14_masking_disabled_path_finishes_cleanly() {
    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = false;
    cfg.timeouts.client_handshake = 1;

    let stats = Arc::new(Stats::new());
    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.14:55014".parse().unwrap(),
        Arc::new(cfg),
        stats.clone(),
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

    let bad = vec![0x16, 0x03, 0x01, 0xFF, 0xF0];
    client_side.write_all(&bad).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(stats.get_handshake_timeouts(), 0);
}

#[tokio::test]
async fn blackhat_campaign_15_light_fuzz_tls_lengths_and_fragmentation() {
    let mut seed = 0x9E3779B97F4A7C15u64;

    for idx in 0..20u16 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut tls_len = (seed as usize) % 20000;
        if idx % 3 == 0 {
            tls_len = MAX_TLS_PLAINTEXT_SIZE + 1 + (tls_len % 1024);
        }

        let body_to_send = if (MIN_TLS_CLIENT_HELLO_SIZE..=MAX_TLS_PLAINTEXT_SIZE).contains(&tls_len)
        {
            (seed as usize % 29).min(tls_len.saturating_sub(1))
        } else {
            0
        };

        let mut probe = vec![0u8; 5 + body_to_send];
        probe[0] = 0x16;
        probe[1] = 0x03;
        probe[2] = 0x01;
        probe[3..5].copy_from_slice(&(tls_len as u16).to_be_bytes());
        for b in &mut probe[5..] {
            seed = seed.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
            *b = (seed >> 24) as u8;
        }

        let expected = probe.clone();
        run_invalid_tls_capture(Arc::new(ProxyConfig::default()), probe, expected).await;
    }
}

#[tokio::test]
async fn blackhat_campaign_16_mixed_probe_burst_stress_finishes_without_panics() {
    let cases = 18usize;
    let mut tasks = Vec::new();

    for i in 0..cases {
        tasks.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let mut probe = vec![0u8; 5 + (i % 13)];
                probe[0] = 0x16;
                probe[1] = 0x03;
                probe[2] = 0x01;
                probe[3..5].copy_from_slice(&600u16.to_be_bytes());
                probe[5..].fill((0x90 + i as u8) ^ 0x5A);
                run_invalid_tls_capture(Arc::new(ProxyConfig::default()), probe.clone(), probe).await;
            } else {
                let hdr = vec![0x16, 0x03, 0x01, 0xFF, i as u8];
                run_invalid_tls_capture(Arc::new(ProxyConfig::default()), hdr.clone(), hdr).await;
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}
