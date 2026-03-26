use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_VERSION};
use crate::protocol::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

struct RedTeamHarness {
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

fn build_harness(secret_hex: &str, mask_port: u16) -> RedTeamHarness {
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

    RedTeamHarness {
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

async fn run_tls_success_mtproto_fail_session(
    secret_hex: &str,
    secret: [u8; 16],
    timestamp: u32,
    tail: Vec<u8>,
) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let harness = build_harness(secret_hex, backend_addr.port());
    let client_hello = make_valid_tls_client_hello(&secret, timestamp, 600, 0x42);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(&tail);

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; trailing_record.len()];
        stream.read_exact(&mut got).await.unwrap();
        got
    });

    let (server_side, mut client_side) = duplex(262144);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.250:56900".parse().unwrap(),
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
    let body_len = u16::from_be_bytes([head[3], head[4]]) as usize;
    let mut body = vec![0u8; body_len];
    client_side.read_exact(&mut body).await.unwrap();

    client_side
        .write_all(&invalid_mtproto_record)
        .await
        .unwrap();
    client_side
        .write_all(&wrap_tls_application_data(&tail))
        .await
        .unwrap();

    let forwarded = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    forwarded
}

#[tokio::test]
#[ignore = "red-team expected-fail: demonstrates that post-TLS fallback still forwards data to backend"]
async fn redteam_01_backend_receives_no_data_after_mtproto_fail() {
    let forwarded = run_tls_success_mtproto_fail_session(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        [0xAA; 16],
        1,
        b"probe-a".to_vec(),
    )
    .await;
    assert!(
        forwarded.is_empty(),
        "backend unexpectedly received fallback bytes"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict no-fallback policy hypothesis"]
async fn redteam_02_backend_must_never_receive_tls_records_after_mtproto_fail() {
    let forwarded = run_tls_success_mtproto_fail_session(
        "abababababababababababababababab",
        [0xAB; 16],
        2,
        b"probe-b".to_vec(),
    )
    .await;
    assert_ne!(
        forwarded[0], 0x17,
        "received TLS application record despite strict policy"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: impossible timing uniformity target"]
async fn redteam_03_masking_duration_must_be_less_than_1ms_when_backend_down() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "acacacacacacacacacacacacacacacac".to_string(),
    );

    let harness = RedTeamHarness {
        config: Arc::new(cfg),
        stats: Arc::new(Stats::new()),
        upstream_manager: Arc::new(UpstreamManager::new(
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
            Arc::new(Stats::new()),
        )),
        replay_checker: Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        buffer_pool: Arc::new(BufferPool::new()),
        rng: Arc::new(SecureRandom::new()),
        route_runtime: Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        ip_tracker: Arc::new(UserIpTracker::new()),
        beobachten: Arc::new(BeobachtenStore::new()),
    };

    let hello = make_valid_tls_client_hello(&[0xAC; 16], 3, 600, 0x42);
    let (server_side, mut client_side) = duplex(131072);

    let started = Instant::now();
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.251:56901".parse().unwrap(),
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
    client_side.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    assert!(
        started.elapsed() < Duration::from_millis(1),
        "fallback path took longer than 1ms"
    );
}

macro_rules! redteam_tail_must_not_forward_case {
    ($name:ident, $hex:expr, $secret:expr, $ts:expr, $len:expr) => {
        #[tokio::test]
        #[ignore = "red-team expected-fail: strict no-forwarding hypothesis"]
        async fn $name() {
            let mut tail = vec![0u8; $len];
            for (i, b) in tail.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(7);
            }
            let forwarded = run_tls_success_mtproto_fail_session($hex, $secret, $ts, tail).await;
            assert!(
                forwarded.is_empty(),
                "strict model expects zero forwarded bytes, got {}",
                forwarded.len()
            );
        }
    };
}

redteam_tail_must_not_forward_case!(
    redteam_04_tail_len_1_not_forwarded,
    "adadadadadadadadadadadadadadadad",
    [0xAD; 16],
    4,
    1
);
redteam_tail_must_not_forward_case!(
    redteam_05_tail_len_2_not_forwarded,
    "aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae",
    [0xAE; 16],
    5,
    2
);
redteam_tail_must_not_forward_case!(
    redteam_06_tail_len_3_not_forwarded,
    "afafafafafafafafafafafafafafafaf",
    [0xAF; 16],
    6,
    3
);
redteam_tail_must_not_forward_case!(
    redteam_07_tail_len_7_not_forwarded,
    "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
    [0xB0; 16],
    7,
    7
);
redteam_tail_must_not_forward_case!(
    redteam_08_tail_len_15_not_forwarded,
    "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    [0xB1; 16],
    8,
    15
);
redteam_tail_must_not_forward_case!(
    redteam_09_tail_len_63_not_forwarded,
    "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    [0xB2; 16],
    9,
    63
);
redteam_tail_must_not_forward_case!(
    redteam_10_tail_len_127_not_forwarded,
    "b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
    [0xB3; 16],
    10,
    127
);
redteam_tail_must_not_forward_case!(
    redteam_11_tail_len_255_not_forwarded,
    "b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4",
    [0xB4; 16],
    11,
    255
);
redteam_tail_must_not_forward_case!(
    redteam_12_tail_len_511_not_forwarded,
    "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
    [0xB5; 16],
    12,
    511
);
redteam_tail_must_not_forward_case!(
    redteam_13_tail_len_1023_not_forwarded,
    "b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6",
    [0xB6; 16],
    13,
    1023
);
redteam_tail_must_not_forward_case!(
    redteam_14_tail_len_2047_not_forwarded,
    "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7",
    [0xB7; 16],
    14,
    2047
);
redteam_tail_must_not_forward_case!(
    redteam_15_tail_len_4095_not_forwarded,
    "b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
    [0xB8; 16],
    15,
    4095
);

#[tokio::test]
#[ignore = "red-team expected-fail: impossible indistinguishability envelope"]
async fn redteam_16_timing_delta_between_paths_must_be_sub_1ms_under_concurrency() {
    let runs = 20usize;
    let mut durations = Vec::with_capacity(runs);

    for i in 0..runs {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        let secret = [0xB9u8; 16];
        let harness = build_harness("b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9", backend_addr.port());
        let hello = make_valid_tls_client_hello(&secret, 100 + i as u32, 600, 0x42);

        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
        });

        let (server_side, mut client_side) = duplex(65536);
        let handler = tokio::spawn(handle_client_stream(
            server_side,
            "198.51.100.252:56902".parse().unwrap(),
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

        let started = Instant::now();
        client_side.write_all(&hello).await.unwrap();
        client_side.shutdown().await.unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(3), handler)
            .await
            .unwrap()
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), accept_task)
            .await
            .unwrap()
            .unwrap();

        durations.push(started.elapsed());
    }

    let min = durations.iter().copied().min().unwrap();
    let max = durations.iter().copied().max().unwrap();
    assert!(
        max - min <= Duration::from_millis(1),
        "timing spread too wide for strict anti-probing envelope"
    );
}

async fn measure_invalid_probe_duration_ms(delay_ms: u64, tls_len: u16, body_sent: usize) -> u128 {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.server_hello_delay_min_ms = delay_ms;
    cfg.censorship.server_hello_delay_max_ms = delay_ms;

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.253:56903".parse().unwrap(),
        Arc::new(cfg),
        Arc::new(Stats::new()),
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
            Arc::new(Stats::new()),
        )),
        Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&tls_len.to_be_bytes());
    probe[5..].fill(0xD7);

    let started = Instant::now();
    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();

    started.elapsed().as_millis()
}

async fn capture_forwarded_probe_len(tls_len: u16, body_sent: usize) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.timeouts.client_handshake = 1;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got.len()
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.254:56904".parse().unwrap(),
        Arc::new(cfg),
        Arc::new(Stats::new()),
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
            Arc::new(Stats::new()),
        )),
        Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&tls_len.to_be_bytes());
    probe[5..].fill(0xBC);

    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

macro_rules! redteam_timing_envelope_case {
    ($name:ident, $delay_ms:expr, $tls_len:expr, $body_sent:expr, $max_ms:expr) => {
        #[tokio::test]
        #[ignore = "red-team expected-fail: unrealistically tight reject timing envelope"]
        async fn $name() {
            let elapsed_ms =
                measure_invalid_probe_duration_ms($delay_ms, $tls_len, $body_sent).await;
            assert!(
                elapsed_ms <= $max_ms,
                "timing envelope violated: elapsed={}ms, max={}ms",
                elapsed_ms,
                $max_ms
            );
        }
    };
}

macro_rules! redteam_constant_shape_case {
    ($name:ident, $tls_len:expr, $body_sent:expr, $expected_len:expr) => {
        #[tokio::test]
        #[ignore = "red-team expected-fail: strict constant-shape backend fingerprint hypothesis"]
        async fn $name() {
            let got = capture_forwarded_probe_len($tls_len, $body_sent).await;
            assert_eq!(
                got, $expected_len,
                "fingerprint shape mismatch: got={} expected={} (strict constant-shape model)",
                got, $expected_len
            );
        }
    };
}

redteam_timing_envelope_case!(redteam_17_timing_env_very_tight_00, 700, 600, 0, 3);
redteam_timing_envelope_case!(redteam_18_timing_env_very_tight_01, 700, 600, 1, 3);
redteam_timing_envelope_case!(redteam_19_timing_env_very_tight_02, 700, 600, 7, 3);
redteam_timing_envelope_case!(redteam_20_timing_env_very_tight_03, 700, 600, 17, 3);
redteam_timing_envelope_case!(redteam_21_timing_env_very_tight_04, 700, 600, 31, 3);
redteam_timing_envelope_case!(redteam_22_timing_env_very_tight_05, 700, 600, 63, 3);
redteam_timing_envelope_case!(redteam_23_timing_env_very_tight_06, 700, 600, 127, 3);
redteam_timing_envelope_case!(redteam_24_timing_env_very_tight_07, 700, 600, 255, 3);
redteam_timing_envelope_case!(redteam_25_timing_env_very_tight_08, 700, 600, 511, 3);
redteam_timing_envelope_case!(redteam_26_timing_env_very_tight_09, 700, 600, 1023, 3);
redteam_timing_envelope_case!(redteam_27_timing_env_very_tight_10, 700, 600, 2047, 3);
redteam_timing_envelope_case!(redteam_28_timing_env_very_tight_11, 700, 600, 4095, 3);

redteam_constant_shape_case!(redteam_29_constant_shape_00, 600, 0, 517);
redteam_constant_shape_case!(redteam_30_constant_shape_01, 600, 1, 517);
redteam_constant_shape_case!(redteam_31_constant_shape_02, 600, 7, 517);
redteam_constant_shape_case!(redteam_32_constant_shape_03, 600, 17, 517);
redteam_constant_shape_case!(redteam_33_constant_shape_04, 600, 31, 517);
redteam_constant_shape_case!(redteam_34_constant_shape_05, 600, 63, 517);
redteam_constant_shape_case!(redteam_35_constant_shape_06, 600, 127, 517);
redteam_constant_shape_case!(redteam_36_constant_shape_07, 600, 255, 517);
redteam_constant_shape_case!(redteam_37_constant_shape_08, 600, 511, 517);
redteam_constant_shape_case!(redteam_38_constant_shape_09, 600, 1023, 517);
redteam_constant_shape_case!(redteam_39_constant_shape_10, 600, 2047, 517);
redteam_constant_shape_case!(redteam_40_constant_shape_11, 600, 4095, 517);
