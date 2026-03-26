//! TLS ClientHello size validation tests for proxy anti-censorship security
//! Covers positive, negative, edge, adversarial, and fuzz cases.
//! Ensures proxy does not reveal itself on probe failures.

use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::protocol::constants::{MAX_TLS_PLAINTEXT_SIZE, MIN_TLS_CLIENT_HELLO_SIZE};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;

fn test_probe_for_len(len: usize) -> [u8; 5] {
    [
        0x16,
        0x03,
        0x03,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
    ]
}

fn make_test_upstream_manager(stats: Arc<Stats>) -> Arc<UpstreamManager> {
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

async fn run_probe_and_assert_masking(len: usize, expect_bad_increment: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = test_probe_for_len(len);
    let backend_reply = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe, "mask backend must receive original probe bytes");
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let bad_before = stats.get_connects_bad();
    let upstream_manager = make_test_upstream_manager(stats.clone());
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "203.0.113.123:55123".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats.clone(),
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        None,
        route_runtime,
        None,
        ip_tracker,
        beobachten,
        false,
    ));

    client_side.write_all(&probe).await.unwrap();
    let mut observed = vec![0u8; backend_reply.len()];
    client_side.read_exact(&mut observed).await.unwrap();
    assert_eq!(
        observed, backend_reply,
        "invalid TLS path must be masked as a real site"
    );

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    accept_task.await.unwrap();

    let expected_bad = if expect_bad_increment {
        bad_before + 1
    } else {
        bad_before
    };
    assert_eq!(
        stats.get_connects_bad(),
        expected_bad,
        "unexpected connects_bad classification for tls_len={len}"
    );
}

#[tokio::test]
async fn tls_client_hello_lower_bound_minus_one_is_masked_and_counted_bad() {
    run_probe_and_assert_masking(MIN_TLS_CLIENT_HELLO_SIZE - 1, true).await;
}

#[tokio::test]
async fn tls_client_hello_upper_bound_plus_one_is_masked_and_counted_bad() {
    run_probe_and_assert_masking(MAX_TLS_PLAINTEXT_SIZE + 1, true).await;
}

#[tokio::test]
async fn tls_client_hello_header_zero_len_is_masked_and_counted_bad() {
    run_probe_and_assert_masking(0, true).await;
}

#[test]
fn tls_client_hello_len_bounds_unit_adversarial_sweep() {
    let cases = [
        (0usize, false),
        (1usize, false),
        (99usize, false),
        (100usize, true),
        (101usize, true),
        (511usize, true),
        (512usize, true),
        (MAX_TLS_PLAINTEXT_SIZE - 1, true),
        (MAX_TLS_PLAINTEXT_SIZE, true),
        (MAX_TLS_PLAINTEXT_SIZE + 1, false),
        (u16::MAX as usize, false),
        (usize::MAX, false),
    ];

    for (len, expected) in cases {
        assert_eq!(
            tls_clienthello_len_in_bounds(len),
            expected,
            "unexpected bounds result for tls_len={len}"
        );
    }
}

#[test]
fn tls_client_hello_len_bounds_light_fuzz_deterministic_lcg() {
    let mut x: u32 = 0xA5A5_5A5A;
    for _ in 0..2_048 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let base = (x as usize) & 0x3fff;
        let len = match x & 0x7 {
            0 => MIN_TLS_CLIENT_HELLO_SIZE - 1,
            1 => MIN_TLS_CLIENT_HELLO_SIZE,
            2 => MIN_TLS_CLIENT_HELLO_SIZE + 1,
            3 => MAX_TLS_PLAINTEXT_SIZE - 1,
            4 => MAX_TLS_PLAINTEXT_SIZE,
            5 => MAX_TLS_PLAINTEXT_SIZE + 1,
            _ => base,
        };
        let expect_bad = !(MIN_TLS_CLIENT_HELLO_SIZE..=MAX_TLS_PLAINTEXT_SIZE).contains(&len);
        assert_eq!(
            tls_clienthello_len_in_bounds(len),
            !expect_bad,
            "deterministic fuzz mismatch for tls_len={len}"
        );
    }
}

#[test]
fn tls_client_hello_len_bounds_stress_many_evaluations() {
    for _ in 0..100_000 {
        assert!(tls_clienthello_len_in_bounds(MIN_TLS_CLIENT_HELLO_SIZE));
        assert!(tls_clienthello_len_in_bounds(MAX_TLS_PLAINTEXT_SIZE));
        assert!(!tls_clienthello_len_in_bounds(
            MIN_TLS_CLIENT_HELLO_SIZE - 1
        ));
        assert!(!tls_clienthello_len_in_bounds(MAX_TLS_PLAINTEXT_SIZE + 1));
    }
}

#[tokio::test]
async fn tls_client_hello_masking_integration_repeated_small_probes() {
    for _ in 0..25 {
        run_probe_and_assert_masking(MIN_TLS_CLIENT_HELLO_SIZE - 1, true).await;
    }
}
