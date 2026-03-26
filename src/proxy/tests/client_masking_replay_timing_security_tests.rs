use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_VERSION};
use crate::protocol::tls;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant};

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

fn make_valid_tls_client_hello(secret: &[u8], timestamp: u32, tls_len: usize, fill: u8) -> Vec<u8> {
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

async fn run_replay_candidate_session(
    replay_checker: Arc<ReplayChecker>,
    hello: &[u8],
    peer: SocketAddr,
    drive_mtproto_fail: bool,
) -> Duration {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.censorship.mask_timing_normalization_enabled = false;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "abababababababababababababababab".to_string(),
    );

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(65536);
    let started = Instant::now();

    let task = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats.clone(),
        new_upstream_manager(stats),
        replay_checker,
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        beobachten,
        false,
    ));

    client_side.write_all(hello).await.unwrap();

    if drive_mtproto_fail {
        let mut server_hello_head = [0u8; 5];
        client_side
            .read_exact(&mut server_hello_head)
            .await
            .unwrap();
        assert_eq!(server_hello_head[0], 0x16);
        let body_len = u16::from_be_bytes([server_hello_head[3], server_hello_head[4]]) as usize;
        let mut body = vec![0u8; body_len];
        client_side.read_exact(&mut body).await.unwrap();

        let mut invalid_mtproto_record = Vec::with_capacity(5 + HANDSHAKE_LEN);
        invalid_mtproto_record.push(0x17);
        invalid_mtproto_record.extend_from_slice(&TLS_VERSION);
        invalid_mtproto_record.extend_from_slice(&(HANDSHAKE_LEN as u16).to_be_bytes());
        invalid_mtproto_record.extend_from_slice(&vec![0u8; HANDSHAKE_LEN]);
        client_side
            .write_all(&invalid_mtproto_record)
            .await
            .unwrap();
        client_side
            .write_all(b"GET /replay-fallback HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
    }

    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap();

    started.elapsed()
}

#[tokio::test]
async fn replay_reject_still_honors_masking_timing_budget() {
    let replay_checker = Arc::new(ReplayChecker::new(256, Duration::from_secs(60)));
    let hello = make_valid_tls_client_hello(&[0xAB; 16], 7, 600, 0x51);

    let seed_elapsed = run_replay_candidate_session(
        Arc::clone(&replay_checker),
        &hello,
        "198.51.100.201:58001".parse().unwrap(),
        true,
    )
    .await;

    assert!(
        seed_elapsed >= Duration::from_millis(40) && seed_elapsed < Duration::from_millis(250),
        "seed replay-candidate run must honor masking timing budget without unbounded delay"
    );

    let replay_elapsed = run_replay_candidate_session(
        Arc::clone(&replay_checker),
        &hello,
        "198.51.100.202:58002".parse().unwrap(),
        false,
    )
    .await;

    assert!(
        replay_elapsed >= Duration::from_millis(40) && replay_elapsed < Duration::from_millis(250),
        "replay rejection path must still satisfy masking timing budget without unbounded DB/CPU delay"
    );
}
