use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_VERSION};
use crate::protocol::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

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

fn build_harness(config: ProxyConfig) -> PipelineHarness {
    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
                bindtodevice: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: None,
            ipv6: None,
            prefer: None,
        }],
        1,
        1,
        1,
        10,
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

    const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
    const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
    const TLS_EXTENSION_PADDING: u16 = 0x0015;
    const X25519_KEY_SHARE_LEN: usize = 32;
    let session_id_len: usize = 32;

    let mut extensions = Vec::new();
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&tls::TLS_NAMED_GROUP_X25519.to_be_bytes());
    key_share.extend_from_slice(&(X25519_KEY_SHARE_LEN as u16).to_be_bytes());
    key_share.push(9);
    key_share.resize(key_share.len() + X25519_KEY_SHARE_LEN - 1, 0);

    let mut key_share_extension = Vec::new();
    key_share_extension.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_extension.extend_from_slice(&key_share);
    extensions.extend_from_slice(&TLS_EXTENSION_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&(key_share_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share_extension);

    let base_tls_len = 4
        + 2
        + 32
        + 1
        + session_id_len
        + 2
        + TLS_AES_128_GCM_SHA256.len()
        + 1
        + 1
        + 2
        + extensions.len();
    assert!(
        tls_len == base_tls_len || tls_len >= base_tls_len + 4,
        "TLS length must leave room for a complete padding extension"
    );
    if tls_len > base_tls_len {
        let padding_len = tls_len - base_tls_len - 4;
        extensions.extend_from_slice(&TLS_EXTENSION_PADDING.to_be_bytes());
        extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
        extensions.resize(extensions.len() + padding_len, fill);
    }

    let body_len = tls_len - 4;
    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[fill; 32]);
    body.push(session_id_len as u8);
    body.extend_from_slice(&[fill; 32]);
    body.extend_from_slice(&(TLS_AES_128_GCM_SHA256.len() as u16).to_be_bytes());
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    assert_eq!(body.len(), body_len);

    let mut handshake = Vec::with_capacity(5 + tls_len);
    handshake.push(0x16);
    handshake.extend_from_slice(&[0x03, 0x01]);
    handshake.extend_from_slice(&(tls_len as u16).to_be_bytes());
    handshake.push(0x01);
    let body_len_bytes = (body_len as u32).to_be_bytes();
    handshake.extend_from_slice(&body_len_bytes[1..4]);
    handshake.extend_from_slice(&body);

    // The proxy authenticates TLS-fronted clients through the random field.
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

async fn read_and_discard_tls_record_body<T>(stream: &mut T, header: [u8; 5])
where
    T: tokio::io::AsyncRead + Unpin,
{
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
}

#[tokio::test]
async fn masking_runs_outside_handshake_timeout_budget_with_high_reject_delay() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 1;
    config.timeouts.client_handshake = 0;
    config.censorship.server_hello_delay_min_ms = 730;
    config.censorship.server_hello_delay_max_ms = 730;

    let harness = build_harness(config);
    let stats = harness.stats.clone();

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "198.51.100.241:56541".parse().unwrap();

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

    let mut invalid_hello = vec![0u8; 5 + 600];
    invalid_hello[0] = 0x16;
    invalid_hello[1] = 0x03;
    invalid_hello[2] = 0x01;
    invalid_hello[3..5].copy_from_slice(&600u16.to_be_bytes());
    invalid_hello[5..].fill(0x44);

    let started = Instant::now();
    client_side.write_all(&invalid_hello).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();

    assert!(
        result.is_ok(),
        "bad-client fallback must not be canceled by handshake timeout"
    );
    assert_eq!(
        stats.get_handshake_timeouts(),
        0,
        "masking fallback path must not increment handshake timeout counter"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "configured reject delay should still be visible before masking"
    );
}

#[tokio::test]
async fn tls_mtproto_bad_client_does_not_reinject_clienthello_into_mask_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_proxy_protocol = 0;
    config.access.ignore_time_skew = true;
    config.access.users.insert(
        "user".to_string(),
        "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0".to_string(),
    );

    let harness = build_harness(config);

    let secret = [0xD0u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 0, 600, 0x41);
    let invalid_mtproto_record = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
    let trailing_record = wrap_tls_application_data(b"no-clienthello-reinject");
    let expected_trailing = trailing_record.clone();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got = vec![0u8; expected_trailing.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got, expected_trailing,
            "mask backend must receive only post-handshake trailing TLS records"
        );
    });

    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.242:56542".parse().unwrap();

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

    let mut client_payload = invalid_mtproto_record;
    client_payload.extend_from_slice(&trailing_record);
    client_side.write_all(&client_payload).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client_side);
    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}
