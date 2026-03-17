use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::tls;
use crate::transport::proxy_protocol::ProxyProtocolV1Builder;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn short_tls_probe_is_masked_through_client_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = vec![0x16, 0x03, 0x01, 0x00, 0x10];
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; probe.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "203.0.113.77:55001".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
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
    assert_eq!(observed, backend_reply);

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn handle_client_stream_increments_connects_all_exactly_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = vec![0x16, 0x03, 0x01, 0x00, 0x10];

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; probe.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    let before = stats.get_connects_all();
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "203.0.113.177:55001".parse().unwrap();

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
    drop(client_side);

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        stats.get_connects_all(),
        before + 1,
        "handle_client_stream must increment connects_all exactly once"
    );
}

#[tokio::test]
async fn running_client_handler_increments_connects_all_exactly_once() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let probe = [0x16, 0x03, 0x01, 0x00, 0x10];

    let mask_accept_task = tokio::spawn(async move {
        let (mut stream, _) = mask_listener.accept().await.unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, probe);
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
    let before = stats.get_connects_all();
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let server_task = {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let route_runtime = route_runtime.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();

        tokio::spawn(async move {
            let (stream, peer) = front_listener.accept().await.unwrap();
            let real_peer_report = Arc::new(std::sync::Mutex::new(None));
            ClientHandler::new(
                stream,
                peer,
                config,
                stats,
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
                real_peer_report,
            )
            .run()
            .await
        })
    };

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&probe).await.unwrap();
    drop(client);

    let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        stats.get_connects_all(),
        before + 1,
        "ClientHandler::run must increment connects_all exactly once"
    );
}

#[tokio::test]
async fn partial_tls_header_stall_triggers_handshake_timeout() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "198.51.100.170:55201".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
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

    client_side
        .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ProxyError::TgHandshakeTimeout)));
}

fn make_valid_tls_client_hello_with_len(secret: &[u8], timestamp: u32, tls_len: usize) -> Vec<u8> {
    assert!(tls_len <= u16::MAX as usize, "TLS length must fit into record header");

    let total_len = 5 + tls_len;
    let mut handshake = vec![0x42u8; total_len];

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

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].copy_from_slice(&digest);
    handshake
}

fn make_valid_tls_client_hello(secret: &[u8], timestamp: u32) -> Vec<u8> {
    make_valid_tls_client_hello_with_len(secret, timestamp, 600)
}

fn make_valid_tls_client_hello_with_alpn(
    secret: &[u8],
    timestamp: u32,
    alpn_protocols: &[&[u8]],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[0u8; 32]);
    body.push(32);
    body.extend_from_slice(&[0x42u8; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);

    let mut ext_blob = Vec::new();
    if !alpn_protocols.is_empty() {
        let mut alpn_list = Vec::new();
        for proto in alpn_protocols {
            alpn_list.push(proto.len() as u8);
            alpn_list.extend_from_slice(proto);
        }

        let mut alpn_data = Vec::new();
        alpn_data.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        alpn_data.extend_from_slice(&alpn_list);

        ext_blob.extend_from_slice(&0x0010u16.to_be_bytes());
        ext_blob.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(&alpn_data);
    }

    body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_blob);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&body_len[1..4]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let computed = sha256_hmac(secret, &record);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }

    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    record
}

fn wrap_tls_application_data(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(0x17);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

#[tokio::test]
async fn valid_tls_path_does_not_fall_back_to_mask_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x11u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 0);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "11111111111111111111111111111111".to_string());

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(8192);
    let peer: SocketAddr = "198.51.100.80:55002".parse().unwrap();
    let stats_for_assert = stats.clone();
    let bad_before = stats_for_assert.get_connects_bad();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
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

    client_side.write_all(&client_hello).await.unwrap();

    let mut record_header = [0u8; 5];
    client_side.read_exact(&mut record_header).await.unwrap();
    assert_eq!(record_header[0], 0x16);

    drop(client_side);
    let handler_result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(handler_result.is_err());

    let no_mask_connect = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
    assert!(
        no_mask_connect.is_err(),
        "Mask backend must not be contacted on authenticated TLS path"
    );

    let bad_after = stats_for_assert.get_connects_bad();
    assert_eq!(
        bad_before,
        bad_after,
        "Authenticated TLS path must not increment connects_bad"
    );
}

#[tokio::test]
async fn valid_tls_with_invalid_mtproto_falls_back_to_mask_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x33u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 0);
    let invalid_mtproto = vec![0u8; crate::protocol::constants::HANDSHAKE_LEN];
    let tls_app_record = wrap_tls_application_data(&invalid_mtproto);

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; invalid_mtproto.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, invalid_mtproto);
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "33333333333333333333333333333333".to_string());

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(32768);
    let peer: SocketAddr = "198.51.100.90:55111".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
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

    client_side.write_all(&client_hello).await.unwrap();
    let mut tls_response_head = [0u8; 5];
    client_side.read_exact(&mut tls_response_head).await.unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side.write_all(&tls_app_record).await.unwrap();

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
async fn client_handler_tls_bad_mtproto_is_forwarded_to_mask_backend() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let secret = [0x44u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 0);
    let invalid_mtproto = vec![0u8; crate::protocol::constants::HANDSHAKE_LEN];
    let tls_app_record = wrap_tls_application_data(&invalid_mtproto);

    let mask_accept_task = tokio::spawn(async move {
        let (mut stream, _) = mask_listener.accept().await.unwrap();
        let mut got = vec![0u8; invalid_mtproto.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, invalid_mtproto);
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "44444444444444444444444444444444".to_string());

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let server_task = {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let route_runtime = route_runtime.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();

        tokio::spawn(async move {
            let (stream, peer) = front_listener.accept().await.unwrap();
            let real_peer_report = Arc::new(std::sync::Mutex::new(None));
            ClientHandler::new(
                stream,
                peer,
                config,
                stats,
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
                real_peer_report,
            )
            .run()
            .await
        })
    };

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&client_hello).await.unwrap();

    let mut tls_response_head = [0u8; 5];
    client.read_exact(&mut tls_response_head).await.unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client.write_all(&tls_app_record).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client);

    let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn alpn_mismatch_tls_probe_is_masked_through_client_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x66u8; 16];
    let probe = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; probe.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    cfg.censorship.alpn_enforce = true;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "66666666666666666666666666666666".to_string());

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(8192);
    let peer: SocketAddr = "198.51.100.66:55211".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
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
    assert_eq!(observed, backend_reply);

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn invalid_hmac_tls_probe_is_masked_through_client_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x77u8; 16];
    let mut probe = make_valid_tls_client_hello(&secret, 0);
    probe[tls::TLS_DIGEST_POS] ^= 0x01;

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; probe.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "77777777777777777777777777777777".to_string());

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(8192);
    let peer: SocketAddr = "198.51.100.77:55212".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
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
async fn burst_invalid_tls_probes_are_masked_verbatim() {
    const N: usize = 12;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x88u8; 16];
    let mut probe = make_valid_tls_client_hello(&secret, 0);
    probe[tls::TLS_DIGEST_POS + 1] ^= 0x01;

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        async move {
            for _ in 0..N {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut got = vec![0u8; probe.len()];
                stream.read_exact(&mut got).await.unwrap();
                assert_eq!(got, probe);
            }
        }
    });

    let mut handlers = Vec::with_capacity(N);
    for i in 0..N {
        let mut cfg = ProxyConfig::default();
        cfg.general.beobachten = false;
        cfg.censorship.mask = true;
        cfg.censorship.mask_unix_sock = None;
        cfg.censorship.mask_host = Some("127.0.0.1".to_string());
        cfg.censorship.mask_port = backend_addr.port();
        cfg.censorship.mask_proxy_protocol = 0;
        cfg.access.ignore_time_skew = true;
        cfg.access
            .users
            .insert("user".to_string(), "88888888888888888888888888888888".to_string());

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
        let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
        let buffer_pool = Arc::new(BufferPool::new());
        let rng = Arc::new(SecureRandom::new());
        let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
        let ip_tracker = Arc::new(UserIpTracker::new());
        let beobachten = Arc::new(BeobachtenStore::new());

        let (server_side, mut client_side) = duplex(8192);
        let peer: SocketAddr = format!("198.51.100.{}:{}", 100 + i, 56000 + i)
            .parse()
            .unwrap();
        let probe_bytes = probe.clone();

        let h = tokio::spawn(async move {
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                peer,
                config,
                stats,
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

            client_side.write_all(&probe_bytes).await.unwrap();
            drop(client_side);

            tokio::time::timeout(Duration::from_secs(3), handler)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        });
        handlers.push(h);
    }

    for h in handlers {
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
    }

    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn unexpected_eof_is_classified_without_string_matching() {
    let beobachten = BeobachtenStore::new();
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;

    let eof = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    let peer_ip: IpAddr = "198.51.100.200".parse().unwrap();

    record_handshake_failure_class(&beobachten, &config, peer_ip, &eof);

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(
        snapshot.contains("[expected_64_got_0]"),
        "UnexpectedEof must be classified as expected_64_got_0"
    );
    assert!(
        snapshot.contains("198.51.100.200-1"),
        "Classified record must include source IP"
    );
}

#[test]
fn non_eof_error_is_classified_as_other() {
    let beobachten = BeobachtenStore::new();
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;

    let non_eof = ProxyError::Io(std::io::Error::other("different error"));
    let peer_ip: IpAddr = "203.0.113.201".parse().unwrap();

    record_handshake_failure_class(&beobachten, &config, peer_ip, &non_eof);

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(
        snapshot.contains("[other]"),
        "Non-EOF errors must map to other"
    );
    assert!(
        snapshot.contains("203.0.113.201-1"),
        "Classified record must include source IP"
    );
    assert!(
        !snapshot.contains("[expected_64_got_0]"),
        "Non-EOF errors must not be misclassified as expected_64_got_0"
    );
}

#[tokio::test]
async fn tcp_limit_rejection_does_not_reserve_ip_or_trigger_rollback() {
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert("user".to_string(), 1);

    let stats = Stats::new();
    stats.increment_user_curr_connects("user");

    let ip_tracker = UserIpTracker::new();
    let peer_addr: SocketAddr = "198.51.100.210:50000".parse().unwrap();

    let result = RunningClientHandler::check_user_limits_static(
        "user",
        &config,
        &stats,
        peer_addr,
        &ip_tracker,
    )
    .await;

    assert!(matches!(
        result,
        Err(ProxyError::ConnectionLimitExceeded { user }) if user == "user"
    ));
    assert_eq!(
        ip_tracker.get_active_ip_count("user").await,
        0,
        "Rejected client must not reserve IP slot"
    );
    assert_eq!(
        stats.get_ip_reservation_rollback_tcp_limit_total(),
        0,
        "No rollback should occur when reservation is not taken"
    );
}

#[tokio::test]
async fn quota_rejection_does_not_reserve_ip_or_trigger_rollback() {
    let mut config = ProxyConfig::default();
    config.access.user_data_quota.insert("user".to_string(), 1024);

    let stats = Stats::new();
    stats.add_user_octets_from("user", 1024);

    let ip_tracker = UserIpTracker::new();
    let peer_addr: SocketAddr = "203.0.113.211:50001".parse().unwrap();

    let result = RunningClientHandler::check_user_limits_static(
        "user",
        &config,
        &stats,
        peer_addr,
        &ip_tracker,
    )
    .await;

    assert!(matches!(
        result,
        Err(ProxyError::DataQuotaExceeded { user }) if user == "user"
    ));
    assert_eq!(
        ip_tracker.get_active_ip_count("user").await,
        0,
        "Quota-rejected client must not reserve IP slot"
    );
    assert_eq!(
        stats.get_ip_reservation_rollback_quota_limit_total(),
        0,
        "No rollback should occur when reservation is not taken"
    );
}

#[tokio::test]
async fn concurrent_limit_rejections_from_mixed_ips_leave_no_ip_footprint() {
    const PARALLEL_IPS: usize = 64;
    const ATTEMPTS_PER_IP: usize = 8;

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert("user".to_string(), 1);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    stats.increment_user_curr_connects("user");
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..PARALLEL_IPS {
        let config = config.clone();
        let stats = stats.clone();
        let ip_tracker = ip_tracker.clone();

        tasks.spawn(async move {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, (i + 1) as u8));
            for _ in 0..ATTEMPTS_PER_IP {
                let peer_addr = SocketAddr::new(ip, 40000 + i as u16);
                let result = RunningClientHandler::check_user_limits_static(
                    "user",
                    &config,
                    &stats,
                    peer_addr,
                    &ip_tracker,
                )
                .await;

                assert!(matches!(
                    result,
                    Err(ProxyError::ConnectionLimitExceeded { user }) if user == "user"
                ));
            }
        });
    }

    while let Some(joined) = tasks.join_next().await {
        joined.unwrap();
    }

    assert_eq!(
        ip_tracker.get_active_ip_count("user").await,
        0,
        "Concurrent rejected attempts must not leave active IP reservations"
    );

    let recent = ip_tracker
        .get_recent_ips_for_users(&["user".to_string()])
        .await;
    assert!(
        recent
            .get("user")
            .map(|ips| ips.is_empty())
            .unwrap_or(true),
        "Concurrent rejected attempts must not leave recent IP footprint"
    );

    assert_eq!(
        stats.get_ip_reservation_rollback_tcp_limit_total(),
        0,
        "No rollback should occur under concurrent rejection storms"
    );
}

#[tokio::test]
async fn atomic_limit_gate_allows_only_one_concurrent_acquire() {
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert("user".to_string(), 1);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..64u16 {
        let config = config.clone();
        let stats = stats.clone();
        let ip_tracker = ip_tracker.clone();
        tasks.spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, (i + 1) as u8)),
                30000 + i,
            );
            RunningClientHandler::check_user_limits_static("user", &config, &stats, peer, &ip_tracker)
                .await
                .is_ok()
        });
    }

    let mut successes = 0u64;
    while let Some(joined) = tasks.join_next().await {
        if joined.unwrap() {
            successes += 1;
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent acquire must pass for a limit=1 user"
    );
    assert_eq!(stats.get_user_curr_connects("user"), 1);
}

#[tokio::test]
async fn untrusted_proxy_header_source_is_rejected() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.server.proxy_protocol_trusted_cidrs = vec!["10.10.0.0/16".parse().unwrap()];

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(2048);
    let peer: SocketAddr = "198.51.100.44:55000".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        None,
        route_runtime,
        None,
        ip_tracker,
        beobachten,
        true,
    ));

    let proxy_header = ProxyProtocolV1Builder::new()
        .tcp4(
            "203.0.113.9:32000".parse().unwrap(),
            "192.0.2.8:443".parse().unwrap(),
        )
        .build();
    client_side.write_all(&proxy_header).await.unwrap();
    drop(client_side);

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ProxyError::InvalidProxyProtocol)));
}

#[tokio::test]
async fn empty_proxy_trusted_cidrs_rejects_proxy_header_by_default() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.server.proxy_protocol_trusted_cidrs.clear();

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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(2048);
    let peer: SocketAddr = "198.51.100.45:55000".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        None,
        route_runtime,
        None,
        ip_tracker,
        beobachten,
        true,
    ));

    let proxy_header = ProxyProtocolV1Builder::new()
        .tcp4(
            "203.0.113.9:32000".parse().unwrap(),
            "192.0.2.8:443".parse().unwrap(),
        )
        .build();
    client_side.write_all(&proxy_header).await.unwrap();
    drop(client_side);

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ProxyError::InvalidProxyProtocol)));
}

#[tokio::test]
async fn oversized_tls_record_is_masked_in_generic_stream_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = [
        0x16,
        0x03,
        0x01,
        (((MAX_TLS_RECORD_SIZE + 1) >> 8) & 0xff) as u8,
        ((MAX_TLS_RECORD_SIZE + 1) & 0xff) as u8,
    ];
    let backend_reply = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    assert_eq!(observed, backend_reply);

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    accept_task.await.unwrap();

    assert_eq!(
        stats.get_connects_bad(),
        bad_before + 1,
        "Oversized TLS probe must be classified as bad"
    );
}

#[tokio::test]
async fn oversized_tls_record_is_masked_in_client_handler_pipeline() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let probe = [
        0x16,
        0x03,
        0x01,
        (((MAX_TLS_RECORD_SIZE + 1) >> 8) & 0xff) as u8,
        ((MAX_TLS_RECORD_SIZE + 1) & 0xff) as u8,
    ];
    let backend_reply = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();

    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let server_task = {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let route_runtime = route_runtime.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();

        tokio::spawn(async move {
            let (stream, peer) = front_listener.accept().await.unwrap();
            let real_peer_report = Arc::new(std::sync::Mutex::new(None));
            ClientHandler::new(
                stream,
                peer,
                config,
                stats,
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
                real_peer_report,
            )
            .run()
            .await
        })
    };

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&probe).await.unwrap();

    let mut observed = vec![0u8; backend_reply.len()];
    client.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);

    tokio::time::timeout(Duration::from_secs(3), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client);

    let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_record_len_511_is_rejected_in_generic_stream_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = [0x16, 0x03, 0x01, 0x01, 0xff];
    let backend_reply = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "203.0.113.130:55130".parse().unwrap();

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
    assert_eq!(observed, backend_reply);

    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    accept_task.await.unwrap();

    assert_eq!(
        stats.get_connects_bad(),
        bad_before + 1,
        "TLS record length 511 must be rejected"
    );
}

#[tokio::test]
async fn tls_record_len_511_is_rejected_in_client_handler_pipeline() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let probe = [0x16, 0x03, 0x01, 0x01, 0xff];
    let backend_reply = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();

    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let server_task = {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let route_runtime = route_runtime.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();

        tokio::spawn(async move {
            let (stream, peer) = front_listener.accept().await.unwrap();
            let real_peer_report = Arc::new(std::sync::Mutex::new(None));
            ClientHandler::new(
                stream,
                peer,
                config,
                stats,
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
                real_peer_report,
            )
            .run()
            .await
        })
    };

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&probe).await.unwrap();

    let mut observed = vec![0u8; backend_reply.len()];
    client.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);

    tokio::time::timeout(Duration::from_secs(3), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    drop(client);

    let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_record_len_16384_is_accepted_in_generic_stream_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x55u8; 16];
    let client_hello = make_valid_tls_client_hello_with_len(&secret, 0, MAX_TLS_RECORD_SIZE);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "55555555555555555555555555555555".to_string());

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let bad_before = stats.get_connects_bad();
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(131072);
    let peer: SocketAddr = "198.51.100.55:56055".parse().unwrap();

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

    client_side.write_all(&client_hello).await.unwrap();
    let mut record_header = [0u8; 5];
    client_side.read_exact(&mut record_header).await.unwrap();
    assert_eq!(record_header[0], 0x16, "Valid max-length ClientHello must be accepted");

    drop(client_side);
    let handler_result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(handler_result.is_err());

    let no_mask_connect = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
    assert!(
        no_mask_connect.is_err(),
        "Valid max-length ClientHello must not trigger mask fallback"
    );

    assert_eq!(
        bad_before,
        stats.get_connects_bad(),
        "Valid max-length ClientHello must not increment bad counter"
    );
}

#[tokio::test]
async fn tls_record_len_16384_is_accepted_in_client_handler_pipeline() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let secret = [0x66u8; 16];
    let client_hello = make_valid_tls_client_hello_with_len(&secret, 0, MAX_TLS_RECORD_SIZE);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), "66666666666666666666666666666666".to_string());

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let bad_before = stats.get_connects_bad();
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
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let server_task = {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let route_runtime = route_runtime.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();

        tokio::spawn(async move {
            let (stream, peer) = front_listener.accept().await.unwrap();
            let real_peer_report = Arc::new(std::sync::Mutex::new(None));
            ClientHandler::new(
                stream,
                peer,
                config,
                stats,
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
                real_peer_report,
            )
            .run()
            .await
        })
    };

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&client_hello).await.unwrap();

    let mut record_header = [0u8; 5];
    client.read_exact(&mut record_header).await.unwrap();
    assert_eq!(record_header[0], 0x16, "Valid max-length ClientHello must be accepted");

    drop(client);

    let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();

    let no_mask_connect = tokio::time::timeout(Duration::from_millis(250), mask_listener.accept()).await;
    assert!(
        no_mask_connect.is_err(),
        "Valid max-length ClientHello must not trigger mask fallback in ClientHandler path"
    );

    assert_eq!(
        bad_before,
        stats.get_connects_bad(),
        "Valid max-length ClientHello must not increment bad counter"
    );
}
