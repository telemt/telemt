use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::AesCtr;
use crate::crypto::sha256_hmac;
use crate::protocol::constants::ProtoTag;
use crate::protocol::tls;
use crate::proxy::handshake::HandshakeSuccess;
use crate::stream::{CryptoReader, CryptoWriter};
use crate::transport::proxy_protocol::ProxyProtocolV1Builder;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn synthetic_local_addr_uses_configured_port_for_zero() {
    let addr = synthetic_local_addr(0);
    assert_eq!(addr.ip(), IpAddr::from([0, 0, 0, 0]));
    assert_eq!(addr.port(), 0);
}

#[test]
fn synthetic_local_addr_uses_configured_port_for_max() {
    let addr = synthetic_local_addr(u16::MAX);
    assert_eq!(addr.ip(), IpAddr::from([0, 0, 0, 0]));
    assert_eq!(addr.port(), u16::MAX);
}

#[test]
fn handshake_timeout_with_mask_grace_includes_mask_margin() {
    let mut config = ProxyConfig::default();
    config.timeouts.client_handshake = 2;

    config.censorship.mask = false;
    assert_eq!(
        handshake_timeout_with_mask_grace(&config),
        Duration::from_secs(2)
    );

    config.censorship.mask = true;
    assert_eq!(
        handshake_timeout_with_mask_grace(&config),
        Duration::from_millis(2750),
        "mask mode extends handshake timeout by 750 ms"
    );
}

#[tokio::test]
async fn read_with_progress_reads_partial_buffers_before_eof() {
    let data = vec![0xAA, 0xBB, 0xCC];
    let mut reader = std::io::Cursor::new(data);
    let mut buf = [0u8; 5];

    let read = read_with_progress(&mut reader, &mut buf).await.unwrap();
    assert_eq!(read, 3);
    assert_eq!(&buf[..3], &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn is_trusted_proxy_source_respects_cidr_list_and_empty_rejects_all() {
    let peer: IpAddr = "10.10.10.10".parse().unwrap();
    assert!(!is_trusted_proxy_source(peer, &[]));

    let trusted = vec!["10.0.0.0/8".parse().unwrap()];
    assert!(is_trusted_proxy_source(peer, &trusted));

    let not_trusted = vec!["192.0.2.0/24".parse().unwrap()];
    assert!(!is_trusted_proxy_source(peer, &not_trusted));
}

#[test]
fn is_trusted_proxy_source_accepts_cidr_zero_zero_as_global_cidr() {
    let peer: IpAddr = "203.0.113.42".parse().unwrap();
    let trust_all = vec!["0.0.0.0/0".parse().unwrap()];
    assert!(is_trusted_proxy_source(peer, &trust_all));

    let peer_v6: IpAddr = "2001:db8::1".parse().unwrap();
    let trust_all_v6 = vec!["::/0".parse().unwrap()];
    assert!(is_trusted_proxy_source(peer_v6, &trust_all_v6));
}

struct ErrorReader;

impl tokio::io::AsyncRead for ErrorReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "fake error",
        )))
    }
}

#[tokio::test]
async fn read_with_progress_returns_error_from_failed_reader() {
    let mut reader = ErrorReader;
    let mut buf = [0u8; 8];
    let err = read_with_progress(&mut reader, &mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn handshake_timeout_with_mask_grace_handles_maximum_values_without_overflow() {
    let mut config = ProxyConfig::default();
    config.timeouts.client_handshake = u64::MAX;
    config.censorship.mask = true;

    let timeout = handshake_timeout_with_mask_grace(&config);
    assert!(timeout >= Duration::from_secs(u64::MAX));
}

#[tokio::test]
async fn read_with_progress_zero_length_buffer_returns_zero() {
    let data = vec![1, 2, 3];
    let mut reader = std::io::Cursor::new(data);
    let mut buf = [];

    let read = read_with_progress(&mut reader, &mut buf).await.unwrap();
    assert_eq!(read, 0);
}

#[test]
fn handshake_timeout_without_mask_is_exact_base() {
    let mut config = ProxyConfig::default();
    config.timeouts.client_handshake = 7;
    config.censorship.mask = false;

    assert_eq!(
        handshake_timeout_with_mask_grace(&config),
        Duration::from_secs(7)
    );
}

#[test]
fn handshake_timeout_mask_enabled_adds_750ms() {
    let mut config = ProxyConfig::default();
    config.timeouts.client_handshake = 3;
    config.censorship.mask = true;

    assert_eq!(
        handshake_timeout_with_mask_grace(&config),
        Duration::from_millis(3750)
    );
}

#[tokio::test]
async fn read_with_progress_full_then_empty_transition() {
    let data = vec![0x10, 0x20];
    let mut cursor = std::io::Cursor::new(data);
    let mut buf = [0u8; 2];

    assert_eq!(read_with_progress(&mut cursor, &mut buf).await.unwrap(), 2);
    assert_eq!(read_with_progress(&mut cursor, &mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn read_with_progress_fragmented_io_works_over_multiple_calls() {
    let mut cursor = std::io::Cursor::new(vec![1, 2, 3, 4, 5]);
    let mut result = Vec::new();

    for chunk_size in 1..=5 {
        let mut b = vec![0u8; chunk_size];
        let n = read_with_progress(&mut cursor, &mut b).await.unwrap();
        result.extend_from_slice(&b[..n]);
        if n == 0 {
            break;
        }
    }

    assert_eq!(result, vec![1, 2, 3, 4, 5]);
}

#[tokio::test]
async fn read_with_progress_stress_randomized_chunk_sizes() {
    for i in 0..128 {
        let mut rng = StdRng::seed_from_u64(i as u64 + 1);
        let mut input: Vec<u8> = (0..(i % 41)).map(|_| rng.next_u32() as u8).collect();
        let mut cursor = std::io::Cursor::new(input.clone());
        let mut collected = Vec::new();

        while cursor.position() < cursor.get_ref().len() as u64 {
            let chunk = 1 + (rng.next_u32() as usize % 8);
            let mut b = vec![0u8; chunk];
            let read = read_with_progress(&mut cursor, &mut b).await.unwrap();
            collected.extend_from_slice(&b[..read]);
            if read == 0 {
                break;
            }
        }

        assert_eq!(collected, input);
    }
}

#[test]
fn is_trusted_proxy_source_boundary_narrow_ipv4() {
    let matching = "172.16.0.1".parse().unwrap();
    let not_matching = "172.15.255.255".parse().unwrap();
    let cidr = vec!["172.16.0.0/12".parse().unwrap()];
    assert!(is_trusted_proxy_source(matching, &cidr));
    assert!(!is_trusted_proxy_source(not_matching, &cidr));
}

#[test]
fn is_trusted_proxy_source_rejects_out_of_family_ipv6_v4_cidr() {
    let peer = "2001:db8::1".parse().unwrap();
    let cidr = vec!["10.0.0.0/8".parse().unwrap()];
    assert!(!is_trusted_proxy_source(peer, &cidr));
}

#[test]
fn wrap_tls_application_record_reserved_chunks_look_reasonable() {
    let payload = vec![0xAA; 1 + (u16::MAX as usize) + 2];
    let wrapped = wrap_tls_application_record(&payload);
    assert!(wrapped.len() > payload.len());
    assert!(wrapped.contains(&0x17));
}

#[test]
fn wrap_tls_application_record_roundtrip_size_check() {
    let payload_len = 3000;
    let payload = vec![0x55; payload_len];
    let wrapped = wrap_tls_application_record(&payload);

    let mut idx = 0;
    let mut consumed = 0;
    while idx + 5 <= wrapped.len() {
        assert_eq!(wrapped[idx], 0x17);
        let len = u16::from_be_bytes([wrapped[idx + 3], wrapped[idx + 4]]) as usize;
        consumed += len;
        idx += 5 + len;
        if idx >= wrapped.len() {
            break;
        }
    }

    assert_eq!(consumed, payload_len);
}

fn make_crypto_reader<R>(reader: R) -> CryptoReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

fn preload_user_quota(stats: &Stats, user: &str, bytes: u64) {
    let user_stats = stats.get_or_create_user_stats_handle(user);
    stats.quota_charge_post_write(user_stats.as_ref(), bytes);
}

#[tokio::test]
async fn user_connection_reservation_drop_enqueues_cleanup_synchronously() {
    let ip_tracker = Arc::new(crate::ip_tracker::UserIpTracker::new());
    let stats = Arc::new(crate::stats::Stats::new());
    let user = "sync-drop-user".to_string();
    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    ip_tracker.set_user_limit(&user, 1).await;
    ip_tracker.check_and_add(&user, ip).await.unwrap();
    stats.increment_user_curr_connects(&user);

    assert_eq!(ip_tracker.get_active_ip_count(&user).await, 1);
    assert_eq!(stats.get_user_curr_connects(&user), 1);

    let reservation =
        UserConnectionReservation::new(stats.clone(), ip_tracker.clone(), user.clone(), ip);

    // Drop the reservation synchronously without any tokio::spawn/await yielding!
    drop(reservation);

    // The IP is now inside the cleanup_queue, check that the queue has length 1
    let queue_len = ip_tracker.cleanup_queue_len_for_tests();
    assert_eq!(
        queue_len, 1,
        "Reservation drop must push directly to synchronized IP queue"
    );

    assert_eq!(
        stats.get_user_curr_connects(&user),
        0,
        "Stats must decrement immediately"
    );

    ip_tracker.drain_cleanup_queue().await;
    assert_eq!(ip_tracker.get_active_ip_count(&user).await, 0);
}

#[tokio::test]
async fn relay_task_abort_releases_user_gate_and_ip_reservation() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let user = "abort-user";
    let peer_addr: SocketAddr = "198.51.100.230:50000".parse().unwrap();

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut cfg = ProxyConfig::default();
    cfg.access.user_max_tcp_conns.insert(user.to_string(), 8);
    cfg.dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(cfg);

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

    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: user.to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: peer_addr,
        is_tls: false,
    };

    let relay_task = tokio::spawn(RunningClientHandler::handle_authenticated_static(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        None,
        route_runtime,
        "127.0.0.1:443".parse().unwrap(),
        peer_addr,
        ip_tracker.clone(),
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user) == 1
                && ip_tracker.get_active_ip_count(user).await == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay must reserve user slot and IP before abort");

    relay_task.abort();
    let joined = relay_task.await;
    assert!(joined.is_err(), "aborted relay task must return join error");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "task abort must release user current-connection slot"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "task abort must release reserved user IP footprint"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn relay_cutover_releases_user_gate_and_ip_reservation() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let user = "cutover-user";
    let peer_addr: SocketAddr = "198.51.100.231:50001".parse().unwrap();

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut cfg = ProxyConfig::default();
    cfg.access.user_max_tcp_conns.insert(user.to_string(), 8);
    cfg.dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(cfg);

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

    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: user.to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: peer_addr,
        is_tls: false,
    };

    let relay_task = tokio::spawn(RunningClientHandler::handle_authenticated_static(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        None,
        route_runtime.clone(),
        "127.0.0.1:443".parse().unwrap(),
        peer_addr,
        ip_tracker.clone(),
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user) == 1
                && ip_tracker.get_active_ip_count(user).await == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay must reserve user slot and IP before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Middle).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(Duration::from_secs(6), relay_task)
        .await
        .expect("relay must terminate after cutover")
        .expect("relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover must terminate direct relay session"
    );

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "cutover exit must release user current-connection slot"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "cutover exit must release reserved user IP footprint"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn integration_route_cutover_and_quota_overlap_fails_closed_and_releases_state() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (mut stream, _) = tg_listener.accept().await.unwrap();
        stream.write_all(&[0x41, 0x42]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let user = "cutover-quota-overlap-user";
    let peer_addr: SocketAddr = "198.51.100.240:50010".parse().unwrap();

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut cfg = ProxyConfig::default();
    cfg.access.user_max_tcp_conns.insert(user.to_string(), 8);
    cfg.access.user_data_quota.insert(user.to_string(), 1);
    cfg.dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(cfg);

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

    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: user.to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: peer_addr,
        is_tls: false,
    };

    let relay_task = tokio::spawn(RunningClientHandler::handle_authenticated_static(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        None,
        route_runtime.clone(),
        "127.0.0.1:443".parse().unwrap(),
        peer_addr,
        ip_tracker.clone(),
    ));

    let observed_progress = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user) >= 1
                || ip_tracker.get_active_ip_count(user).await >= 1
                || relay_task.is_finished()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        observed_progress,
        "overlap race test precondition must observe activation or bounded early termination"
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    let _ = route_runtime.set_mode(RelayRouteMode::Middle);

    let relay_result = tokio::time::timeout(Duration::from_secs(3), relay_task)
        .await
        .expect("overlap race relay must terminate")
        .expect("overlap race relay task must not panic");

    assert!(
        matches!(relay_result, Err(ProxyError::DataQuotaExceeded { .. }))
            || matches!(relay_result, Err(ProxyError::Proxy(ref msg)) if msg == crate::proxy::route_mode::ROUTE_SWITCH_ERROR_MSG),
        "overlap race must fail closed via quota enforcement or generic cutover termination"
    );

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "overlap race exit must release user current-connection slot"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "overlap race exit must release reserved user IP footprint"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn stress_drop_without_release_converges_to_zero_user_and_ip_state() {
    let user = "gap-t05-drop-stress-user";
    let mut config = crate::config::ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 4096);

    let stats = std::sync::Arc::new(crate::stats::Stats::new());
    let ip_tracker = std::sync::Arc::new(crate::ip_tracker::UserIpTracker::new());

    let mut reservations = Vec::new();
    for idx in 0..512u16 {
        let peer = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                198,
                51,
                (idx >> 8) as u8,
                (idx & 0xff) as u8,
            )),
            30_000 + idx,
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("reservation acquisition must succeed in stress precondition");
        reservations.push(reservation);
    }

    assert_eq!(stats.get_user_curr_connects(user), 512);

    for reservation in reservations {
        std::thread::spawn(move || drop(reservation))
            .join()
            .expect("drop thread must not panic");
    }

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("drop-only path must eventually release all user/IP reservations");
}

#[tokio::test]
async fn proxy_protocol_header_is_rejected_when_trust_list_is_empty() {
    let mut cfg = crate::config::ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.server.proxy_protocol_trusted_cidrs.clear();

    let config = std::sync::Arc::new(cfg);
    let stats = std::sync::Arc::new(crate::stats::Stats::new());
    let upstream_manager = std::sync::Arc::new(crate::transport::UpstreamManager::new(
        vec![crate::config::UpstreamConfig {
            upstream_type: crate::config::UpstreamType::Direct {
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
    let replay_checker = std::sync::Arc::new(crate::stats::ReplayChecker::new(
        128,
        std::time::Duration::from_secs(60),
    ));
    let buffer_pool = std::sync::Arc::new(crate::stream::BufferPool::new());
    let rng = std::sync::Arc::new(crate::crypto::SecureRandom::new());
    let route_runtime = std::sync::Arc::new(crate::proxy::route_mode::RouteRuntimeController::new(
        crate::proxy::route_mode::RelayRouteMode::Direct,
    ));
    let ip_tracker = std::sync::Arc::new(crate::ip_tracker::UserIpTracker::new());
    let beobachten = std::sync::Arc::new(crate::stats::beobachten::BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(2048);
    let peer: std::net::SocketAddr = "198.51.100.80:55000".parse().unwrap();

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

    let result = tokio::time::timeout(std::time::Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ProxyError::InvalidProxyProtocol)));
}

#[tokio::test]
async fn proxy_protocol_header_from_untrusted_peer_range_is_rejected_under_load() {
    let mut cfg = crate::config::ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.server.proxy_protocol_trusted_cidrs = vec!["10.0.0.0/8".parse().unwrap()];

    let config = std::sync::Arc::new(cfg);

    for idx in 0..32u16 {
        let stats = std::sync::Arc::new(crate::stats::Stats::new());
        let upstream_manager = std::sync::Arc::new(crate::transport::UpstreamManager::new(
            vec![crate::config::UpstreamConfig {
                upstream_type: crate::config::UpstreamType::Direct {
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
        let replay_checker = std::sync::Arc::new(crate::stats::ReplayChecker::new(
            64,
            std::time::Duration::from_secs(60),
        ));
        let buffer_pool = std::sync::Arc::new(crate::stream::BufferPool::new());
        let rng = std::sync::Arc::new(crate::crypto::SecureRandom::new());
        let route_runtime =
            std::sync::Arc::new(crate::proxy::route_mode::RouteRuntimeController::new(
                crate::proxy::route_mode::RelayRouteMode::Direct,
            ));
        let ip_tracker = std::sync::Arc::new(crate::ip_tracker::UserIpTracker::new());
        let beobachten = std::sync::Arc::new(crate::stats::beobachten::BeobachtenStore::new());

        let (server_side, mut client_side) = duplex(1024);
        let peer = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, (idx + 1) as u8)),
            55_000 + idx,
        );

        let handler = tokio::spawn(handle_client_stream(
            server_side,
            peer,
            config.clone(),
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
                "203.0.113.10:32000".parse().unwrap(),
                "192.0.2.8:443".parse().unwrap(),
            )
            .build();
        client_side.write_all(&proxy_header).await.unwrap();
        drop(client_side);

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handler)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(ProxyError::InvalidProxyProtocol)),
            "burst idx {idx}: untrusted source must be rejected"
        );
    }
}

#[tokio::test]
async fn reservation_limit_failure_does_not_leak_curr_connects_counter() {
    let user = "leak-check-user";
    let mut config = crate::config::ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let stats = Arc::new(crate::stats::Stats::new());
    let ip_tracker = Arc::new(crate::ip_tracker::UserIpTracker::new());
    ip_tracker.set_user_limit(user, 8).await;

    let first_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 200, 1)), 50001);
    let first = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        first_peer,
        ip_tracker.clone(),
    )
    .await
    .expect("first reservation must succeed");

    assert_eq!(stats.get_user_curr_connects(user), 1);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    let second_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 200, 2)), 50002);
    let second = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        second_peer,
        ip_tracker.clone(),
    )
    .await;

    assert!(
        matches!(second, Err(crate::error::ProxyError::ConnectionLimitExceeded { user: denied }) if denied == user),
        "second reservation must be rejected at the configured tcp-conns limit"
    );
    assert_eq!(
        stats.get_user_curr_connects(user),
        1,
        "failed acquisition must not leak a counter increment"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        1,
        "failed acquisition must not mutate IP tracker state"
    );

    first.release().await;
    ip_tracker.drain_cleanup_queue().await;

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

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
async fn tls12_record_probe_is_masked_through_client_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = vec![0x16, 0x03, 0x03, 0x00, 0x10];
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
    let peer: SocketAddr = "203.0.113.78:55001".parse().unwrap();

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
    assert!(
        tls_len <= u16::MAX as usize,
        "TLS length must fit into record header"
    );

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

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
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

    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].copy_from_slice(&digest);
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
    cfg.access.users.insert(
        "user".to_string(),
        "11111111111111111111111111111111".to_string(),
    );

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

    let (server_side, mut client_side) = duplex(131072);
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
        bad_before, bad_after,
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
    let trailing_tls_payload = b"still-tls-after-fallback".to_vec();
    let trailing_tls_record = wrap_tls_application_data(&trailing_tls_payload);

    let expected_trailing_tls_record = trailing_tls_record.clone();
    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut trailing = vec![0u8; expected_trailing_tls_record.len()];
        stream.read_exact(&mut trailing).await.unwrap();
        assert_eq!(trailing, expected_trailing_tls_record);
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "33333333333333333333333333333333".to_string(),
    );

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
    client_side
        .read_exact(&mut tls_response_head)
        .await
        .unwrap();
    assert_eq!(tls_response_head[0], 0x16);

    client_side.write_all(&tls_app_record).await.unwrap();
    client_side.write_all(&trailing_tls_record).await.unwrap();

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
    let trailing_tls_payload = b"second-tls-record".to_vec();
    let trailing_tls_record = wrap_tls_application_data(&trailing_tls_payload);

    let expected_trailing_tls_record = trailing_tls_record.clone();
    let mask_accept_task = tokio::spawn(async move {
        let (mut stream, _) = mask_listener.accept().await.unwrap();
        let mut trailing = vec![0u8; expected_trailing_tls_record.len()];
        stream.read_exact(&mut trailing).await.unwrap();
        assert_eq!(trailing, expected_trailing_tls_record);
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "44444444444444444444444444444444".to_string(),
    );

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
    client.write_all(&trailing_tls_record).await.unwrap();

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
    cfg.access.users.insert(
        "user".to_string(),
        "66666666666666666666666666666666".to_string(),
    );

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
    cfg.access.users.insert(
        "user".to_string(),
        "77777777777777777777777777777777".to_string(),
    );

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
        cfg.access.users.insert(
            "user".to_string(),
            "88888888888888888888888888888888".to_string(),
        );

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

#[test]
fn beobachten_ttl_zero_minutes_is_floored_to_one_minute() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 0;

    let ttl = beobachten_ttl(&config);
    assert_eq!(
        ttl,
        Duration::from_secs(60),
        "beobachten_minutes=0 must be fail-closed to a one-minute minimum TTL"
    );
}

#[test]
fn beobachten_ttl_positive_minutes_remain_unchanged() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 7;

    let ttl = beobachten_ttl(&config);
    assert_eq!(
        ttl,
        Duration::from_secs(7 * 60),
        "configured positive beobacten TTL must be preserved"
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
async fn zero_tcp_limit_rejects_without_ip_or_counter_side_effects() {
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert("user".to_string(), 0);

    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();
    let peer_addr: SocketAddr = "198.51.100.211:50001".parse().unwrap();

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
    assert_eq!(stats.get_user_curr_connects("user"), 0);
    assert_eq!(ip_tracker.get_active_ip_count("user").await, 0);
}

#[tokio::test]
async fn check_user_limits_static_success_does_not_leak_counter_or_ip_reservation() {
    let user = "check-helper-user";
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();
    let peer_addr: SocketAddr = "198.51.100.212:50002".parse().unwrap();

    let first = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer_addr,
        &ip_tracker,
    )
    .await;
    assert!(
        first.is_ok(),
        "first check-only limit validation must succeed"
    );

    let second = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer_addr,
        &ip_tracker,
    )
    .await;
    assert!(
        second.is_ok(),
        "second check-only validation must not fail from leaked state"
    );
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn stress_check_user_limits_static_success_never_leaks_state() {
    let user = "check-helper-stress-user";
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();

    for i in 0..4096u16 {
        let peer_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 110, (i % 250) as u8 + 1)),
            40000 + (i % 1024),
        );

        let result = RunningClientHandler::check_user_limits_static(
            user,
            &config,
            &stats,
            peer_addr,
            &ip_tracker,
        )
        .await;
        assert!(
            result.is_ok(),
            "check-only helper must remain leak-free under stress"
        );
    }

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "stress success loop must not leak user connection counters"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "stress success loop must not leak active IP reservations"
    );
}

#[tokio::test]
async fn concurrent_distinct_ip_rejections_rollback_user_counter_without_leak() {
    let user = "rollback-storm-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 128);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let keeper_peer: SocketAddr = "198.51.100.212:50002".parse().unwrap();
    let keeper = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        keeper_peer,
        ip_tracker.clone(),
    )
    .await
    .expect("keeper reservation must succeed");

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..64u8 {
        let config = config.clone();
        let stats = stats.clone();
        let ip_tracker = ip_tracker.clone();
        tasks.spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 101, i.saturating_add(1))),
                41000 + i as u16,
            );
            let result = RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await;
            assert!(matches!(
                result,
                Err(ProxyError::ConnectionLimitExceeded { user }) if user == "rollback-storm-user"
            ));
        });
    }

    while let Some(joined) = tasks.join_next().await {
        joined.unwrap();
    }

    assert_eq!(
        stats.get_user_curr_connects(user),
        1,
        "failed distinct-IP attempts must rollback acquired user slots"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        1,
        "failed distinct-IP attempts must not leave extra active IPs"
    );

    keeper.release().await;
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn explicit_reservation_release_cleans_user_and_ip_immediately() {
    let user = "release-user";
    let peer_addr: SocketAddr = "198.51.100.240:50002".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 4);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("reservation acquisition must succeed");

    assert_eq!(stats.get_user_curr_connects(user), 1);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    reservation.release().await;

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "explicit release must synchronously free user connection slot"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "explicit release must synchronously remove reserved user IP"
    );
}

#[tokio::test]
async fn explicit_reservation_release_does_not_double_decrement_on_drop() {
    let user = "release-once-user";
    let peer_addr: SocketAddr = "198.51.100.241:50003".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 4);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker,
    )
    .await
    .expect("reservation acquisition must succeed");

    reservation.release().await;

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "release must disarm drop and prevent double decrement"
    );
}

#[tokio::test]
async fn drop_fallback_eventually_cleans_user_and_ip_reservation() {
    let user = "drop-fallback-user";
    let peer_addr: SocketAddr = "198.51.100.242:50004".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 4);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("reservation acquisition must succeed");

    assert_eq!(stats.get_user_curr_connects(user), 1);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    drop(reservation);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("drop fallback must eventually clean both user slot and active IP");
}

#[tokio::test]
async fn explicit_release_allows_immediate_cross_ip_reacquire_under_limit() {
    let user = "cross-ip-user";
    let peer1: SocketAddr = "198.51.100.243:50005".parse().unwrap();
    let peer2: SocketAddr = "198.51.100.244:50006".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 4);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let first = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer1,
        ip_tracker.clone(),
    )
    .await
    .expect("first reservation must succeed");
    first.release().await;

    let second = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer2,
        ip_tracker.clone(),
    )
    .await
    .expect("second reservation must succeed immediately after explicit release");
    second.release().await;

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn release_abort_storm_does_not_leak_user_or_ip_reservations() {
    const ATTEMPTS: usize = 256;

    let user = "release-abort-storm-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), ATTEMPTS + 16);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    for idx in 0..ATTEMPTS {
        let peer = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 114, (idx % 250 + 1) as u8)),
            52000 + idx as u16,
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("reservation acquisition must succeed in abort storm");

        let release_task = tokio::spawn(async move {
            reservation.release().await;
        });
        release_task.abort();
        let _ = release_task.await;
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("release abort storm must not leak user slots or active IP entries");
}

#[tokio::test]
async fn release_abort_loop_preserves_immediate_same_ip_reacquire() {
    const ITERATIONS: usize = 128;

    let user = "release-abort-reacquire-user";
    let peer: SocketAddr = "198.51.100.246:53001".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    for _ in 0..ITERATIONS {
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("baseline acquisition must succeed");

        let release_task = tokio::spawn(async move {
            reservation.release().await;
        });
        release_task.abort();
        let _ = release_task.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if stats.get_user_curr_connects(user) == 0
                    && ip_tracker.get_active_ip_count(user).await == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("aborted release must still converge to zero footprint");
    }

    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer,
        ip_tracker.clone(),
    )
    .await
    .expect("same-ip reacquire must succeed after repeated abort-release churn");
    reservation.release().await;
}

#[tokio::test]
async fn adversarial_mixed_release_drop_abort_wave_converges_to_zero() {
    const RESERVATIONS: usize = 192;

    let user = "mixed-wave-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), RESERVATIONS + 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut reservations = Vec::with_capacity(RESERVATIONS);
    for idx in 0..RESERVATIONS {
        let peer = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 115, (idx % 250 + 1) as u8)),
            54000 + idx as u16,
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("mixed-wave acquisition must succeed");
        reservations.push(reservation);
    }

    let mut seed: u64 = 0xDEAD_BEEF_CAFE_BA5E;
    let mut join_set = tokio::task::JoinSet::new();
    for reservation in reservations {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        match seed % 3 {
            0 => {
                join_set.spawn(async move {
                    reservation.release().await;
                });
            }
            1 => {
                drop(reservation);
            }
            _ => {
                let task = tokio::spawn(async move {
                    reservation.release().await;
                });
                task.abort();
                let _ = task.await;
            }
        }
    }

    while let Some(result) = join_set.join_next().await {
        result.expect("release subtask must not panic");
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("mixed release/drop/abort wave must converge to zero footprint");
}

#[tokio::test]
async fn parallel_users_abort_release_isolation_preserves_independent_cleanup() {
    let user_a = "abort-isolation-a";
    let user_b = "abort-isolation-b";

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user_a.to_string(), 64);
    config
        .access
        .user_max_tcp_conns
        .insert(user_b.to_string(), 64);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut tasks = tokio::task::JoinSet::new();
    for idx in 0..64usize {
        let user = if idx % 2 == 0 { user_a } else { user_b };
        let peer = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, (idx % 250 + 1) as u8)),
            55000 + idx as u16,
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("parallel-user acquisition must succeed");

        tasks.spawn(async move {
            let t = tokio::spawn(async move {
                reservation.release().await;
            });
            t.abort();
            let _ = t.await;
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("parallel-user abort task must not panic");
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user_a) == 0
                && stats.get_user_curr_connects(user_b) == 0
                && ip_tracker.get_active_ip_count(user_a).await == 0
                && ip_tracker.get_active_ip_count(user_b).await == 0
            {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("parallel users must cleanup independently under abort churn");
}

#[tokio::test]
async fn concurrent_release_storm_leaves_zero_user_and_ip_footprint() {
    const RESERVATIONS: usize = 64;

    let user = "release-storm-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), RESERVATIONS + 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut reservations = Vec::with_capacity(RESERVATIONS);
    for idx in 0..RESERVATIONS {
        let ip = std::net::Ipv4Addr::new(203, 0, 113, (idx + 1) as u8);
        let peer = SocketAddr::new(IpAddr::V4(ip), 51000 + idx as u16);
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("reservation acquisition in storm must succeed");
        reservations.push(reservation);
    }

    assert_eq!(stats.get_user_curr_connects(user), RESERVATIONS as u64);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, RESERVATIONS);

    let mut tasks = tokio::task::JoinSet::new();
    for reservation in reservations {
        tasks.spawn(async move {
            reservation.release().await;
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("release task must not panic");
    }

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "release storm must drain user current-connection counter to zero"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "release storm must clear all active IP entries"
    );
}

#[tokio::test]
async fn relay_connect_error_releases_user_and_ip_before_return() {
    let user = "relay-error-user";
    let peer_addr: SocketAddr = "198.51.100.245:50007".parse().unwrap();

    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);
    config
        .dc_overrides
        .insert("2".to_string(), vec![format!("127.0.0.1:{dead_port}")]);
    let config = Arc::new(config);

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

    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));

    let (server_side, _client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: user.to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: peer_addr,
        is_tls: false,
    };

    let result = RunningClientHandler::handle_authenticated_static(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        None,
        route_runtime,
        "127.0.0.1:443".parse().unwrap(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await;

    assert!(
        result.is_err(),
        "relay must fail when upstream DC is unreachable"
    );
    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "error return must release user slot before returning"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "error return must release user IP reservation before returning"
    );
}

#[tokio::test]
async fn mixed_release_and_drop_same_ip_preserves_counter_correctness() {
    let user = "same-ip-mixed-user";
    let peer_addr: SocketAddr = "198.51.100.246:50008".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation_a = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("first reservation must succeed");
    let reservation_b = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("second reservation must succeed");

    assert_eq!(stats.get_user_curr_connects(user), 2);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    reservation_a.release().await;
    assert_eq!(
        stats.get_user_curr_connects(user),
        1,
        "explicit release must decrement only one active reservation"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        1,
        "same IP must remain active while second reservation exists"
    );

    drop(reservation_b);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("drop fallback must clear final same-IP reservation");
}

#[tokio::test]
async fn drop_one_of_two_same_ip_reservations_keeps_ip_active() {
    let user = "same-ip-drop-one-user";
    let peer_addr: SocketAddr = "198.51.100.247:50009".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation_a = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("first reservation must succeed");
    let reservation_b = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("second reservation must succeed");

    drop(reservation_a);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 1
                && ip_tracker.get_active_ip_count(user).await == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dropping one reservation must keep same-IP activity for remaining reservation");

    reservation_b.release().await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("final release must converge to zero footprint after async fallback cleanup");
}

#[tokio::test]
async fn quota_rejection_does_not_reserve_ip_or_trigger_rollback() {
    let mut config = ProxyConfig::default();
    config
        .access
        .user_data_quota
        .insert("user".to_string(), 1024);

    let stats = Stats::new();
    preload_user_quota(&stats, "user", 1024);

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
async fn expired_user_rejection_does_not_reserve_ip_or_increment_curr_connects() {
    let mut config = ProxyConfig::default();
    config.access.user_expirations.insert(
        "user".to_string(),
        chrono::Utc::now() - chrono::Duration::seconds(1),
    );

    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();
    let peer_addr: SocketAddr = "203.0.113.212:50002".parse().unwrap();

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
        Err(ProxyError::UserExpired { user }) if user == "user"
    ));
    assert_eq!(stats.get_user_curr_connects("user"), 0);
    assert_eq!(ip_tracker.get_active_ip_count("user").await, 0);
}

#[tokio::test]
async fn same_ip_second_reservation_succeeds_under_unique_ip_limit_one() {
    let user = "same-ip-unique-limit-user";
    let peer_addr: SocketAddr = "198.51.100.248:50010".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let first = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("first reservation must succeed");
    let second = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("second reservation from same IP must succeed under unique-ip limit=1");

    assert_eq!(stats.get_user_curr_connects(user), 2);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    first.release().await;
    second.release().await;
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn second_distinct_ip_is_rejected_under_unique_ip_limit_one() {
    let user = "distinct-ip-unique-limit-user";
    let peer1: SocketAddr = "198.51.100.249:50011".parse().unwrap();
    let peer2: SocketAddr = "198.51.100.250:50012".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let first = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer1,
        ip_tracker.clone(),
    )
    .await
    .expect("first reservation must succeed");

    let second = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer2,
        ip_tracker.clone(),
    )
    .await;

    assert!(matches!(
        second,
        Err(ProxyError::ConnectionLimitExceeded { user }) if user == "distinct-ip-unique-limit-user"
    ));
    assert_eq!(stats.get_user_curr_connects(user), 1);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    first.release().await;
}

#[tokio::test]
async fn cross_thread_drop_uses_captured_runtime_for_ip_cleanup() {
    let user = "cross-thread-drop-user";
    let peer_addr: SocketAddr = "198.51.100.251:50013".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 8);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("reservation acquisition must succeed");

    assert_eq!(stats.get_user_curr_connects(user), 1);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    std::thread::spawn(move || {
        drop(reservation);
    })
    .join()
    .expect("drop thread must not panic");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cross-thread drop must still converge to zero user and IP footprint");
}

#[tokio::test]
async fn immediate_reacquire_after_cross_thread_drop_succeeds() {
    let user = "cross-thread-reacquire-user";
    let peer_addr: SocketAddr = "198.51.100.252:50014".parse().unwrap();

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_addr,
        ip_tracker.clone(),
    )
    .await
    .expect("initial reservation must succeed");

    std::thread::spawn(move || {
        drop(reservation);
    })
    .join()
    .expect("drop thread must not panic");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cross-thread cleanup must settle before reacquire check");

    let reacquire = RunningClientHandler::acquire_user_connection_reservation_static(
        user, &config, stats, peer_addr, ip_tracker,
    )
    .await;
    assert!(
        reacquire.is_ok(),
        "reacquire must succeed after cross-thread drop cleanup"
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
        recent.get("user").map(|ips| ips.is_empty()).unwrap_or(true),
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
            RunningClientHandler::acquire_user_connection_reservation_static(
                "user", &config, stats, peer, ip_tracker,
            )
            .await
            .ok()
        });
    }

    let mut successes = 0u64;
    let mut held_reservations = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Some(reservation) = joined.unwrap() {
            successes += 1;
            held_reservations.push(reservation);
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent acquire must pass for a limit=1 user"
    );
    assert_eq!(stats.get_user_curr_connects("user"), 1);

    drop(held_reservations);
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
        (((MAX_TLS_PLAINTEXT_SIZE + 1) >> 8) & 0xff) as u8,
        ((MAX_TLS_PLAINTEXT_SIZE + 1) & 0xff) as u8,
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
        (((MAX_TLS_PLAINTEXT_SIZE + 1) >> 8) & 0xff) as u8,
        ((MAX_TLS_PLAINTEXT_SIZE + 1) & 0xff) as u8,
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
async fn tls_record_len_min_minus_1_is_rejected_in_generic_stream_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = [
        0x16,
        0x03,
        0x01,
        (((MIN_TLS_CLIENT_HELLO_SIZE - 1) >> 8) & 0xff) as u8,
        ((MIN_TLS_CLIENT_HELLO_SIZE - 1) & 0xff) as u8,
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
        "TLS record length below minimum structural ClientHello size must be rejected"
    );
}

#[tokio::test]
async fn tls_record_len_min_minus_1_is_rejected_in_client_handler_pipeline() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let probe = [
        0x16,
        0x03,
        0x01,
        (((MIN_TLS_CLIENT_HELLO_SIZE - 1) >> 8) & 0xff) as u8,
        ((MIN_TLS_CLIENT_HELLO_SIZE - 1) & 0xff) as u8,
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
async fn tls_record_len_16384_is_accepted_in_generic_stream_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0x55u8; 16];
    let client_hello = make_valid_tls_client_hello_with_len(&secret, 0, MAX_TLS_PLAINTEXT_SIZE);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "55555555555555555555555555555555".to_string(),
    );

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
    assert_eq!(
        record_header[0], 0x16,
        "Valid max-length ClientHello must be accepted"
    );

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
    let client_hello = make_valid_tls_client_hello_with_len(&secret, 0, MAX_TLS_PLAINTEXT_SIZE);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "66666666666666666666666666666666".to_string(),
    );

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
    assert_eq!(
        record_header[0], 0x16,
        "Valid max-length ClientHello must be accepted"
    );

    drop(client);

    let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();

    let no_mask_connect =
        tokio::time::timeout(Duration::from_millis(250), mask_listener.accept()).await;
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

fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

async fn wait_for_user_and_ip_zero(
    stats: &Arc<Stats>,
    ip_tracker: &Arc<UserIpTracker>,
    user: &str,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_user_curr_connects(user) == 0
                && ip_tracker.get_active_ip_count(user).await == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cleanup must converge to zero user and IP footprint");
}

async fn burst_acquire_distinct_ips(
    user: &'static str,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    ip_tracker: Arc<UserIpTracker>,
    third_octet: u8,
    attempts: u16,
) -> (Vec<UserConnectionReservation>, usize) {
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..attempts {
        let config = config.clone();
        let stats = stats.clone();
        let ip_tracker = ip_tracker.clone();
        tasks.spawn(async move {
            let host = (i as u8).saturating_add(1);
            let peer = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, third_octet, host)),
                55000 + i,
            );
            RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await
        });
    }

    let mut successes = Vec::new();
    let mut failures = 0usize;
    while let Some(joined) = tasks.join_next().await {
        match joined.expect("burst acquire task must not panic") {
            Ok(reservation) => successes.push(reservation),
            Err(err) => {
                assert!(matches!(
                    err,
                    ProxyError::ConnectionLimitExceeded { user: ref denied_user }
                        if denied_user == user
                ));
                failures = failures.saturating_add(1);
            }
        }
    }

    (successes, failures)
}

#[tokio::test]
async fn deterministic_mixed_reservation_churn_preserves_counter_and_eventual_cleanup() {
    let user = "deterministic-churn-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 12);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 4).await;

    let mut seed = 0xD1F2_A4C8_991B_77E1u64;
    let mut reservations: Vec<Option<UserConnectionReservation>> = Vec::new();

    for step in 0..220u64 {
        let op = (lcg_next(&mut seed) % 100) as u8;
        let active = reservations.iter().filter(|entry| entry.is_some()).count();

        if active == 0 || op < 55 {
            let ip_octet = (lcg_next(&mut seed) % 16 + 1) as u8;
            let peer = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 120, ip_octet)),
                52000 + (step % 4000) as u16,
            );
            let result = RunningClientHandler::acquire_user_connection_reservation_static(
                user,
                &config,
                stats.clone(),
                peer,
                ip_tracker.clone(),
            )
            .await;

            if let Ok(reservation) = result {
                reservations.push(Some(reservation));
            } else {
                assert!(matches!(
                    result,
                    Err(ProxyError::ConnectionLimitExceeded { user }) if user == "deterministic-churn-user"
                ));
            }
        } else {
            let selected = reservations
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.is_some())
                .map(|(idx, _)| idx)
                .nth((lcg_next(&mut seed) as usize) % active)
                .unwrap();

            let reservation = reservations[selected].take().unwrap();
            if op < 80 {
                reservation.release().await;
            } else {
                std::thread::spawn(move || {
                    drop(reservation);
                })
                .join()
                .expect("cross-thread drop must not panic");
            }
        }

        let live_slots = reservations.iter().filter(|entry| entry.is_some()).count() as u64;
        assert_eq!(
            stats.get_user_curr_connects(user),
            live_slots,
            "current-connects counter must match number of live reservations"
        );
        assert!(
            stats.get_user_curr_connects(user) <= 12,
            "current-connects must stay within configured TCP limit"
        );
        assert!(
            ip_tracker.get_active_ip_count(user).await <= 4,
            "active unique IPs must stay within configured per-user IP limit"
        );
    }

    for reservation in reservations.into_iter().flatten() {
        reservation.release().await;
    }
    wait_for_user_and_ip_zero(&stats, &ip_tracker, user).await;
}

#[tokio::test]
async fn cross_thread_drop_storm_then_parallel_reacquire_wave_has_no_leak() {
    let user = "drop-storm-reacquire-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 64);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 8).await;

    let mut initial = Vec::new();
    for i in 0..32u16 {
        let ip_octet = (i % 8 + 1) as u8;
        let peer = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 120, ip_octet)),
            53000 + i,
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("initial reservation must succeed");
        initial.push(reservation);
    }

    let mut second_half = initial.split_off(16);

    let mut releases = Vec::new();
    for reservation in initial {
        releases.push(tokio::spawn(async move {
            reservation.release().await;
        }));
    }
    for release_task in releases {
        release_task.await.expect("release task must not panic");
    }

    let mut drop_threads = Vec::new();
    for reservation in second_half.drain(..) {
        drop_threads.push(std::thread::spawn(move || {
            drop(reservation);
        }));
    }
    for drop_thread in drop_threads {
        drop_thread
            .join()
            .expect("cross-thread drop worker must not panic");
    }

    wait_for_user_and_ip_zero(&stats, &ip_tracker, user).await;

    let mut reacquire_tasks = tokio::task::JoinSet::new();
    for i in 0..16u16 {
        let config = config.clone();
        let stats = stats.clone();
        let ip_tracker = ip_tracker.clone();
        reacquire_tasks.spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 121, (i + 1) as u8)),
                54000 + i,
            );
            RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await
        });
    }

    let mut acquired = Vec::new();
    while let Some(joined) = reacquire_tasks.join_next().await {
        match joined.expect("reacquire task must not panic") {
            Ok(reservation) => acquired.push(reservation),
            Err(err) => {
                assert!(matches!(
                    err,
                    ProxyError::ConnectionLimitExceeded { user }
                        if user == "drop-storm-reacquire-user"
                ));
            }
        }
    }

    assert!(
        acquired.len() <= 8,
        "parallel distinct-IP reacquire wave must not exceed per-user unique IP limit"
    );
    for reservation in acquired {
        reservation.release().await;
    }
    wait_for_user_and_ip_zero(&stats, &ip_tracker, user).await;
}

#[tokio::test]
async fn scheduled_near_limit_and_burst_windows_preserve_admission_invariants() {
    let user: &'static str = "scheduled-attack-user";
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 6);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 2).await;

    let mut base = Vec::new();
    for i in 0..5u16 {
        let peer = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 130, 1)),
            56000 + i,
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("near-limit warmup reservation must succeed");
        base.push(reservation);
    }
    assert_eq!(stats.get_user_curr_connects(user), 5);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    let (wave1_success, wave1_fail) = burst_acquire_distinct_ips(
        user,
        config.clone(),
        stats.clone(),
        ip_tracker.clone(),
        131,
        32,
    )
    .await;
    assert_eq!(wave1_success.len(), 1);
    assert_eq!(wave1_fail, 31);
    assert_eq!(stats.get_user_curr_connects(user), 6);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 2);

    let released = base.pop().expect("must have releasable reservation");
    released.release().await;
    for reservation in wave1_success {
        reservation.release().await;
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if stats.get_user_curr_connects(user) == 4
                && ip_tracker.get_active_ip_count(user).await == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("window cleanup must settle to expected occupancy");

    let (wave2_success, wave2_fail) =
        burst_acquire_distinct_ips(user, config, stats.clone(), ip_tracker.clone(), 132, 32).await;
    assert_eq!(wave2_success.len(), 1);
    assert_eq!(wave2_fail, 31);
    assert_eq!(stats.get_user_curr_connects(user), 5);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 2);

    let tail = base.split_off(2);

    let mut drop_threads = Vec::new();
    for reservation in base {
        drop_threads.push(std::thread::spawn(move || {
            drop(reservation);
        }));
    }
    for drop_thread in drop_threads {
        drop_thread
            .join()
            .expect("cross-thread scheduled cleanup must not panic");
    }

    for reservation in tail {
        reservation.release().await;
    }
    for reservation in wave2_success {
        reservation.release().await;
    }

    wait_for_user_and_ip_zero(&stats, &ip_tracker, user).await;
}

#[tokio::test]
async fn scheduled_mode_switch_burst_churn_preserves_limits_and_cleanup() {
    let user: &'static str = "scheduled-mode-switch-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 10);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 3).await;

    let base_peer = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 140, 1)), 57000);
    let mut base = Vec::new();
    for i in 0..7u16 {
        let peer = SocketAddr::new(base_peer.ip(), base_peer.port().saturating_add(i));
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .expect("base occupancy reservation must succeed");
        base.push(reservation);
    }

    assert_eq!(stats.get_user_curr_connects(user), 7);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    for round in 0..8u8 {
        let (wave_success, wave_fail) = burst_acquire_distinct_ips(
            user,
            config.clone(),
            stats.clone(),
            ip_tracker.clone(),
            141u8.saturating_add(round),
            24,
        )
        .await;

        assert!(
            wave_success.len() <= 2,
            "burst must not exceed available unique-IP headroom under limit=3"
        );
        assert_eq!(wave_success.len() + wave_fail, 24);
        assert_eq!(
            stats.get_user_curr_connects(user),
            7 + wave_success.len() as u64,
            "slot counter must reflect base occupancy plus successful burst leases"
        );
        assert!(ip_tracker.get_active_ip_count(user).await <= 3);

        if round % 2 == 0 {
            for reservation in wave_success {
                reservation.release().await;
            }
            let rotated = base.pop().expect("base rotation reservation must exist");
            rotated.release().await;
        } else {
            for reservation in wave_success {
                std::thread::spawn(move || {
                    drop(reservation);
                })
                .join()
                .expect("drop-heavy burst cleanup thread must not panic");
            }
            let rotated = base.pop().expect("base rotation reservation must exist");
            std::thread::spawn(move || {
                drop(rotated);
            })
            .join()
            .expect("drop-heavy base cleanup thread must not panic");
        }

        let replacement = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            base_peer,
            ip_tracker.clone(),
        )
        .await
        .expect("base replacement reservation must succeed after each round");
        base.push(replacement);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if stats.get_user_curr_connects(user) == 7
                    && ip_tracker.get_active_ip_count(user).await <= 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("round cleanup must converge to steady base occupancy");
    }

    for reservation in base {
        reservation.release().await;
    }
    wait_for_user_and_ip_zero(&stats, &ip_tracker, user).await;
}
