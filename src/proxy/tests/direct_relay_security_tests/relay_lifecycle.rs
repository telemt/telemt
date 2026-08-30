use super::*;

#[test]
fn fallback_dc_never_panics_with_single_dc_list() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.default_dc = Some(42);

    let addr = get_dc_addr_static(999, &cfg).expect("fallback dc must resolve safely");
    let expected = SocketAddr::new(TG_DATACENTERS_V6[0], TG_DATACENTER_PORT);
    assert_eq!(addr, expected);
}

#[tokio::test]
async fn direct_relay_abort_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

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

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "abort-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50000".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xabad1dea,
    ));

    let started = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        started.is_ok(),
        "direct relay must increment route gauge before abort"
    );

    relay_task.abort();
    let joined = relay_task.await;
    assert!(
        joined.is_err(),
        "aborted direct relay task must return join error"
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay task is aborted mid-flight"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

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

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "cutover-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50002".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xface_cafe,
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("direct relay must increment route gauge before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Middle).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(Duration::from_secs(6), relay_task)
        .await
        .expect("direct relay must terminate after cutover")
        .expect("direct relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover should terminate direct relay session"
    );
    assert!(
        matches!(relay_result, Err(ProxyError::RouteSwitched)),
        "client-visible cutover error must stay generic and avoid route-internal metadata"
    );

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay exits on cutover"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_storm_multi_session_keeps_generic_errors_and_releases_gauge() {
    let session_count = 6usize;
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let mut held_streams = Vec::with_capacity(session_count);
        for _ in 0..session_count {
            let (stream, _) = tg_listener.accept().await.unwrap();
            held_streams.push(stream);
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(held_streams);
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

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

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let mut relay_tasks = Vec::with_capacity(session_count);
    let mut client_sides = Vec::with_capacity(session_count);

    for idx in 0..session_count {
        let (server_side, client_side) = duplex(64 * 1024);
        client_sides.push(client_side);
        let (server_reader, server_writer) = tokio::io::split(server_side);
        let client_reader = make_crypto_reader(server_reader);
        let client_writer = make_crypto_writer(server_writer);

        let success = HandshakeSuccess {
            user: format!("cutover-storm-direct-user-{idx}"),
            dc_idx: 2,
            proto_tag: ProtoTag::Intermediate,
            dec_key: [0u8; 32],
            dec_iv: 0,
            enc_key: [0u8; 32],
            enc_iv: 0,
            peer: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                51000 + idx as u16,
            ),
            is_tls: false,
        };

        relay_tasks.push(tokio::spawn(handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager.clone(),
            stats.clone(),
            config.clone(),
            buffer_pool.clone(),
            rng.clone(),
            route_runtime.subscribe(),
            route_snapshot,
            0xA000_0000 + idx as u64,
        )));
    }

    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if stats.get_current_connections_direct() == session_count as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all direct sessions must become active before cutover storm");

    let route_runtime_flipper = route_runtime.clone();
    let flipper = tokio::spawn(async move {
        for step in 0..64u32 {
            let mode = if (step & 1) == 0 {
                RelayRouteMode::Middle
            } else {
                RelayRouteMode::Direct
            };
            let _ = route_runtime_flipper.set_mode(mode);
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    });

    for relay_task in relay_tasks {
        let relay_result = tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("direct relay task must finish under cutover storm")
            .expect("direct relay task must not panic");

        assert!(
            matches!(relay_result, Err(ProxyError::RouteSwitched)),
            "storm-cutover termination must remain generic for all direct sessions"
        );
    }

    flipper.abort();
    let _ = flipper.await;

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "direct route gauge must return to zero after cutover storm"
    );

    drop(client_sides);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}
