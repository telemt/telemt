use super::*;

#[tokio::test]
async fn chaos_burst_reconnect_storm_for_masking_and_relay_concurrently() {
    const MASKING_SESSIONS: usize = 48;
    const RELAY_SESSIONS: usize = 48;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let backend_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            for _ in 0..MASKING_SESSIONS {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut req = [0u8; 32];
                stream.read_exact(&mut req).await.unwrap();
                assert!(
                    req.starts_with(b"GET /storm/"),
                    "masking backend must receive storm reconnect probes"
                );
                stream.write_all(&backend_reply).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        }
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_proxy_protocol = 0;

    let config = Arc::new(config);
    let beobachten = Arc::new(BeobachtenStore::new());
    let peer: SocketAddr = "198.51.100.200:55555".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let mut masking_tasks = Vec::with_capacity(MASKING_SESSIONS);
    for i in 0..MASKING_SESSIONS {
        let config = Arc::clone(&config);
        let beobachten = Arc::clone(&beobachten);
        let expected_reply = backend_reply.clone();
        masking_tasks.push(tokio::spawn(async move {
            let mut probe = [0u8; 32];
            let template = format!("GET /storm/{i:04} HTTP/1.1\r\n\r\n");
            let bytes = template.as_bytes();
            probe[..bytes.len()].copy_from_slice(bytes);

            let (client_reader, client_writer) = duplex(256);
            drop(client_writer);
            let (mut client_visible_reader, client_visible_writer) = duplex(1024);

            let handle = tokio::spawn(async move {
                handle_bad_client(
                    client_reader,
                    client_visible_writer,
                    &probe,
                    peer,
                    local,
                    &config,
                    &beobachten,
                )
                .await;
            });

            let mut observed = vec![0u8; expected_reply.len()];
            client_visible_reader
                .read_exact(&mut observed)
                .await
                .unwrap();
            assert_eq!(observed, expected_reply);

            timeout(Duration::from_secs(2), handle)
                .await
                .expect("masking reconnect task must complete")
                .unwrap();
        }));
    }

    let mut relay_tasks = Vec::with_capacity(RELAY_SESSIONS);
    for i in 0..RELAY_SESSIONS {
        relay_tasks.push(tokio::spawn(async move {
            let stats = Arc::new(Stats::new());
            let (mut client_peer, relay_client) = duplex(4096);
            let (relay_server, mut server_peer) = duplex(4096);

            let (client_reader, client_writer) = tokio::io::split(relay_client);
            let (server_reader, server_writer) = tokio::io::split(relay_server);

            let relay_task = tokio::spawn(relay_bidirectional(
                client_reader,
                client_writer,
                server_reader,
                server_writer,
                1024,
                1024,
                "chaos-storm-relay",
                stats,
                None,
                Arc::new(BufferPool::new()),
            ));

            let c2s = vec![(i as u8).wrapping_add(1); 64];
            client_peer.write_all(&c2s).await.unwrap();
            let mut c2s_seen = vec![0u8; c2s.len()];
            server_peer.read_exact(&mut c2s_seen).await.unwrap();
            assert_eq!(c2s_seen, c2s);

            let s2c = vec![(i as u8).wrapping_add(17); 96];
            server_peer.write_all(&s2c).await.unwrap();
            let mut s2c_seen = vec![0u8; s2c.len()];
            client_peer.read_exact(&mut s2c_seen).await.unwrap();
            assert_eq!(s2c_seen, s2c);

            drop(client_peer);
            drop(server_peer);
            timeout(Duration::from_secs(2), relay_task)
                .await
                .expect("relay reconnect task must complete")
                .unwrap()
                .unwrap();
        }));
    }

    for task in masking_tasks {
        timeout(Duration::from_secs(3), task)
            .await
            .expect("masking storm join must complete")
            .unwrap();
    }

    for task in relay_tasks {
        timeout(Duration::from_secs(3), task)
            .await
            .expect("relay storm join must complete")
            .unwrap();
    }

    timeout(Duration::from_secs(3), backend_task)
        .await
        .expect("masking backend accept loop must complete")
        .unwrap();
}

fn read_env_usize_or_default(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(parsed) if parsed > 0 => parsed,
            _ => default,
        },
        Err(_) => default,
    }
}

#[tokio::test]
#[ignore = "heavy soak; run manually"]
async fn chaos_burst_reconnect_storm_for_masking_and_relay_multiwave_soak() {
    let waves = read_env_usize_or_default("CHAOS_WAVES", 4);
    let masking_per_wave = read_env_usize_or_default("CHAOS_MASKING_PER_WAVE", 160);
    let relay_per_wave = read_env_usize_or_default("CHAOS_RELAY_PER_WAVE", 160);
    let total_masking = waves * masking_per_wave;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let backend_reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();

    let backend_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            for _ in 0..total_masking {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut req = [0u8; 32];
                stream.read_exact(&mut req).await.unwrap();
                assert!(
                    req.starts_with(b"GET /storm/"),
                    "mask backend must only receive storm probes"
                );
                stream.write_all(&backend_reply).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        }
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_proxy_protocol = 0;

    let config = Arc::new(config);
    let beobachten = Arc::new(BeobachtenStore::new());
    let peer: SocketAddr = "198.51.100.201:56565".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();

    for wave in 0..waves {
        let mut masking_tasks = Vec::with_capacity(masking_per_wave);
        for i in 0..masking_per_wave {
            let config = Arc::clone(&config);
            let beobachten = Arc::clone(&beobachten);
            let expected_reply = backend_reply.clone();
            masking_tasks.push(tokio::spawn(async move {
                let mut probe = [0u8; 32];
                let template = format!("GET /storm/{wave:02}-{i:03}\r\n\r\n");
                let bytes = template.as_bytes();
                probe[..bytes.len()].copy_from_slice(bytes);

                let (client_reader, client_writer) = duplex(256);
                drop(client_writer);
                let (mut client_visible_reader, client_visible_writer) = duplex(1024);

                let handle = tokio::spawn(async move {
                    handle_bad_client(
                        client_reader,
                        client_visible_writer,
                        &probe,
                        peer,
                        local,
                        &config,
                        &beobachten,
                    )
                    .await;
                });

                let mut observed = vec![0u8; expected_reply.len()];
                client_visible_reader
                    .read_exact(&mut observed)
                    .await
                    .unwrap();
                assert_eq!(observed, expected_reply);

                timeout(Duration::from_secs(3), handle)
                    .await
                    .expect("masking storm task must complete")
                    .unwrap();
            }));
        }

        let mut relay_tasks = Vec::with_capacity(relay_per_wave);
        for i in 0..relay_per_wave {
            relay_tasks.push(tokio::spawn(async move {
                let stats = Arc::new(Stats::new());
                let (mut client_peer, relay_client) = duplex(4096);
                let (relay_server, mut server_peer) = duplex(4096);

                let (client_reader, client_writer) = tokio::io::split(relay_client);
                let (server_reader, server_writer) = tokio::io::split(relay_server);

                let relay_task = tokio::spawn(relay_bidirectional(
                    client_reader,
                    client_writer,
                    server_reader,
                    server_writer,
                    1024,
                    1024,
                    "chaos-multiwave-relay",
                    stats,
                    None,
                    Arc::new(BufferPool::new()),
                ));

                let c2s = vec![(wave as u8).wrapping_add(i as u8).wrapping_add(1); 32];
                client_peer.write_all(&c2s).await.unwrap();
                let mut c2s_seen = vec![0u8; c2s.len()];
                server_peer.read_exact(&mut c2s_seen).await.unwrap();
                assert_eq!(c2s_seen, c2s);

                let s2c = vec![(wave as u8).wrapping_add(i as u8).wrapping_add(17); 48];
                server_peer.write_all(&s2c).await.unwrap();
                let mut s2c_seen = vec![0u8; s2c.len()];
                client_peer.read_exact(&mut s2c_seen).await.unwrap();
                assert_eq!(s2c_seen, s2c);

                drop(client_peer);
                drop(server_peer);
                timeout(Duration::from_secs(3), relay_task)
                    .await
                    .expect("relay storm task must complete")
                    .unwrap()
                    .unwrap();
            }));
        }

        for task in masking_tasks {
            timeout(Duration::from_secs(6), task)
                .await
                .expect("masking wave task join must complete")
                .unwrap();
        }

        for task in relay_tasks {
            timeout(Duration::from_secs(6), task)
                .await
                .expect("relay wave task join must complete")
                .unwrap();
        }
    }

    timeout(Duration::from_secs(8), backend_task)
        .await
        .expect("mask backend must complete all accepted storm sessions")
        .unwrap();
}

#[tokio::test]
#[ignore = "heavy soak; run manually"]
async fn masking_timing_bucket_soak_refused_backend_stays_within_narrow_band() {
    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 1;

    let peer: SocketAddr = "203.0.113.74:50006".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let mut samples = Vec::with_capacity(128);
    for _ in 0..128 {
        let (client_reader, _client_writer) = duplex(128);
        let (_client_visible_reader, client_visible_writer) = duplex(128);
        let started = Instant::now();
        handle_bad_client(
            client_reader,
            client_visible_writer,
            b"GET / HTTP/1.1\r\n",
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
        samples.push(started.elapsed().as_millis());
    }

    samples.sort_unstable();
    let p10 = samples[samples.len() / 10];
    let p90 = samples[(samples.len() * 9) / 10];
    assert!(
        p90.saturating_sub(p10) <= 40,
        "timing spread too wide for refused-backend masking path: p10={p10}ms p90={p90}ms"
    );
}
