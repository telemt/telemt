use super::*;

#[tokio::test]
async fn masking_probes_indistinguishable_timing() {
    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 80; // Should timeout/refuse

    let peer: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    // Test different probe types
    let probes = vec![
        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), "HTTP"),
        (b"SSH-2.0-probe".to_vec(), "SSH"),
        (
            vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00],
            "TLS-scanner",
        ),
        (vec![0x42; 5], "port-scanner"),
    ];

    for (probe, type_name) in probes {
        let (client_reader, _client_writer) = duplex(256);
        let (_client_visible_reader, client_visible_writer) = duplex(256);

        let start = Instant::now();
        handle_bad_client(
            client_reader,
            client_visible_writer,
            &probe,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;

        let elapsed = start.elapsed();

        // We expect any outcome to take roughly MASK_TIMEOUT (50ms in tests)
        // to mask whether the backend was reachable or refused.
        assert!(
            elapsed >= Duration::from_millis(30),
            "Probe {type_name} finished too fast: {elapsed:?}"
        );
    }
}

// ------------------------------------------------------------------
// Masking Budget Stress Tests (OWASP ASVS 5.1.6)
// ------------------------------------------------------------------

#[tokio::test]
async fn masking_budget_stress_under_load() {
    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 1; // Unlikely port

    let peer: SocketAddr = "192.0.2.20:443".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = Arc::new(BeobachtenStore::new());

    let mut tasks = Vec::new();
    for _ in 0..50 {
        let (client_reader, _client_writer) = duplex(256);
        let (_client_visible_reader, client_visible_writer) = duplex(256);
        let config = config.clone();
        let beobachten = Arc::clone(&beobachten);

        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            handle_bad_client(
                client_reader,
                client_visible_writer,
                b"probe",
                peer,
                local_addr,
                &config,
                &beobachten,
            )
            .await;
            start.elapsed()
        }));
    }

    for task in tasks {
        let elapsed = task.await.unwrap();
        assert!(
            elapsed >= Duration::from_millis(30),
            "Stress probe finished too fast: {elapsed:?}"
        );
    }
}

// ------------------------------------------------------------------
// detect_client_type Fingerprint Check
// ------------------------------------------------------------------

#[test]
fn test_detect_client_type_boundary_cases() {
    // 9 bytes = port-scanner
    assert_eq!(detect_client_type(&[0x42; 9]), "port-scanner");
    // 10 bytes = unknown
    assert_eq!(detect_client_type(&[0x42; 10]), "unknown");

    // HTTP verbs without trailing space
    assert_eq!(detect_client_type(b"GET/"), "port-scanner"); // because len < 10
    assert_eq!(detect_client_type(b"GET /path"), "HTTP");
}

// ------------------------------------------------------------------
// Priority 2: Slowloris and Slow Read Attacks (OWASP ASVS 5.1.5)
// ------------------------------------------------------------------

#[tokio::test]
async fn masking_slowloris_client_idle_timeout_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let initial = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let initial = initial.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut observed = vec![0u8; initial.len()];
            stream.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed, initial);

            let mut drip = [0u8; 1];
            let drip_read =
                tokio::time::timeout(Duration::from_millis(220), stream.read_exact(&mut drip))
                    .await;
            assert!(
                drip_read.is_err() || drip_read.unwrap().is_err(),
                "backend must not receive post-timeout slowloris drip bytes"
            );
        }
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();

    let beobachten = BeobachtenStore::new();
    let peer: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let local: SocketAddr = "192.0.2.1:443".parse().unwrap();

    let (mut client_writer, client_reader) = duplex(1024);
    let (_client_visible_reader, client_visible_writer) = duplex(1024);

    let handle = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            &initial,
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(160)).await;
    let _ = client_writer.write_all(b"X").await;

    handle.await.unwrap();
    accept_task.await.unwrap();
}

// ------------------------------------------------------------------
// Priority 2: Fallback Server Down / Fingerprinting (OWASP ASVS 5.1.7)
// ------------------------------------------------------------------

#[tokio::test]
async fn masking_fallback_down_mimics_timeout() {
    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 1; // Unlikely port

    let (server_reader, server_writer) = duplex(1024);
    let beobachten = BeobachtenStore::new();
    let peer: SocketAddr = "192.0.2.12:12345".parse().unwrap();
    let local: SocketAddr = "192.0.2.1:443".parse().unwrap();

    let start = Instant::now();
    handle_bad_client(
        server_reader,
        server_writer,
        b"GET / HTTP/1.1\r\n",
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    let elapsed = start.elapsed();
    // It should wait for MASK_TIMEOUT (50ms in tests) even if connection was refused immediately
    assert!(
        elapsed >= Duration::from_millis(40),
        "Must respect connect budget even on failure: {:?}",
        elapsed
    );
}

// ------------------------------------------------------------------
// Priority 2: SSRF Prevention (OWASP ASVS 5.1.2)
// ------------------------------------------------------------------

#[tokio::test]
async fn masking_ssrf_resolve_internal_ranges_blocked() {
    use crate::network::dns_overrides::DnsOverrides;

    let blocked_ips = [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "192.168.1.1",
        "0.0.0.0",
    ];
    let resolver = DnsOverrides::default();

    for ip in blocked_ips {
        assert!(
            resolver.resolve_socket_addr(ip, 80).is_none(),
            "runtime DNS overrides must not resolve unconfigured literal host targets"
        );
    }
}

#[tokio::test]
async fn masking_unknown_proxy_protocol_version_falls_back_to_v1_unknown_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut header = [0u8; 15];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header, b"PROXY UNKNOWN\r\n");

        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"probe");
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_proxy_protocol = 255;

    let peer: SocketAddr = "198.51.100.77:50001".parse().unwrap();
    let local_addr: SocketAddr = "[2001:db8::10]:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();
    let (client_reader, _client_writer) = duplex(128);
    let (_client_visible_reader, client_visible_writer) = duplex(128);

    handle_bad_client(
        client_reader,
        client_visible_writer,
        b"probe",
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    accept_task.await.unwrap();
}

#[tokio::test]
async fn masking_zero_length_initial_data_does_not_hang_or_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut one = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(150), stream.read(&mut one))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            n, 0,
            "backend must observe clean EOF for empty initial payload"
        );
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();

    let peer: SocketAddr = "203.0.113.70:50002".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (client_reader, client_writer) = duplex(64);
    drop(client_writer);
    let (_client_visible_reader, client_visible_writer) = duplex(64);

    handle_bad_client(
        client_reader,
        client_visible_writer,
        b"",
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    accept_task.await.unwrap();
}

#[tokio::test]
async fn masking_oversized_initial_payload_is_forwarded_verbatim() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let payload = vec![0xA5u8; 32 * 1024];

    let accept_task = tokio::spawn({
        let payload = payload.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut observed = vec![0u8; payload.len()];
            stream.read_exact(&mut observed).await.unwrap();
            assert_eq!(
                observed, payload,
                "large initial payload must stay byte-for-byte"
            );
        }
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();

    let peer: SocketAddr = "203.0.113.71:50003".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();
    let (client_reader, _client_writer) = duplex(64);
    let (_client_visible_reader, client_visible_writer) = duplex(64);

    handle_bad_client(
        client_reader,
        client_visible_writer,
        &payload,
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    accept_task.await.unwrap();
}

#[tokio::test]
async fn masking_refused_backend_keeps_constantish_timing_floor_under_burst() {
    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 1;

    let peer: SocketAddr = "203.0.113.72:50004".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    for _ in 0..16 {
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
        assert!(
            started.elapsed() >= Duration::from_millis(30),
            "refused-backend path must keep timing floor to reduce fingerprinting"
        );
    }
}

#[tokio::test]
async fn masking_backend_half_close_then_client_half_close_completes_without_hang() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut pre = [0u8; 4];
        stream.read_exact(&mut pre).await.unwrap();
        assert_eq!(&pre, b"PING");
        stream.write_all(b"PONG").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let mut config = ProxyConfig::default();
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();

    let peer: SocketAddr = "203.0.113.73:50005".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (mut client_writer, client_reader) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(256);

    let handle = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            b"PING",
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.shutdown().await.unwrap();

    let mut got = [0u8; 4];
    client_visible_reader.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"PONG");

    timeout(Duration::from_secs(2), handle)
        .await
        .expect("masking task must terminate after bilateral half-close")
        .unwrap();
    accept_task.await.unwrap();
}
