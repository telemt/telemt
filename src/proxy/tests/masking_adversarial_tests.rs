use super::*;
use crate::config::ProxyConfig;
use crate::proxy::relay::relay_bidirectional;
use crate::stats::Stats;
use crate::stats::beobachten::BeobachtenStore;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

// ------------------------------------------------------------------
// Probing Indistinguishability (OWASP ASVS 5.1.7)
// ------------------------------------------------------------------

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
    use crate::network::dns_overrides::resolve_socket_addr;

    let blocked_ips = [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "192.168.1.1",
        "0.0.0.0",
    ];

    for ip in blocked_ips {
        assert!(
            resolve_socket_addr(ip, 80).is_none(),
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
