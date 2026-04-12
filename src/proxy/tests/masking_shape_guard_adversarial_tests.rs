use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex, empty, sink};
use tokio::time::{Duration, sleep, timeout};

fn oracle_len(
    total_sent: usize,
    shape_enabled: bool,
    ended_by_eof: bool,
    initial_len: usize,
    floor: usize,
    cap: usize,
) -> usize {
    if shape_enabled && ended_by_eof && initial_len > 0 {
        next_mask_shape_bucket(total_sent, floor, cap)
    } else {
        total_sent
    }
}

async fn run_relay_case(
    initial: Vec<u8>,
    extra: Vec<u8>,
    close_client: bool,
    shape_enabled: bool,
    floor: usize,
    cap: usize,
    above_cap_blur: bool,
    above_cap_blur_max_bytes: usize,
) -> Vec<u8> {
    let (client_reader, mut client_writer) = duplex(8192);
    let (mut mask_observer, mask_writer) = duplex(8192);

    let relay = tokio::spawn(async move {
        relay_to_mask(
            client_reader,
            sink(),
            empty(),
            mask_writer,
            &initial,
            shape_enabled,
            floor,
            cap,
            above_cap_blur,
            above_cap_blur_max_bytes,
            false,
            5 * 1024 * 1024,
            MASK_RELAY_IDLE_TIMEOUT,
        )
        .await;
    });

    if !extra.is_empty() {
        client_writer.write_all(&extra).await.unwrap();
    }

    if close_client {
        client_writer.shutdown().await.unwrap();
    }

    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();

    if !close_client {
        drop(client_writer);
    }

    let mut observed = Vec::new();
    timeout(
        Duration::from_secs(2),
        mask_observer.read_to_end(&mut observed),
    )
    .await
    .unwrap()
    .unwrap();
    observed
}

#[tokio::test]
async fn masking_shape_guard_negative_timeout_path_never_shapes_even_with_blur_enabled() {
    let initial = b"GET /timeout-path HTTP/1.1\r\n".to_vec();
    let extra = vec![0xCC; 700];
    let total = initial.len() + extra.len();

    let observed = run_relay_case(
        initial.clone(),
        extra.clone(),
        false,
        true,
        512,
        4096,
        true,
        1024,
    )
    .await;

    assert_eq!(observed.len(), total, "timeout path must stay unshaped");
    assert_eq!(&observed[..initial.len()], initial.as_slice());
    assert_eq!(&observed[initial.len()..], extra.as_slice());
}

#[tokio::test]
async fn masking_shape_guard_positive_clean_eof_path_shapes_and_preserves_prefix() {
    let initial = b"GET /ok HTTP/1.1\r\n".to_vec();
    let extra = vec![0x55; 300];
    let total = initial.len() + extra.len();

    let observed = run_relay_case(
        initial.clone(),
        extra.clone(),
        true,
        true,
        512,
        4096,
        false,
        0,
    )
    .await;

    let expected_len = oracle_len(total, true, true, initial.len(), 512, 4096);
    assert_eq!(
        observed.len(),
        expected_len,
        "clean EOF path must be bucket-shaped"
    );
    assert_eq!(&observed[..initial.len()], initial.as_slice());
    assert_eq!(
        &observed[initial.len()..(initial.len() + extra.len())],
        extra.as_slice()
    );
}

#[tokio::test]
async fn masking_shape_guard_edge_empty_initial_remains_transparent_under_clean_eof() {
    let initial = Vec::new();
    let extra = vec![0xA1; 257];

    let observed = run_relay_case(initial, extra.clone(), true, true, 512, 4096, false, 0).await;

    assert_eq!(
        observed.len(),
        extra.len(),
        "empty initial_data must never trigger shaping"
    );
    assert_eq!(observed, extra);
}

#[tokio::test]
async fn masking_shape_guard_light_fuzz_oracle_matches_for_eof_and_timeout_variants() {
    let floor = 512usize;
    let cap = 4096usize;

    // Deterministic xorshift to keep this fuzz test stable in CI.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..96 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let initial_len = (s as usize) % 48;

        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let extra_len = (s as usize) % 1800;

        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let close_client = (s & 1) == 0;

        let initial = vec![0x42; initial_len];
        let extra = vec![0x99; extra_len];
        let total = initial_len + extra_len;

        let observed = run_relay_case(
            initial.clone(),
            extra.clone(),
            close_client,
            true,
            floor,
            cap,
            false,
            0,
        )
        .await;

        let expected = oracle_len(total, true, close_client, initial_len, floor, cap);
        assert_eq!(
            observed.len(),
            expected,
            "oracle mismatch: initial_len={initial_len} extra_len={extra_len} close_client={close_client}"
        );

        if initial_len > 0 {
            assert_eq!(&observed[..initial_len], initial.as_slice());
        }
        if extra_len > 0 {
            assert_eq!(
                &observed[initial_len..(initial_len + extra_len)],
                extra.as_slice(),
                "payload prefix must remain byte-for-byte before any optional shaping tail"
            );
        }
    }
}

#[tokio::test]
async fn masking_shape_guard_stress_parallel_mixed_sessions_keep_oracle_and_no_hangs() {
    let mut tasks = Vec::new();

    for i in 0..48usize {
        tasks.push(tokio::spawn(async move {
            let initial_len = if i % 3 == 0 { 0 } else { 5 + (i % 19) };
            let extra_len = 64 + (i * 37 % 1300);
            let close_client = i % 2 == 0;

            let initial = vec![i as u8; initial_len];
            let extra = vec![0xE0 | ((i as u8) & 0x0F); extra_len];
            let total = initial_len + extra_len;

            let observed = run_relay_case(
                initial.clone(),
                extra.clone(),
                close_client,
                true,
                512,
                4096,
                false,
                0,
            )
            .await;

            let expected = oracle_len(total, true, close_client, initial_len, 512, 4096);
            assert_eq!(
                observed.len(),
                expected,
                "stress oracle mismatch for worker={i} close_client={close_client}"
            );

            if initial_len > 0 {
                assert_eq!(&observed[..initial_len], initial.as_slice());
            }
            if extra_len > 0 {
                assert_eq!(
                    &observed[initial_len..(initial_len + extra_len)],
                    extra.as_slice()
                );
            }
        }));
    }

    for task in tasks {
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn masking_shape_guard_integration_slow_drip_timeout_is_cut_without_tail_leak() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let initial = b"GET /drip-guard HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let initial = initial.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut observed = vec![0u8; initial.len()];
            stream.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed, initial);

            let mut one = [0u8; 1];
            let r = timeout(Duration::from_millis(220), stream.read_exact(&mut one)).await;
            assert!(
                r.is_err() || r.unwrap().is_err(),
                "no post-timeout drip/tail may reach backend"
            );
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;

    let peer: SocketAddr = "198.51.100.245:53101".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (mut client_writer, client_reader) = duplex(1024);
    let (_client_visible_reader, client_visible_writer) = duplex(1024);
    let beobachten = BeobachtenStore::new();

    let relay = tokio::spawn(async move {
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

    sleep(Duration::from_millis(160)).await;
    let _ = client_writer.write_all(b"X").await;

    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn masking_shape_guard_above_cap_blur_statistical_quality_and_bounds() {
    let base_len = 5005usize; // 5-byte header + 5000 payload
    let max_extra = 64usize;
    let mut extras = Vec::new();

    for _ in 0..192 {
        let observed = run_relay_case(
            vec![0x16, 0x03, 0x01, 0x1B, 0x58],
            vec![0xAA; 5000],
            true,
            true,
            512,
            4096,
            true,
            max_extra,
        )
        .await;

        assert!(
            observed.len() >= base_len && observed.len() <= base_len + max_extra,
            "above-cap blur length must stay in bounded window"
        );
        extras.push(observed.len() - base_len);
    }

    let unique: std::collections::BTreeSet<_> = extras.iter().copied().collect();
    let mean = extras.iter().copied().sum::<usize>() as f64 / extras.len() as f64;

    // For uniform [0..=64], mean is ~32. Keep wide bounds to avoid CI flakiness.
    assert!(
        (20.0..=44.0).contains(&mean),
        "blur mean drifted too far from expected center, mean={mean:.2}"
    );
    assert!(
        unique.len() >= 16,
        "blur distribution appears too low-entropy, unique_extras={}",
        unique.len()
    );
}

#[tokio::test]
async fn masking_shape_guard_above_cap_blur_parallel_stress_keeps_bounds() {
    let max_extra = 96usize;
    let mut tasks = Vec::new();

    for i in 0..64usize {
        tasks.push(tokio::spawn(async move {
            let body_len = 4500 + (i % 256);
            let base_len = 5 + body_len;

            let observed = run_relay_case(
                vec![0x16, 0x03, 0x01, 0x1B, 0x58],
                vec![0xA0 | ((i as u8) & 0x0F); body_len],
                true,
                true,
                512,
                4096,
                true,
                max_extra,
            )
            .await;

            assert!(
                observed.len() >= base_len && observed.len() <= base_len + max_extra,
                "parallel blur bounds violated for worker={i}: observed_len={} base_len={} max_extra={}",
                observed.len(),
                base_len,
                max_extra
            );
        }));
    }

    for task in tasks {
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn masking_shape_guard_above_cap_blur_disabled_keeps_exact_length_even_on_clean_eof() {
    let initial = vec![0x16, 0x03, 0x01, 0x1B, 0x58];
    let body = vec![0x77; 5200];
    let expected = initial.len() + body.len();

    let observed = run_relay_case(initial, body, true, true, 512, 4096, false, 0).await;
    assert_eq!(
        observed.len(),
        expected,
        "without above-cap blur the output must remain exact even on clean EOF"
    );
}
