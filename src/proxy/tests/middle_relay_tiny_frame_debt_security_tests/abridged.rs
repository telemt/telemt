use super::*;

#[tokio::test]
async fn abridged_quickack_tiny_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(21, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0x80u8; 256];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer.write_all(&flood_encrypted).await.unwrap();
    drop(writer);

    let result = read_bounded(
        &mut crypto_reader,
        ProtoTag::Abridged,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Proxy(_))),
        "quickack-marked zero-length flood must fail closed"
    );
}

#[tokio::test]
async fn abridged_extended_zero_len_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(22, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut flood_plaintext = Vec::with_capacity(4 * 256);
    for _ in 0..256 {
        flood_plaintext.extend_from_slice(&[0x7f, 0x00, 0x00, 0x00]);
    }
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer.write_all(&flood_encrypted).await.unwrap();
    drop(writer);

    let result = read_bounded(
        &mut crypto_reader,
        ProtoTag::Abridged,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Proxy(_))),
        "extended zero-length abridged flood must fail closed"
    );
}

#[tokio::test]
async fn one_to_eight_abridged_wire_pattern_survives_without_false_positive_close() {
    let mut plaintext = Vec::with_capacity(9 * 300);
    for idx in 0..300usize {
        plaintext.push(0x00);
        for _ in 0..8 {
            let b = idx as u8;
            plaintext.push(0x01);
            plaintext.extend_from_slice(&[b, b ^ 0x11, b ^ 0x22, b ^ 0x33]);
        }
    }

    // Keep the test single-task and deterministic: make duplex capacity larger than the
    // generated ciphertext so write_all cannot block waiting for a concurrent reader.
    let duplex_capacity = plaintext.len().saturating_add(1024);
    let (reader, mut writer) = duplex(duplex_capacity);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(23, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();
    drop(writer);

    let mut closed = false;
    for _ in 0..3000 {
        match read_bounded(
            &mut crypto_reader,
            ProtoTag::Abridged,
            &buffer_pool,
            &forensics,
            &mut frame_counter,
            &stats,
            &idle_policy,
            &mut idle_state,
            &last_downstream_activity_ms,
            session_started_at,
        )
        .await
        {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(ProxyError::Proxy(_)) => {
                closed = true;
                break;
            }
            Err(other) => panic!("unexpected error in 1:8 wire test: {other}"),
        }
    }

    assert!(
        !closed,
        "wire-level 1:8 tiny-to-real pattern should not trigger debt close"
    );
}

#[tokio::test]
async fn deterministic_light_fuzz_abridged_wire_behavior_matches_model() {
    let mut seed = 0xD1CE_BAAD_2026_0322u64;

    for case_idx in 0..32u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let events = 300 + ((seed as usize) & 0xff);
        let mut pattern = Vec::with_capacity(events);
        let mut local = seed;
        for _ in 0..events {
            local ^= local << 7;
            local ^= local >> 9;
            local ^= local << 8;
            pattern.push((local & 0x03) == 0);
        }

        let mut plaintext = Vec::with_capacity(events * 6);
        for (idx, tiny) in pattern.iter().copied().enumerate() {
            if tiny {
                plaintext.push(0x00);
            } else {
                let b = (idx as u8) ^ (case_idx as u8);
                plaintext.push(0x01);
                plaintext.extend_from_slice(&[b, b ^ 0x1F, b ^ 0x7A, b ^ 0xC3]);
            }
        }

        let (reader, mut writer) = duplex(16 * 1024);
        let mut crypto_reader = make_crypto_reader(reader);
        let buffer_pool = Arc::new(BufferPool::new());
        let stats = Stats::new();
        let session_started_at = Instant::now();
        let forensics = make_forensics(500 + case_idx, session_started_at);
        let mut frame_counter = 0u64;
        let mut idle_state = RelayClientIdleState::new(session_started_at);
        let idle_policy = make_enabled_idle_policy();
        let last_downstream_activity_ms = AtomicU64::new(0);

        writer
            .write_all(&encrypt_for_reader(&plaintext))
            .await
            .unwrap();
        drop(writer);

        let (expected_close, _, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
        let mut observed_close = false;

        for _ in 0..(events + 8) {
            match read_bounded(
                &mut crypto_reader,
                ProtoTag::Abridged,
                &buffer_pool,
                &forensics,
                &mut frame_counter,
                &stats,
                &idle_policy,
                &mut idle_state,
                &last_downstream_activity_ms,
                session_started_at,
            )
            .await
            {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(ProxyError::Proxy(_)) => {
                    observed_close = true;
                    break;
                }
                Err(other) => panic!("unexpected fuzz error: {other}"),
            }
        }

        assert_eq!(
            observed_close,
            expected_close.is_some(),
            "wire parser behavior must match debt model for case {case_idx}"
        );
    }
}
