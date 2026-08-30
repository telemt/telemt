use super::*;

#[tokio::test]
async fn idle_policy_enabled_intermediate_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(11, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0u8; 4 * 256];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer.write_all(&flood_encrypted).await.unwrap();
    drop(writer);

    let result = read_bounded(
        &mut crypto_reader,
        ProtoTag::Intermediate,
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

    assert!(matches!(result, Err(ProxyError::Proxy(_))));
}

#[tokio::test]
async fn idle_policy_enabled_secure_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(12, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0u8; 4 * 256];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer.write_all(&flood_encrypted).await.unwrap();
    drop(writer);

    let result = read_bounded(
        &mut crypto_reader,
        ProtoTag::Secure,
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

    assert!(matches!(result, Err(ProxyError::Proxy(_))));
}

#[tokio::test]
async fn intermediate_alternating_zero_and_real_eventually_closes() {
    let (reader, mut writer) = duplex(8192);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(13, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(3000);
    for idx in 0..160u8 {
        plaintext.extend_from_slice(&0u32.to_le_bytes());
        plaintext.extend_from_slice(&4u32.to_le_bytes());
        plaintext.extend_from_slice(&[idx, idx ^ 0x11, idx ^ 0x22, idx ^ 0x33]);
    }
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();
    drop(writer);

    let mut closed = false;
    for _ in 0..220 {
        let result = read_bounded(
            &mut crypto_reader,
            ProtoTag::Intermediate,
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

        match result {
            Ok(Some(_)) => {}
            Err(ProxyError::Proxy(_)) => {
                closed = true;
                break;
            }
            Ok(None) => break,
            Err(other) => panic!("unexpected error while probing alternating close: {other}"),
        }
    }

    assert!(closed, "intermediate alternating attack must fail closed");
}

#[tokio::test]
async fn small_tiny_burst_followed_by_real_frame_does_not_spuriously_close() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(14, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(64);
    for _ in 0..8 {
        plaintext.push(0x00);
    }
    plaintext.push(0x01);
    plaintext.extend_from_slice(&[1, 2, 3, 4]);

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let first = read_bounded(
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

    match first {
        Ok(Some((payload, _))) => assert_eq!(payload.as_ref(), &[1, 2, 3, 4]),
        Err(e) => panic!("unexpected close after small tiny burst: {e}"),
        Ok(None) => panic!("unexpected EOF before real frame"),
    }
}

#[tokio::test]
async fn idle_policy_enabled_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(1, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0u8; 1024];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer
        .write_all(&flood_encrypted)
        .await
        .expect("zero-length flood bytes must be writable");
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
        "idle policy enabled must fail closed for pure zero-length flood"
    );
}

#[tokio::test]
async fn idle_policy_enabled_alternating_tiny_real_eventually_closes() {
    let (reader, mut writer) = duplex(8192);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(2, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(256 * 6);
    for idx in 0..=255u8 {
        plaintext.push(0x00);
        plaintext.push(0x01);
        plaintext.extend_from_slice(&[idx, idx ^ 0x55, idx ^ 0xAA, 0x11]);
    }

    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted)
        .await
        .expect("alternating flood bytes must be writable");
    drop(writer);

    let mut saw_proxy_close = false;
    for _ in 0..300 {
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

        match result {
            Ok(Some((_payload, _quickack))) => {}
            Err(ProxyError::Proxy(_)) => {
                saw_proxy_close = true;
                break;
            }
            Err(ProxyError::Io(e)) => panic!("unexpected IO error before close: {e}"),
            Ok(None) => panic!("unexpected EOF before debt-based closure"),
            Err(other) => panic!("unexpected error before close: {other}"),
        }
    }

    assert!(
        saw_proxy_close,
        "alternating tiny/real sequence must eventually fail closed"
    );
}

#[tokio::test]
async fn enabled_idle_policy_valid_nonzero_frame_still_passes() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(3, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let payload = [7u8, 8, 9, 10];
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(0x01);
    plaintext.extend_from_slice(&payload);

    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted)
        .await
        .expect("nonzero frame must be writable");

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
    .await
    .expect("valid frame should decode")
    .expect("valid frame should return payload");

    assert_eq!(result.0.as_ref(), &payload);
    assert!(!result.1);
    assert_eq!(frame_counter, 1);
}
