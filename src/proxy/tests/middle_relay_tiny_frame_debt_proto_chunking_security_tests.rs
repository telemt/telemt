use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, PooledBuffer};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWriteExt, duplex};
use tokio::time::{Duration as TokioDuration, sleep};

fn make_crypto_reader<T>(reader: T) -> CryptoReader<T>
where
    T: AsyncRead + Unpin + Send + 'static,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

fn make_forensics(conn_id: u64, started_at: Instant) -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 0xB300_0000 + conn_id,
        conn_id,
        user: format!("tiny-frame-debt-proto-chunk-user-{conn_id}"),
        peer: "127.0.0.1:50000".parse().expect("peer parse must succeed"),
        peer_hash: hash_ip("127.0.0.1".parse().expect("ip parse must succeed")),
        started_at,
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

fn make_enabled_idle_policy() -> RelayClientIdlePolicy {
    RelayClientIdlePolicy {
        enabled: true,
        soft_idle: Duration::from_millis(50),
        hard_idle: Duration::from_millis(120),
        grace_after_downstream_activity: Duration::from_secs(0),
        legacy_frame_read_timeout: Duration::from_millis(50),
    }
}

fn append_tiny_frame(plaintext: &mut Vec<u8>, proto: ProtoTag) {
    match proto {
        ProtoTag::Abridged => plaintext.push(0x00),
        ProtoTag::Intermediate | ProtoTag::Secure => {
            plaintext.extend_from_slice(&0u32.to_le_bytes())
        }
    }
}

fn append_real_frame(plaintext: &mut Vec<u8>, proto: ProtoTag, payload: [u8; 4]) {
    match proto {
        ProtoTag::Abridged => {
            plaintext.push(0x01);
            plaintext.extend_from_slice(&payload);
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            plaintext.extend_from_slice(&4u32.to_le_bytes());
            plaintext.extend_from_slice(&payload);
        }
    }
}

async fn write_chunked_with_jitter(
    writer: &mut tokio::io::DuplexStream,
    bytes: &[u8],
    mut seed: u64,
) {
    let mut offset = 0usize;
    while offset < bytes.len() {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let chunk_len = 1 + ((seed as usize) & 0x1f);
        let end = (offset + chunk_len).min(bytes.len());
        writer.write_all(&bytes[offset..end]).await.unwrap();

        let delay_ms = ((seed >> 16) % 3) as u64;
        if delay_ms > 0 {
            sleep(TokioDuration::from_millis(delay_ms)).await;
        }
        offset = end;
    }
}

async fn read_once_with_state(
    crypto_reader: &mut CryptoReader<tokio::io::DuplexStream>,
    proto: ProtoTag,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    idle_state: &mut RelayClientIdleState,
) -> Result<Option<(PooledBuffer, bool)>> {
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);
    read_client_payload_with_idle_policy(
        crypto_reader,
        proto,
        1024,
        &buffer_pool,
        forensics,
        frame_counter,
        &stats,
        &idle_policy,
        idle_state,
        &last_downstream_activity_ms,
        forensics.started_at,
    )
    .await
}

fn is_fail_closed_outcome(result: &Result<Option<(PooledBuffer, bool)>>) -> bool {
    matches!(result, Err(ProxyError::Proxy(_)))
        || matches!(result, Err(ProxyError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut)
}

#[tokio::test]
async fn intermediate_chunked_zero_flood_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let started = Instant::now();
    let forensics = make_forensics(6101, started);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(started);

    let mut plaintext = Vec::with_capacity(4 * 256);
    for _ in 0..256 {
        append_tiny_frame(&mut plaintext, ProtoTag::Intermediate);
    }
    let encrypted = encrypt_for_reader(&plaintext);
    write_chunked_with_jitter(&mut writer, &encrypted, 0x1111_2222).await;
    drop(writer);

    let result = run_relay_test_step_timeout(
        "intermediate flood read",
        read_once_with_state(
            &mut crypto_reader,
            ProtoTag::Intermediate,
            &forensics,
            &mut frame_counter,
            &mut idle_state,
        ),
    )
    .await;

    assert!(
        is_fail_closed_outcome(&result),
        "zero-length flood must fail closed via debt guard or idle timeout"
    );
    assert_eq!(frame_counter, 0);
}

#[tokio::test]
async fn secure_chunked_zero_flood_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let started = Instant::now();
    let forensics = make_forensics(6102, started);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(started);

    let mut plaintext = Vec::with_capacity(4 * 256);
    for _ in 0..256 {
        append_tiny_frame(&mut plaintext, ProtoTag::Secure);
    }
    let encrypted = encrypt_for_reader(&plaintext);
    write_chunked_with_jitter(&mut writer, &encrypted, 0x3333_4444).await;
    drop(writer);

    let result = run_relay_test_step_timeout(
        "secure flood read",
        read_once_with_state(
            &mut crypto_reader,
            ProtoTag::Secure,
            &forensics,
            &mut frame_counter,
            &mut idle_state,
        ),
    )
    .await;

    assert!(
        is_fail_closed_outcome(&result),
        "secure zero-length flood must fail closed via debt guard or idle timeout"
    );
    assert_eq!(frame_counter, 0);
}

#[tokio::test]
async fn intermediate_chunked_alternating_attack_closes_before_eof() {
    let (reader, mut writer) = duplex(8192);
    let mut crypto_reader = make_crypto_reader(reader);
    let started = Instant::now();
    let forensics = make_forensics(6103, started);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(started);

    let mut plaintext = Vec::with_capacity(8 * 200);
    for n in 0..180u8 {
        append_tiny_frame(&mut plaintext, ProtoTag::Intermediate);
        append_real_frame(
            &mut plaintext,
            ProtoTag::Intermediate,
            [n, n ^ 1, n ^ 2, n ^ 3],
        );
    }
    let encrypted = encrypt_for_reader(&plaintext);

    let writer_task = tokio::spawn(async move {
        write_chunked_with_jitter(&mut writer, &encrypted, 0x5555_6666).await;
        drop(writer);
    });

    let mut closed = false;
    for _ in 0..240 {
        let step = run_relay_test_step_timeout(
            "intermediate alternating read step",
            read_once_with_state(
                &mut crypto_reader,
                ProtoTag::Intermediate,
                &forensics,
                &mut frame_counter,
                &mut idle_state,
            ),
        )
        .await;

        match step {
            Ok(Some(_)) => {}
            Err(ProxyError::Proxy(_)) => {
                closed = true;
                break;
            }
            Ok(None) => break,
            Err(other) => panic!("unexpected intermediate alternating error: {other}"),
        }
    }

    writer_task
        .await
        .expect("intermediate writer task must not panic");
    assert!(closed, "intermediate alternating attack must fail closed");
}

#[tokio::test]
async fn secure_chunked_alternating_attack_closes_before_eof() {
    let (reader, mut writer) = duplex(8192);
    let mut crypto_reader = make_crypto_reader(reader);
    let started = Instant::now();
    let forensics = make_forensics(6104, started);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(started);

    let mut plaintext = Vec::with_capacity(8 * 200);
    for n in 0..180u8 {
        append_tiny_frame(&mut plaintext, ProtoTag::Secure);
        append_real_frame(&mut plaintext, ProtoTag::Secure, [n, n ^ 7, n ^ 11, n ^ 19]);
    }
    let encrypted = encrypt_for_reader(&plaintext);

    let writer_task = tokio::spawn(async move {
        write_chunked_with_jitter(&mut writer, &encrypted, 0x7777_8888).await;
        drop(writer);
    });

    let mut closed = false;
    for _ in 0..240 {
        let step = run_relay_test_step_timeout(
            "secure alternating read step",
            read_once_with_state(
                &mut crypto_reader,
                ProtoTag::Secure,
                &forensics,
                &mut frame_counter,
                &mut idle_state,
            ),
        )
        .await;

        match step {
            Ok(Some(_)) => {}
            Err(ProxyError::Proxy(_)) => {
                closed = true;
                break;
            }
            Ok(None) => break,
            Err(other) => panic!("unexpected secure alternating error: {other}"),
        }
    }

    writer_task
        .await
        .expect("secure writer task must not panic");
    assert!(closed, "secure alternating attack must fail closed");
}

#[tokio::test]
async fn intermediate_chunked_safe_small_burst_still_returns_real_frame() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let started = Instant::now();
    let forensics = make_forensics(6105, started);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(started);

    let payload = [9u8, 8, 7, 6];
    let mut plaintext = Vec::new();
    for _ in 0..7 {
        append_tiny_frame(&mut plaintext, ProtoTag::Intermediate);
    }
    append_real_frame(&mut plaintext, ProtoTag::Intermediate, payload);
    let encrypted = encrypt_for_reader(&plaintext);
    write_chunked_with_jitter(&mut writer, &encrypted, 0xAAAA_BBBB).await;

    let result = read_once_with_state(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        &forensics,
        &mut frame_counter,
        &mut idle_state,
    )
    .await
    .expect("intermediate safe burst should parse")
    .expect("intermediate safe burst should return a frame");

    assert_eq!(result.0.as_ref(), &payload);
    assert_eq!(frame_counter, 1);
}

#[tokio::test]
async fn secure_chunked_safe_small_burst_still_returns_real_frame() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let started = Instant::now();
    let forensics = make_forensics(6106, started);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(started);

    let payload = [3u8, 1, 4, 1];
    let mut plaintext = Vec::new();
    for _ in 0..7 {
        append_tiny_frame(&mut plaintext, ProtoTag::Secure);
    }
    append_real_frame(&mut plaintext, ProtoTag::Secure, payload);
    let encrypted = encrypt_for_reader(&plaintext);
    write_chunked_with_jitter(&mut writer, &encrypted, 0xCCCC_DDDD).await;

    let result = read_once_with_state(
        &mut crypto_reader,
        ProtoTag::Secure,
        &forensics,
        &mut frame_counter,
        &mut idle_state,
    )
    .await
    .expect("secure safe burst should parse")
    .expect("secure safe burst should return a frame");

    assert_eq!(result.0.as_ref(), &payload);
    assert_eq!(frame_counter, 1);
}

#[tokio::test]
async fn light_fuzz_proto_chunking_outcomes_are_bounded() {
    let mut seed = 0xDEAD_BEEF_2026_0322u64;

    for case in 0..48u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let proto = if (seed & 1) == 0 {
            ProtoTag::Intermediate
        } else {
            ProtoTag::Secure
        };

        let (reader, mut writer) = duplex(8192);
        let mut crypto_reader = make_crypto_reader(reader);
        let started = Instant::now();
        let forensics = make_forensics(6200 + case, started);
        let mut frame_counter = 0u64;
        let mut idle_state = RelayClientIdleState::new(started);

        let mut stream = Vec::new();
        let mut local_seed = seed ^ case;
        for _ in 0..220 {
            local_seed ^= local_seed << 7;
            local_seed ^= local_seed >> 9;
            local_seed ^= local_seed << 8;
            if (local_seed & 1) == 0 {
                append_tiny_frame(&mut stream, proto);
            } else {
                let b = (local_seed >> 8) as u8;
                append_real_frame(&mut stream, proto, [b, b ^ 0x12, b ^ 0x24, b ^ 0x48]);
            }
        }

        let encrypted = encrypt_for_reader(&stream);
        write_chunked_with_jitter(&mut writer, &encrypted, seed ^ 0x1234_5678).await;
        drop(writer);

        for _ in 0..260 {
            let step = run_relay_test_step_timeout(
                "fuzz proto read step",
                read_once_with_state(
                    &mut crypto_reader,
                    proto,
                    &forensics,
                    &mut frame_counter,
                    &mut idle_state,
                ),
            )
            .await;

            match step {
                Ok(Some((_payload, _))) => {}
                Err(ProxyError::Proxy(_)) => break,
                Err(ProxyError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Ok(None) => break,
                Err(other) => panic!("unexpected proto chunking fuzz error: {other}"),
            }
        }
    }
}
