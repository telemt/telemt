use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWriteExt, duplex};
use tokio::task::JoinSet;
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
        trace_id: 0xB200_0000 + conn_id,
        conn_id,
        user: format!("tiny-frame-debt-concurrency-user-{conn_id}"),
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

async fn read_once(
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_pure_tiny_floods_all_fail_closed() {
    let mut set = JoinSet::new();

    for idx in 0..32u64 {
        set.spawn(async move {
            let (reader, mut writer) = duplex(4096);
            let mut crypto_reader = make_crypto_reader(reader);
            let started = Instant::now();
            let forensics = make_forensics(1000 + idx, started);
            let mut frame_counter = 0u64;
            let mut idle_state = RelayClientIdleState::new(started);

            let flood_plaintext = vec![0u8; 1024];
            let flood_encrypted = encrypt_for_reader(&flood_plaintext);
            writer.write_all(&flood_encrypted).await.unwrap();
            drop(writer);

            let result = run_relay_test_step_timeout(
                "tiny flood task",
                read_once(
                    &mut crypto_reader,
                    ProtoTag::Abridged,
                    &forensics,
                    &mut frame_counter,
                    &mut idle_state,
                ),
            )
            .await;

            assert!(matches!(result, Err(ProxyError::Proxy(_))));
            assert_eq!(frame_counter, 0);
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("parallel tiny flood worker must not panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_benign_tiny_burst_then_real_all_pass() {
    let mut set = JoinSet::new();

    for idx in 0..24u64 {
        set.spawn(async move {
            let (reader, mut writer) = duplex(2048);
            let mut crypto_reader = make_crypto_reader(reader);
            let started = Instant::now();
            let forensics = make_forensics(2000 + idx, started);
            let mut frame_counter = 0u64;
            let mut idle_state = RelayClientIdleState::new(started);

            let payload = [idx as u8, 2, 3, 4];
            let mut plaintext = Vec::with_capacity(20);
            for _ in 0..6 {
                plaintext.push(0x00);
            }
            plaintext.push(0x01);
            plaintext.extend_from_slice(&payload);
            let encrypted = encrypt_for_reader(&plaintext);
            writer.write_all(&encrypted).await.unwrap();

            let result = run_relay_test_step_timeout(
                "benign tiny burst read",
                read_once(
                    &mut crypto_reader,
                    ProtoTag::Abridged,
                    &forensics,
                    &mut frame_counter,
                    &mut idle_state,
                ),
            )
            .await
            .expect("benign payload must parse")
            .expect("benign payload must return frame");

            assert_eq!(result.0.as_ref(), &payload);
            assert_eq!(frame_counter, 1);
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("parallel benign worker must not panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_lockstep_alternating_attack_under_jitter_closes() {
    let mut set = JoinSet::new();

    for idx in 0..12u64 {
        set.spawn(async move {
            let (reader, mut writer) = duplex(8192);
            let mut crypto_reader = make_crypto_reader(reader);
            let started = Instant::now();
            let forensics = make_forensics(3000 + idx, started);
            let mut frame_counter = 0u64;
            let mut idle_state = RelayClientIdleState::new(started);

            let mut plaintext = Vec::with_capacity(2000);
            for n in 0..180u8 {
                plaintext.push(0x00);
                plaintext.push(0x01);
                plaintext.extend_from_slice(&[n, n ^ 0x21, n ^ 0x42, n ^ 0x84]);
            }
            let encrypted = encrypt_for_reader(&plaintext);

            let writer_task = tokio::spawn(async move {
                for chunk in encrypted.chunks(17) {
                    writer.write_all(chunk).await.unwrap();
                    sleep(TokioDuration::from_millis(1)).await;
                }
                drop(writer);
            });

            let mut closed = false;
            for _ in 0..220 {
                let result = run_relay_test_step_timeout(
                    "alternating jitter read step",
                    read_once(
                        &mut crypto_reader,
                        ProtoTag::Abridged,
                        &forensics,
                        &mut frame_counter,
                        &mut idle_state,
                    ),
                )
                .await;

                match result {
                    Ok(Some((_payload, _))) => {}
                    Err(ProxyError::Proxy(_)) => {
                        closed = true;
                        break;
                    }
                    Ok(None) => break,
                    Err(other) => panic!("unexpected error in alternating jitter case: {other}"),
                }
            }

            writer_task
                .await
                .expect("writer jitter task must not panic");
            assert!(closed, "alternating attack must close before EOF");
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("alternating jitter worker must not panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_mixed_population_attackers_close_benign_survive() {
    let mut set = JoinSet::new();

    for idx in 0..20u64 {
        set.spawn(async move {
            let (reader, mut writer) = duplex(4096);
            let mut crypto_reader = make_crypto_reader(reader);
            let started = Instant::now();
            let forensics = make_forensics(4000 + idx, started);
            let mut frame_counter = 0u64;
            let mut idle_state = RelayClientIdleState::new(started);

            if idx % 2 == 0 {
                let mut plaintext = Vec::with_capacity(1280);
                for n in 0..140u8 {
                    plaintext.push(0x00);
                    plaintext.push(0x01);
                    plaintext.extend_from_slice(&[n, n, n, n]);
                }
                writer
                    .write_all(&encrypt_for_reader(&plaintext))
                    .await
                    .unwrap();
                drop(writer);

                let mut closed = false;
                for _ in 0..200 {
                    match read_once(
                        &mut crypto_reader,
                        ProtoTag::Abridged,
                        &forensics,
                        &mut frame_counter,
                        &mut idle_state,
                    )
                    .await
                    {
                        Ok(Some(_)) => {}
                        Err(ProxyError::Proxy(_)) => {
                            closed = true;
                            break;
                        }
                        Ok(None) => break,
                        Err(other) => panic!("unexpected attacker error: {other}"),
                    }
                }
                assert!(closed, "attacker session must fail closed");
            } else {
                let payload = [1u8, 9, 8, 7];
                let mut plaintext = Vec::new();
                for _ in 0..4 {
                    plaintext.push(0x00);
                }
                plaintext.push(0x01);
                plaintext.extend_from_slice(&payload);
                writer
                    .write_all(&encrypt_for_reader(&plaintext))
                    .await
                    .unwrap();

                let got = read_once(
                    &mut crypto_reader,
                    ProtoTag::Abridged,
                    &forensics,
                    &mut frame_counter,
                    &mut idle_state,
                )
                .await
                .expect("benign session must parse")
                .expect("benign session must return a frame");
                assert_eq!(got.0.as_ref(), &payload);
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("mixed-population worker must not panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_parallel_patterns_no_hang_or_panic() {
    let mut set = JoinSet::new();

    for case in 0..40u64 {
        set.spawn(async move {
            let (reader, mut writer) = duplex(8192);
            let mut crypto_reader = make_crypto_reader(reader);
            let started = Instant::now();
            let forensics = make_forensics(5000 + case, started);
            let mut frame_counter = 0u64;
            let mut idle_state = RelayClientIdleState::new(started);

            let mut seed = 0x9E37_79B9u64 ^ (case << 8);
            let mut plaintext = Vec::with_capacity(2048);
            for _ in 0..256 {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                let is_tiny = (seed & 1) == 0;
                if is_tiny {
                    plaintext.push(0x00);
                } else {
                    plaintext.push(0x01);
                    plaintext.extend_from_slice(&[(seed >> 8) as u8, 2, 3, 4]);
                }
            }

            writer
                .write_all(&encrypt_for_reader(&plaintext))
                .await
                .unwrap();
            drop(writer);

            for _ in 0..320 {
                let step = run_relay_test_step_timeout(
                    "fuzz case read step",
                    read_once(
                        &mut crypto_reader,
                        ProtoTag::Abridged,
                        &forensics,
                        &mut frame_counter,
                        &mut idle_state,
                    ),
                )
                .await;

                match step {
                    Ok(Some(_)) => {}
                    Err(ProxyError::Proxy(_)) => break,
                    Ok(None) => break,
                    Err(other) => panic!("unexpected fuzz case error: {other}"),
                }
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("fuzz worker must not panic");
    }
}
