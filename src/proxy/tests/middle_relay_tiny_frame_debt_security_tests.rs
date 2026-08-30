use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWriteExt, duplex};

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
        trace_id: 0xB100_0000 + conn_id,
        conn_id,
        user: format!("tiny-frame-debt-user-{conn_id}"),
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

async fn read_bounded(
    crypto_reader: &mut CryptoReader<tokio::io::DuplexStream>,
    proto_tag: ProtoTag,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
    idle_policy: &RelayClientIdlePolicy,
    idle_state: &mut RelayClientIdleState,
    last_downstream_activity_ms: &AtomicU64,
    session_started_at: Instant,
) -> Result<Option<(PooledBuffer, bool)>> {
    run_relay_test_step_timeout(
        "tiny-frame debt read step",
        read_client_payload_with_idle_policy(
            crypto_reader,
            proto_tag,
            1024,
            buffer_pool,
            forensics,
            frame_counter,
            stats,
            idle_policy,
            idle_state,
            last_downstream_activity_ms,
            session_started_at,
        ),
    )
    .await
}

fn simulate_tiny_debt_pattern(pattern: &[bool], max_steps: usize) -> (Option<usize>, u32, usize) {
    let mut debt = 0u32;
    let mut reals = 0usize;
    for (idx, is_tiny) in pattern.iter().copied().take(max_steps).enumerate() {
        if is_tiny {
            debt = debt.saturating_add(TINY_FRAME_DEBT_PER_TINY);
            if debt >= TINY_FRAME_DEBT_LIMIT {
                return (Some(idx + 1), debt, reals);
            }
        } else {
            reals = reals.saturating_add(1);
            debt = debt.saturating_sub(1);
        }
    }
    (None, debt, reals)
}

// Pure tiny-frame debt model invariants.
#[path = "middle_relay_tiny_frame_debt_security_tests/model.rs"]
mod model;
// Intermediate and secure transport debt behavior.
#[path = "middle_relay_tiny_frame_debt_security_tests/transport.rs"]
mod transport;
// Abridged framing debt behavior.
#[path = "middle_relay_tiny_frame_debt_security_tests/abridged.rs"]
mod abridged;
