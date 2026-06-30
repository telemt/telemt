use std::collections::BTreeSet;
#[cfg(test)]
use std::collections::hash_map::DefaultHasher;
#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::hash::Hasher;
use std::hash::{BuildHasher, Hash};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::config::{ConntrackPressureProfile, ProxyConfig};
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{secure_padding_len, *};
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::route_mode::{
    RelayRouteMode, RouteCutoverState, affected_cutover_state, cutover_stagger_delay,
};
use crate::proxy::shared_state::{
    ConntrackCloseEvent, ConntrackClosePublishResult, ConntrackCloseReason, ProxySharedState,
};
use crate::proxy::traffic_limiter::{RateDirection, TrafficLease, next_refill_delay};
use crate::stats::{
    MeD2cFlushReason, MeD2cQuotaRejectStage, MeD2cWriteMode, QuotaReserveError, Stats, UserStats,
};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter, PooledBuffer};
use crate::transport::middle_proxy::{MePool, MeResponse, proto_flags_for_tag};

mod c2me;
mod d2c;
mod desync;
mod idle;
mod quota;
mod session;

pub(crate) use self::desync::DesyncDedupRotationState;
pub(crate) use self::idle::{RelayIdleCandidateRegistry, note_global_relay_pressure};
pub(crate) use self::session::handle_via_middle_proxy;

use self::c2me::{
    C2MeCommand, acquire_c2me_payload_permit, c2me_queued_permit_budget, enqueue_c2me_command_in,
    should_yield_c2me_sender,
};
use self::d2c::{
    MeD2cFlushPolicy, MeWriterResponseOutcome, classify_me_d2c_flush_reason,
    flush_client_or_cancel, me_d2c_flush_reason_requires_client_flush, observe_me_d2c_flush_event,
    process_me_writer_response_with_traffic_lease,
};
use self::desync::{RelayForensicsState, hash_ip_in, report_desync_frame_too_large_in};
use self::idle::{
    RelayClientIdlePolicy, RelayClientIdleState, clear_relay_idle_candidate_in,
    maybe_evict_idle_candidate_on_pressure_in, note_relay_pressure_event_in,
    read_client_payload_with_idle_policy_in, relay_pressure_event_seq_in,
};
use self::quota::{
    MiddleQuotaReserveError, quota_soft_cap, reserve_user_quota_with_yield,
    wait_for_traffic_budget, wait_for_traffic_budget_or_cancel,
};

#[cfg(test)]
use self::c2me::enqueue_c2me_command;
#[cfg(test)]
use self::d2c::{
    compute_intermediate_secure_wire_len, process_me_writer_response, write_client_payload,
};
#[cfg(test)]
pub(crate) use self::desync::{
    clear_desync_dedup_for_testing_in_shared, desync_dedup_get_for_testing,
    desync_dedup_insert_for_testing, desync_dedup_keys_for_testing, desync_dedup_len_for_testing,
    desync_forensics_len_bytes, hash_ip, report_desync_frame_too_large,
    should_emit_full_desync_for_testing,
};
#[cfg(test)]
use self::idle::RelayIdleCandidateMeta;
#[cfg(test)]
pub(crate) use self::idle::{
    clear_relay_idle_candidate_for_testing, clear_relay_idle_pressure_state_for_testing_in_shared,
    mark_relay_idle_candidate_for_testing, maybe_evict_idle_candidate_on_pressure_for_testing,
    note_relay_pressure_event_for_testing, oldest_relay_idle_candidate_for_testing,
    read_client_payload, read_client_payload_legacy, read_client_payload_with_idle_policy,
    relay_idle_mark_seq_for_testing, relay_pressure_event_seq_for_testing,
    set_relay_pressure_state_for_testing,
};

const DESYNC_DEDUP_WINDOW: Duration = Duration::from_secs(60);
const DESYNC_DEDUP_MAX_ENTRIES: usize = 65_536;
const DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL: Duration = Duration::from_millis(1000);
const DESYNC_ERROR_CLASS: &str = "frame_too_large_crypto_desync";
const C2ME_CHANNEL_CAPACITY_FALLBACK: usize = 128;
const C2ME_SOFT_PRESSURE_MIN_FREE_SLOTS: usize = 64;
const C2ME_SENDER_FAIRNESS_BUDGET: usize = 32;
const C2ME_QUEUED_BYTE_PERMIT_UNIT: usize = 16 * 1024;
const C2ME_QUEUED_PERMITS_PER_SLOT: usize = 4;
const RELAY_IDLE_IO_POLL_MAX: Duration = Duration::from_secs(1);
const TINY_FRAME_DEBT_PER_TINY: u32 = 8;
const TINY_FRAME_DEBT_LIMIT: u32 = 512;
#[cfg(test)]
const RELAY_TEST_STEP_TIMEOUT: Duration = Duration::from_secs(1);
const ME_D2C_FLUSH_BATCH_MAX_FRAMES_MIN: usize = 1;
const ME_D2C_FLUSH_BATCH_MAX_BYTES_MIN: usize = 4096;
const ME_D2C_FRAME_BUF_SHRINK_HYSTERESIS_FACTOR: usize = 2;
const ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES: usize = 128 * 1024;
const QUOTA_RESERVE_SPIN_RETRIES: usize = 32;
const QUOTA_RESERVE_BACKOFF_MIN_MS: u64 = 1;
const QUOTA_RESERVE_BACKOFF_MAX_MS: u64 = 16;
const QUOTA_RESERVE_MAX_BACKOFF_ROUNDS: usize = 16;
const ME_CHILD_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
async fn run_relay_test_step_timeout<F, T>(context: &'static str, fut: F) -> T
where
    F: Future<Output = T>,
{
    timeout(RELAY_TEST_STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{context} exceeded {}s", RELAY_TEST_STEP_TIMEOUT.as_secs()))
}

#[cfg(test)]
#[path = "tests/middle_relay_idle_policy_security_tests.rs"]
mod idle_policy_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_desync_all_full_dedup_security_tests.rs"]
mod desync_all_full_dedup_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_stub_completion_security_tests.rs"]
mod stub_completion_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_length_cast_hardening_security_tests.rs"]
mod length_cast_hardening_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_idle_registry_poison_security_tests.rs"]
mod middle_relay_idle_registry_poison_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_zero_length_frame_security_tests.rs"]
mod middle_relay_zero_length_frame_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_tiny_frame_debt_security_tests.rs"]
mod middle_relay_tiny_frame_debt_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_tiny_frame_debt_concurrency_security_tests.rs"]
mod middle_relay_tiny_frame_debt_concurrency_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_tiny_frame_debt_proto_chunking_security_tests.rs"]
mod middle_relay_tiny_frame_debt_proto_chunking_security_tests;

#[cfg(test)]
#[path = "tests/middle_relay_atomic_quota_invariant_tests.rs"]
mod middle_relay_atomic_quota_invariant_tests;

#[cfg(test)]
#[path = "tests/middle_relay_baseline_invariant_tests.rs"]
mod middle_relay_baseline_invariant_tests;

#[cfg(test)]
#[path = "tests/middle_relay_d2c_flush_padding_security_tests.rs"]
mod middle_relay_d2c_flush_padding_security_tests;
