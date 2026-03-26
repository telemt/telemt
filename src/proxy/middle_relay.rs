use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap};
#[cfg(test)]
use std::future::Future;
use std::hash::{BuildHasher, Hash};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{secure_padding_len, *};
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::route_mode::{
    ROUTE_SWITCH_ERROR_MSG, RelayRouteMode, RouteCutoverState, affected_cutover_state,
    cutover_stagger_delay,
};
use crate::stats::{
    MeD2cFlushReason, MeD2cQuotaRejectStage, MeD2cWriteMode, QuotaReserveError, Stats, UserStats,
};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter, PooledBuffer};
use crate::transport::middle_proxy::{MePool, MeResponse, proto_flags_for_tag};

enum C2MeCommand {
    Data { payload: PooledBuffer, flags: u32 },
    Close,
}

const DESYNC_DEDUP_WINDOW: Duration = Duration::from_secs(60);
const DESYNC_DEDUP_MAX_ENTRIES: usize = 65_536;
const DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL: Duration = Duration::from_millis(1000);
const DESYNC_ERROR_CLASS: &str = "frame_too_large_crypto_desync";
const C2ME_CHANNEL_CAPACITY_FALLBACK: usize = 128;
const C2ME_SOFT_PRESSURE_MIN_FREE_SLOTS: usize = 64;
const C2ME_SENDER_FAIRNESS_BUDGET: usize = 32;
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
static DESYNC_DEDUP: OnceLock<DashMap<u64, Instant>> = OnceLock::new();
static DESYNC_DEDUP_PREVIOUS: OnceLock<DashMap<u64, Instant>> = OnceLock::new();
static DESYNC_HASHER: OnceLock<RandomState> = OnceLock::new();
static DESYNC_FULL_CACHE_LAST_EMIT_AT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
static DESYNC_DEDUP_ROTATION_STATE: OnceLock<Mutex<DesyncDedupRotationState>> = OnceLock::new();
// Invariant for async callers:
// this std::sync::Mutex is allowed only because critical sections are short,
// synchronous, and MUST never cross an `.await`.
static RELAY_IDLE_CANDIDATE_REGISTRY: OnceLock<Mutex<RelayIdleCandidateRegistry>> = OnceLock::new();
static RELAY_IDLE_MARK_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct DesyncDedupRotationState {
    current_started_at: Option<Instant>,
}

struct RelayForensicsState {
    trace_id: u64,
    conn_id: u64,
    user: String,
    peer: SocketAddr,
    peer_hash: u64,
    started_at: Instant,
    bytes_c2me: u64,
    bytes_me2c: Arc<AtomicU64>,
    desync_all_full: bool,
}

#[derive(Default)]
struct RelayIdleCandidateRegistry {
    by_conn_id: HashMap<u64, RelayIdleCandidateMeta>,
    ordered: BTreeSet<(u64, u64)>,
    pressure_event_seq: u64,
    pressure_consumed_seq: u64,
}

#[derive(Clone, Copy)]
struct RelayIdleCandidateMeta {
    mark_order_seq: u64,
    mark_pressure_seq: u64,
}

fn relay_idle_candidate_registry() -> &'static Mutex<RelayIdleCandidateRegistry> {
    RELAY_IDLE_CANDIDATE_REGISTRY.get_or_init(|| Mutex::new(RelayIdleCandidateRegistry::default()))
}

fn relay_idle_candidate_registry_lock() -> std::sync::MutexGuard<'static, RelayIdleCandidateRegistry>
{
    // Keep lock scope narrow and synchronous: callers must drop guard before any `.await`.
    let registry = relay_idle_candidate_registry();
    match registry.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            // Fail closed after panic while holding registry lock: drop all
            // candidates and pressure cursors to avoid stale cross-session state.
            *guard = RelayIdleCandidateRegistry::default();
            registry.clear_poison();
            guard
        }
    }
}

fn mark_relay_idle_candidate(conn_id: u64) -> bool {
    let mut guard = relay_idle_candidate_registry_lock();

    if guard.by_conn_id.contains_key(&conn_id) {
        return false;
    }

    let mark_order_seq = RELAY_IDLE_MARK_SEQ
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let meta = RelayIdleCandidateMeta {
        mark_order_seq,
        mark_pressure_seq: guard.pressure_event_seq,
    };
    guard.by_conn_id.insert(conn_id, meta);
    guard.ordered.insert((meta.mark_order_seq, conn_id));
    true
}

fn clear_relay_idle_candidate(conn_id: u64) {
    let mut guard = relay_idle_candidate_registry_lock();

    if let Some(meta) = guard.by_conn_id.remove(&conn_id) {
        guard.ordered.remove(&(meta.mark_order_seq, conn_id));
    }
}

#[cfg(test)]
fn oldest_relay_idle_candidate() -> Option<u64> {
    let guard = relay_idle_candidate_registry_lock();
    guard.ordered.iter().next().map(|(_, conn_id)| *conn_id)
}

fn note_relay_pressure_event() {
    let mut guard = relay_idle_candidate_registry_lock();
    guard.pressure_event_seq = guard.pressure_event_seq.wrapping_add(1);
}

fn relay_pressure_event_seq() -> u64 {
    let guard = relay_idle_candidate_registry_lock();
    guard.pressure_event_seq
}

fn maybe_evict_idle_candidate_on_pressure(
    conn_id: u64,
    seen_pressure_seq: &mut u64,
    stats: &Stats,
) -> bool {
    let mut guard = relay_idle_candidate_registry_lock();

    let latest_pressure_seq = guard.pressure_event_seq;
    if latest_pressure_seq == *seen_pressure_seq {
        return false;
    }
    *seen_pressure_seq = latest_pressure_seq;

    if latest_pressure_seq == guard.pressure_consumed_seq {
        return false;
    }

    if guard.ordered.is_empty() {
        guard.pressure_consumed_seq = latest_pressure_seq;
        return false;
    }

    let oldest = guard
        .ordered
        .iter()
        .next()
        .map(|(_, candidate_conn_id)| *candidate_conn_id);
    if oldest != Some(conn_id) {
        return false;
    }

    let Some(candidate_meta) = guard.by_conn_id.get(&conn_id).copied() else {
        return false;
    };

    // Pressure events that happened before candidate soft-mark are stale for this candidate.
    if latest_pressure_seq == candidate_meta.mark_pressure_seq {
        return false;
    }

    if let Some(meta) = guard.by_conn_id.remove(&conn_id) {
        guard.ordered.remove(&(meta.mark_order_seq, conn_id));
    }
    guard.pressure_consumed_seq = latest_pressure_seq;
    stats.increment_relay_pressure_evict_total();
    true
}

#[cfg(test)]
fn clear_relay_idle_pressure_state_for_testing() {
    if RELAY_IDLE_CANDIDATE_REGISTRY.get().is_some() {
        let mut guard = relay_idle_candidate_registry_lock();
        *guard = RelayIdleCandidateRegistry::default();
    }
    RELAY_IDLE_MARK_SEQ.store(0, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
struct MeD2cFlushPolicy {
    max_frames: usize,
    max_bytes: usize,
    max_delay: Duration,
    ack_flush_immediate: bool,
    quota_soft_overshoot_bytes: u64,
    frame_buf_shrink_threshold_bytes: usize,
}

#[derive(Clone, Copy)]
struct RelayClientIdlePolicy {
    enabled: bool,
    soft_idle: Duration,
    hard_idle: Duration,
    grace_after_downstream_activity: Duration,
    legacy_frame_read_timeout: Duration,
}

impl RelayClientIdlePolicy {
    fn from_config(config: &ProxyConfig) -> Self {
        Self {
            enabled: config.timeouts.relay_idle_policy_v2_enabled,
            soft_idle: Duration::from_secs(config.timeouts.relay_client_idle_soft_secs.max(1)),
            hard_idle: Duration::from_secs(config.timeouts.relay_client_idle_hard_secs.max(1)),
            grace_after_downstream_activity: Duration::from_secs(
                config
                    .timeouts
                    .relay_idle_grace_after_downstream_activity_secs,
            ),
            legacy_frame_read_timeout: Duration::from_secs(config.timeouts.client_handshake.max(1)),
        }
    }

    #[cfg(test)]
    fn disabled(frame_read_timeout: Duration) -> Self {
        Self {
            enabled: false,
            soft_idle: Duration::from_secs(0),
            hard_idle: Duration::from_secs(0),
            grace_after_downstream_activity: Duration::from_secs(0),
            legacy_frame_read_timeout: frame_read_timeout,
        }
    }
}

struct RelayClientIdleState {
    last_client_frame_at: Instant,
    soft_idle_marked: bool,
    tiny_frame_debt: u32,
}

impl RelayClientIdleState {
    fn new(now: Instant) -> Self {
        Self {
            last_client_frame_at: now,
            soft_idle_marked: false,
            tiny_frame_debt: 0,
        }
    }

    fn on_client_frame(&mut self, now: Instant) {
        self.last_client_frame_at = now;
        self.soft_idle_marked = false;
    }
}

impl MeD2cFlushPolicy {
    fn from_config(config: &ProxyConfig) -> Self {
        Self {
            max_frames: config
                .general
                .me_d2c_flush_batch_max_frames
                .max(ME_D2C_FLUSH_BATCH_MAX_FRAMES_MIN),
            max_bytes: config
                .general
                .me_d2c_flush_batch_max_bytes
                .max(ME_D2C_FLUSH_BATCH_MAX_BYTES_MIN),
            max_delay: Duration::from_micros(config.general.me_d2c_flush_batch_max_delay_us),
            ack_flush_immediate: config.general.me_d2c_ack_flush_immediate,
            quota_soft_overshoot_bytes: config.general.me_quota_soft_overshoot_bytes,
            frame_buf_shrink_threshold_bytes: config
                .general
                .me_d2c_frame_buf_shrink_threshold_bytes
                .max(4096),
        }
    }
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let state = DESYNC_HASHER.get_or_init(RandomState::new);
    state.hash_one(value)
}

fn hash_ip(ip: IpAddr) -> u64 {
    hash_value(&ip)
}

fn should_emit_full_desync(key: u64, all_full: bool, now: Instant) -> bool {
    if all_full {
        return true;
    }

    let dedup_current = DESYNC_DEDUP.get_or_init(DashMap::new);
    let dedup_previous = DESYNC_DEDUP_PREVIOUS.get_or_init(DashMap::new);
    let rotation_state =
        DESYNC_DEDUP_ROTATION_STATE.get_or_init(|| Mutex::new(DesyncDedupRotationState::default()));

    let mut state = match rotation_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = DesyncDedupRotationState::default();
            rotation_state.clear_poison();
            guard
        }
    };

    let rotate_now = match state.current_started_at {
        Some(current_started_at) => match now.checked_duration_since(current_started_at) {
            Some(elapsed) => elapsed >= DESYNC_DEDUP_WINDOW,
            None => true,
        },
        None => true,
    };
    if rotate_now {
        dedup_previous.clear();
        for entry in dedup_current.iter() {
            dedup_previous.insert(*entry.key(), *entry.value());
        }
        dedup_current.clear();
        state.current_started_at = Some(now);
    }

    if let Some(seen_at) = dedup_current.get(&key).map(|entry| *entry.value()) {
        let within_window = match now.checked_duration_since(seen_at) {
            Some(elapsed) => elapsed < DESYNC_DEDUP_WINDOW,
            None => true,
        };
        if within_window {
            return false;
        }
        dedup_current.insert(key, now);
        return true;
    }

    if let Some(seen_at) = dedup_previous.get(&key).map(|entry| *entry.value()) {
        let within_window = match now.checked_duration_since(seen_at) {
            Some(elapsed) => elapsed < DESYNC_DEDUP_WINDOW,
            None => true,
        };
        if within_window {
            // Keep the original timestamp when promoting from previous bucket,
            // so dedup expiry remains tied to first-seen time.
            dedup_current.insert(key, seen_at);
            return false;
        }
        dedup_previous.remove(&key);
    }

    if dedup_current.len() >= DESYNC_DEDUP_MAX_ENTRIES {
        // Bounded eviction path: rotate buckets instead of scanning/evicting
        // arbitrary entries from a saturated single map.
        dedup_previous.clear();
        for entry in dedup_current.iter() {
            dedup_previous.insert(*entry.key(), *entry.value());
        }
        dedup_current.clear();
        state.current_started_at = Some(now);
        dedup_current.insert(key, now);
        should_emit_full_desync_full_cache(now)
    } else {
        dedup_current.insert(key, now);
        true
    }
}

fn should_emit_full_desync_full_cache(now: Instant) -> bool {
    let gate = DESYNC_FULL_CACHE_LAST_EMIT_AT.get_or_init(|| Mutex::new(None));
    let Ok(mut last_emit_at) = gate.lock() else {
        return false;
    };

    match *last_emit_at {
        None => {
            *last_emit_at = Some(now);
            true
        }
        Some(last) => {
            let Some(elapsed) = now.checked_duration_since(last) else {
                *last_emit_at = Some(now);
                return true;
            };
            if elapsed >= DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL {
                *last_emit_at = Some(now);
                true
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
fn clear_desync_dedup_for_testing() {
    if let Some(dedup) = DESYNC_DEDUP.get() {
        dedup.clear();
    }
    if let Some(dedup_previous) = DESYNC_DEDUP_PREVIOUS.get() {
        dedup_previous.clear();
    }
    if let Some(rotation_state) = DESYNC_DEDUP_ROTATION_STATE.get() {
        match rotation_state.lock() {
            Ok(mut guard) => {
                *guard = DesyncDedupRotationState::default();
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = DesyncDedupRotationState::default();
                rotation_state.clear_poison();
            }
        }
    }
    if let Some(last_emit_at) = DESYNC_FULL_CACHE_LAST_EMIT_AT.get() {
        match last_emit_at.lock() {
            Ok(mut guard) => {
                *guard = None;
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = None;
                last_emit_at.clear_poison();
            }
        }
    }
}

#[cfg(test)]
fn desync_dedup_test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

fn desync_forensics_len_bytes(len: usize) -> ([u8; 4], bool) {
    match u32::try_from(len) {
        Ok(value) => (value.to_le_bytes(), false),
        Err(_) => (u32::MAX.to_le_bytes(), true),
    }
}

fn report_desync_frame_too_large(
    state: &RelayForensicsState,
    proto_tag: ProtoTag,
    frame_counter: u64,
    max_frame: usize,
    len: usize,
    raw_len_bytes: Option<[u8; 4]>,
    stats: &Stats,
) -> ProxyError {
    let (fallback_len_buf, len_buf_truncated) = desync_forensics_len_bytes(len);
    let len_buf = raw_len_bytes.unwrap_or(fallback_len_buf);
    let looks_like_tls = raw_len_bytes
        .map(|b| b[0] == 0x16 && b[1] == 0x03)
        .unwrap_or(false);
    let looks_like_http = raw_len_bytes
        .map(|b| matches!(b[0], b'G' | b'P' | b'H' | b'C' | b'D'))
        .unwrap_or(false);
    let now = Instant::now();
    let dedup_key = hash_value(&(
        state.user.as_str(),
        state.peer_hash,
        proto_tag,
        DESYNC_ERROR_CLASS,
    ));
    let emit_full = should_emit_full_desync(dedup_key, state.desync_all_full, now);
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let bytes_me2c = state.bytes_me2c.load(Ordering::Relaxed);

    stats.increment_desync_total();
    stats.increment_relay_protocol_desync_close_total();
    stats.observe_desync_frames_ok(frame_counter);
    if emit_full {
        stats.increment_desync_full_logged();
        warn!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            mode = "middle_proxy",
            is_tls = true,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            raw_len_hex = format_args!("0x{:08x}", len),
            raw_len_bytes_truncated = len_buf_truncated,
            raw_bytes = format_args!(
                "{:02x} {:02x} {:02x} {:02x}",
                len_buf[0], len_buf[1], len_buf[2], len_buf[3]
            ),
            max_frame,
            tls_like = looks_like_tls,
            http_like = looks_like_http,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            desync_all_full = state.desync_all_full,
            full_reason = if state.desync_all_full { "desync_all_full" } else { "first_in_dedup_window" },
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensics"
        );
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer = %state.peer,
            "Frame too large forensic peer detail"
        );
    } else {
        stats.increment_desync_suppressed();
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensic suppressed"
        );
    }

    ProxyError::Proxy(format!(
        "Frame too large: {len} (max {max_frame}), frames_ok={frame_counter}, conn_id={}, trace_id=0x{:016x}",
        state.conn_id, state.trace_id
    ))
}

fn should_yield_c2me_sender(sent_since_yield: usize, has_backlog: bool) -> bool {
    has_backlog && sent_since_yield >= C2ME_SENDER_FAIRNESS_BUDGET
}

fn quota_soft_cap(limit: u64, overshoot: u64) -> u64 {
    limit.saturating_add(overshoot)
}

async fn reserve_user_quota_with_yield(
    user_stats: &UserStats,
    bytes: u64,
    limit: u64,
) -> std::result::Result<u64, QuotaReserveError> {
    loop {
        for _ in 0..QUOTA_RESERVE_SPIN_RETRIES {
            match user_stats.quota_try_reserve(bytes, limit) {
                Ok(total) => return Ok(total),
                Err(QuotaReserveError::LimitExceeded) => {
                    return Err(QuotaReserveError::LimitExceeded);
                }
                Err(QuotaReserveError::Contended) => std::hint::spin_loop(),
            }
        }

        tokio::task::yield_now().await;
    }
}

fn classify_me_d2c_flush_reason(
    flush_immediately: bool,
    batch_frames: usize,
    max_frames: usize,
    batch_bytes: usize,
    max_bytes: usize,
    max_delay_fired: bool,
) -> MeD2cFlushReason {
    if flush_immediately {
        return MeD2cFlushReason::AckImmediate;
    }
    if batch_frames >= max_frames {
        return MeD2cFlushReason::BatchFrames;
    }
    if batch_bytes >= max_bytes {
        return MeD2cFlushReason::BatchBytes;
    }
    if max_delay_fired {
        return MeD2cFlushReason::MaxDelay;
    }
    MeD2cFlushReason::QueueDrain
}

fn observe_me_d2c_flush_event(
    stats: &Stats,
    reason: MeD2cFlushReason,
    batch_frames: usize,
    batch_bytes: usize,
    flush_duration_us: Option<u64>,
) {
    stats.increment_me_d2c_flush_reason(reason);
    if batch_frames > 0 || batch_bytes > 0 {
        stats.increment_me_d2c_batches_total();
        stats.add_me_d2c_batch_frames_total(batch_frames as u64);
        stats.add_me_d2c_batch_bytes_total(batch_bytes as u64);
        stats.observe_me_d2c_batch_frames(batch_frames as u64);
        stats.observe_me_d2c_batch_bytes(batch_bytes as u64);
    }
    if let Some(duration_us) = flush_duration_us {
        stats.observe_me_d2c_flush_duration_us(duration_us);
    }
}

#[cfg(test)]
fn relay_idle_pressure_test_guard() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
pub(crate) fn relay_idle_pressure_test_scope() -> std::sync::MutexGuard<'static, ()> {
    relay_idle_pressure_test_guard()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn enqueue_c2me_command(
    tx: &mpsc::Sender<C2MeCommand>,
    cmd: C2MeCommand,
    send_timeout: Option<Duration>,
) -> std::result::Result<(), mpsc::error::SendError<C2MeCommand>> {
    match tx.try_send(cmd) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(cmd)) => Err(mpsc::error::SendError(cmd)),
        Err(mpsc::error::TrySendError::Full(cmd)) => {
            note_relay_pressure_event();
            // Cooperative yield reduces burst catch-up when the per-conn queue is near saturation.
            if tx.capacity() <= C2ME_SOFT_PRESSURE_MIN_FREE_SLOTS {
                tokio::task::yield_now().await;
            }
            let reserve_result = match send_timeout {
                Some(send_timeout) => match timeout(send_timeout, tx.reserve()).await {
                    Ok(result) => result,
                    Err(_) => return Err(mpsc::error::SendError(cmd)),
                },
                None => tx.reserve().await,
            };
            match reserve_result {
                Ok(permit) => {
                    permit.send(cmd);
                    Ok(())
                }
                Err(_) => Err(mpsc::error::SendError(cmd)),
            }
        }
    }
}

#[cfg(test)]
async fn run_relay_test_step_timeout<F, T>(context: &'static str, fut: F) -> T
where
    F: Future<Output = T>,
{
    timeout(RELAY_TEST_STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{context} exceeded {}s", RELAY_TEST_STEP_TIMEOUT.as_secs()))
}

pub(crate) async fn handle_via_middle_proxy<R, W>(
    mut crypto_reader: CryptoReader<R>,
    crypto_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    me_pool: Arc<MePool>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    local_addr: SocketAddr,
    rng: Arc<SecureRandom>,
    mut route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = success.user.clone();
    let quota_limit = config.access.user_data_quota.get(&user).copied();
    let quota_user_stats = quota_limit.map(|_| stats.get_or_create_user_stats_handle(&user));
    let peer = success.peer;
    let proto_tag = success.proto_tag;
    let pool_generation = me_pool.current_generation();

    debug!(
        user = %user,
        peer = %peer,
        dc = success.dc_idx,
        proto = ?proto_tag,
        mode = "middle_proxy",
        pool_generation,
        "Routing via Middle-End"
    );

    let (conn_id, me_rx) = me_pool.registry().register().await;
    let trace_id = session_id;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut forensics = RelayForensicsState {
        trace_id,
        conn_id,
        user: user.clone(),
        peer,
        peer_hash: hash_ip(peer.ip()),
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: bytes_me2c.clone(),
        desync_all_full: config.general.desync_all_full,
    };

    stats.increment_user_connects(&user);
    let _me_connection_lease = stats.acquire_me_connection_lease();

    if let Some(cutover) =
        affected_cutover_state(&route_rx, RelayRouteMode::Middle, route_snapshot.generation)
    {
        let delay = cutover_stagger_delay(session_id, cutover.generation);
        warn!(
            conn_id,
            target_mode = cutover.mode.as_str(),
            cutover_generation = cutover.generation,
            delay_ms = delay.as_millis() as u64,
            "Cutover affected middle session before relay start, closing client connection"
        );
        tokio::time::sleep(delay).await;
        let _ = me_pool.send_close(conn_id).await;
        me_pool.registry().unregister(conn_id).await;
        return Err(ProxyError::Proxy(ROUTE_SWITCH_ERROR_MSG.to_string()));
    }

    // Per-user ad_tag from access.user_ad_tags; fallback to general.ad_tag (hot-reloadable)
    let user_tag: Option<Vec<u8>> = config
        .access
        .user_ad_tags
        .get(&user)
        .and_then(|s| hex::decode(s).ok())
        .filter(|v| v.len() == 16);
    let global_tag: Option<Vec<u8>> = config
        .general
        .ad_tag
        .as_ref()
        .and_then(|s| hex::decode(s).ok())
        .filter(|v| v.len() == 16);
    let effective_tag = user_tag.or(global_tag);

    let proto_flags = proto_flags_for_tag(proto_tag, effective_tag.is_some());
    debug!(
        trace_id = format_args!("0x{:016x}", trace_id),
        user = %user,
        conn_id,
        peer_hash = format_args!("0x{:016x}", forensics.peer_hash),
        desync_all_full = forensics.desync_all_full,
        proto_flags = format_args!("0x{:08x}", proto_flags),
        pool_generation,
        "ME relay started"
    );

    let translated_local_addr = me_pool.translate_our_addr(local_addr);

    let frame_limit = config.general.max_client_frame;
    let relay_idle_policy = RelayClientIdlePolicy::from_config(&config);
    let session_started_at = forensics.started_at;
    let mut relay_idle_state = RelayClientIdleState::new(session_started_at);
    let last_downstream_activity_ms = Arc::new(AtomicU64::new(0));

    let c2me_channel_capacity = config
        .general
        .me_c2me_channel_capacity
        .max(C2ME_CHANNEL_CAPACITY_FALLBACK);
    let c2me_send_timeout = match config.general.me_c2me_send_timeout_ms {
        0 => None,
        timeout_ms => Some(Duration::from_millis(timeout_ms)),
    };
    let (c2me_tx, mut c2me_rx) = mpsc::channel::<C2MeCommand>(c2me_channel_capacity);
    let me_pool_c2me = me_pool.clone();
    let c2me_sender = tokio::spawn(async move {
        let mut sent_since_yield = 0usize;
        while let Some(cmd) = c2me_rx.recv().await {
            match cmd {
                C2MeCommand::Data { payload, flags } => {
                    me_pool_c2me
                        .send_proxy_req(
                            conn_id,
                            success.dc_idx,
                            peer,
                            translated_local_addr,
                            payload.as_ref(),
                            flags,
                            effective_tag.as_deref(),
                        )
                        .await?;
                    sent_since_yield = sent_since_yield.saturating_add(1);
                    if should_yield_c2me_sender(sent_since_yield, !c2me_rx.is_empty()) {
                        sent_since_yield = 0;
                        tokio::task::yield_now().await;
                    }
                }
                C2MeCommand::Close => {
                    let _ = me_pool_c2me.send_close(conn_id).await;
                    return Ok(());
                }
            }
        }
        Ok(())
    });

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let mut me_rx_task = me_rx;
    let stats_clone = stats.clone();
    let rng_clone = rng.clone();
    let user_clone = user.clone();
    let quota_user_stats_me_writer = quota_user_stats.clone();
    let last_downstream_activity_ms_clone = last_downstream_activity_ms.clone();
    let bytes_me2c_clone = bytes_me2c.clone();
    let d2c_flush_policy = MeD2cFlushPolicy::from_config(&config);
    let me_writer = tokio::spawn(async move {
        let mut writer = crypto_writer;
        let mut frame_buf = Vec::with_capacity(16 * 1024);
        loop {
            tokio::select! {
                msg = me_rx_task.recv() => {
                    let Some(first) = msg else {
                        debug!(conn_id, "ME channel closed");
                        return Err(ProxyError::Proxy("ME connection lost".into()));
                    };

                    let mut batch_frames = 0usize;
                    let mut batch_bytes = 0usize;
                    let mut flush_immediately;
                    let mut max_delay_fired = false;

                    let first_is_downstream_activity =
                        matches!(&first, MeResponse::Data { .. } | MeResponse::Ack(_));
                    match process_me_writer_response(
                        first,
                        &mut writer,
                        proto_tag,
                        rng_clone.as_ref(),
                        &mut frame_buf,
                        stats_clone.as_ref(),
                        &user_clone,
                        quota_user_stats_me_writer.as_deref(),
                        quota_limit,
                        d2c_flush_policy.quota_soft_overshoot_bytes,
                        bytes_me2c_clone.as_ref(),
                        conn_id,
                        d2c_flush_policy.ack_flush_immediate,
                        false,
                    ).await? {
                        MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                            if first_is_downstream_activity {
                                last_downstream_activity_ms_clone
                                    .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                            }
                            batch_frames = batch_frames.saturating_add(frames);
                            batch_bytes = batch_bytes.saturating_add(bytes);
                            flush_immediately = immediate;
                        }
                        MeWriterResponseOutcome::Close => {
                            let flush_started_at = if stats_clone.telemetry_policy().me_level.allows_debug() {
                                Some(Instant::now())
                            } else {
                                None
                            };
                            let _ = writer.flush().await;
                            let flush_duration_us = flush_started_at.map(|started| {
                                started
                                    .elapsed()
                                    .as_micros()
                                    .min(u128::from(u64::MAX)) as u64
                            });
                            observe_me_d2c_flush_event(
                                stats_clone.as_ref(),
                                MeD2cFlushReason::Close,
                                batch_frames,
                                batch_bytes,
                                flush_duration_us,
                            );
                            return Ok(());
                        }
                    }

                    while !flush_immediately
                        && batch_frames < d2c_flush_policy.max_frames
                        && batch_bytes < d2c_flush_policy.max_bytes
                    {
                        let Ok(next) = me_rx_task.try_recv() else {
                            break;
                        };

                        let next_is_downstream_activity =
                            matches!(&next, MeResponse::Data { .. } | MeResponse::Ack(_));
                        match process_me_writer_response(
                            next,
                            &mut writer,
                            proto_tag,
                            rng_clone.as_ref(),
                            &mut frame_buf,
                            stats_clone.as_ref(),
                            &user_clone,
                            quota_user_stats_me_writer.as_deref(),
                            quota_limit,
                            d2c_flush_policy.quota_soft_overshoot_bytes,
                            bytes_me2c_clone.as_ref(),
                            conn_id,
                            d2c_flush_policy.ack_flush_immediate,
                            true,
                        ).await? {
                            MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                if next_is_downstream_activity {
                                    last_downstream_activity_ms_clone
                                        .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                                }
                                batch_frames = batch_frames.saturating_add(frames);
                                batch_bytes = batch_bytes.saturating_add(bytes);
                                flush_immediately |= immediate;
                            }
                            MeWriterResponseOutcome::Close => {
                                let flush_started_at =
                                    if stats_clone.telemetry_policy().me_level.allows_debug() {
                                        Some(Instant::now())
                                    } else {
                                        None
                                    };
                                let _ = writer.flush().await;
                                let flush_duration_us = flush_started_at.map(|started| {
                                    started
                                        .elapsed()
                                        .as_micros()
                                        .min(u128::from(u64::MAX))
                                        as u64
                                });
                                observe_me_d2c_flush_event(
                                    stats_clone.as_ref(),
                                    MeD2cFlushReason::Close,
                                    batch_frames,
                                    batch_bytes,
                                    flush_duration_us,
                                );
                                return Ok(());
                            }
                        }
                    }

                    if !flush_immediately
                        && !d2c_flush_policy.max_delay.is_zero()
                        && batch_frames < d2c_flush_policy.max_frames
                        && batch_bytes < d2c_flush_policy.max_bytes
                    {
                        stats_clone.increment_me_d2c_batch_timeout_armed_total();
                        match tokio::time::timeout(d2c_flush_policy.max_delay, me_rx_task.recv()).await {
                            Ok(Some(next)) => {
                                let next_is_downstream_activity =
                                    matches!(&next, MeResponse::Data { .. } | MeResponse::Ack(_));
                                match process_me_writer_response(
                                    next,
                                    &mut writer,
                                    proto_tag,
                                    rng_clone.as_ref(),
                                    &mut frame_buf,
                                    stats_clone.as_ref(),
                                    &user_clone,
                                    quota_user_stats_me_writer.as_deref(),
                                    quota_limit,
                                    d2c_flush_policy.quota_soft_overshoot_bytes,
                                    bytes_me2c_clone.as_ref(),
                                    conn_id,
                                    d2c_flush_policy.ack_flush_immediate,
                                    true,
                                ).await? {
                                    MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                        if next_is_downstream_activity {
                                            last_downstream_activity_ms_clone
                                                .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                                        }
                                        batch_frames = batch_frames.saturating_add(frames);
                                        batch_bytes = batch_bytes.saturating_add(bytes);
                                        flush_immediately |= immediate;
                                    }
                                    MeWriterResponseOutcome::Close => {
                                        let flush_started_at = if stats_clone
                                            .telemetry_policy()
                                            .me_level
                                            .allows_debug()
                                        {
                                            Some(Instant::now())
                                        } else {
                                            None
                                        };
                                        let _ = writer.flush().await;
                                        let flush_duration_us = flush_started_at.map(|started| {
                                            started
                                                .elapsed()
                                                .as_micros()
                                                .min(u128::from(u64::MAX))
                                                as u64
                                        });
                                        observe_me_d2c_flush_event(
                                            stats_clone.as_ref(),
                                            MeD2cFlushReason::Close,
                                            batch_frames,
                                            batch_bytes,
                                            flush_duration_us,
                                        );
                                        return Ok(());
                                    }
                                }

                                while !flush_immediately
                                    && batch_frames < d2c_flush_policy.max_frames
                                    && batch_bytes < d2c_flush_policy.max_bytes
                                {
                                    let Ok(extra) = me_rx_task.try_recv() else {
                                        break;
                                    };

                                    let extra_is_downstream_activity =
                                        matches!(&extra, MeResponse::Data { .. } | MeResponse::Ack(_));
                                    match process_me_writer_response(
                                        extra,
                                        &mut writer,
                                        proto_tag,
                                        rng_clone.as_ref(),
                                        &mut frame_buf,
                                        stats_clone.as_ref(),
                                        &user_clone,
                                        quota_user_stats_me_writer.as_deref(),
                                        quota_limit,
                                        d2c_flush_policy.quota_soft_overshoot_bytes,
                                        bytes_me2c_clone.as_ref(),
                                        conn_id,
                                        d2c_flush_policy.ack_flush_immediate,
                                        true,
                                    ).await? {
                                        MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                            if extra_is_downstream_activity {
                                                last_downstream_activity_ms_clone
                                                    .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                                            }
                                            batch_frames = batch_frames.saturating_add(frames);
                                            batch_bytes = batch_bytes.saturating_add(bytes);
                                            flush_immediately |= immediate;
                                        }
                                        MeWriterResponseOutcome::Close => {
                                            let flush_started_at = if stats_clone
                                                .telemetry_policy()
                                                .me_level
                                                .allows_debug()
                                            {
                                                Some(Instant::now())
                                            } else {
                                                None
                                            };
                                            let _ = writer.flush().await;
                                            let flush_duration_us = flush_started_at.map(|started| {
                                                started
                                                    .elapsed()
                                                    .as_micros()
                                                    .min(u128::from(u64::MAX))
                                                    as u64
                                            });
                                            observe_me_d2c_flush_event(
                                                stats_clone.as_ref(),
                                                MeD2cFlushReason::Close,
                                                batch_frames,
                                                batch_bytes,
                                                flush_duration_us,
                                            );
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                debug!(conn_id, "ME channel closed");
                                return Err(ProxyError::Proxy("ME connection lost".into()));
                            }
                            Err(_) => {
                                max_delay_fired = true;
                                stats_clone.increment_me_d2c_batch_timeout_fired_total();
                            }
                        }
                    }

                    let flush_reason = classify_me_d2c_flush_reason(
                        flush_immediately,
                        batch_frames,
                        d2c_flush_policy.max_frames,
                        batch_bytes,
                        d2c_flush_policy.max_bytes,
                        max_delay_fired,
                    );
                    let flush_started_at = if stats_clone.telemetry_policy().me_level.allows_debug() {
                        Some(Instant::now())
                    } else {
                        None
                    };
                    writer.flush().await.map_err(ProxyError::Io)?;
                    let flush_duration_us = flush_started_at.map(|started| {
                        started
                            .elapsed()
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64
                    });
                    observe_me_d2c_flush_event(
                        stats_clone.as_ref(),
                        flush_reason,
                        batch_frames,
                        batch_bytes,
                        flush_duration_us,
                    );
                    let shrink_threshold = d2c_flush_policy.frame_buf_shrink_threshold_bytes;
                    let shrink_trigger = shrink_threshold
                        .saturating_mul(ME_D2C_FRAME_BUF_SHRINK_HYSTERESIS_FACTOR);
                    if frame_buf.capacity() > shrink_trigger {
                        let cap_before = frame_buf.capacity();
                        frame_buf.shrink_to(shrink_threshold);
                        let cap_after = frame_buf.capacity();
                        let bytes_freed = cap_before.saturating_sub(cap_after) as u64;
                        stats_clone.observe_me_d2c_frame_buf_shrink(bytes_freed);
                    }
                }
                _ = &mut stop_rx => {
                    debug!(conn_id, "ME writer stop signal");
                    return Ok(());
                }
            }
        }
    });

    let mut main_result: Result<()> = Ok(());
    let mut client_closed = false;
    let mut frame_counter: u64 = 0;
    let mut route_watch_open = true;
    let mut seen_pressure_seq = relay_pressure_event_seq();
    loop {
        if relay_idle_policy.enabled
            && maybe_evict_idle_candidate_on_pressure(
                conn_id,
                &mut seen_pressure_seq,
                stats.as_ref(),
            )
        {
            info!(
                conn_id,
                trace_id = format_args!("0x{:016x}", trace_id),
                user = %user,
                "Middle-relay pressure eviction for idle-candidate session"
            );
            let _ = enqueue_c2me_command(&c2me_tx, C2MeCommand::Close, c2me_send_timeout).await;
            main_result = Err(ProxyError::Proxy(
                "middle-relay session evicted under pressure (idle-candidate)".to_string(),
            ));
            break;
        }

        if let Some(cutover) =
            affected_cutover_state(&route_rx, RelayRouteMode::Middle, route_snapshot.generation)
        {
            let delay = cutover_stagger_delay(session_id, cutover.generation);
            warn!(
                conn_id,
                target_mode = cutover.mode.as_str(),
                cutover_generation = cutover.generation,
                delay_ms = delay.as_millis() as u64,
                "Cutover affected middle session, closing client connection"
            );
            tokio::time::sleep(delay).await;
            let _ = enqueue_c2me_command(&c2me_tx, C2MeCommand::Close, c2me_send_timeout).await;
            main_result = Err(ProxyError::Proxy(ROUTE_SWITCH_ERROR_MSG.to_string()));
            break;
        }

        tokio::select! {
            changed = route_rx.changed(), if route_watch_open => {
                if changed.is_err() {
                    route_watch_open = false;
                }
            }
            payload_result = read_client_payload_with_idle_policy(
                &mut crypto_reader,
                proto_tag,
                frame_limit,
                &buffer_pool,
                &forensics,
                &mut frame_counter,
                &stats,
                &relay_idle_policy,
                &mut relay_idle_state,
                last_downstream_activity_ms.as_ref(),
                session_started_at,
            ) => {
                match payload_result {
                    Ok(Some((payload, quickack))) => {
                        trace!(conn_id, bytes = payload.len(), "C->ME frame");
                        forensics.bytes_c2me = forensics
                            .bytes_c2me
                            .saturating_add(payload.len() as u64);
                        if let (Some(limit), Some(user_stats)) =
                            (quota_limit, quota_user_stats.as_deref())
                        {
                            if reserve_user_quota_with_yield(
                                user_stats,
                                payload.len() as u64,
                                limit,
                            )
                            .await
                            .is_err()
                            {
                                main_result = Err(ProxyError::DataQuotaExceeded {
                                    user: user.clone(),
                                });
                                break;
                            }
                            stats.add_user_octets_from_handle(user_stats, payload.len() as u64);
                        } else {
                            stats.add_user_octets_from(&user, payload.len() as u64);
                        }
                        let mut flags = proto_flags;
                        if quickack {
                            flags |= RPC_FLAG_QUICKACK;
                        }
                        if payload.len() >= 8 && payload[..8].iter().all(|b| *b == 0) {
                            flags |= RPC_FLAG_NOT_ENCRYPTED;
                        }
                        // Keep client read loop lightweight: route heavy ME send path via a dedicated task.
                        if enqueue_c2me_command(
                            &c2me_tx,
                            C2MeCommand::Data { payload, flags },
                            c2me_send_timeout,
                        )
                        .await
                            .is_err()
                        {
                            main_result = Err(ProxyError::Proxy("ME sender channel closed".into()));
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!(conn_id, "Client EOF");
                        client_closed = true;
                        let _ =
                            enqueue_c2me_command(&c2me_tx, C2MeCommand::Close, c2me_send_timeout)
                                .await;
                        break;
                    }
                    Err(e) => {
                        main_result = Err(e);
                        break;
                    }
                }
            }
        }
    }

    drop(c2me_tx);
    let c2me_result = c2me_sender
        .await
        .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME sender join error: {e}"))));

    let _ = stop_tx.send(());
    let mut writer_result = me_writer
        .await
        .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME writer join error: {e}"))));

    // When client closes, but ME channel stopped as unregistered - it isnt error
    if client_closed
        && matches!(
            writer_result,
            Err(ProxyError::Proxy(ref msg)) if msg == "ME connection lost"
        )
    {
        writer_result = Ok(());
    }

    let result = match (main_result, c2me_result, writer_result) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(e), _, _) => Err(e),
        (_, Err(e), _) => Err(e),
        (_, _, Err(e)) => Err(e),
    };

    debug!(
        user = %user,
        conn_id,
        trace_id = format_args!("0x{:016x}", trace_id),
        duration_ms = forensics.started_at.elapsed().as_millis() as u64,
        bytes_c2me = forensics.bytes_c2me,
        bytes_me2c = forensics.bytes_me2c.load(Ordering::Relaxed),
        frames_ok = frame_counter,
        "ME relay cleanup"
    );
    clear_relay_idle_candidate(conn_id);
    me_pool.registry().unregister(conn_id).await;
    result
}

async fn read_client_payload_with_idle_policy<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
    idle_policy: &RelayClientIdlePolicy,
    idle_state: &mut RelayClientIdleState,
    last_downstream_activity_ms: &AtomicU64,
    session_started_at: Instant,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    const LEGACY_MAX_CONSECUTIVE_ZERO_LEN_FRAMES: u32 = 4;

    async fn read_exact_with_policy<R>(
        client_reader: &mut CryptoReader<R>,
        buf: &mut [u8],
        idle_policy: &RelayClientIdlePolicy,
        idle_state: &mut RelayClientIdleState,
        last_downstream_activity_ms: &AtomicU64,
        session_started_at: Instant,
        forensics: &RelayForensicsState,
        stats: &Stats,
        read_label: &'static str,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        fn hard_deadline(
            idle_policy: &RelayClientIdlePolicy,
            idle_state: &RelayClientIdleState,
            session_started_at: Instant,
            last_downstream_activity_ms: u64,
        ) -> Instant {
            let mut deadline = idle_state.last_client_frame_at + idle_policy.hard_idle;
            if idle_policy.grace_after_downstream_activity.is_zero() {
                return deadline;
            }

            let downstream_at =
                session_started_at + Duration::from_millis(last_downstream_activity_ms);
            if downstream_at > idle_state.last_client_frame_at {
                let grace_deadline = downstream_at + idle_policy.grace_after_downstream_activity;
                if grace_deadline > deadline {
                    deadline = grace_deadline;
                }
            }
            deadline
        }

        let mut filled = 0usize;
        while filled < buf.len() {
            let timeout_window = if idle_policy.enabled {
                let now = Instant::now();
                let downstream_ms = last_downstream_activity_ms.load(Ordering::Relaxed);
                let hard_deadline =
                    hard_deadline(idle_policy, idle_state, session_started_at, downstream_ms);
                if now >= hard_deadline {
                    clear_relay_idle_candidate(forensics.conn_id);
                    stats.increment_relay_idle_hard_close_total();
                    let client_idle_secs = now
                        .saturating_duration_since(idle_state.last_client_frame_at)
                        .as_secs();
                    let downstream_idle_secs = now
                        .saturating_duration_since(
                            session_started_at + Duration::from_millis(downstream_ms),
                        )
                        .as_secs();
                    warn!(
                        trace_id = format_args!("0x{:016x}", forensics.trace_id),
                        conn_id = forensics.conn_id,
                        user = %forensics.user,
                        read_label,
                        client_idle_secs,
                        downstream_idle_secs,
                        soft_idle_secs = idle_policy.soft_idle.as_secs(),
                        hard_idle_secs = idle_policy.hard_idle.as_secs(),
                        grace_secs = idle_policy.grace_after_downstream_activity.as_secs(),
                        "Middle-relay hard idle close"
                    );
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "middle-relay hard idle timeout while reading {read_label}: client_idle_secs={client_idle_secs}, downstream_idle_secs={downstream_idle_secs}, soft_idle_secs={}, hard_idle_secs={}, grace_secs={}",
                            idle_policy.soft_idle.as_secs(),
                            idle_policy.hard_idle.as_secs(),
                            idle_policy.grace_after_downstream_activity.as_secs(),
                        ),
                    )));
                }

                if !idle_state.soft_idle_marked
                    && now.saturating_duration_since(idle_state.last_client_frame_at)
                        >= idle_policy.soft_idle
                {
                    idle_state.soft_idle_marked = true;
                    if mark_relay_idle_candidate(forensics.conn_id) {
                        stats.increment_relay_idle_soft_mark_total();
                    }
                    info!(
                        trace_id = format_args!("0x{:016x}", forensics.trace_id),
                        conn_id = forensics.conn_id,
                        user = %forensics.user,
                        read_label,
                        soft_idle_secs = idle_policy.soft_idle.as_secs(),
                        hard_idle_secs = idle_policy.hard_idle.as_secs(),
                        grace_secs = idle_policy.grace_after_downstream_activity.as_secs(),
                        "Middle-relay soft idle mark"
                    );
                }

                let soft_deadline = idle_state.last_client_frame_at + idle_policy.soft_idle;
                let next_deadline = if idle_state.soft_idle_marked {
                    hard_deadline
                } else {
                    soft_deadline.min(hard_deadline)
                };
                let mut remaining = next_deadline.saturating_duration_since(now);
                if remaining.is_zero() {
                    remaining = Duration::from_millis(1);
                }
                remaining.min(RELAY_IDLE_IO_POLL_MAX)
            } else {
                idle_policy.legacy_frame_read_timeout
            };

            let read_result = timeout(timeout_window, client_reader.read(&mut buf[filled..])).await;
            match read_result {
                Ok(Ok(0)) => {
                    return Err(ProxyError::Io(std::io::Error::from(
                        std::io::ErrorKind::UnexpectedEof,
                    )));
                }
                Ok(Ok(n)) => {
                    filled = filled.saturating_add(n);
                }
                Ok(Err(e)) => return Err(ProxyError::Io(e)),
                Err(_) if !idle_policy.enabled => {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "middle-relay client frame read timeout while reading {read_label}"
                        ),
                    )));
                }
                Err(_) => {}
            }
        }

        Ok(())
    }

    let mut consecutive_zero_len_frames = 0u32;
    loop {
        let (len, quickack, raw_len_bytes) = match proto_tag {
            ProtoTag::Abridged => {
                let mut first = [0u8; 1];
                match read_exact_with_policy(
                    client_reader,
                    &mut first,
                    idle_policy,
                    idle_state,
                    last_downstream_activity_ms,
                    session_started_at,
                    forensics,
                    stats,
                    "abridged.first_len_byte",
                )
                .await
                {
                    Ok(()) => {}
                    Err(ProxyError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }

                let quickack = (first[0] & 0x80) != 0;
                let len_words = if (first[0] & 0x7f) == 0x7f {
                    let mut ext = [0u8; 3];
                    read_exact_with_policy(
                        client_reader,
                        &mut ext,
                        idle_policy,
                        idle_state,
                        last_downstream_activity_ms,
                        session_started_at,
                        forensics,
                        stats,
                        "abridged.extended_len",
                    )
                    .await?;
                    u32::from_le_bytes([ext[0], ext[1], ext[2], 0]) as usize
                } else {
                    (first[0] & 0x7f) as usize
                };

                let len = len_words
                    .checked_mul(4)
                    .ok_or_else(|| ProxyError::Proxy("Abridged frame length overflow".into()))?;
                (len, quickack, None)
            }
            ProtoTag::Intermediate | ProtoTag::Secure => {
                let mut len_buf = [0u8; 4];
                match read_exact_with_policy(
                    client_reader,
                    &mut len_buf,
                    idle_policy,
                    idle_state,
                    last_downstream_activity_ms,
                    session_started_at,
                    forensics,
                    stats,
                    "len_prefix",
                )
                .await
                {
                    Ok(()) => {}
                    Err(ProxyError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
                let quickack = (len_buf[3] & 0x80) != 0;
                (
                    (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize,
                    quickack,
                    Some(len_buf),
                )
            }
        };

        if len == 0 {
            idle_state.tiny_frame_debt = idle_state
                .tiny_frame_debt
                .saturating_add(TINY_FRAME_DEBT_PER_TINY);
            if idle_state.tiny_frame_debt >= TINY_FRAME_DEBT_LIMIT {
                stats.increment_relay_protocol_desync_close_total();
                return Err(ProxyError::Proxy(format!(
                    "Tiny frame overhead limit exceeded: debt={}, conn_id={}",
                    idle_state.tiny_frame_debt, forensics.conn_id
                )));
            }

            if !idle_policy.enabled {
                consecutive_zero_len_frames = consecutive_zero_len_frames.saturating_add(1);
                if consecutive_zero_len_frames > LEGACY_MAX_CONSECUTIVE_ZERO_LEN_FRAMES {
                    stats.increment_relay_protocol_desync_close_total();
                    return Err(ProxyError::Proxy(
                        "Excessive zero-length abridged frames".to_string(),
                    ));
                }
            }
            continue;
        }
        if len < 4 && proto_tag != ProtoTag::Abridged {
            warn!(
                trace_id = format_args!("0x{:016x}", forensics.trace_id),
                conn_id = forensics.conn_id,
                user = %forensics.user,
                len,
                proto = ?proto_tag,
                "Frame too small — corrupt or probe"
            );
            stats.increment_relay_protocol_desync_close_total();
            return Err(ProxyError::Proxy(format!("Frame too small: {len}")));
        }

        if len > max_frame {
            return Err(report_desync_frame_too_large(
                forensics,
                proto_tag,
                *frame_counter,
                max_frame,
                len,
                raw_len_bytes,
                stats,
            ));
        }

        let secure_payload_len = if proto_tag == ProtoTag::Secure {
            match secure_payload_len_from_wire_len(len) {
                Some(payload_len) => payload_len,
                None => {
                    stats.increment_secure_padding_invalid();
                    stats.increment_relay_protocol_desync_close_total();
                    return Err(ProxyError::Proxy(format!(
                        "Invalid secure frame length: {len}"
                    )));
                }
            }
        } else {
            len
        };

        let mut payload = buffer_pool.get();
        payload.clear();
        let current_cap = payload.capacity();
        if current_cap < len {
            payload.reserve(len - current_cap);
        }
        payload.resize(len, 0);
        read_exact_with_policy(
            client_reader,
            &mut payload[..len],
            idle_policy,
            idle_state,
            last_downstream_activity_ms,
            session_started_at,
            forensics,
            stats,
            "payload",
        )
        .await?;

        // Secure Intermediate: strip validated trailing padding bytes.
        if proto_tag == ProtoTag::Secure {
            payload.truncate(secure_payload_len);
        }
        *frame_counter += 1;
        idle_state.on_client_frame(Instant::now());
        idle_state.tiny_frame_debt = idle_state.tiny_frame_debt.saturating_sub(1);
        clear_relay_idle_candidate(forensics.conn_id);
        return Ok(Some((payload, quickack)));
    }
}

#[cfg(test)]
async fn read_client_payload_legacy<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    frame_read_timeout: Duration,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let now = Instant::now();
    let mut idle_state = RelayClientIdleState::new(now);
    let last_downstream_activity_ms = AtomicU64::new(0);
    let idle_policy = RelayClientIdlePolicy::disabled(frame_read_timeout);
    read_client_payload_with_idle_policy(
        client_reader,
        proto_tag,
        max_frame,
        buffer_pool,
        forensics,
        frame_counter,
        stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        now,
    )
    .await
}

#[cfg(test)]
async fn read_client_payload<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    frame_read_timeout: Duration,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    read_client_payload_legacy(
        client_reader,
        proto_tag,
        max_frame,
        frame_read_timeout,
        buffer_pool,
        forensics,
        frame_counter,
        stats,
    )
    .await
}

enum MeWriterResponseOutcome {
    Continue {
        frames: usize,
        bytes: usize,
        flush_immediately: bool,
    },
    Close,
}

async fn process_me_writer_response<W>(
    response: MeResponse,
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
    stats: &Stats,
    user: &str,
    quota_user_stats: Option<&UserStats>,
    quota_limit: Option<u64>,
    quota_soft_overshoot_bytes: u64,
    bytes_me2c: &AtomicU64,
    conn_id: u64,
    ack_flush_immediate: bool,
    batched: bool,
) -> Result<MeWriterResponseOutcome>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    match response {
        MeResponse::Data { flags, data } => {
            if batched {
                trace!(conn_id, bytes = data.len(), flags, "ME->C data (batched)");
            } else {
                trace!(conn_id, bytes = data.len(), flags, "ME->C data");
            }
            let data_len = data.len() as u64;
            if let (Some(limit), Some(user_stats)) = (quota_limit, quota_user_stats) {
                let soft_limit = quota_soft_cap(limit, quota_soft_overshoot_bytes);
                if reserve_user_quota_with_yield(user_stats, data_len, soft_limit)
                    .await
                    .is_err()
                {
                    stats.increment_me_d2c_quota_reject_total(MeD2cQuotaRejectStage::PreWrite);
                    return Err(ProxyError::DataQuotaExceeded {
                        user: user.to_string(),
                    });
                }
            }

            let write_mode =
                match write_client_payload(client_writer, proto_tag, flags, &data, rng, frame_buf)
                    .await
                {
                    Ok(mode) => mode,
                    Err(err) => {
                        if quota_limit.is_some() {
                            stats.add_quota_write_fail_bytes_total(data_len);
                            stats.increment_quota_write_fail_events_total();
                        }
                        return Err(err);
                    }
                };

            bytes_me2c.fetch_add(data_len, Ordering::Relaxed);
            if let Some(user_stats) = quota_user_stats {
                stats.add_user_octets_to_handle(user_stats, data_len);
            } else {
                stats.add_user_octets_to(user, data_len);
            }
            stats.increment_me_d2c_data_frames_total();
            stats.add_me_d2c_payload_bytes_total(data_len);
            stats.increment_me_d2c_write_mode(write_mode);

            Ok(MeWriterResponseOutcome::Continue {
                frames: 1,
                bytes: data.len(),
                flush_immediately: false,
            })
        }
        MeResponse::Ack(confirm) => {
            if batched {
                trace!(conn_id, confirm, "ME->C quickack (batched)");
            } else {
                trace!(conn_id, confirm, "ME->C quickack");
            }
            write_client_ack(client_writer, proto_tag, confirm).await?;
            stats.increment_me_d2c_ack_frames_total();

            Ok(MeWriterResponseOutcome::Continue {
                frames: 1,
                bytes: 4,
                flush_immediately: ack_flush_immediate,
            })
        }
        MeResponse::Close => {
            if batched {
                debug!(conn_id, "ME sent close (batched)");
            } else {
                debug!(conn_id, "ME sent close");
            }
            Ok(MeWriterResponseOutcome::Close)
        }
    }
}

fn compute_intermediate_secure_wire_len(
    data_len: usize,
    padding_len: usize,
    quickack: bool,
) -> Result<(u32, usize)> {
    let wire_len = data_len
        .checked_add(padding_len)
        .ok_or_else(|| ProxyError::Proxy("Frame length overflow".into()))?;
    if wire_len > 0x7fff_ffffusize {
        return Err(ProxyError::Proxy(format!(
            "Intermediate/Secure frame too large: {wire_len}"
        )));
    }

    let total = 4usize
        .checked_add(wire_len)
        .ok_or_else(|| ProxyError::Proxy("Frame buffer size overflow".into()))?;
    let mut len_val = u32::try_from(wire_len)
        .map_err(|_| ProxyError::Proxy("Frame length conversion overflow".into()))?;
    if quickack {
        len_val |= 0x8000_0000;
    }
    Ok((len_val, total))
}

async fn write_client_payload<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    flags: u32,
    data: &[u8],
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
) -> Result<MeD2cWriteMode>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let quickack = (flags & RPC_FLAG_QUICKACK) != 0;

    let write_mode = match proto_tag {
        ProtoTag::Abridged => {
            if !data.len().is_multiple_of(4) {
                return Err(ProxyError::Proxy(format!(
                    "Abridged payload must be 4-byte aligned, got {}",
                    data.len()
                )));
            }

            let len_words = data.len() / 4;
            if len_words < 0x7f {
                let mut first = len_words as u8;
                if quickack {
                    first |= 0x80;
                }
                let wire_len = 1usize.saturating_add(data.len());
                if wire_len <= ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES {
                    frame_buf.clear();
                    frame_buf.reserve(wire_len);
                    frame_buf.push(first);
                    frame_buf.extend_from_slice(data);
                    client_writer
                        .write_all(frame_buf.as_slice())
                        .await
                        .map_err(ProxyError::Io)?;
                    MeD2cWriteMode::Coalesced
                } else {
                    let header = [first];
                    client_writer
                        .write_all(&header)
                        .await
                        .map_err(ProxyError::Io)?;
                    client_writer
                        .write_all(data)
                        .await
                        .map_err(ProxyError::Io)?;
                    MeD2cWriteMode::Split
                }
            } else if len_words < (1 << 24) {
                let mut first = 0x7fu8;
                if quickack {
                    first |= 0x80;
                }
                let lw = (len_words as u32).to_le_bytes();
                let wire_len = 4usize.saturating_add(data.len());
                if wire_len <= ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES {
                    frame_buf.clear();
                    frame_buf.reserve(wire_len);
                    frame_buf.extend_from_slice(&[first, lw[0], lw[1], lw[2]]);
                    frame_buf.extend_from_slice(data);
                    client_writer
                        .write_all(frame_buf.as_slice())
                        .await
                        .map_err(ProxyError::Io)?;
                    MeD2cWriteMode::Coalesced
                } else {
                    let header = [first, lw[0], lw[1], lw[2]];
                    client_writer
                        .write_all(&header)
                        .await
                        .map_err(ProxyError::Io)?;
                    client_writer
                        .write_all(data)
                        .await
                        .map_err(ProxyError::Io)?;
                    MeD2cWriteMode::Split
                }
            } else {
                return Err(ProxyError::Proxy(format!(
                    "Abridged frame too large: {}",
                    data.len()
                )));
            }
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            let padding_len = if proto_tag == ProtoTag::Secure {
                if !is_valid_secure_payload_len(data.len()) {
                    return Err(ProxyError::Proxy(format!(
                        "Secure payload must be 4-byte aligned, got {}",
                        data.len()
                    )));
                }
                secure_padding_len(data.len(), rng)
            } else {
                0
            };

            let (len_val, total) =
                compute_intermediate_secure_wire_len(data.len(), padding_len, quickack)?;
            if total <= ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES {
                frame_buf.clear();
                frame_buf.reserve(total);
                frame_buf.extend_from_slice(&len_val.to_le_bytes());
                frame_buf.extend_from_slice(data);
                if padding_len > 0 {
                    let start = frame_buf.len();
                    frame_buf.resize(start + padding_len, 0);
                    rng.fill(&mut frame_buf[start..]);
                }
                client_writer
                    .write_all(frame_buf.as_slice())
                    .await
                    .map_err(ProxyError::Io)?;
                MeD2cWriteMode::Coalesced
            } else {
                let header = len_val.to_le_bytes();
                client_writer
                    .write_all(&header)
                    .await
                    .map_err(ProxyError::Io)?;
                client_writer
                    .write_all(data)
                    .await
                    .map_err(ProxyError::Io)?;
                if padding_len > 0 {
                    frame_buf.clear();
                    if frame_buf.capacity() < padding_len {
                        frame_buf.reserve(padding_len);
                    }
                    frame_buf.resize(padding_len, 0);
                    rng.fill(frame_buf.as_mut_slice());
                    client_writer
                        .write_all(frame_buf.as_slice())
                        .await
                        .map_err(ProxyError::Io)?;
                }
                MeD2cWriteMode::Split
            }
        }
    };

    Ok(write_mode)
}

async fn write_client_ack<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    confirm: u32,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let bytes = if proto_tag == ProtoTag::Abridged {
        confirm.to_be_bytes()
    } else {
        confirm.to_le_bytes()
    };
    client_writer
        .write_all(&bytes)
        .await
        .map_err(ProxyError::Io)
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
