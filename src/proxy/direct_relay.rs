use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::proxy::handshake::{HandshakeSuccess, encrypt_tg_nonce_with_ciphers, generate_tg_nonce};
use crate::proxy::route_mode::{
    RelayRouteMode, RouteCutoverState, affected_cutover_state, cutover_stagger_delay,
};
use crate::proxy::shared_state::{
    ConntrackCloseEvent, ConntrackClosePublishResult, ConntrackCloseReason, ProxySharedState,
};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg, OFlag, openat};
#[cfg(unix)]
use nix::sys::stat::Mode;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const UNKNOWN_DC_LOG_DISTINCT_LIMIT: usize = 1024;
static LOGGED_UNKNOWN_DCS: OnceLock<Mutex<HashSet<i16>>> = OnceLock::new();
const MAX_SCOPE_HINT_LEN: usize = 64;

fn validated_scope_hint(user: &str) -> Option<&str> {
    let scope = user.strip_prefix("scope_")?;
    if scope.is_empty() || scope.len() > MAX_SCOPE_HINT_LEN {
        return None;
    }
    if scope
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Some(scope)
    } else {
        None
    }
}

#[derive(Clone)]
struct SanitizedUnknownDcLogPath {
    resolved_path: PathBuf,
    allowed_parent: PathBuf,
    file_name: OsString,
}

// In tests, this function shares global mutable state. Callers that also use
// cache-reset helpers must hold `unknown_dc_test_lock()` to keep assertions
// deterministic under parallel execution.
fn should_log_unknown_dc(dc_idx: i16) -> bool {
    let set = LOGGED_UNKNOWN_DCS.get_or_init(|| Mutex::new(HashSet::new()));
    should_log_unknown_dc_with_set(set, dc_idx)
}

fn should_log_unknown_dc_with_set(set: &Mutex<HashSet<i16>>, dc_idx: i16) -> bool {
    match set.lock() {
        Ok(mut guard) => {
            if guard.contains(&dc_idx) {
                return false;
            }
            if guard.len() >= UNKNOWN_DC_LOG_DISTINCT_LIMIT {
                return false;
            }
            guard.insert(dc_idx)
        }
        // Fail closed on poisoned state to avoid unbounded blocking log writes.
        Err(_) => false,
    }
}

fn sanitize_unknown_dc_log_path(path: &str) -> Option<SanitizedUnknownDcLogPath> {
    let candidate = Path::new(path);
    if candidate.as_os_str().is_empty() {
        return None;
    }
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }

    let cwd = std::env::current_dir().ok()?;
    let file_name = candidate.file_name()?;
    let parent = candidate.parent().unwrap_or_else(|| Path::new("."));
    let parent_path = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        cwd.join(parent)
    };
    let canonical_parent = parent_path.canonicalize().ok()?;
    if !canonical_parent.is_dir() {
        return None;
    }

    Some(SanitizedUnknownDcLogPath {
        resolved_path: canonical_parent.join(file_name),
        allowed_parent: canonical_parent,
        file_name: file_name.to_os_string(),
    })
}

fn unknown_dc_log_path_is_still_safe(path: &SanitizedUnknownDcLogPath) -> bool {
    let Some(parent) = path.resolved_path.parent() else {
        return false;
    };
    let Ok(current_parent) = parent.canonicalize() else {
        return false;
    };
    if current_parent != path.allowed_parent {
        return false;
    }

    if let Ok(canonical_target) = path.resolved_path.canonicalize() {
        let Some(target_parent) = canonical_target.parent() else {
            return false;
        };
        let Some(target_name) = canonical_target.file_name() else {
            return false;
        };
        if target_parent != path.allowed_parent || target_name != path.file_name {
            return false;
        }
    }

    true
}

#[cfg(test)]
fn open_unknown_dc_log_append(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unknown_dc_file_log_enabled requires unix O_NOFOLLOW support",
        ))
    }
}

fn open_unknown_dc_log_append_anchored(
    path: &SanitizedUnknownDcLogPath,
) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path.allowed_parent)?;

        let oflags = OFlag::O_CREAT
            | OFlag::O_APPEND
            | OFlag::O_WRONLY
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC;
        let mode = Mode::from_bits_truncate(0o600);
        let path_component = Path::new(path.file_name.as_os_str());
        let fd = openat(&parent, path_component, oflags, mode)
            .map_err(|err| std::io::Error::from_raw_os_error(err as i32))?;
        let file = std::fs::File::from(fd);
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unknown_dc_file_log_enabled requires unix O_NOFOLLOW support",
        ))
    }
}

fn append_unknown_dc_line(file: &mut std::fs::File, dc_idx: i16) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let cloned = file.try_clone()?;
        let mut locked = Flock::lock(cloned, FlockArg::LockExclusive)
            .map_err(|(_, err)| std::io::Error::from_raw_os_error(err as i32))?;
        let write_result = writeln!(&mut *locked, "dc_idx={dc_idx}");
        let _ = locked
            .unlock()
            .map_err(|(_, err)| std::io::Error::from_raw_os_error(err as i32))?;
        write_result
    }
    #[cfg(not(unix))]
    {
        writeln!(file, "dc_idx={dc_idx}")
    }
}

#[cfg(test)]
fn clear_unknown_dc_log_cache_for_testing() {
    if let Some(set) = LOGGED_UNKNOWN_DCS.get()
        && let Ok(mut guard) = set.lock()
    {
        guard.clear();
    }
}

#[cfg(test)]
fn unknown_dc_test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

#[allow(dead_code)]
pub(crate) async fn handle_via_direct<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    upstream_manager: Arc<UpstreamManager>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_via_direct_with_shared(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats,
        config.clone(),
        buffer_pool,
        rng,
        route_rx,
        route_snapshot,
        session_id,
        SocketAddr::from(([0, 0, 0, 0], config.server.port)),
        ProxySharedState::new(),
    )
    .await
}

pub(crate) async fn handle_via_direct_with_shared<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    upstream_manager: Arc<UpstreamManager>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    mut route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
    local_addr: SocketAddr,
    shared: Arc<ProxySharedState>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = &success.user;
    let dc_addr = get_dc_addr_static(success.dc_idx, &config)?;

    debug!(
        user = %user,
        peer = %success.peer,
        dc = success.dc_idx,
        dc_addr = %dc_addr,
        proto = ?success.proto_tag,
        mode = "direct",
        "Connecting to Telegram DC"
    );

    let scope_hint = validated_scope_hint(user);
    if user.starts_with("scope_") && scope_hint.is_none() {
        warn!(
            user = %user,
            "Ignoring invalid scope hint and falling back to default upstream selection"
        );
    }
    let tg_stream = upstream_manager
        .connect(dc_addr, Some(success.dc_idx), scope_hint)
        .await?;

    debug!(peer = %success.peer, dc_addr = %dc_addr, "Connected, performing TG handshake");

    let (tg_reader, tg_writer) =
        do_tg_handshake_static(tg_stream, &success, &config, rng.as_ref()).await?;

    debug!(peer = %success.peer, "TG handshake complete, starting relay");

    stats.increment_user_connects(user);
    let _direct_connection_lease = stats.acquire_direct_connection_lease();
    let traffic_lease = shared
        .traffic_limiter
        .acquire_lease(user, success.peer.ip());

    let buffer_pool_trim = Arc::clone(&buffer_pool);
    let relay_activity_timeout = if shared.conntrack_pressure_active() {
        Duration::from_secs(
            config
                .server
                .conntrack_control
                .profile
                .direct_activity_timeout_secs(),
        )
    } else {
        Duration::from_secs(1800)
    };
    let relay_result = crate::proxy::relay::relay_bidirectional_with_activity_timeout_and_lease(
        client_reader,
        client_writer,
        tg_reader,
        tg_writer,
        config.general.direct_relay_copy_buf_c2s_bytes,
        config.general.direct_relay_copy_buf_s2c_bytes,
        user,
        Arc::clone(&stats),
        config.access.user_data_quota.get(user).copied(),
        buffer_pool,
        traffic_lease,
        relay_activity_timeout,
    );
    tokio::pin!(relay_result);
    let relay_result = loop {
        if let Some(cutover) =
            affected_cutover_state(&route_rx, RelayRouteMode::Direct, route_snapshot.generation)
        {
            let delay = cutover_stagger_delay(session_id, cutover.generation);
            warn!(
                user = %user,
                target_mode = cutover.mode.as_str(),
                cutover_generation = cutover.generation,
                delay_ms = delay.as_millis() as u64,
                "Cutover affected direct session, closing client connection"
            );
            tokio::time::sleep(delay).await;
            break Err(ProxyError::RouteSwitched);
        }
        tokio::select! {
            result = &mut relay_result => {
                break result;
            }
            changed = route_rx.changed() => {
                if changed.is_err() {
                    break relay_result.await;
                }
            }
        }
    };

    match &relay_result {
        Ok(()) => debug!(user = %user, "Direct relay completed"),
        Err(e) => debug!(user = %user, error = %e, "Direct relay ended with error"),
    }

    buffer_pool_trim.trim_to(buffer_pool_trim.max_buffers().min(64));
    let pool_snapshot = buffer_pool_trim.stats();
    stats.set_buffer_pool_gauges(
        pool_snapshot.pooled,
        pool_snapshot.allocated,
        pool_snapshot.allocated.saturating_sub(pool_snapshot.pooled),
    );

    let close_reason = classify_conntrack_close_reason(&relay_result);
    let publish_result = shared.publish_conntrack_close_event(ConntrackCloseEvent {
        src: success.peer,
        dst: local_addr,
        reason: close_reason,
    });
    if !matches!(
        publish_result,
        ConntrackClosePublishResult::Sent | ConntrackClosePublishResult::Disabled
    ) {
        stats.increment_conntrack_close_event_drop_total();
    }

    relay_result
}

fn classify_conntrack_close_reason(result: &Result<()>) -> ConntrackCloseReason {
    match result {
        Ok(()) => ConntrackCloseReason::NormalEof,
        Err(crate::error::ProxyError::Io(error))
            if matches!(error.kind(), std::io::ErrorKind::TimedOut) =>
        {
            ConntrackCloseReason::Timeout
        }
        Err(crate::error::ProxyError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            ConntrackCloseReason::Reset
        }
        Err(crate::error::ProxyError::Proxy(message))
            if message.contains("pressure") || message.contains("evicted") =>
        {
            ConntrackCloseReason::Pressure
        }
        Err(_) => ConntrackCloseReason::Other,
    }
}

fn get_dc_addr_static(dc_idx: i16, config: &ProxyConfig) -> Result<SocketAddr> {
    let prefer_v6 = config.network.prefer == 6 && config.network.ipv6.unwrap_or(true);
    let datacenters = if prefer_v6 {
        &*TG_DATACENTERS_V6
    } else {
        &*TG_DATACENTERS_V4
    };

    let num_dcs = datacenters.len();

    let dc_key = dc_idx.to_string();
    if let Some(addrs) = config.dc_overrides.get(&dc_key) {
        let mut parsed = Vec::new();
        for addr_str in addrs {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => parsed.push(addr),
                Err(_) => {
                    warn!(dc_idx = dc_idx, addr_str = %addr_str, "Invalid DC override address in config, ignoring")
                }
            }
        }

        if let Some(addr) = parsed
            .iter()
            .find(|a| a.is_ipv6() == prefer_v6)
            .or_else(|| parsed.first())
            .copied()
        {
            debug!(dc_idx = dc_idx, addr = %addr, count = parsed.len(), "Using DC override from config");
            return Ok(addr);
        }
    }

    let abs_dc = dc_idx.unsigned_abs() as usize;
    if abs_dc >= 1 && abs_dc <= num_dcs {
        return Ok(SocketAddr::new(datacenters[abs_dc - 1], TG_DATACENTER_PORT));
    }

    // Unknown DC requested by client without override: log and fall back.
    if !config.dc_overrides.contains_key(&dc_key) {
        warn!(
            dc_idx = dc_idx,
            "Requested non-standard DC with no override; falling back to default cluster"
        );
        if config.general.unknown_dc_file_log_enabled
            && let Some(path) = &config.general.unknown_dc_log_path
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            if let Some(path) = sanitize_unknown_dc_log_path(path) {
                if should_log_unknown_dc(dc_idx) {
                    handle.spawn_blocking(move || {
                        if unknown_dc_log_path_is_still_safe(&path)
                            && let Ok(mut file) = open_unknown_dc_log_append_anchored(&path)
                        {
                            let _ = append_unknown_dc_line(&mut file, dc_idx);
                        }
                    });
                }
            } else {
                warn!(dc_idx = dc_idx, raw_path = %path, "Rejected unsafe unknown DC log path");
            }
        }
    }

    let default_dc = config.default_dc.unwrap_or(2) as usize;
    let fallback_idx = if default_dc >= 1 && default_dc <= num_dcs {
        default_dc - 1
    } else {
        0
    };

    info!(
        original_dc = dc_idx,
        fallback_dc = (fallback_idx + 1) as u16,
        fallback_addr = %datacenters[fallback_idx],
        "Special DC ---> default_cluster"
    );

    Ok(SocketAddr::new(
        datacenters[fallback_idx],
        TG_DATACENTER_PORT,
    ))
}

async fn do_tg_handshake_static<S>(
    mut stream: S,
    success: &HandshakeSuccess,
    config: &ProxyConfig,
    rng: &SecureRandom,
) -> Result<(CryptoReader<ReadHalf<S>>, CryptoWriter<WriteHalf<S>>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (nonce, _tg_enc_key, _tg_enc_iv, _tg_dec_key, _tg_dec_iv) = generate_tg_nonce(
        success.proto_tag,
        success.dc_idx,
        &success.enc_key,
        success.enc_iv,
        rng,
        config.general.fast_mode,
    );

    let (encrypted_nonce, tg_encryptor, tg_decryptor) = encrypt_tg_nonce_with_ciphers(&nonce);

    debug!(
        peer = %success.peer,
        nonce_head = %hex::encode(&nonce[..16]),
        "Sending nonce to Telegram"
    );

    stream.write_all(&encrypted_nonce).await?;
    stream.flush().await?;

    let (read_half, write_half) = split(stream);

    let max_pending = config.general.crypto_pending_buffer;
    Ok((
        CryptoReader::new(read_half, tg_decryptor),
        CryptoWriter::new(write_half, tg_encryptor, max_pending),
    ))
}

#[cfg(test)]
mod pure_helpers_tests {
    use super::*;

    // ============= validated_scope_hint =============

    #[test]
    fn validated_scope_hint_accepts_well_formed_scopes() {
        assert_eq!(validated_scope_hint("scope_eu-west-1"), Some("eu-west-1"));
        assert_eq!(validated_scope_hint("scope_a"), Some("a"));
        assert_eq!(validated_scope_hint("scope_123-xyz"), Some("123-xyz"));
    }

    #[test]
    fn validated_scope_hint_rejects_users_without_prefix() {
        assert!(validated_scope_hint("alice").is_none());
        assert!(validated_scope_hint("scope").is_none());
        assert!(validated_scope_hint("Scope_eu").is_none()); // case-sensitive prefix
        assert!(validated_scope_hint("").is_none());
    }

    #[test]
    fn validated_scope_hint_rejects_empty_or_oversized_scope() {
        assert!(validated_scope_hint("scope_").is_none());
        let too_long = format!("scope_{}", "a".repeat(MAX_SCOPE_HINT_LEN + 1));
        assert!(validated_scope_hint(&too_long).is_none());

        // Boundary: exactly MAX is allowed.
        let max = format!("scope_{}", "a".repeat(MAX_SCOPE_HINT_LEN));
        assert_eq!(
            validated_scope_hint(&max),
            Some(&max[6..]),
            "MAX_SCOPE_HINT_LEN boundary must be inclusive"
        );
    }

    #[test]
    fn validated_scope_hint_rejects_non_alnum_dash_chars() {
        assert!(validated_scope_hint("scope_eu_west").is_none()); // underscore
        assert!(validated_scope_hint("scope_eu.west").is_none()); // dot
        assert!(validated_scope_hint("scope_eu west").is_none()); // space
        assert!(validated_scope_hint("scope_eu/west").is_none()); // slash
    }

    // ============= classify_conntrack_close_reason =============

    fn io_err(kind: std::io::ErrorKind) -> ProxyError {
        ProxyError::Io(std::io::Error::new(kind, "test"))
    }

    #[test]
    fn classify_close_reason_ok_is_normal_eof() {
        let r: Result<()> = Ok(());
        assert!(matches!(
            classify_conntrack_close_reason(&r),
            ConntrackCloseReason::NormalEof
        ));
    }

    #[test]
    fn classify_close_reason_timeout_is_timeout() {
        let r: Result<()> = Err(io_err(std::io::ErrorKind::TimedOut));
        assert!(matches!(
            classify_conntrack_close_reason(&r),
            ConntrackCloseReason::Timeout
        ));
    }

    #[test]
    fn classify_close_reason_reset_family_is_reset() {
        // The five "client-disappeared" io::ErrorKinds all classify as Reset.
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::NotConnected,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let r: Result<()> = Err(io_err(kind));
            assert!(
                matches!(
                    classify_conntrack_close_reason(&r),
                    ConntrackCloseReason::Reset
                ),
                "expected Reset for {:?}",
                kind
            );
        }
    }

    #[test]
    fn classify_close_reason_pressure_keyword_is_pressure() {
        let r: Result<()> = Err(ProxyError::Proxy("backpressure exceeded".to_string()));
        assert!(matches!(
            classify_conntrack_close_reason(&r),
            ConntrackCloseReason::Pressure
        ));
        let r: Result<()> = Err(ProxyError::Proxy(
            "session evicted by admission control".to_string(),
        ));
        assert!(matches!(
            classify_conntrack_close_reason(&r),
            ConntrackCloseReason::Pressure
        ));
    }

    #[test]
    fn classify_close_reason_unrelated_errors_are_other() {
        let r: Result<()> = Err(ProxyError::Proxy("unrelated message".to_string()));
        assert!(matches!(
            classify_conntrack_close_reason(&r),
            ConntrackCloseReason::Other
        ));
        let r: Result<()> = Err(io_err(std::io::ErrorKind::PermissionDenied));
        assert!(matches!(
            classify_conntrack_close_reason(&r),
            ConntrackCloseReason::Other
        ));
    }

    // ============= should_log_unknown_dc_with_set =============
    //
    // Pure variant taking an explicit set — easy to drive without touching
    // the global `LOGGED_UNKNOWN_DCS` static.

    #[test]
    fn should_log_unknown_dc_returns_true_only_for_first_sight() {
        let set = Mutex::new(HashSet::new());
        assert!(should_log_unknown_dc_with_set(&set, 999));
        // Same dc seen again must NOT relog.
        assert!(!should_log_unknown_dc_with_set(&set, 999));
        // Different dc still loggable.
        assert!(should_log_unknown_dc_with_set(&set, 1000));
    }

    #[test]
    fn should_log_unknown_dc_respects_distinct_limit() {
        let set = Mutex::new(HashSet::new());
        // Fill to the cap.
        for i in 0..UNKNOWN_DC_LOG_DISTINCT_LIMIT as i16 {
            assert!(should_log_unknown_dc_with_set(&set, i));
        }
        // Next unseen dc must be rejected — at the cap.
        assert!(!should_log_unknown_dc_with_set(
            &set,
            UNKNOWN_DC_LOG_DISTINCT_LIMIT as i16 + 1
        ));
    }

    #[test]
    fn should_log_unknown_dc_handles_negative_and_extreme_indices() {
        let set = Mutex::new(HashSet::new());
        assert!(should_log_unknown_dc_with_set(&set, i16::MIN));
        assert!(should_log_unknown_dc_with_set(&set, i16::MAX));
        assert!(should_log_unknown_dc_with_set(&set, 0));
        assert!(should_log_unknown_dc_with_set(&set, -1));
        // Each re-seen index returns false.
        assert!(!should_log_unknown_dc_with_set(&set, i16::MIN));
        assert!(!should_log_unknown_dc_with_set(&set, 0));
    }

    // ============= classify_conntrack_close_reason — extended variant coverage =============

    #[test]
    fn classify_close_reason_other_variants() {
        // All ProxyError variants that have no dedicated mapping in
        // classify_conntrack_close_reason must fall through to `Other`.
        // Collapsed from per-variant tests — one assertion per variant
        // with a descriptive failure message identifies regressions just
        // as precisely.
        let cases: Vec<Result<()>> = vec![
            Err(ProxyError::Crypto("aes failed".to_string())),
            Err(ProxyError::InvalidKeyLength { expected: 32, got: 16 }),
            Err(ProxyError::InvalidHandshake("bad padding".to_string())),
            Err(ProxyError::InvalidProtoTag([0xDE, 0xAD, 0xBE, 0xEF])),
            Err(ProxyError::RouteSwitched),
            Err(ProxyError::MiddleConnectionLost),
            Err(ProxyError::TgHandshakeTimeout),
            Err(ProxyError::ConnectionTimeout {
                addr: "149.154.175.50:443".to_string(),
            }),
            Err(ProxyError::ConnectionRefused {
                addr: "149.154.175.50:443".to_string(),
            }),
            Err(ProxyError::RateLimited),
            Err(ProxyError::Internal("bug".to_string())),
            Err(ProxyError::UnknownUser),
            Err(ProxyError::Config("missing field".to_string())),
            Err(ProxyError::TlsHandshakeFailed {
                reason: "cert rejected".to_string(),
            }),
        ];
        for variant in &cases {
            let reason = classify_conntrack_close_reason(variant);
            assert!(
                matches!(reason, ConntrackCloseReason::Other),
                "variant {:?} should classify as Other, got {:?}",
                variant,
                reason
            );
        }
    }

    // ============= get_dc_addr_static — boundary & edge cases =============

    #[test]
    fn dc_addr_zero_falls_to_default_fallback() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        let addr = get_dc_addr_static(0, &cfg).expect("dc_idx=0 must resolve to fallback");

        // default_dc is None → falls to 2 → TG_DATACENTERS_V4[1]:443
        let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_six_out_of_range_falls_to_default() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        let addr = get_dc_addr_static(6, &cfg).expect("dc_idx=6 must resolve to fallback");

        let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_negative_one_maps_to_dc1() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        let addr = get_dc_addr_static(-1, &cfg).expect("dc_idx=-1 must resolve via abs");

        let expected = SocketAddr::new(TG_DATACENTERS_V4[0], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_negative_five_maps_to_dc5() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        let addr = get_dc_addr_static(-5, &cfg).expect("dc_idx=-5 must resolve via abs");

        let expected = SocketAddr::new(TG_DATACENTERS_V4[4], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_negative_six_out_of_range_falls_to_default() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        let addr = get_dc_addr_static(-6, &cfg).expect("dc_idx=-6 must resolve to fallback");

        let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_default_dc_none_falls_to_dc2() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        assert!(cfg.default_dc.is_none());

        let addr = get_dc_addr_static(99, &cfg).expect("unknown dc must resolve via fallback");
        let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_default_dc_out_of_range_clamps_to_first() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let mut cfg = ProxyConfig::default();
        cfg.default_dc = Some(42);

        let addr = get_dc_addr_static(99, &cfg).expect("unknown dc with bad default must still resolve");
        let expected = SocketAddr::new(TG_DATACENTERS_V4[0], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_override_empty_vec_falls_to_static_table() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let mut cfg = ProxyConfig::default();
        cfg.dc_overrides.insert("2".to_string(), vec![]);

        let addr = get_dc_addr_static(2, &cfg).expect("empty override must fall to static table");
        let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
        assert_eq!(addr, expected);
    }

    #[test]
    fn dc_addr_prefer_v4_with_only_ipv6_override_degrades_to_first() {
        let mut cfg = ProxyConfig::default();
        // prefer=4 is default, ipv6 is Some(false) by default
        assert_eq!(cfg.network.prefer, 4);
        cfg.dc_overrides.insert(
            "2".to_string(),
            vec!["[2001:db8::1]:443".to_string()],
        );

        let addr = get_dc_addr_static(2, &cfg).expect("ipv6-only override with prefer=4 must degrade");
        assert_eq!(addr, "[2001:db8::1]:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn dc_addr_all_valid_dcs_resolve_to_correct_ipv4() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        for dc in 1..=5i16 {
            let addr = get_dc_addr_static(dc, &cfg).unwrap_or_else(|e| {
                panic!("dc_idx={dc} must resolve: {e}")
            });
            let expected = SocketAddr::new(TG_DATACENTERS_V4[(dc - 1) as usize], TG_DATACENTER_PORT);
            assert_eq!(addr, expected, "mismatch for dc_idx={dc}");
        }
    }

    #[test]
    fn dc_addr_all_negative_valid_dcs_resolve_to_correct_ipv4() {
        use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};

        let cfg = ProxyConfig::default();
        for dc in -1..=-5i16 {
            let abs_dc = dc.unsigned_abs() as usize;
            let addr = get_dc_addr_static(dc, &cfg).unwrap_or_else(|e| {
                panic!("dc_idx={dc} must resolve: {e}")
            });
            let expected = SocketAddr::new(TG_DATACENTERS_V4[abs_dc - 1], TG_DATACENTER_PORT);
            assert_eq!(addr, expected, "mismatch for dc_idx={dc}");
        }
    }

    #[test]
    fn dc_addr_override_mixed_v4_v6_prefers_matching_family() {
        let mut cfg = ProxyConfig::default();
        // prefer=4 (default) should pick the IPv4 entry
        cfg.dc_overrides.insert(
            "3".to_string(),
            vec![
                "[2001:db8::1]:443".to_string(),
                "198.51.100.7:443".to_string(),
            ],
        );

        let addr = get_dc_addr_static(3, &cfg).expect("must resolve");
        assert!(
            addr.is_ipv4(),
            "prefer=4 must select IPv4 override, got {addr}"
        );
        assert_eq!(addr, "198.51.100.7:443".parse::<SocketAddr>().unwrap());
    }

    // ============= validated_scope_hint — additional edge cases =============

    #[test]
    fn scope_hint_allows_max_boundary_length() {
        let max_scope = "a".repeat(MAX_SCOPE_HINT_LEN);
        let input = format!("scope_{max_scope}");
        assert_eq!(
            validated_scope_hint(&input),
            Some(max_scope.as_str()),
            "exactly MAX_SCOPE_HINT_LEN chars must be accepted"
        );
    }

    #[test]
    fn scope_hint_rejects_one_over_max() {
        let over = "a".repeat(MAX_SCOPE_HINT_LEN + 1);
        let input = format!("scope_{over}");
        assert_eq!(validated_scope_hint(&input), None);
    }

    #[test]
    fn scope_hint_allows_digits_only() {
        assert_eq!(validated_scope_hint("scope_123456"), Some("123456"));
    }

    #[test]
    fn scope_hint_allows_hyphen_only_scope() {
        assert_eq!(validated_scope_hint("scope_a-b-c"), Some("a-b-c"));
    }

    // ============= should_log_unknown_dc_with_set — edge cases =============

    #[test]
    fn should_log_dc_poisoned_mutex_returns_false() {
        use std::sync::Mutex;

        let _set: Mutex<HashSet<i16>> = Mutex::new(HashSet::new());
        // The empty set is unused — the actual poisoned set is created below.

        // Manually poison: create a Mutex, lock it, then panic inside a catch.
        let poisoned: Mutex<HashSet<i16>> = Mutex::new(HashSet::new());
        let _ = std::panic::catch_unwind(|| {
            let _g = poisoned.lock().unwrap();
            panic!("intentional poison");
        });
        assert!(
            !should_log_unknown_dc_with_set(&poisoned, 42),
            "poisoned mutex must return false (fail-closed)"
        );
    }

    #[test]
    fn should_log_dc_returns_false_for_repeated_within_limit() {
        let set = Mutex::new(HashSet::new());
        assert!(should_log_unknown_dc_with_set(&set, 7));
        assert!(!should_log_unknown_dc_with_set(&set, 7));
        assert!(!should_log_unknown_dc_with_set(&set, 7));
        // Still can log new dc.
        assert!(should_log_unknown_dc_with_set(&set, 8));
    }
}

#[cfg(test)]
#[path = "tests/direct_relay_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/direct_relay_business_logic_tests.rs"]
mod business_logic_tests;

#[cfg(test)]
#[path = "tests/direct_relay_common_mistakes_tests.rs"]
mod common_mistakes_tests;

#[cfg(test)]
#[path = "tests/direct_relay_subtle_adversarial_tests.rs"]
mod subtle_adversarial_tests;

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn should_log_unknown_dc_first_sight_true_replay_false(
            dc_idx in any::<i16>()
        ) {
            let set = Mutex::new(HashSet::new());
            let first = should_log_unknown_dc_with_set(&set, dc_idx);
            prop_assert!(first, "first sight of dc_idx={dc_idx} must log");
            let replay = should_log_unknown_dc_with_set(&set, dc_idx);
            prop_assert!(!replay, "second sight of dc_idx={dc_idx} must not log");
        }
    }
}
