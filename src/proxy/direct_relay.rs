use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::proxy::handshake::{HandshakeSuccess, encrypt_tg_nonce_with_ciphers, generate_tg_nonce};
use crate::proxy::relay::relay_bidirectional;
use crate::proxy::route_mode::{
    ROUTE_SWITCH_ERROR_MSG, RelayRouteMode, RouteCutoverState, affected_cutover_state,
    cutover_stagger_delay,
};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};

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

fn open_unknown_dc_log_append_anchored(path: &SanitizedUnknownDcLogPath) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path.allowed_parent)?;

        let file_name = std::ffi::CString::new(path.file_name.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown DC log file name contains NUL byte"))?;

        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                file_name.as_ptr(),
                libc::O_CREAT | libc::O_APPEND | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let file = unsafe { std::fs::File::from_raw_fd(fd) };
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
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let write_result = writeln!(file, "dc_idx={dc_idx}");

        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

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

pub(crate) async fn handle_via_direct<R, W>(
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

    let relay_result = relay_bidirectional(
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
            break Err(ProxyError::Proxy(ROUTE_SWITCH_ERROR_MSG.to_string()));
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

    relay_result
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
