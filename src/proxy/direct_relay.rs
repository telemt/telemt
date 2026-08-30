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
use tokio_util::sync::CancellationToken;
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
    ConntrackCloseEvent, ConntrackClosePolicy, ConntrackClosePublishResult, ConntrackCloseReason,
    ProxySharedState,
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

// Direct relay lifecycle and conntrack publication.
mod relay;
// Telegram DC resolution and upstream handshake.
mod routing;

pub(crate) use relay::{
    handle_via_direct, handle_via_direct_with_shared, handle_via_direct_with_shared_and_conntrack,
};
use routing::*;
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
fn unknown_dc_test_lock() -> &'static tokio::sync::Mutex<()> {
    static TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
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
