use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::proxy::handshake::{HandshakeSuccess, encrypt_tg_nonce_with_ciphers, generate_tg_nonce};
use crate::proxy::relay::relay_bidirectional;
use crate::proxy::route_mode::{
    RelayRouteMode, RouteCutoverState, ROUTE_SWITCH_ERROR_MSG, affected_cutover_state,
    cutover_stagger_delay,
};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;

const UNKNOWN_DC_LOG_DISTINCT_LIMIT: usize = 1024;
static LOGGED_UNKNOWN_DCS: OnceLock<Mutex<HashSet<i16>>> = OnceLock::new();

// In tests, this function shares global mutable state. Callers that also use
// cache-reset helpers must hold `unknown_dc_test_lock()` to keep assertions
// deterministic under parallel execution.
fn should_log_unknown_dc(dc_idx: i16) -> bool {
    let set = LOGGED_UNKNOWN_DCS.get_or_init(|| Mutex::new(HashSet::new()));
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
        // If the lock is poisoned, keep logging rather than silently dropping
        // operator-visible diagnostics.
        Err(_) => true,
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

    let tg_stream = upstream_manager
        .connect(dc_addr, Some(success.dc_idx), user.strip_prefix("scope_").filter(|s| !s.is_empty()))
        .await?;

    debug!(peer = %success.peer, dc_addr = %dc_addr, "Connected, performing TG handshake");

    let (tg_reader, tg_writer) =
        do_tg_handshake_static(tg_stream, &success, &config, rng.as_ref()).await?;

    debug!(peer = %success.peer, "TG handshake complete, starting relay");

    stats.increment_user_connects(user);
    stats.increment_current_connections_direct();

    let relay_result = relay_bidirectional(
        client_reader,
        client_writer,
        tg_reader,
        tg_writer,
        config.general.direct_relay_copy_buf_c2s_bytes,
        config.general.direct_relay_copy_buf_s2c_bytes,
        user,
        Arc::clone(&stats),
        buffer_pool,
    );
    tokio::pin!(relay_result);
    let relay_result = loop {
        if let Some(cutover) = affected_cutover_state(
            &route_rx,
            RelayRouteMode::Direct,
            route_snapshot.generation,
        ) {
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

    stats.decrement_current_connections_direct();

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
                Err(_) => warn!(dc_idx = dc_idx, addr_str = %addr_str, "Invalid DC override address in config, ignoring"),
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
        warn!(dc_idx = dc_idx, "Requested non-standard DC with no override; falling back to default cluster");
        if config.general.unknown_dc_file_log_enabled
            && let Some(path) = &config.general.unknown_dc_log_path
            && should_log_unknown_dc(dc_idx)
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let path = path.clone();
            handle.spawn_blocking(move || {
                if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                    let _ = writeln!(file, "dc_idx={dc_idx}");
                }
            });
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

async fn do_tg_handshake_static(
    mut stream: TcpStream,
    success: &HandshakeSuccess,
    config: &ProxyConfig,
    rng: &SecureRandom,
) -> Result<(
    CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    CryptoWriter<tokio::net::tcp::OwnedWriteHalf>,
)> {
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

    let (read_half, write_half) = stream.into_split();

    let max_pending = config.general.crypto_pending_buffer;
    Ok((
        CryptoReader::new(read_half, tg_decryptor),
        CryptoWriter::new(write_half, tg_encryptor, max_pending),
    ))
}

#[cfg(test)]
#[path = "direct_relay_security_tests.rs"]
mod security_tests;
