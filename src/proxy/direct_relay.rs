use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::Result;
use crate::protocol::constants::*;
use crate::proxy::handshake::{HandshakeSuccess, encrypt_tg_nonce_with_ciphers, generate_tg_nonce};
use crate::proxy::relay::relay_bidirectional;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;

pub(crate) async fn handle_via_direct<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    upstream_manager: Arc<UpstreamManager>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = &success.user;
    let dc_addr = get_dc_addr_static(success.dc_idx, &config)?;

    info!(
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
    stats.increment_user_curr_connects(user);

    let relay_result = relay_bidirectional(
        client_reader,
        client_writer,
        tg_reader,
        tg_writer,
        user,
        Arc::clone(&stats),
        buffer_pool,
    )
    .await;

    stats.decrement_user_curr_connects(user);

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
        if let Some(path) = &config.general.unknown_dc_log_path
            && let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = writeln!(file, "dc_idx={dc_idx}");
        }
    }

    let default_dc = config.default_dc.unwrap_or(2) as usize;
    let fallback_idx = if default_dc >= 1 && default_dc <= num_dcs {
        default_dc - 1
    } else {
        1
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
        &success.dec_key,
        success.dec_iv,
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
