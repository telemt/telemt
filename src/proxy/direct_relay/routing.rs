use super::*;

pub(super) fn get_dc_addr_static(dc_idx: i16, config: &ProxyConfig) -> Result<SocketAddr> {
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

pub(super) async fn do_tg_handshake_static<S>(
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
