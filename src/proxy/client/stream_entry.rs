use super::*;

#[cfg(test)]
pub async fn handle_client_stream<S>(
    stream: S,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    proxy_protocol_enabled: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_stream_with_shared(
        stream,
        peer,
        config,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        me_pool,
        route_runtime,
        tls_cache,
        ip_tracker,
        beobachten,
        ProxySharedState::new(),
        proxy_protocol_enabled,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub async fn handle_client_stream_with_shared<S>(
    stream: S,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    shared: Arc<ProxySharedState>,
    proxy_protocol_enabled: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_stream_with_shared_and_pool_runtime(
        stream,
        peer,
        config,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        me_pool,
        None,
        route_runtime,
        tls_cache,
        ip_tracker,
        beobachten,
        shared,
        proxy_protocol_enabled,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client_stream_with_shared_and_pool_runtime<S>(
    mut stream: S,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    me_pool_runtime: Option<Arc<RwLock<Option<Arc<MePool>>>>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    shared: Arc<ProxySharedState>,
    proxy_protocol_enabled: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stats.increment_connects_all();
    let mut real_peer = normalize_ip(peer);

    // For non-TCP streams, use a synthetic local address; may be overridden by PROXY protocol dst
    let mut local_addr = synthetic_local_addr(config.server.port);

    if proxy_protocol_enabled {
        if !is_trusted_proxy_source(peer.ip(), &config.server.proxy_protocol_trusted_cidrs) {
            stats.increment_connects_bad_with_class("proxy_protocol_untrusted");
            warn!(
                peer = %peer,
                trusted = ?config.server.proxy_protocol_trusted_cidrs,
                "Rejecting PROXY protocol header from untrusted source"
            );
            record_beobachten_class(&beobachten, &config, peer.ip(), "other");
            return Err(ProxyError::InvalidProxyProtocol);
        }

        let proxy_header_timeout =
            Duration::from_millis(config.server.proxy_protocol_header_timeout_ms.max(1));
        match timeout(
            proxy_header_timeout,
            parse_proxy_protocol(&mut stream, peer),
        )
        .await
        {
            Ok(Ok(info)) => {
                debug!(
                    peer = %peer,
                    client = %info.src_addr,
                    version = info.version,
                    "PROXY protocol header parsed"
                );
                real_peer = normalize_ip(info.src_addr);
                if let Some(dst) = info.dst_addr {
                    local_addr = dst;
                }
            }
            Ok(Err(e)) => {
                stats.increment_connects_bad_with_class("proxy_protocol_invalid_header");
                warn!(peer = %peer, error = %e, "Invalid PROXY protocol header");
                record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                return Err(e);
            }
            Err(_) => {
                stats.increment_connects_bad_with_class("proxy_protocol_header_timeout");
                warn!(peer = %peer, timeout_ms = proxy_header_timeout.as_millis(), "PROXY protocol header timeout");
                record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                return Err(ProxyError::InvalidProxyProtocol);
            }
        }
    }

    debug!(peer = %real_peer, "New connection (generic stream)");

    let first_byte_idle_secs = effective_client_first_byte_idle_secs(&config, shared.as_ref());
    let first_byte = if first_byte_idle_secs == 0 {
        None
    } else {
        let idle_timeout = Duration::from_secs(first_byte_idle_secs);
        let mut first_byte = [0u8; 1];
        match timeout(idle_timeout, stream.read(&mut first_byte)).await {
            Ok(Ok(0)) => {
                debug!(peer = %real_peer, "Connection closed before first client byte");
                return Ok(());
            }
            Ok(Ok(_)) => Some(first_byte[0]),
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                debug!(
                    peer = %real_peer,
                    error = %e,
                    "Connection closed before first client byte"
                );
                return Ok(());
            }
            Ok(Err(e)) => {
                debug!(
                    peer = %real_peer,
                    error = %e,
                    "Failed while waiting for first client byte"
                );
                return Err(ProxyError::Io(e));
            }
            Err(_) => {
                debug!(
                    peer = %real_peer,
                    idle_secs = first_byte_idle_secs,
                    "Closing idle pooled connection before first client byte"
                );
                return Ok(());
            }
        }
    };

    let handshake_timeout = handshake_timeout_with_mask_grace(&config);
    let stats_for_timeout = stats.clone();
    let config_for_timeout = config.clone();
    let beobachten_for_timeout = beobachten.clone();
    let peer_for_timeout = real_peer.ip();

    // Phase 2: active handshake (with timeout after the first client byte)
    let outcome = match timeout(handshake_timeout, async {
        let mut first_bytes = [0u8; 5];
        if let Some(first_byte) = first_byte {
            first_bytes[0] = first_byte;
            stream.read_exact(&mut first_bytes[1..]).await?;
        } else {
            stream.read_exact(&mut first_bytes).await?;
        }

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        debug!(peer = %real_peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

            // RFC 8446 §5.1: TLS record payload MUST NOT exceed 2^14 (16_384) bytes.
            // Lower bound is a structural minimum for a valid TLS 1.3 ClientHello
            // (record header + handshake header + random + session_id + cipher_suites
            // + compression + at least one extension with SNI). The previous value of
            // 512 was implicitly coupled to TLS_REQUEST_LENGTH=517 from the official
            // Telegram MTProxy reference server, leaving only a 5-byte margin and
            // incorrectly rejecting compact but spec-compliant ClientHellos from
            // third-party clients or future Telegram versions.
            if !tls_clienthello_len_in_bounds(tls_len) {
                debug!(peer = %real_peer, tls_len = tls_len, max_tls_len = MAX_TLS_PLAINTEXT_SIZE, "TLS handshake length out of bounds");
                stats.increment_connects_bad_with_class("tls_clienthello_len_out_of_bounds");
                maybe_apply_mask_reject_delay(&config).await;
                let (reader, writer) = tokio::io::split(stream);
                return Ok(masking_outcome(
                    reader,
                    writer,
                    first_bytes.to_vec(),
                    real_peer,
                    local_addr,
                    config.clone(),
                    upstream_manager.clone(),
                    beobachten.clone(),
                    shared.clone(),
                ));
            }

            let mut handshake = vec![0u8; 5 + tls_len];
            handshake[..5].copy_from_slice(&first_bytes);
            let body_read = match read_with_progress(&mut stream, &mut handshake[5..]).await {
                Ok(n) => n,
                Err(e) => {
                    debug!(peer = %real_peer, error = %e, tls_len = tls_len, "TLS ClientHello body read failed; engaging masking fallback");
                    stats.increment_connects_bad_with_class("tls_clienthello_read_error");
                    maybe_apply_mask_reject_delay(&config).await;
                    let initial_len = 5;
                    let (reader, writer) = tokio::io::split(stream);
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        handshake[..initial_len].to_vec(),
                        real_peer,
                        local_addr,
                        config.clone(),
                        upstream_manager.clone(),
                        beobachten.clone(),
                        shared.clone(),
                    ));
                }
            };

            if body_read < tls_len {
                debug!(peer = %real_peer, got = body_read, expected = tls_len, "Truncated in-range TLS ClientHello; engaging masking fallback");
                stats.increment_connects_bad_with_class("tls_clienthello_truncated");
                maybe_apply_mask_reject_delay(&config).await;
                let initial_len = 5 + body_read;
                let (reader, writer) = tokio::io::split(stream);
                return Ok(masking_outcome(
                    reader,
                    writer,
                    handshake[..initial_len].to_vec(),
                    real_peer,
                    local_addr,
                    config.clone(),
                    upstream_manager.clone(),
                    beobachten.clone(),
                    shared.clone(),
                ));
            }

            let tls_fingerprint =
                observe_tls_client_fingerprint(stats.as_ref(), &config, real_peer.ip(), &handshake);

            let (read_half, write_half) = tokio::io::split(stream);

            let (mut tls_reader, tls_writer, tls_user) = match handle_tls_handshake_with_shared(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, &rng, tls_cache.clone(),
                shared.as_ref(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad_with_class("tls_handshake_bad_client");
                    record_tls_fingerprint_bad_or_probe(
                        stats.as_ref(),
                        &config,
                        real_peer.ip(),
                        tls_fingerprint.as_ref(),
                    );
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        handshake.clone(),
                        real_peer,
                        local_addr,
                        config.clone(),
                        upstream_manager.clone(),
                        beobachten.clone(),
                        shared.clone(),
                    ));
                }
                HandshakeResult::Error(e) => {
                    record_tls_fingerprint_bad_or_probe(
                        stats.as_ref(),
                        &config,
                        real_peer.ip(),
                        tls_fingerprint.as_ref(),
                    );
                    increment_bad_on_unknown_tls_sni(stats.as_ref(), &e);
                    return Err(e);
                }
            };
            record_tls_fingerprint_auth_success(
                stats.as_ref(),
                &config,
                real_peer.ip(),
                tls_fingerprint.as_ref(),
                tls_user.as_str(),
            );

            debug!(peer = %peer, "Reading MTProto handshake through TLS");
            let mtproto_data = tls_reader.read_exact(HANDSHAKE_LEN).await?;
            let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..].try_into()
                .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake_with_shared(
                &mtproto_handshake, tls_reader, tls_writer, real_peer,
                &config, &replay_checker, true, Some(tls_user.as_str()),
                shared.as_ref(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    // MTProto failed after TLS ServerHello was already sent.
                    // Switch fallback relay back to raw transport so the mask
                    // backend receives valid TLS records (not unwrapped payload).
                    let (reader, pending_plaintext) = reader.into_inner_with_pending_plaintext();
                    let writer = writer.into_inner();
                    let pending_record = if pending_plaintext.is_empty() {
                        Vec::new()
                    } else {
                        wrap_tls_application_record(&pending_plaintext)
                    };
                    let reader = tokio::io::AsyncReadExt::chain(std::io::Cursor::new(pending_record), reader);
                    stats.increment_connects_bad_with_class("tls_mtproto_bad_client");
                    debug!(
                        peer = %peer,
                        "Authenticated TLS session failed MTProto validation; engaging masking fallback"
                    );
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        Vec::new(),
                        real_peer,
                        local_addr,
                        config.clone(),
                        upstream_manager.clone(),
                        beobachten.clone(),
                        shared.clone(),
                    ));
                }
                HandshakeResult::Error(e) => return Err(e),
            };

            Ok(HandshakeOutcome::NeedsRelay(Box::pin(
                RunningClientHandler::handle_authenticated_static_with_shared(
                    crypto_reader, crypto_writer, success,
                    upstream_manager, stats, config, buffer_pool, rng, me_pool,
                    me_pool_runtime,
                    route_runtime.clone(),
                    local_addr, real_peer, ip_tracker.clone(),
                    shared.clone(),
                ),
            )))
        } else {
            if !config.general.modes.classic && !config.general.modes.secure {
                debug!(peer = %real_peer, "Non-TLS modes disabled");
                stats.increment_connects_bad_with_class("direct_modes_disabled");
                maybe_apply_mask_reject_delay(&config).await;
                let (reader, writer) = tokio::io::split(stream);
                return Ok(masking_outcome(
                    reader,
                    writer,
                    first_bytes.to_vec(),
                    real_peer,
                    local_addr,
                    config.clone(),
                    upstream_manager.clone(),
                    beobachten.clone(),
                    shared.clone(),
                ));
            }

            let mut handshake = [0u8; HANDSHAKE_LEN];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake_with_shared(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, false, None,
                shared.as_ref(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad_with_class("direct_mtproto_bad_client");
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        handshake.to_vec(),
                        real_peer,
                        local_addr,
                        config.clone(),
                        upstream_manager.clone(),
                        beobachten.clone(),
                        shared.clone(),
                    ));
                }
                HandshakeResult::Error(e) => return Err(e),
            };

            Ok(HandshakeOutcome::NeedsRelay(Box::pin(
                RunningClientHandler::handle_authenticated_static_with_shared(
                    crypto_reader,
                    crypto_writer,
                    success,
                    upstream_manager,
                    stats,
                    config,
                    buffer_pool,
                    rng,
                    me_pool,
                    me_pool_runtime,
                    route_runtime.clone(),
                    local_addr,
                    real_peer,
                    ip_tracker.clone(),
                    shared.clone(),
                )
            )))
        }
    }).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(e)) => {
            debug!(peer = %peer, error = %e, "Handshake failed");
            stats_for_timeout.increment_handshake_failure_class(classify_handshake_failure_class(&e));
            record_handshake_failure_class(
                &beobachten_for_timeout,
                &config_for_timeout,
                peer_for_timeout,
                &e,
            );
            return Err(e);
        }
        Err(_) => {
            stats_for_timeout.increment_handshake_timeouts();
            stats_for_timeout.increment_handshake_failure_class("timeout");
            debug!(peer = %peer, "Handshake timeout");
            record_beobachten_class(
                &beobachten_for_timeout,
                &config_for_timeout,
                peer_for_timeout,
                "other",
            );
            return Err(ProxyError::TgHandshakeTimeout);
        }
    };

    // Phase 2: relay (WITHOUT handshake timeout — relay has its own activity timeouts)
    match outcome {
        HandshakeOutcome::NeedsRelay(fut) | HandshakeOutcome::NeedsMasking(fut) => fut.await,
    }
}
