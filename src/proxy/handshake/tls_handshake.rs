use super::*;

/// Handle fake TLS handshake
#[cfg(test)]
pub async fn handle_tls_handshake<R, W>(
    handshake: &[u8],
    reader: R,
    mut writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let shared = ProxySharedState::new();
    handle_tls_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        rng,
        tls_cache,
        shared.as_ref(),
        TlsResponseWriteOptions::default(),
    )
    .await
}

pub async fn handle_tls_handshake_with_shared<R, W>(
    handshake: &[u8],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
    shared: &ProxySharedState,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    handle_tls_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        rng,
        tls_cache,
        shared,
        TlsResponseWriteOptions::default(),
    )
    .await
}

/// Handles FakeTLS with optional best-effort initial-response chunking.
pub(crate) async fn handle_tls_handshake_with_shared_and_options<R, W>(
    handshake: &[u8],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
    shared: &ProxySharedState,
    response_write_options: TlsResponseWriteOptions,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    handle_tls_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        rng,
        tls_cache,
        shared,
        response_write_options,
    )
    .await
}

async fn handle_tls_handshake_impl<R, W>(
    handshake: &[u8],
    reader: R,
    mut writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
    shared: &ProxySharedState,
    response_write_options: TlsResponseWriteOptions,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    debug!(peer = %peer, handshake_len = handshake.len(), "Processing TLS handshake");

    let throttle_now = Instant::now();
    if auth_probe_should_apply_preauth_throttle_in(shared, peer.ip(), throttle_now) {
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "TLS handshake rejected by pre-auth probe throttle");
        return HandshakeResult::BadClient { reader, writer };
    }

    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "TLS handshake too short");
        return HandshakeResult::BadClient { reader, writer };
    }

    let client_sni = tls::extract_sni_from_client_hello(handshake);
    let preferred_user_hint = client_sni
        .as_deref()
        .filter(|sni| config.access.users.contains_key(*sni));
    let matched_tls_domain = client_sni
        .as_deref()
        .and_then(|sni| find_matching_tls_domain(config, sni));

    let alpn_list = if config.censorship.alpn_enforce {
        tls::extract_alpn_from_client_hello(handshake)
    } else {
        Vec::new()
    };
    let selected_alpn = if config.censorship.alpn_enforce {
        if alpn_list.iter().any(|p| p == b"h2") {
            Some(b"h2".to_vec())
        } else if alpn_list.iter().any(|p| p == b"http/1.1") {
            Some(b"http/1.1".to_vec())
        } else if !alpn_list.is_empty() {
            maybe_apply_server_hello_delay(config).await;
            debug!(peer = %peer, "Client ALPN list has no supported protocol; using masking fallback");
            return HandshakeResult::BadClient { reader, writer };
        } else {
            None
        }
    } else {
        None
    };
    // Fail-closed to TLS 1.3 semantics when ClientHello version is ambiguous:
    // this avoids leaking certificate payload on malformed probes.
    let client_tls_version = tls::detect_client_hello_tls_version(handshake)
        .unwrap_or(tls::ClientHelloTlsVersion::Tls13);

    if client_sni.is_some() && matched_tls_domain.is_none() && preferred_user_hint.is_none() {
        let sni = client_sni.as_deref().unwrap_or_default();
        match config.censorship.unknown_sni_action {
            UnknownSniAction::Accept => {
                debug!(
                    peer = %peer,
                    sni = %sni,
                    unknown_sni = true,
                    unknown_sni_action = ?config.censorship.unknown_sni_action,
                    "TLS handshake accepted by unknown SNI policy"
                );
            }
            action @ (UnknownSniAction::Drop
            | UnknownSniAction::Mask
            | UnknownSniAction::RejectHandshake) => {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                // For Drop/Mask we apply the synthetic ServerHello delay so
                // the fail-closed path is timing-indistinguishable from the
                // success path. For RejectHandshake we deliberately skip the
                // delay: a stock modern nginx with `ssl_reject_handshake on;`
                // responds with the alert essentially immediately, so
                // injecting 8-24ms here would itself become a distinguisher
                // against the public baseline we are trying to blend into.
                if !matches!(action, UnknownSniAction::RejectHandshake) {
                    maybe_apply_server_hello_delay(config).await;
                }
                let log_now = Instant::now();
                if should_emit_unknown_sni_warn_in(shared, log_now) {
                    warn!(
                        peer = %peer,
                        sni = %sni,
                        unknown_sni = true,
                        unknown_sni_action = ?action,
                        "TLS handshake rejected by unknown SNI policy"
                    );
                } else {
                    info!(
                        peer = %peer,
                        sni = %sni,
                        unknown_sni = true,
                        unknown_sni_action = ?action,
                        "TLS handshake rejected by unknown SNI policy"
                    );
                }
                if matches!(action, UnknownSniAction::RejectHandshake) {
                    // TLS alert record layer:
                    //   0x15            ContentType.alert
                    //   0x03 0x03       legacy_record_version = TLS 1.2
                    //                   (matches what modern nginx emits in
                    //                   the first server -> client record,
                    //                   per RFC 8446 5.1 guidance)
                    //   0x00 0x02       length = 2
                    // Alert payload:
                    //   0x02            AlertLevel.fatal
                    //   0x70            AlertDescription.unrecognized_name (112, RFC 6066)
                    const TLS_ALERT_UNRECOGNIZED_NAME: [u8; 7] =
                        [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];
                    if let Err(e) = writer.write_all(&TLS_ALERT_UNRECOGNIZED_NAME).await {
                        debug!(
                            peer = %peer,
                            error = %e,
                            "Failed to write unrecognized_name TLS alert"
                        );
                    } else {
                        let _ = writer.flush().await;
                    }
                }
                return match action {
                    UnknownSniAction::Drop | UnknownSniAction::RejectHandshake => {
                        HandshakeResult::Error(ProxyError::UnknownTlsSni)
                    }
                    UnknownSniAction::Mask => HandshakeResult::BadClient { reader, writer },
                    UnknownSniAction::Accept => unreachable!(),
                };
            }
        }
    }

    let Some(validation) = tls_validation::validate_tls_client(
        handshake,
        peer,
        config,
        shared,
        preferred_user_hint,
        &client_sni,
    )
    .await
    else {
        return HandshakeResult::BadClient { reader, writer };
    };
    let tls_validation::TlsClientValidation {
        digest: validation_digest,
        session_id: validation_session_id,
        session_id_len: validation_session_id_len,
        user: validated_user,
        secret: validated_secret,
        user_id: validated_user_id,
    } = validation;
    // Reject known replay digests before expensive cache/domain/ALPN policy work.
    let digest_half = &validation_digest[..tls::TLS_DIGEST_HALF_LEN];
    if replay_checker.check_tls_digest(digest_half) {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        warn!(peer = %peer, "TLS replay attack detected (duplicate digest)");
        return HandshakeResult::BadClient { reader, writer };
    }

    let selected_tls_domain = matched_tls_domain.unwrap_or(config.censorship.tls_domain.as_str());
    let cached_entry = if config.censorship.tls_emulation {
        if let Some(cache) = tls_cache.as_ref() {
            let cached_entry = cache.get(selected_tls_domain).await;
            Some(cached_entry)
        } else {
            None
        }
    } else {
        None
    };

    let preferred_key_share_group = cached_entry
        .as_ref()
        .and_then(|cached_entry| emulator::profiled_server_hello_key_share_group(cached_entry));
    let Some(server_key_share) =
        tls::build_server_hello_key_share(handshake, preferred_key_share_group, rng)
    else {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        debug!(
            peer = %peer,
            "TLS handshake rejected: ClientHello did not offer a usable TLS 1.3 key_share"
        );
        return HandshakeResult::BadClient { reader, writer };
    };

    let preferred_cipher_suite = if let Some(cached_entry) = cached_entry.as_ref() {
        if cached_entry.server_hello_template.cipher_suite == [0, 0] {
            [0x13, 0x01]
        } else {
            cached_entry.server_hello_template.cipher_suite
        }
    } else {
        [0x13, 0x01]
    };
    let Some(selected_cipher_suite) =
        tls::select_server_hello_cipher_suite(handshake, preferred_cipher_suite)
    else {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        debug!(
            peer = %peer,
            "TLS handshake rejected: ClientHello did not offer a supported TLS 1.3 cipher suite"
        );
        return HandshakeResult::BadClient { reader, writer };
    };

    let cached = if let Some(cached_entry) = cached_entry {
        let use_full_cert_payload = if config.censorship.serverhello_compact
            && matches!(client_tls_version, tls::ClientHelloTlsVersion::Tls12)
        {
            if let Some(cache) = tls_cache.as_ref() {
                cache
                    .take_full_cert_budget_for_ip(
                        selected_tls_domain,
                        peer.ip(),
                        Duration::from_secs(config.censorship.tls_full_cert_ttl_secs),
                    )
                    .await
            } else {
                true
            }
        } else {
            true
        };
        Some((cached_entry, use_full_cert_payload))
    } else {
        None
    };

    // Add replay digest only for policy-valid handshakes.
    replay_checker.add_tls_digest(digest_half);

    let validation_session_id_slice = &validation_session_id[..validation_session_id_len];

    let response = if let Some((cached_entry, use_full_cert_payload)) = cached {
        emulator::build_emulated_server_hello(
            &validated_secret,
            &validation_digest,
            validation_session_id_slice,
            &cached_entry,
            use_full_cert_payload,
            config.censorship.serverhello_compact,
            client_tls_version,
            selected_cipher_suite,
            &server_key_share,
            rng,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    } else {
        tls::build_server_hello_with_cipher(
            &validated_secret,
            &validation_digest,
            validation_session_id_slice,
            config.censorship.fake_cert_len,
            rng,
            selected_cipher_suite,
            &server_key_share,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    };

    // Apply the same optional delay budget used by reject paths to reduce
    // distinguishability between success and fail-closed handshakes.
    maybe_apply_server_hello_delay(config).await;

    debug!(peer = %peer, response_len = response.len(), "Sending TLS ServerHello");

    if let Err(e) = write_tls_response(&mut writer, &response, response_write_options).await {
        warn!(peer = %peer, error = %e, "Failed to write TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    debug!(
        peer = %peer,
        user = %validated_user,
        "TLS handshake successful"
    );

    auth_probe_record_success_in(shared, peer.ip());

    if let Some(user_id) = validated_user_id {
        sticky_hint_record_success_in(shared, peer.ip(), user_id, client_sni.as_deref());
        record_recent_user_success_in(shared, user_id);
    }

    HandshakeResult::Success((
        FakeTlsReader::new(reader),
        FakeTlsWriter::new(writer),
        validated_user,
    ))
}

async fn write_tls_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &[u8],
    options: TlsResponseWriteOptions,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if let (Some(fd), Some(fragment_size)) = (options.socket_fd, options.fragment_size) {
        return crate::transport::socket::send_tcp_fragmented_fd(
            fd,
            response,
            usize::from(fragment_size),
        )
        .await;
    }

    let _ = options;
    writer.write_all(response).await?;
    writer.flush().await
}
