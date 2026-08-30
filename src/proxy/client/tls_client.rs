use super::*;

impl RunningClientHandler {
    pub(super) async fn handle_tls_client(
        mut self,
        first_bytes: [u8; 5],
        local_addr: SocketAddr,
    ) -> Result<HandshakeOutcome> {
        let peer = self.peer;

        let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

        debug!(peer = %peer, tls_len = tls_len, "Reading TLS handshake");

        // RFC 8446 §5.1: TLS record payload MUST NOT exceed 2^14 (16_384) bytes.
        // Lower bound is a structural minimum for a valid TLS 1.3 ClientHello
        // (record header + handshake header + random + session_id + cipher_suites
        // + compression + at least one extension with SNI). The previous value of
        // 512 was implicitly coupled to TLS_REQUEST_LENGTH=517 from the official
        // Telegram MTProxy reference server, leaving only a 5-byte margin and
        // incorrectly rejecting compact but spec-compliant ClientHellos from
        // third-party clients or future Telegram versions.
        if !tls_clienthello_len_in_bounds(tls_len) {
            debug!(peer = %peer, tls_len = tls_len, max_tls_len = MAX_TLS_PLAINTEXT_SIZE, "TLS handshake length out of bounds");
            self.stats
                .increment_connects_bad_with_class("tls_clienthello_len_out_of_bounds");
            maybe_apply_mask_reject_delay(&self.config).await;
            let (reader, writer) = self.stream.into_split();
            return Ok(masking_outcome(
                reader,
                writer,
                first_bytes.to_vec(),
                peer,
                local_addr,
                self.config.clone(),
                self.upstream_manager.clone(),
                self.beobachten.clone(),
                self.shared.clone(),
            ));
        }

        let mut handshake = vec![0u8; 5 + tls_len];
        handshake[..5].copy_from_slice(&first_bytes);
        let body_read = match read_with_progress(&mut self.stream, &mut handshake[5..]).await {
            Ok(n) => n,
            Err(e) => {
                debug!(peer = %peer, error = %e, tls_len = tls_len, "TLS ClientHello body read failed; engaging masking fallback");
                self.stats
                    .increment_connects_bad_with_class("tls_clienthello_read_error");
                maybe_apply_mask_reject_delay(&self.config).await;
                let (reader, writer) = self.stream.into_split();
                return Ok(masking_outcome(
                    reader,
                    writer,
                    handshake[..5].to_vec(),
                    peer,
                    local_addr,
                    self.config.clone(),
                    self.upstream_manager.clone(),
                    self.beobachten.clone(),
                    self.shared.clone(),
                ));
            }
        };

        if body_read < tls_len {
            debug!(peer = %peer, got = body_read, expected = tls_len, "Truncated in-range TLS ClientHello; engaging masking fallback");
            self.stats
                .increment_connects_bad_with_class("tls_clienthello_truncated");
            maybe_apply_mask_reject_delay(&self.config).await;
            let initial_len = 5 + body_read;
            let (reader, writer) = self.stream.into_split();
            return Ok(masking_outcome(
                reader,
                writer,
                handshake[..initial_len].to_vec(),
                peer,
                local_addr,
                self.config.clone(),
                self.upstream_manager.clone(),
                self.beobachten.clone(),
                self.shared.clone(),
            ));
        }

        let tls_fingerprint = observe_tls_client_fingerprint(
            self.stats.as_ref(),
            &self.config,
            peer.ip(),
            &handshake,
        );

        let config = self.config.clone();
        let replay_checker = self.replay_checker.clone();
        let stats = self.stats.clone();
        let buffer_pool = self.buffer_pool.clone();

        let (read_half, write_half) = self.stream.into_split();

        #[cfg(target_os = "linux")]
        let response_write_options =
            TlsResponseWriteOptions::tcp(self.raw_fd, self.tls_response_fragment_size);
        #[cfg(not(target_os = "linux"))]
        let response_write_options = TlsResponseWriteOptions::default();

        let (mut tls_reader, tls_writer, tls_user) =
            match handle_tls_handshake_with_shared_and_options(
                &handshake,
                read_half,
                write_half,
                peer,
                &config,
                &replay_checker,
                &self.rng,
                self.tls_cache.clone(),
                self.shared.as_ref(),
                response_write_options,
            )
            .await
            {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad_with_class("tls_handshake_bad_client");
                    record_tls_fingerprint_bad_or_probe(
                        stats.as_ref(),
                        &config,
                        peer.ip(),
                        tls_fingerprint.as_ref(),
                    );
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        handshake.clone(),
                        peer,
                        local_addr,
                        config.clone(),
                        self.upstream_manager.clone(),
                        self.beobachten.clone(),
                        self.shared.clone(),
                    ));
                }
                HandshakeResult::Error(e) => {
                    record_tls_fingerprint_bad_or_probe(
                        stats.as_ref(),
                        &config,
                        peer.ip(),
                        tls_fingerprint.as_ref(),
                    );
                    increment_bad_on_unknown_tls_sni(stats.as_ref(), &e);
                    return Err(e);
                }
            };
        record_tls_fingerprint_auth_success(
            stats.as_ref(),
            &config,
            peer.ip(),
            tls_fingerprint.as_ref(),
            tls_user.as_str(),
        );

        debug!(peer = %peer, "Reading MTProto handshake through TLS");
        let mtproto_data = tls_reader.read_exact(HANDSHAKE_LEN).await?;
        let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..]
            .try_into()
            .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;

        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake_with_shared(
            &mtproto_handshake,
            tls_reader,
            tls_writer,
            peer,
            &config,
            &replay_checker,
            true,
            Some(tls_user.as_str()),
            self.shared.as_ref(),
        )
        .await
        {
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
                let reader =
                    tokio::io::AsyncReadExt::chain(std::io::Cursor::new(pending_record), reader);
                stats.increment_connects_bad_with_class("tls_mtproto_bad_client");
                debug!(
                    peer = %peer,
                    "Authenticated TLS session failed MTProto validation; engaging masking fallback"
                );
                return Ok(masking_outcome(
                    reader,
                    writer,
                    Vec::new(),
                    peer,
                    local_addr,
                    config.clone(),
                    self.upstream_manager.clone(),
                    self.beobachten.clone(),
                    self.shared.clone(),
                ));
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Ok(HandshakeOutcome::NeedsRelay(Box::pin(
            Self::handle_authenticated_static_with_shared(
                crypto_reader,
                crypto_writer,
                success,
                self.upstream_manager,
                self.stats,
                self.config,
                buffer_pool,
                self.rng,
                self.me_pool,
                self.me_pool_runtime,
                self.route_runtime.clone(),
                local_addr,
                peer,
                self.ip_tracker,
                self.shared,
            ),
        )))
    }
}
