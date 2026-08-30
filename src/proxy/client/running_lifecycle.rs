use super::*;

impl RunningClientHandler {
    pub async fn run(self) -> Result<()> {
        self.stats.increment_connects_all();
        let peer = self.peer;
        debug!(peer = %peer, "New connection");

        if let Err(e) = configure_client_socket(
            &self.stream,
            self.config.timeouts.client_keepalive,
            self.config.timeouts.client_ack,
        ) {
            debug!(peer = %peer, error = %e, "Failed to configure client socket");
        }

        #[cfg(unix)]
        let raw_fd = self.raw_fd;
        let rst_on_close = self.rst_on_close;

        let outcome = match self.do_handshake().await? {
            Some(outcome) => outcome,
            None => return Ok(()),
        };

        // Phase 2: relay (WITHOUT handshake timeout — relay has its own activity timeouts)
        match outcome {
            HandshakeOutcome::NeedsRelay(fut) => {
                #[cfg(unix)]
                if matches!(rst_on_close, crate::config::RstOnCloseMode::Errors) {
                    let _ = crate::transport::socket::clear_linger_fd(raw_fd);
                }
                fut.await
            }
            HandshakeOutcome::NeedsMasking(fut) => fut.await,
        }
    }

    pub(super) async fn do_handshake(mut self) -> Result<Option<HandshakeOutcome>> {
        let mut local_addr = self.stream.local_addr().map_err(ProxyError::Io)?;

        if self.proxy_protocol_enabled {
            if !is_trusted_proxy_source(
                self.peer.ip(),
                &self.config.server.proxy_protocol_trusted_cidrs,
            ) {
                self.stats
                    .increment_connects_bad_with_class("proxy_protocol_untrusted");
                warn!(
                    peer = %self.peer,
                    trusted = ?self.config.server.proxy_protocol_trusted_cidrs,
                    "Rejecting PROXY protocol header from untrusted source"
                );
                record_beobachten_class(&self.beobachten, &self.config, self.peer.ip(), "other");
                return Err(ProxyError::InvalidProxyProtocol);
            }

            let proxy_header_timeout =
                Duration::from_millis(self.config.server.proxy_protocol_header_timeout_ms.max(1));
            match timeout(
                proxy_header_timeout,
                parse_proxy_protocol(&mut self.stream, self.peer),
            )
            .await
            {
                Ok(Ok(info)) => {
                    debug!(
                        peer = %self.peer,
                        client = %info.src_addr,
                        version = info.version,
                        "PROXY protocol header parsed"
                    );
                    self.peer = normalize_ip(info.src_addr);
                    self.real_peer_from_proxy = Some(self.peer);
                    if let Ok(mut slot) = self.real_peer_report.lock() {
                        *slot = Some(self.peer);
                    }
                    if let Some(dst) = info.dst_addr {
                        local_addr = dst;
                    }
                }
                Ok(Err(e)) => {
                    self.stats
                        .increment_connects_bad_with_class("proxy_protocol_invalid_header");
                    warn!(peer = %self.peer, error = %e, "Invalid PROXY protocol header");
                    record_beobachten_class(
                        &self.beobachten,
                        &self.config,
                        self.peer.ip(),
                        "other",
                    );
                    return Err(e);
                }
                Err(_) => {
                    self.stats
                        .increment_connects_bad_with_class("proxy_protocol_header_timeout");
                    warn!(
                        peer = %self.peer,
                        timeout_ms = proxy_header_timeout.as_millis(),
                        "PROXY protocol header timeout"
                    );
                    record_beobachten_class(
                        &self.beobachten,
                        &self.config,
                        self.peer.ip(),
                        "other",
                    );
                    return Err(ProxyError::InvalidProxyProtocol);
                }
            }
        }

        let first_byte_idle_secs =
            effective_client_first_byte_idle_secs(&self.config, self.shared.as_ref());
        let first_byte = if first_byte_idle_secs == 0 {
            None
        } else {
            let idle_timeout = Duration::from_secs(first_byte_idle_secs);
            let mut first_byte = [0u8; 1];
            match timeout(idle_timeout, self.stream.read(&mut first_byte)).await {
                Ok(Ok(0)) => {
                    debug!(peer = %self.peer, "Connection closed before first client byte");
                    return Ok(None);
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
                        peer = %self.peer,
                        error = %e,
                        "Connection closed before first client byte"
                    );
                    return Ok(None);
                }
                Ok(Err(e)) => {
                    debug!(
                        peer = %self.peer,
                        error = %e,
                        "Failed while waiting for first client byte"
                    );
                    return Err(ProxyError::Io(e));
                }
                Err(_) => {
                    debug!(
                        peer = %self.peer,
                        idle_secs = first_byte_idle_secs,
                        "Closing idle pooled connection before first client byte"
                    );
                    return Ok(None);
                }
            }
        };

        let handshake_timeout = handshake_timeout_with_mask_grace(&self.config);
        let stats = self.stats.clone();
        let config_for_timeout = self.config.clone();
        let beobachten_for_timeout = self.beobachten.clone();
        let peer_for_timeout = self.peer.ip();
        let peer_for_log = self.peer;

        let outcome = match timeout(handshake_timeout, async {
            let mut first_bytes = [0u8; 5];
            if let Some(first_byte) = first_byte {
                first_bytes[0] = first_byte;
                self.stream.read_exact(&mut first_bytes[1..]).await?;
            } else {
                self.stream.read_exact(&mut first_bytes).await?;
            }

            let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
            let peer = self.peer;

            debug!(peer = %peer, is_tls = is_tls, "Handshake type detected");

            if is_tls {
                self.handle_tls_client(first_bytes, local_addr).await
            } else {
                self.handle_direct_client(first_bytes, local_addr).await
            }
        })
        .await
        {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                debug!(peer = %peer_for_log, error = %e, "Handshake failed");
                stats.increment_handshake_failure_class(classify_handshake_failure_class(&e));
                record_handshake_failure_class(
                    &beobachten_for_timeout,
                    &config_for_timeout,
                    peer_for_timeout,
                    &e,
                );
                return Err(e);
            }
            Err(_) => {
                stats.increment_handshake_timeouts();
                stats.increment_handshake_failure_class("timeout");
                debug!(peer = %peer_for_log, "Handshake timeout");
                record_beobachten_class(
                    &beobachten_for_timeout,
                    &config_for_timeout,
                    peer_for_timeout,
                    "other",
                );
                return Err(ProxyError::TgHandshakeTimeout);
            }
        };

        Ok(Some(outcome))
    }
}
