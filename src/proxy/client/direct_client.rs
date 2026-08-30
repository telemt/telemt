use super::*;

impl RunningClientHandler {
    pub(super) async fn handle_direct_client(
        mut self,
        first_bytes: [u8; 5],
        local_addr: SocketAddr,
    ) -> Result<HandshakeOutcome> {
        let peer = self.peer;

        if !self.config.general.modes.classic && !self.config.general.modes.secure {
            debug!(peer = %peer, "Non-TLS modes disabled");
            self.stats
                .increment_connects_bad_with_class("direct_modes_disabled");
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

        let mut handshake = [0u8; HANDSHAKE_LEN];
        handshake[..5].copy_from_slice(&first_bytes);
        self.stream.read_exact(&mut handshake[5..]).await?;

        let config = self.config.clone();
        let replay_checker = self.replay_checker.clone();
        let stats = self.stats.clone();
        let buffer_pool = self.buffer_pool.clone();

        let (read_half, write_half) = self.stream.into_split();

        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake_with_shared(
            &handshake,
            read_half,
            write_half,
            peer,
            &config,
            &replay_checker,
            false,
            None,
            self.shared.as_ref(),
        )
        .await
        {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad_with_class("direct_mtproto_bad_client");
                return Ok(masking_outcome(
                    reader,
                    writer,
                    handshake.to_vec(),
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
