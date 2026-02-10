//! Client Handler

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, warn, error, trace};

use crate::config::{ProxyConfig, UpstreamType};
use crate::error::{ProxyError, Result, HandshakeResult};
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stats::{Stats, ReplayChecker};
use crate::transport::{configure_client_socket, UpstreamManager};
use crate::stream::{CryptoReader, CryptoWriter, FakeTlsReader, FakeTlsWriter, BufferPool};
use crate::crypto::{AesCtr, SecureRandom};
use crate::util::ip::IpInfo;

use crate::proxy::handshake::{
    handle_tls_handshake, handle_mtproto_handshake,
    HandshakeSuccess, generate_tg_nonce, encrypt_tg_nonce,
};
use crate::proxy::relay::relay_bidirectional;
use crate::proxy::masking::handle_bad_client;
use crate::proxy::middle::{MiddleProxyPool, relay_middle_proxy};

pub struct ClientHandler;

pub struct RunningClientHandler {
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    replay_checker: Arc<ReplayChecker>,
    upstream_manager: Arc<UpstreamManager>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    middle_pool: Option<Arc<MiddleProxyPool>>,
    ip_info: Arc<IpInfo>,
}

impl ClientHandler {
    pub fn new(
        stream: TcpStream,
        peer: SocketAddr,
        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
        upstream_manager: Arc<UpstreamManager>,
        replay_checker: Arc<ReplayChecker>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        middle_pool: Option<Arc<MiddleProxyPool>>,
        ip_info: Arc<IpInfo>,
    ) -> RunningClientHandler {
        RunningClientHandler {
            stream, peer, config, stats, replay_checker,
            upstream_manager, buffer_pool, rng,
            middle_pool, ip_info,
        }
    }
}

impl RunningClientHandler {
    pub async fn run(mut self) -> Result<()> {
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

        let handshake_timeout = Duration::from_secs(self.config.timeouts.client_handshake);
        let stats = self.stats.clone();

        let result = timeout(handshake_timeout, self.do_handshake()).await;

        match result {
            Ok(Ok(())) => {
                debug!(peer = %peer, "Connection handled successfully");
                Ok(())
            }
            Ok(Err(e)) => {
                debug!(peer = %peer, error = %e, "Handshake failed");
                Err(e)
            }
            Err(_) => {
                stats.increment_handshake_timeouts();
                debug!(peer = %peer, "Handshake timeout");
                Err(ProxyError::TgHandshakeTimeout)
            }
        }
    }

    async fn do_handshake(mut self) -> Result<()> {
        let mut first_bytes = [0u8; 5];
        self.stream.read_exact(&mut first_bytes).await?;

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        let peer = self.peer;

        debug!(peer = %peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            self.handle_tls_client(first_bytes).await
        } else {
            self.handle_direct_client(first_bytes).await
        }
    }

    async fn handle_tls_client(mut self, first_bytes: [u8; 5]) -> Result<()> {
        let peer = self.peer;

        let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

        debug!(peer = %peer, tls_len = tls_len, "Reading TLS handshake");

        if tls_len < 512 {
            debug!(peer = %peer, tls_len = tls_len, "TLS handshake too short");
            self.stats.increment_connects_bad();
            let (reader, writer) = self.stream.into_split();
            handle_bad_client(reader, writer, &first_bytes, &self.config).await;
            return Ok(());
        }

        let mut handshake = vec![0u8; 5 + tls_len];
        handshake[..5].copy_from_slice(&first_bytes);
        self.stream.read_exact(&mut handshake[5..]).await?;

        let config = self.config.clone();
        let replay_checker = self.replay_checker.clone();
        let stats = self.stats.clone();
        let buffer_pool = self.buffer_pool.clone();

        let (read_half, write_half) = self.stream.into_split();

        let (mut tls_reader, tls_writer, _tls_user) = match handle_tls_handshake(
            &handshake, read_half, write_half, peer,
            &config, &replay_checker, &self.rng,
        ).await {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad();
                handle_bad_client(reader, writer, &handshake, &config).await;
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        debug!(peer = %peer, "Reading MTProto handshake through TLS");
        let mtproto_data = tls_reader.read_exact(HANDSHAKE_LEN).await?;
        let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..].try_into()
            .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;

        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
            &mtproto_handshake, tls_reader, tls_writer, peer,
            &config, &replay_checker, true,
        ).await {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader: _, writer: _ } => {
                stats.increment_connects_bad();
                debug!(peer = %peer, "Valid TLS but invalid MTProto handshake");
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Self::handle_authenticated_static(
            crypto_reader, crypto_writer, success,
            self.upstream_manager, self.stats, self.config,
            buffer_pool, self.rng, self.middle_pool, self.ip_info,
        ).await
    }

    async fn handle_direct_client(mut self, first_bytes: [u8; 5]) -> Result<()> {
        let peer = self.peer;

        if !self.config.general.modes.classic && !self.config.general.modes.secure {
            debug!(peer = %peer, "Non-TLS modes disabled");
            self.stats.increment_connects_bad();
            let (reader, writer) = self.stream.into_split();
            handle_bad_client(reader, writer, &first_bytes, &self.config).await;
            return Ok(());
        }

        let mut handshake = [0u8; HANDSHAKE_LEN];
        handshake[..5].copy_from_slice(&first_bytes);
        self.stream.read_exact(&mut handshake[5..]).await?;

        let config = self.config.clone();
        let replay_checker = self.replay_checker.clone();
        let stats = self.stats.clone();
        let buffer_pool = self.buffer_pool.clone();

        let (read_half, write_half) = self.stream.into_split();

        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
            &handshake, read_half, write_half, peer,
            &config, &replay_checker, false,
        ).await {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad();
                handle_bad_client(reader, writer, &handshake, &config).await;
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Self::handle_authenticated_static(
            crypto_reader, crypto_writer, success,
            self.upstream_manager, self.stats, self.config,
            buffer_pool, self.rng, self.middle_pool, self.ip_info,
        ).await
    }

    // ========================
    //  Post-Handshake Router
    // ========================

    async fn handle_authenticated_static<R, W>(
        client_reader: CryptoReader<R>,
        client_writer: CryptoWriter<W>,
        success: HandshakeSuccess,
        upstream_manager: Arc<UpstreamManager>,
        stats: Arc<Stats>,
        config: Arc<ProxyConfig>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        middle_pool: Option<Arc<MiddleProxyPool>>,
        ip_info: Arc<IpInfo>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let user = &success.user;

        if let Err(e) = Self::check_user_limits_static(user, &config, &stats) {
            warn!(user = %user, error = %e, "User limit exceeded");
            return Err(e);
        }

        // Decide: middle proxy or direct
        let use_middle = config.is_middle_proxy_enabled()
            && middle_pool.is_some()
            && !Self::has_socks_upstream(&config);

        if use_middle {
            Self::handle_via_middle_proxy(
                client_reader, client_writer, success,
                stats, config, rng, middle_pool.unwrap(),
            ).await
        } else {
            Self::handle_via_direct(
                client_reader, client_writer, success,
                upstream_manager, stats, config, buffer_pool, rng,
            ).await
        }
    }

    // ========================
    //  Middle Proxy Path
    // ========================

    async fn handle_via_middle_proxy<R, W>(
        client_reader: CryptoReader<R>,
        client_writer: CryptoWriter<W>,
        success: HandshakeSuccess,
        stats: Arc<Stats>,
        config: Arc<ProxyConfig>,
        rng: Arc<SecureRandom>,
        middle_pool: Arc<MiddleProxyPool>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let user = success.user.clone();
        let dc_idx = success.dc_idx as i32;
        let peer = success.peer;

        let ad_tag = config.ad_tag_bytes().ok_or_else(|| {
            ProxyError::Config("Middle proxy requires valid ad_tag".into())
        })?;

        info!(
            user = %user,
            peer = %peer,
            dc = dc_idx,
            proto = ?success.proto_tag,
            "Connecting to Telegram via middle proxy (pooled)"
        );

        // Get pre-handshaked connection from pool (or create on-demand)
        let handshaked_conn = middle_pool.get_or_create(dc_idx).await?;

        // Bind to this specific client
        let middle_proxy_stream = handshaked_conn.into_stream(
            peer,
            success.proto_tag,
            ad_tag,
            &rng,
        );

        debug!(peer = %peer, "Middle proxy connection ready, starting relay");

        stats.increment_user_connects(&user);
        stats.increment_user_curr_connects(&user);

        let start = std::time::Instant::now();

        let relay_result = relay_middle_proxy(
            client_reader,
            client_writer,
            middle_proxy_stream,
            success.proto_tag,
            user.clone(),
            Arc::clone(&stats),
            rng,
        ).await;

        let duration = start.elapsed().as_secs_f64();
        stats.decrement_user_curr_connects(&user);

        match &relay_result {
            Ok(()) => info!(
                user = %user,
                duration_secs = format!("{:.1}", duration),
                "Middle proxy relay completed"
            ),
            Err(e) => debug!(user = %user, error = %e, "Middle proxy relay ended with error"),
        }

        relay_result
    }

    // ========================
    //  Direct Path (existing)
    // ========================

    async fn handle_via_direct<R, W>(
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
        let dc_addr = Self::get_dc_addr_static(success.dc_idx, &config)?;

        info!(
            user = %user,
            peer = %success.peer,
            dc = success.dc_idx,
            dc_addr = %dc_addr,
            proto = ?success.proto_tag,
            "Connecting to Telegram (direct)"
        );

        let tg_stream = upstream_manager.connect(dc_addr, Some(success.dc_idx)).await?;

        debug!(peer = %success.peer, dc_addr = %dc_addr, "Connected, performing TG handshake");

        let (tg_reader, tg_writer) = Self::do_tg_handshake_static(
            tg_stream, &success, &config, rng.as_ref(),
        ).await?;

        debug!(peer = %success.peer, "TG handshake complete, starting relay");

        stats.increment_user_connects(user);
        stats.increment_user_curr_connects(user);

        let relay_result = relay_bidirectional(
            client_reader, client_writer,
            tg_reader, tg_writer,
            user, Arc::clone(&stats), buffer_pool,
        ).await;

        stats.decrement_user_curr_connects(user);

        match &relay_result {
            Ok(()) => debug!(user = %user, "Relay completed"),
            Err(e) => debug!(user = %user, error = %e, "Relay ended with error"),
        }

        relay_result
    }

    // ========================
    //  Helpers
    // ========================

    /// Check if any enabled upstream uses SOCKS (incompatible with middle proxy).
    fn has_socks_upstream(config: &ProxyConfig) -> bool {
        config.upstreams.iter().any(|u| {
            u.enabled && matches!(
                u.upstream_type,
                UpstreamType::Socks4 { .. } | UpstreamType::Socks5 { .. }
            )
        })
    }

    fn check_user_limits_static(user: &str, config: &ProxyConfig, stats: &Stats) -> Result<()> {
        if let Some(expiration) = config.access.user_expirations.get(user) {
            if chrono::Utc::now() > *expiration {
                return Err(ProxyError::UserExpired { user: user.to_string() });
            }
        }

        if let Some(limit) = config.access.user_max_tcp_conns.get(user) {
            if stats.get_user_curr_connects(user) >= *limit as u64 {
                return Err(ProxyError::ConnectionLimitExceeded { user: user.to_string() });
            }
        }

        if let Some(quota) = config.access.user_data_quota.get(user) {
            if stats.get_user_total_octets(user) >= *quota {
                return Err(ProxyError::DataQuotaExceeded { user: user.to_string() });
            }
        }

        Ok(())
    }

    fn get_dc_addr_static(dc_idx: i16, config: &ProxyConfig) -> Result<SocketAddr> {
        let idx = (dc_idx.abs() - 1) as usize;

        let datacenters = if config.general.prefer_ipv6 {
            &*TG_DATACENTERS_V6
        } else {
            &*TG_DATACENTERS_V4
        };

        datacenters.get(idx)
            .map(|ip| SocketAddr::new(*ip, TG_DATACENTER_PORT))
            .ok_or_else(|| ProxyError::InvalidHandshake(
                format!("Invalid DC index: {}", dc_idx)
            ))
    }

    async fn do_tg_handshake_static(
        mut stream: TcpStream,
        success: &HandshakeSuccess,
        config: &ProxyConfig,
        rng: &SecureRandom,
    ) -> Result<(CryptoReader<tokio::net::tcp::OwnedReadHalf>, CryptoWriter<tokio::net::tcp::OwnedWriteHalf>)> {
        let (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv) = generate_tg_nonce(
            success.proto_tag,
            &success.dec_key,
            success.dec_iv,
            rng,
            config.general.fast_mode,
        );

        let encrypted_nonce = encrypt_tg_nonce(&nonce);

        debug!(
            peer = %success.peer,
            nonce_head = %hex::encode(&nonce[..16]),
            "Sending nonce to Telegram"
        );

        stream.write_all(&encrypted_nonce).await?;
        stream.flush().await?;

        let (read_half, write_half) = stream.into_split();

        // TG→proxy decryptor starts at position 0 — correct, because
        // Telegram's encryptor for this (reverse) direction also starts
        // fresh; Telegram does not send any nonce back to us.
        let decryptor = AesCtr::new(&tg_dec_key, tg_dec_iv);

        // When we sent the nonce, `encrypt_tg_nonce` created a local AES-CTR
        // cipher with (tg_enc_key, tg_enc_iv), encrypted all 64 bytes, then
        // dropped the cipher.  Telegram's decryptor used the same key/IV to
        // process the received nonce — so its CTR counter is now at 64.
        //
        // If our stream encryptor starts at position 0, every byte we send
        // will be decrypted by Telegram with the wrong keystream offset,
        // producing garbage and causing the connection to fail.
        let mut encryptor = AesCtr::new(&tg_enc_key, tg_enc_iv);
        {
            let mut skip = [0u8; HANDSHAKE_LEN];
            encryptor.apply(&mut skip);
        }

        Ok((
            CryptoReader::new(read_half, decryptor),
            CryptoWriter::new(write_half, encryptor),
        ))
    }
}