//! Client Handler

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{HandshakeResult, ProxyError, Result};
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::MePool;
use crate::transport::{UpstreamManager, configure_client_socket};

use crate::proxy::direct_relay::handle_via_direct;
use crate::proxy::handshake::{HandshakeSuccess, handle_mtproto_handshake, handle_tls_handshake};
use crate::proxy::masking::handle_bad_client;
use crate::proxy::middle_relay::handle_via_middle_proxy;

/// Handle a client connection from any stream type (TCP, Unix socket)
///
/// This is the generic entry point for client handling. Unlike `ClientHandler::new().run()`,
/// it skips TCP-specific socket configuration (TCP_NODELAY, keepalive, TCP_USER_TIMEOUT)
/// which is appropriate for non-TCP streams like Unix sockets.
pub async fn handle_client_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stats.increment_connects_all();
    debug!(peer = %peer, "New connection (generic stream)");

    let handshake_timeout = Duration::from_secs(config.timeouts.client_handshake);
    let stats_for_timeout = stats.clone();

    // For non-TCP streams, use a synthetic local address
    let local_addr: SocketAddr = format!("0.0.0.0:{}", config.server.port)
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:443".parse().unwrap());

    let result = timeout(handshake_timeout, async {
        let mut first_bytes = [0u8; 5];
        stream.read_exact(&mut first_bytes).await?;

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        debug!(peer = %peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

            if tls_len < 512 {
                debug!(peer = %peer, tls_len = tls_len, "TLS handshake too short");
                stats.increment_connects_bad();
                let (reader, writer) = tokio::io::split(stream);
                handle_bad_client(reader, writer, &first_bytes, &config).await;
                return Ok(());
            }

            let mut handshake = vec![0u8; 5 + tls_len];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

            let (mut tls_reader, tls_writer, _tls_user) = match handle_tls_handshake(
                &handshake, read_half, write_half, peer,
                &config, &replay_checker, &rng,
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

            RunningClientHandler::handle_authenticated_static(
                crypto_reader, crypto_writer, success,
                upstream_manager, stats, config, buffer_pool, rng, me_pool,
                local_addr,
            ).await
        } else {
            if !config.general.modes.classic && !config.general.modes.secure {
                debug!(peer = %peer, "Non-TLS modes disabled");
                stats.increment_connects_bad();
                let (reader, writer) = tokio::io::split(stream);
                handle_bad_client(reader, writer, &first_bytes, &config).await;
                return Ok(());
            }

            let mut handshake = [0u8; HANDSHAKE_LEN];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

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

            RunningClientHandler::handle_authenticated_static(
                crypto_reader, crypto_writer, success,
                upstream_manager, stats, config, buffer_pool, rng, me_pool,
                local_addr,
            ).await
        }
    }).await;

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
            stats_for_timeout.increment_handshake_timeouts();
            debug!(peer = %peer, "Handshake timeout");
            Err(ProxyError::TgHandshakeTimeout)
        }
    }
}

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
    me_pool: Option<Arc<MePool>>,
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
        me_pool: Option<Arc<MePool>>,
    ) -> RunningClientHandler {
        RunningClientHandler {
            stream,
            peer,
            config,
            stats,
            replay_checker,
            upstream_manager,
            buffer_pool,
            rng,
            me_pool,
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

        let local_addr = self.stream.local_addr().map_err(ProxyError::Io)?;
        let (read_half, write_half) = self.stream.into_split();

        let (mut tls_reader, tls_writer, _tls_user) = match handle_tls_handshake(
            &handshake,
            read_half,
            write_half,
            peer,
            &config,
            &replay_checker,
            &self.rng,
        )
        .await
        {
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
        let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..]
            .try_into()
            .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;

        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
            &mtproto_handshake,
            tls_reader,
            tls_writer,
            peer,
            &config,
            &replay_checker,
            true,
        )
        .await
        {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient {
                reader: _,
                writer: _,
            } => {
                stats.increment_connects_bad();
                debug!(peer = %peer, "Valid TLS but invalid MTProto handshake");
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Self::handle_authenticated_static(
            crypto_reader,
            crypto_writer,
            success,
            self.upstream_manager,
            self.stats,
            self.config,
            buffer_pool,
            self.rng,
            self.me_pool,
            local_addr,
        )
        .await
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

        let local_addr = self.stream.local_addr().map_err(ProxyError::Io)?;
        let (read_half, write_half) = self.stream.into_split();

        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
            &handshake,
            read_half,
            write_half,
            peer,
            &config,
            &replay_checker,
            false,
        )
        .await
        {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad();
                handle_bad_client(reader, writer, &handshake, &config).await;
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Self::handle_authenticated_static(
            crypto_reader,
            crypto_writer,
            success,
            self.upstream_manager,
            self.stats,
            self.config,
            buffer_pool,
            self.rng,
            self.me_pool,
            local_addr,
        )
        .await
    }

    /// Main dispatch after successful handshake.
    /// Two modes:
    ///   - Direct: TCP relay to TG DC (existing behavior)
    ///   - Middle Proxy: RPC multiplex through ME pool (new — supports CDN DCs)
    pub(crate) async fn handle_authenticated_static<R, W>(
        client_reader: CryptoReader<R>,
        client_writer: CryptoWriter<W>,
        success: HandshakeSuccess,
        upstream_manager: Arc<UpstreamManager>,
        stats: Arc<Stats>,
        config: Arc<ProxyConfig>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        me_pool: Option<Arc<MePool>>,
        local_addr: SocketAddr,
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
        if config.general.use_middle_proxy {
            if let Some(ref pool) = me_pool {
                return handle_via_middle_proxy(
                    client_reader,
                    client_writer,
                    success,
                    pool.clone(),
                    stats,
                    config,
                    buffer_pool,
                    local_addr,
                )
                .await;
            }
            warn!("use_middle_proxy=true but MePool not initialized, falling back to direct");
        }

        // Direct mode (original behavior)
        handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager,
            stats,
            config,
            buffer_pool,
            rng,
        )
        .await
    }

    fn check_user_limits_static(user: &str, config: &ProxyConfig, stats: &Stats) -> Result<()> {
        if let Some(expiration) = config.access.user_expirations.get(user) {
            if chrono::Utc::now() > *expiration {
                return Err(ProxyError::UserExpired {
                    user: user.to_string(),
                });
            }
        }

        if let Some(limit) = config.access.user_max_tcp_conns.get(user) {
            if stats.get_user_curr_connects(user) >= *limit as u64 {
                return Err(ProxyError::ConnectionLimitExceeded {
                    user: user.to_string(),
                });
            }
        }

        if let Some(quota) = config.access.user_data_quota.get(user) {
            if stats.get_user_total_octets(user) >= *quota {
                return Err(ProxyError::DataQuotaExceeded {
                    user: user.to_string(),
                });
            }
        }

        Ok(())
    }
}
