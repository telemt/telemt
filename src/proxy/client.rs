//! Client Handler

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Post-handshake future (relay phase, runs outside handshake timeout)
type PostHandshakeFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Result of the handshake phase
enum HandshakeOutcome {
    /// Handshake succeeded, relay work to do (outside timeout)
    NeedsRelay(PostHandshakeFuture),
    /// Already fully handled (bad client masking, etc.)
    Handled,
}

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{HandshakeResult, ProxyError, Result};
use crate::ip_tracker::UserIpTracker;
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::MePool;
use crate::transport::{UpstreamManager, configure_client_socket, parse_proxy_protocol};
use crate::transport::socket::normalize_ip;
use crate::tls_front::TlsFrontCache;

use crate::proxy::direct_relay::handle_via_direct;
use crate::proxy::handshake::{HandshakeSuccess, handle_mtproto_handshake, handle_tls_handshake};
use crate::proxy::masking::handle_bad_client;
use crate::proxy::middle_relay::handle_via_middle_proxy;

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
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    proxy_protocol_enabled: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stats.increment_connects_all();
    let mut real_peer = normalize_ip(peer);

    if proxy_protocol_enabled {
        match parse_proxy_protocol(&mut stream, peer).await {
            Ok(info) => {
                debug!(
                    peer = %peer,
                    client = %info.src_addr,
                    version = info.version,
                    "PROXY protocol header parsed"
                );
                real_peer = normalize_ip(info.src_addr);
            }
            Err(e) => {
                stats.increment_connects_bad();
                warn!(peer = %peer, error = %e, "Invalid PROXY protocol header");
                return Err(e);
            }
        }
    }

    debug!(peer = %real_peer, "New connection (generic stream)");

    let handshake_timeout = Duration::from_secs(config.timeouts.client_handshake);
    let stats_for_timeout = stats.clone();

    // For non-TCP streams, use a synthetic local address
    let local_addr: SocketAddr = format!("0.0.0.0:{}", config.server.port)
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:443".parse().unwrap());

    // Phase 1: handshake (with timeout)
    let outcome = match timeout(handshake_timeout, async {
        let mut first_bytes = [0u8; 5];
        stream.read_exact(&mut first_bytes).await?;

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        debug!(peer = %real_peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

            if tls_len < 512 {
                debug!(peer = %real_peer, tls_len = tls_len, "TLS handshake too short");
                stats.increment_connects_bad();
                let (reader, writer) = tokio::io::split(stream);
                handle_bad_client(reader, writer, &first_bytes, &config).await;
                return Ok(HandshakeOutcome::Handled);
            }

            let mut handshake = vec![0u8; 5 + tls_len];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

            let (mut tls_reader, tls_writer, _tls_user) = match handle_tls_handshake(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, &rng, tls_cache.clone(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad();
                    handle_bad_client(reader, writer, &handshake, &config).await;
                    return Ok(HandshakeOutcome::Handled);
                }
                HandshakeResult::Error(e) => return Err(e),
            };

            debug!(peer = %peer, "Reading MTProto handshake through TLS");
            let mtproto_data = tls_reader.read_exact(HANDSHAKE_LEN).await?;
            let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..].try_into()
                .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
                &mtproto_handshake, tls_reader, tls_writer, real_peer,
                &config, &replay_checker, true,
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader: _, writer: _ } => {
                    stats.increment_connects_bad();
                    debug!(peer = %peer, "Valid TLS but invalid MTProto handshake");
                    return Ok(HandshakeOutcome::Handled);
                }
                HandshakeResult::Error(e) => return Err(e),
            };

            Ok(HandshakeOutcome::NeedsRelay(Box::pin(
                RunningClientHandler::handle_authenticated_static(
                    crypto_reader, crypto_writer, success,
                    upstream_manager, stats, config, buffer_pool, rng, me_pool,
                    local_addr, real_peer, ip_tracker.clone(),
                ),
            )))
        } else {
            if !config.general.modes.classic && !config.general.modes.secure {
                debug!(peer = %real_peer, "Non-TLS modes disabled");
                stats.increment_connects_bad();
                let (reader, writer) = tokio::io::split(stream);
                handle_bad_client(reader, writer, &first_bytes, &config).await;
                return Ok(HandshakeOutcome::Handled);
            }

            let mut handshake = [0u8; HANDSHAKE_LEN];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, false,
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad();
                    handle_bad_client(reader, writer, &handshake, &config).await;
                    return Ok(HandshakeOutcome::Handled);
                }
                HandshakeResult::Error(e) => return Err(e),
            };

            Ok(HandshakeOutcome::NeedsRelay(Box::pin(
                RunningClientHandler::handle_authenticated_static(
                    crypto_reader,
                    crypto_writer,
                    success,
                    upstream_manager,
                    stats,
                    config,
                    buffer_pool,
                    rng,
                    me_pool,
                    local_addr,
                    real_peer,
                    ip_tracker.clone(),
                )
            )))
        }
    }).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(e)) => {
            debug!(peer = %peer, error = %e, "Handshake failed");
            return Err(e);
        }
        Err(_) => {
            stats_for_timeout.increment_handshake_timeouts();
            debug!(peer = %peer, "Handshake timeout");
            return Err(ProxyError::TgHandshakeTimeout);
        }
    };

    // Phase 2: relay (WITHOUT handshake timeout — relay has its own activity timeouts)
    match outcome {
        HandshakeOutcome::NeedsRelay(fut) => fut.await,
        HandshakeOutcome::Handled => Ok(()),
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
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    proxy_protocol_enabled: bool,
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
        tls_cache: Option<Arc<TlsFrontCache>>,
        ip_tracker: Arc<UserIpTracker>,
        proxy_protocol_enabled: bool,
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
            tls_cache,
            ip_tracker,
            proxy_protocol_enabled,
        }
    }
}

impl RunningClientHandler {
    pub async fn run(mut self) -> Result<()> {
        self.stats.increment_connects_all();

        self.peer = normalize_ip(self.peer);
        let peer = self.peer;
        let ip_tracker = self.ip_tracker.clone();
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

        // Phase 1: handshake (with timeout)
        let outcome = match timeout(handshake_timeout, self.do_handshake()).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                debug!(peer = %peer, error = %e, "Handshake failed");
                return Err(e);
            }
            Err(_) => {
                stats.increment_handshake_timeouts();
                debug!(peer = %peer, "Handshake timeout");
                return Err(ProxyError::TgHandshakeTimeout);
            }
        };

        // Phase 2: relay (WITHOUT handshake timeout — relay has its own activity timeouts)
        match outcome {
            HandshakeOutcome::NeedsRelay(fut) => fut.await,
            HandshakeOutcome::Handled => Ok(()),
        }
    }

    async fn do_handshake(mut self) -> Result<HandshakeOutcome> {
        if self.proxy_protocol_enabled {
            match parse_proxy_protocol(&mut self.stream, self.peer).await {
                Ok(info) => {
                    debug!(
                        peer = %self.peer,
                        client = %info.src_addr,
                        version = info.version,
                        "PROXY protocol header parsed"
                    );
                    self.peer = normalize_ip(info.src_addr);
                }
                Err(e) => {
                    self.stats.increment_connects_bad();
                    warn!(peer = %self.peer, error = %e, "Invalid PROXY protocol header");
                    return Err(e);
                }
            }
        }

        let mut first_bytes = [0u8; 5];
        self.stream.read_exact(&mut first_bytes).await?;

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        let peer = self.peer;
        let ip_tracker = self.ip_tracker.clone();

        debug!(peer = %peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            self.handle_tls_client(first_bytes).await
        } else {
            self.handle_direct_client(first_bytes).await
        }
    }

    async fn handle_tls_client(mut self, first_bytes: [u8; 5]) -> Result<HandshakeOutcome> {
        let peer = self.peer;
        let ip_tracker = self.ip_tracker.clone();

        let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

        debug!(peer = %peer, tls_len = tls_len, "Reading TLS handshake");

        if tls_len < 512 {
            debug!(peer = %peer, tls_len = tls_len, "TLS handshake too short");
            self.stats.increment_connects_bad();
            let (reader, writer) = self.stream.into_split();
            handle_bad_client(reader, writer, &first_bytes, &self.config).await;
            return Ok(HandshakeOutcome::Handled);
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
            self.tls_cache.clone(),
        )
        .await
        {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad();
                handle_bad_client(reader, writer, &handshake, &config).await;
                return Ok(HandshakeOutcome::Handled);
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
                return Ok(HandshakeOutcome::Handled);
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Ok(HandshakeOutcome::NeedsRelay(Box::pin(
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
                peer,
                self.ip_tracker,
            ),
        )))
    }

    async fn handle_direct_client(mut self, first_bytes: [u8; 5]) -> Result<HandshakeOutcome> {
        let peer = self.peer;
        let ip_tracker = self.ip_tracker.clone();

        if !self.config.general.modes.classic && !self.config.general.modes.secure {
            debug!(peer = %peer, "Non-TLS modes disabled");
            self.stats.increment_connects_bad();
            let (reader, writer) = self.stream.into_split();
            handle_bad_client(reader, writer, &first_bytes, &self.config).await;
            return Ok(HandshakeOutcome::Handled);
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
                return Ok(HandshakeOutcome::Handled);
            }
            HandshakeResult::Error(e) => return Err(e),
        };

        Ok(HandshakeOutcome::NeedsRelay(Box::pin(
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
                peer,
                self.ip_tracker,
            ),
        )))
    }

    /// Main dispatch after successful handshake.
    /// Two modes:
    ///   - Direct: TCP relay to TG DC (existing behavior)  
    ///   - Middle Proxy: RPC multiplex through ME pool (new — supports CDN DCs)
    async fn handle_authenticated_static<R, W>(
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
        peer_addr: SocketAddr,
        ip_tracker: Arc<UserIpTracker>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let user = &success.user;

        if let Err(e) = Self::check_user_limits_static(user, &config, &stats, peer_addr, &ip_tracker).await {
            warn!(user = %user, error = %e, "User limit exceeded");
            return Err(e);
        }

        // IP Cleanup Guard: автоматически удаляет IP при выходе из scope
        struct IpCleanupGuard {
            tracker: Arc<UserIpTracker>,
            user: String,
            ip: std::net::IpAddr,
        }
        
        impl Drop for IpCleanupGuard {
            fn drop(&mut self) {
                let tracker = self.tracker.clone();
                let user = self.user.clone();
                let ip = self.ip;
                tokio::spawn(async move {
                    tracker.remove_ip(&user, ip).await;
                    debug!(user = %user, ip = %ip, "IP cleaned up on disconnect");
                });
            }
        }
        
        let _cleanup = IpCleanupGuard {
            tracker: ip_tracker,
            user: user.clone(),
            ip: peer_addr.ip(),
        };

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
                    rng,
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

    async fn check_user_limits_static(
        user: &str, 
        config: &ProxyConfig, 
        stats: &Stats,
        peer_addr: SocketAddr,
        ip_tracker: &UserIpTracker,
    ) -> Result<()> {
        if let Some(expiration) = config.access.user_expirations.get(user) {
            if chrono::Utc::now() > *expiration {
                return Err(ProxyError::UserExpired {
                    user: user.to_string(),
                });
            }
        }

        // IP limit check
        if let Err(reason) = ip_tracker.check_and_add(user, peer_addr.ip()).await {
            warn!(
                user = %user, 
                ip = %peer_addr.ip(),
                reason = %reason,
                "IP limit exceeded"
            );
            return Err(ProxyError::ConnectionLimitExceeded {
                user: user.to_string(),
            });
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
