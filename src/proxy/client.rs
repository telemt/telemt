//! Client Handler

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
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
use crate::stats::beobachten::BeobachtenStore;
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
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};

const fn beobachten_ttl(config: &ProxyConfig) -> Duration {
    Duration::from_secs(config.general.beobachten_minutes.saturating_mul(60))
}

fn record_beobachten_class(
    beobachten: &BeobachtenStore,
    config: &ProxyConfig,
    peer_ip: IpAddr,
    class: &str,
) {
    if !config.general.beobachten {
        return;
    }
    beobachten.record(class, peer_ip, beobachten_ttl(config));
}

fn record_handshake_failure_class(
    beobachten: &BeobachtenStore,
    config: &ProxyConfig,
    peer_ip: IpAddr,
    error: &ProxyError,
) {
    // Classify connection-closed-before-handshake probes separately so the
    // beobachten store can distinguish port scanners (send SYN, read banner,
    // drop) from other failures. Matching on error variants is robust against
    // changes to error message formatting.
    let class = match error {
        ProxyError::Stream(crate::error::StreamError::UnexpectedEof) => "expected_64_got_0",
        ProxyError::Stream(crate::error::StreamError::PartialRead { got: 0, .. }) => {
            "expected_64_got_0"
        }
        ProxyError::Io(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            "expected_64_got_0"
        }
        _ => "other",
    };
    record_beobachten_class(beobachten, config, peer_ip, class);
}

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
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    proxy_protocol_enabled: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stats.increment_connects_all();
    let mut real_peer = normalize_ip(peer);

    // For non-TCP streams, use a synthetic local address; may be overridden by PROXY protocol dst
    let mut local_addr: SocketAddr = format!("0.0.0.0:{}", config.server.port)
        .parse()
        .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 443)));

    if proxy_protocol_enabled {
        let proxy_header_timeout = Duration::from_millis(
            config.server.proxy_protocol_header_timeout_ms.max(1),
        );
        match timeout(proxy_header_timeout, parse_proxy_protocol(&mut stream, peer)).await {
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
                stats.increment_connects_bad();
                warn!(peer = %peer, error = %e, "Invalid PROXY protocol header");
                record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                return Err(e);
            }
            Err(_) => {
                stats.increment_connects_bad();
                warn!(peer = %peer, timeout_ms = proxy_header_timeout.as_millis(), "PROXY protocol header timeout");
                record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                return Err(ProxyError::InvalidProxyProtocol);
            }
        }
    }

    debug!(peer = %real_peer, "New connection (generic stream)");

    let handshake_timeout = Duration::from_secs(config.timeouts.client_handshake);
    let stats_for_timeout = stats.clone();
    let config_for_timeout = config.clone();
    let beobachten_for_timeout = beobachten.clone();
    let peer_for_timeout = real_peer.ip();

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
                handle_bad_client(
                    reader,
                    writer,
                    &first_bytes,
                    real_peer,
                    local_addr,
                    &config,
                    &beobachten,
                )
                .await;
                return Ok(HandshakeOutcome::Handled);
            }

            let mut handshake = vec![0u8; 5 + tls_len];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

            let (mut tls_reader, tls_writer, tls_user) = match handle_tls_handshake(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, &rng, tls_cache.clone(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad();
                    handle_bad_client(
                        reader,
                        writer,
                        &handshake,
                        real_peer,
                        local_addr,
                        &config,
                        &beobachten,
                    )
                    .await;
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
                &config, &replay_checker, true, Some(tls_user.as_str()),
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
                    route_runtime.clone(),
                    local_addr, real_peer, ip_tracker.clone(),
                ),
            )))
        } else {
            if !config.general.modes.classic && !config.general.modes.secure {
                debug!(peer = %real_peer, "Non-TLS modes disabled");
                stats.increment_connects_bad();
                let (reader, writer) = tokio::io::split(stream);
                handle_bad_client(
                    reader,
                    writer,
                    &first_bytes,
                    real_peer,
                    local_addr,
                    &config,
                    &beobachten,
                )
                .await;
                return Ok(HandshakeOutcome::Handled);
            }

            let mut handshake = [0u8; HANDSHAKE_LEN];
            handshake[..5].copy_from_slice(&first_bytes);
            stream.read_exact(&mut handshake[5..]).await?;

            let (read_half, write_half) = tokio::io::split(stream);

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, false, None,
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad();
                    handle_bad_client(
                        reader,
                        writer,
                        &handshake,
                        real_peer,
                        local_addr,
                        &config,
                        &beobachten,
                    )
                    .await;
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
                    route_runtime.clone(),
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
        HandshakeOutcome::NeedsRelay(fut) => fut.await,
        HandshakeOutcome::Handled => Ok(()),
    }
}

pub struct ClientHandler;

pub struct RunningClientHandler {
    stream: TcpStream,
    peer: SocketAddr,
    real_peer_from_proxy: Option<SocketAddr>,
    real_peer_report: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    replay_checker: Arc<ReplayChecker>,
    upstream_manager: Arc<UpstreamManager>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    proxy_protocol_enabled: bool,
}

impl ClientHandler {
    pub const fn new(
        stream: TcpStream,
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
        real_peer_report: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    ) -> RunningClientHandler {
        let normalized_peer = normalize_ip(peer);
        RunningClientHandler {
            stream,
            peer: normalized_peer,
            real_peer_from_proxy: None,
            real_peer_report,
            config,
            stats,
            replay_checker,
            upstream_manager,
            buffer_pool,
            rng,
            me_pool,
            route_runtime,
            tls_cache,
            ip_tracker,
            beobachten,
            proxy_protocol_enabled,
        }
    }
}

impl RunningClientHandler {
    pub async fn run(self) -> Result<()> {
        self.stats.increment_connects_all();
        let peer = self.peer;
        let _ip_tracker = self.ip_tracker.clone();
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
        let config_for_timeout = self.config.clone();
        let beobachten_for_timeout = self.beobachten.clone();
        let peer_for_timeout = peer.ip();

        // Phase 1: handshake (with timeout)
        let outcome = match timeout(handshake_timeout, self.do_handshake()).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                debug!(peer = %peer, error = %e, "Handshake failed");
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
            HandshakeOutcome::NeedsRelay(fut) => fut.await,
            HandshakeOutcome::Handled => Ok(()),
        }
    }

    async fn do_handshake(mut self) -> Result<HandshakeOutcome> {
        let mut local_addr = self.stream.local_addr().map_err(ProxyError::Io)?;

        if self.proxy_protocol_enabled {
            let proxy_header_timeout = Duration::from_millis(
                self.config.server.proxy_protocol_header_timeout_ms.max(1),
            );
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
                    self.stats.increment_connects_bad();
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
                    self.stats.increment_connects_bad();
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

        let mut first_bytes = [0u8; 5];
        self.stream.read_exact(&mut first_bytes).await?;

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        let peer = self.peer;
        let _ip_tracker = self.ip_tracker.clone();

        debug!(peer = %peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            self.handle_tls_client(first_bytes, local_addr).await
        } else {
            self.handle_direct_client(first_bytes, local_addr).await
        }
    }

    async fn handle_tls_client(mut self, first_bytes: [u8; 5], local_addr: SocketAddr) -> Result<HandshakeOutcome> {
        let peer = self.peer;
        let _ip_tracker = self.ip_tracker.clone();

        let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;

        debug!(peer = %peer, tls_len = tls_len, "Reading TLS handshake");

        if tls_len < 512 {
            debug!(peer = %peer, tls_len = tls_len, "TLS handshake too short");
            self.stats.increment_connects_bad();
            let (reader, writer) = self.stream.into_split();
            handle_bad_client(
                reader,
                writer,
                &first_bytes,
                peer,
                local_addr,
                &self.config,
                &self.beobachten,
            )
            .await;
            return Ok(HandshakeOutcome::Handled);
        }

        let mut handshake = vec![0u8; 5 + tls_len];
        handshake[..5].copy_from_slice(&first_bytes);
        self.stream.read_exact(&mut handshake[5..]).await?;

        let config = self.config.clone();
        let replay_checker = self.replay_checker.clone();
        let stats = self.stats.clone();
        let buffer_pool = self.buffer_pool.clone();

        let (read_half, write_half) = self.stream.into_split();

        let (mut tls_reader, tls_writer, tls_user) = match handle_tls_handshake(
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
                handle_bad_client(
                    reader,
                    writer,
                    &handshake,
                    peer,
                    local_addr,
                    &config,
                    &self.beobachten,
                )
                .await;
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
            Some(tls_user.as_str()),
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
                self.route_runtime.clone(),
                local_addr,
                peer,
                self.ip_tracker,
            ),
        )))
    }

    async fn handle_direct_client(mut self, first_bytes: [u8; 5], local_addr: SocketAddr) -> Result<HandshakeOutcome> {
        let peer = self.peer;
        let _ip_tracker = self.ip_tracker.clone();

        if !self.config.general.modes.classic && !self.config.general.modes.secure {
            debug!(peer = %peer, "Non-TLS modes disabled");
            self.stats.increment_connects_bad();
            let (reader, writer) = self.stream.into_split();
            handle_bad_client(
                reader,
                writer,
                &first_bytes,
                peer,
                local_addr,
                &self.config,
                &self.beobachten,
            )
            .await;
            return Ok(HandshakeOutcome::Handled);
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
            &handshake,
            read_half,
            write_half,
            peer,
            &config,
            &replay_checker,
            false,
            None,
        )
        .await
        {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad();
                handle_bad_client(
                    reader,
                    writer,
                    &handshake,
                    peer,
                    local_addr,
                    &config,
                    &self.beobachten,
                )
                .await;
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
                self.route_runtime.clone(),
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
        route_runtime: Arc<RouteRuntimeController>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        ip_tracker: Arc<UserIpTracker>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let user = success.user.clone();

        if let Err(e) = Self::check_user_limits_static(&user, &config, &stats, peer_addr, &ip_tracker).await {
            warn!(user = %user, error = %e, "User limit exceeded");
            return Err(e);
        }

        let route_snapshot = route_runtime.snapshot();
        let session_id = rng.u64();
        let relay_result = if config.general.use_middle_proxy
            && matches!(route_snapshot.mode, RelayRouteMode::Middle)
        {
            if let Some(ref pool) = me_pool {
                handle_via_middle_proxy(
                    client_reader,
                    client_writer,
                    success,
                    pool.clone(),
                    stats,
                    config,
                    buffer_pool,
                    local_addr,
                    rng,
                    route_runtime.subscribe(),
                    route_snapshot,
                    session_id,
                )
                .await
            } else {
                warn!("use_middle_proxy=true but MePool not initialized, falling back to direct");
                handle_via_direct(
                    client_reader,
                    client_writer,
                    success,
                    upstream_manager,
                    stats,
                    config,
                    buffer_pool,
                    rng,
                    route_runtime.subscribe(),
                    route_snapshot,
                    session_id,
                )
                .await
            }
        } else {
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
                route_runtime.subscribe(),
                route_snapshot,
                session_id,
            )
            .await
        };

        ip_tracker.remove_ip(&user, peer_addr.ip()).await;
        relay_result
    }

    async fn check_user_limits_static(
        user: &str, 
        config: &ProxyConfig, 
        stats: &Stats,
        peer_addr: SocketAddr,
        ip_tracker: &UserIpTracker,
    ) -> Result<()> {
        if let Some(expiration) = config.access.user_expirations.get(user)
            && chrono::Utc::now() > *expiration
        {
            return Err(ProxyError::UserExpired {
                user: user.to_string(),
            });
        }

        let ip_reserved = match ip_tracker.check_and_add(user, peer_addr.ip()).await {
            Ok(()) => true,
            Err(reason) => {
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
        };
        // IP limit check

        if let Some(limit) = config.access.user_max_tcp_conns.get(user)
            && stats.get_user_curr_connects(user) >= *limit as u64
        {
            if ip_reserved {
                ip_tracker.remove_ip(user, peer_addr.ip()).await;
                stats.increment_ip_reservation_rollback_tcp_limit_total();
            }
            return Err(ProxyError::ConnectionLimitExceeded {
                user: user.to_string(),
            });
        }

        if let Some(quota) = config.access.user_data_quota.get(user)
            && stats.get_user_total_octets(user) >= *quota
        {
            if ip_reserved {
                ip_tracker.remove_ip(user, peer_addr.ip()).await;
                stats.increment_ip_reservation_rollback_quota_limit_total();
            }
            return Err(ProxyError::DataQuotaExceeded {
                user: user.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StreamError;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::stats::beobachten::BeobachtenStore;

    fn make_beobachten() -> Arc<BeobachtenStore> {
        Arc::new(BeobachtenStore::default())
    }

    fn make_config_beobachten_on() -> Arc<ProxyConfig> {
        // Default ProxyConfig: beobachten=true, beobachten_minutes=10
        Arc::new(ProxyConfig::default())
    }

    fn make_config_beobachten_off() -> Arc<ProxyConfig> {
        let mut cfg = ProxyConfig::default();
        cfg.general.beobachten = false;
        Arc::new(cfg)
    }

    fn peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
    }

    /// Verify that the given class name appears in the beobachten snapshot.
    ///
    /// `snapshot_text` format: `[class_name]\n<ip>-<count>\n...`
    fn snapshot_contains_class(store: &BeobachtenStore, class: &str) -> bool {
        // Use a large TTL so entries are never expired during the test.
        let text = store.snapshot_text(Duration::from_secs(3600));
        let header = format!("[{class}]");
        text.contains(&header)
    }

    // ── record_handshake_failure_class ───────────────────────────────────────

    #[test]
    fn unexpected_eof_io_error_classified_as_port_scanner_class() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(
            snapshot_contains_class(&b, "expected_64_got_0"),
            "UnexpectedEof should be classified as 'expected_64_got_0'"
        );
        assert!(
            !snapshot_contains_class(&b, "other"),
            "should not also appear under 'other'"
        );
    }

    #[test]
    fn connection_reset_io_error_classified_as_port_scanner_class() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "expected_64_got_0"));
    }

    #[test]
    fn stream_unexpected_eof_classified_as_port_scanner_class() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Stream(StreamError::UnexpectedEof);
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "expected_64_got_0"));
    }

    #[test]
    fn partial_read_got_zero_classified_as_port_scanner_class() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 64, got: 0 });
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "expected_64_got_0"));
    }

    #[test]
    fn partial_read_got_nonzero_classified_as_other() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        // got > 0: partial data received, not a clean close
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 64, got: 32 });
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(
            snapshot_contains_class(&b, "other"),
            "PartialRead with got=32 should be 'other'"
        );
        assert!(
            !snapshot_contains_class(&b, "expected_64_got_0"),
            "should not be classified as 'expected_64_got_0'"
        );
    }

    #[test]
    fn proxy_error_string_classified_as_other() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Proxy("upstream refused connection".into());
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "other"));
    }

    #[test]
    fn handshake_timeout_classified_as_other() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::TgHandshakeTimeout;
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "other"));
    }

    #[test]
    fn beobachten_disabled_records_nothing() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_off();
        let err = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        // When beobachten is disabled, the store must remain empty.
        let snap = b.snapshot_text(Duration::from_secs(3600));
        assert_eq!(snap, "empty\n", "beobachten disabled: store must be empty");
    }

    #[test]
    fn error_message_format_change_does_not_affect_classification() {
        // Regression: old code used `.to_string().contains("expected 64 bytes, got 0")`
        // which silently breaks if the error format changes. This tests the new
        // variant-matching path is independent of formatting.
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();

        // ProxyError::Io wrapping an UnexpectedEof — the Display format of
        // io::Error can change between Rust versions. Classification must not
        // depend on the human-readable string.
        let raw_io = std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "some version-specific message that could change",
        );
        let err = ProxyError::Io(raw_io);
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(
            snapshot_contains_class(&b, "expected_64_got_0"),
            "Classification must be based on error kind, not message text"
        );
    }

    // ── Boundary: got == 0 vs got == 1 ──────────────────────────────────────
    // A censor that sends exactly 1 byte before closing (slow-probe) is
    // classified as "other" — only a clean 0-byte close gets "expected_64_got_0".

    #[test]
    fn partial_read_got_one_is_other() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 64, got: 1 });
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "other"));
        assert!(!snapshot_contains_class(&b, "expected_64_got_0"));
    }

    #[test]
    fn partial_read_expected_5_got_zero_is_expected_64_got_0() {
        // The class name is historical; it fires for ANY got==0 partial read,
        // not only 64-byte ones.  The `..` wildcard in the match arm guarantees this.
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 5, got: 0 });
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "expected_64_got_0"));
    }

    #[test]
    fn invalid_handshake_error_classified_as_other() {
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let err = ProxyError::InvalidHandshake("garbled bytes from censor".into());
        record_handshake_failure_class(&b, &cfg, peer_ip(), &err);

        assert!(snapshot_contains_class(&b, "other"));
        assert!(!snapshot_contains_class(&b, "expected_64_got_0"));
    }

    #[test]
    fn two_different_ips_accumulate_under_same_class() {
        // If two censors from distinct IPs both do a clean-close probe, both
        // must appear under "expected_64_got_0" without stomping each other.
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let err = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        record_handshake_failure_class(&b, &cfg, ip_a, &err);
        record_handshake_failure_class(&b, &cfg, ip_b, &err);

        let text = b.snapshot_text(Duration::from_secs(3600));
        assert!(text.contains("[expected_64_got_0]"));
        // Both IPs must appear under the same section.
        assert!(text.contains("10.0.0.1") || text.contains("::ffff:10.0.0.1"), "ip_a missing");
        assert!(text.contains("10.0.0.2") || text.contains("::ffff:10.0.0.2"), "ip_b missing");
    }

    #[test]
    fn two_different_ips_with_different_classes_do_not_bleed() {
        // IP A → expected_64_got_0, IP B → other.  They must end up in separate
        // beobachten sections and must NOT appear under each other's section.
        let b = make_beobachten();
        let cfg = make_config_beobachten_on();
        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let err_eof = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        let err_other = ProxyError::TgHandshakeTimeout;

        record_handshake_failure_class(&b, &cfg, ip_a, &err_eof);
        record_handshake_failure_class(&b, &cfg, ip_b, &err_other);

        let text = b.snapshot_text(Duration::from_secs(3600));

        // Find positions of each section header.
        let pos_eof = text.find("[expected_64_got_0]").expect("[expected_64_got_0] section missing");
        let pos_other = text.find("[other]").expect("[other] section missing");

        // ip_a must appear AFTER pos_eof and BEFORE pos_other (or after, depending on order)
        // — the key invariant is that each IP appears exactly once.
        let ip_a_pos = text.find("192.168.1.1").or_else(|| text.find("::ffff:192.168.1.1")).expect("ip_a not found in snapshot");
        let ip_b_pos = text.find("192.168.1.2").or_else(|| text.find("::ffff:192.168.1.2")).expect("ip_b not found in snapshot");

        // ip_a should be in the expected_64_got_0 section (between pos_eof and the next section)
        assert!(
            ip_a_pos > pos_eof && (ip_a_pos < pos_other || pos_other < pos_eof),
            "ip_a not in expected_64_got_0 section"
        );
        // ip_b should be in the other section
        assert!(
            ip_b_pos > pos_other || pos_other > pos_eof,
            "ip_b not in other section"
        );
    }
}
