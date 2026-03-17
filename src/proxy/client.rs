//! Client Handler

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use ipnetwork::IpNetwork;
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
use crate::error::{HandshakeResult, ProxyError, Result, StreamError};
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

fn beobachten_ttl(config: &ProxyConfig) -> Duration {
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
    let class = match error {
        ProxyError::Io(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            "expected_64_got_0"
        }
        ProxyError::Stream(StreamError::UnexpectedEof) => "expected_64_got_0",
        _ => "other",
    };
    record_beobachten_class(beobachten, config, peer_ip, class);
}

fn is_trusted_proxy_source(peer_ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    if trusted.is_empty() {
        static EMPTY_PROXY_TRUST_WARNED: OnceLock<AtomicBool> = OnceLock::new();
        let warned = EMPTY_PROXY_TRUST_WARNED.get_or_init(|| AtomicBool::new(false));
        if !warned.swap(true, Ordering::Relaxed) {
            warn!(
                "PROXY protocol enabled but server.proxy_protocol_trusted_cidrs is empty; rejecting all PROXY headers by default"
            );
        }
        return false;
    }
    trusted.iter().any(|cidr| cidr.contains(peer_ip))
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
        .unwrap_or_else(|_| "0.0.0.0:443".parse().unwrap());

    if proxy_protocol_enabled {
        let proxy_header_timeout = Duration::from_millis(
            config.server.proxy_protocol_header_timeout_ms.max(1),
        );
        match timeout(proxy_header_timeout, parse_proxy_protocol(&mut stream, peer)).await {
            Ok(Ok(info)) => {
                if !is_trusted_proxy_source(peer.ip(), &config.server.proxy_protocol_trusted_cidrs)
                {
                    stats.increment_connects_bad();
                    warn!(
                        peer = %peer,
                        trusted = ?config.server.proxy_protocol_trusted_cidrs,
                        "Rejecting PROXY protocol header from untrusted source"
                    );
                    record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                    return Err(ProxyError::InvalidProxyProtocol);
                }
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

// RFC 8446 §5.1 mandates that TLSPlaintext records must not exceed 2^14
        // bytes (16_384). A client claiming a larger record is non-compliant and
        // may be an active probe attempting to force large allocations.
        //
        // Also enforce a minimum record size to avoid trivial/garbage probes.
        if !(512..=MAX_TLS_RECORD_SIZE).contains(&tls_len) {
                debug!(peer = %real_peer, tls_len = tls_len, max_tls_len = MAX_TLS_RECORD_SIZE, "TLS handshake length out of bounds");
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
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad();
                    debug!(peer = %peer, "Valid TLS but invalid MTProto handshake");
                    handle_bad_client(
                        reader,
                        writer,
                        &mtproto_handshake,
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
                    if !is_trusted_proxy_source(
                        self.peer.ip(),
                        &self.config.server.proxy_protocol_trusted_cidrs,
                    ) {
                        self.stats.increment_connects_bad();
                        warn!(
                            peer = %self.peer,
                            trusted = ?self.config.server.proxy_protocol_trusted_cidrs,
                            "Rejecting PROXY protocol header from untrusted source"
                        );
                        record_beobachten_class(
                            &self.beobachten,
                            &self.config,
                            self.peer.ip(),
                            "other",
                        );
                        return Err(ProxyError::InvalidProxyProtocol);
                    }
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

        // See RFC 8446 §5.1: TLSPlaintext records must not exceed 16_384 bytes.
        // Treat too-small or too-large lengths as active probes and mask them.
        if !(512..=MAX_TLS_RECORD_SIZE).contains(&tls_len) {
            debug!(peer = %peer, tls_len = tls_len, max_tls_len = MAX_TLS_RECORD_SIZE, "TLS handshake length out of bounds");
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
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad();
                debug!(peer = %peer, "Valid TLS but invalid MTProto handshake");
                handle_bad_client(
                    reader,
                    writer,
                    &mtproto_handshake,
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
                    stats.clone(),
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
                    stats.clone(),
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
                stats.clone(),
                config,
                buffer_pool,
                rng,
                route_runtime.subscribe(),
                route_snapshot,
                session_id,
            )
            .await
        };

        stats.decrement_user_curr_connects(&user);
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

        if let Some(quota) = config.access.user_data_quota.get(user)
            && stats.get_user_total_octets(user) >= *quota
        {
            return Err(ProxyError::DataQuotaExceeded {
                user: user.to_string(),
            });
        }

        let limit = config
            .access
            .user_max_tcp_conns
            .get(user)
            .map(|v| *v as u64);
        if !stats.try_acquire_user_curr_connects(user, limit) {
            return Err(ProxyError::ConnectionLimitExceeded {
                user: user.to_string(),
            });
        }

        match ip_tracker.check_and_add(user, peer_addr.ip()).await {
            Ok(()) => {}
            Err(reason) => {
                stats.decrement_user_curr_connects(user);
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
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "client_security_tests.rs"]
mod security_tests;
