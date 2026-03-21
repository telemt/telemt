//! Client Handler

use ipnetwork::IpNetwork;
use rand::RngExt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Handshake failed and masking must run outside handshake timeout budget
    NeedsMasking(PostHandshakeFuture),
}

#[must_use = "UserConnectionReservation must be kept alive to retain user/IP reservation until release or drop"]
struct UserConnectionReservation {
    stats: Arc<Stats>,
    ip_tracker: Arc<UserIpTracker>,
    user: String,
    ip: IpAddr,
    active: bool,
}

impl UserConnectionReservation {
    fn new(stats: Arc<Stats>, ip_tracker: Arc<UserIpTracker>, user: String, ip: IpAddr) -> Self {
        Self {
            stats,
            ip_tracker,
            user,
            ip,
            active: true,
        }
    }

    async fn release(mut self) {
        if !self.active {
            return;
        }
        self.ip_tracker.remove_ip(&self.user, self.ip).await;
        self.active = false;
        self.stats.decrement_user_curr_connects(&self.user);
    }
}

impl Drop for UserConnectionReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.stats.decrement_user_curr_connects(&self.user);
        self.ip_tracker.enqueue_cleanup(self.user.clone(), self.ip);
    }
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
use crate::tls_front::TlsFrontCache;
use crate::transport::middle_proxy::MePool;
use crate::transport::socket::normalize_ip;
use crate::transport::{UpstreamManager, configure_client_socket, parse_proxy_protocol};

use crate::proxy::direct_relay::handle_via_direct;
use crate::proxy::handshake::{HandshakeSuccess, handle_mtproto_handshake, handle_tls_handshake};
use crate::proxy::masking::handle_bad_client;
use crate::proxy::middle_relay::handle_via_middle_proxy;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};

fn beobachten_ttl(config: &ProxyConfig) -> Duration {
    const BEOBACHTEN_TTL_MAX_MINUTES: u64 = 24 * 60;
    let minutes = config.general.beobachten_minutes;
    if minutes == 0 {
        static BEOBACHTEN_ZERO_MINUTES_WARNED: OnceLock<AtomicBool> = OnceLock::new();
        let warned = BEOBACHTEN_ZERO_MINUTES_WARNED.get_or_init(|| AtomicBool::new(false));
        if !warned.swap(true, Ordering::Relaxed) {
            warn!(
                "general.beobachten_minutes=0 is insecure because entries expire immediately; forcing minimum TTL to 1 minute"
            );
        }
        return Duration::from_secs(60);
    }

    if minutes > BEOBACHTEN_TTL_MAX_MINUTES {
        static BEOBACHTEN_OVERSIZED_MINUTES_WARNED: OnceLock<AtomicBool> = OnceLock::new();
        let warned = BEOBACHTEN_OVERSIZED_MINUTES_WARNED.get_or_init(|| AtomicBool::new(false));
        if !warned.swap(true, Ordering::Relaxed) {
            warn!(
                configured_minutes = minutes,
                max_minutes = BEOBACHTEN_TTL_MAX_MINUTES,
                "general.beobachten_minutes is too large; clamping to secure maximum"
            );
        }
    }

    Duration::from_secs(minutes.min(BEOBACHTEN_TTL_MAX_MINUTES).saturating_mul(60))
}

fn wrap_tls_application_record(payload: &[u8]) -> Vec<u8> {
    let chunks = payload.len().div_ceil(u16::MAX as usize).max(1);
    let mut record = Vec::with_capacity(payload.len() + 5 * chunks);

    if payload.is_empty() {
        record.push(TLS_RECORD_APPLICATION);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&0u16.to_be_bytes());
        return record;
    }

    for chunk in payload.chunks(u16::MAX as usize) {
        record.push(TLS_RECORD_APPLICATION);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        record.extend_from_slice(chunk);
    }

    record
}

fn tls_clienthello_len_in_bounds(tls_len: usize) -> bool {
    (MIN_TLS_CLIENT_HELLO_SIZE..=MAX_TLS_PLAINTEXT_SIZE).contains(&tls_len)
}

async fn read_with_progress<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut total = 0usize;
    while !buf.is_empty() {
        match reader.read(buf).await {
            Ok(0) => return Ok(total),
            Ok(n) => {
                total += n;
                let (_, rest) = buf.split_at_mut(n);
                buf = rest;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

async fn maybe_apply_mask_reject_delay(config: &ProxyConfig) {
    let min = config.censorship.server_hello_delay_min_ms;
    let max = config.censorship.server_hello_delay_max_ms;
    if max == 0 {
        return;
    }

    let delay_ms = if min >= max {
        max
    } else {
        rand::rng().random_range(min..=max)
    };

    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

fn handshake_timeout_with_mask_grace(config: &ProxyConfig) -> Duration {
    let base = Duration::from_secs(config.timeouts.client_handshake);
    if config.censorship.mask {
        base.saturating_add(Duration::from_millis(750))
    } else {
        base
    }
}

fn masking_outcome<R, W>(
    reader: R,
    writer: W,
    initial_data: Vec<u8>,
    peer: SocketAddr,
    local_addr: SocketAddr,
    config: Arc<ProxyConfig>,
    beobachten: Arc<BeobachtenStore>,
) -> HandshakeOutcome
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    HandshakeOutcome::NeedsMasking(Box::pin(async move {
        handle_bad_client(
            reader,
            writer,
            &initial_data,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
        Ok(())
    }))
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

fn synthetic_local_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
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
    let mut local_addr = synthetic_local_addr(config.server.port);

    if proxy_protocol_enabled {
        let proxy_header_timeout =
            Duration::from_millis(config.server.proxy_protocol_header_timeout_ms.max(1));
        match timeout(
            proxy_header_timeout,
            parse_proxy_protocol(&mut stream, peer),
        )
        .await
        {
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

    let handshake_timeout = handshake_timeout_with_mask_grace(&config);
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
                stats.increment_connects_bad();
                maybe_apply_mask_reject_delay(&config).await;
                let (reader, writer) = tokio::io::split(stream);
                return Ok(masking_outcome(
                    reader,
                    writer,
                    first_bytes.to_vec(),
                    real_peer,
                    local_addr,
                    config.clone(),
                    beobachten.clone(),
                ));
            }

            let mut handshake = vec![0u8; 5 + tls_len];
            handshake[..5].copy_from_slice(&first_bytes);
            let body_read = match read_with_progress(&mut stream, &mut handshake[5..]).await {
                Ok(n) => n,
                Err(e) => {
                    debug!(peer = %real_peer, error = %e, tls_len = tls_len, "TLS ClientHello body read failed; engaging masking fallback");
                    stats.increment_connects_bad();
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
                        beobachten.clone(),
                    ));
                }
            };

            if body_read < tls_len {
                debug!(peer = %real_peer, got = body_read, expected = tls_len, "Truncated in-range TLS ClientHello; engaging masking fallback");
                stats.increment_connects_bad();
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
                    beobachten.clone(),
                ));
            }

            let (read_half, write_half) = tokio::io::split(stream);

            let (mut tls_reader, tls_writer, tls_user) = match handle_tls_handshake(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, &rng, tls_cache.clone(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad();
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        handshake.clone(),
                        real_peer,
                        local_addr,
                        config.clone(),
                        beobachten.clone(),
                    ));
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
                    stats.increment_connects_bad();
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
                        beobachten.clone(),
                    ));
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
                maybe_apply_mask_reject_delay(&config).await;
                let (reader, writer) = tokio::io::split(stream);
                return Ok(masking_outcome(
                    reader,
                    writer,
                    first_bytes.to_vec(),
                    real_peer,
                    local_addr,
                    config.clone(),
                    beobachten.clone(),
                ));
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
                    return Ok(masking_outcome(
                        reader,
                        writer,
                        handshake.to_vec(),
                        real_peer,
                        local_addr,
                        config.clone(),
                        beobachten.clone(),
                    ));
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
        HandshakeOutcome::NeedsRelay(fut) | HandshakeOutcome::NeedsMasking(fut) => fut.await,
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
        debug!(peer = %peer, "New connection");

        if let Err(e) = configure_client_socket(
            &self.stream,
            self.config.timeouts.client_keepalive,
            self.config.timeouts.client_ack,
        ) {
            debug!(peer = %peer, error = %e, "Failed to configure client socket");
        }

        let handshake_timeout = handshake_timeout_with_mask_grace(&self.config);
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
            HandshakeOutcome::NeedsRelay(fut) | HandshakeOutcome::NeedsMasking(fut) => fut.await,
        }
    }

    async fn do_handshake(mut self) -> Result<HandshakeOutcome> {
        let mut local_addr = self.stream.local_addr().map_err(ProxyError::Io)?;

        if self.proxy_protocol_enabled {
            let proxy_header_timeout =
                Duration::from_millis(self.config.server.proxy_protocol_header_timeout_ms.max(1));
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

        debug!(peer = %peer, is_tls = is_tls, "Handshake type detected");

        if is_tls {
            self.handle_tls_client(first_bytes, local_addr).await
        } else {
            self.handle_direct_client(first_bytes, local_addr).await
        }
    }

    async fn handle_tls_client(
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
            self.stats.increment_connects_bad();
            maybe_apply_mask_reject_delay(&self.config).await;
            let (reader, writer) = self.stream.into_split();
            return Ok(masking_outcome(
                reader,
                writer,
                first_bytes.to_vec(),
                peer,
                local_addr,
                self.config.clone(),
                self.beobachten.clone(),
            ));
        }

        let mut handshake = vec![0u8; 5 + tls_len];
        handshake[..5].copy_from_slice(&first_bytes);
        let body_read = match read_with_progress(&mut self.stream, &mut handshake[5..]).await {
            Ok(n) => n,
            Err(e) => {
                debug!(peer = %peer, error = %e, tls_len = tls_len, "TLS ClientHello body read failed; engaging masking fallback");
                self.stats.increment_connects_bad();
                maybe_apply_mask_reject_delay(&self.config).await;
                let (reader, writer) = self.stream.into_split();
                return Ok(masking_outcome(
                    reader,
                    writer,
                    handshake[..5].to_vec(),
                    peer,
                    local_addr,
                    self.config.clone(),
                    self.beobachten.clone(),
                ));
            }
        };

        if body_read < tls_len {
            debug!(peer = %peer, got = body_read, expected = tls_len, "Truncated in-range TLS ClientHello; engaging masking fallback");
            self.stats.increment_connects_bad();
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
                self.beobachten.clone(),
            ));
        }

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
                return Ok(masking_outcome(
                    reader,
                    writer,
                    handshake.clone(),
                    peer,
                    local_addr,
                    config.clone(),
                    self.beobachten.clone(),
                ));
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
                stats.increment_connects_bad();
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
                    self.beobachten.clone(),
                ));
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

    async fn handle_direct_client(
        mut self,
        first_bytes: [u8; 5],
        local_addr: SocketAddr,
    ) -> Result<HandshakeOutcome> {
        let peer = self.peer;

        if !self.config.general.modes.classic && !self.config.general.modes.secure {
            debug!(peer = %peer, "Non-TLS modes disabled");
            self.stats.increment_connects_bad();
            maybe_apply_mask_reject_delay(&self.config).await;
            let (reader, writer) = self.stream.into_split();
            return Ok(masking_outcome(
                reader,
                writer,
                first_bytes.to_vec(),
                peer,
                local_addr,
                self.config.clone(),
                self.beobachten.clone(),
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
                return Ok(masking_outcome(
                    reader,
                    writer,
                    handshake.to_vec(),
                    peer,
                    local_addr,
                    config.clone(),
                    self.beobachten.clone(),
                ));
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

        let user_limit_reservation = match Self::acquire_user_connection_reservation_static(
            &user,
            &config,
            stats.clone(),
            peer_addr,
            ip_tracker,
        )
        .await
        {
            Ok(reservation) => reservation,
            Err(e) => {
                warn!(user = %user, error = %e, "User admission check failed");
                return Err(e);
            }
        };

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
        user_limit_reservation.release().await;
        relay_result
    }

    async fn acquire_user_connection_reservation_static(
        user: &str,
        config: &ProxyConfig,
        stats: Arc<Stats>,
        peer_addr: SocketAddr,
        ip_tracker: Arc<UserIpTracker>,
    ) -> Result<UserConnectionReservation> {
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

        Ok(UserConnectionReservation::new(
            stats,
            ip_tracker,
            user.to_string(),
            peer_addr.ip(),
        ))
    }

    #[cfg(test)]
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
            Ok(()) => {
                ip_tracker.remove_ip(user, peer_addr.ip()).await;
                stats.decrement_user_curr_connects(user);
            }
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
#[path = "tests/client_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/client_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/client_tls_mtproto_fallback_security_tests.rs"]
mod tls_mtproto_fallback_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_clienthello_size_security_tests.rs"]
mod tls_clienthello_size_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_clienthello_truncation_adversarial_tests.rs"]
mod tls_clienthello_truncation_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_timing_profile_adversarial_tests.rs"]
mod timing_profile_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_budget_security_tests.rs"]
mod masking_budget_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_redteam_expected_fail_tests.rs"]
mod masking_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/client_masking_hard_adversarial_tests.rs"]
mod masking_hard_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_stress_adversarial_tests.rs"]
mod masking_stress_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_blackhat_campaign_tests.rs"]
mod masking_blackhat_campaign_tests;

#[cfg(test)]
#[path = "tests/client_masking_diagnostics_security_tests.rs"]
mod masking_diagnostics_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_hardening_security_tests.rs"]
mod masking_shape_hardening_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_hardening_adversarial_tests.rs"]
mod masking_shape_hardening_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_hardening_redteam_expected_fail_tests.rs"]
mod masking_shape_hardening_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_classifier_fuzz_redteam_expected_fail_tests.rs"]
mod masking_shape_classifier_fuzz_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/client_masking_probe_evasion_blackhat_tests.rs"]
mod masking_probe_evasion_blackhat_tests;

#[cfg(test)]
#[path = "tests/client_beobachten_ttl_bounds_security_tests.rs"]
mod beobachten_ttl_bounds_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_record_wrap_hardening_security_tests.rs"]
mod tls_record_wrap_hardening_security_tests;
