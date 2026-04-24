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

use crate::proxy::direct_relay::handle_via_direct_with_shared;
use crate::proxy::handshake::{
    HandshakeSuccess, handle_mtproto_handshake_with_shared, handle_tls_handshake_with_shared,
};
#[cfg(test)]
use crate::proxy::handshake::{handle_mtproto_handshake, handle_tls_handshake};
use crate::proxy::masking::handle_bad_client;
use crate::proxy::middle_relay::handle_via_middle_proxy;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;

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

fn effective_client_first_byte_idle_secs(config: &ProxyConfig, shared: &ProxySharedState) -> u64 {
    let idle_secs = config.timeouts.client_first_byte_idle_secs;
    if idle_secs == 0 {
        return 0;
    }
    if shared.conntrack_pressure_active() {
        idle_secs.min(
            config
                .server
                .conntrack_control
                .profile
                .client_first_byte_idle_cap_secs(),
        )
    } else {
        idle_secs
    }
}

const MASK_CLASSIFIER_PREFETCH_WINDOW: usize = 16;
#[cfg(test)]
const MASK_CLASSIFIER_PREFETCH_TIMEOUT: Duration = Duration::from_millis(5);

fn mask_classifier_prefetch_timeout(config: &ProxyConfig) -> Duration {
    Duration::from_millis(config.censorship.mask_classifier_prefetch_timeout_ms)
}

fn should_prefetch_mask_classifier_window(initial_data: &[u8]) -> bool {
    if initial_data.len() >= MASK_CLASSIFIER_PREFETCH_WINDOW {
        return false;
    }

    if initial_data.is_empty() {
        // Empty initial_data means there is no client probe prefix to refine.
        // Prefetching in this case can consume fallback relay payload bytes and
        // accidentally route them through shaping heuristics.
        return false;
    }

    if initial_data[0] == 0x16 || initial_data.starts_with(b"SSH-") {
        return false;
    }

    initial_data
        .iter()
        .all(|b| b.is_ascii_alphabetic() || *b == b' ')
}

#[cfg(test)]
async fn extend_masking_initial_window<R>(reader: &mut R, initial_data: &mut Vec<u8>)
where
    R: AsyncRead + Unpin,
{
    extend_masking_initial_window_with_timeout(
        reader,
        initial_data,
        MASK_CLASSIFIER_PREFETCH_TIMEOUT,
    )
    .await;
}

async fn extend_masking_initial_window_with_timeout<R>(
    reader: &mut R,
    initial_data: &mut Vec<u8>,
    prefetch_timeout: Duration,
) where
    R: AsyncRead + Unpin,
{
    if !should_prefetch_mask_classifier_window(initial_data) {
        return;
    }

    let need = MASK_CLASSIFIER_PREFETCH_WINDOW.saturating_sub(initial_data.len());
    if need == 0 {
        return;
    }

    let mut extra = [0u8; MASK_CLASSIFIER_PREFETCH_WINDOW];
    if let Ok(Ok(n)) = timeout(prefetch_timeout, reader.read(&mut extra[..need])).await
        && n > 0
    {
        initial_data.extend_from_slice(&extra[..n]);
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
        let mut reader = reader;
        let mut initial_data = initial_data;
        extend_masking_initial_window_with_timeout(
            &mut reader,
            &mut initial_data,
            mask_classifier_prefetch_timeout(&config),
        )
        .await;

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

fn classify_expected_64_got_0(kind: std::io::ErrorKind) -> Option<&'static str> {
    match kind {
        std::io::ErrorKind::UnexpectedEof => Some("expected_64_got_0_unexpected_eof"),
        std::io::ErrorKind::ConnectionReset => Some("expected_64_got_0_connection_reset"),
        std::io::ErrorKind::ConnectionAborted => Some("expected_64_got_0_connection_aborted"),
        std::io::ErrorKind::BrokenPipe => Some("expected_64_got_0_broken_pipe"),
        std::io::ErrorKind::NotConnected => Some("expected_64_got_0_not_connected"),
        _ => None,
    }
}

fn classify_handshake_failure_class(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::Io(err) => classify_expected_64_got_0(err.kind()).unwrap_or("other"),
        ProxyError::Stream(StreamError::UnexpectedEof) => "expected_64_got_0_unexpected_eof",
        ProxyError::Stream(StreamError::Io(err)) => {
            classify_expected_64_got_0(err.kind()).unwrap_or("other")
        }
        _ => "other",
    }
}

fn record_handshake_failure_class(
    beobachten: &BeobachtenStore,
    config: &ProxyConfig,
    peer_ip: IpAddr,
    error: &ProxyError,
) {
    // Keep beobachten buckets stable while detailed per-kind classification
    // is tracked in API counters.
    let class = match classify_handshake_failure_class(error) {
        value if value.starts_with("expected_64_got_0_") => "expected_64_got_0",
        _ => "other",
    };
    record_beobachten_class(beobachten, config, peer_ip, class);
}

#[inline]
fn increment_bad_on_unknown_tls_sni(stats: &Stats, error: &ProxyError) {
    if matches!(error, ProxyError::UnknownTlsSni) {
        stats.increment_connects_bad_with_class("unknown_tls_sni");
    }
}

fn is_trusted_proxy_source(peer_ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    if trusted.is_empty() {
        static EMPTY_PROXY_TRUST_WARNED: OnceLock<AtomicBool> = OnceLock::new();
        let warned = EMPTY_PROXY_TRUST_WARNED.get_or_init(|| AtomicBool::new(false));
        if !warned.swap(true, Ordering::Relaxed) {
            warn!(
                "PROXY protocol enabled but server.proxy_protocol_trusted_cidrs is empty; rejecting all PROXY headers"
            );
        }
        return false;
    }
    trusted.iter().any(|cidr| cidr.contains(peer_ip))
}

fn synthetic_local_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
}

#[cfg(test)]
pub async fn handle_client_stream<S>(
    stream: S,
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
    handle_client_stream_with_shared(
        stream,
        peer,
        config,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        me_pool,
        route_runtime,
        tls_cache,
        ip_tracker,
        beobachten,
        ProxySharedState::new(),
        proxy_protocol_enabled,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client_stream_with_shared<S>(
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
    shared: Arc<ProxySharedState>,
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
                    stats.increment_connects_bad_with_class("proxy_protocol_untrusted");
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
                stats.increment_connects_bad_with_class("proxy_protocol_invalid_header");
                warn!(peer = %peer, error = %e, "Invalid PROXY protocol header");
                record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                return Err(e);
            }
            Err(_) => {
                stats.increment_connects_bad_with_class("proxy_protocol_header_timeout");
                warn!(peer = %peer, timeout_ms = proxy_header_timeout.as_millis(), "PROXY protocol header timeout");
                record_beobachten_class(&beobachten, &config, peer.ip(), "other");
                return Err(ProxyError::InvalidProxyProtocol);
            }
        }
    }

    debug!(peer = %real_peer, "New connection (generic stream)");

    let first_byte_idle_secs = effective_client_first_byte_idle_secs(&config, shared.as_ref());
    let first_byte = if first_byte_idle_secs == 0 {
        None
    } else {
        let idle_timeout = Duration::from_secs(first_byte_idle_secs);
        let mut first_byte = [0u8; 1];
        match timeout(idle_timeout, stream.read(&mut first_byte)).await {
            Ok(Ok(0)) => {
                debug!(peer = %real_peer, "Connection closed before first client byte");
                return Ok(());
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
                    peer = %real_peer,
                    error = %e,
                    "Connection closed before first client byte"
                );
                return Ok(());
            }
            Ok(Err(e)) => {
                debug!(
                    peer = %real_peer,
                    error = %e,
                    "Failed while waiting for first client byte"
                );
                return Err(ProxyError::Io(e));
            }
            Err(_) => {
                debug!(
                    peer = %real_peer,
                    idle_secs = first_byte_idle_secs,
                    "Closing idle pooled connection before first client byte"
                );
                return Ok(());
            }
        }
    };

    let handshake_timeout = handshake_timeout_with_mask_grace(&config);
    let stats_for_timeout = stats.clone();
    let config_for_timeout = config.clone();
    let beobachten_for_timeout = beobachten.clone();
    let peer_for_timeout = real_peer.ip();

    // Phase 2: active handshake (with timeout after the first client byte)
    let outcome = match timeout(handshake_timeout, async {
        let mut first_bytes = [0u8; 5];
        if let Some(first_byte) = first_byte {
            first_bytes[0] = first_byte;
            stream.read_exact(&mut first_bytes[1..]).await?;
        } else {
            stream.read_exact(&mut first_bytes).await?;
        }

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
                stats.increment_connects_bad_with_class("tls_clienthello_len_out_of_bounds");
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
                    stats.increment_connects_bad_with_class("tls_clienthello_read_error");
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
                stats.increment_connects_bad_with_class("tls_clienthello_truncated");
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

            let (mut tls_reader, tls_writer, tls_user) = match handle_tls_handshake_with_shared(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, &rng, tls_cache.clone(),
                shared.as_ref(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad_with_class("tls_handshake_bad_client");
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
                HandshakeResult::Error(e) => {
                    increment_bad_on_unknown_tls_sni(stats.as_ref(), &e);
                    return Err(e);
                }
            };

            debug!(peer = %peer, "Reading MTProto handshake through TLS");
            let mtproto_data = tls_reader.read_exact(HANDSHAKE_LEN).await?;
            let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..].try_into()
                .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake_with_shared(
                &mtproto_handshake, tls_reader, tls_writer, real_peer,
                &config, &replay_checker, true, Some(tls_user.as_str()),
                shared.as_ref(),
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
                    stats.increment_connects_bad_with_class("tls_mtproto_bad_client");
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
                RunningClientHandler::handle_authenticated_static_with_shared(
                    crypto_reader, crypto_writer, success,
                    upstream_manager, stats, config, buffer_pool, rng, me_pool,
                    route_runtime.clone(),
                    local_addr, real_peer, ip_tracker.clone(),
                    shared.clone(),
                ),
            )))
        } else {
            if !config.general.modes.classic && !config.general.modes.secure {
                debug!(peer = %real_peer, "Non-TLS modes disabled");
                stats.increment_connects_bad_with_class("direct_modes_disabled");
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

            let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake_with_shared(
                &handshake, read_half, write_half, real_peer,
                &config, &replay_checker, false, None,
                shared.as_ref(),
            ).await {
                HandshakeResult::Success(result) => result,
                HandshakeResult::BadClient { reader, writer } => {
                    stats.increment_connects_bad_with_class("direct_mtproto_bad_client");
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
                RunningClientHandler::handle_authenticated_static_with_shared(
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
                    shared.clone(),
                )
            )))
        }
    }).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(e)) => {
            debug!(peer = %peer, error = %e, "Handshake failed");
            stats_for_timeout.increment_handshake_failure_class(classify_handshake_failure_class(&e));
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
            stats_for_timeout.increment_handshake_failure_class("timeout");
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
    shared: Arc<ProxySharedState>,
    proxy_protocol_enabled: bool,
    #[cfg(unix)]
    raw_fd: std::os::unix::io::RawFd,
    rst_on_close: crate::config::RstOnCloseMode,
}

impl ClientHandler {
    #[cfg(test)]
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
        #[cfg(unix)]
        let raw_fd = {
            use std::os::unix::io::AsRawFd;
            stream.as_raw_fd()
        };
        Self::new_with_shared(
            stream,
            peer,
            config,
            stats,
            upstream_manager,
            replay_checker,
            buffer_pool,
            rng,
            me_pool,
            route_runtime,
            tls_cache,
            ip_tracker,
            beobachten,
            ProxySharedState::new(),
            proxy_protocol_enabled,
            real_peer_report,
            #[cfg(unix)]
            raw_fd,
            crate::config::RstOnCloseMode::Off,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_shared(
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
        shared: Arc<ProxySharedState>,
        proxy_protocol_enabled: bool,
        real_peer_report: Arc<std::sync::Mutex<Option<SocketAddr>>>,
        #[cfg(unix)] raw_fd: std::os::unix::io::RawFd,
        rst_on_close: crate::config::RstOnCloseMode,
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
            shared,
            proxy_protocol_enabled,
            #[cfg(unix)]
            raw_fd,
            rst_on_close,
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

    async fn do_handshake(mut self) -> Result<Option<HandshakeOutcome>> {
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
                        self.stats
                            .increment_connects_bad_with_class("proxy_protocol_untrusted");
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
                self.beobachten.clone(),
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
                    self.beobachten.clone(),
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
                self.beobachten.clone(),
            ));
        }

        let config = self.config.clone();
        let replay_checker = self.replay_checker.clone();
        let stats = self.stats.clone();
        let buffer_pool = self.buffer_pool.clone();

        let (read_half, write_half) = self.stream.into_split();

        let (mut tls_reader, tls_writer, tls_user) = match handle_tls_handshake_with_shared(
            &handshake,
            read_half,
            write_half,
            peer,
            &config,
            &replay_checker,
            &self.rng,
            self.tls_cache.clone(),
            self.shared.as_ref(),
        )
        .await
        {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient { reader, writer } => {
                stats.increment_connects_bad_with_class("tls_handshake_bad_client");
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
            HandshakeResult::Error(e) => {
                increment_bad_on_unknown_tls_sni(stats.as_ref(), &e);
                return Err(e);
            }
        };

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
                    self.beobachten.clone(),
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
                self.route_runtime.clone(),
                local_addr,
                peer,
                self.ip_tracker,
                self.shared,
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
                    self.beobachten.clone(),
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
                self.route_runtime.clone(),
                local_addr,
                peer,
                self.ip_tracker,
                self.shared,
            ),
        )))
    }

    /// Main dispatch after successful handshake.
    /// Two modes:
    ///   - Direct: TCP relay to TG DC (existing behavior)  
    ///   - Middle Proxy: RPC multiplex through ME pool (new — supports CDN DCs)
    #[cfg(test)]
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
        Self::handle_authenticated_static_with_shared(
            client_reader,
            client_writer,
            success,
            upstream_manager,
            stats,
            config,
            buffer_pool,
            rng,
            me_pool,
            route_runtime,
            local_addr,
            peer_addr,
            ip_tracker,
            ProxySharedState::new(),
        )
        .await
    }

    async fn handle_authenticated_static_with_shared<R, W>(
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
        shared: Arc<ProxySharedState>,
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
                    shared.clone(),
                )
                .await
            } else {
                warn!("use_middle_proxy=true but MePool not initialized, falling back to direct");
                handle_via_direct_with_shared(
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
                    local_addr,
                    shared.clone(),
                )
                .await
            }
        } else {
            // Direct mode (original behavior)
            handle_via_direct_with_shared(
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
                local_addr,
                shared.clone(),
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
            && stats.get_user_quota_used(user) >= *quota
        {
            return Err(ProxyError::DataQuotaExceeded {
                user: user.to_string(),
            });
        }

        let limit = config
            .access
            .user_max_tcp_conns
            .get(user)
            .copied()
            .filter(|limit| *limit > 0)
            .or((config.access.user_max_tcp_conns_global_each > 0)
                .then_some(config.access.user_max_tcp_conns_global_each))
            .map(|v| v as u64);
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
            && stats.get_user_quota_used(user) >= *quota
        {
            return Err(ProxyError::DataQuotaExceeded {
                user: user.to_string(),
            });
        }

        let limit = config
            .access
            .user_max_tcp_conns
            .get(user)
            .copied()
            .filter(|limit| *limit > 0)
            .or((config.access.user_max_tcp_conns_global_each > 0)
                .then_some(config.access.user_max_tcp_conns_global_each))
            .map(|v| v as u64);
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
#[path = "tests/client_masking_fragmented_classifier_security_tests.rs"]
mod masking_fragmented_classifier_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_replay_timing_security_tests.rs"]
mod masking_replay_timing_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_http2_fragmented_preface_security_tests.rs"]
mod masking_http2_fragmented_preface_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_invariant_security_tests.rs"]
mod masking_prefetch_invariant_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_timing_matrix_security_tests.rs"]
mod masking_prefetch_timing_matrix_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_config_runtime_security_tests.rs"]
mod masking_prefetch_config_runtime_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_config_pipeline_integration_security_tests.rs"]
mod masking_prefetch_config_pipeline_integration_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_strict_boundary_security_tests.rs"]
mod masking_prefetch_strict_boundary_security_tests;

#[cfg(test)]
#[path = "tests/client_beobachten_ttl_bounds_security_tests.rs"]
mod beobachten_ttl_bounds_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_record_wrap_hardening_security_tests.rs"]
mod tls_record_wrap_hardening_security_tests;

#[cfg(test)]
#[path = "tests/client_clever_advanced_tests.rs"]
mod client_clever_advanced_tests;

#[cfg(test)]
#[path = "tests/client_more_advanced_tests.rs"]
mod client_more_advanced_tests;

#[cfg(test)]
#[path = "tests/client_deep_invariants_tests.rs"]
mod client_deep_invariants_tests;
