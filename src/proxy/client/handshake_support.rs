use super::*;

pub(super) fn beobachten_ttl(config: &ProxyConfig) -> Duration {
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

pub(super) fn wrap_tls_application_record(payload: &[u8]) -> Vec<u8> {
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

pub(super) fn tls_clienthello_len_in_bounds(tls_len: usize) -> bool {
    (MIN_TLS_CLIENT_HELLO_SIZE..=MAX_TLS_PLAINTEXT_SIZE).contains(&tls_len)
}

pub(super) async fn read_with_progress<R: AsyncRead + Unpin>(
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

pub(super) async fn maybe_apply_mask_reject_delay(config: &ProxyConfig) {
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

pub(super) fn handshake_timeout_with_mask_grace(config: &ProxyConfig) -> Duration {
    let base = Duration::from_secs(config.timeouts.client_handshake);
    if config.censorship.mask {
        base.saturating_add(Duration::from_millis(750))
    } else {
        base
    }
}

pub(super) fn effective_client_first_byte_idle_secs(
    config: &ProxyConfig,
    shared: &ProxySharedState,
) -> u64 {
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
pub(super) const MASK_CLASSIFIER_PREFETCH_TIMEOUT: Duration = Duration::from_millis(5);

pub(super) fn mask_classifier_prefetch_timeout(config: &ProxyConfig) -> Duration {
    Duration::from_millis(config.censorship.mask_classifier_prefetch_timeout_ms)
}

pub(super) fn should_prefetch_mask_classifier_window(initial_data: &[u8]) -> bool {
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
pub(super) async fn extend_masking_initial_window<R>(reader: &mut R, initial_data: &mut Vec<u8>)
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

pub(super) async fn extend_masking_initial_window_with_timeout<R>(
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

pub(super) fn masking_outcome<R, W>(
    reader: R,
    writer: W,
    initial_data: Vec<u8>,
    peer: SocketAddr,
    local_addr: SocketAddr,
    config: Arc<ProxyConfig>,
    upstream_manager: Arc<UpstreamManager>,
    beobachten: Arc<BeobachtenStore>,
    shared: Arc<ProxySharedState>,
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

        crate::proxy::masking::handle_bad_client_with_shared_resolver(
            reader,
            writer,
            &initial_data,
            peer,
            local_addr,
            &config,
            &beobachten,
            shared.as_ref(),
            Some(upstream_manager.as_ref()),
        )
        .await;
        Ok(())
    }))
}

pub(super) fn record_beobachten_class(
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

pub(super) fn tls_fingerprint_collection_enabled(config: &ProxyConfig) -> bool {
    config.general.beobachten || config.server.api.runtime_edge_enabled
}

pub(super) fn observe_tls_client_fingerprint(
    stats: &Stats,
    config: &ProxyConfig,
    peer_ip: IpAddr,
    handshake: &[u8],
) -> Option<TlsClientFingerprint> {
    if !tls_fingerprint_collection_enabled(config) {
        return None;
    }

    match tls_fingerprint::fingerprint_client_hello(handshake) {
        Some(fingerprint) => {
            stats.record_tls_fingerprint_observed(&fingerprint, peer_ip, beobachten_ttl(config));
            Some(fingerprint)
        }
        None => {
            stats.increment_tls_fingerprint_parse_error();
            None
        }
    }
}

pub(super) fn record_tls_fingerprint_auth_success(
    stats: &Stats,
    config: &ProxyConfig,
    peer_ip: IpAddr,
    fingerprint: Option<&TlsClientFingerprint>,
    user: &str,
) {
    if let Some(fingerprint) = fingerprint {
        stats.record_tls_fingerprint_auth_success(
            fingerprint,
            peer_ip,
            user,
            beobachten_ttl(config),
        );
    }
}

pub(super) fn record_tls_fingerprint_bad_or_probe(
    stats: &Stats,
    config: &ProxyConfig,
    peer_ip: IpAddr,
    fingerprint: Option<&TlsClientFingerprint>,
) {
    if let Some(fingerprint) = fingerprint {
        stats.record_tls_fingerprint_bad_or_probe(fingerprint, peer_ip, beobachten_ttl(config));
    }
}

pub(super) fn classify_expected_64_got_0(kind: std::io::ErrorKind) -> Option<&'static str> {
    match kind {
        std::io::ErrorKind::UnexpectedEof => Some("expected_64_got_0_unexpected_eof"),
        std::io::ErrorKind::ConnectionReset => Some("expected_64_got_0_connection_reset"),
        std::io::ErrorKind::ConnectionAborted => Some("expected_64_got_0_connection_aborted"),
        std::io::ErrorKind::BrokenPipe => Some("expected_64_got_0_broken_pipe"),
        std::io::ErrorKind::NotConnected => Some("expected_64_got_0_not_connected"),
        _ => None,
    }
}

pub(super) fn classify_handshake_failure_class(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::Io(err) => classify_expected_64_got_0(err.kind()).unwrap_or("other"),
        ProxyError::Stream(StreamError::UnexpectedEof) => "expected_64_got_0_unexpected_eof",
        ProxyError::Stream(StreamError::Io(err)) => {
            classify_expected_64_got_0(err.kind()).unwrap_or("other")
        }
        _ => "other",
    }
}

pub(super) fn record_handshake_failure_class(
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
pub(super) fn increment_bad_on_unknown_tls_sni(stats: &Stats, error: &ProxyError) {
    if matches!(error, ProxyError::UnknownTlsSni) {
        stats.increment_connects_bad_with_class("unknown_tls_sni");
    }
}

pub(super) fn is_trusted_proxy_source(peer_ip: IpAddr, trusted: &[IpNetwork]) -> bool {
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

pub(super) fn synthetic_local_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
}
