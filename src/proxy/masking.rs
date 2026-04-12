//! Masking - forward unrecognized traffic to mask host

use crate::config::ProxyConfig;
use crate::network::dns_overrides::resolve_socket_addr;
use crate::stats::beobachten::BeobachtenStore;
use crate::transport::proxy_protocol::{ProxyProtocolV1Builder, ProxyProtocolV2Builder};
#[cfg(unix)]
use nix::ifaddrs::getifaddrs;
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use std::net::{IpAddr, SocketAddr};
use std::str;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{Instant, timeout};
use tracing::debug;

#[cfg(not(test))]
const MASK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const MASK_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum duration for the entire masking relay under test (replaced by config at runtime).
#[cfg(test)]
const MASK_RELAY_TIMEOUT: Duration = Duration::from_millis(200);
/// Per-read idle timeout for masking relay and drain paths under test (replaced by config at runtime).
#[cfg(test)]
const MASK_RELAY_IDLE_TIMEOUT: Duration = Duration::from_millis(100);
const MASK_BUFFER_SIZE: usize = 8192;
#[cfg(unix)]
#[cfg(not(test))]
const LOCAL_INTERFACE_CACHE_TTL: Duration = Duration::from_secs(300);
#[cfg(all(unix, test))]
const LOCAL_INTERFACE_CACHE_TTL: Duration = Duration::from_secs(1);

struct CopyOutcome {
    total: usize,
    ended_by_eof: bool,
}

async fn copy_with_idle_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    byte_cap: usize,
    shutdown_on_eof: bool,
    idle_timeout: Duration,
) -> CopyOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = Box::new([0u8; MASK_BUFFER_SIZE]);
    let mut total = 0usize;
    let mut ended_by_eof = false;

    if byte_cap == 0 {
        return CopyOutcome {
            total,
            ended_by_eof,
        };
    }

    loop {
        let remaining_budget = byte_cap.saturating_sub(total);
        if remaining_budget == 0 {
            break;
        }

        let read_len = remaining_budget.min(MASK_BUFFER_SIZE);
        let read_res = timeout(idle_timeout, reader.read(&mut buf[..read_len])).await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };
        if n == 0 {
            ended_by_eof = true;
            if shutdown_on_eof {
                let _ = timeout(idle_timeout, writer.shutdown()).await;
            }
            break;
        }
        total = total.saturating_add(n);

        let write_res = timeout(idle_timeout, writer.write_all(&buf[..n])).await;
        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    CopyOutcome {
        total,
        ended_by_eof,
    }
}

fn is_http_probe(data: &[u8]) -> bool {
    // RFC 7540 section 3.5: HTTP/2 client preface starts with "PRI ".
    const HTTP_METHODS: [&[u8]; 10] = [
        b"GET ", b"POST", b"HEAD", b"PUT ", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE", b"PATCH",
        b"PRI ",
    ];

    if data.is_empty() {
        return false;
    }

    let window = &data[..data.len().min(16)];
    for method in HTTP_METHODS {
        if data.len() >= method.len() && window.starts_with(method) {
            return true;
        }

        if (2..=3).contains(&window.len()) && method.starts_with(window) {
            return true;
        }
    }

    false
}

fn next_mask_shape_bucket(total: usize, floor: usize, cap: usize) -> usize {
    if total == 0 || floor == 0 || cap < floor {
        return total;
    }

    if total >= cap {
        return total;
    }

    let mut bucket = floor;
    while bucket < total {
        match bucket.checked_mul(2) {
            Some(next) => bucket = next,
            None => return total,
        }
        if bucket > cap {
            return cap;
        }
    }
    bucket
}

async fn maybe_write_shape_padding<W>(
    mask_write: &mut W,
    total_sent: usize,
    enabled: bool,
    floor: usize,
    cap: usize,
    above_cap_blur: bool,
    above_cap_blur_max_bytes: usize,
    aggressive_mode: bool,
) where
    W: AsyncWrite + Unpin,
{
    if !enabled {
        return;
    }

    let target_total = if total_sent >= cap && above_cap_blur && above_cap_blur_max_bytes > 0 {
        let mut rng = rand::rng();
        let extra = if aggressive_mode {
            rng.random_range(1..=above_cap_blur_max_bytes)
        } else {
            rng.random_range(0..=above_cap_blur_max_bytes)
        };
        total_sent.saturating_add(extra)
    } else {
        next_mask_shape_bucket(total_sent, floor, cap)
    };

    if target_total <= total_sent {
        return;
    }

    let mut remaining = target_total - total_sent;
    let mut pad_chunk = [0u8; 1024];
    let deadline = Instant::now() + MASK_TIMEOUT;
    // Use a Send RNG so relay futures remain spawn-safe under Tokio.
    let mut rng = {
        let mut seed_source = rand::rng();
        StdRng::from_rng(&mut seed_source)
    };

    while remaining > 0 {
        let now = Instant::now();
        if now >= deadline {
            return;
        }

        let write_len = remaining.min(pad_chunk.len());
        rng.fill_bytes(&mut pad_chunk[..write_len]);
        let write_budget = deadline.saturating_duration_since(now);
        match timeout(write_budget, mask_write.write_all(&pad_chunk[..write_len])).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return,
        }
        remaining -= write_len;
    }

    let now = Instant::now();
    if now >= deadline {
        return;
    }
    let flush_budget = deadline.saturating_duration_since(now);
    let _ = timeout(flush_budget, mask_write.flush()).await;
}

async fn write_proxy_header_with_timeout<W>(mask_write: &mut W, header: &[u8]) -> bool
where
    W: AsyncWrite + Unpin,
{
    match timeout(MASK_TIMEOUT, mask_write.write_all(header)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => false,
        Err(_) => {
            debug!("Timeout writing proxy protocol header to mask backend");
            false
        }
    }
}

async fn consume_client_data_with_timeout_and_cap<R>(
    reader: R,
    byte_cap: usize,
    relay_timeout: Duration,
    idle_timeout: Duration,
) where
    R: AsyncRead + Unpin,
{
    if timeout(
        relay_timeout,
        consume_client_data(reader, byte_cap, idle_timeout),
    )
    .await
    .is_err()
    {
        debug!("Timed out while consuming client data on masking fallback path");
    }
}

async fn wait_mask_connect_budget(started: Instant) {
    let elapsed = started.elapsed();
    if elapsed < MASK_TIMEOUT {
        tokio::time::sleep(MASK_TIMEOUT - elapsed).await;
    }
}

// Log-normal sample bounded to [floor, ceiling]. Median = sqrt(floor * ceiling).
// Implements Box-Muller transform for standard normal sampling — no external
// dependency on rand_distr (which is incompatible with rand 0.10).
// sigma is chosen so ~99% of raw samples land inside [floor, ceiling] before clamp.
// When floor > ceiling (misconfiguration), returns ceiling (the smaller value).
// When floor == ceiling, returns that value. When both are 0, returns 0.
pub(crate) fn sample_lognormal_percentile_bounded(
    floor: u64,
    ceiling: u64,
    rng: &mut impl Rng,
) -> u64 {
    if ceiling == 0 && floor == 0 {
        return 0;
    }
    if floor > ceiling {
        return ceiling;
    }
    if floor == ceiling {
        return floor;
    }
    let floor_f = floor.max(1) as f64;
    let ceiling_f = ceiling.max(1) as f64;
    let mu = (floor_f.ln() + ceiling_f.ln()) / 2.0;
    // 4.65 ≈ 2 * 2.326 (double-sided z-score for 99th percentile)
    let sigma = ((ceiling_f / floor_f).ln() / 4.65).max(0.01);
    // Box-Muller transform: two uniform samples → one standard normal sample
    let u1: f64 = rng.random_range(f64::MIN_POSITIVE..1.0);
    let u2: f64 = rng.random_range(0.0_f64..std::f64::consts::TAU);
    let normal_sample = (-2.0_f64 * u1.ln()).sqrt() * u2.cos();
    let raw = (mu + sigma * normal_sample).exp();
    if raw.is_finite() {
        (raw as u64).clamp(floor, ceiling)
    } else {
        ((floor_f * ceiling_f).sqrt()) as u64
    }
}

fn mask_outcome_target_budget(config: &ProxyConfig) -> Duration {
    if config.censorship.mask_timing_normalization_enabled {
        let floor = config.censorship.mask_timing_normalization_floor_ms;
        let ceiling = config.censorship.mask_timing_normalization_ceiling_ms;
        if floor == 0 {
            if ceiling == 0 {
                return Duration::from_millis(0);
            }
            // floor=0 stays uniform: log-normal cannot model distribution anchored at zero
            let mut rng = rand::rng();
            return Duration::from_millis(rng.random_range(0..=ceiling));
        }
        if ceiling > floor {
            let mut rng = rand::rng();
            return Duration::from_millis(sample_lognormal_percentile_bounded(
                floor, ceiling, &mut rng,
            ));
        }
        // ceiling <= floor: use the larger value (fail-closed: preserve longer delay)
        return Duration::from_millis(floor.max(ceiling));
    }

    MASK_TIMEOUT
}

async fn wait_mask_connect_budget_if_needed(started: Instant, config: &ProxyConfig) {
    if config.censorship.mask_timing_normalization_enabled {
        return;
    }

    wait_mask_connect_budget(started).await;
}

async fn wait_mask_outcome_budget(started: Instant, config: &ProxyConfig) {
    let target = mask_outcome_target_budget(config);
    let elapsed = started.elapsed();
    if elapsed < target {
        tokio::time::sleep(target - elapsed).await;
    }
}

/// Detect client type based on initial data
fn detect_client_type(data: &[u8]) -> &'static str {
    // Check for HTTP request
    if is_http_probe(data) {
        return "HTTP";
    }

    // Check for TLS ClientHello (0x16 = handshake, 0x03 0x01-0x03 = TLS version)
    if data.len() > 3 && data[0] == 0x16 && data[1] == 0x03 {
        return "TLS-scanner";
    }

    // Check for SSH
    if data.starts_with(b"SSH-") {
        return "SSH";
    }

    // Port scanner (very short data)
    if data.len() < 10 {
        return "port-scanner";
    }

    "unknown"
}

fn parse_mask_host_ip_literal(host: &str) -> Option<IpAddr> {
    if host.starts_with('[') && host.ends_with(']') {
        return host[1..host.len() - 1].parse::<IpAddr>().ok();
    }
    host.parse::<IpAddr>().ok()
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

#[cfg(unix)]
fn collect_local_interface_ips() -> Vec<IpAddr> {
    #[cfg(test)]
    LOCAL_INTERFACE_ENUMERATIONS.fetch_add(1, Ordering::Relaxed);

    let mut out = Vec::new();
    if let Ok(addrs) = getifaddrs() {
        for iface in addrs {
            if let Some(address) = iface.address {
                if let Some(v4) = address.as_sockaddr_in() {
                    out.push(canonical_ip(IpAddr::V4(v4.ip())));
                } else if let Some(v6) = address.as_sockaddr_in6() {
                    out.push(canonical_ip(IpAddr::V6(v6.ip())));
                }
            }
        }
    }
    out
}

fn choose_interface_snapshot(previous: &[IpAddr], refreshed: Vec<IpAddr>) -> Vec<IpAddr> {
    if refreshed.is_empty() && !previous.is_empty() {
        return previous.to_vec();
    }

    refreshed
}

#[cfg(unix)]
#[derive(Default)]
struct LocalInterfaceCache {
    ips: Vec<IpAddr>,
    refreshed_at: Option<StdInstant>,
}

#[cfg(unix)]
static LOCAL_INTERFACE_CACHE: OnceLock<Mutex<LocalInterfaceCache>> = OnceLock::new();

#[cfg(unix)]
static LOCAL_INTERFACE_REFRESH_LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();

#[cfg(all(unix, test))]
fn local_interface_ips() -> Vec<IpAddr> {
    let cache = LOCAL_INTERFACE_CACHE.get_or_init(|| Mutex::new(LocalInterfaceCache::default()));
    let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());

    let stale = guard
        .refreshed_at
        .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
    if stale {
        let refreshed = collect_local_interface_ips();
        guard.ips = choose_interface_snapshot(&guard.ips, refreshed);
        guard.refreshed_at = Some(StdInstant::now());
    }

    guard.ips.clone()
}

#[cfg(unix)]
async fn local_interface_ips_async() -> Vec<IpAddr> {
    let cache = LOCAL_INTERFACE_CACHE.get_or_init(|| Mutex::new(LocalInterfaceCache::default()));

    {
        let guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        let stale = guard
            .refreshed_at
            .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
        if !stale {
            return guard.ips.clone();
        }
    }

    let refresh_lock = LOCAL_INTERFACE_REFRESH_LOCK.get_or_init(|| AsyncMutex::new(()));
    let _refresh_guard = refresh_lock.lock().await;

    {
        let guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        let stale = guard
            .refreshed_at
            .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
        if !stale {
            return guard.ips.clone();
        }
    }

    let refreshed = tokio::task::spawn_blocking(collect_local_interface_ips)
        .await
        .unwrap_or_default();

    let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
    let stale = guard
        .refreshed_at
        .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
    if stale {
        guard.ips = choose_interface_snapshot(&guard.ips, refreshed);
        guard.refreshed_at = Some(StdInstant::now());
    }

    guard.ips.clone()
}

#[cfg(all(not(unix), test))]
fn local_interface_ips() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(not(unix))]
async fn local_interface_ips_async() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
static LOCAL_INTERFACE_ENUMERATIONS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
fn reset_local_interface_enumerations_for_tests() {
    LOCAL_INTERFACE_ENUMERATIONS.store(0, Ordering::Relaxed);

    #[cfg(unix)]
    if let Some(cache) = LOCAL_INTERFACE_CACHE.get() {
        let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        guard.ips.clear();
        guard.refreshed_at = None;
    }
}

#[cfg(test)]
fn local_interface_enumerations_for_tests() -> usize {
    LOCAL_INTERFACE_ENUMERATIONS.load(Ordering::Relaxed)
}

fn is_mask_target_local_listener_with_interfaces(
    mask_host: &str,
    mask_port: u16,
    local_addr: SocketAddr,
    resolved_override: Option<SocketAddr>,
    interface_ips: &[IpAddr],
) -> bool {
    if mask_port != local_addr.port() {
        return false;
    }

    let local_ip = canonical_ip(local_addr.ip());
    let literal_mask_ip = parse_mask_host_ip_literal(mask_host).map(canonical_ip);

    if let Some(addr) = resolved_override {
        let resolved_ip = canonical_ip(addr.ip());
        if resolved_ip == local_ip {
            return true;
        }

        if local_ip.is_unspecified()
            && (resolved_ip.is_loopback()
                || resolved_ip.is_unspecified()
                || interface_ips.contains(&resolved_ip))
        {
            return true;
        }
    }

    if let Some(mask_ip) = literal_mask_ip {
        if mask_ip == local_ip {
            return true;
        }

        if local_ip.is_unspecified()
            && (mask_ip.is_loopback()
                || mask_ip.is_unspecified()
                || interface_ips.contains(&mask_ip))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
fn is_mask_target_local_listener(
    mask_host: &str,
    mask_port: u16,
    local_addr: SocketAddr,
    resolved_override: Option<SocketAddr>,
) -> bool {
    if mask_port != local_addr.port() {
        return false;
    }

    let interfaces = local_interface_ips();
    is_mask_target_local_listener_with_interfaces(
        mask_host,
        mask_port,
        local_addr,
        resolved_override,
        &interfaces,
    )
}

async fn is_mask_target_local_listener_async(
    mask_host: &str,
    mask_port: u16,
    local_addr: SocketAddr,
    resolved_override: Option<SocketAddr>,
) -> bool {
    if mask_port != local_addr.port() {
        return false;
    }

    let interfaces = local_interface_ips_async().await;
    is_mask_target_local_listener_with_interfaces(
        mask_host,
        mask_port,
        local_addr,
        resolved_override,
        &interfaces,
    )
}

fn masking_beobachten_ttl(config: &ProxyConfig) -> Duration {
    let minutes = config.general.beobachten_minutes;
    let clamped = minutes.clamp(1, 24 * 60);
    Duration::from_secs(clamped.saturating_mul(60))
}

fn build_mask_proxy_header(
    version: u8,
    peer: SocketAddr,
    local_addr: SocketAddr,
) -> Option<Vec<u8>> {
    match version {
        0 => None,
        2 => Some(
            ProxyProtocolV2Builder::new()
                .with_addrs(peer, local_addr)
                .build(),
        ),
        _ => {
            let header = match (peer, local_addr) {
                (SocketAddr::V4(src), SocketAddr::V4(dst)) => ProxyProtocolV1Builder::new()
                    .tcp4(src.into(), dst.into())
                    .build(),
                (SocketAddr::V6(src), SocketAddr::V6(dst)) => ProxyProtocolV1Builder::new()
                    .tcp6(src.into(), dst.into())
                    .build(),
                _ => ProxyProtocolV1Builder::new().build(),
            };
            Some(header)
        }
    }
}

/// Handle a bad client by forwarding to mask host
pub async fn handle_bad_client<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    local_addr: SocketAddr,
    config: &ProxyConfig,
    beobachten: &BeobachtenStore,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let client_type = detect_client_type(initial_data);
    if config.general.beobachten {
        let ttl = masking_beobachten_ttl(config);
        beobachten.record(client_type, peer.ip(), ttl);
    }

    let relay_timeout = Duration::from_millis(config.censorship.mask_relay_timeout_ms);
    let idle_timeout = Duration::from_millis(config.censorship.mask_relay_idle_timeout_ms);

    if !config.censorship.mask {
        // Masking disabled, just consume data
        consume_client_data_with_timeout_and_cap(
            reader,
            config.censorship.mask_relay_max_bytes,
            relay_timeout,
            idle_timeout,
        )
        .await;
        return;
    }

    // Connect via Unix socket or TCP
    #[cfg(unix)]
    if let Some(ref sock_path) = config.censorship.mask_unix_sock {
        let outcome_started = Instant::now();
        let connect_started = Instant::now();
        debug!(
            client_type = client_type,
            sock = %sock_path,
            data_len = initial_data.len(),
            "Forwarding bad client to mask unix socket"
        );

        let connect_result = timeout(MASK_TIMEOUT, UnixStream::connect(sock_path)).await;
        match connect_result {
            Ok(Ok(stream)) => {
                let (mask_read, mut mask_write) = stream.into_split();
                let proxy_header = build_mask_proxy_header(
                    config.censorship.mask_proxy_protocol,
                    peer,
                    local_addr,
                );
                if let Some(header) = proxy_header
                    && !write_proxy_header_with_timeout(&mut mask_write, &header).await
                {
                    wait_mask_outcome_budget(outcome_started, config).await;
                    return;
                }
                if timeout(
                    relay_timeout,
                    relay_to_mask(
                        reader,
                        writer,
                        mask_read,
                        mask_write,
                        initial_data,
                        config.censorship.mask_shape_hardening,
                        config.censorship.mask_shape_bucket_floor_bytes,
                        config.censorship.mask_shape_bucket_cap_bytes,
                        config.censorship.mask_shape_above_cap_blur,
                        config.censorship.mask_shape_above_cap_blur_max_bytes,
                        config.censorship.mask_shape_hardening_aggressive_mode,
                        config.censorship.mask_relay_max_bytes,
                        idle_timeout,
                    ),
                )
                .await
                .is_err()
                {
                    debug!("Mask relay timed out (unix socket)");
                }
                wait_mask_outcome_budget(outcome_started, config).await;
            }
            Ok(Err(e)) => {
                wait_mask_connect_budget_if_needed(connect_started, config).await;
                debug!(error = %e, "Failed to connect to mask unix socket");
                consume_client_data_with_timeout_and_cap(
                    reader,
                    config.censorship.mask_relay_max_bytes,
                    relay_timeout,
                    idle_timeout,
                )
                .await;
                wait_mask_outcome_budget(outcome_started, config).await;
            }
            Err(_) => {
                debug!("Timeout connecting to mask unix socket");
                consume_client_data_with_timeout_and_cap(
                    reader,
                    config.censorship.mask_relay_max_bytes,
                    relay_timeout,
                    idle_timeout,
                )
                .await;
                wait_mask_outcome_budget(outcome_started, config).await;
            }
        }
        return;
    }

    let mask_host = config
        .censorship
        .mask_host
        .as_deref()
        .unwrap_or(&config.censorship.tls_domain);
    let mask_port = config.censorship.mask_port;

    // Fail closed when fallback points at our own listener endpoint.
    // Self-referential masking can create recursive proxy loops under
    // misconfiguration and leak distinguishable load spikes to adversaries.
    let resolved_mask_addr = resolve_socket_addr(mask_host, mask_port);
    if is_mask_target_local_listener_async(mask_host, mask_port, local_addr, resolved_mask_addr)
        .await
    {
        let outcome_started = Instant::now();
        debug!(
            client_type = client_type,
            host = %mask_host,
            port = mask_port,
            local = %local_addr,
            "Mask target resolves to local listener; refusing self-referential masking fallback"
        );
        consume_client_data_with_timeout_and_cap(
            reader,
            config.censorship.mask_relay_max_bytes,
            relay_timeout,
            idle_timeout,
        )
        .await;
        wait_mask_outcome_budget(outcome_started, config).await;
        return;
    }

    let outcome_started = Instant::now();

    debug!(
        client_type = client_type,
        host = %mask_host,
        port = mask_port,
        data_len = initial_data.len(),
        "Forwarding bad client to mask host"
    );

    // Apply runtime DNS override for mask target when configured.
    let mask_addr = resolved_mask_addr
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| format!("{}:{}", mask_host, mask_port));
    let connect_started = Instant::now();
    let connect_result = timeout(MASK_TIMEOUT, TcpStream::connect(&mask_addr)).await;
    match connect_result {
        Ok(Ok(stream)) => {
            let proxy_header =
                build_mask_proxy_header(config.censorship.mask_proxy_protocol, peer, local_addr);

            let (mask_read, mut mask_write) = stream.into_split();
            if let Some(header) = proxy_header
                && !write_proxy_header_with_timeout(&mut mask_write, &header).await
            {
                wait_mask_outcome_budget(outcome_started, config).await;
                return;
            }
            if timeout(
                relay_timeout,
                relay_to_mask(
                    reader,
                    writer,
                    mask_read,
                    mask_write,
                    initial_data,
                    config.censorship.mask_shape_hardening,
                    config.censorship.mask_shape_bucket_floor_bytes,
                    config.censorship.mask_shape_bucket_cap_bytes,
                    config.censorship.mask_shape_above_cap_blur,
                    config.censorship.mask_shape_above_cap_blur_max_bytes,
                    config.censorship.mask_shape_hardening_aggressive_mode,
                    config.censorship.mask_relay_max_bytes,
                    idle_timeout,
                ),
            )
            .await
            .is_err()
            {
                debug!("Mask relay timed out");
            }
            wait_mask_outcome_budget(outcome_started, config).await;
        }
        Ok(Err(e)) => {
            wait_mask_connect_budget_if_needed(connect_started, config).await;
            debug!(error = %e, "Failed to connect to mask host");
            consume_client_data_with_timeout_and_cap(
                reader,
                config.censorship.mask_relay_max_bytes,
                relay_timeout,
                idle_timeout,
            )
            .await;
            wait_mask_outcome_budget(outcome_started, config).await;
        }
        Err(_) => {
            debug!("Timeout connecting to mask host");
            consume_client_data_with_timeout_and_cap(
                reader,
                config.censorship.mask_relay_max_bytes,
                relay_timeout,
                idle_timeout,
            )
            .await;
            wait_mask_outcome_budget(outcome_started, config).await;
        }
    }
}

/// Relay traffic between client and mask backend
async fn relay_to_mask<R, W, MR, MW>(
    mut reader: R,
    mut writer: W,
    mut mask_read: MR,
    mut mask_write: MW,
    initial_data: &[u8],
    shape_hardening_enabled: bool,
    shape_bucket_floor_bytes: usize,
    shape_bucket_cap_bytes: usize,
    shape_above_cap_blur: bool,
    shape_above_cap_blur_max_bytes: usize,
    shape_hardening_aggressive_mode: bool,
    mask_relay_max_bytes: usize,
    idle_timeout: Duration,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    MR: AsyncRead + Unpin + Send + 'static,
    MW: AsyncWrite + Unpin + Send + 'static,
{
    // Send initial data to mask host
    if mask_write.write_all(initial_data).await.is_err() {
        return;
    }
    if mask_write.flush().await.is_err() {
        return;
    }

    let (upstream_copy, downstream_copy) = tokio::join!(
        async {
            copy_with_idle_timeout(
                &mut reader,
                &mut mask_write,
                mask_relay_max_bytes,
                !shape_hardening_enabled,
                idle_timeout,
            )
            .await
        },
        async {
            copy_with_idle_timeout(
                &mut mask_read,
                &mut writer,
                mask_relay_max_bytes,
                true,
                idle_timeout,
            )
            .await
        }
    );

    let total_sent = initial_data.len().saturating_add(upstream_copy.total);

    let should_shape = shape_hardening_enabled
        && !initial_data.is_empty()
        && (upstream_copy.ended_by_eof
            || (shape_hardening_aggressive_mode && downstream_copy.total == 0));

    maybe_write_shape_padding(
        &mut mask_write,
        total_sent,
        should_shape,
        shape_bucket_floor_bytes,
        shape_bucket_cap_bytes,
        shape_above_cap_blur,
        shape_above_cap_blur_max_bytes,
        shape_hardening_aggressive_mode,
    )
    .await;

    let _ = mask_write.shutdown().await;
    let _ = writer.shutdown().await;
}

/// Just consume all data from client without responding.
async fn consume_client_data<R: AsyncRead + Unpin>(
    mut reader: R,
    byte_cap: usize,
    idle_timeout: Duration,
) {
    if byte_cap == 0 {
        return;
    }

    // Keep drain path fail-closed under slow-loris stalls.
    let mut buf = Box::new([0u8; MASK_BUFFER_SIZE]);
    let mut total = 0usize;

    loop {
        let remaining_budget = byte_cap.saturating_sub(total);
        if remaining_budget == 0 {
            break;
        }

        let read_len = remaining_budget.min(MASK_BUFFER_SIZE);
        let n = match timeout(idle_timeout, reader.read(&mut buf[..read_len])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };

        if n == 0 {
            break;
        }

        total = total.saturating_add(n);
        if total >= byte_cap {
            break;
        }
    }
}

#[cfg(test)]
#[path = "tests/masking_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/masking_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_hardening_adversarial_tests.rs"]
mod masking_shape_hardening_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_above_cap_blur_security_tests.rs"]
mod masking_shape_above_cap_blur_security_tests;

#[cfg(test)]
#[path = "tests/masking_timing_normalization_security_tests.rs"]
mod masking_timing_normalization_security_tests;

#[cfg(test)]
#[path = "tests/masking_timing_budget_coupling_security_tests.rs"]
mod masking_timing_budget_coupling_security_tests;

#[cfg(test)]
#[path = "tests/masking_ab_envelope_blur_integration_security_tests.rs"]
mod masking_ab_envelope_blur_integration_security_tests;

#[cfg(test)]
#[path = "tests/masking_shape_guard_security_tests.rs"]
mod masking_shape_guard_security_tests;

#[cfg(test)]
#[path = "tests/masking_shape_guard_adversarial_tests.rs"]
mod masking_shape_guard_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_classifier_resistance_adversarial_tests.rs"]
mod masking_shape_classifier_resistance_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_bypass_blackhat_tests.rs"]
mod masking_shape_bypass_blackhat_tests;

#[cfg(test)]
#[path = "tests/masking_aggressive_mode_security_tests.rs"]
mod masking_aggressive_mode_security_tests;

#[cfg(test)]
#[path = "tests/masking_timing_sidechannel_redteam_expected_fail_tests.rs"]
mod masking_timing_sidechannel_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/masking_self_target_loop_security_tests.rs"]
mod masking_self_target_loop_security_tests;

#[cfg(test)]
#[path = "tests/masking_classification_completeness_security_tests.rs"]
mod masking_classification_completeness_security_tests;

#[cfg(test)]
#[path = "tests/masking_relay_guardrails_security_tests.rs"]
mod masking_relay_guardrails_security_tests;

#[cfg(test)]
#[path = "tests/masking_connect_failure_close_matrix_security_tests.rs"]
mod masking_connect_failure_close_matrix_security_tests;

#[cfg(test)]
#[path = "tests/masking_additional_hardening_security_tests.rs"]
mod masking_additional_hardening_security_tests;

#[cfg(test)]
#[path = "tests/masking_consume_idle_timeout_security_tests.rs"]
mod masking_consume_idle_timeout_security_tests;

#[cfg(test)]
#[path = "tests/masking_http2_probe_classification_security_tests.rs"]
mod masking_http2_probe_classification_security_tests;

#[cfg(test)]
#[path = "tests/masking_http_probe_boundary_security_tests.rs"]
mod masking_http_probe_boundary_security_tests;

#[cfg(test)]
#[path = "tests/masking_rng_hoist_perf_regression_tests.rs"]
mod masking_rng_hoist_perf_regression_tests;

#[cfg(test)]
#[path = "tests/masking_http2_preface_integration_security_tests.rs"]
mod masking_http2_preface_integration_security_tests;

#[cfg(test)]
#[path = "tests/masking_consume_stress_adversarial_tests.rs"]
mod masking_consume_stress_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_interface_cache_security_tests.rs"]
mod masking_interface_cache_security_tests;

#[cfg(test)]
#[path = "tests/masking_interface_cache_defense_in_depth_security_tests.rs"]
mod masking_interface_cache_defense_in_depth_security_tests;

#[cfg(test)]
#[path = "tests/masking_interface_cache_concurrency_security_tests.rs"]
mod masking_interface_cache_concurrency_security_tests;

#[cfg(test)]
#[path = "tests/masking_production_cap_regression_security_tests.rs"]
mod masking_production_cap_regression_security_tests;

#[cfg(test)]
#[path = "tests/masking_extended_attack_surface_security_tests.rs"]
mod masking_extended_attack_surface_security_tests;

#[cfg(test)]
#[path = "tests/masking_padding_timeout_adversarial_tests.rs"]
mod masking_padding_timeout_adversarial_tests;

#[cfg(all(test, feature = "redteam_offline_expected_fail"))]
#[path = "tests/masking_offline_target_redteam_expected_fail_tests.rs"]
mod masking_offline_target_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/masking_baseline_invariant_tests.rs"]
mod masking_baseline_invariant_tests;

#[cfg(test)]
#[path = "tests/masking_lognormal_timing_security_tests.rs"]
mod masking_lognormal_timing_security_tests;
