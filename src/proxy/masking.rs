//! Masking - forward unrecognized traffic to mask host

use crate::config::ProxyConfig;
use crate::network::dns_overrides::resolve_socket_addr;
use crate::stats::beobachten::BeobachtenStore;
use crate::transport::proxy_protocol::{ProxyProtocolV1Builder, ProxyProtocolV2Builder};
use rand::{Rng, RngExt};
use std::net::SocketAddr;
use std::str;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout};
use tracing::debug;

#[cfg(not(test))]
const MASK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const MASK_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum duration for the entire masking relay.
/// Limits resource consumption from slow-loris attacks and port scanners.
#[cfg(not(test))]
const MASK_RELAY_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const MASK_RELAY_TIMEOUT: Duration = Duration::from_millis(200);
#[cfg(not(test))]
const MASK_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const MASK_RELAY_IDLE_TIMEOUT: Duration = Duration::from_millis(100);
const MASK_BUFFER_SIZE: usize = 8192;

struct CopyOutcome {
    total: usize,
    ended_by_eof: bool,
}

async fn copy_with_idle_timeout<R, W>(reader: &mut R, writer: &mut W) -> CopyOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; MASK_BUFFER_SIZE];
    let mut total = 0usize;
    let mut ended_by_eof = false;
    loop {
        let read_res = timeout(MASK_RELAY_IDLE_TIMEOUT, reader.read(&mut buf)).await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };
        if n == 0 {
            ended_by_eof = true;
            break;
        }
        total = total.saturating_add(n);

        let write_res = timeout(MASK_RELAY_IDLE_TIMEOUT, writer.write_all(&buf[..n])).await;
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

    while remaining > 0 {
        let now = Instant::now();
        if now >= deadline {
            return;
        }

        let write_len = remaining.min(pad_chunk.len());
        {
            let mut rng = rand::rng();
            rng.fill_bytes(&mut pad_chunk[..write_len]);
        }
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

async fn consume_client_data_with_timeout<R>(reader: R)
where
    R: AsyncRead + Unpin,
{
    if timeout(MASK_RELAY_TIMEOUT, consume_client_data(reader))
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

fn mask_outcome_target_budget(config: &ProxyConfig) -> Duration {
    if config.censorship.mask_timing_normalization_enabled {
        let floor = config.censorship.mask_timing_normalization_floor_ms;
        let ceiling = config.censorship.mask_timing_normalization_ceiling_ms;
        if ceiling > floor {
            let mut rng = rand::rng();
            return Duration::from_millis(rng.random_range(floor..=ceiling));
        }
        return Duration::from_millis(floor);
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
    if data.len() > 4
        && (data.starts_with(b"GET ")
            || data.starts_with(b"POST")
            || data.starts_with(b"HEAD")
            || data.starts_with(b"PUT ")
            || data.starts_with(b"DELETE")
            || data.starts_with(b"OPTIONS"))
    {
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
        let ttl = Duration::from_secs(config.general.beobachten_minutes.saturating_mul(60));
        beobachten.record(client_type, peer.ip(), ttl);
    }

    if !config.censorship.mask {
        // Masking disabled, just consume data
        consume_client_data_with_timeout(reader).await;
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
                    MASK_RELAY_TIMEOUT,
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
                consume_client_data_with_timeout(reader).await;
                wait_mask_outcome_budget(outcome_started, config).await;
            }
            Err(_) => {
                debug!("Timeout connecting to mask unix socket");
                consume_client_data_with_timeout(reader).await;
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

    debug!(
        client_type = client_type,
        host = %mask_host,
        port = mask_port,
        data_len = initial_data.len(),
        "Forwarding bad client to mask host"
    );

    // Apply runtime DNS override for mask target when configured.
    let mask_addr = resolve_socket_addr(mask_host, mask_port)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| format!("{}:{}", mask_host, mask_port));
    let outcome_started = Instant::now();
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
                MASK_RELAY_TIMEOUT,
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
            consume_client_data_with_timeout(reader).await;
            wait_mask_outcome_budget(outcome_started, config).await;
        }
        Err(_) => {
            debug!("Timeout connecting to mask host");
            consume_client_data_with_timeout(reader).await;
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
        async { copy_with_idle_timeout(&mut reader, &mut mask_write).await },
        async { copy_with_idle_timeout(&mut mask_read, &mut writer).await }
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

/// Just consume all data from client without responding
async fn consume_client_data<R: AsyncRead + Unpin>(mut reader: R) {
    let mut buf = vec![0u8; MASK_BUFFER_SIZE];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
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
