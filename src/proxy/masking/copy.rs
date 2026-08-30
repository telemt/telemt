use super::*;

pub(super) fn mask_copy_read_len(total: usize, byte_cap: usize) -> usize {
    // Keep short scanner probes on the small baseline buffer and grow only
    // after the session has proven to be sustained masking relay traffic.
    let active_buffer_size = if total >= MASK_BUFFER_GROW_AFTER_BYTES {
        MASK_BUFFER_MAX_SIZE
    } else {
        MASK_BUFFER_SIZE
    };

    if byte_cap == 0 {
        return active_buffer_size;
    }

    let remaining_budget = byte_cap.saturating_sub(total);
    if remaining_budget == 0 {
        return 0;
    }

    remaining_budget.min(active_buffer_size)
}

pub(super) async fn copy_with_idle_timeout<R, W>(
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
    let mut buf = vec![0u8; MASK_BUFFER_SIZE];
    let mut total = 0usize;
    let mut ended_by_eof = false;

    loop {
        let read_len = mask_copy_read_len(total, byte_cap);
        if read_len == 0 {
            break;
        }
        if buf.len() < read_len {
            buf.resize(read_len, 0);
        }
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

pub(super) fn is_http_probe(data: &[u8]) -> bool {
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

pub(super) fn next_mask_shape_bucket(total: usize, floor: usize, cap: usize) -> usize {
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

pub(super) async fn maybe_write_shape_padding<W>(
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

pub(super) async fn write_proxy_header_with_timeout<W>(mask_write: &mut W, header: &[u8]) -> bool
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

pub(super) async fn consume_client_data_with_timeout_and_cap<R>(
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

pub(super) fn mask_failure_drain_cap(config: &ProxyConfig) -> usize {
    let configured_cap = config.censorship.mask_relay_max_bytes;
    if configured_cap == 0 {
        return MASK_BUFFER_SIZE;
    }

    configured_cap.min(MASK_BUFFER_SIZE)
}

pub(super) async fn consume_mask_failure_path<R>(
    reader: R,
    config: &ProxyConfig,
    relay_timeout: Duration,
    idle_timeout: Duration,
) where
    R: AsyncRead + Unpin,
{
    consume_client_data_with_timeout_and_cap(
        reader,
        mask_failure_drain_cap(config),
        relay_timeout,
        idle_timeout,
    )
    .await;
}

pub(super) async fn wait_mask_connect_budget(started: Instant) {
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
