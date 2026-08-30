use super::*;

/// Handles a bad client with shared pre-auth fallback admission state.
pub(crate) async fn handle_bad_client_with_shared<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    local_addr: SocketAddr,
    config: &ProxyConfig,
    beobachten: &BeobachtenStore,
    shared: &ProxySharedState,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_bad_client_with_shared_resolver(
        reader,
        writer,
        initial_data,
        peer,
        local_addr,
        config,
        beobachten,
        shared,
        None,
    )
    .await;
}

pub(in crate::proxy) async fn handle_bad_client_with_shared_resolver<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    local_addr: SocketAddr,
    config: &ProxyConfig,
    beobachten: &BeobachtenStore,
    shared: &ProxySharedState,
    upstream_manager: Option<&crate::transport::UpstreamManager>,
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

    let Some(_masking_permit) = shared.try_acquire_masking_fallback_permit() else {
        let outcome_started = Instant::now();
        debug!(
            client_type = client_type,
            "Masking fallback concurrency limit reached"
        );
        consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
        wait_mask_outcome_budget(outcome_started, config).await;
        return;
    };

    let client_sni = tls::extract_sni_from_client_hello(initial_data);
    let exclusive_tcp_target = client_sni
        .as_deref()
        .and_then(|sni| exclusive_mask_target_for_sni(config, sni));

    // Connect via Unix socket or TCP
    #[cfg(unix)]
    if exclusive_tcp_target.is_none()
        && let Some(ref sock_path) = config.censorship.mask_unix_sock
    {
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
                consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
                wait_mask_outcome_budget(outcome_started, config).await;
            }
            Err(_) => {
                debug!("Timeout connecting to mask unix socket");
                consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
                wait_mask_outcome_budget(outcome_started, config).await;
            }
        }
        return;
    }

    let mask_target = exclusive_tcp_target.unwrap_or_else(|| {
        default_mask_tcp_target_for_initial_data(config, initial_data, client_sni.as_deref())
    });
    let mask_host = mask_target.host;
    let mask_port = mask_target.port;

    let resolved_mask_addrs =
        match resolve_mask_target_addrs(mask_host, mask_port, upstream_manager).await {
            Ok(addrs) => addrs,
            Err(e) => {
                let outcome_started = Instant::now();
                debug!(
                    client_type = client_type,
                    host = %mask_host,
                    port = mask_port,
                    error = %e,
                    "Failed to resolve mask target"
                );
                consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
                wait_mask_outcome_budget(outcome_started, config).await;
                return;
            }
        };

    // Fail closed when fallback points at our own listener endpoint.
    // Self-referential masking can create recursive proxy loops under
    // misconfiguration and leak distinguishable load spikes to adversaries.
    if is_mask_target_local_listener_async(mask_host, mask_port, local_addr, &resolved_mask_addrs)
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
        consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
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

    let connect_started = Instant::now();
    let connect_result = timeout(
        MASK_TIMEOUT,
        TcpStream::connect(resolved_mask_addrs.as_slice()),
    )
    .await;
    match connect_result {
        Ok(Ok(stream)) => {
            configure_mask_backend_socket(&stream);
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
            consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
            wait_mask_outcome_budget(outcome_started, config).await;
        }
        Err(_) => {
            debug!("Timeout connecting to mask host");
            consume_mask_failure_path(reader, config, relay_timeout, idle_timeout).await;
            wait_mask_outcome_budget(outcome_started, config).await;
        }
    }
}
