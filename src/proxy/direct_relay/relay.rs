use super::*;

#[allow(dead_code)]
/// Runs Direct relay with standalone cancellation and shared-state defaults.
pub(crate) async fn handle_via_direct<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    upstream_manager: Arc<UpstreamManager>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_via_direct_with_shared(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats,
        config.clone(),
        buffer_pool,
        rng,
        route_rx,
        route_snapshot,
        session_id,
        SocketAddr::from(([0, 0, 0, 0], config.server.port)),
        CancellationToken::new(),
        ProxySharedState::new(),
    )
    .await
}

/// Runs Direct relay for a kernel-backed TCP client tuple.
pub(crate) async fn handle_via_direct_with_shared<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    upstream_manager: Arc<UpstreamManager>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
    local_addr: SocketAddr,
    session_cancel: CancellationToken,
    shared: Arc<ProxySharedState>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_via_direct_with_shared_and_conntrack(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats,
        config,
        buffer_pool,
        rng,
        route_rx,
        route_snapshot,
        session_id,
        local_addr,
        session_cancel,
        shared,
        ConntrackClosePolicy::Publish,
    )
    .await
}

/// Runs Direct relay with explicit kernel-conntrack close publication policy.
pub(crate) async fn handle_via_direct_with_shared_and_conntrack<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    upstream_manager: Arc<UpstreamManager>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    mut route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
    local_addr: SocketAddr,
    session_cancel: CancellationToken,
    shared: Arc<ProxySharedState>,
    conntrack_close_policy: ConntrackClosePolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = &success.user;
    let dc_addr = get_dc_addr_static(success.dc_idx, &config)?;

    debug!(
        user = %user,
        peer = %success.peer,
        dc = success.dc_idx,
        dc_addr = %dc_addr,
        proto = ?success.proto_tag,
        mode = "direct",
        "Connecting to Telegram DC"
    );

    let scope_hint = validated_scope_hint(user);
    if user.starts_with("scope_") && scope_hint.is_none() {
        warn!(
            user = %user,
            "Ignoring invalid scope hint and falling back to default upstream selection"
        );
    }
    let tg_stream = tokio::select! {
        result = upstream_manager.connect(dc_addr, Some(success.dc_idx), scope_hint) => result?,
        _ = session_cancel.cancelled() => {
            return Err(ProxyError::UserDisabled {
                user: user.to_string(),
            });
        }
    };

    debug!(peer = %success.peer, dc_addr = %dc_addr, "Connected, performing TG handshake");

    let (tg_reader, tg_writer) = tokio::select! {
        result = do_tg_handshake_static(tg_stream, &success, &config, rng.as_ref()) => result?,
        _ = session_cancel.cancelled() => {
            return Err(ProxyError::UserDisabled {
                user: user.to_string(),
            });
        }
    };

    debug!(peer = %success.peer, "TG handshake complete, starting relay");

    stats.increment_user_connects(user);
    let _direct_connection_lease = stats.acquire_direct_connection_lease();
    let traffic_lease = shared
        .traffic_limiter
        .acquire_lease(user, success.peer.ip());

    let buffer_pool_trim = Arc::clone(&buffer_pool);
    let relay_activity_timeout = if shared.conntrack_pressure_active() {
        Duration::from_secs(
            config
                .server
                .conntrack_control
                .profile
                .direct_activity_timeout_secs(),
        )
    } else {
        Duration::from_secs(1800)
    };
    let relay_result = crate::proxy::relay::relay_direct_adaptive(
        client_reader,
        client_writer,
        tg_reader,
        tg_writer,
        config.general.direct_relay_copy_buf_c2s_bytes,
        config.general.direct_relay_copy_buf_s2c_bytes,
        config.server.max_connections,
        user,
        Arc::clone(&stats),
        config.access.user_data_quota.get(user).copied(),
        traffic_lease,
        relay_activity_timeout,
        session_cancel.clone(),
        Arc::clone(&shared.direct_buffer_budget),
    );
    tokio::pin!(relay_result);
    let relay_result = loop {
        if let Some(cutover) =
            affected_cutover_state(&route_rx, RelayRouteMode::Direct, route_snapshot.generation)
        {
            let delay = cutover_stagger_delay(session_id, cutover.generation);
            warn!(
                user = %user,
                target_mode = cutover.mode.as_str(),
                cutover_generation = cutover.generation,
                delay_ms = delay.as_millis() as u64,
                "Cutover affected direct session, closing client connection"
            );
            let _cutover_park_lease = stats.acquire_direct_cutover_park_lease();
            tokio::time::sleep(delay).await;
            break Err(ProxyError::RouteSwitched);
        }
        tokio::select! {
            result = &mut relay_result => {
                break result;
            }
            changed = route_rx.changed() => {
                if changed.is_err() {
                    break relay_result.await;
                }
            }
            _ = session_cancel.cancelled() => {
                break Err(ProxyError::UserDisabled {
                    user: user.to_string(),
                });
            }
        }
    };

    match &relay_result {
        Ok(()) => debug!(user = %user, "Direct relay completed"),
        Err(e) => debug!(user = %user, error = %e, "Direct relay ended with error"),
    }

    let pool_snapshot = buffer_pool_trim.stats();
    stats.set_buffer_pool_gauges(
        pool_snapshot.pooled,
        pool_snapshot.allocated,
        pool_snapshot.allocated.saturating_sub(pool_snapshot.pooled),
    );

    if conntrack_close_policy == ConntrackClosePolicy::Publish {
        let close_reason = classify_conntrack_close_reason(&relay_result);
        let publish_result = shared.publish_conntrack_close_event(ConntrackCloseEvent {
            src: success.peer,
            dst: local_addr,
            reason: close_reason,
        });
        if !matches!(
            publish_result,
            ConntrackClosePublishResult::Sent | ConntrackClosePublishResult::Disabled
        ) {
            stats.increment_conntrack_close_event_drop_total();
        }
    }

    relay_result
}

fn classify_conntrack_close_reason(result: &Result<()>) -> ConntrackCloseReason {
    match result {
        Ok(()) => ConntrackCloseReason::NormalEof,
        Err(crate::error::ProxyError::Io(error))
            if matches!(error.kind(), std::io::ErrorKind::TimedOut) =>
        {
            ConntrackCloseReason::Timeout
        }
        Err(crate::error::ProxyError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            ConntrackCloseReason::Reset
        }
        Err(crate::error::ProxyError::Proxy(message))
            if message.contains("pressure") || message.contains("evicted") =>
        {
            ConntrackCloseReason::Pressure
        }
        Err(_) => ConntrackCloseReason::Other,
    }
}
