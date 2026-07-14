use super::*;

pub(crate) async fn handle_via_middle_proxy<R, W>(
    mut crypto_reader: CryptoReader<R>,
    crypto_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    me_pool: Arc<MePool>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    buffer_pool: Arc<BufferPool>,
    local_addr: SocketAddr,
    rng: Arc<SecureRandom>,
    mut route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
    session_cancel: CancellationToken,
    shared: Arc<ProxySharedState>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = success.user.clone();
    if session_cancel.is_cancelled() {
        return Err(ProxyError::UserDisabled { user });
    }

    let quota_limit = config.access.user_data_quota.get(&user).copied();
    let quota_user_stats = quota_limit.map(|_| stats.get_or_create_user_stats_handle(&user));
    let peer = success.peer;
    let traffic_lease = shared.traffic_limiter.acquire_lease(&user, peer.ip());
    let proto_tag = success.proto_tag;
    let pool_generation = me_pool.current_generation();

    debug!(
        user = %user,
        peer = %peer,
        dc = success.dc_idx,
        proto = ?proto_tag,
        mode = "middle_proxy",
        pool_generation,
        "Routing via Middle-End"
    );

    let (conn_id, me_rx) = me_pool.registry().register().await;
    let trace_id = session_id;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut forensics = RelayForensicsState {
        trace_id,
        conn_id,
        user: user.clone(),
        peer,
        peer_hash: hash_ip_in(shared.as_ref(), peer.ip()),
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: bytes_me2c.clone(),
        desync_all_full: config.general.desync_all_full,
    };

    stats.increment_user_connects(&user);
    let _me_connection_lease = stats.acquire_me_connection_lease();

    if let Some(cutover) =
        affected_cutover_state(&route_rx, RelayRouteMode::Middle, route_snapshot.generation)
    {
        let delay = cutover_stagger_delay(session_id, cutover.generation);
        warn!(
            conn_id,
            target_mode = cutover.mode.as_str(),
            cutover_generation = cutover.generation,
            delay_ms = delay.as_millis() as u64,
            "Cutover affected middle session before relay start, closing client connection"
        );
        let _cutover_park_lease = stats.acquire_middle_cutover_park_lease();
        tokio::time::sleep(delay).await;
        let _ = me_pool.send_close(conn_id).await;
        me_pool.registry().unregister(conn_id).await;
        return Err(ProxyError::RouteSwitched);
    }

    // Per-user ad_tag from access.user_ad_tags; fallback to general.ad_tag (hot-reloadable)
    let user_tag: Option<Vec<u8>> = config
        .access
        .user_ad_tags
        .get(&user)
        .and_then(|s| hex::decode(s).ok())
        .filter(|v| v.len() == 16);
    let global_tag: Option<Vec<u8>> = config
        .general
        .ad_tag
        .as_ref()
        .and_then(|s| hex::decode(s).ok())
        .filter(|v| v.len() == 16);
    let effective_tag = user_tag.or(global_tag);

    let proto_flags = proto_flags_for_tag(proto_tag, effective_tag.is_some());
    let effective_tag_array = effective_tag
        .as_deref()
        .and_then(|tag| <[u8; 16]>::try_from(tag).ok());
    debug!(
        trace_id = format_args!("0x{:016x}", trace_id),
        user = %user,
        conn_id,
        peer_hash = format_args!("0x{:016x}", forensics.peer_hash),
        desync_all_full = forensics.desync_all_full,
        proto_flags = format_args!("0x{:08x}", proto_flags),
        pool_generation,
        "ME relay started"
    );

    let translated_local_addr = me_pool.translate_our_addr(local_addr);

    let frame_limit = config.general.max_client_frame;
    let mut relay_idle_policy = RelayClientIdlePolicy::from_config(&config);
    let mut pressure_caps_applied = false;
    if shared.conntrack_pressure_active() {
        relay_idle_policy.apply_pressure_caps(config.server.conntrack_control.profile);
        pressure_caps_applied = true;
    }
    let session_started_at = forensics.started_at;
    let mut relay_idle_state = RelayClientIdleState::new(session_started_at);
    let last_downstream_activity_ms = Arc::new(AtomicU64::new(0));

    let c2me_channel_capacity = config
        .general
        .me_c2me_channel_capacity
        .max(C2ME_CHANNEL_CAPACITY_FALLBACK);
    let c2me_send_timeout = match config.general.me_c2me_send_timeout_ms {
        0 => None,
        timeout_ms => Some(Duration::from_millis(timeout_ms)),
    };
    let c2me_byte_budget = c2me_queued_permit_budget(c2me_channel_capacity, frame_limit);
    let c2me_byte_semaphore = Arc::new(Semaphore::new(c2me_byte_budget));
    let (c2me_tx, mut c2me_rx) = mpsc::channel::<C2MeCommand>(c2me_channel_capacity);
    let me_pool_c2me = me_pool.clone();
    let mut c2me_sender = tokio::spawn(async move {
        let mut sent_since_yield = 0usize;
        while let Some(cmd) = c2me_rx.recv().await {
            match cmd {
                C2MeCommand::Data {
                    payload,
                    flags,
                    _permit,
                } => {
                    me_pool_c2me
                        .send_proxy_req_pooled(
                            conn_id,
                            success.dc_idx,
                            peer,
                            translated_local_addr,
                            payload,
                            _permit,
                            flags,
                            effective_tag_array,
                        )
                        .await?;
                    sent_since_yield = sent_since_yield.saturating_add(1);
                    if should_yield_c2me_sender(sent_since_yield, !c2me_rx.is_empty()) {
                        sent_since_yield = 0;
                        tokio::task::yield_now().await;
                    }
                }
                C2MeCommand::Close => {
                    let _ = me_pool_c2me.send_close(conn_id).await;
                    return Ok(());
                }
            }
        }
        Ok(())
    });

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let flow_cancel = CancellationToken::new();
    let mut me_rx_task = me_rx;
    let stats_clone = stats.clone();
    let rng_clone = rng.clone();
    let user_clone = user.clone();
    let quota_user_stats_me_writer = quota_user_stats.clone();
    let traffic_lease_me_writer = traffic_lease.clone();
    let flow_cancel_me_writer = flow_cancel.clone();
    let last_downstream_activity_ms_clone = last_downstream_activity_ms.clone();
    let bytes_me2c_clone = bytes_me2c.clone();
    let d2c_flush_policy = MeD2cFlushPolicy::from_config(&config);
    let mut me_writer = tokio::spawn(async move {
        let mut writer = crypto_writer;
        let mut frame_buf = Vec::with_capacity(16 * 1024);
        let shrink_threshold = d2c_flush_policy.frame_buf_shrink_threshold_bytes;

        fn shrink_session_vec(buf: &mut Vec<u8>, threshold: usize) {
            if buf.capacity() > threshold {
                buf.clear();
                buf.shrink_to(threshold);
            } else {
                buf.clear();
            }
        }

        loop {
            tokio::select! {
                msg = me_rx_task.recv() => {
                    let Some(first) = msg else {
                        debug!(conn_id, "ME channel closed");
                        shrink_session_vec(&mut frame_buf, shrink_threshold);
                        return Err(ProxyError::MiddleConnectionLost);
                    };

                    let mut batch_frames = 0usize;
                    let mut batch_bytes = 0usize;
                    let mut flush_immediately;
                    let mut max_delay_fired = false;

                    let first_is_downstream_activity =
                        matches!(&first, MeResponse::Data { .. } | MeResponse::Ack(_));
                    match process_me_writer_response_with_traffic_lease(
                        first,
                        &mut writer,
                        proto_tag,
                        rng_clone.as_ref(),
                        &mut frame_buf,
                        stats_clone.as_ref(),
                        &user_clone,
                        quota_user_stats_me_writer.as_deref(),
                        quota_limit,
                        d2c_flush_policy.quota_soft_overshoot_bytes,
                        traffic_lease_me_writer.as_ref(),
                        &flow_cancel_me_writer,
                        bytes_me2c_clone.as_ref(),
                        conn_id,
                        d2c_flush_policy.ack_flush_immediate,
                        false,
                    ).await? {
                        MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                            if first_is_downstream_activity {
                                last_downstream_activity_ms_clone
                                    .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                            }
                            batch_frames = batch_frames.saturating_add(frames);
                            batch_bytes = batch_bytes.saturating_add(bytes);
                            flush_immediately = immediate;
                        }
                        MeWriterResponseOutcome::Close => {
                            let flush_started_at = if stats_clone.telemetry_policy().me_level.allows_debug() {
                                Some(Instant::now())
                            } else {
                                None
                            };
                            let _ = flush_client_or_cancel(&mut writer, &flow_cancel_me_writer).await;
                            let flush_duration_us = flush_started_at.map(|started| {
                                started
                                    .elapsed()
                                    .as_micros()
                                    .min(u128::from(u64::MAX)) as u64
                            });
                            observe_me_d2c_flush_event(
                                stats_clone.as_ref(),
                                MeD2cFlushReason::Close,
                                batch_frames,
                                batch_bytes,
                                flush_duration_us,
                            );
                            shrink_session_vec(&mut frame_buf, shrink_threshold);
                            return Ok(());
                        }
                    }

                    while !flush_immediately
                        && batch_frames < d2c_flush_policy.max_frames
                        && batch_bytes < d2c_flush_policy.max_bytes
                    {
                        let Ok(next) = me_rx_task.try_recv() else {
                            break;
                        };

                        let next_is_downstream_activity =
                            matches!(&next, MeResponse::Data { .. } | MeResponse::Ack(_));
                        match process_me_writer_response_with_traffic_lease(
                            next,
                            &mut writer,
                            proto_tag,
                            rng_clone.as_ref(),
                            &mut frame_buf,
                            stats_clone.as_ref(),
                            &user_clone,
                            quota_user_stats_me_writer.as_deref(),
                            quota_limit,
                            d2c_flush_policy.quota_soft_overshoot_bytes,
                            traffic_lease_me_writer.as_ref(),
                            &flow_cancel_me_writer,
                            bytes_me2c_clone.as_ref(),
                            conn_id,
                            d2c_flush_policy.ack_flush_immediate,
                            true,
                        ).await? {
                            MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                if next_is_downstream_activity {
                                    last_downstream_activity_ms_clone
                                        .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                                }
                                batch_frames = batch_frames.saturating_add(frames);
                                batch_bytes = batch_bytes.saturating_add(bytes);
                                flush_immediately |= immediate;
                            }
                            MeWriterResponseOutcome::Close => {
                                let flush_started_at =
                                    if stats_clone.telemetry_policy().me_level.allows_debug() {
                                        Some(Instant::now())
                                    } else {
                                        None
                                    };
                                let _ =
                                    flush_client_or_cancel(&mut writer, &flow_cancel_me_writer).await;
                                let flush_duration_us = flush_started_at.map(|started| {
                                    started
                                        .elapsed()
                                        .as_micros()
                                        .min(u128::from(u64::MAX))
                                        as u64
                                });
                                observe_me_d2c_flush_event(
                                    stats_clone.as_ref(),
                                    MeD2cFlushReason::Close,
                                    batch_frames,
                                    batch_bytes,
                                    flush_duration_us,
                                );
                                shrink_session_vec(&mut frame_buf, shrink_threshold);
                                return Ok(());
                            }
                        }
                    }

                    if !flush_immediately
                        && !d2c_flush_policy.max_delay.is_zero()
                        && batch_frames < d2c_flush_policy.max_frames
                        && batch_bytes < d2c_flush_policy.max_bytes
                    {
                        stats_clone.increment_me_d2c_batch_timeout_armed_total();
                        match tokio::time::timeout(d2c_flush_policy.max_delay, me_rx_task.recv()).await {
                            Ok(Some(next)) => {
                                let next_is_downstream_activity =
                                    matches!(&next, MeResponse::Data { .. } | MeResponse::Ack(_));
                                match process_me_writer_response_with_traffic_lease(
                                    next,
                                    &mut writer,
                                    proto_tag,
                                    rng_clone.as_ref(),
                                    &mut frame_buf,
                                    stats_clone.as_ref(),
                                    &user_clone,
                                    quota_user_stats_me_writer.as_deref(),
                                    quota_limit,
                                    d2c_flush_policy.quota_soft_overshoot_bytes,
                                    traffic_lease_me_writer.as_ref(),
                                    &flow_cancel_me_writer,
                                    bytes_me2c_clone.as_ref(),
                                    conn_id,
                                    d2c_flush_policy.ack_flush_immediate,
                                    true,
                                ).await? {
                                    MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                        if next_is_downstream_activity {
                                            last_downstream_activity_ms_clone
                                                .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                                        }
                                        batch_frames = batch_frames.saturating_add(frames);
                                        batch_bytes = batch_bytes.saturating_add(bytes);
                                        flush_immediately |= immediate;
                                    }
                                    MeWriterResponseOutcome::Close => {
                                        let flush_started_at = if stats_clone
                                            .telemetry_policy()
                                            .me_level
                                            .allows_debug()
                                        {
                                            Some(Instant::now())
                                        } else {
                                            None
                                        };
                                        let _ = flush_client_or_cancel(
                                            &mut writer,
                                            &flow_cancel_me_writer,
                                        )
                                        .await;
                                        let flush_duration_us = flush_started_at.map(|started| {
                                            started
                                                .elapsed()
                                                .as_micros()
                                                .min(u128::from(u64::MAX))
                                                as u64
                                        });
                                        observe_me_d2c_flush_event(
                                            stats_clone.as_ref(),
                                            MeD2cFlushReason::Close,
                                            batch_frames,
                                            batch_bytes,
                                            flush_duration_us,
                                        );
                                        shrink_session_vec(&mut frame_buf, shrink_threshold);
                                        return Ok(());
                                    }
                                }

                                while !flush_immediately
                                    && batch_frames < d2c_flush_policy.max_frames
                                    && batch_bytes < d2c_flush_policy.max_bytes
                                {
                                    let Ok(extra) = me_rx_task.try_recv() else {
                                        break;
                                    };

                                    let extra_is_downstream_activity =
                                        matches!(&extra, MeResponse::Data { .. } | MeResponse::Ack(_));
                                    match process_me_writer_response_with_traffic_lease(
                                        extra,
                                        &mut writer,
                                        proto_tag,
                                        rng_clone.as_ref(),
                                        &mut frame_buf,
                                        stats_clone.as_ref(),
                                        &user_clone,
                                        quota_user_stats_me_writer.as_deref(),
                                        quota_limit,
                                        d2c_flush_policy.quota_soft_overshoot_bytes,
                                        traffic_lease_me_writer.as_ref(),
                                        &flow_cancel_me_writer,
                                        bytes_me2c_clone.as_ref(),
                                        conn_id,
                                        d2c_flush_policy.ack_flush_immediate,
                                        true,
                                    ).await? {
                                        MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                            if extra_is_downstream_activity {
                                                last_downstream_activity_ms_clone
                                                    .store(session_started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
                                            }
                                            batch_frames = batch_frames.saturating_add(frames);
                                            batch_bytes = batch_bytes.saturating_add(bytes);
                                            flush_immediately |= immediate;
                                        }
                                        MeWriterResponseOutcome::Close => {
                                            let flush_started_at = if stats_clone
                                                .telemetry_policy()
                                                .me_level
                                                .allows_debug()
                                            {
                                                Some(Instant::now())
                                            } else {
                                                None
                                            };
                                            let _ = flush_client_or_cancel(
                                                &mut writer,
                                                &flow_cancel_me_writer,
                                            )
                                            .await;
                                            let flush_duration_us = flush_started_at.map(|started| {
                                                started
                                                    .elapsed()
                                                    .as_micros()
                                                    .min(u128::from(u64::MAX))
                                                    as u64
                                            });
                                            observe_me_d2c_flush_event(
                                                stats_clone.as_ref(),
                                                MeD2cFlushReason::Close,
                                                batch_frames,
                                                batch_bytes,
                                                flush_duration_us,
                                            );
                                            shrink_session_vec(&mut frame_buf, shrink_threshold);
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                debug!(conn_id, "ME channel closed");
                                shrink_session_vec(&mut frame_buf, shrink_threshold);
                                return Err(ProxyError::MiddleConnectionLost);
                            }
                            Err(_) => {
                                max_delay_fired = true;
                                stats_clone.increment_me_d2c_batch_timeout_fired_total();
                            }
                        }
                    }

                    let flush_reason = classify_me_d2c_flush_reason(
                        flush_immediately,
                        batch_frames,
                        d2c_flush_policy.max_frames,
                        batch_bytes,
                        d2c_flush_policy.max_bytes,
                        max_delay_fired,
                    );
                    let physical_flush =
                        me_d2c_flush_reason_requires_client_flush(flush_reason);
                    let flush_started_at = if physical_flush
                        && stats_clone.telemetry_policy().me_level.allows_debug()
                    {
                        Some(Instant::now())
                    } else {
                        None
                    };
                    if physical_flush {
                        flush_client_or_cancel(&mut writer, &flow_cancel_me_writer).await?;
                    }
                    let flush_duration_us = flush_started_at.map(|started| {
                        started
                            .elapsed()
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64
                    });
                    observe_me_d2c_flush_event(
                        stats_clone.as_ref(),
                        flush_reason,
                        batch_frames,
                        batch_bytes,
                        flush_duration_us,
                    );
                    let shrink_threshold = d2c_flush_policy.frame_buf_shrink_threshold_bytes;
                    let shrink_trigger = shrink_threshold
                        .saturating_mul(ME_D2C_FRAME_BUF_SHRINK_HYSTERESIS_FACTOR);
                    if frame_buf.capacity() > shrink_trigger {
                        let cap_before = frame_buf.capacity();
                        frame_buf.shrink_to(shrink_threshold);
                        let cap_after = frame_buf.capacity();
                        let bytes_freed = cap_before.saturating_sub(cap_after) as u64;
                        stats_clone.observe_me_d2c_frame_buf_shrink(bytes_freed);
                    }
                }
                _ = &mut stop_rx => {
                    debug!(conn_id, "ME writer stop signal");
                    shrink_session_vec(&mut frame_buf, shrink_threshold);
                    return Ok(());
                }
            }
        }
    });

    let mut main_result: Result<()> = Ok(());
    let mut client_closed = false;
    let mut frame_counter: u64 = 0;
    let mut route_watch_open = true;
    let mut seen_pressure_seq = relay_pressure_event_seq_in(shared.as_ref());
    loop {
        if shared.conntrack_pressure_active() && !pressure_caps_applied {
            relay_idle_policy.apply_pressure_caps(config.server.conntrack_control.profile);
            pressure_caps_applied = true;
        }

        if relay_idle_policy.enabled
            && maybe_evict_idle_candidate_on_pressure_in(
                shared.as_ref(),
                conn_id,
                &mut seen_pressure_seq,
                stats.as_ref(),
            )
        {
            info!(
                conn_id,
                trace_id = format_args!("0x{:016x}", trace_id),
                user = %user,
                "Middle-relay pressure eviction for idle-candidate session"
            );
            let _ = enqueue_c2me_command_in(
                shared.as_ref(),
                &c2me_tx,
                C2MeCommand::Close,
                c2me_send_timeout,
                stats.as_ref(),
            )
            .await;
            main_result = Err(ProxyError::Proxy(
                "middle-relay session evicted under pressure (idle-candidate)".to_string(),
            ));
            break;
        }

        if let Some(cutover) =
            affected_cutover_state(&route_rx, RelayRouteMode::Middle, route_snapshot.generation)
        {
            let delay = cutover_stagger_delay(session_id, cutover.generation);
            warn!(
                conn_id,
                target_mode = cutover.mode.as_str(),
                cutover_generation = cutover.generation,
                delay_ms = delay.as_millis() as u64,
                "Cutover affected middle session, closing client connection"
            );
            let _cutover_park_lease = stats.acquire_middle_cutover_park_lease();
            tokio::time::sleep(delay).await;
            let _ = enqueue_c2me_command_in(
                shared.as_ref(),
                &c2me_tx,
                C2MeCommand::Close,
                c2me_send_timeout,
                stats.as_ref(),
            )
            .await;
            main_result = Err(ProxyError::RouteSwitched);
            break;
        }

        tokio::select! {
            _ = session_cancel.cancelled() => {
                warn!(
                    user = %user,
                    conn_id,
                    "Disabled user middle session cancelled"
                );
                let _ = enqueue_c2me_command_in(
                    shared.as_ref(),
                    &c2me_tx,
                    C2MeCommand::Close,
                    c2me_send_timeout,
                    stats.as_ref(),
                )
                .await;
                main_result = Err(ProxyError::UserDisabled {
                    user: user.clone(),
                });
                break;
            }
            changed = route_rx.changed(), if route_watch_open => {
                if changed.is_err() {
                    route_watch_open = false;
                }
            }
            payload_result = read_client_payload_with_idle_policy_in(
                &mut crypto_reader,
                proto_tag,
                frame_limit,
                &buffer_pool,
                &forensics,
                &mut frame_counter,
                &stats,
                shared.as_ref(),
                &relay_idle_policy,
                &mut relay_idle_state,
                last_downstream_activity_ms.as_ref(),
                session_started_at,
            ) => {
                match payload_result {
                    Ok(Some((payload, quickack))) => {
                        trace!(conn_id, bytes = payload.len(), "C->ME frame");
                        wait_for_traffic_budget(
                            traffic_lease.as_ref(),
                            RateDirection::Up,
                            payload.len() as u64,
                            None,
                        )
                        .await?;
                        forensics.bytes_c2me = forensics
                            .bytes_c2me
                            .saturating_add(payload.len() as u64);
                        if let (Some(limit), Some(user_stats)) =
                            (quota_limit, quota_user_stats.as_deref())
                        {
                            match reserve_user_quota_with_yield(
                                user_stats,
                                payload.len() as u64,
                                limit,
                                stats.as_ref(),
                                &flow_cancel,
                                None,
                            )
                            .await
                            {
                                Ok(_) => {}
                                Err(MiddleQuotaReserveError::LimitExceeded) => {
                                    main_result = Err(ProxyError::DataQuotaExceeded {
                                        user: user.clone(),
                                    });
                                    break;
                                }
                                Err(MiddleQuotaReserveError::Contended) => {
                                    main_result = Err(ProxyError::Proxy(
                                        "ME C->ME quota reservation contended".into(),
                                    ));
                                    break;
                                }
                                Err(MiddleQuotaReserveError::Cancelled) => {
                                    main_result = Err(ProxyError::Proxy(
                                        "ME C->ME quota reservation cancelled".into(),
                                    ));
                                    break;
                                }
                                Err(MiddleQuotaReserveError::DeadlineExceeded) => {
                                    main_result = Err(ProxyError::Proxy(
                                        "ME C->ME quota reservation deadline exceeded".into(),
                                    ));
                                    break;
                                }
                            }
                            stats.add_user_octets_from_handle(user_stats, payload.len() as u64);
                        } else {
                            stats.add_user_octets_from(&user, payload.len() as u64);
                        }
                        let mut flags = proto_flags;
                        if quickack {
                            flags |= RPC_FLAG_QUICKACK;
                        }
                        if payload.len() >= 8 && payload[..8].iter().all(|b| *b == 0) {
                            flags |= RPC_FLAG_NOT_ENCRYPTED;
                        }
                        let payload_permit = match acquire_c2me_payload_permit(
                            &c2me_byte_semaphore,
                            payload.len(),
                            c2me_send_timeout,
                            stats.as_ref(),
                        )
                        .await
                        {
                            Ok(permit) => permit,
                            Err(e) => {
                                main_result = Err(e);
                                break;
                            }
                        };
                        // Keep client read loop lightweight: route heavy ME send path via a dedicated task.
                        if enqueue_c2me_command_in(
                            shared.as_ref(),
                            &c2me_tx,
                            C2MeCommand::Data {
                                payload,
                                flags,
                                _permit: payload_permit,
                            },
                            c2me_send_timeout,
                            stats.as_ref(),
                        )
                        .await
                            .is_err()
                        {
                            main_result = Err(ProxyError::Proxy("ME sender channel closed".into()));
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!(conn_id, "Client EOF");
                        client_closed = true;
                        let _ = enqueue_c2me_command_in(
                            shared.as_ref(),
                            &c2me_tx,
                            C2MeCommand::Close,
                            c2me_send_timeout,
                            stats.as_ref(),
                        )
                        .await;
                        break;
                    }
                    Err(e) => {
                        main_result = Err(e);
                        break;
                    }
                }
            }
        }
    }

    drop(c2me_tx);
    let c2me_result = match timeout(ME_CHILD_JOIN_TIMEOUT, &mut c2me_sender).await {
        Ok(joined) => {
            joined.unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME sender join error: {e}"))))
        }
        Err(_) => {
            stats.increment_me_child_join_timeout_total();
            stats.increment_me_child_abort_total();
            c2me_sender.abort();
            Err(ProxyError::Proxy("ME sender join timeout".into()))
        }
    };

    flow_cancel.cancel();
    let _ = stop_tx.send(());
    let mut writer_result = match timeout(ME_CHILD_JOIN_TIMEOUT, &mut me_writer).await {
        Ok(joined) => {
            joined.unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME writer join error: {e}"))))
        }
        Err(_) => {
            stats.increment_me_child_join_timeout_total();
            stats.increment_me_child_abort_total();
            me_writer.abort();
            Err(ProxyError::Proxy("ME writer join timeout".into()))
        }
    };

    // When client closes, but ME channel stopped as unregistered - it isnt error
    if client_closed && matches!(writer_result, Err(ProxyError::MiddleConnectionLost)) {
        writer_result = Ok(());
    }

    let result = match (main_result, c2me_result, writer_result) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(e), _, _) => Err(e),
        (_, Err(e), _) => Err(e),
        (_, _, Err(e)) => Err(e),
    };

    debug!(
        user = %user,
        conn_id,
        trace_id = format_args!("0x{:016x}", trace_id),
        duration_ms = forensics.started_at.elapsed().as_millis() as u64,
        bytes_c2me = forensics.bytes_c2me,
        bytes_me2c = forensics.bytes_me2c.load(Ordering::Relaxed),
        frames_ok = frame_counter,
        "ME relay cleanup"
    );

    let close_reason = classify_conntrack_close_reason(&result);
    let publish_result = shared.publish_conntrack_close_event(ConntrackCloseEvent {
        src: peer,
        dst: local_addr,
        reason: close_reason,
    });
    if !matches!(
        publish_result,
        ConntrackClosePublishResult::Sent | ConntrackClosePublishResult::Disabled
    ) {
        stats.increment_conntrack_close_event_drop_total();
    }

    clear_relay_idle_candidate_in(shared.as_ref(), conn_id);
    me_pool.registry().unregister(conn_id).await;
    let pool_snapshot = buffer_pool.stats();
    stats.set_buffer_pool_gauges(
        pool_snapshot.pooled,
        pool_snapshot.allocated,
        pool_snapshot.allocated.saturating_sub(pool_snapshot.pooled),
    );
    result
}

fn classify_conntrack_close_reason(result: &Result<()>) -> ConntrackCloseReason {
    match result {
        Ok(()) => ConntrackCloseReason::NormalEof,
        Err(ProxyError::Io(error)) if matches!(error.kind(), std::io::ErrorKind::TimedOut) => {
            ConntrackCloseReason::Timeout
        }
        Err(ProxyError::Io(error))
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
        Err(ProxyError::Proxy(message))
            if message.contains("pressure") || message.contains("evicted") =>
        {
            ConntrackCloseReason::Pressure
        }
        Err(_) => ConntrackCloseReason::Other,
    }
}
