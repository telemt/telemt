use super::*;

// Bounded C2ME sender and downstream writer tasks.
mod tasks;
// Conntrack close classification.
mod close_reason;

use close_reason::classify_conntrack_close_reason;
use tasks::{run_c2me_sender, run_me_writer};
struct RelayConnLease {
    connection: Option<ConnLease>,
    conn_id: u64,
    shared: Arc<ProxySharedState>,
}

impl RelayConnLease {
    fn new(connection: ConnLease, shared: Arc<ProxySharedState>) -> Self {
        let conn_id = connection.conn_id();
        Self {
            connection: Some(connection),
            conn_id,
            shared,
        }
    }

    fn conn_id(&self) -> u64 {
        self.conn_id
    }

    async fn unregister(mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        clear_relay_idle_candidate_in(self.shared.as_ref(), connection.conn_id());
        connection.unregister().await;
    }
}

impl Drop for RelayConnLease {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.as_ref() {
            clear_relay_idle_candidate_in(self.shared.as_ref(), connection.conn_id());
        }
    }
}

/// Runs Middle-End relay with explicit kernel-conntrack close publication policy.
pub(crate) async fn handle_via_middle_proxy_with_conntrack<R, W>(
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
    conntrack_close_policy: ConntrackClosePolicy,
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

    let Some((connection, me_rx)) = me_pool.register_connection().await else {
        return Err(ProxyError::MiddleConnectionLost);
    };
    let relay_connection = RelayConnLease::new(connection, Arc::clone(&shared));
    let conn_id = relay_connection.conn_id();
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
        relay_connection.unregister().await;
        return Err(ProxyError::RouteSwitched);
    }

    // Prefer the hot-reloadable per-user ad tag over the global fallback.
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
    let (c2me_tx, c2me_rx) = mpsc::channel::<C2MeCommand>(c2me_channel_capacity);
    let me_pool_c2me = me_pool.clone();
    let mut c2me_sender = tokio::spawn(run_c2me_sender(
        c2me_rx,
        me_pool_c2me,
        conn_id,
        success,
        peer,
        translated_local_addr,
        effective_tag_array,
    ));

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let flow_cancel = CancellationToken::new();
    let me_rx_task = me_rx;
    let stats_clone = stats.clone();
    let rng_clone = rng.clone();
    let user_clone = user.clone();
    let quota_user_stats_me_writer = quota_user_stats.clone();
    let traffic_lease_me_writer = traffic_lease.clone();
    let flow_cancel_me_writer = flow_cancel.clone();
    let last_downstream_activity_ms_clone = last_downstream_activity_ms.clone();
    let bytes_me2c_clone = bytes_me2c.clone();
    let d2c_flush_policy = MeD2cFlushPolicy::from_config(&config);
    let mut me_writer = tokio::spawn(run_me_writer(
        crypto_writer,
        me_rx_task,
        stats_clone,
        rng_clone,
        user_clone,
        quota_user_stats_me_writer,
        quota_limit,
        traffic_lease_me_writer,
        flow_cancel_me_writer,
        last_downstream_activity_ms_clone,
        bytes_me2c_clone,
        d2c_flush_policy,
        proto_tag,
        session_started_at,
        conn_id,
        stop_rx,
    ));

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

    // A client-initiated close can unregister the ME channel before its writer exits.
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

    if conntrack_close_policy == ConntrackClosePolicy::Publish {
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
    }

    relay_connection.unregister().await;
    let pool_snapshot = buffer_pool.stats();
    stats.set_buffer_pool_gauges(
        pool_snapshot.pooled,
        pool_snapshot.allocated,
        pool_snapshot.allocated.saturating_sub(pool_snapshot.pooled),
    );
    result
}
