use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_c2me_sender(
    mut c2me_rx: mpsc::Receiver<C2MeCommand>,
    me_pool_c2me: Arc<MePool>,
    conn_id: u64,
    success: HandshakeSuccess,
    peer: SocketAddr,
    translated_local_addr: SocketAddr,
    effective_tag_array: Option<[u8; 16]>,
) -> Result<()> {
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
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_me_writer<W>(
    crypto_writer: CryptoWriter<W>,
    mut me_rx_task: mpsc::Receiver<MeResponse>,
    stats_clone: Arc<Stats>,
    rng_clone: Arc<SecureRandom>,
    user_clone: String,
    quota_user_stats_me_writer: Option<Arc<UserStats>>,
    quota_limit: Option<u64>,
    traffic_lease_me_writer: Option<Arc<TrafficLease>>,
    flow_cancel_me_writer: CancellationToken,
    last_downstream_activity_ms_clone: Arc<AtomicU64>,
    bytes_me2c_clone: Arc<AtomicU64>,
    d2c_flush_policy: MeD2cFlushPolicy,
    proto_tag: ProtoTag,
    session_started_at: Instant,
    conn_id: u64,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
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
}
