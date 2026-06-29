use super::*;

#[derive(Clone, Copy)]
pub(super) struct MeD2cFlushPolicy {
    pub(super) max_frames: usize,
    pub(super) max_bytes: usize,
    pub(super) max_delay: Duration,
    pub(super) ack_flush_immediate: bool,
    pub(super) quota_soft_overshoot_bytes: u64,
    pub(super) frame_buf_shrink_threshold_bytes: usize,
}

impl MeD2cFlushPolicy {
    pub(super) fn from_config(config: &ProxyConfig) -> Self {
        Self {
            max_frames: config
                .general
                .me_d2c_flush_batch_max_frames
                .max(ME_D2C_FLUSH_BATCH_MAX_FRAMES_MIN),
            max_bytes: config
                .general
                .me_d2c_flush_batch_max_bytes
                .max(ME_D2C_FLUSH_BATCH_MAX_BYTES_MIN),
            max_delay: Duration::from_micros(config.general.me_d2c_flush_batch_max_delay_us),
            ack_flush_immediate: config.general.me_d2c_ack_flush_immediate,
            quota_soft_overshoot_bytes: config.general.me_quota_soft_overshoot_bytes,
            frame_buf_shrink_threshold_bytes: config
                .general
                .me_d2c_frame_buf_shrink_threshold_bytes
                .max(4096),
        }
    }
}

pub(super) fn classify_me_d2c_flush_reason(
    flush_immediately: bool,
    batch_frames: usize,
    max_frames: usize,
    batch_bytes: usize,
    max_bytes: usize,
    max_delay_fired: bool,
) -> MeD2cFlushReason {
    if flush_immediately {
        return MeD2cFlushReason::AckImmediate;
    }
    if batch_frames >= max_frames {
        return MeD2cFlushReason::BatchFrames;
    }
    if batch_bytes >= max_bytes {
        return MeD2cFlushReason::BatchBytes;
    }
    if max_delay_fired {
        return MeD2cFlushReason::MaxDelay;
    }
    MeD2cFlushReason::QueueDrain
}

pub(super) fn me_d2c_flush_reason_requires_client_flush(_reason: MeD2cFlushReason) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_flush_reasons_trigger_physical_flush() {
        assert!(me_d2c_flush_reason_requires_client_flush(
            MeD2cFlushReason::QueueDrain
        ));
        assert!(me_d2c_flush_reason_requires_client_flush(
            MeD2cFlushReason::AckImmediate
        ));
        assert!(me_d2c_flush_reason_requires_client_flush(
            MeD2cFlushReason::BatchFrames
        ));
        assert!(me_d2c_flush_reason_requires_client_flush(
            MeD2cFlushReason::BatchBytes
        ));
        assert!(me_d2c_flush_reason_requires_client_flush(
            MeD2cFlushReason::MaxDelay
        ));
        assert!(me_d2c_flush_reason_requires_client_flush(
            MeD2cFlushReason::Close
        ));
    }
}

pub(super) fn observe_me_d2c_flush_event(
    stats: &Stats,
    reason: MeD2cFlushReason,
    batch_frames: usize,
    batch_bytes: usize,
    flush_duration_us: Option<u64>,
) {
    stats.increment_me_d2c_flush_reason(reason);
    if batch_frames > 0 || batch_bytes > 0 {
        stats.increment_me_d2c_batches_total();
        stats.add_me_d2c_batch_frames_total(batch_frames as u64);
        stats.add_me_d2c_batch_bytes_total(batch_bytes as u64);
        stats.observe_me_d2c_batch_frames(batch_frames as u64);
        stats.observe_me_d2c_batch_bytes(batch_bytes as u64);
    }
    if let Some(duration_us) = flush_duration_us {
        stats.observe_me_d2c_flush_duration_us(duration_us);
    }
}

pub(super) enum MeWriterResponseOutcome {
    Continue {
        frames: usize,
        bytes: usize,
        flush_immediately: bool,
    },
    Close,
}

#[cfg(test)]
pub(crate) async fn process_me_writer_response<W>(
    response: MeResponse,
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
    stats: &Stats,
    user: &str,
    quota_user_stats: Option<&UserStats>,
    quota_limit: Option<u64>,
    quota_soft_overshoot_bytes: u64,
    bytes_me2c: &AtomicU64,
    conn_id: u64,
    ack_flush_immediate: bool,
    batched: bool,
) -> Result<MeWriterResponseOutcome>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    process_me_writer_response_with_traffic_lease(
        response,
        client_writer,
        proto_tag,
        rng,
        frame_buf,
        stats,
        user,
        quota_user_stats,
        quota_limit,
        quota_soft_overshoot_bytes,
        None,
        &CancellationToken::new(),
        bytes_me2c,
        conn_id,
        ack_flush_immediate,
        batched,
    )
    .await
}

pub(crate) async fn process_me_writer_response_with_traffic_lease<W>(
    response: MeResponse,
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
    stats: &Stats,
    user: &str,
    quota_user_stats: Option<&UserStats>,
    quota_limit: Option<u64>,
    quota_soft_overshoot_bytes: u64,
    traffic_lease: Option<&Arc<TrafficLease>>,
    cancel: &CancellationToken,
    bytes_me2c: &AtomicU64,
    conn_id: u64,
    ack_flush_immediate: bool,
    batched: bool,
) -> Result<MeWriterResponseOutcome>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    match response {
        MeResponse::Data { flags, data, .. } => {
            if batched {
                trace!(conn_id, bytes = data.len(), flags, "ME->C data (batched)");
            } else {
                trace!(conn_id, bytes = data.len(), flags, "ME->C data");
            }
            let data_len = data.len() as u64;
            if let (Some(limit), Some(user_stats)) = (quota_limit, quota_user_stats) {
                let soft_limit = quota_soft_cap(limit, quota_soft_overshoot_bytes);
                match reserve_user_quota_with_yield(
                    user_stats, data_len, soft_limit, stats, cancel, None,
                )
                .await
                {
                    Ok(_) => {}
                    Err(MiddleQuotaReserveError::LimitExceeded) => {
                        stats.increment_me_d2c_quota_reject_total(MeD2cQuotaRejectStage::PreWrite);
                        return Err(ProxyError::DataQuotaExceeded {
                            user: user.to_string(),
                        });
                    }
                    Err(MiddleQuotaReserveError::Contended) => {
                        return Err(ProxyError::Proxy(
                            "ME D->C quota reservation contended".into(),
                        ));
                    }
                    Err(MiddleQuotaReserveError::Cancelled) => {
                        return Err(ProxyError::Proxy(
                            "ME D->C quota reservation cancelled".into(),
                        ));
                    }
                    Err(MiddleQuotaReserveError::DeadlineExceeded) => {
                        return Err(ProxyError::Proxy(
                            "ME D->C quota reservation deadline exceeded".into(),
                        ));
                    }
                }
            }
            wait_for_traffic_budget_or_cancel(
                traffic_lease,
                RateDirection::Down,
                data_len,
                cancel,
                stats,
                None,
            )
            .await?;

            let write_mode = match write_client_payload(
                client_writer,
                proto_tag,
                flags,
                &data,
                rng,
                frame_buf,
                cancel,
            )
            .await
            {
                Ok(mode) => mode,
                Err(err) => {
                    if quota_limit.is_some() {
                        stats.add_quota_write_fail_bytes_total(data_len);
                        stats.increment_quota_write_fail_events_total();
                    }
                    return Err(err);
                }
            };

            bytes_me2c.fetch_add(data_len, Ordering::Relaxed);
            if let Some(user_stats) = quota_user_stats {
                stats.add_user_octets_to_handle(user_stats, data_len);
            } else {
                stats.add_user_octets_to(user, data_len);
            }
            stats.increment_me_d2c_data_frames_total();
            stats.add_me_d2c_payload_bytes_total(data_len);
            stats.increment_me_d2c_write_mode(write_mode);

            Ok(MeWriterResponseOutcome::Continue {
                frames: 1,
                bytes: data.len(),
                flush_immediately: false,
            })
        }
        MeResponse::Ack(confirm) => {
            if batched {
                trace!(conn_id, confirm, "ME->C quickack (batched)");
            } else {
                trace!(conn_id, confirm, "ME->C quickack");
            }
            wait_for_traffic_budget_or_cancel(
                traffic_lease,
                RateDirection::Down,
                4,
                cancel,
                stats,
                None,
            )
            .await?;
            write_client_ack(client_writer, proto_tag, confirm, cancel).await?;
            stats.increment_me_d2c_ack_frames_total();

            Ok(MeWriterResponseOutcome::Continue {
                frames: 1,
                bytes: 4,
                flush_immediately: ack_flush_immediate,
            })
        }
        MeResponse::Close => {
            if batched {
                debug!(conn_id, "ME sent close (batched)");
            } else {
                debug!(conn_id, "ME sent close");
            }
            Ok(MeWriterResponseOutcome::Close)
        }
    }
}

/// Computes the intermediate/secure wire length while rejecting lossy casts.
pub(in crate::proxy::middle_relay) fn compute_intermediate_secure_wire_len(
    data_len: usize,
    padding_len: usize,
    quickack: bool,
) -> Result<(u32, usize)> {
    let wire_len = data_len
        .checked_add(padding_len)
        .ok_or_else(|| ProxyError::Proxy("Frame length overflow".into()))?;
    let len_val = crate::protocol::framing::encode_intermediate_header(wire_len, quickack)
        .ok_or_else(|| {
            ProxyError::Proxy(format!("Intermediate/Secure frame too large: {wire_len}"))
        })?;
    let total = 4usize
        .checked_add(wire_len)
        .ok_or_else(|| ProxyError::Proxy("Frame buffer size overflow".into()))?;
    Ok((len_val, total))
}

pub(super) async fn write_client_payload<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    flags: u32,
    data: &[u8],
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
    cancel: &CancellationToken,
) -> Result<MeD2cWriteMode>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let quickack = (flags & RPC_FLAG_QUICKACK) != 0;

    let write_mode = match proto_tag {
        ProtoTag::Abridged => {
            if !data.len().is_multiple_of(4) {
                return Err(ProxyError::Proxy(format!(
                    "Abridged payload must be 4-byte aligned, got {}",
                    data.len()
                )));
            }

            let len_words = data.len() / 4;
            if len_words < 0x7f {
                let mut first = len_words as u8;
                if quickack {
                    first |= 0x80;
                }
                let wire_len = 1usize.saturating_add(data.len());
                if wire_len <= ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES {
                    frame_buf.clear();
                    frame_buf.reserve(wire_len);
                    frame_buf.push(first);
                    frame_buf.extend_from_slice(data);
                    write_all_client_or_cancel(client_writer, frame_buf.as_slice(), cancel).await?;
                    MeD2cWriteMode::Coalesced
                } else {
                    let header = [first];
                    write_all_client_or_cancel(client_writer, &header, cancel).await?;
                    write_all_client_or_cancel(client_writer, data, cancel).await?;
                    MeD2cWriteMode::Split
                }
            } else if len_words < (1 << 24) {
                let mut first = 0x7fu8;
                if quickack {
                    first |= 0x80;
                }
                let lw = (len_words as u32).to_le_bytes();
                let wire_len = 4usize.saturating_add(data.len());
                if wire_len <= ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES {
                    frame_buf.clear();
                    frame_buf.reserve(wire_len);
                    frame_buf.extend_from_slice(&[first, lw[0], lw[1], lw[2]]);
                    frame_buf.extend_from_slice(data);
                    write_all_client_or_cancel(client_writer, frame_buf.as_slice(), cancel).await?;
                    MeD2cWriteMode::Coalesced
                } else {
                    let header = [first, lw[0], lw[1], lw[2]];
                    write_all_client_or_cancel(client_writer, &header, cancel).await?;
                    write_all_client_or_cancel(client_writer, data, cancel).await?;
                    MeD2cWriteMode::Split
                }
            } else {
                return Err(ProxyError::Proxy(format!(
                    "Abridged frame too large: {}",
                    data.len()
                )));
            }
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            let padding_len = if proto_tag == ProtoTag::Secure {
                if !is_valid_secure_payload_len(data.len()) {
                    return Err(ProxyError::Proxy(format!(
                        "Secure payload must be 4-byte aligned, got {}",
                        data.len()
                    )));
                }
                secure_padding_len(data.len(), rng)
            } else {
                0
            };

            let (len_val, total) =
                compute_intermediate_secure_wire_len(data.len(), padding_len, quickack)?;
            if total <= ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES {
                frame_buf.clear();
                frame_buf.reserve(total);
                frame_buf.extend_from_slice(&len_val.to_le_bytes());
                frame_buf.extend_from_slice(data);
                if padding_len > 0 {
                    let start = frame_buf.len();
                    frame_buf.resize(start + padding_len, 0);
                    rng.fill(&mut frame_buf[start..]);
                }
                write_all_client_or_cancel(client_writer, frame_buf.as_slice(), cancel).await?;
                MeD2cWriteMode::Coalesced
            } else {
                let header = len_val.to_le_bytes();
                write_all_client_or_cancel(client_writer, &header, cancel).await?;
                write_all_client_or_cancel(client_writer, data, cancel).await?;
                if padding_len > 0 {
                    frame_buf.clear();
                    if frame_buf.capacity() < padding_len {
                        frame_buf.reserve(padding_len);
                    }
                    frame_buf.resize(padding_len, 0);
                    rng.fill(frame_buf.as_mut_slice());
                    write_all_client_or_cancel(client_writer, frame_buf.as_slice(), cancel).await?;
                }
                MeD2cWriteMode::Split
            }
        }
    };

    Ok(write_mode)
}

pub(super) async fn write_client_ack<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    confirm: u32,
    cancel: &CancellationToken,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let bytes = if proto_tag == ProtoTag::Abridged {
        confirm.to_be_bytes()
    } else {
        confirm.to_le_bytes()
    };
    write_all_client_or_cancel(client_writer, &bytes, cancel).await
}

pub(super) async fn write_all_client_or_cancel<W>(
    client_writer: &mut CryptoWriter<W>,
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(ProxyError::MiddleClientWriterCancelled),
        result = client_writer.write_all(bytes) => result.map_err(ProxyError::Io),
    }
}

pub(super) async fn flush_client_or_cancel<W>(
    client_writer: &mut CryptoWriter<W>,
    cancel: &CancellationToken,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(ProxyError::MiddleClientWriterCancelled),
        result = client_writer.flush() => result.map_err(ProxyError::Io),
    }
}
