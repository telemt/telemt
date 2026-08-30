use super::*;

/// Relays traffic between the client and mask backend.
pub(super) async fn relay_to_mask<R, W, MR, MW>(
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
pub(super) async fn consume_client_data<R: AsyncRead + Unpin>(
    mut reader: R,
    byte_cap: usize,
    idle_timeout: Duration,
) {
    // Keep drain path fail-closed under slow-loris stalls.
    let mut buf = vec![0u8; MASK_BUFFER_SIZE];
    let mut total = 0usize;

    loop {
        let read_len = mask_copy_read_len(total, byte_cap);
        if read_len == 0 {
            break;
        }
        if buf.len() < read_len {
            buf.resize(read_len, 0);
        }
        let n = match timeout(idle_timeout, reader.read(&mut buf[..read_len])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };

        if n == 0 {
            break;
        }

        total = total.saturating_add(n);
        if byte_cap != 0 && total >= byte_cap {
            break;
        }
    }
}
