use super::*;

pub(super) fn has_bound_clients_on_endpoint(
    writer_ids: &[u64],
    bound_clients_by_writer: &HashMap<u64, usize>,
) -> bool {
    writer_ids
        .iter()
        .any(|writer_id| bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) > 0)
}

pub(super) async fn recover_single_endpoint_outage(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    endpoint: SocketAddr,
    required: usize,
    outage_backoff: &mut HashMap<(i32, IpFamily), u64>,
    outage_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
    reconnect_sem: &Arc<Semaphore>,
) {
    let now = Instant::now();
    if let Some(ts) = outage_next_attempt.get(&key)
        && now < *ts
    {
        return;
    }

    let (min_backoff_ms, max_backoff_ms) = pool.single_endpoint_outage_backoff_bounds_ms();
    if reconnect_sem.available_permits() == 0 {
        outage_next_attempt.insert(key, now + Duration::from_millis(min_backoff_ms.max(250)));
        debug!(
            dc = %key.0,
            family = ?key.1,
            %endpoint,
            required,
            "Single-endpoint outage reconnect deferred by health reconnect budget"
        );
        return;
    }
    let Ok(_reconnect_permit) = reconnect_sem.clone().try_acquire_owned() else {
        outage_next_attempt.insert(key, now + Duration::from_millis(min_backoff_ms.max(250)));
        debug!(
            dc = %key.0,
            family = ?key.1,
            %endpoint,
            required,
            "Single-endpoint outage reconnect deferred by semaphore saturation"
        );
        return;
    };
    pool.stats.increment_me_reconnect_attempt();
    pool.stats
        .increment_me_single_endpoint_outage_reconnect_attempt_total();

    let bypass_quarantine = pool.single_endpoint_outage_disable_quarantine();
    let attempt_ok = if bypass_quarantine {
        pool.stats
            .increment_me_single_endpoint_quarantine_bypass_total();
        match tokio::time::timeout(
            pool.reconnect_runtime.me_one_timeout,
            pool.connect_one_for_dc(endpoint, key.0, rng.as_ref()),
        )
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                debug!(
                    dc = %key.0,
                    family = ?key.1,
                    %endpoint,
                    error = %e,
                    "Single-endpoint outage reconnect failed (quarantine bypass path)"
                );
                false
            }
            Err(_) => {
                debug!(
                    dc = %key.0,
                    family = ?key.1,
                    %endpoint,
                    "Single-endpoint outage reconnect timed out (quarantine bypass path)"
                );
                false
            }
        }
    } else {
        let one_endpoint = [endpoint];
        match tokio::time::timeout(
            pool.reconnect_runtime.me_one_timeout,
            pool.connect_endpoints_round_robin(key.0, &one_endpoint, rng.as_ref()),
        )
        .await
        {
            Ok(ok) => ok,
            Err(_) => {
                debug!(
                    dc = %key.0,
                    family = ?key.1,
                    %endpoint,
                    "Single-endpoint outage reconnect timed out"
                );
                false
            }
        }
    };

    if attempt_ok {
        pool.stats
            .increment_me_single_endpoint_outage_reconnect_success_total();
        pool.stats.increment_me_reconnect_success();
        outage_backoff.insert(key, min_backoff_ms);
        let jitter = min_backoff_ms / JITTER_FRAC_NUM;
        let wait = Duration::from_millis(min_backoff_ms)
            + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
        outage_next_attempt.insert(key, now + wait);
        info!(
            dc = %key.0,
            family = ?key.1,
            %endpoint,
            required,
            backoff_ms = min_backoff_ms,
            "Single-endpoint outage reconnect succeeded"
        );
        return;
    }

    let current_ms = *outage_backoff.get(&key).unwrap_or(&min_backoff_ms);
    let next_ms = current_ms.saturating_mul(2).min(max_backoff_ms);
    outage_backoff.insert(key, next_ms);
    let jitter = next_ms / JITTER_FRAC_NUM;
    let wait = Duration::from_millis(next_ms)
        + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
    outage_next_attempt.insert(key, now + wait);
    warn!(
        dc = %key.0,
        family = ?key.1,
        %endpoint,
        required,
        backoff_ms = next_ms,
        "Single-endpoint outage reconnect scheduled"
    );
}

pub(super) async fn maybe_rotate_single_endpoint_shadow(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    dc: i32,
    family: IpFamily,
    endpoints: &[SocketAddr],
    alive: usize,
    required: usize,
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    bound_clients_by_writer: &HashMap<u64, usize>,
    shadow_rotate_deadline: &mut HashMap<(i32, IpFamily), Instant>,
) {
    if endpoints.len() != 1 || alive < required {
        return;
    }

    let Some(interval) = pool.single_endpoint_shadow_rotate_interval() else {
        return;
    };

    let now = Instant::now();
    if let Some(deadline) = shadow_rotate_deadline.get(&key)
        && now < *deadline
    {
        return;
    }

    let endpoint = endpoints[0];
    if pool.is_endpoint_quarantined(endpoint).await {
        pool.stats
            .increment_me_single_endpoint_shadow_rotate_skipped_quarantine_total();
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        debug!(
            dc = %dc,
            ?family,
            %endpoint,
            "Single-endpoint shadow rotation skipped: endpoint is quarantined"
        );
        return;
    }

    let Some(writer_ids) = live_writer_ids_by_addr.get(&(dc, endpoint)) else {
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        return;
    };

    let mut candidate_writer_id = None;
    for writer_id in writer_ids {
        if bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) == 0 {
            candidate_writer_id = Some(*writer_id);
            break;
        }
    }

    let Some(old_writer_id) = candidate_writer_id else {
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        debug!(
            dc = %dc,
            ?family,
            %endpoint,
            alive,
            required,
            "Single-endpoint shadow rotation skipped: no empty writer candidate"
        );
        return;
    };

    let rotate_ok = match tokio::time::timeout(
        pool.reconnect_runtime.me_one_timeout,
        pool.connect_one_for_dc(endpoint, dc, rng.as_ref()),
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                error = %e,
                "Single-endpoint shadow rotation connect failed"
            );
            false
        }
        Err(_) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                "Single-endpoint shadow rotation connect timed out"
            );
            false
        }
    };

    if !rotate_ok {
        shadow_rotate_deadline.insert(
            key,
            now + interval.min(Duration::from_secs(SHADOW_ROTATE_RETRY_SECS)),
        );
        return;
    }

    pool.mark_writer_draining_with_timeout(old_writer_id, pool.force_close_timeout(), false)
        .await;
    pool.stats
        .increment_me_single_endpoint_shadow_rotate_total();
    shadow_rotate_deadline.insert(key, now + interval);
    info!(
        dc = %dc,
        ?family,
        %endpoint,
        old_writer_id,
        rotate_every_secs = interval.as_secs(),
        "Single-endpoint shadow writer rotated"
    );
}
