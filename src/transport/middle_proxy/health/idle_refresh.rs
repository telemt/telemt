use super::*;


pub(super) async fn maybe_refresh_idle_writer_for_dc(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    dc: i32,
    family: IpFamily,
    endpoints: &[SocketAddr],
    alive: usize,
    required: usize,
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    writer_idle_since: &HashMap<u64, u64>,
    bound_clients_by_writer: &HashMap<u64, usize>,
    idle_refresh_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
) {
    let now = Instant::now();
    if let Some(next) = idle_refresh_next_attempt.get(&key)
        && now < *next
    {
        return;
    }

    let now_epoch_secs = MePool::now_epoch_secs();
    let mut candidate: Option<(u64, SocketAddr, u64, u64)> = None;
    for endpoint in endpoints {
        let Some(writer_ids) = live_writer_ids_by_addr.get(&(dc, *endpoint)) else {
            continue;
        };
        for writer_id in writer_ids {
            if bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) > 0 {
                continue;
            }
            let Some(idle_since_epoch_secs) = writer_idle_since.get(writer_id).copied() else {
                continue;
            };
            let idle_age_secs = now_epoch_secs.saturating_sub(idle_since_epoch_secs);
            let threshold_secs = IDLE_REFRESH_TRIGGER_BASE_SECS
                + (*writer_id % (IDLE_REFRESH_TRIGGER_JITTER_SECS + 1));
            if idle_age_secs < threshold_secs {
                continue;
            }
            if candidate
                .as_ref()
                .map(|(_, _, age, _)| idle_age_secs > *age)
                .unwrap_or(true)
            {
                candidate = Some((*writer_id, *endpoint, idle_age_secs, threshold_secs));
            }
        }
    }

    let Some((old_writer_id, endpoint, idle_age_secs, threshold_secs)) = candidate else {
        return;
    };
    let expected_role = {
        let writers = pool.writers.read().await;
        writers
            .iter()
            .find(|writer| writer.id == old_writer_id)
            .map(WriterRole::from_writer)
    };
    let Some(expected_role) = expected_role else {
        return;
    };
    if expected_role.dc != dc
        || expected_role.family != family
        || expected_role.contour != WriterContour::Active
    {
        return;
    }
    let Some(mut reservation) = pool
        .registry
        .try_reserve_writer_replacement(old_writer_id)
        .await
    else {
        return;
    };
    let generation = pool.current_generation();
    let purpose = if expected_role.generation == generation {
        WriterReplacementPurpose::IdleRefresh
    } else {
        WriterReplacementPurpose::GenerationConvergence
    };
    let replace = pool.replace_writer_with_generation_contour_for_dc(
        endpoint,
        rng.as_ref(),
        generation,
        WriterContour::Active,
        dc,
        expected_role,
        purpose,
        &mut reservation,
    );
    let rotate_ok = match tokio::time::timeout(pool.reconnect_runtime.me_one_timeout, replace).await
    {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                old_writer_id,
                idle_age_secs,
                threshold_secs,
                %error,
                "Idle writer pre-refresh replacement failed"
            );
            false
        }
        Err(_) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                old_writer_id,
                idle_age_secs,
                threshold_secs,
                "Idle writer pre-refresh replacement timed out"
            );
            false
        }
    };

    if !rotate_ok {
        idle_refresh_next_attempt.insert(key, now + Duration::from_secs(IDLE_REFRESH_RETRY_SECS));
        return;
    }

    idle_refresh_next_attempt.insert(
        key,
        now + Duration::from_secs(IDLE_REFRESH_SUCCESS_GUARD_SECS),
    );
    info!(
        dc = %dc,
        ?family,
        %endpoint,
        old_writer_id,
        idle_age_secs,
        threshold_secs,
        alive,
        required,
        generation_convergence = expected_role.generation != generation,
        "Idle writer refreshed before upstream idle timeout"
    );
}
