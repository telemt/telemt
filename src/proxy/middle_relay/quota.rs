use super::*;

pub(super) enum MiddleQuotaReserveError {
    LimitExceeded,
    Contended,
    Cancelled,
    DeadlineExceeded,
}

pub(super) fn quota_soft_cap(limit: u64, overshoot: u64) -> u64 {
    limit.saturating_add(overshoot)
}

pub(super) async fn reserve_user_quota_with_yield(
    user_stats: &UserStats,
    bytes: u64,
    limit: u64,
    stats: &Stats,
    cancel: &CancellationToken,
    deadline: Option<Instant>,
) -> std::result::Result<u64, MiddleQuotaReserveError> {
    let mut backoff_ms = QUOTA_RESERVE_BACKOFF_MIN_MS;
    let mut backoff_rounds = 0usize;
    loop {
        for _ in 0..QUOTA_RESERVE_SPIN_RETRIES {
            match user_stats.quota_try_reserve(bytes, limit) {
                Ok(total) => return Ok(total),
                Err(QuotaReserveError::LimitExceeded) => {
                    return Err(MiddleQuotaReserveError::LimitExceeded);
                }
                Err(QuotaReserveError::Contended) => {
                    stats.increment_quota_contention_total();
                    std::hint::spin_loop();
                }
            }
        }

        tokio::task::yield_now().await;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            stats.increment_quota_contention_timeout_total();
            return Err(MiddleQuotaReserveError::DeadlineExceeded);
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                stats.increment_quota_acquire_cancelled_total();
                return Err(MiddleQuotaReserveError::Cancelled);
            }
            _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
        }
        backoff_rounds = backoff_rounds.saturating_add(1);
        if backoff_rounds >= QUOTA_RESERVE_MAX_BACKOFF_ROUNDS {
            stats.increment_quota_contention_timeout_total();
            return Err(MiddleQuotaReserveError::Contended);
        }
        backoff_ms = backoff_ms
            .saturating_mul(2)
            .min(QUOTA_RESERVE_BACKOFF_MAX_MS);
    }
}

pub(super) async fn wait_for_traffic_budget(
    lease: Option<&Arc<TrafficLease>>,
    direction: RateDirection,
    bytes: u64,
    deadline: Option<Instant>,
) -> Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    let Some(lease) = lease else {
        return Ok(());
    };

    let mut remaining = bytes;
    while remaining > 0 {
        let consume = lease.try_consume(direction, remaining);
        if consume.granted > 0 {
            remaining = remaining.saturating_sub(consume.granted);
            continue;
        }

        let wait_started_at = Instant::now();
        if deadline.is_some_and(|deadline| wait_started_at >= deadline) {
            return Err(ProxyError::TrafficBudgetWaitDeadlineExceeded);
        }
        tokio::time::sleep(next_refill_delay()).await;
        let wait_ms = wait_started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        lease.observe_wait_ms(
            direction,
            consume.blocked_user,
            consume.blocked_cidr,
            wait_ms,
        );
    }

    Ok(())
}

pub(super) async fn wait_for_traffic_budget_or_cancel(
    lease: Option<&Arc<TrafficLease>>,
    direction: RateDirection,
    bytes: u64,
    cancel: &CancellationToken,
    stats: &Stats,
    deadline: Option<Instant>,
) -> Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    let Some(lease) = lease else {
        return Ok(());
    };

    let mut remaining = bytes;
    while remaining > 0 {
        let consume = lease.try_consume(direction, remaining);
        if consume.granted > 0 {
            remaining = remaining.saturating_sub(consume.granted);
            continue;
        }

        let wait_started_at = Instant::now();
        if deadline.is_some_and(|deadline| wait_started_at >= deadline) {
            stats.increment_flow_wait_middle_rate_limit_cancelled_total();
            return Err(ProxyError::TrafficBudgetWaitDeadlineExceeded);
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                stats.increment_flow_wait_middle_rate_limit_cancelled_total();
                return Err(ProxyError::TrafficBudgetWaitCancelled);
            }
            _ = tokio::time::sleep(next_refill_delay()) => {}
        }
        let wait_ms = wait_started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        lease.observe_wait_ms(
            direction,
            consume.blocked_user,
            consume.blocked_cidr,
            wait_ms,
        );
        stats.observe_flow_wait_middle_rate_limit_ms(wait_ms);
    }

    Ok(())
}
