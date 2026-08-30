use super::*;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    let mut backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut inflight: HashMap<(i32, IpFamily), usize> = HashMap::new();
    let mut outage_backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut outage_next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut single_endpoint_outage: HashSet<(i32, IpFamily)> = HashSet::new();
    let mut shadow_rotate_deadline: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut idle_refresh_next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut floor_warn_next_allowed: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut drain_warn_next_allowed: HashMap<u64, Instant> = HashMap::new();
    let mut degraded_interval = true;
    loop {
        let interval = if degraded_interval {
            pool.health_interval_unhealthy()
        } else {
            pool.health_interval_healthy()
        };
        tokio::time::sleep(interval).await;
        pool.prune_closed_writers().await;
        pool.sweep_endpoint_quarantine().await;
        reap_draining_writers(&pool, &mut drain_warn_next_allowed).await;
        let v4_degraded = check_family(
            IpFamily::V4,
            &pool,
            &rng,
            &mut backoff,
            &mut next_attempt,
            &mut inflight,
            &mut outage_backoff,
            &mut outage_next_attempt,
            &mut single_endpoint_outage,
            &mut shadow_rotate_deadline,
            &mut idle_refresh_next_attempt,
            &mut floor_warn_next_allowed,
        )
        .await;
        let v6_degraded = check_family(
            IpFamily::V6,
            &pool,
            &rng,
            &mut backoff,
            &mut next_attempt,
            &mut inflight,
            &mut outage_backoff,
            &mut outage_next_attempt,
            &mut single_endpoint_outage,
            &mut shadow_rotate_deadline,
            &mut idle_refresh_next_attempt,
            &mut floor_warn_next_allowed,
        )
        .await;
        update_family_runtime_state(&pool, IpFamily::V4, v4_degraded);
        update_family_runtime_state(&pool, IpFamily::V6, v6_degraded);
        degraded_interval = v4_degraded || v6_degraded;
    }
}
