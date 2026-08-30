use super::*;

#[tokio::test]
async fn reap_draining_writers_clears_warn_state_when_pool_empty() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(11, Instant::now() + Duration::from_secs(5));
    warn_next_allowed.insert(22, Instant::now() + Duration::from_secs(5));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(warn_next_allowed.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_respects_threshold_across_multiple_overflow_cycles() {
    let threshold = 3u64;
    let (pool, _rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=60u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _ in 0..64 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if writer_count(&pool).await <= threshold as usize {
            break;
        }
    }

    assert_eq!(writer_count(&pool).await, threshold as usize);
    assert_eq!(sorted_writer_ids(&pool).await, vec![1, 2, 3]);
}

#[tokio::test]
async fn reap_draining_writers_handles_large_empty_writer_population() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let total = health_drain_close_budget()
        .saturating_mul(3)
        .saturating_add(27);

    for writer_id in 1..=total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(120), 0, 0).await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _ in 0..24 {
        if writer_count(&pool).await == 0 {
            break;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
    }

    assert_eq!(writer_count(&pool).await, 0);
}

#[tokio::test]
async fn reap_draining_writers_processes_mass_deadline_expiry_without_unbounded_growth() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let total = health_drain_close_budget()
        .saturating_mul(4)
        .saturating_add(31);

    for writer_id in 1..=total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(180),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _ in 0..40 {
        if writer_count(&pool).await == 0 {
            break;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
    }

    assert_eq!(writer_count(&pool).await, 0);
}

#[tokio::test]
async fn reap_draining_writers_maintains_warn_state_subset_property_under_bulk_churn() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut warn_next_allowed = HashMap::new();

    for wave in 0..40u64 {
        for offset in 0..8u64 {
            insert_draining_writer(
                &pool,
                wave * 100 + offset,
                now_epoch_secs.saturating_sub(400 + offset),
                1,
                0,
            )
            .await;
        }

        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= writer_count(&pool).await);

        let ids = sorted_writer_ids(&pool).await;
        for writer_id in ids.into_iter().take(3) {
            let _ = pool.remove_writer_and_close_clients(writer_id).await;
        }

        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= writer_count(&pool).await);
    }
}

#[tokio::test]
async fn reap_draining_writers_budgeted_cleanup_never_increases_pool_size() {
    let (pool, _rng) = make_pool(5, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=200u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(240).saturating_add(writer_id),
            1,
            0,
        )
        .await;
    }

    let mut warn_next_allowed = HashMap::new();
    let mut previous = writer_count(&pool).await;
    for _ in 0..32 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        let current = writer_count(&pool).await;
        assert!(current <= previous);
        previous = current;
    }
}

#[tokio::test]
async fn me_health_monitor_converges_to_threshold_under_live_injection_churn() {
    let threshold = 7u64;
    let (pool, rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=40u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(300).saturating_add(writer_id),
            1,
            0,
        )
        .await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));

    for wave in 0..8u64 {
        for offset in 0..10u64 {
            insert_draining_writer(
                &pool,
                1000 + wave * 100 + offset,
                now_epoch_secs.saturating_sub(120).saturating_add(offset),
                1,
                0,
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(writer_count(&pool).await <= threshold as usize);
}

#[tokio::test]
async fn me_health_monitor_drains_deadline_storm_with_budgeted_progress() {
    let (pool, rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=220u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(120),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));
    tokio::time::sleep(Duration::from_millis(120)).await;
    monitor.abort();
    let _ = monitor.await;

    assert_eq!(writer_count(&pool).await, 0);
}

#[tokio::test]
async fn me_health_monitor_eliminates_mixed_empty_and_deadline_backlog() {
    let threshold = 12u64;
    let (pool, rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=180u64 {
        let bound_clients = if writer_id % 3 == 0 { 0 } else { 1 };
        let deadline = if writer_id % 2 == 0 {
            now_epoch_secs.saturating_sub(1)
        } else {
            0
        };
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(250).saturating_add(writer_id),
            bound_clients,
            deadline,
        )
        .await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));
    tokio::time::sleep(Duration::from_millis(140)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(writer_count(&pool).await <= threshold as usize);
}
