use super::*;

#[tokio::test]
async fn reap_draining_writers_threshold_zero_preserves_non_expired_non_empty_writers() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(40), 1, 0).await;
    insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(30), 1, 0).await;
    insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(20), 1, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![10, 20, 30]);
}

#[tokio::test]
async fn reap_draining_writers_prioritizes_force_close_before_empty_cleanup() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    for writer_id in 1..=close_budget.saturating_add(1) as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }
    let empty_writer_id = close_budget.saturating_add(2) as u64;
    insert_draining_writer(
        &pool,
        empty_writer_id,
        now_epoch_secs.saturating_sub(20),
        0,
        0,
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![1, empty_writer_id]);
}

#[tokio::test]
async fn reap_draining_writers_empty_cleanup_does_not_increment_force_close_metric() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 1, now_epoch_secs.saturating_sub(60), 0, 0).await;
    insert_draining_writer(&pool, 2, now_epoch_secs.saturating_sub(50), 0, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(current_writer_ids(&pool).await.is_empty());
    assert_eq!(pool.stats.get_pool_force_close_total(), 0);
}

#[tokio::test]
async fn reap_draining_writers_handles_duplicate_force_close_requests_for_same_writer() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(
        &pool,
        10,
        now_epoch_secs.saturating_sub(30),
        1,
        now_epoch_secs.saturating_sub(1),
    )
    .await;
    insert_draining_writer(
        &pool,
        20,
        now_epoch_secs.saturating_sub(20),
        1,
        now_epoch_secs.saturating_sub(1),
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(current_writer_ids(&pool).await.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_warn_state_never_exceeds_live_draining_population_under_churn() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut warn_next_allowed = HashMap::new();

    for wave in 0..12u64 {
        for offset in 0..9u64 {
            insert_draining_writer(
                &pool,
                wave * 100 + offset,
                now_epoch_secs.saturating_sub(120 + offset),
                1,
                0,
            )
            .await;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= pool.writers.read().await.len());

        let existing_writer_ids = current_writer_ids(&pool).await;
        for writer_id in existing_writer_ids.into_iter().take(4) {
            let _ = pool.remove_writer_and_close_clients(writer_id).await;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= pool.writers.read().await.len());
    }
}

#[tokio::test]
async fn reap_draining_writers_mixed_backlog_converges_without_leaking_warn_state() {
    let pool = make_pool(6).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut warn_next_allowed = HashMap::new();

    for writer_id in 1..=18u64 {
        let bound_clients = if writer_id % 3 == 0 { 0 } else { 1 };
        let deadline = if writer_id % 2 == 0 {
            now_epoch_secs.saturating_sub(1)
        } else {
            0
        };
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(300).saturating_add(writer_id),
            bound_clients,
            deadline,
        )
        .await;
    }

    for _ in 0..16 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if pool.writers.read().await.len() <= 6 {
            break;
        }
    }

    assert!(pool.writers.read().await.len() <= 6);
    assert!(warn_next_allowed.len() <= pool.writers.read().await.len());
}

#[test]
fn general_config_default_drain_threshold_remains_enabled() {
    assert_eq!(GeneralConfig::default().me_pool_drain_threshold, 32);
    assert!(GeneralConfig::default().me_pool_drain_soft_evict_enabled);
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_grace_secs,
        10
    );
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_per_writer,
        2
    );
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_budget_per_core,
        16
    );
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_cooldown_ms,
        1000
    );
    assert_eq!(
        GeneralConfig::default().me_bind_stale_mode,
        MeBindStaleMode::Never
    );
}

#[tokio::test]
async fn prune_closed_writers_closes_bound_clients_when_writer_is_non_empty() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_ids =
        insert_draining_writer(&pool, 910, now_epoch_secs.saturating_sub(60), 1, 0).await;

    pool.prune_closed_writers().await;

    assert!(!writer_exists(&pool, 910).await);
    assert!(pool.registry.get_writer(conn_ids[0]).await.is_none());
}
