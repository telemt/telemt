use super::*;

#[tokio::test]
async fn reap_draining_writers_drops_warn_state_for_removed_writer() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_ids = insert_draining_writer(
        &pool,
        7,
        now_epoch_secs.saturating_sub(180),
        1,
        now_epoch_secs.saturating_add(3_600),
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(warn_next_allowed.contains_key(&7));

    let _ = pool.remove_writer_and_close_clients(7).await;
    assert!(pool.registry.get_writer(conn_ids[0]).await.is_none());

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(!warn_next_allowed.contains_key(&7));
}

#[tokio::test]
async fn reap_draining_writers_removes_empty_draining_writers() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 1, now_epoch_secs.saturating_sub(40), 0, 0).await;
    insert_draining_writer(&pool, 2, now_epoch_secs.saturating_sub(30), 0, 0).await;
    insert_draining_writer(&pool, 3, now_epoch_secs.saturating_sub(20), 1, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![3]);
}

#[tokio::test]
async fn reap_draining_writers_overflow_closes_oldest_non_empty_writers() {
    let pool = make_pool(2).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 11, now_epoch_secs.saturating_sub(40), 1, 0).await;
    insert_draining_writer(&pool, 22, now_epoch_secs.saturating_sub(30), 1, 0).await;
    insert_draining_writer(&pool, 33, now_epoch_secs.saturating_sub(20), 1, 0).await;
    insert_draining_writer(&pool, 44, now_epoch_secs.saturating_sub(10), 1, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![33, 44]);
}

#[tokio::test]
async fn reap_draining_writers_deadline_force_close_applies_under_threshold() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(
        &pool,
        50,
        now_epoch_secs.saturating_sub(15),
        1,
        now_epoch_secs.saturating_sub(1),
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(current_writer_ids(&pool).await.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_limits_closes_per_health_tick() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_add(20);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(pool.writers.read().await.len(), writer_total - close_budget);
}

#[tokio::test]
async fn reap_draining_writers_keeps_warn_state_for_deadline_backlog_writers() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_add(5);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(60),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }
    let target_writer_id = writer_total as u64;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(target_writer_id, Instant::now() + Duration::from_secs(300));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(writer_exists(&pool, target_writer_id).await);
    assert!(warn_next_allowed.contains_key(&target_writer_id));
}

#[tokio::test]
async fn reap_draining_writers_keeps_warn_state_for_overflow_backlog_writers() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_add(6);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(300).saturating_add(writer_id),
            1,
            0,
        )
        .await;
    }
    let target_writer_id = writer_total.saturating_sub(1) as u64;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(target_writer_id, Instant::now() + Duration::from_secs(300));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(writer_exists(&pool, target_writer_id).await);
    assert!(warn_next_allowed.contains_key(&target_writer_id));
}

#[tokio::test]
async fn reap_draining_writers_drops_warn_state_when_writer_exits_draining_state() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 71, now_epoch_secs.saturating_sub(60), 1, 0).await;

    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(71, Instant::now() + Duration::from_secs(300));

    set_writer_draining(&pool, 71, false).await;
    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(writer_exists(&pool, 71).await);
    assert!(
        !warn_next_allowed.contains_key(&71),
        "warn cooldown state must be dropped after writer leaves draining state"
    );
}

#[tokio::test]
async fn reap_draining_writers_preserves_warn_state_across_multiple_budget_deferrals() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_mul(2).saturating_add(1);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(120),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }

    let tail_writer_id = writer_total as u64;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(tail_writer_id, Instant::now() + Duration::from_secs(300));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(writer_exists(&pool, tail_writer_id).await);
    assert!(warn_next_allowed.contains_key(&tail_writer_id));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(writer_exists(&pool, tail_writer_id).await);
    assert!(warn_next_allowed.contains_key(&tail_writer_id));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(!writer_exists(&pool, tail_writer_id).await);
    assert!(
        !warn_next_allowed.contains_key(&tail_writer_id),
        "warn cooldown state must clear once writer is actually removed"
    );
}

#[tokio::test]
async fn reap_draining_writers_backlog_drains_across_ticks() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_mul(2).saturating_add(7);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 0, 0).await;
    }
    let mut warn_next_allowed = HashMap::new();

    for _ in 0..8 {
        if pool.writers.read().await.is_empty() {
            break;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
    }

    assert!(pool.writers.read().await.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_threshold_backlog_converges_to_threshold() {
    let threshold = 5u64;
    let pool = make_pool(threshold).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = threshold as usize + close_budget.saturating_add(12);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }
    let mut warn_next_allowed = HashMap::new();

    for _ in 0..16 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if pool.writers.read().await.len() <= threshold as usize {
            break;
        }
    }

    assert_eq!(pool.writers.read().await.len(), threshold as usize);
}
