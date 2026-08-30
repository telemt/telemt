use super::*;

#[tokio::test]
async fn reap_draining_writers_deterministic_mixed_state_churn_preserves_invariants() {
    let threshold = 9u64;
    let (pool, _rng) = make_pool(threshold, 1, 1).await;
    let mut warn_next_allowed = HashMap::new();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next_writer_id = 20_000u64;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=72u64 {
        let bound_clients = if writer_id % 4 == 0 { 0 } else { 1 };
        let deadline = if writer_id % 5 == 0 {
            now_epoch_secs.saturating_sub(1)
        } else {
            0
        };
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(500).saturating_add(writer_id),
            bound_clients,
            deadline,
        )
        .await;
    }

    for _round in 0..90 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;

        let draining_ids = draining_writer_ids(&pool).await;
        assert!(
            warn_next_allowed.keys().all(|id| draining_ids.contains(id)),
            "warn-state keys must always be a subset of live draining writers"
        );

        let writer_ids = sorted_writer_ids(&pool).await;
        if writer_ids.is_empty() {
            continue;
        }

        let remove_n = (lcg_next(&mut seed) % 3) as usize;
        for writer_id in writer_ids.iter().copied().take(remove_n) {
            let _ = pool.remove_writer_and_close_clients(writer_id).await;
        }

        let survivors = sorted_writer_ids(&pool).await;
        if !survivors.is_empty() {
            let idx = (lcg_next(&mut seed) as usize) % survivors.len();
            let target = survivors[idx];
            set_writer_runtime_state(&pool, target, false, 0, 0).await;
        }

        let survivors = sorted_writer_ids(&pool).await;
        if survivors.len() > 1 {
            let idx = (lcg_next(&mut seed) as usize) % survivors.len();
            let target = survivors[idx];
            let expired_deadline = if lcg_next(&mut seed) & 1 == 0 {
                now_epoch_secs.saturating_sub(1)
            } else {
                0
            };
            set_writer_runtime_state(
                &pool,
                target,
                true,
                now_epoch_secs.saturating_sub(120),
                expired_deadline,
            )
            .await;
        }

        let inject_n = (lcg_next(&mut seed) % 4) as usize;
        for _ in 0..inject_n {
            let bound_clients = if lcg_next(&mut seed) & 1 == 0 { 0 } else { 1 };
            let deadline = if lcg_next(&mut seed) & 1 == 0 {
                now_epoch_secs.saturating_sub(1)
            } else {
                0
            };
            insert_draining_writer(
                &pool,
                next_writer_id,
                now_epoch_secs.saturating_sub(240),
                bound_clients,
                deadline,
            )
            .await;
            next_writer_id = next_writer_id.saturating_add(1);
        }
    }

    for _ in 0..64 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if writer_count(&pool).await <= threshold as usize {
            break;
        }
    }

    assert!(writer_count(&pool).await <= threshold as usize);
    let draining_ids = draining_writer_ids(&pool).await;
    assert!(warn_next_allowed.keys().all(|id| draining_ids.contains(id)));
}

#[tokio::test]
async fn reap_draining_writers_repeated_draining_flips_never_leave_stale_warn_state() {
    let (pool, _rng) = make_pool(64, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=24u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(240), 1, 0).await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _round in 0..48u64 {
        for writer_id in 1..=24u64 {
            let draining = (writer_id + _round) % 3 != 0;
            set_writer_runtime_state(
                &pool,
                writer_id,
                draining,
                now_epoch_secs.saturating_sub(120),
                0,
            )
            .await;
        }

        reap_draining_writers(&pool, &mut warn_next_allowed).await;

        let draining_ids = draining_writer_ids(&pool).await;
        assert!(
            warn_next_allowed.keys().all(|id| draining_ids.contains(id)),
            "warn-state map must not retain entries for writers outside draining set"
        );
    }
}

#[test]
fn health_drain_close_budget_is_within_expected_bounds() {
    let budget = health_drain_close_budget();
    assert!((16..=256).contains(&budget));
}
