use super::*;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_period_metadata_commit_preserves_traffic_and_finishes_after_waiter_abort() {
    let (_dir, store, owner) = fixture();
    let cfg = config(Some(UserQuotaPeriod::Daily));
    request(&store, &cfg, START);
    store.current_handle("alice").unwrap().charge(100);
    let (hook, started) = test_io::Hook::install(owner.path(), true);
    let operation_owner = owner.clone();
    let waiter = tokio::spawn(async move { operation_owner.process_schedules(START, false).await });
    started.await.unwrap();
    assert!(owner.mutation.try_lock().is_err());
    store.current_handle("alice").unwrap().charge(77);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(owner.mutation.try_lock().is_err());
    hook.release();
    let _guard = tokio::time::timeout(std::time::Duration::from_secs(2), owner.lock())
        .await
        .unwrap();
    assert_eq!(store.used("alice"), 177);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), START)
            .quota_schedule_state,
        "active"
    );
    assert_eq!(hook.writes.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_period_durable_reset_fences_recreation_until_commit() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START);
    owner.process_schedules(START, false).await.unwrap();
    let old = store.current_handle("alice").unwrap();
    old.charge(900);
    let (hook, started) = test_io::Hook::install(owner.path(), true);
    let reset_owner = owner.clone();
    let reset =
        tokio::spawn(async move { reset_owner.process_schedules(START + DAY, false).await });
    started.await.unwrap();
    let mutate_store = store.clone();
    let mutation = tokio::spawn(async move {
        let _guard = mutate_store.mutation_gate().lock_owned().await;
        mutate_store.retire_through("alice", 2);
        mutate_store.activate_fresh("alice", 3);
        mutate_store.current_handle("alice").unwrap().charge(400);
    });
    tokio::task::yield_now().await;
    assert!(!mutation.is_finished());
    assert_eq!(old.used(), 900);
    hook.release();
    reset.await.unwrap().unwrap();
    mutation.await.unwrap();
    assert_eq!(old.used(), 0);
    assert_eq!(store.used("alice"), 400);
    assert_eq!(
        store.current_handle("alice").unwrap().schedule_checkpoint(),
        QuotaScheduleCheckpoint::default()
    );
    owner.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(store.used("alice"), 400);
    let persisted = read_state_file(owner.path()).await.unwrap().unwrap();
    assert_eq!(persisted.users["alice"].used_bytes, 400);
    assert_eq!(
        persisted.users["alice"].schedule,
        QuotaScheduleCheckpoint::default()
    );
}

#[tokio::test]
async fn quota_period_restart_after_ambiguous_commit_never_replays_completed_boundary() {
    let (dir, store, owner) = fixture();
    let cfg = config(Some(UserQuotaPeriod::Daily));
    request(&store, &cfg, START);
    owner.process_schedules(START, false).await.unwrap();
    store.current_handle("alice").unwrap().charge(900);
    let (hook, _) = test_io::Hook::install(owner.path(), false);
    hook.fail_after.store(true, Ordering::Relaxed);
    assert!(owner.process_schedules(START + DAY, false).await.is_err());
    assert_eq!(store.used("alice"), 900);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), START + DAY)
            .quota_schedule_state,
        "error"
    );
    drop(hook);
    let restarted = Arc::new(QuotaStore::default());
    let restart = QuotaStateOwner::new(dir.path().join("quota.json"), restarted.clone());
    restart.load_for_config(&cfg).await.unwrap();
    restarted.activate_fresh("alice", 1);
    request(&restarted, &cfg, START + DAY);
    restarted.current_handle("alice").unwrap().charge(77);
    restart.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(restarted.used("alice"), 77);
}

#[tokio::test]
async fn quota_period_unchanged_reload_is_io_free_and_pending_reversal_is_not_a_reset() {
    let (_dir, store, owner) = fixture();
    let cfg = config(Some(UserQuotaPeriod::Daily));
    request(&store, &cfg, START);
    owner.process_schedules(START, false).await.unwrap();
    let (hook, _) = test_io::Hook::install(owner.path(), false);
    for _ in 0..1000 {
        request(&store, &cfg, START + 500);
        owner.process_schedules(START + 500, false).await.unwrap();
    }
    request(&store, &config(Some(UserQuotaPeriod::Weekly)), START + 500);
    request(&store, &cfg, START + 500);
    owner.process_schedules(START + 500, false).await.unwrap();
    assert_eq!(hook.writes.load(Ordering::Relaxed), 0);
    assert_eq!(store.schedule_deadline(), Some(START + DAY));
}

#[tokio::test]
async fn quota_period_manual_recovery_clears_error_without_postponing_calendar() {
    let (_dir, store, owner) = fixture();
    let now = now_epoch_secs();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), now - 3 * DAY);
    owner.process_schedules(now - 3 * DAY, false).await.unwrap();
    let (hook, _) = test_io::Hook::install(owner.path(), false);
    hook.fail_after.store(true, Ordering::Relaxed);
    assert!(owner.process_schedules(now, false).await.is_err());
    hook.fail_after.store(false, Ordering::Relaxed);
    owner
        .reset_user(&BTreeSet::from(["alice".into()]), "alice")
        .await
        .unwrap();
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), now)
            .quota_schedule_state,
        "active"
    );
    assert!(!store.schedule_ready(now));
}

#[tokio::test]
async fn quota_period_stale_candidate_cannot_attach_retired_policy_to_fresh_account() {
    let (_dir, store, owner) = fixture();
    let old = config(Some(UserQuotaPeriod::Daily));
    let stale_candidate = Arc::new((*old).clone());
    let credential = credential_id_from_hex(SECRET).unwrap();
    store.fence_fresh_schedule(
        "alice",
        &old,
        credential,
        Some(UserQuotaPeriod::Monthly),
        Some(1024),
    );
    store.request_schedule("alice", 1, credential, &stale_candidate, START, false);
    assert_eq!(store.schedule_deadline(), None);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly), START)
            .quota_schedule_state,
        "pending"
    );
    request(&store, &config(Some(UserQuotaPeriod::Monthly)), START);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
}

#[tokio::test]
async fn quota_period_worker_drops_obsolete_retry_and_shuts_down_cooperatively() {
    let (_dir, store, owner) = fixture();
    let now = now_epoch_secs();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), now - 3 * DAY);
    owner.process_schedules(now - 3 * DAY, false).await.unwrap();
    let (hook, started) = test_io::Hook::install(owner.path(), false);
    hook.fail_after.store(true, Ordering::Relaxed);
    let control = crate::maestro::control_plane::ProcessControlPlane::new();
    owner.spawn_scheduler(&control);
    started.await.unwrap();
    let guard = owner.lock().await;
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), now)
            .quota_schedule_state,
        "error"
    );
    hook.fail_after.store(false, Ordering::Relaxed);
    owner
        .reset_user_locked(&BTreeSet::from(["alice".into()]), "alice", now, guard)
        .await
        .unwrap();
    tokio::time::pause();
    let before = owner.scheduler_iterations.load(Ordering::Relaxed);
    tokio::time::advance(std::time::Duration::from_secs(65)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    let iterations = owner.scheduler_iterations.load(Ordering::Relaxed) - before;
    assert!(iterations < 20, "idle scheduler spun {iterations} times");
    assert!(!store.schedule_ready(now));
    assert!(control.shutdown(std::time::Duration::from_secs(2)).await);
    tokio::time::resume();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_period_manual_commit_crossing_midnight_handles_new_boundary_once() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START);
    owner.process_schedules(START, false).await.unwrap();
    let (hook, started) = test_io::Hook::install(owner.path(), true);
    let manual_owner = owner.clone();
    let manual = tokio::spawn(async move {
        let guard = manual_owner.lock().await;
        manual_owner
            .reset_user_locked(
                &BTreeSet::from(["alice".into()]),
                "alice",
                START + DAY - 1,
                guard,
            )
            .await
    });
    started.await.unwrap();
    hook.release();
    manual.await.unwrap().unwrap();
    store.current_handle("alice").unwrap().charge(13);
    owner.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(store.used("alice"), 0);
    store.current_handle("alice").unwrap().charge(19);
    owner.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(store.used("alice"), 19);
}
