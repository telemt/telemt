use super::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn quota_period_retained_cursor_survives_legacy_inventory_growth() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START);
    owner.process_schedules(START, false).await.unwrap();
    let mut users = (0..QUOTA_STATE_MAX_USERS)
        .map(|i| format!("a{i:05}"))
        .collect::<BTreeSet<_>>();
    for user in &users {
        store.current_or_legacy_handle(user).charge(1);
    }
    users.insert("alice".into());
    request(&store, &config(None), START + 1);
    owner.process_schedules(START + 1, false).await.unwrap();
    owner.save(&users).await.unwrap();
    let state = read_state_file(owner.path()).await.unwrap().unwrap();
    assert_eq!(state.users.len(), QUOTA_STATE_MAX_USERS);
    assert_eq!(state.users["alice"].schedule.quota_period, None);
    assert_eq!(
        state.users["alice"].schedule.period_cursor_epoch_secs,
        START + 1
    );
    assert!(!state.users.contains_key("a65535"));
}

#[tokio::test]
async fn quota_period_oversized_checkpoint_cannot_publish_reset() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START);
    owner.process_schedules(START, false).await.unwrap();
    let before = std::fs::read(owner.path()).unwrap();
    let huge_name = "x".repeat(QUOTA_STATE_MAX_BYTES as usize);
    store.current_or_legacy_handle(&huge_name).charge(1);
    store.current_handle("alice").unwrap().charge(77);
    assert!(owner.process_schedules(START + DAY, false).await.is_err());
    assert_eq!(store.used("alice"), 77);
    assert_eq!(std::fs::read(owner.path()).unwrap(), before);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), START + DAY)
            .quota_schedule_state,
        "error"
    );
}

#[tokio::test]
async fn quota_period_many_due_users_share_one_durable_batch() {
    let (_dir, store, owner) = fixture();
    let mut cfg = (*config(Some(UserQuotaPeriod::Daily))).clone();
    for i in 0..128 {
        let user = format!("user{i}");
        store.activate_fresh(&user, 1);
        store.current_handle(&user).unwrap().charge(123);
        cfg.access.users.insert(user.clone(), SECRET.into());
        cfg.access.user_data_quota.insert(user.clone(), 1024);
        cfg.access
            .user_quota_periods
            .insert(user, UserQuotaPeriod::Daily);
    }
    let cfg = Arc::new(cfg);
    for user in cfg.access.users.keys() {
        store.request_schedule(
            user,
            1,
            credential_id_from_hex(SECRET).unwrap(),
            &cfg,
            START,
            true,
        );
    }
    let (hook, _) = super::super::test_io::Hook::install(owner.path(), false);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(hook.writes.load(Ordering::Relaxed), 1);
    owner.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(hook.writes.load(Ordering::Relaxed), 2);
    for user in cfg.access.users.keys() {
        assert_eq!(store.used(user), 0);
    }
    assert_eq!(store.schedule_deadline(), Some(START + 2 * DAY));
}

#[test]
fn quota_period_daily_model_preserves_monotonic_cursor_under_clock_pressure() {
    let (_dir, store, _owner) = fixture();
    let cfg = config(Some(UserQuotaPeriod::Daily));
    request(&store, &cfg, START + 123);
    for change in store.schedule_changes(START + 123).unwrap() {
        store.publish_schedule(&change, START + 123);
    }
    let mut cursor = START + 123;
    let mut used = 0;
    let mut seed = 19u64;
    for step in 0..10_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let now = START + (seed % 90) * DAY + seed % DAY;
        let amount = seed % 100;
        store.current_handle("alice").unwrap().charge(amount);
        used += amount;
        let boundary = now / DAY * DAY;
        if boundary > cursor {
            cursor = boundary;
            used = 0;
        }
        for change in store.schedule_changes(now).unwrap() {
            store.publish_schedule(&change, now);
        }
        if step % 100 == 0 {
            store.advance_preserving_usage("alice", step + 2);
        }
        assert_eq!(store.used("alice"), used);
        assert_eq!(
            store
                .current_handle("alice")
                .unwrap()
                .schedule_checkpoint()
                .period_cursor_epoch_secs,
            cursor
        );
        assert_eq!(store.schedule_deadline(), Some((cursor / DAY + 1) * DAY));
    }
}

#[tokio::test]
async fn quota_period_invalid_clock_reports_error_without_publishing_metadata() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), u64::MAX);
    store.current_handle("alice").unwrap().charge(5);
    assert!(owner.process_schedules(u64::MAX, false).await.is_err());
    assert_eq!(store.used("alice"), 5);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), u64::MAX)
            .quota_schedule_state,
        "error"
    );
    assert!(!owner.path().exists());
}
