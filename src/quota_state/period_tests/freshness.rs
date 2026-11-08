use super::*;
use std::time::{Duration, Instant};

fn source(period: Option<UserQuotaPeriod>, at: Instant) -> Arc<ProxyConfig> {
    let mut cfg = (*config(period)).clone();
    cfg.quota_source_read_at = Some(at);
    Arc::new(cfg)
}

#[tokio::test]
async fn quota_period_b11_unchanged_api_intent_fences_prepared_conflicting_source() {
    let (_dir, store, owner) = fixture();
    let monthly = source(Some(UserQuotaPeriod::Monthly), Instant::now());
    request(&store, &monthly, START);
    owner.process_schedules(START, false).await.unwrap();
    let delayed = source(Some(UserQuotaPeriod::Daily), Instant::now());
    let gate = owner.lock().await;
    store.refresh_fresh_schedule("alice", &monthly);
    assert!(!store.has_fresh_schedules());
    request(&store, &delayed, START);
    drop(gate);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly), START)
            .quota_schedule_state,
        "active"
    );
}

#[tokio::test]
async fn quota_period_b11_stale_publication_preserves_monthly_boundary() {
    for accepted in [false, true] {
        let (_dir, store, owner) = fixture();
        let at = Instant::now();
        let daily = source(Some(UserQuotaPeriod::Daily), at);
        let monthly = source(Some(UserQuotaPeriod::Monthly), at + Duration::from_secs(1));
        let now = START + 19 * DAY + 86340;
        request(&store, &daily, now);
        owner.process_schedules(now, false).await.unwrap();
        request(&store, &monthly, now);
        owner.process_schedules(now, false).await.unwrap();
        let account = store.current_handle("alice").unwrap();
        account.charge(700);
        let checkpoint = account.schedule_checkpoint();
        store.request_schedule(
            "alice",
            1,
            credential_id_from_hex(SECRET).unwrap(),
            &daily,
            now,
            accepted,
        );
        owner.process_schedules(now, false).await.unwrap();
        assert_eq!(
            account.schedule_checkpoint(),
            checkpoint,
            "accepted={accepted}"
        );
        assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
        owner
            .process_schedules(START + 20 * DAY, false)
            .await
            .unwrap();
        assert_eq!(store.used("alice"), 700);
        assert_eq!(
            store
                .schedule_status("alice", Some(UserQuotaPeriod::Monthly), now)
                .quota_schedule_state,
            "active"
        );
        // Missing evidence cannot bypass an established source watermark either.
        request(&store, &config(Some(UserQuotaPeriod::Daily)), now);
        owner.process_schedules(now, false).await.unwrap();
        assert_eq!(account.schedule_checkpoint(), checkpoint);
        owner
            .process_schedules(START + 31 * DAY, false)
            .await
            .unwrap();
        assert_eq!(store.used("alice"), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_period_b11_concurrent_publication_preserves_latest_source() {
    let (_dir, store, owner) = fixture();
    let at = Instant::now();
    request(&store, &source(Some(UserQuotaPeriod::Monthly), at), START);
    owner.process_schedules(START, false).await.unwrap();
    store.current_handle("alice").unwrap().charge(700);
    let start = Arc::new(tokio::sync::Barrier::new(4));
    let mut tasks = Vec::new();
    for worker in 0..4 {
        let store = store.clone();
        let start = start.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            for index in (0..128).rev() {
                let sequence = index * 4 + worker + 1;
                let period = if sequence % 2 == 0 {
                    UserQuotaPeriod::Monthly
                } else {
                    UserQuotaPeriod::Daily
                };
                let cfg = source(Some(period), at + Duration::from_secs(sequence));
                let gate = store.mutation_gate().lock_owned().await;
                request(&store, &cfg, START);
                drop(gate);
                tokio::task::yield_now().await;
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
    assert_eq!(store.used("alice"), 700);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly), START)
            .quota_schedule_state,
        "active"
    );
}

#[tokio::test]
async fn quota_period_b11_unchanged_policy_advances_source_watermark() {
    let (_dir, store, owner) = fixture();
    let at = Instant::now();
    let daily = source(Some(UserQuotaPeriod::Daily), at);
    let delayed = source(Some(UserQuotaPeriod::Monthly), at + Duration::from_secs(1));
    let confirmed = source(Some(UserQuotaPeriod::Daily), at + Duration::from_secs(2));
    request(&store, &daily, START);
    owner.process_schedules(START, false).await.unwrap();
    request(&store, &confirmed, START);
    request(&store, &delayed, START);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + DAY));
    let removed = source(None, at + Duration::from_secs(3));
    request(&store, &removed, START);
    owner.process_schedules(START, false).await.unwrap();
    request(&store, &confirmed, START);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), None);
    assert_eq!(
        store
            .schedule_status("alice", None, START)
            .quota_schedule_state,
        "disabled"
    );
    // A genuinely newer edit may intentionally restore the previous policy.
    request(
        &store,
        &source(Some(UserQuotaPeriod::Daily), at + Duration::from_secs(4)),
        START,
    );
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + DAY));
    // Account recreation must not inherit the retired account's source watermark.
    store.retire_through("alice", 2);
    store.activate_fresh("alice", 3);
    request(&store, &delayed, START);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
}

#[tokio::test]
async fn quota_period_b11_api_fence_survives_matching_attachment_and_failed_write() {
    let (_dir, store, owner) = fixture();
    let daily = source(Some(UserQuotaPeriod::Daily), Instant::now());
    let monthly = source(Some(UserQuotaPeriod::Monthly), Instant::now());
    request(&store, &daily, START);
    owner.process_schedules(START, false).await.unwrap();
    store.current_handle("alice").unwrap().charge(700);
    let gate = owner.lock().await;
    store.refresh_fresh_schedule("alice", &monthly);
    assert!(store.has_fresh_schedules());
    store.request_schedule(
        "alice",
        1,
        credential_id_from_hex(SECRET).unwrap(),
        &monthly,
        START,
        false,
    );
    drop(gate);
    let (hook, _) = test_io::Hook::install(owner.path(), false);
    hook.fail_after
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(owner.process_schedules(START, false).await.is_err());
    request(&store, &daily, START);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly), START)
            .quota_schedule_state,
        "error"
    );
    hook.fail_after
        .store(false, std::sync::atomic::Ordering::Relaxed);
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
    assert_eq!(store.used("alice"), 700);
    let gate = owner.lock().await;
    owner
        .reset_user_locked(
            &BTreeSet::from(["alice".into()]),
            "alice",
            START + DAY,
            gate,
        )
        .await
        .unwrap();
    store.current_handle("alice").unwrap().charge(23);
    request(&store, &daily, START + DAY);
    owner
        .process_schedules(START + 2 * DAY, false)
        .await
        .unwrap();
    assert_eq!(store.used("alice"), 23);
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
}

#[tokio::test]
async fn quota_period_b11_rejected_source_gets_fresh_evidence_from_unchanged_watcher() {
    let (dir, store, owner) = fixture();
    let path = dir.path().join("config.toml");
    let text = |period: &str| {
        format!(
            "[access.users]\nalice = '{SECRET}'\n[access.user_data_quota]\nalice = 1024\n[access.user_quota_periods]\nalice = '{period}'\n"
        )
    };
    std::fs::write(&path, text("daily")).unwrap();
    let daily = Arc::new(ProxyConfig::load(&path).unwrap());
    std::fs::write(&path, text("monthly")).unwrap();
    let monthly = Arc::new(ProxyConfig::load(&path).unwrap());
    request(&store, &monthly, START);
    owner.process_schedules(START, false).await.unwrap();
    request(&store, &daily, START);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly), START)
            .quota_schedule_state,
        "active"
    );
    assert!(store.has_fresh_schedules());
    // The new runtime already has these bytes; only its read evidence is stale.
    std::fs::write(&path, text("daily")).unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let refresh_store = store.clone();
    let (mut rx, _, task) = crate::config::hot_reload::spawn_config_watcher(
        path,
        daily.clone(),
        None,
        None,
        cancel.clone(),
        None,
        None,
        Some(store.mutation_gate()),
        Some(Arc::new(move || refresh_store.has_fresh_schedules())),
    );
    let task = tokio::spawn(task);
    tokio::time::timeout(Duration::from_secs(5), rx.changed())
        .await
        .unwrap()
        .unwrap();
    let refreshed = rx.borrow_and_update().clone();
    assert!(refreshed.quota_source_read_at > monthly.quota_source_read_at);
    let gate = owner.lock().await;
    request(&store, &refreshed, START);
    drop(gate);
    owner.process_schedules(START, false).await.unwrap();
    assert!(!store.has_fresh_schedules());
    assert_eq!(store.schedule_deadline(), Some(START + DAY));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
