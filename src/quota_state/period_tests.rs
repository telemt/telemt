use super::*;
use crate::config::{ProxyConfig, UserQuotaPeriod};
use crate::proxy::user_admission::{UserAdmissionAuthority, credential_id_from_hex};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const DAY: u64 = 86400;
const START: u64 = 1_735_689_600;

fn config(period: Option<UserQuotaPeriod>) -> Arc<ProxyConfig> {
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config.access.users.insert("alice".into(), SECRET.into());
    config.access.user_data_quota.insert("alice".into(), 1024);
    if let Some(period) = period {
        config
            .access
            .user_quota_periods
            .insert("alice".into(), period);
    }
    Arc::new(config)
}

fn request(store: &QuotaStore, config: &Arc<ProxyConfig>, now: u64) {
    let target = store.current_handle("alice").unwrap();
    store.request_schedule(
        "alice",
        target.incarnation(),
        credential_id_from_hex(&config.access.users["alice"]).unwrap(),
        config,
        now,
        true,
    );
}

fn fixture() -> (tempfile::TempDir, Arc<QuotaStore>, Arc<QuotaStateOwner>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(QuotaStore::default());
    store.activate_fresh("alice", 1);
    let owner = QuotaStateOwner::new(dir.path().join("quota.json"), store.clone());
    (dir, store, owner)
}

#[tokio::test]
async fn quota_period_activation_preserves_usage_and_boundaries_are_idempotent() {
    let (_dir, store, owner) = fixture();
    let cfg = config(Some(UserQuotaPeriod::Daily));
    store.current_handle("alice").unwrap().charge(600);
    request(&store, &cfg, START + 100);
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), START)
            .quota_schedule_state,
        "pending"
    );
    owner.process_schedules(START + 100, false).await.unwrap();
    assert_eq!(store.used("alice"), 600);
    assert_eq!(store.schedule_deadline(), Some(START + DAY));
    owner
        .process_schedules(START + DAY - 1, false)
        .await
        .unwrap();
    assert_eq!(store.used("alice"), 600);
    owner.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(store.used("alice"), 0);
    store.current_handle("alice").unwrap().charge(17);
    for now in [START, START + DAY, START + DAY + 10] {
        owner.process_schedules(now, false).await.unwrap();
        assert_eq!(store.used("alice"), 17);
    }
    owner
        .process_schedules(START + 50 * DAY + 1, false)
        .await
        .unwrap();
    assert_eq!(store.used("alice"), 0);
    assert_eq!(store.schedule_deadline(), Some(START + 51 * DAY));
    let state = read_state_file(owner.path()).await.unwrap().unwrap();
    assert_eq!(
        state.users["alice"].schedule.period_cursor_epoch_secs,
        START + 50 * DAY
    );
}

#[tokio::test]
async fn quota_period_change_remove_reenable_and_rotation_preserve_watermark() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START + 100);
    owner.process_schedules(START + 100, false).await.unwrap();
    owner
        .process_schedules(START + 2 * DAY, false)
        .await
        .unwrap();
    store.current_handle("alice").unwrap().charge(600);
    let before = store.current_handle("alice").unwrap().schedule_checkpoint();
    store.advance_preserving_usage("alice", 2);
    assert_eq!(
        store.current_handle("alice").unwrap().schedule_checkpoint(),
        before
    );
    for cfg in [
        config(None),
        config(Some(UserQuotaPeriod::Weekly)),
        config(Some(UserQuotaPeriod::Daily)),
    ] {
        request(&store, &cfg, START);
        owner.process_schedules(START, false).await.unwrap();
        assert_eq!(store.used("alice"), 600);
        assert!(
            store
                .current_handle("alice")
                .unwrap()
                .schedule_checkpoint()
                .period_cursor_epoch_secs
                >= START + 2 * DAY
        );
    }
    assert_eq!(store.schedule_deadline(), Some(START + 3 * DAY));
}

#[tokio::test]
async fn quota_period_failure_keeps_usage_and_cursor_until_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(QuotaStore::default());
    store.activate_fresh("alice", 1);
    let path = dir.path().join("blocked");
    std::fs::create_dir(&path).unwrap();
    let owner = QuotaStateOwner::new(path.clone(), store.clone());
    store.current_handle("alice").unwrap().charge(500);
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START);
    assert!(owner.process_schedules(START, false).await.is_err());
    assert_eq!(store.used("alice"), 500);
    assert_eq!(
        store.current_handle("alice").unwrap().schedule_checkpoint(),
        QuotaScheduleCheckpoint::default()
    );
    assert_eq!(
        store
            .schedule_status("alice", Some(UserQuotaPeriod::Daily), START)
            .quota_schedule_state,
        "error"
    );
    std::fs::remove_dir(path).unwrap();
    owner.process_schedules(START, false).await.unwrap();
    assert_eq!(store.used("alice"), 500);
    owner.process_schedules(START + DAY, false).await.unwrap();
    assert_eq!(store.used("alice"), 0);
}

#[tokio::test]
async fn quota_period_old_reservations_cannot_refund_the_new_period() {
    let (_dir, store, owner) = fixture();
    request(&store, &config(Some(UserQuotaPeriod::Daily)), START);
    owner.process_schedules(START, false).await.unwrap();
    let target = store.current_handle("alice").unwrap();
    let reservation = target.try_reserve(700, 1024).unwrap();
    owner.process_schedules(START + DAY, false).await.unwrap();
    target.charge(200);
    drop(reservation);
    assert_eq!(target.used(), 200);
}

#[tokio::test]
async fn quota_period_restart_catches_up_once_and_legacy_migration_preserves_usage() {
    let (dir, store, owner) = fixture();
    let cfg = config(Some(UserQuotaPeriod::Monthly));
    std::fs::write(owner.path(), r#"{"last_reset_epoch_secs":0,"users":{"alice":{"used_bytes":712,"last_reset_epoch_secs":0}}}"#).unwrap();
    owner.load_for_config(&cfg).await.unwrap();
    request(&store, &cfg, START + 200);
    owner.process_schedules(START + 200, true).await.unwrap();
    assert_eq!(store.used("alice"), 712);
    let restarted = Arc::new(QuotaStore::default());
    let second = QuotaStateOwner::new(dir.path().join("quota.json"), restarted.clone());
    second.load_for_config(&cfg).await.unwrap();
    restarted.activate_fresh("alice", 1);
    request(&restarted, &cfg, START + 70 * DAY);
    second
        .process_schedules(START + 70 * DAY, true)
        .await
        .unwrap();
    assert_eq!(restarted.used("alice"), 0);
    restarted.current_handle("alice").unwrap().charge(55);
    second
        .process_schedules(START + 70 * DAY, false)
        .await
        .unwrap();
    assert_eq!(restarted.used("alice"), 55);
}

#[tokio::test]
async fn quota_period_strict_startup_rejects_corruption_but_legacy_policy_does_not() {
    let (_dir, _store, owner) = fixture();
    std::fs::write(owner.path(), b"{broken").unwrap();
    assert!(
        owner
            .load_for_config(&config(Some(UserQuotaPeriod::Daily)))
            .await
            .is_err()
    );
    assert!(owner.load_for_config(&config(None)).await.is_ok());
    std::fs::write(owner.path(), r#"{"last_reset_epoch_secs":0,"users":{"alice":{"used_bytes":7,"last_reset_epoch_secs":0,"quota_period":"daily","period_cursor_epoch_secs":18446744073709551615}}}"#).unwrap();
    assert!(
        owner
            .load_for_config(&config(Some(UserQuotaPeriod::Daily)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn quota_period_fresh_account_rejects_stale_snapshot_and_does_not_inherit_cursor() {
    let (_dir, store, owner) = fixture();
    let old = config(Some(UserQuotaPeriod::Daily));
    request(&store, &old, START);
    owner.process_schedules(START, false).await.unwrap();
    store.retire_through("alice", 2);
    store.activate_fresh("alice", 3);
    let credential = credential_id_from_hex(SECRET).unwrap();
    store.fence_fresh_schedule(
        "alice",
        &old,
        credential,
        Some(UserQuotaPeriod::Monthly),
        Some(1024),
    );
    request(&store, &old, START);
    assert_eq!(
        store.current_handle("alice").unwrap().schedule_checkpoint(),
        QuotaScheduleCheckpoint::default()
    );
    assert_eq!(store.schedule_deadline(), None);
    request(&store, &config(Some(UserQuotaPeriod::Monthly)), START + 1);
    owner.process_schedules(START + 1, false).await.unwrap();
    assert_eq!(store.schedule_deadline(), Some(START + 31 * DAY));
}

#[tokio::test]
async fn quota_period_manual_reset_advances_cursor_without_changing_cadence() {
    let (_dir, store, owner) = fixture();
    let now = now_epoch_secs();
    let cfg = config(Some(UserQuotaPeriod::Daily));
    request(&store, &cfg, now - 3 * DAY);
    owner.process_schedules(now - 3 * DAY, false).await.unwrap();
    store.current_handle("alice").unwrap().charge(250);
    owner
        .reset_user(&BTreeSet::from(["alice".into()]), "alice")
        .await
        .unwrap();
    let next = store.schedule_deadline().unwrap();
    assert_eq!(next, UserQuotaPeriod::Daily.next(now_epoch_secs()).unwrap());
    store.current_handle("alice").unwrap().charge(80);
    owner
        .process_schedules(now_epoch_secs(), false)
        .await
        .unwrap();
    assert_eq!(store.used("alice"), 80);
}

#[test]
fn quota_period_gate_is_shared_with_the_admission_authority() {
    let (_dir, store, owner) = fixture();
    let admission = UserAdmissionAuthority::new_with_quota_store(store.clone());
    assert!(Arc::ptr_eq(
        &owner.mutation,
        &admission.quota_mutation_gate()
    ));
    assert!(Arc::ptr_eq(&owner.mutation, &store.mutation_gate()));
}

#[tokio::test]
async fn quota_period_disabled_expired_account_keeps_calendar_without_becoming_enabled() {
    let (_dir, store, owner) = fixture();
    let authority = UserAdmissionAuthority::new_with_quota_store(store.clone());
    let mut cfg = (*config(Some(UserQuotaPeriod::Daily))).clone();
    cfg.access.user_enabled.insert("alice".into(), false);
    cfg.access.user_expirations.insert(
        "alice".into(),
        chrono::DateTime::from_timestamp(0, 0).unwrap(),
    );
    let cfg = Arc::new(cfg);
    authority.activate_config_source(1, None, &cfg.access.users, &cfg.access.user_enabled);
    let guard = owner.lock().await;
    authority.publish_quota_config(1, &cfg, true);
    drop(guard);
    owner
        .process_schedules(now_epoch_secs(), false)
        .await
        .unwrap();
    store.current_handle("alice").unwrap().charge(700);
    let boundary = store.schedule_deadline().unwrap();
    owner.process_schedules(boundary, false).await.unwrap();
    assert_eq!(store.used("alice"), 0);
    assert!(!authority.is_user_enabled("alice"));
    assert!(cfg.access.user_expirations["alice"].timestamp() < now_epoch_secs() as i64);
}

mod concurrency;

mod resource_model;

// Account-lifetime freshness and delayed source publication regressions.
mod freshness;
