use super::*;
use std::sync::atomic::Ordering;

async fn fixture() -> (tempfile::TempDir, Arc<QuotaStateOwner>) {
    let dir = tempfile::tempdir().unwrap();
    let owner = QuotaStateOwner::new(
        dir.path().join("quota.json"),
        Arc::new(QuotaStore::default()),
    );
    let mut state = QuotaStateFile::default();
    state.last_reset_epoch_secs = 123;
    state.users.insert(
        "alice".into(),
        quota_user_state(UserQuotaSnapshot {
            used_bytes: 700,
            last_reset_epoch_secs: 123,
        }),
    );
    state.users.insert(
        "bob".into(),
        QuotaUserState {
            used_bytes: 321,
            last_reset_epoch_secs: 111,
            schedule: QuotaScheduleCheckpoint {
                quota_period: Some(crate::config::UserQuotaPeriod::Monthly),
                period_cursor_epoch_secs: 1_793_491_200,
            },
        },
    );
    write_state_file(owner.path(), state).await.unwrap();
    (dir, owner)
}

#[tokio::test]
async fn creation_removes_only_retired_row_and_returns_owned_gate() {
    let (_dir, owner) = fixture().await;
    let before = read_state_file(owner.path()).await.unwrap().unwrap();
    let guard = owner.lock().await;
    let guard = owner
        .prepare_user_creation_locked("alice", guard)
        .await
        .unwrap();
    assert!(owner.mutation.try_lock().is_err());
    let after = read_state_file(owner.path()).await.unwrap().unwrap();
    assert!(!after.users.contains_key("alice"));
    assert_eq!(
        serde_json::to_value(&after.users["bob"]).unwrap(),
        serde_json::to_value(&before.users["bob"]).unwrap()
    );
    assert_eq!(after.last_reset_epoch_secs, before.last_reset_epoch_secs);
    drop(guard);
    assert!(owner.mutation.try_lock().is_ok());
}

#[tokio::test]
async fn creation_without_checkpoint_does_not_require_a_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing/quota.json");
    let owner = QuotaStateOwner::new(path.clone(), Arc::new(QuotaStore::default()));
    let guard = owner.lock().await;
    let _guard = owner
        .prepare_user_creation_locked("alice", guard)
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(owner.mutation.try_lock().is_err());
}

#[tokio::test]
async fn creation_retries_durability_after_ambiguous_removal() {
    let (_dir, owner) = fixture().await;
    let (hook, _) = test_io::Hook::install(owner.path(), false);
    hook.fail_after.store(true, Ordering::Relaxed);
    let guard = owner.lock().await;
    assert!(
        owner
            .prepare_user_creation_locked("alice", guard)
            .await
            .is_err()
    );
    assert!(
        !read_state_file(owner.path())
            .await
            .unwrap()
            .unwrap()
            .users
            .contains_key("alice")
    );
    // The absent row does not prove that the previous directory sync succeeded.
    let guard = owner.lock().await;
    assert!(
        owner
            .prepare_user_creation_locked("alice", guard)
            .await
            .is_err()
    );
    assert_eq!(hook.writes.load(Ordering::Relaxed), 2);
    hook.fail_after.store(false, Ordering::Relaxed);
    let guard = owner.lock().await;
    let _guard = owner
        .prepare_user_creation_locked("alice", guard)
        .await
        .unwrap();
    assert_eq!(hook.writes.load(Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_waiter_abort_keeps_gate_until_durable_removal_finishes() {
    let (_dir, owner) = fixture().await;
    let (hook, started) = test_io::Hook::install(owner.path(), true);
    let operation = owner.clone();
    let waiter = tokio::spawn(async move {
        let guard = operation.lock().await;
        operation.prepare_user_creation_locked("alice", guard).await
    });
    started.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(owner.mutation.try_lock().is_err());
    assert!(
        read_state_file(owner.path())
            .await
            .unwrap()
            .unwrap()
            .users
            .contains_key("alice")
    );
    hook.release();
    let _guard = tokio::time::timeout(std::time::Duration::from_secs(2), owner.lock())
        .await
        .unwrap();
    assert!(
        !read_state_file(owner.path())
            .await
            .unwrap()
            .unwrap()
            .users
            .contains_key("alice")
    );
    assert_eq!(hook.writes.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_write_failure_keeps_retired_checkpoint_for_safe_retry() {
    let (_dir, owner) = fixture().await;
    let retired = owner.path().with_extension("retired");
    let (hook, started) = test_io::Hook::install(owner.path(), true);
    let operation = owner.clone();
    let writer = tokio::spawn(async move {
        let guard = operation.lock().await;
        operation.prepare_user_creation_locked("alice", guard).await
    });
    started.await.unwrap();
    std::fs::rename(owner.path(), &retired).unwrap();
    std::fs::create_dir(owner.path()).unwrap();
    hook.release();
    assert!(writer.await.unwrap().is_err());
    std::fs::remove_dir(owner.path()).unwrap();
    std::fs::rename(retired, owner.path()).unwrap();
    assert!(
        read_state_file(owner.path())
            .await
            .unwrap()
            .unwrap()
            .users
            .contains_key("alice")
    );
    let guard = owner.lock().await;
    let _guard = owner
        .prepare_user_creation_locked("alice", guard)
        .await
        .unwrap();
    assert!(
        !read_state_file(owner.path())
            .await
            .unwrap()
            .unwrap()
            .users
            .contains_key("alice")
    );
}
