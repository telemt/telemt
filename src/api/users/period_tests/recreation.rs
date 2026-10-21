use super::*;

#[tokio::test]
async fn quota_period_failed_delete_recreate_restart_must_not_inherit_retired_calendar() {
    for secret in ["0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"] {
        quota_period_delete_recreate_restart(true, secret).await;
    }
}

#[tokio::test]
async fn quota_period_successful_delete_recreate_restart_has_fresh_calendar() {
    for secret in ["0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"] {
        quota_period_delete_recreate_restart(false, secret).await;
    }
}

async fn quota_period_delete_recreate_restart(fail_deletion: bool, secret: &str) {
    let fixture = Fixture::new();
    let create = |secret: &str| serde_json::from_value(serde_json::json!({
        "username":"alice", "secret":secret,
        "data_quota_bytes":1024, "quota_period":"monthly"
    })).unwrap();
    create_user(create("0123456789abcdef0123456789abcdef"), None, &fixture.shared).await.unwrap();
    fixture.publish().await;
    let now = crate::quota_state::now_epoch_secs();
    // Model a previously processed future boundary followed by clock rollback.
    let next = UserQuotaPeriod::Monthly.next(now).unwrap();
    let future = UserQuotaPeriod::Monthly.next(next).unwrap();
    fixture.shared.quota_state.process_schedules(future, false).await.unwrap();
    fixture.store.current_handle("alice").unwrap().charge(700);
    fixture.shared.quota_state.save(&std::collections::BTreeSet::from(["alice".into(), "admin".into()])).await.unwrap();
    let old_checkpoint = fixture.store.current_handle("alice").unwrap().schedule_checkpoint();
    let quota_path = fixture.shared.quota_state.path().to_owned();
    let retired_file = quota_path.with_extension("retired");
    if fail_deletion {
        std::fs::rename(&quota_path, &retired_file).unwrap();
        std::fs::create_dir(&quota_path).unwrap();
    }
    // Config deletion succeeds but the quota file cannot replace a directory.
    delete_user("alice", None, &fixture.shared).await.unwrap();
    assert!(fixture.store.current_handle("alice").is_none());
    if fail_deletion {
        let config_before = std::fs::read(&fixture.shared.config_path).unwrap();
        assert!(create_user(create(secret), None, &fixture.shared).await.is_err());
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), config_before);
        assert!(fixture.store.current_handle("alice").is_none());
        // Restore the old durable bytes to model storage recovery before retry.
        std::fs::remove_dir(&quota_path).unwrap();
        std::fs::rename(&retired_file, &quota_path).unwrap();
    }
    create_user(create(secret), None, &fixture.shared).await.unwrap();
    assert_eq!(fixture.store.used("alice"), 0);
    assert_eq!(fixture.store.current_handle("alice").unwrap().schedule_checkpoint().period_cursor_epoch_secs, 0);
    let cfg = Arc::new(ProxyConfig::load(&fixture.shared.config_path).unwrap());
    let restart_store = Arc::new(QuotaStore::default());
    let restart = QuotaStateOwner::new(quota_path, restart_store.clone());
    restart.load_for_config(&cfg).await.unwrap();
    let authority = UserAdmissionAuthority::new_with_quota_store(restart_store.clone());
    let gate = restart.lock().await;
    authority.activate_config_source(1, None, &cfg.access.users, &cfg.access.user_enabled).unwrap();
    authority.publish_quota_config(1, &cfg, true);
    drop(gate);
    restart.process_schedules(now, true).await.unwrap();
    let actual = restart_store.current_handle("alice").unwrap().schedule_checkpoint();
    assert!(actual.period_cursor_epoch_secs < old_checkpoint.period_cursor_epoch_secs);
    assert_eq!(restart_store.schedule_deadline(), Some(next), "recreated account inherited a retired calendar watermark across restart");
    assert_eq!(restart_store.used("alice"), 0, "recreated account inherited retired usage");
    fixture.finish().await;
}

#[tokio::test]
async fn quota_period_create_rejects_unreadable_checkpoint_without_publishing_user() {
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.shared.quota_state.path();
        if corrupt {
            std::fs::write(path, b"invalid checkpoint").unwrap();
        } else {
            std::fs::create_dir(path).unwrap();
        }
        let before = std::fs::read(&fixture.shared.config_path).unwrap();
        let result = create_user(
            serde_json::from_value(serde_json::json!({
                "username":"alice", "data_quota_bytes":1024, "quota_period":"monthly"
            })).unwrap(),
            None,
            &fixture.shared,
        ).await;
        assert!(result.is_err(), "CREATE must reject untrusted durable quota state");
        assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
        assert!(fixture.store.current_handle("alice").is_none());
        fixture.finish().await;
    }
}

#[tokio::test]
async fn quota_period_create_revision_conflict_does_not_touch_retired_checkpoint() {
    let fixture = Fixture::new();
    let retired = b"{\"last_reset_epoch_secs\":123,\"users\":{\"alice\":{\"used_bytes\":700,\"last_reset_epoch_secs\":123}}}";
    std::fs::write(fixture.shared.quota_state.path(), retired).unwrap();
    let before = std::fs::read(&fixture.shared.config_path).unwrap();
    let result = create_user(
        serde_json::from_value(serde_json::json!({"username":"alice"})).unwrap(),
        Some("outdated-revision".into()),
        &fixture.shared,
    ).await;
    assert_eq!(result.err().unwrap().code, "revision_conflict");
    assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), before);
    assert_eq!(std::fs::read(fixture.shared.quota_state.path()).unwrap(), retired);
    assert!(fixture.store.current_handle("alice").is_none());
    fixture.finish().await;
}
