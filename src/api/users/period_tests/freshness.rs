use super::*;

#[tokio::test]
async fn quota_period_b11_patch_preserves_active_policy_against_delayed_source() {
    for accepted in [false, true] {
        let fixture = Fixture::new();
        // The startup account has no API-creation fence.
        patch_user(
            "admin",
            patch(serde_json::json!({"data_quota_bytes":1024,"quota_period":"daily"})),
            None,
            &fixture.shared,
        )
        .await
        .unwrap();
        fixture.publish().await;
        let stale = ProxyConfig::parse_source(&fixture.shared.config_path).unwrap();
        let authority = fixture.shared.proxy_shared.user_admission();
        let epoch = authority.epoch();
        patch_user(
            "admin",
            patch(serde_json::json!({"quota_period":"monthly"})),
            None,
            &fixture.shared,
        )
        .await
        .unwrap();
        assert_eq!(authority.epoch(), epoch);
        assert!(authority.has_fresh_quota_schedules());
        fixture.publish().await;
        assert!(!authority.has_fresh_quota_schedules());
        let account = fixture.store.current_handle("admin").unwrap();
        account.charge(700);
        let checkpoint = account.schedule_checkpoint();
        let stale = Arc::new(stale.prepare().await.unwrap().config);
        let gate = fixture.shared.quota_state.lock().await;
        fixture
            .shared
            .proxy_shared
            .publish_quota_config(1, &stale, accepted);
        drop(gate);
        fixture
            .shared
            .quota_state
            .process_schedules(crate::quota_state::now_epoch_secs(), false)
            .await
            .unwrap();
        assert_eq!(account.schedule_checkpoint(), checkpoint);
        assert_eq!(fixture.store.used("admin"), 700);
        assert_eq!(
            fixture
                .shared
                .quota_state
                .schedule_status("admin", Some(UserQuotaPeriod::Monthly))
                .quota_schedule_state,
            "active"
        );
        assert_eq!(
            fixture.store.current_handle("admin").unwrap().incarnation(),
            account.incarnation()
        );
        fixture.publish().await;
        assert!(!authority.has_fresh_quota_schedules());
        fixture.finish().await;
    }
}

#[tokio::test]
async fn quota_period_b11_noop_patch_keeps_active_status_without_publication() {
    let fixture = Fixture::new();
    patch_user(
        "admin",
        patch(serde_json::json!({"data_quota_bytes":1024,"quota_period":"monthly"})),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    fixture.publish().await;
    let account = fixture.store.current_handle("admin").unwrap();
    account.charge(700);
    let checkpoint = account.schedule_checkpoint();
    patch_user("admin", patch(serde_json::json!({})), None, &fixture.shared)
        .await
        .unwrap();
    assert_eq!(account.schedule_checkpoint(), checkpoint);
    assert_eq!(fixture.store.used("admin"), 700);
    assert!(
        !fixture
            .shared
            .proxy_shared
            .user_admission()
            .has_fresh_quota_schedules()
    );
    assert_eq!(
        fixture
            .shared
            .quota_state
            .schedule_status("admin", Some(UserQuotaPeriod::Monthly))
            .quota_schedule_state,
        "active"
    );
    fixture.finish().await;
}
