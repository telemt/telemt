use super::*;

#[tokio::test]
async fn quota_period_b11_prepared_runtime_cannot_restore_superseded_period() {
    for mode in [ReloadMode::Instant, ReloadMode::Drain] {
        let mut daily = user_config();
        daily.quota_source_read_at = Some(std::time::Instant::now());
        daily
            .access
            .user_quota_periods
            .insert("alice".into(), UserQuotaPeriod::Daily);
        let (fixture, authority, store) = shared_fixture(daily.clone(), daily.clone(), mode).await;
        let dir = tempfile::tempdir().unwrap();
        let quota = QuotaStateOwner::new(dir.path().join("quota.json"), store.clone());
        let gate = quota.lock().await;
        authority.publish_quota_config(1, &fixture.old_runtime.config(), true);
        drop(gate);
        quota
            .process_schedules(crate::quota_state::now_epoch_secs(), false)
            .await
            .unwrap();
        let prepared = prepared_runtime(fixture.new_runtime.clone());
        let mut monthly = daily;
        monthly
            .access
            .user_quota_periods
            .insert("alice".into(), UserQuotaPeriod::Monthly);
        let gate = quota.lock().await;
        quota.refresh_fresh_schedule("alice", &monthly);
        monthly.quota_source_read_at = Some(std::time::Instant::now());
        authority.publish_quota_config(1, &Arc::new(monthly), true);
        assert_eq!(authority.epoch(), prepared.user_admission_epoch);
        drop(gate);
        quota
            .process_schedules(crate::quota_state::now_epoch_secs(), false)
            .await
            .unwrap();
        let account = store.current_handle("alice").unwrap();
        let checkpoint = account.schedule_checkpoint();
        account.charge(700);
        fixture
            .supervisor
            .activate_prepared(
                fixture.command,
                fixture.old_runtime.clone(),
                prepared,
                RevisionGateAction::Warn("config revision changed during preparation".into()),
            )
            .await;
        quota
            .process_schedules(crate::quota_state::now_epoch_secs(), false)
            .await
            .unwrap();
        assert_eq!(account.schedule_checkpoint(), checkpoint);
        assert_eq!(store.used("alice"), 700);
        assert_eq!(fixture.supervisor.active_runtime.load().id, 2);
        assert_eq!(
            fixture.control.status(1).await.unwrap().state,
            ReloadPhase::Succeeded
        );
        fixture.new_runtime.stop_sessions().await;
        fixture.new_runtime.stop_background_tasks().await;
    }
}
