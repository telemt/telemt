use super::*;

#[test]
fn request_defaults_to_instant_keep_new() {
    let request: ReloadRequest = serde_json::from_str("{}").unwrap();
    assert_eq!(request, ReloadRequest::default());
    assert_eq!(request.validate(), Ok(()));
}
#[test]
fn drain_requires_bounded_timeout() {
    let missing = ReloadRequest {
        mode: ReloadMode::Drain,
        ..ReloadRequest::default()
    };
    assert!(missing.validate().is_err());
    let valid = ReloadRequest {
        mode: ReloadMode::Drain,
        timeout_secs: Some(30),
        ..ReloadRequest::default()
    };
    assert_eq!(valid.validate(), Ok(()));
}

#[test]
fn patch_query_parses_reload_policy() {
    let request =
        ReloadRequest::from_query(Some("reload=drain&timeout_secs=30&failure_policy=rollback"))
            .unwrap()
            .unwrap();
    assert_eq!(request.mode, ReloadMode::Drain);
    assert_eq!(request.timeout_secs, Some(30));
    assert_eq!(request.failure_policy, ReloadFailurePolicy::Rollback);
    assert!(ReloadRequest::from_query(Some("timeout_secs=30")).is_err());
}

#[test]
fn status_uses_documented_deferred_process_fields_key() {
    let status = ReloadStatus {
        reload_id: 1,
        target_generation: 2,
        config_revision: "revision".to_string(),
        state: ReloadPhase::Succeeded,
        mode: ReloadMode::Instant,
        failure_policy: ReloadFailurePolicy::KeepNew,
        requested_at_epoch_secs: 10,
        started_at_epoch_secs: Some(11),
        finished_at_epoch_secs: Some(12),
        deferred_fields: vec!["server.listeners".to_string()],
        warnings: Vec::new(),
        error: None,
    };
    let value = serde_json::to_value(status).unwrap();

    assert_eq!(
        value["deferred_process_fields"],
        serde_json::json!(["server.listeners"])
    );
    assert!(value.get("deferred_fields").is_none());
}

#[tokio::test]
async fn coordinator_rejects_concurrent_reload_and_releases_terminal_slot() {
    let (control, mut receiver) = ReloadControl::channel(1);
    let first = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-1".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    let _command = receiver.recv().await.unwrap();
    let second = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-2".to_string(),
            ReloadRequest::default(),
        )
        .await;
    assert_eq!(second, Err(ReloadSubmitError::InProgress(first.reload_id)));
    control
        .succeed(first.reload_id, first.target_generation)
        .await;
    let third = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-3".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    assert_eq!(third.reload_id, first.reload_id + 1);
}

#[tokio::test]
async fn terminal_outcomes_release_slot_and_only_success_advances_generation() {
    let (control, mut receiver) = ReloadControl::channel(7);

    let failed = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-failed".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    let _command = receiver.recv().await.unwrap();
    control
        .mark_phase(failed.reload_id, ReloadPhase::Preparing)
        .await;
    control.fail(failed.reload_id, "prepare failed").await;
    let failed_status = control.status(failed.reload_id).await.unwrap();
    assert_eq!(failed_status.state, ReloadPhase::Failed);
    assert_eq!(failed_status.error.as_deref(), Some("prepare failed"));
    assert!(failed_status.started_at_epoch_secs.is_some());
    assert!(failed_status.finished_at_epoch_secs.is_some());

    let rolled_back = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-rollback".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    let _command = receiver.recv().await.unwrap();
    assert_eq!(rolled_back.target_generation, 8);
    control
        .rolled_back(rolled_back.reload_id, "revision changed")
        .await;

    let succeeded = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-success".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    let _command = receiver.recv().await.unwrap();
    assert_eq!(succeeded.target_generation, 8);
    control
        .succeed(succeeded.reload_id, succeeded.target_generation)
        .await;

    let next = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-next".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    assert_eq!(next.target_generation, 9);
}

#[tokio::test]
async fn stale_success_cannot_advance_generation_or_release_active_reload() {
    let (control, mut receiver) = ReloadControl::channel(3);
    let active = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-active".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    let _command = receiver.recv().await.unwrap();

    control.succeed(active.reload_id + 100, 99).await;

    assert_eq!(control.in_progress().await, Some(active.reload_id));
    control.fail(active.reload_id, "expected failure").await;
    let next = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-next".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    assert_eq!(next.target_generation, 4);
}

#[tokio::test]
async fn status_history_retains_only_the_latest_entries() {
    let (control, mut receiver) = ReloadControl::channel(1);
    let mut reload_ids = Vec::new();
    for index in 0..=RELOAD_HISTORY_CAPACITY {
        let accepted = control
            .submit(
                Arc::new(ProxyConfig::default()),
                format!("rev-{index}"),
                ReloadRequest::default(),
            )
            .await
            .unwrap();
        let _command = receiver.recv().await.unwrap();
        reload_ids.push(accepted.reload_id);
        control.fail(accepted.reload_id, "expected failure").await;
    }

    assert!(control.status(reload_ids[0]).await.is_none());
    assert!(control.status(reload_ids[1]).await.is_some());
    assert!(control.status(*reload_ids.last().unwrap()).await.is_some());
}

#[tokio::test]
async fn closed_command_channel_marks_reload_failed_and_releases_slot() {
    let (control, receiver) = ReloadControl::channel(1);
    drop(receiver);

    let result = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-closed".to_string(),
            ReloadRequest::default(),
        )
        .await;

    assert_eq!(result, Err(ReloadSubmitError::MaestroUnavailable));
    assert_eq!(control.in_progress().await, None);
    let status = control.status(1).await.unwrap();
    assert_eq!(status.state, ReloadPhase::Failed);
    assert_eq!(
        status.error.as_deref(),
        Some("maestro command channel is closed")
    );
}

#[tokio::test]
async fn shutdown_gate_rejects_new_commands_without_disturbing_active_status() {
    let (control, mut receiver) = ReloadControl::channel(4);
    let active = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-active".to_string(),
            ReloadRequest::default(),
        )
        .await
        .unwrap();
    let _command = receiver.recv().await.unwrap();

    control.begin_shutdown().await;
    let rejected = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "rev-rejected".to_string(),
            ReloadRequest::default(),
        )
        .await;

    assert_eq!(rejected, Err(ReloadSubmitError::MaestroUnavailable));
    assert_eq!(control.in_progress().await, Some(active.reload_id));
    control.fail(active.reload_id, "shutdown test").await;
}
