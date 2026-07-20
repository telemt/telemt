use super::*;
use crate::config::ProxyConfig;
use crate::maestro::generation::test_runtime_generation;
use crate::maestro::reload::{ReloadRequest, ReloadSubmitError};
use crate::stats::QuotaStore;
use tokio::sync::Notify;
use tracing_subscriber::{EnvFilter, Registry};

struct ReloadFixture {
    supervisor: Arc<ReloadSupervisor>,
    control: ReloadControl,
    command: ReloadCommand,
    old_runtime: Arc<RuntimeGeneration>,
    new_runtime: Arc<RuntimeGeneration>,
    runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
}

fn runtime_log_filter() -> RuntimeLogFilter {
    let (_layer, handle) =
        tracing_subscriber::reload::Layer::<EnvFilter, Registry>::new(EnvFilter::new("info"));
    RuntimeLogFilter::new(handle)
}

async fn fixture(request: ReloadRequest) -> ReloadFixture {
    let old_runtime = test_runtime_generation(1, ProxyConfig::default());
    let new_config = Arc::new(ProxyConfig::default());
    let new_runtime = test_runtime_generation(2, new_config.as_ref().clone());
    let active_runtime = Arc::new(ArcSwap::from(old_runtime.clone()));
    let (control, commands) = ReloadControl::channel(old_runtime.id);
    let accepted = control
        .submit(new_config.clone(), "revision".to_string(), request.clone())
        .await
        .unwrap();
    let (detected_ips_tx, _detected_ips_rx) = watch::channel((None, None));
    let (runtime_watch_tx, runtime_watch_rx) = watch::channel(Some(old_runtime.watch_state()));
    let supervisor = Arc::new(ReloadSupervisor {
        active_runtime,
        control: control.clone(),
        commands,
        config_path: PathBuf::new(),
        quota_store: Arc::new(QuotaStore::default()),
        detected_ips_tx,
        runtime_log_filter: runtime_log_filter(),
        runtime_watch_tx,
    });
    let command = ReloadCommand {
        reload_id: accepted.reload_id,
        target_generation: accepted.target_generation,
        config: new_config,
        config_revision: accepted.config_revision,
        request,
    };
    ReloadFixture {
        supervisor,
        control,
        command,
        old_runtime,
        new_runtime,
        runtime_watch_rx,
    }
}

struct DropSignal(Arc<Notify>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[test]
fn revision_gate_proceeds_only_on_verified_match() {
    assert_eq!(
        revision_gate_action(
            "accepted",
            Ok("accepted".to_string()),
            ReloadFailurePolicy::Rollback,
        ),
        RevisionGateAction::Proceed
    );
}

#[test]
fn revision_gate_applies_failure_policy_to_mismatch_and_read_error() {
    for result in [Ok("changed".to_string()), Err("read failed".to_string())] {
        assert!(matches!(
            revision_gate_action("accepted", result.clone(), ReloadFailurePolicy::KeepNew,),
            RevisionGateAction::Warn(_)
        ));
        assert!(matches!(
            revision_gate_action("accepted", result, ReloadFailurePolicy::Rollback),
            RevisionGateAction::Rollback(_)
        ));
    }
}
#[tokio::test]
async fn revision_rollback_keeps_old_generation_and_cleans_candidate() {
    let fixture = fixture(ReloadRequest {
        failure_policy: ReloadFailurePolicy::Rollback,
        ..ReloadRequest::default()
    })
    .await;
    let candidate_dropped = Arc::new(Notify::new());
    let candidate_drop = candidate_dropped.clone();
    assert!(fixture.new_runtime.spawn_session(async move {
        let _drop_signal = DropSignal(candidate_drop);
        std::future::pending::<()>().await;
    }));
    tokio::task::yield_now().await;

    fixture
        .supervisor
        .activate_prepared(
            fixture.command,
            fixture.old_runtime.clone(),
            PreparedRuntime {
                generation: fixture.new_runtime,
                detected_ips: (None, None),
            },
            RevisionGateAction::Rollback("revision changed".to_string()),
            |_| -> Result<(), String> { panic!("DNS activation must not run on rollback") },
        )
        .await;

    tokio::time::timeout(Duration::from_secs(1), candidate_dropped.notified())
        .await
        .unwrap();
    assert_eq!(fixture.supervisor.active_runtime.load().id, 1);
    assert_eq!(
        fixture
            .runtime_watch_rx
            .borrow()
            .as_ref()
            .unwrap()
            .generation_id,
        1
    );
    assert!(fixture.old_runtime.spawn_session(async {}));
    let status = fixture.control.status(1).await.unwrap();
    assert_eq!(status.state, ReloadPhase::RolledBack);
    fixture.old_runtime.stop_sessions().await;
}

#[tokio::test]
async fn dns_failure_policy_controls_rollback_or_keep_new() {
    for policy in [ReloadFailurePolicy::Rollback, ReloadFailurePolicy::KeepNew] {
        let fixture = fixture(ReloadRequest {
            failure_policy: policy,
            ..ReloadRequest::default()
        })
        .await;
        fixture
            .supervisor
            .activate_prepared(
                fixture.command,
                fixture.old_runtime.clone(),
                PreparedRuntime {
                    generation: fixture.new_runtime.clone(),
                    detected_ips: (None, None),
                },
                RevisionGateAction::Proceed,
                |_| Err("invalid DNS entry".to_string()),
            )
            .await;

        let status = fixture.control.status(1).await.unwrap();
        match policy {
            ReloadFailurePolicy::Rollback => {
                assert_eq!(fixture.supervisor.active_runtime.load().id, 1);
                assert_eq!(status.state, ReloadPhase::RolledBack);
                assert!(fixture.old_runtime.spawn_session(async {}));
                fixture.old_runtime.stop_sessions().await;
            }
            ReloadFailurePolicy::KeepNew => {
                assert_eq!(fixture.supervisor.active_runtime.load().id, 2);
                assert_eq!(status.state, ReloadPhase::Succeeded);
                assert_eq!(status.warnings.len(), 1);
                assert!(!fixture.old_runtime.spawn_session(async {}));
                fixture.new_runtime.stop_sessions().await;
            }
        }
    }
}

#[tokio::test]
async fn drain_publishes_new_generation_before_old_sessions_finish() {
    let mut fixture = fixture(ReloadRequest {
        mode: ReloadMode::Drain,
        timeout_secs: Some(30),
        ..ReloadRequest::default()
    })
    .await;
    let old_started = Arc::new(Notify::new());
    let old_release = Arc::new(Notify::new());
    let started = old_started.clone();
    let release = old_release.clone();
    assert!(fixture.old_runtime.spawn_session(async move {
        started.notify_one();
        release.notified().await;
    }));
    old_started.notified().await;

    let supervisor = fixture.supervisor.clone();
    let old_runtime = fixture.old_runtime.clone();
    let new_runtime = fixture.new_runtime.clone();
    let activation = tokio::spawn(async move {
        supervisor
            .activate_prepared(
                fixture.command,
                old_runtime,
                PreparedRuntime {
                    generation: new_runtime,
                    detected_ips: (None, None),
                },
                RevisionGateAction::Proceed,
                |_| Ok(()),
            )
            .await;
    });

    fixture.runtime_watch_rx.changed().await.unwrap();
    assert_eq!(
        fixture
            .runtime_watch_rx
            .borrow()
            .as_ref()
            .unwrap()
            .generation_id,
        2
    );
    assert!(!activation.is_finished());
    assert!(!fixture.old_runtime.spawn_session(async {}));

    old_release.notify_one();
    activation.await.unwrap();
    assert_eq!(
        fixture.control.status(1).await.unwrap().state,
        ReloadPhase::Succeeded
    );
    fixture.new_runtime.stop_sessions().await;
}

#[tokio::test(start_paused = true)]
async fn drain_timeout_cancels_old_sessions_and_records_one_warning() {
    let mut fixture = fixture(ReloadRequest {
        mode: ReloadMode::Drain,
        timeout_secs: Some(1),
        ..ReloadRequest::default()
    })
    .await;
    let dropped = Arc::new(Notify::new());
    let drop_signal = dropped.clone();
    assert!(fixture.old_runtime.spawn_session(async move {
        let _drop_signal = DropSignal(drop_signal);
        std::future::pending::<()>().await;
    }));
    tokio::task::yield_now().await;

    let supervisor = fixture.supervisor.clone();
    let old_runtime = fixture.old_runtime.clone();
    let new_runtime = fixture.new_runtime.clone();
    let activation = tokio::spawn(async move {
        supervisor
            .activate_prepared(
                fixture.command,
                old_runtime,
                PreparedRuntime {
                    generation: new_runtime,
                    detected_ips: (None, None),
                },
                RevisionGateAction::Proceed,
                |_| Ok(()),
            )
            .await;
    });
    fixture.runtime_watch_rx.changed().await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    activation.await.unwrap();

    dropped.notified().await;
    let status = fixture.control.status(1).await.unwrap();
    assert_eq!(status.state, ReloadPhase::Succeeded);
    assert_eq!(status.warnings.len(), 1);
    assert!(status.warnings[0].contains("exceeded drain timeout"));
    fixture.new_runtime.stop_sessions().await;
}

#[tokio::test]
async fn quiesce_joins_idle_supervisor_and_rejects_later_submissions() {
    let runtime = test_runtime_generation(1, ProxyConfig::default());
    let active_runtime = Arc::new(ArcSwap::from(runtime.clone()));
    let (control, commands) = ReloadControl::channel(runtime.id);
    let (detected_ips_tx, _detected_ips_rx) = watch::channel((None, None));
    let (runtime_watch_tx, _runtime_watch_rx) = watch::channel(Some(runtime.watch_state()));
    let handle = ReloadSupervisor::spawn(
        active_runtime,
        control.clone(),
        commands,
        PathBuf::new(),
        Arc::new(QuotaStore::default()),
        detected_ips_tx,
        runtime_log_filter(),
        runtime_watch_tx,
    );

    tokio::time::timeout(Duration::from_secs(1), handle.quiesce())
        .await
        .unwrap();
    let result = control
        .submit(
            Arc::new(ProxyConfig::default()),
            "revision".to_string(),
            ReloadRequest::default(),
        )
        .await;

    assert_eq!(result, Err(ReloadSubmitError::MaestroUnavailable));
    runtime.stop_sessions().await;
}
