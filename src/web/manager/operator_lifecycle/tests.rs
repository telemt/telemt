use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use tokio::sync::Barrier;

use super::*;
use crate::config::ProxyConfig;
use crate::maestro::generation::test_runtime_generation;

fn test_runtime() -> (
    Arc<WebProcessRuntime>,
    Arc<crate::maestro::generation::RuntimeGeneration>,
) {
    let generation = test_runtime_generation(1, ProxyConfig::default());
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    (runtime, generation)
}

async fn stop_runtime(
    runtime: Arc<WebProcessRuntime>,
    generation: Arc<crate::maestro::generation::RuntimeGeneration>,
) {
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn pause_is_idempotent_and_resume_advances_only_real_transitions() {
    let (runtime, generation) = test_runtime();
    let initial = runtime.operator_lifecycle_status();
    assert_eq!(initial.state, OperatorLifecycleState::Running);
    assert_eq!(initial.epoch, 0);

    let paused = runtime.pause_operator().await.unwrap();
    assert_eq!(paused.state, OperatorLifecycleState::Paused);
    assert!(!paused.admission_open);
    let repeated_pause = runtime.pause_operator().await.unwrap();
    assert_eq!(repeated_pause.epoch, paused.epoch);

    let resumed = runtime.resume_operator().await.unwrap();
    assert_eq!(resumed.state, OperatorLifecycleState::Running);
    assert!(resumed.admission_open);
    let repeated_resume = runtime.resume_operator().await.unwrap();
    assert_eq!(repeated_resume.epoch, resumed.epoch);

    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn pause_waits_for_pre_cutover_admission_and_rejects_late_registration() {
    let (runtime, generation) = test_runtime();
    let registration = runtime.try_operator_admission().unwrap();
    let pause_runtime = Arc::clone(&runtime);
    let pause = tokio::spawn(async move { pause_runtime.pause_operator().await.unwrap() });
    tokio::task::yield_now().await;

    assert!(!pause.is_finished());
    assert_eq!(
        runtime.try_operator_admission().err(),
        Some(super::super::ManagerError::AdmissionPaused)
    );
    drop(registration);
    let paused = pause.await.unwrap();
    assert_eq!(paused.state, OperatorLifecycleState::Paused);

    stop_runtime(runtime, generation).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_fence_leaves_no_late_admission_commits_under_scheduler_pressure() {
    const ATTEMPTS: usize = 10_000;

    let (runtime, generation) = test_runtime();
    let start = Arc::new(Barrier::new(ATTEMPTS + 1));
    let committed = Arc::new(AtomicUsize::new(0));
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..ATTEMPTS {
        let runtime = Arc::clone(&runtime);
        let start = Arc::clone(&start);
        let committed = Arc::clone(&committed);
        attempts.spawn(async move {
            start.wait().await;
            if let Ok(_registration) = runtime.try_operator_admission() {
                tokio::task::yield_now().await;
                committed.fetch_add(1, Ordering::Release);
            }
        });
    }
    start.wait().await;
    runtime.pause_operator().await.unwrap();
    let committed_at_pause = committed.load(Ordering::Acquire);
    while let Some(result) = attempts.join_next().await {
        result.unwrap();
    }

    assert_eq!(committed.load(Ordering::Acquire), committed_at_pause);
    assert!(matches!(
        runtime.try_operator_admission(),
        Err(super::super::ManagerError::AdmissionPaused)
    ));
    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn empty_drain_completes_gracefully_and_stays_closed_until_resume() {
    let (runtime, generation) = test_runtime();
    let accepted = runtime
        .drain_operator(Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(accepted.state, OperatorLifecycleState::Draining);

    let completed = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let status = runtime.operator_lifecycle_status();
            if status.state == OperatorLifecycleState::Drained {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let drain = completed.drain.unwrap();
    assert_eq!(drain.state, OperatorDrainState::Completed);
    assert_eq!(drain.outcome, Some(OperatorDrainOutcome::Graceful));
    assert!(!completed.admission_open);

    let resumed = runtime.resume_operator().await.unwrap();
    assert_eq!(resumed.state, OperatorLifecycleState::Running);
    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn drain_request_returns_after_registering_its_worker() {
    let (runtime, generation) = test_runtime();
    let registration = runtime.try_operator_admission().unwrap();
    let drain_runtime = Arc::clone(&runtime);
    let drain = tokio::spawn(async move {
        drain_runtime
            .drain_operator(Duration::from_secs(30))
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.operator_lifecycle_status().state != OperatorLifecycleState::Draining {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(accepted.state, OperatorLifecycleState::Draining);
    drop(registration);

    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.operator_lifecycle_status().state != OperatorLifecycleState::Drained {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn resume_after_force_commit_cancels_wait_but_preserves_force_evidence() {
    let (runtime, generation) = test_runtime();
    let sequence = 7;
    let cancellation = CancellationToken::new();
    {
        let mut inner = runtime.operator_lifecycle.inner.lock();
        runtime
            .operator_lifecycle
            .admission
            .close(OperatorAdmissionRejection::Draining);
        inner.active = Some(ActiveDrain {
            sequence,
            cancellation,
        });
        inner.drain = Some(OperatorDrainStatus {
            operation_id: format!("wd1.{}.{sequence:016x}", runtime.runtime_instance()),
            state: OperatorDrainState::Draining,
            outcome: None,
            timeout_secs: 30,
            started_epoch_millis: 1,
            deadline_epoch_millis: 30_001,
            completed_epoch_millis: None,
            remaining_sessions: 1,
            remaining_streams: 0,
            remaining_websockets: 0,
            force_close_signalled: false,
        });
        runtime
            .operator_lifecycle
            .transition_locked(&mut inner, OperatorLifecycleState::Draining);
        runtime.operator_lifecycle.publish_locked(&inner);
    }
    assert!(runtime.operator_lifecycle.commit_force(
        sequence,
        WorkCounts {
            sessions: 1,
            streams: 0,
            websockets: 0,
        }
    ));

    let resumed = runtime.resume_operator().await.unwrap();
    assert_eq!(resumed.state, OperatorLifecycleState::Running);
    let drain = resumed.drain.unwrap();
    assert_eq!(drain.state, OperatorDrainState::Cancelled);
    assert_eq!(drain.outcome, Some(OperatorDrainOutcome::Cancelled));
    assert!(drain.force_close_signalled);
    stop_runtime(runtime, generation).await;
}

#[tokio::test]
async fn reload_cannot_reopen_operator_pause_and_resume_cannot_override_disabled_config() {
    let mut initial_config = ProxyConfig::default();
    initial_config.web.enabled = true;
    let initial = test_runtime_generation(1, initial_config);
    let active = Arc::new(ArcSwap::from(Arc::clone(&initial)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active));
    let paused = runtime.pause_operator().await.unwrap();
    assert!(!paused.admission_open);

    let disabled = test_runtime_generation(2, ProxyConfig::default());
    active.store(Arc::clone(&disabled));
    let after_reload = runtime.operator_lifecycle_status();
    assert_eq!(after_reload.state, OperatorLifecycleState::Paused);
    let resumed = runtime.resume_operator().await.unwrap();
    assert!(resumed.admission_open);
    assert!(!resumed.effective_new_work_admission);

    runtime.shutdown().await;
    initial.stop_sessions().await;
    initial.stop_background_tasks().await;
    disabled.stop_sessions().await;
    disabled.stop_background_tasks().await;
}

#[tokio::test]
async fn shutdown_terminally_prevents_resume() {
    let (runtime, generation) = test_runtime();
    runtime.pause_operator().await.unwrap();
    let drain = runtime.begin_shutdown();
    assert!(matches!(
        runtime.resume_operator().await,
        Err(OperatorLifecycleError::Closed)
    ));
    let _ = drain
        .wait_until(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
