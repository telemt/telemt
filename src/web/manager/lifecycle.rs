use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::time::Instant as TokioInstant;
use tracing::{info, warn};

use super::state::{
    decrement_map, remember_closed_session_locked, remember_closed_token_locked,
    remove_bootstrap_locked, remove_expired_locked,
};
use super::{ProfileKey, TokenHash, WebProcessRuntime};

/// Result of draining all process-owned WEB work under one absolute deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WebShutdownOutcome {
    /// Every registered session and auxiliary task completed.
    Drained,
    /// Cancellation was asserted, but registered work remained at the deadline.
    DeadlineExceeded,
}

/// Owned shutdown snapshot retained after sessions leave the live registry.
pub(crate) struct WebShutdownDrain {
    runtime: std::sync::Arc<WebProcessRuntime>,
    sessions: Vec<std::sync::Arc<crate::web::session::WebSession>>,
    started: TokioInstant,
}

impl WebProcessRuntime {
    /// Removes one closed session and retains a bounded host-bound replay marker.
    pub(crate) fn session_finished(
        &self,
        hash: TokenHash,
        client_ip: IpAddr,
        profile_key: ProfileKey,
        profile_host: &str,
        closed_token_lifetime: Duration,
    ) {
        let mut state = self.state.lock();
        let Some(session) = state.sessions.remove(&hash) else {
            return;
        };
        decrement_map(&mut state.sessions_per_ip, &client_ip);
        decrement_map(&mut state.sessions_per_profile, &profile_key);
        remember_closed_token_locked(
            &mut state,
            hash,
            profile_host,
            closed_token_lifetime,
            self.limits.max_sessions_global.saturating_mul(16),
        );
        let trace_session_id = session.trace_session_id();
        if state
            .session_index
            .get(&trace_session_id)
            .is_some_and(|index| index.session_hash == hash)
        {
            state.session_index.remove(&trace_session_id);
            remember_closed_session_locked(
                &mut state,
                trace_session_id,
                session.carrier_attempt(),
                closed_token_lifetime,
                self.limits.max_sessions_global,
            );
        }
        let bootstrap_hashes = state
            .bootstraps
            .iter()
            .filter_map(|(bootstrap_hash, bootstrap)| {
                bootstrap
                    .session
                    .as_ref()
                    .is_some_and(|session| session.token_hash() == hash)
                    .then_some(*bootstrap_hash)
            })
            .collect::<Vec<_>>();
        for bootstrap_hash in bootstrap_hashes {
            remove_bootstrap_locked(&mut state, bootstrap_hash);
        }
        self.telemetry.record_session_closed();
        drop(state);
        self.notify_operator_work_changed();
    }

    /// Closes every WEB authority gate before any graceful wait begins.
    pub(crate) fn begin_shutdown(self: &std::sync::Arc<Self>) -> WebShutdownDrain {
        let started = TokioInstant::now();
        self.close_operator_lifecycle();
        self.shutdown.cancel();
        self.close_control_submission_gate();
        self.close_websockets();
        self.data_budget.close();
        self.http_connections.close();
        self.http_overload_connections.close();
        self.http_handlers.close();
        self.lane_polls.close();
        self.lane_aux_polls.close();
        self.body_readers.close();
        self.body_bytes.close();
        self.stream_handshakes.close();
        self.websocket_connections.close();
        let sessions = {
            let mut state = self.state.lock();
            state.closed = true;
            state.bootstraps.clear();
            state.bootstraps_per_ip.clear();
            state.sessions.values().cloned().collect::<Vec<_>>()
        };
        self.stream_admission.lock().closed = true;
        for session in &sessions {
            session.close();
        }
        self.tasks.close();
        WebShutdownDrain {
            runtime: std::sync::Arc::clone(self),
            sessions,
            started,
        }
    }

    /// Stops issuance and drains all WEB work until one absolute deadline.
    pub(crate) async fn shutdown_until(
        self: &std::sync::Arc<Self>,
        deadline: TokioInstant,
    ) -> WebShutdownOutcome {
        self.begin_shutdown().wait_until(deadline).await
    }

    /// Stops issuance and drains WEB work under the currently configured budget.
    pub(crate) async fn shutdown(self: &std::sync::Arc<Self>) -> WebShutdownOutcome {
        let timeout_secs = self
            .active_runtime
            .load()
            .config()
            .web
            .timeouts
            .shutdown_secs;
        let now = TokioInstant::now();
        let deadline = now
            .checked_add(Duration::from_secs(timeout_secs))
            .unwrap_or(now);
        self.shutdown_until(deadline).await
    }

    /// Expires credentials and closes idle sessions without holding locks across callbacks.
    pub(super) fn cleanup(&self) {
        self.cleanup_websockets();
        let now = Instant::now();
        let generation = self.active_generation();
        let config = &generation.config().web;
        let learning_enabled = config.carrier_negotiation_enabled() && config.carrier_learning;
        let mut learning = self.learning.lock();
        let _ = learning.apply_policy(
            now,
            learning_enabled,
            config.carrier_negotiation_aggressiveness,
            Duration::from_secs(config.timeouts.carrier_learning_secs),
        );
        learning.prune(now);
        drop(learning);
        let (sessions, expired_chains) = {
            let mut state = self.state.lock();
            state.apply_issuance_policy(generation.id, config.enabled);
            let expired = state
                .bootstraps
                .iter()
                .filter_map(|(hash, bootstrap)| {
                    (bootstrap.carrier_phase == super::state::CarrierChainPhase::Provisional
                        && bootstrap
                            .carrier_deadline_at
                            .is_some_and(|deadline| now >= deadline)
                        && bootstrap
                            .session
                            .as_ref()
                            .is_some_and(|session| !session.is_carrier_committed()))
                    .then_some((*hash, bootstrap.session.clone()))
                })
                .collect::<Vec<_>>();
            let expired_chains = expired
                .iter()
                .filter_map(|(_, session)| session.clone())
                .collect::<Vec<_>>();
            for (hash, _) in expired {
                remove_bootstrap_locked(&mut state, hash);
            }
            remove_expired_locked(&mut state, now);
            (
                state.sessions.values().cloned().collect::<Vec<_>>(),
                expired_chains,
            )
        };
        for session in expired_chains {
            session.close();
        }
        for session in sessions {
            session.close_if_due(now);
        }
    }
}

impl WebShutdownDrain {
    /// Waits for frozen session ownership and process auxiliary tasks concurrently.
    pub(crate) async fn wait_until(self, deadline: TokioInstant) -> WebShutdownOutcome {
        let sessions = &self.sessions;
        let session_waits = async {
            for session in sessions {
                session.wait().await;
            }
        };
        let outcome = wait_for_drain(deadline, session_waits, self.runtime.tasks.wait()).await;
        self.log_outcome(outcome, deadline);
        outcome
    }

    fn log_outcome(&self, outcome: WebShutdownOutcome, deadline: TokioInstant) {
        let sessions_live = self.runtime.state.lock().sessions.len();
        let streams_live = self.runtime.stream_admission.lock().streams_live;
        let session_tasks_live = self.sessions.iter().fold(0usize, |total, session| {
            total.saturating_add(session.tasks_live())
        });
        let sessions_pending = self
            .sessions
            .iter()
            .filter(|session| session.tasks_live() != 0)
            .count();
        let auxiliary_tasks_live = self.runtime.tasks.len();
        let budget = self.runtime.data_budget.snapshot();
        let budget_ms = deadline
            .saturating_duration_since(self.started)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let elapsed_ms = TokioInstant::now()
            .saturating_duration_since(self.started)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let aggregates = self.runtime.telemetry.aggregates();
        match outcome {
            WebShutdownOutcome::Drained => info!(
                target: "telemt::web",
                shutdown_drained = true,
                shutdown_budget_ms = budget_ms,
                shutdown_elapsed_ms = elapsed_ms,
                sessions_created = aggregates.sessions_created,
                sessions_closed = aggregates.sessions_closed,
                sessions_live,
                sessions_pending,
                session_tasks_live,
                auxiliary_tasks_live,
                streams_opened = aggregates.streams_opened,
                streams_rejected = aggregates.streams_rejected,
                streams_live,
                pending_bytes = budget.queue_bytes,
                pending_items = budget.queue_items,
                websocket_bytes = budget.websocket_bytes,
                data_high_water_bytes = budget.high_water_bytes,
                bytes_up = aggregates.bytes_up,
                bytes_down = aggregates.bytes_down,
                limit_hits = aggregates.limit_hits,
                "WEB runtime stopped"
            ),
            WebShutdownOutcome::DeadlineExceeded => warn!(
                target: "telemt::web",
                shutdown_drained = false,
                shutdown_budget_ms = budget_ms,
                shutdown_elapsed_ms = elapsed_ms,
                sessions_created = aggregates.sessions_created,
                sessions_closed = aggregates.sessions_closed,
                sessions_live,
                sessions_pending,
                session_tasks_live,
                auxiliary_tasks_live,
                streams_opened = aggregates.streams_opened,
                streams_rejected = aggregates.streams_rejected,
                streams_live,
                pending_bytes = budget.queue_bytes,
                pending_items = budget.queue_items,
                websocket_bytes = budget.websocket_bytes,
                data_high_water_bytes = budget.high_water_bytes,
                bytes_up = aggregates.bytes_up,
                bytes_down = aggregates.bytes_down,
                limit_hits = aggregates.limit_hits,
                "WEB runtime shutdown deadline exceeded"
            ),
        }
    }
}

async fn wait_for_drain<S, T>(deadline: TokioInstant, sessions: S, tasks: T) -> WebShutdownOutcome
where
    S: std::future::Future<Output = ()>,
    T: std::future::Future<Output = ()>,
{
    let waits = async {
        tokio::join!(sessions, tasks);
    };
    if tokio::time::timeout_at(deadline, waits).await.is_ok() {
        WebShutdownOutcome::Drained
    } else {
        WebShutdownOutcome::DeadlineExceeded
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use arc_swap::ArcSwap;
    use tokio::sync::Notify;

    use super::*;
    use crate::config::ProxyConfig;
    use crate::maestro::generation::test_runtime_generation;
    use crate::web::manager::{CloseOperationSelector, ControlError};

    struct DropProbe {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Future for DropProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            Poll::Pending
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn runtime() -> (
        Arc<WebProcessRuntime>,
        Arc<crate::maestro::generation::RuntimeGeneration>,
    ) {
        let generation = test_runtime_generation(1, ProxyConfig::default());
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        (runtime, generation)
    }

    #[tokio::test(start_paused = true)]
    async fn drain_uses_one_absolute_deadline_for_both_wait_groups() {
        let started = TokioInstant::now();
        let outcome = wait_for_drain(
            started + Duration::from_secs(5),
            tokio::time::sleep(Duration::from_secs(4)),
            tokio::time::sleep(Duration::from_secs(9)),
        )
        .await;

        assert_eq!(outcome, WebShutdownOutcome::DeadlineExceeded);
        assert_eq!(TokioInstant::now() - started, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_returns_when_both_wait_groups_finish() {
        let started = TokioInstant::now();
        let outcome = wait_for_drain(
            started + Duration::from_secs(5),
            tokio::time::sleep(Duration::from_secs(3)),
            tokio::time::sleep(Duration::from_secs(2)),
        )
        .await;

        assert_eq!(outcome, WebShutdownOutcome::Drained);
        assert_eq!(TokioInstant::now() - started, Duration::from_secs(3));
    }

    #[tokio::test]
    async fn post_shutdown_auxiliary_is_dropped_without_polling() {
        let (runtime, generation) = runtime();
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let drain = runtime.begin_shutdown();

        runtime.spawn_auxiliary(DropProbe {
            polls: Arc::clone(&polls),
            drops: Arc::clone(&drops),
        });

        assert_eq!(polls.load(Ordering::Acquire), 0);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(
            drain
                .wait_until(TokioInstant::now() + Duration::from_secs(1))
                .await,
            WebShutdownOutcome::Drained
        );
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }

    #[tokio::test]
    async fn initial_trace_policy_is_attributed_to_active_generation() {
        let (runtime, generation) = runtime();

        assert_eq!(runtime.trace().status().policy_generation, generation.id);

        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }

    #[tokio::test]
    async fn shutdown_closes_the_control_submission_gate() {
        let (runtime, generation) = runtime();
        let drain = runtime.begin_shutdown();

        assert!(matches!(
            runtime.start_close_operation(
                runtime.runtime_instance(),
                CloseOperationSelector::Refs(vec![1]),
            ),
            Err(ControlError::Closed)
        ));
        assert!(matches!(
            runtime.reset_carrier_learning(),
            Err(crate::web::manager::ManagerError::Closed)
        ));
        assert!(matches!(runtime.clear_debug(), Err(ControlError::Closed)));
        assert_eq!(
            drain
                .wait_until(TokioInstant::now() + Duration::from_secs(1))
                .await,
            WebShutdownOutcome::Drained
        );
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }

    #[tokio::test(start_paused = true)]
    async fn expired_deadline_still_closes_every_runtime_gate() {
        let (runtime, generation) = runtime();
        let existing = runtime.try_http_connection().unwrap();
        let release = Arc::new(Notify::new());
        let release_task = Arc::clone(&release);
        runtime.tasks.spawn(async move {
            release_task.notified().await;
        });
        tokio::task::yield_now().await;
        let drain = runtime.begin_shutdown();

        assert_eq!(
            runtime.try_http_connection().unwrap_err(),
            super::super::HttpConnectionAdmissionError::Closed
        );
        assert!(runtime.try_http_handler().is_none());
        assert!(runtime.try_lane_poll(false).is_none());
        assert_eq!(
            drain.wait_until(TokioInstant::now()).await,
            WebShutdownOutcome::DeadlineExceeded
        );

        drop(existing);
        release.notify_waiters();
        runtime.tasks.wait().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
