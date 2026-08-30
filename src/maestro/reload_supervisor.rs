use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::stats::QuotaStore;
use crate::tls_front::cache::TlsFullCertBudget;
use crate::web::trace::WebTraceStore;

use super::generation::{RuntimeGeneration, RuntimeWatchState};
use super::listeners::{ListenerManager, PreparedListenerTransition};
use super::reload::{
    ReloadCommand, ReloadCommandReceiver, ReloadControl, ReloadFailurePolicy, ReloadMode,
    ReloadPhase,
};
use super::runtime_build::{PreparedRuntime, prepare_runtime, resolve_reload_config};
use super::runtime_tasks::RuntimeLogFilter;

pub(crate) struct ReloadSupervisor {
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    control: ReloadControl,
    commands: ReloadCommandReceiver,
    config_path: PathBuf,
    quota_store: Arc<QuotaStore>,
    tls_full_cert_budget: Arc<TlsFullCertBudget>,
    detected_ips_tx: watch::Sender<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
    runtime_log_filter: RuntimeLogFilter,
    runtime_watch_tx: watch::Sender<Option<RuntimeWatchState>>,
    listener_manager: Arc<Mutex<ListenerManager>>,
    web_trace: Arc<WebTraceStore>,
}

/// Process-owned handle that quiesces reloads before shutdown snapshots the runtime.
pub(crate) struct ReloadSupervisorHandle {
    control: ReloadControl,
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
    listener_manager: Arc<Mutex<ListenerManager>>,
}

impl ReloadSupervisorHandle {
    /// Stops new submissions and waits for the accepted reload to finish.
    pub(crate) async fn quiesce(self) -> Arc<Mutex<ListenerManager>> {
        self.control.begin_shutdown().await;
        self.shutdown.cancel();
        if let Err(error) = self.join.await {
            warn!(error = %error, "Reload supervisor failed while quiescing");
        }
        self.listener_manager
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RevisionGateAction {
    Proceed,
    Warn(String),
    Rollback(String),
}

fn revision_gate_action(
    accepted_revision: &str,
    current_revision: Result<String, String>,
    failure_policy: ReloadFailurePolicy,
) -> RevisionGateAction {
    let warning = match current_revision {
        Ok(current) if current == accepted_revision => return RevisionGateAction::Proceed,
        Ok(current) => format!(
            "config revision changed during preparation: accepted={} current={}",
            accepted_revision, current
        ),
        Err(error) => format!("config revision verification failed: {}", error),
    };
    match failure_policy {
        ReloadFailurePolicy::KeepNew => RevisionGateAction::Warn(warning),
        ReloadFailurePolicy::Rollback => RevisionGateAction::Rollback(warning),
    }
}

async fn stop_background_and_middle_end(generation: &RuntimeGeneration) -> bool {
    generation.stop_background_tasks().await;
    !generation.stop_middle_end(Duration::from_secs(5)).await
}

async fn cleanup_candidate(generation: &RuntimeGeneration) -> bool {
    generation.stop_sessions().await;
    stop_background_and_middle_end(generation).await
}

impl ReloadSupervisor {
    #[allow(clippy::too_many_arguments)]
    /// Starts the process-scoped reload supervisor and returns its shutdown owner.
    pub(crate) fn spawn(
        active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
        control: ReloadControl,
        commands: ReloadCommandReceiver,
        config_path: PathBuf,
        quota_store: Arc<QuotaStore>,
        tls_full_cert_budget: Arc<TlsFullCertBudget>,
        detected_ips_tx: watch::Sender<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
        runtime_log_filter: RuntimeLogFilter,
        runtime_watch_tx: watch::Sender<Option<RuntimeWatchState>>,
        listener_manager: ListenerManager,
        web_trace: Arc<WebTraceStore>,
    ) -> ReloadSupervisorHandle {
        let listener_manager = Arc::new(Mutex::new(listener_manager));
        let supervisor = Self {
            active_runtime,
            control,
            commands,
            config_path,
            quota_store,
            tls_full_cert_budget,
            detected_ips_tx,
            runtime_log_filter,
            runtime_watch_tx,
            listener_manager: listener_manager.clone(),
            web_trace,
        };
        let control = supervisor.control.clone();
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(supervisor.run(shutdown.clone()));
        ReloadSupervisorHandle {
            control,
            shutdown,
            join,
            listener_manager,
        }
    }

    async fn run(mut self, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    if self.control.in_progress().await.is_some()
                        && let Some(command) = self.commands.recv().await
                    {
                        self.reload(command).await;
                    }
                    break;
                }
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    self.reload(command).await;
                }
            }
        }
    }

    async fn reload(&self, command: ReloadCommand) {
        self.control
            .mark_phase(command.reload_id, ReloadPhase::Preparing)
            .await;
        let old_runtime = self.active_runtime.load_full();
        let resolved = resolve_reload_config(&old_runtime.config(), &command.config);
        self.control
            .set_deferred_fields(command.reload_id, resolved.deferred_process_fields.clone())
            .await;

        let prepared = match prepare_runtime(
            command.target_generation,
            resolved.effective,
            &self.config_path,
            self.quota_store.clone(),
            self.runtime_log_filter.clone(),
            self.tls_full_cert_budget.clone(),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                self.control.fail(command.reload_id, error).await;
                return;
            }
        };

        let listener_transition = match self
            .listener_manager
            .lock()
            .await
            .prepare_transition(prepared.generation.config().as_ref())
        {
            Ok(transition) => transition,
            Err(error) => {
                let _ = cleanup_candidate(&prepared.generation).await;
                self.runtime_log_filter
                    .apply_reload(&old_runtime.config().general.log_level);
                self.control.fail(command.reload_id, error).await;
                return;
            }
        };
        let revision_action = revision_gate_action(
            &command.config_revision,
            crate::api::config_store::current_revision_for_maestro(&self.config_path).await,
            command.request.failure_policy,
        );
        self.activate_prepared_with_transition(
            command,
            old_runtime,
            prepared,
            listener_transition,
            revision_action,
        )
        .await;
    }

    #[cfg(test)]
    async fn activate_prepared(
        &self,
        command: ReloadCommand,
        old_runtime: Arc<RuntimeGeneration>,
        prepared: PreparedRuntime,
        revision_action: RevisionGateAction,
    ) {
        let listener_transition = match self
            .listener_manager
            .lock()
            .await
            .prepare_transition(prepared.generation.config().as_ref())
        {
            Ok(transition) => transition,
            Err(error) => {
                let _ = cleanup_candidate(&prepared.generation).await;
                self.control.fail(command.reload_id, error).await;
                return;
            }
        };
        self.activate_prepared_with_transition(
            command,
            old_runtime,
            prepared,
            listener_transition,
            revision_action,
        )
        .await;
    }

    async fn activate_prepared_with_transition(
        &self,
        command: ReloadCommand,
        old_runtime: Arc<RuntimeGeneration>,
        prepared: PreparedRuntime,
        listener_transition: Option<PreparedListenerTransition>,
        revision_action: RevisionGateAction,
    ) {
        match revision_action {
            RevisionGateAction::Proceed => {}
            RevisionGateAction::Warn(warning) => {
                self.control.add_warning(command.reload_id, warning).await;
            }
            RevisionGateAction::Rollback(warning) => {
                let _ = cleanup_candidate(&prepared.generation).await;
                self.runtime_log_filter
                    .apply_reload(&old_runtime.config().general.log_level);
                self.control.rolled_back(command.reload_id, warning).await;
                return;
            }
        }

        self.control
            .mark_phase(command.reload_id, ReloadPhase::Activating)
            .await;
        let PreparedRuntime {
            generation: new_runtime,
            detected_ips,
            config_watcher_activation,
        } = prepared;
        let pending_listener_transition = if let Some(listener_transition) = listener_transition {
            match self
                .listener_manager
                .lock()
                .await
                .begin_transition(listener_transition)
                .await
            {
                Ok(pending) => Some(pending),
                Err(error) => {
                    let _ = cleanup_candidate(&new_runtime).await;
                    self.runtime_log_filter
                        .apply_reload(&old_runtime.config().general.log_level);
                    self.control.fail(command.reload_id, error).await;
                    return;
                }
            }
        } else {
            None
        };
        old_runtime.stop_accepting_sessions();
        let replaced = self.active_runtime.swap(new_runtime.clone());
        self.web_trace
            .apply_policy(new_runtime.id, &new_runtime.config().web.debug);
        config_watcher_activation.send_replace(true);
        if let Some(pending) = pending_listener_transition {
            self.listener_manager
                .lock()
                .await
                .finish_transition(pending);
        }
        self.detected_ips_tx.send_replace(detected_ips);
        self.runtime_log_filter
            .apply_reload(&new_runtime.config().general.log_level);
        self.runtime_watch_tx
            .send_replace(Some(new_runtime.watch_state()));

        info!(
            reload_id = command.reload_id,
            old_generation = replaced.id,
            new_generation = new_runtime.id,
            config_revision = %command.config_revision,
            "Runtime generation activated"
        );

        match command.request.mode {
            ReloadMode::Instant => {
                replaced.stop_sessions().await;
            }
            ReloadMode::Drain => {
                self.control
                    .mark_phase(command.reload_id, ReloadPhase::Draining)
                    .await;
                let timeout = Duration::from_secs(
                    command
                        .request
                        .timeout_secs
                        .expect("validated drain request must carry timeout_secs"),
                );
                if !replaced.drain_sessions(timeout).await {
                    let warning = format!(
                        "generation {} exceeded drain timeout; remaining sessions were cancelled",
                        replaced.id
                    );
                    warn!(reload_id = command.reload_id, warning = %warning);
                    self.control.add_warning(command.reload_id, warning).await;
                }
            }
        }

        if stop_background_and_middle_end(&replaced).await {
            let warning = format!(
                "generation {} Middle-End lifecycle shutdown timed out",
                replaced.id
            );
            warn!(reload_id = command.reload_id, warning = %warning);
            self.control.add_warning(command.reload_id, warning).await;
        }
        self.control
            .succeed(command.reload_id, new_runtime.id)
            .await;
    }
}

#[cfg(test)]
#[path = "reload_supervisor_tests.rs"]
mod tests;
