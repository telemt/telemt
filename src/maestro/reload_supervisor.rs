use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::stats::QuotaStore;

use super::generation::{RuntimeGeneration, RuntimeWatchState};
use super::reload::{
    ReloadCommand, ReloadCommandReceiver, ReloadControl, ReloadFailurePolicy, ReloadMode,
    ReloadPhase,
};
use super::runtime_build::{PreparedRuntime, deferred_process_fields, prepare_runtime};
use super::runtime_tasks::RuntimeLogFilter;

pub(crate) struct ReloadSupervisor {
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    control: ReloadControl,
    commands: ReloadCommandReceiver,
    config_path: PathBuf,
    quota_store: Arc<QuotaStore>,
    detected_ips_tx: watch::Sender<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
    runtime_log_filter: RuntimeLogFilter,
    runtime_watch_tx: watch::Sender<Option<RuntimeWatchState>>,
}

/// Process-owned handle that quiesces reloads before shutdown snapshots the runtime.
pub(crate) struct ReloadSupervisorHandle {
    control: ReloadControl,
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl ReloadSupervisorHandle {
    /// Stops new submissions and waits for the accepted reload to finish.
    pub(crate) async fn quiesce(self) {
        self.control.begin_shutdown().await;
        self.shutdown.cancel();
        if let Err(error) = self.join.await {
            warn!(error = %error, "Reload supervisor failed while quiescing");
        }
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
    let Some(pool) = generation.current_me_pool().await else {
        return false;
    };
    tokio::time::timeout(Duration::from_secs(2), pool.shutdown_send_close_conn_all())
        .await
        .is_err()
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
        detected_ips_tx: watch::Sender<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
        runtime_log_filter: RuntimeLogFilter,
        runtime_watch_tx: watch::Sender<Option<RuntimeWatchState>>,
    ) -> ReloadSupervisorHandle {
        let supervisor = Self {
            active_runtime,
            control,
            commands,
            config_path,
            quota_store,
            detected_ips_tx,
            runtime_log_filter,
            runtime_watch_tx,
        };
        let control = supervisor.control.clone();
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(supervisor.run(shutdown.clone()));
        ReloadSupervisorHandle {
            control,
            shutdown,
            join,
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
        let deferred = deferred_process_fields(&old_runtime.config(), &command.config);
        self.control
            .set_deferred_fields(command.reload_id, deferred)
            .await;

        let prepared = match prepare_runtime(
            command.target_generation,
            command.config.as_ref().clone(),
            &self.config_path,
            self.quota_store.clone(),
            self.runtime_log_filter.clone(),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                self.control.fail(command.reload_id, error).await;
                return;
            }
        };

        let revision_action = revision_gate_action(
            &command.config_revision,
            crate::api::config_store::current_revision_for_maestro(&self.config_path).await,
            command.request.failure_policy,
        );
        self.activate_prepared(command, old_runtime, prepared, revision_action, |entries| {
            crate::network::dns_overrides::install_entries(entries)
                .map_err(|error| error.to_string())
        })
        .await;
    }

    async fn activate_prepared<InstallDns>(
        &self,
        command: ReloadCommand,
        old_runtime: Arc<RuntimeGeneration>,
        prepared: PreparedRuntime,
        revision_action: RevisionGateAction,
        install_dns: InstallDns,
    ) where
        InstallDns: FnOnce(&[String]) -> Result<(), String>,
    {
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
        let new_runtime = prepared.generation;
        old_runtime.stop_accepting_sessions();
        if let Err(error) = install_dns(&new_runtime.config().network.dns_overrides) {
            let message = format!("runtime DNS activation failed: {}", error);
            if command.request.failure_policy == ReloadFailurePolicy::Rollback {
                old_runtime.resume_accepting_sessions();
                let _ = cleanup_candidate(&new_runtime).await;
                self.runtime_log_filter
                    .apply_reload(&old_runtime.config().general.log_level);
                self.control.rolled_back(command.reload_id, message).await;
                return;
            }
            self.control.add_warning(command.reload_id, message).await;
        }
        let replaced = self.active_runtime.swap(new_runtime.clone());
        self.detected_ips_tx.send_replace(prepared.detected_ips);
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
                "generation {} Middle-End close broadcast timed out",
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
