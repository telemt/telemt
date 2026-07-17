use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::stats::QuotaStore;

use super::generation::RuntimeGeneration;
use super::reload::{
    ReloadCommand, ReloadCommandReceiver, ReloadControl, ReloadFailurePolicy, ReloadMode,
    ReloadPhase,
};
use super::runtime_build::{deferred_process_fields, prepare_runtime};
use super::runtime_tasks::RuntimeLogFilter;

pub(crate) struct ReloadSupervisor {
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    control: ReloadControl,
    commands: ReloadCommandReceiver,
    config_path: PathBuf,
    quota_store: Arc<QuotaStore>,
    detected_ips_tx: watch::Sender<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
    runtime_log_filter: RuntimeLogFilter,
}

impl ReloadSupervisor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
        control: ReloadControl,
        commands: ReloadCommandReceiver,
        config_path: PathBuf,
        quota_store: Arc<QuotaStore>,
        detected_ips_tx: watch::Sender<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
        runtime_log_filter: RuntimeLogFilter,
    ) {
        let supervisor = Self {
            active_runtime,
            control,
            commands,
            config_path,
            quota_store,
            detected_ips_tx,
            runtime_log_filter,
        };
        tokio::spawn(supervisor.run());
    }

    async fn run(mut self) {
        while let Some(command) = self.commands.recv().await {
            self.reload(command).await;
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

        if let Ok(current_revision) =
            crate::api::config_store::current_revision_for_maestro(&self.config_path).await
            && current_revision != command.config_revision
        {
            let warning = format!(
                "config revision changed during preparation: accepted={} current={}",
                command.config_revision, current_revision
            );
            if command.request.failure_policy == ReloadFailurePolicy::Rollback {
                self.runtime_log_filter
                    .apply_reload(&old_runtime.config().general.log_level);
                prepared.generation.stop_sessions().await;
                if let Some(pool) = prepared.generation.current_me_pool().await {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        pool.shutdown_send_close_conn_all(),
                    )
                    .await;
                }
                prepared.generation.stop_background_tasks().await;
                self.control.rolled_back(command.reload_id, warning).await;
                return;
            }
            self.control.add_warning(command.reload_id, warning).await;
        }

        self.control
            .mark_phase(command.reload_id, ReloadPhase::Activating)
            .await;
        let new_runtime = prepared.generation;
        old_runtime.stop_accepting_sessions();
        let replaced = self.active_runtime.swap(new_runtime.clone());
        if let Err(error) = crate::network::dns_overrides::install_entries(
            &new_runtime.config().network.dns_overrides,
        ) {
            let message = format!("runtime DNS activation failed: {}", error);
            if command.request.failure_policy == ReloadFailurePolicy::Rollback {
                let candidate = self.active_runtime.swap(replaced.clone());
                replaced.resume_accepting_sessions();
                self.runtime_log_filter
                    .apply_reload(&replaced.config().general.log_level);
                let _ = crate::network::dns_overrides::install_entries(
                    &replaced.config().network.dns_overrides,
                );
                candidate.stop_sessions().await;
                if let Some(pool) = candidate.current_me_pool().await {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        pool.shutdown_send_close_conn_all(),
                    )
                    .await;
                }
                candidate.stop_background_tasks().await;
                self.control.rolled_back(command.reload_id, message).await;
                return;
            }
            self.control.add_warning(command.reload_id, message).await;
        }
        self.detected_ips_tx.send_replace(prepared.detected_ips);
        self.runtime_log_filter
            .apply_reload(&new_runtime.config().general.log_level);
        crate::synlimit_control::reconcile_synlimit_rules(&new_runtime.config()).await;

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

        if let Some(pool) = replaced.current_me_pool().await
            && tokio::time::timeout(Duration::from_secs(2), pool.shutdown_send_close_conn_all())
                .await
                .is_err()
        {
            let warning = format!(
                "generation {} Middle-End close broadcast timed out",
                replaced.id
            );
            warn!(reload_id = command.reload_id, warning = %warning);
            self.control.add_warning(command.reload_id, warning).await;
        }
        replaced.stop_background_tasks().await;
        self.control
            .succeed(command.reload_id, new_runtime.id)
            .await;
    }
}
