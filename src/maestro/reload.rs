use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc};

use crate::config::ProxyConfig;

const RELOAD_HISTORY_CAPACITY: usize = 32;
const RELOAD_COMMAND_CAPACITY: usize = 1;
const MAX_DRAIN_TIMEOUT_SECS: u64 = 3_600;

/// Session handling policy for an in-process runtime reload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReloadMode {
    #[default]
    Instant,
    Drain,
}

/// Failure policy applied during the activation barrier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReloadFailurePolicy {
    #[default]
    KeepNew,
    Rollback,
}

/// Request body accepted by the maestro reload endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReloadRequest {
    #[serde(default)]
    pub(crate) mode: ReloadMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) timeout_secs: Option<u64>,
    #[serde(default)]
    pub(crate) failure_policy: ReloadFailurePolicy,
}

impl ReloadRequest {
    /// Validates mode-specific request parameters.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        match (self.mode, self.timeout_secs) {
            (ReloadMode::Instant, None) => Ok(()),
            (ReloadMode::Instant, Some(_)) => Err("timeout_secs is only valid when mode is drain"),
            (ReloadMode::Drain, Some(1..=MAX_DRAIN_TIMEOUT_SECS)) => Ok(()),
            (ReloadMode::Drain, Some(_)) => Err("timeout_secs must be within 1..=3600"),
            (ReloadMode::Drain, None) => Err("timeout_secs is required when mode is drain"),
        }
    }

    /// Parses optional PATCH query parameters into a reload request.
    pub(crate) fn from_query(query: Option<&str>) -> Result<Option<Self>, String> {
        let Some(query) = query.filter(|query| !query.is_empty()) else {
            return Ok(None);
        };
        let mut mode = None;
        let mut timeout_secs = None;
        let mut failure_policy = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "reload" if mode.is_none() => {
                    mode = Some(match value.as_ref() {
                        "instant" => ReloadMode::Instant,
                        "drain" => ReloadMode::Drain,
                        _ => return Err("reload must be instant or drain".to_string()),
                    });
                }
                "timeout_secs" if timeout_secs.is_none() => {
                    timeout_secs = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "timeout_secs must be an integer".to_string())?,
                    );
                }
                "failure_policy" if failure_policy.is_none() => {
                    failure_policy = Some(match value.as_ref() {
                        "keep_new" => ReloadFailurePolicy::KeepNew,
                        "rollback" => ReloadFailurePolicy::Rollback,
                        _ => {
                            return Err("failure_policy must be keep_new or rollback".to_string());
                        }
                    });
                }
                "reload" | "timeout_secs" | "failure_policy" => {
                    return Err(format!("duplicate query parameter: {}", key));
                }
                _ => return Err(format!("unknown query parameter: {}", key)),
            }
        }
        let mode = mode.ok_or_else(|| "reload query parameter is required".to_string())?;
        let request = Self {
            mode,
            timeout_secs,
            failure_policy: failure_policy.unwrap_or_default(),
        };
        request.validate().map_err(str::to_string)?;
        Ok(Some(request))
    }
}

/// Observable phase of one reload operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReloadPhase {
    Accepted,
    Preparing,
    Activating,
    Draining,
    Succeeded,
    RolledBack,
    Failed,
}

impl ReloadPhase {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            ReloadPhase::Succeeded | ReloadPhase::RolledBack | ReloadPhase::Failed
        )
    }
}

/// Bounded public status for one reload operation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReloadStatus {
    pub(crate) reload_id: u64,
    pub(crate) target_generation: u64,
    pub(crate) config_revision: String,
    pub(crate) state: ReloadPhase,
    pub(crate) mode: ReloadMode,
    pub(crate) failure_policy: ReloadFailurePolicy,
    pub(crate) requested_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) started_at_epoch_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finished_at_epoch_secs: Option<u64>,
    #[serde(
        rename = "deferred_process_fields",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub(crate) deferred_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// Accepted operation metadata returned before asynchronous preparation starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ReloadAccepted {
    pub(crate) reload_id: u64,
    pub(crate) target_generation: u64,
    pub(crate) config_revision: String,
    pub(crate) state: ReloadPhase,
    pub(crate) mode: ReloadMode,
    pub(crate) failure_policy: ReloadFailurePolicy,
}

pub(crate) struct ReloadCommand {
    pub(crate) reload_id: u64,
    pub(crate) target_generation: u64,
    pub(crate) config: Arc<ProxyConfig>,
    pub(crate) config_revision: String,
    pub(crate) request: ReloadRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadSubmitError {
    InProgress(u64),
    MaestroUnavailable,
}

#[derive(Clone)]
pub(crate) struct ReloadControl {
    command_tx: mpsc::Sender<ReloadCommand>,
    status_store: Arc<ReloadStatusStore>,
    active_generation: Arc<AtomicU64>,
}

pub(crate) struct ReloadCommandReceiver {
    command_rx: mpsc::Receiver<ReloadCommand>,
}

struct ReloadStatusState {
    next_reload_id: u64,
    active_reload_id: Option<u64>,
    statuses: VecDeque<ReloadStatus>,
    accepting_commands: bool,
}

impl Default for ReloadStatusState {
    fn default() -> Self {
        Self {
            next_reload_id: 0,
            active_reload_id: None,
            statuses: VecDeque::new(),
            accepting_commands: true,
        }
    }
}

#[derive(Default)]
struct ReloadStatusStore {
    state: Mutex<ReloadStatusState>,
}

impl ReloadControl {
    /// Creates the process-scoped coordinator channel and status store.
    pub(crate) fn channel(initial_generation: u64) -> (Self, ReloadCommandReceiver) {
        let (command_tx, command_rx) = mpsc::channel(RELOAD_COMMAND_CAPACITY);
        (
            Self {
                command_tx,
                status_store: Arc::new(ReloadStatusStore::default()),
                active_generation: Arc::new(AtomicU64::new(initial_generation)),
            },
            ReloadCommandReceiver { command_rx },
        )
    }

    /// Atomically reserves and enqueues one reload operation.
    pub(crate) async fn submit(
        &self,
        config: Arc<ProxyConfig>,
        config_revision: String,
        request: ReloadRequest,
    ) -> Result<ReloadAccepted, ReloadSubmitError> {
        let target_generation = self
            .active_generation
            .load(Ordering::Acquire)
            .saturating_add(1);
        let status = self
            .status_store
            .reserve(target_generation, config_revision, request.clone())
            .await?;
        let command = ReloadCommand {
            reload_id: status.reload_id,
            target_generation,
            config,
            config_revision: status.config_revision.clone(),
            request,
        };
        if self.command_tx.try_send(command).is_err() {
            self.status_store
                .finish(
                    status.reload_id,
                    ReloadPhase::Failed,
                    Some("maestro command channel is closed".to_string()),
                )
                .await;
            return Err(ReloadSubmitError::MaestroUnavailable);
        }
        Ok(ReloadAccepted {
            reload_id: status.reload_id,
            target_generation,
            config_revision: status.config_revision,
            state: ReloadPhase::Accepted,
            mode: status.mode,
            failure_policy: status.failure_policy,
        })
    }

    /// Returns a retained reload status by identifier.
    pub(crate) async fn status(&self, reload_id: u64) -> Option<ReloadStatus> {
        self.status_store.get(reload_id).await
    }

    /// Returns the identifier of the currently active reload.
    pub(crate) async fn in_progress(&self) -> Option<u64> {
        self.status_store.state.lock().await.active_reload_id
    }

    /// Rejects new commands while preserving an already accepted operation.
    pub(crate) async fn begin_shutdown(&self) {
        self.status_store.state.lock().await.accepting_commands = false;
    }

    /// Records a non-terminal lifecycle phase.
    pub(crate) async fn mark_phase(&self, reload_id: u64, phase: ReloadPhase) {
        self.status_store.mark_phase(reload_id, phase).await;
    }

    /// Records process-owned fields deferred until the next process restart.
    pub(crate) async fn set_deferred_fields(&self, reload_id: u64, fields: Vec<String>) {
        self.status_store
            .update(reload_id, |status| status.deferred_fields = fields)
            .await;
    }

    /// Commits the active generation and completes the matching reload.
    pub(crate) async fn succeed(&self, reload_id: u64, generation: u64) {
        self.status_store
            .finish_success(reload_id, generation, &self.active_generation)
            .await;
    }

    /// Marks the matching reload as failed.
    pub(crate) async fn fail(&self, reload_id: u64, error: impl Into<String>) {
        self.status_store
            .finish(reload_id, ReloadPhase::Failed, Some(error.into()))
            .await;
    }

    /// Marks the matching reload as rolled back.
    pub(crate) async fn rolled_back(&self, reload_id: u64, error: impl Into<String>) {
        self.status_store
            .finish(reload_id, ReloadPhase::RolledBack, Some(error.into()))
            .await;
    }

    /// Appends a non-fatal warning to the matching reload status.
    pub(crate) async fn add_warning(&self, reload_id: u64, warning: impl Into<String>) {
        let warning = warning.into();
        self.status_store
            .update(reload_id, |status| status.warnings.push(warning))
            .await;
    }
}

impl ReloadCommandReceiver {
    /// Receives the next accepted reload command.
    pub(crate) async fn recv(&mut self) -> Option<ReloadCommand> {
        self.command_rx.recv().await
    }
}

impl ReloadStatusStore {
    async fn reserve(
        &self,
        target_generation: u64,
        config_revision: String,
        request: ReloadRequest,
    ) -> Result<ReloadStatus, ReloadSubmitError> {
        let mut state = self.state.lock().await;
        if !state.accepting_commands {
            return Err(ReloadSubmitError::MaestroUnavailable);
        }
        if let Some(reload_id) = state.active_reload_id {
            return Err(ReloadSubmitError::InProgress(reload_id));
        }
        state.next_reload_id = state.next_reload_id.saturating_add(1).max(1);
        let reload_id = state.next_reload_id;
        let status = ReloadStatus {
            reload_id,
            target_generation,
            config_revision,
            state: ReloadPhase::Accepted,
            mode: request.mode,
            failure_policy: request.failure_policy,
            requested_at_epoch_secs: now_epoch_secs(),
            started_at_epoch_secs: None,
            finished_at_epoch_secs: None,
            deferred_fields: Vec::new(),
            warnings: Vec::new(),
            error: None,
        };
        state.active_reload_id = Some(reload_id);
        state.statuses.push_back(status.clone());
        while state.statuses.len() > RELOAD_HISTORY_CAPACITY {
            state.statuses.pop_front();
        }
        Ok(status)
    }

    async fn get(&self, reload_id: u64) -> Option<ReloadStatus> {
        self.state
            .lock()
            .await
            .statuses
            .iter()
            .find(|status| status.reload_id == reload_id)
            .cloned()
    }

    async fn mark_phase(&self, reload_id: u64, phase: ReloadPhase) {
        self.update(reload_id, |status| {
            status.state = phase;
            if status.started_at_epoch_secs.is_none() && phase != ReloadPhase::Accepted {
                status.started_at_epoch_secs = Some(now_epoch_secs());
            }
        })
        .await;
    }

    async fn finish(&self, reload_id: u64, phase: ReloadPhase, error: Option<String>) {
        debug_assert!(phase.is_terminal());
        let mut state = self.state.lock().await;
        if let Some(status) = state
            .statuses
            .iter_mut()
            .find(|status| status.reload_id == reload_id)
        {
            status.state = phase;
            status.error = error;
            status.finished_at_epoch_secs = Some(now_epoch_secs());
        }
        if state.active_reload_id == Some(reload_id) {
            state.active_reload_id = None;
        }
    }

    async fn finish_success(&self, reload_id: u64, generation: u64, active_generation: &AtomicU64) {
        let mut state = self.state.lock().await;
        if state.active_reload_id != Some(reload_id) {
            return;
        }
        let Some(status) = state
            .statuses
            .iter_mut()
            .find(|status| status.reload_id == reload_id)
        else {
            return;
        };
        status.state = ReloadPhase::Succeeded;
        status.error = None;
        status.finished_at_epoch_secs = Some(now_epoch_secs());
        active_generation.store(generation, Ordering::Release);
        state.active_reload_id = None;
    }

    async fn update(&self, reload_id: u64, update: impl FnOnce(&mut ReloadStatus)) {
        let mut state = self.state.lock().await;
        if let Some(status) = state
            .statuses
            .iter_mut()
            .find(|status| status.reload_id == reload_id)
        {
            update(status);
        }
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
#[path = "reload_tests.rs"]
mod tests;
