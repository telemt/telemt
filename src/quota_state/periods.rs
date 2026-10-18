use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use super::{QuotaStateOwner, now_epoch_secs, wait_for_blocking_io, write_state_file_blocking};
use crate::config::ProxyConfig;
use crate::maestro::control_plane::ProcessControlPlane;
use crate::stats::{QuotaScheduleStatus, UserQuotaSnapshot};

impl QuotaStateOwner {
    /// Exposes the same control-plane gate used by account lifecycle transitions.
    pub(crate) async fn lock(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.mutation).lock_owned().await
    }

    /// Loads legacy files tolerantly; scheduled policies require trustworthy state.
    pub(crate) async fn load_for_config(&self, config: &ProxyConfig) -> std::io::Result<()> {
        self.load_inner(
            &config.access.users.keys().cloned().collect(),
            !config.access.user_quota_periods.is_empty(),
        )
        .await
    }

    /// Fences first calendar attachment for an API-created account.
    pub(crate) fn fence_fresh_schedule(
        &self,
        user: &str,
        source: &Arc<ProxyConfig>,
        credential: crate::proxy::user_admission::UserCredentialId,
        period: Option<crate::config::UserQuotaPeriod>,
        quota: Option<u64>,
    ) {
        self.store
            .fence_fresh_schedule(user, source, credential, period, quota);
    }

    /// Retains first-attachment fencing through API edits and secret rotation.
    pub(crate) fn refresh_fresh_schedule(&self, user: &str, config: &ProxyConfig) {
        self.store.refresh_fresh_schedule(user, config);
    }

    /// Captures API status under the caller's mutation guard.
    pub(crate) fn schedule_status(
        &self,
        user: &str,
        desired: Option<crate::config::UserQuotaPeriod>,
    ) -> QuotaScheduleStatus {
        self.store.schedule_status(user, desired, now_epoch_secs())
    }

    /// Checkpoints a bounded batch before publishing any reset or calendar metadata.
    pub(crate) async fn process_schedules(
        &self,
        now: u64,
        force_save: bool,
    ) -> std::io::Result<()> {
        let guard = self.lock().await;
        self.process_schedules_locked(now, force_save, guard).await
    }

    async fn process_schedules_locked(
        &self,
        now: u64,
        force_save: bool,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> std::io::Result<()> {
        if !force_save && !self.store.schedule_ready(now) {
            return Ok(());
        }
        let changes = self.store.schedule_changes(now)?;
        let configured_users = self.store.configured_quota_users();
        let mut state = self.state_for_users(&configured_users, None);
        for change in &changes {
            let quota = if change.reset {
                UserQuotaSnapshot {
                    used_bytes: 0,
                    last_reset_epoch_secs: now,
                }
            } else {
                change.target.snapshot()
            };
            let mut entry = super::quota_user_state(quota);
            entry.schedule = change.checkpoint;
            state.users.insert(change.user.clone(), entry);
        }
        state.last_reset_epoch_secs = state
            .users
            .values()
            .map(|entry| entry.last_reset_epoch_secs)
            .max()
            .unwrap_or(0);
        let path = self.path.clone();
        let store = Arc::clone(&self.store);
        let task = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            if let Err(error) = write_state_file_blocking(&path, &state) {
                store.schedule_failed(&changes);
                return Err(error);
            }
            let reset_count = changes.iter().filter(|change| change.reset).count();
            for change in &changes {
                store.publish_schedule(change, now);
            }
            store.schedule_saved();
            if reset_count > 0 {
                info!(users = reset_count, "Completed scheduled quota reset batch");
            }
            Ok(())
        });
        wait_for_blocking_io(task).await
    }

    /// Owns one worker across runtime generations; accepted commits finish on shutdown.
    pub(crate) fn spawn_scheduler(self: &Arc<Self>, control: &ProcessControlPlane) {
        let owner = Arc::clone(self);
        let _ = control.spawn_cooperative(move |cancel| async move {
            let mut retry = 1u64;
            let mut retry_at = None;
            let mut last_warning: Option<tokio::time::Instant> = None;
            loop {
                #[cfg(test)]
                owner.scheduler_iterations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if cancel.is_cancelled() { break; }
                let now = now_epoch_secs();
                let can_retry = retry_at.is_none_or(|at| tokio::time::Instant::now() >= at);
                if can_retry && owner.store.schedule_ready(now) {
                    // Cancellation can discard waiting work, but never an accepted commit.
                    let guard = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        guard = owner.lock() => guard,
                    };
                    if let Err(error) = owner.process_schedules_locked(now_epoch_secs(), false, guard).await {
                        let instant = tokio::time::Instant::now();
                        if last_warning.is_none_or(|at| instant.duration_since(at) >= Duration::from_secs(60)) {
                            warn!(error = %error, "Quota schedule checkpoint failed; usage remains unchanged");
                            last_warning = Some(instant);
                        }
                        retry_at = Some(instant + Duration::from_secs(retry));
                        retry = (retry * 2).min(60);
                    } else {
                        if retry_at.is_some() { info!("Quota schedule persistence recovered"); }
                        retry_at = None;
                        retry = 1;
                        last_warning = None;
                    }
                    continue;
                }
                // A manual reset or policy removal may resolve the failed work.
                // An expired retry must never turn an idle worker into sleep(0) polling.
                if can_retry && !owner.store.schedule_ready(now) {
                    retry_at = None;
                    retry = 1;
                    last_warning = None;
                }
                let delay = retry_at.map(|at| at.saturating_duration_since(tokio::time::Instant::now()))
                    .or_else(|| owner.store.schedule_deadline().map(|at| Duration::from_secs(at.saturating_sub(now).min(1))));
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = owner.store.schedule_notified() => {},
                    _ = async {
                        match delay {
                            Some(duration) => tokio::time::sleep(duration).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {},
                }
            }
        });
    }
}
