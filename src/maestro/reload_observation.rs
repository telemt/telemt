use serde::Serialize;

use super::{ReloadControl, ReloadPhase};

/// Sanitized owner snapshot. Raw reload errors/warnings can contain source data.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReloadObservation {
    pub(crate) reload_id: u64,
    pub(crate) target_generation: u64,
    pub(crate) source_revision: String,
    pub(crate) phase: ReloadPhase,
    pub(crate) source_generation: Option<u64>,
    pub(crate) activated_generation: Option<u64>,
    pub(crate) retiring_generation: Option<u64>,
    pub(crate) retiring_config_epoch: Option<u64>,
    pub(crate) retirement: Option<&'static str>,
    pub(crate) error_present: bool,
    pub(crate) warning_count: usize,
}

impl ReloadControl {
    /// Reads bounded owner metadata without waiting for a contended status lock.
    pub(crate) fn observation(&self) -> Option<Option<ReloadObservation>> {
        let state = self.status_store.state.try_lock()?;
        Some(state.statuses.back().map(|status| ReloadObservation {
            reload_id: status.reload_id,
            target_generation: status.target_generation,
            source_revision: status.config_revision.clone(),
            phase: status.state,
            source_generation: status.source_generation,
            activated_generation: status.activated_generation,
            retiring_generation: status.retiring_generation,
            retiring_config_epoch: status.retiring_config_epoch,
            retirement: status.retirement,
            error_present: status.error.is_some(),
            warning_count: status.warnings.len(),
        }))
    }

    pub(crate) fn record_source_generation(&self, id: u64, generation: u64) {
        self.status_store
            .update(id, |status| status.source_generation = Some(generation));
    }

    pub(crate) fn record_activation(
        &self,
        id: u64,
        active: u64,
        retiring: u64,
        retiring_epoch: u64,
    ) {
        self.status_store.update(id, |status| {
            status.activated_generation = Some(active);
            status.retiring_generation = Some(retiring);
            status.retiring_config_epoch = Some(retiring_epoch);
            status.retirement = Some("retiring");
        });
    }

    pub(crate) fn record_retirement(&self, id: u64, timed_out: bool) {
        self.status_store.update(id, |status| {
            status.retirement = Some(if timed_out {
                "cleanup_timeout"
            } else {
                "retired"
            })
        });
    }
}
