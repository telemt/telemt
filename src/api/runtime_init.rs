use serde::Serialize;

use crate::startup::{
    COMPONENT_ME_CONNECTIVITY_PING, COMPONENT_ME_POOL_CONSTRUCT, COMPONENT_ME_POOL_INIT_STAGE1,
    COMPONENT_ME_PROXY_CONFIG_V4, COMPONENT_ME_PROXY_CONFIG_V6, COMPONENT_ME_SECRET_FETCH,
    StartupComponentStatus, StartupMeStatus, compute_progress_pct,
};

use super::ApiShared;

#[derive(Serialize)]
pub(super) struct RuntimeInitializationComponentData {
    pub(super) id: &'static str,
    pub(super) title: &'static str,
    pub(super) status: &'static str,
    pub(super) started_at_epoch_ms: Option<u64>,
    pub(super) finished_at_epoch_ms: Option<u64>,
    pub(super) duration_ms: Option<u64>,
    pub(super) attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) details: Option<String>,
}

#[derive(Serialize)]
pub(super) struct RuntimeInitializationMeData {
    pub(super) status: &'static str,
    pub(super) current_stage: String,
    pub(super) progress_pct: f64,
    pub(super) init_attempt: u32,
    pub(super) retry_limit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_error: Option<String>,
}

#[derive(Serialize)]
pub(super) struct RuntimeInitializationData {
    pub(super) status: &'static str,
    pub(super) degraded: bool,
    pub(super) current_stage: String,
    pub(super) progress_pct: f64,
    pub(super) started_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ready_at_epoch_secs: Option<u64>,
    pub(super) total_elapsed_ms: u64,
    pub(super) transport_mode: String,
    pub(super) me: RuntimeInitializationMeData,
    pub(super) components: Vec<RuntimeInitializationComponentData>,
}

#[derive(Clone)]
pub(super) struct RuntimeStartupSummaryData {
    pub(super) status: &'static str,
    pub(super) stage: String,
    pub(super) progress_pct: f64,
}

pub(super) async fn build_runtime_startup_summary(shared: &ApiShared) -> RuntimeStartupSummaryData {
    let snapshot = shared.startup_tracker.snapshot().await;
    let me_pool_progress = current_me_pool_stage_progress(shared).await;
    let progress_pct = compute_progress_pct(&snapshot, me_pool_progress);
    RuntimeStartupSummaryData {
        status: snapshot.status.as_str(),
        stage: snapshot.current_stage,
        progress_pct,
    }
}

pub(super) async fn build_runtime_initialization_data(
    shared: &ApiShared,
) -> RuntimeInitializationData {
    let snapshot = shared.startup_tracker.snapshot().await;
    let me_pool_progress = current_me_pool_stage_progress(shared).await;
    let progress_pct = compute_progress_pct(&snapshot, me_pool_progress);
    let me_progress_pct = compute_me_progress_pct(&snapshot, me_pool_progress);

    RuntimeInitializationData {
        status: snapshot.status.as_str(),
        degraded: snapshot.degraded,
        current_stage: snapshot.current_stage,
        progress_pct,
        started_at_epoch_secs: snapshot.started_at_epoch_secs,
        ready_at_epoch_secs: snapshot.ready_at_epoch_secs,
        total_elapsed_ms: snapshot.total_elapsed_ms,
        transport_mode: snapshot.transport_mode,
        me: RuntimeInitializationMeData {
            status: snapshot.me.status.as_str(),
            current_stage: snapshot.me.current_stage,
            progress_pct: me_progress_pct,
            init_attempt: snapshot.me.init_attempt,
            retry_limit: snapshot.me.retry_limit,
            last_error: snapshot.me.last_error,
        },
        components: snapshot
            .components
            .into_iter()
            .map(|component| RuntimeInitializationComponentData {
                id: component.id,
                title: component.title,
                status: component.status.as_str(),
                started_at_epoch_ms: component.started_at_epoch_ms,
                finished_at_epoch_ms: component.finished_at_epoch_ms,
                duration_ms: component.duration_ms,
                attempts: component.attempts,
                details: component.details,
            })
            .collect(),
    }
}

fn compute_me_progress_pct(
    snapshot: &crate::startup::StartupSnapshot,
    me_pool_progress: Option<f64>,
) -> f64 {
    match snapshot.me.status {
        StartupMeStatus::Pending => 0.0,
        StartupMeStatus::Ready | StartupMeStatus::Failed | StartupMeStatus::Skipped => 100.0,
        StartupMeStatus::Initializing => {
            let mut total_weight = 0.0f64;
            let mut completed_weight = 0.0f64;
            for component in &snapshot.components {
                if !is_me_component(component.id) {
                    continue;
                }
                total_weight += component.weight;
                let unit_progress = match component.status {
                    StartupComponentStatus::Pending => 0.0,
                    StartupComponentStatus::Running => {
                        if component.id == COMPONENT_ME_POOL_INIT_STAGE1 {
                            me_pool_progress.unwrap_or(0.0).clamp(0.0, 1.0)
                        } else {
                            0.0
                        }
                    }
                    StartupComponentStatus::Ready
                    | StartupComponentStatus::Failed
                    | StartupComponentStatus::Skipped => 1.0,
                };
                completed_weight += component.weight * unit_progress;
            }
            if total_weight <= f64::EPSILON {
                0.0
            } else {
                ((completed_weight / total_weight) * 100.0).clamp(0.0, 100.0)
            }
        }
    }
}

fn is_me_component(component_id: &str) -> bool {
    matches!(
        component_id,
        COMPONENT_ME_SECRET_FETCH
            | COMPONENT_ME_PROXY_CONFIG_V4
            | COMPONENT_ME_PROXY_CONFIG_V6
            | COMPONENT_ME_POOL_CONSTRUCT
            | COMPONENT_ME_POOL_INIT_STAGE1
            | COMPONENT_ME_CONNECTIVITY_PING
    )
}

async fn current_me_pool_stage_progress(shared: &ApiShared) -> Option<f64> {
    let snapshot = shared.startup_tracker.snapshot().await;
    if snapshot.me.status != StartupMeStatus::Initializing {
        return None;
    }

    let pool = shared.me_pool.read().await.clone()?;
    let status = pool.api_status_snapshot().await;
    let configured_dc_groups = status.configured_dc_groups;
    let covered_dc_groups = status.dcs.iter().filter(|dc| dc.alive_writers > 0).count();

    let dc_coverage = ratio_01(covered_dc_groups, configured_dc_groups);
    let writer_coverage = ratio_01(status.alive_writers, status.required_writers);
    Some((0.7 * dc_coverage + 0.3 * writer_coverage).clamp(0.0, 1.0))
}

fn ratio_01(part: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    ((part as f64) / (total as f64)).clamp(0.0, 1.0)
}
