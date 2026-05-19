use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

pub const COMPONENT_CONFIG_LOAD: &str = "config_load";
pub const COMPONENT_TRACING_INIT: &str = "tracing_init";
pub const COMPONENT_API_BOOTSTRAP: &str = "api_bootstrap";
pub const COMPONENT_TLS_FRONT_BOOTSTRAP: &str = "tls_front_bootstrap";
pub const COMPONENT_NETWORK_PROBE: &str = "network_probe";
pub const COMPONENT_ME_SECRET_FETCH: &str = "me_secret_fetch";
pub const COMPONENT_ME_PROXY_CONFIG_V4: &str = "me_proxy_config_fetch_v4";
pub const COMPONENT_ME_PROXY_CONFIG_V6: &str = "me_proxy_config_fetch_v6";
pub const COMPONENT_ME_POOL_CONSTRUCT: &str = "me_pool_construct";
pub const COMPONENT_ME_POOL_INIT_STAGE1: &str = "me_pool_init_stage1";
pub const COMPONENT_ME_CONNECTIVITY_PING: &str = "me_connectivity_ping";
pub const COMPONENT_DC_CONNECTIVITY_PING: &str = "dc_connectivity_ping";
pub const COMPONENT_LISTENERS_BIND: &str = "listeners_bind";
pub const COMPONENT_CONFIG_WATCHER_START: &str = "config_watcher_start";
pub const COMPONENT_METRICS_START: &str = "metrics_start";
pub const COMPONENT_RUNTIME_READY: &str = "runtime_ready";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupStatus {
    Initializing,
    Ready,
}

impl StartupStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupComponentStatus {
    Pending,
    Running,
    Ready,
    Failed,
    Skipped,
}

impl StartupComponentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupMeStatus {
    Pending,
    Initializing,
    Ready,
    Failed,
    Skipped,
}

impl StartupMeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StartupComponentSnapshot {
    pub id: &'static str,
    pub title: &'static str,
    pub weight: f64,
    pub status: StartupComponentStatus,
    pub started_at_epoch_ms: Option<u64>,
    pub finished_at_epoch_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub attempts: u32,
    pub details: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StartupMeSnapshot {
    pub status: StartupMeStatus,
    pub current_stage: String,
    pub init_attempt: u32,
    pub retry_limit: String,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StartupSnapshot {
    pub status: StartupStatus,
    pub degraded: bool,
    pub current_stage: String,
    pub started_at_epoch_secs: u64,
    pub ready_at_epoch_secs: Option<u64>,
    pub total_elapsed_ms: u64,
    pub transport_mode: String,
    pub me: StartupMeSnapshot,
    pub components: Vec<StartupComponentSnapshot>,
}

#[derive(Clone, Debug)]
struct StartupComponent {
    id: &'static str,
    title: &'static str,
    weight: f64,
    status: StartupComponentStatus,
    started_at_epoch_ms: Option<u64>,
    finished_at_epoch_ms: Option<u64>,
    duration_ms: Option<u64>,
    attempts: u32,
    details: Option<String>,
}

#[derive(Clone, Debug)]
struct StartupState {
    status: StartupStatus,
    degraded: bool,
    current_stage: String,
    started_at_epoch_secs: u64,
    ready_at_epoch_secs: Option<u64>,
    transport_mode: String,
    me: StartupMeSnapshot,
    components: Vec<StartupComponent>,
}

pub struct StartupTracker {
    started_at_instant: Instant,
    state: RwLock<StartupState>,
}

impl StartupTracker {
    pub fn new(started_at_epoch_secs: u64) -> Self {
        Self {
            started_at_instant: Instant::now(),
            state: RwLock::new(StartupState {
                status: StartupStatus::Initializing,
                degraded: false,
                current_stage: COMPONENT_CONFIG_LOAD.to_string(),
                started_at_epoch_secs,
                ready_at_epoch_secs: None,
                transport_mode: "unknown".to_string(),
                me: StartupMeSnapshot {
                    status: StartupMeStatus::Pending,
                    current_stage: "pending".to_string(),
                    init_attempt: 0,
                    retry_limit: "unlimited".to_string(),
                    last_error: None,
                },
                components: component_blueprint(),
            }),
        }
    }

    pub async fn set_transport_mode(&self, mode: &'static str) {
        self.state.write().await.transport_mode = mode.to_string();
    }

    pub async fn set_degraded(&self, degraded: bool) {
        self.state.write().await.degraded = degraded;
    }

    pub async fn start_component(&self, id: &'static str, details: Option<String>) {
        let mut guard = self.state.write().await;
        guard.current_stage = id.to_string();
        if let Some(component) = guard
            .components
            .iter_mut()
            .find(|component| component.id == id)
        {
            if component.started_at_epoch_ms.is_none() {
                component.started_at_epoch_ms = Some(now_epoch_ms());
            }
            component.attempts = component.attempts.saturating_add(1);
            component.status = StartupComponentStatus::Running;
            component.details = normalize_details(details);
        }
    }

    pub async fn complete_component(&self, id: &'static str, details: Option<String>) {
        self.finish_component(id, StartupComponentStatus::Ready, details)
            .await;
    }

    pub async fn fail_component(&self, id: &'static str, details: Option<String>) {
        self.finish_component(id, StartupComponentStatus::Failed, details)
            .await;
    }

    pub async fn skip_component(&self, id: &'static str, details: Option<String>) {
        self.finish_component(id, StartupComponentStatus::Skipped, details)
            .await;
    }

    async fn finish_component(
        &self,
        id: &'static str,
        status: StartupComponentStatus,
        details: Option<String>,
    ) {
        let mut guard = self.state.write().await;
        let finished_at = now_epoch_ms();
        if let Some(component) = guard
            .components
            .iter_mut()
            .find(|component| component.id == id)
        {
            if component.started_at_epoch_ms.is_none() {
                component.started_at_epoch_ms = Some(finished_at);
                component.attempts = component.attempts.saturating_add(1);
            }
            component.finished_at_epoch_ms = Some(finished_at);
            component.duration_ms = component
                .started_at_epoch_ms
                .map(|started_at| finished_at.saturating_sub(started_at));
            component.status = status;
            component.details = normalize_details(details);
        }
    }

    pub async fn set_me_status(&self, status: StartupMeStatus, stage: &'static str) {
        let mut guard = self.state.write().await;
        guard.me.status = status;
        guard.me.current_stage = stage.to_string();
    }

    pub async fn set_me_retry_limit(&self, retry_limit: String) {
        self.state.write().await.me.retry_limit = retry_limit;
    }

    pub async fn set_me_init_attempt(&self, attempt: u32) {
        self.state.write().await.me.init_attempt = attempt;
    }

    pub async fn set_me_last_error(&self, error: Option<String>) {
        self.state.write().await.me.last_error = normalize_details(error);
    }

    pub async fn mark_ready(&self) {
        let mut guard = self.state.write().await;
        if guard.status == StartupStatus::Ready {
            return;
        }
        guard.status = StartupStatus::Ready;
        guard.current_stage = "ready".to_string();
        guard.ready_at_epoch_secs = Some(now_epoch_secs());
    }

    pub async fn snapshot(&self) -> StartupSnapshot {
        let guard = self.state.read().await;
        StartupSnapshot {
            status: guard.status,
            degraded: guard.degraded,
            current_stage: guard.current_stage.clone(),
            started_at_epoch_secs: guard.started_at_epoch_secs,
            ready_at_epoch_secs: guard.ready_at_epoch_secs,
            total_elapsed_ms: self.started_at_instant.elapsed().as_millis() as u64,
            transport_mode: guard.transport_mode.clone(),
            me: guard.me.clone(),
            components: guard
                .components
                .iter()
                .map(|component| StartupComponentSnapshot {
                    id: component.id,
                    title: component.title,
                    weight: component.weight,
                    status: component.status,
                    started_at_epoch_ms: component.started_at_epoch_ms,
                    finished_at_epoch_ms: component.finished_at_epoch_ms,
                    duration_ms: component.duration_ms,
                    attempts: component.attempts,
                    details: component.details.clone(),
                })
                .collect(),
        }
    }
}

pub fn compute_progress_pct(snapshot: &StartupSnapshot, me_stage_progress: Option<f64>) -> f64 {
    if snapshot.status == StartupStatus::Ready {
        return 100.0;
    }

    let mut total_weight = 0.0f64;
    let mut completed_weight = 0.0f64;

    for component in &snapshot.components {
        total_weight += component.weight;
        let unit_progress = match component.status {
            StartupComponentStatus::Pending => 0.0,
            StartupComponentStatus::Running => {
                if component.id == COMPONENT_ME_POOL_INIT_STAGE1 {
                    me_stage_progress.unwrap_or(0.0).clamp(0.0, 1.0)
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

fn component_blueprint() -> Vec<StartupComponent> {
    vec![
        component(COMPONENT_CONFIG_LOAD, "Config load", 5.0),
        component(COMPONENT_TRACING_INIT, "Tracing init", 3.0),
        component(COMPONENT_API_BOOTSTRAP, "API bootstrap", 5.0),
        component(COMPONENT_TLS_FRONT_BOOTSTRAP, "TLS front bootstrap", 5.0),
        component(COMPONENT_NETWORK_PROBE, "Network probe", 10.0),
        component(COMPONENT_ME_SECRET_FETCH, "ME secret fetch", 8.0),
        component(COMPONENT_ME_PROXY_CONFIG_V4, "ME config v4 fetch", 4.0),
        component(COMPONENT_ME_PROXY_CONFIG_V6, "ME config v6 fetch", 4.0),
        component(COMPONENT_ME_POOL_CONSTRUCT, "ME pool construct", 6.0),
        component(COMPONENT_ME_POOL_INIT_STAGE1, "ME pool init stage1", 24.0),
        component(COMPONENT_ME_CONNECTIVITY_PING, "ME connectivity ping", 6.0),
        component(COMPONENT_DC_CONNECTIVITY_PING, "DC connectivity ping", 8.0),
        component(COMPONENT_LISTENERS_BIND, "Listener bind", 8.0),
        component(COMPONENT_CONFIG_WATCHER_START, "Config watcher start", 2.0),
        component(COMPONENT_METRICS_START, "Metrics start", 1.0),
        component(COMPONENT_RUNTIME_READY, "Runtime ready", 1.0),
    ]
}

fn component(id: &'static str, title: &'static str, weight: f64) -> StartupComponent {
    StartupComponent {
        id,
        title,
        weight,
        status: StartupComponentStatus::Pending,
        started_at_epoch_ms: None,
        finished_at_epoch_ms: None,
        duration_ms: None,
        attempts: 0,
        details: None,
    }
}

fn normalize_details(details: Option<String>) -> Option<String> {
    details.map(|detail| {
        if detail.len() <= 256 {
            detail
        } else {
            detail[..256].to_string()
        }
    })
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_me_snapshot() -> StartupMeSnapshot {
        StartupMeSnapshot {
            status: StartupMeStatus::Pending,
            current_stage: "pending".to_string(),
            init_attempt: 0,
            retry_limit: "unlimited".to_string(),
            last_error: None,
        }
    }

    fn make_component(
        id: &'static str,
        weight: f64,
        status: StartupComponentStatus,
    ) -> StartupComponentSnapshot {
        StartupComponentSnapshot {
            id,
            title: "test",
            weight,
            status,
            started_at_epoch_ms: None,
            finished_at_epoch_ms: None,
            duration_ms: None,
            attempts: 0,
            details: None,
        }
    }

    fn make_snapshot(
        status: StartupStatus,
        components: Vec<StartupComponentSnapshot>,
    ) -> StartupSnapshot {
        StartupSnapshot {
            status,
            degraded: false,
            current_stage: "test".to_string(),
            started_at_epoch_secs: 1000,
            ready_at_epoch_secs: None,
            total_elapsed_ms: 500,
            transport_mode: "test".to_string(),
            me: make_me_snapshot(),
            components,
        }
    }

    // --- Enum as_str matrices ---

    #[test]
    fn startup_status_as_str() {
        assert_eq!(StartupStatus::Initializing.as_str(), "initializing");
        assert_eq!(StartupStatus::Ready.as_str(), "ready");
    }

    #[test]
    fn component_status_as_str() {
        assert_eq!(StartupComponentStatus::Pending.as_str(), "pending");
        assert_eq!(StartupComponentStatus::Running.as_str(), "running");
        assert_eq!(StartupComponentStatus::Ready.as_str(), "ready");
        assert_eq!(StartupComponentStatus::Failed.as_str(), "failed");
        assert_eq!(StartupComponentStatus::Skipped.as_str(), "skipped");
    }

    #[test]
    fn me_status_as_str() {
        assert_eq!(StartupMeStatus::Pending.as_str(), "pending");
        assert_eq!(StartupMeStatus::Initializing.as_str(), "initializing");
        assert_eq!(StartupMeStatus::Ready.as_str(), "ready");
        assert_eq!(StartupMeStatus::Failed.as_str(), "failed");
        assert_eq!(StartupMeStatus::Skipped.as_str(), "skipped");
    }

    // --- compute_progress_pct ---

    #[test]
    fn progress_ready_returns_100() {
        let snap = make_snapshot(StartupStatus::Ready, vec![]);
        assert_eq!(compute_progress_pct(&snap, None), 100.0);
    }

    #[test]
    fn progress_all_pending_returns_0() {
        let components = vec![
            make_component("a", 5.0, StartupComponentStatus::Pending),
            make_component("b", 10.0, StartupComponentStatus::Pending),
        ];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        assert_eq!(compute_progress_pct(&snap, None), 0.0);
    }

    #[test]
    fn progress_all_ready_returns_100() {
        let components = vec![
            make_component("a", 5.0, StartupComponentStatus::Ready),
            make_component("b", 10.0, StartupComponentStatus::Ready),
        ];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        let pct = compute_progress_pct(&snap, None);
        assert!((pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_all_skipped_returns_100() {
        let components = vec![
            make_component("a", 5.0, StartupComponentStatus::Skipped),
            make_component("b", 10.0, StartupComponentStatus::Skipped),
        ];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        let pct = compute_progress_pct(&snap, None);
        assert!((pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_all_failed_returns_100() {
        let components = vec![
            make_component("a", 5.0, StartupComponentStatus::Failed),
            make_component("b", 10.0, StartupComponentStatus::Failed),
        ];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        let pct = compute_progress_pct(&snap, None);
        assert!((pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_mixed_partial() {
        let components = vec![
            make_component("a", 5.0, StartupComponentStatus::Ready),
            make_component("b", 10.0, StartupComponentStatus::Pending),
        ];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        let pct = compute_progress_pct(&snap, None);
        assert!((pct - 33.333_333_333_333_33).abs() < 0.001);
    }

    #[test]
    fn progress_running_non_me_returns_0() {
        let components = vec![make_component(
            "some_other_stage",
            10.0,
            StartupComponentStatus::Running,
        )];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        assert_eq!(compute_progress_pct(&snap, Some(0.5)), 0.0);
    }

    #[test]
    fn progress_running_me_stage_partial() {
        let components = vec![
            make_component(
                COMPONENT_ME_POOL_INIT_STAGE1,
                24.0,
                StartupComponentStatus::Running,
            ),
            make_component("other", 16.0, StartupComponentStatus::Ready),
        ];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        let pct = compute_progress_pct(&snap, Some(0.5));
        // me: 24.0 * 0.5 = 12.0, other: 16.0 * 1.0 = 16.0
        // total = 40.0, completed = 28.0 → 70.0%
        assert!((pct - 70.0).abs() < 0.001);
    }

    #[test]
    fn progress_empty_components_returns_0() {
        let snap = make_snapshot(StartupStatus::Initializing, vec![]);
        assert_eq!(compute_progress_pct(&snap, None), 0.0);
    }

    #[test]
    fn progress_me_stage_negative_clamped_to_zero() {
        let components = vec![make_component(
            COMPONENT_ME_POOL_INIT_STAGE1,
            10.0,
            StartupComponentStatus::Running,
        )];
        let snap = make_snapshot(StartupStatus::Initializing, components);
        let pct = compute_progress_pct(&snap, Some(-0.5));
        assert_eq!(pct, 0.0);
    }

    // --- normalize_details ---

    #[test]
    fn normalize_details_none_returns_none() {
        assert!(super::normalize_details(None).is_none());
    }

    #[test]
    fn normalize_details_short_preserved() {
        let s = "hello".to_string();
        assert_eq!(super::normalize_details(Some(s.clone())), Some(s));
    }

    #[test]
    fn normalize_details_exact_256_preserved() {
        let s = "a".repeat(256);
        assert_eq!(super::normalize_details(Some(s.clone())), Some(s));
    }

    #[test]
    fn normalize_details_over_256_truncated() {
        let s = "a".repeat(300);
        let result = super::normalize_details(Some(s));
        assert_eq!(result.map(|r| r.len()), Some(256));
    }

    #[test]
    fn normalize_details_empty_string_preserved() {
        let s = String::new();
        assert_eq!(super::normalize_details(Some(s.clone())), Some(s));
    }

    // --- component_blueprint ---

    #[test]
    fn blueprint_has_16_components() {
        assert_eq!(super::component_blueprint().len(), 16);
    }

    #[test]
    fn blueprint_all_start_pending() {
        let bp = super::component_blueprint();
        assert!(bp.iter().all(|c| c.status == StartupComponentStatus::Pending));
    }

    #[test]
    fn blueprint_known_ids_present() {
        let bp = super::component_blueprint();
        let ids: Vec<&str> = bp.iter().map(|c| c.id).collect();
        assert!(ids.contains(&COMPONENT_CONFIG_LOAD));
        assert!(ids.contains(&COMPONENT_RUNTIME_READY));
        assert!(ids.contains(&COMPONENT_ME_POOL_INIT_STAGE1));
        assert!(ids.contains(&COMPONENT_DC_CONNECTIVITY_PING));
    }

    #[test]
    fn blueprint_weights_all_positive() {
        let bp = super::component_blueprint();
        assert!(bp.iter().all(|c| c.weight > 0.0));
    }

    #[test]
    fn blueprint_zero_attempts_and_no_timestamps() {
        let bp = super::component_blueprint();
        assert!(bp.iter().all(|c| c.attempts == 0));
        assert!(bp.iter().all(|c| c.started_at_epoch_ms.is_none()));
        assert!(bp.iter().all(|c| c.finished_at_epoch_ms.is_none()));
        assert!(bp.iter().all(|c| c.duration_ms.is_none()));
        assert!(bp.iter().all(|c| c.details.is_none()));
    }
}
