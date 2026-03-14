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
    pub const fn as_str(self) -> &'static str {
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
    pub const fn as_str(self) -> &'static str {
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
    pub const fn as_str(self) -> &'static str {
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
        if let Some(component) = guard.components.iter_mut().find(|component| component.id == id) {
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
        if let Some(component) = guard.components.iter_mut().find(|component| component.id == id) {
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

const fn component(id: &'static str, title: &'static str, weight: f64) -> StartupComponent {
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
            // floor_char_boundary ensures we never slice inside a multibyte codepoint.
            let boundary = detail.floor_char_boundary(256);
            detail[..boundary].to_string()
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
    use super::normalize_details;

    #[test]
    fn normalize_details_none_returns_none() {
        assert!(normalize_details(None).is_none());
    }

    #[test]
    fn normalize_details_short_string_unchanged() {
        let s = "hello".to_string();
        assert_eq!(normalize_details(Some(s.clone())), Some(s));
    }

    #[test]
    fn normalize_details_exactly_256_ascii_unchanged() {
        let s = "a".repeat(256);
        let result = normalize_details(Some(s));
        assert_eq!(result.as_deref().map(str::len), Some(256));
    }

    #[test]
    fn normalize_details_ascii_over_256_truncated_to_256() {
        let s = "a".repeat(300);
        let result = normalize_details(Some(s)).unwrap();
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn normalize_details_multibyte_char_at_boundary_truncates_before_it() {
        // 255 ASCII bytes + 3-byte UTF-8 '€' (E2 82 AC) = 258 bytes total.
        // floor_char_boundary(256) must land at 255 (before the multibyte char).
        let mut s = "a".repeat(255);
        s.push('\u{20AC}'); // '€' — 3 bytes
        assert_eq!(s.len(), 258);
        let result = normalize_details(Some(s)).unwrap();
        assert!(result.len() <= 256);
        assert_eq!(result.len(), 255);
    }

    #[test]
    fn normalize_details_4byte_char_spanning_byte_256_does_not_panic() {
        // 254 ASCII bytes + 4-byte char (𝕳 = F0 9D 95 B3) = 258 bytes total.
        // Byte 256 falls inside the 4-byte char (at position 2 of bytes 254..257).
        // floor_char_boundary(256) must return 254, not 256, to stay before the char.
        // The old direct slice indexing would panic; this also validates the exact boundary.
        let mut s = "a".repeat(254);
        s.push('\u{1D573}'); // 4-byte codepoint
        assert_eq!(s.len(), 258);
        let result = normalize_details(Some(s)).unwrap();
        assert!(result.len() <= 256);
        assert_eq!(result.len(), 254, "floor_char_boundary(256) must land at 254, not inside the 4-byte char");
    }

    #[test]
    fn normalize_details_all_3byte_chars_truncated_on_char_boundary() {
        // 86 × '€' (3 bytes each) = 258 bytes.
        // floor_char_boundary(256) must return 255 (85 × 3 = 255).
        let s = "\u{20AC}".repeat(86);
        assert_eq!(s.len(), 258);
        let result = normalize_details(Some(s)).unwrap();
        assert!(result.is_char_boundary(result.len()));
        assert_eq!(result.len(), 255);
    }

    #[test]
    fn normalize_details_2byte_chars_boundary_at_even_offset() {
        // 128 × 'é' (C3 A9, 2 bytes each) = 256 bytes — exactly on boundary.
        let s = "\u{00E9}".repeat(128);
        assert_eq!(s.len(), 256);
        let result = normalize_details(Some(s.clone())).unwrap();
        // Exactly 256 bytes, so returned unchanged.
        assert_eq!(result.len(), 256);
        assert_eq!(result, s);
    }

    #[test]
    fn normalize_details_2byte_chars_above_boundary_truncated() {
        // 129 × 'é' = 258 bytes.  floor_char_boundary(256) == 256 (even boundary).
        let s = "\u{00E9}".repeat(129);
        assert_eq!(s.len(), 258);
        let result = normalize_details(Some(s)).unwrap();
        assert!(result.is_char_boundary(result.len()));
        assert_eq!(result.len(), 256); // 128 × 2 = 256
    }
}
