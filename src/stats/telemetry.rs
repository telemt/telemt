use crate::config::{MeTelemetryLevel, TelemetryConfig};

/// Runtime telemetry policy used by hot-path counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryPolicy {
    pub core_enabled: bool,
    pub user_enabled: bool,
    pub me_level: MeTelemetryLevel,
}

impl Default for TelemetryPolicy {
    fn default() -> Self {
        Self {
            core_enabled: true,
            user_enabled: true,
            me_level: MeTelemetryLevel::Normal,
        }
    }
}

impl TelemetryPolicy {
    pub fn from_config(cfg: &TelemetryConfig) -> Self {
        Self {
            core_enabled: cfg.core_enabled,
            user_enabled: cfg.user_enabled,
            me_level: cfg.me_level,
        }
    }
}
