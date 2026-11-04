use serde::{Deserialize, Serialize};

/// Shape of the optional additive HTTP retry delay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebRetryJitterDistribution {
    /// Equal probability for each integer delay in the configured interval.
    #[default]
    Uniform,
    /// Continuous triangular density rounded to milliseconds.
    Triangular,
}

/// Page-owned retry policy; configuration reload affects newly rendered bridges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebRetryJitterConfig {
    /// Replaces the legacy jitter while retaining the underlying retry delay.
    pub enabled: bool,
    /// Inclusive minimum additive delay in milliseconds.
    pub min_ms: u32,
    /// Inclusive maximum additive delay, bounded to 30000 milliseconds.
    pub max_ms: u32,
    /// Probability distribution used independently for each retry.
    pub distribution: WebRetryJitterDistribution,
    /// Triangular mode; omission selects the midpoint of the interval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_ms: Option<u32>,
}

impl Default for WebRetryJitterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_ms: 0,
            max_ms: 250,
            distribution: WebRetryJitterDistribution::Uniform,
            peak_ms: None,
        }
    }
}

impl WebRetryJitterConfig {
    /// Validates inactive policies too, so later activation cannot expose invalid values.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.min_ms > self.max_ms || self.max_ms > 30000 {
            return Err("web.retry_jitter requires 0 <= min_ms <= max_ms <= 30000");
        }
        if let Some(peak) = self.peak_ms {
            if self.distribution != WebRetryJitterDistribution::Triangular
                || peak < self.min_ms
                || peak > self.max_ms
            {
                return Err(
                    "web.retry_jitter.peak_ms requires triangular distribution and an in-range peak",
                );
            }
        }
        Ok(())
    }

    /// Emits only typed numeric and boolean literals, without user-controlled script text.
    pub(crate) fn bridge_policy(&self) -> String {
        let peak = self
            .peak_ms
            .map(f64::from)
            .unwrap_or((f64::from(self.min_ms) + f64::from(self.max_ms)) / 2.0);
        format!(
            "{{enabled:{},min:{},max:{},peak:{},triangular:{}}}",
            self.enabled,
            self.min_ms,
            self.max_ms,
            peak,
            self.distribution == WebRetryJitterDistribution::Triangular,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_jitter_validation_and_roundtrip() {
        let default = WebRetryJitterConfig::default();
        assert!(!default.enabled);
        assert_eq!(default.validate(), Ok(()));
        for (min, max, peak, triangular, valid) in [
            (0, 250, None, false, true),
            (250, 250, Some(250), true, true),
            (0, 30000, Some(0), true, true),
            (0, 250, Some(250), true, true),
            (251, 250, None, false, false),
            (0, 30001, None, false, false),
            (0, 250, Some(125), false, false),
            (100, 250, Some(99), true, false),
            (0, 250, Some(251), true, false),
        ] {
            for enabled in [false, true] {
                let policy = WebRetryJitterConfig {
                    enabled,
                    min_ms: min,
                    max_ms: max,
                    peak_ms: peak,
                    distribution: if triangular {
                        WebRetryJitterDistribution::Triangular
                    } else {
                        WebRetryJitterDistribution::Uniform
                    },
                };
                assert_eq!(policy.validate().is_ok(), valid);
                let json = serde_json::to_string(&policy).unwrap();
                assert_eq!(
                    serde_json::from_str::<WebRetryJitterConfig>(&json).unwrap(),
                    policy
                );
            }
        }
        for json in [
            r#"{"min_ms":-1}"#,
            r#"{"max_ms":1.5}"#,
            r#"{"distribution":"normal"}"#,
            r#"{"unknown":1}"#,
        ] {
            assert!(serde_json::from_str::<WebRetryJitterConfig>(json).is_err());
        }
    }
}
