use std::time::{Duration, Instant};

use super::model::PressureState;

#[derive(Debug, Clone, Copy)]
pub(crate) struct PressureSignals {
    pub(crate) active_flows: usize,
    pub(crate) total_queued_bytes: u64,
    pub(crate) standing_flows: usize,
    pub(crate) backpressured_flows: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct PressureConfig {
    pub(crate) backpressure_enabled: bool,
    pub(crate) evaluate_every_rounds: u32,
    pub(crate) transition_hysteresis_rounds: u8,
    pub(crate) standing_ratio_pressured_pct: u8,
    pub(crate) standing_ratio_shedding_pct: u8,
    pub(crate) standing_ratio_saturated_pct: u8,
    pub(crate) queue_ratio_pressured_pct: u8,
    pub(crate) queue_ratio_shedding_pct: u8,
    pub(crate) queue_ratio_saturated_pct: u8,
    pub(crate) reject_window: Duration,
    pub(crate) rejects_pressured: u32,
    pub(crate) rejects_shedding: u32,
    pub(crate) rejects_saturated: u32,
    pub(crate) stalls_pressured: u32,
    pub(crate) stalls_shedding: u32,
    pub(crate) stalls_saturated: u32,
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            backpressure_enabled: true,
            evaluate_every_rounds: 8,
            transition_hysteresis_rounds: 3,
            standing_ratio_pressured_pct: 20,
            standing_ratio_shedding_pct: 35,
            standing_ratio_saturated_pct: 50,
            queue_ratio_pressured_pct: 65,
            queue_ratio_shedding_pct: 82,
            queue_ratio_saturated_pct: 94,
            reject_window: Duration::from_secs(2),
            rejects_pressured: 32,
            rejects_shedding: 96,
            rejects_saturated: 256,
            stalls_pressured: 32,
            stalls_shedding: 96,
            stalls_saturated: 256,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PressureEvaluator {
    state: PressureState,
    candidate_state: PressureState,
    candidate_hits: u8,
    rounds_since_eval: u32,
    window_started_at: Instant,
    admission_rejects_window: u32,
    route_stalls_window: u32,
}

impl PressureEvaluator {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            state: PressureState::Normal,
            candidate_state: PressureState::Normal,
            candidate_hits: 0,
            rounds_since_eval: 0,
            window_started_at: now,
            admission_rejects_window: 0,
            route_stalls_window: 0,
        }
    }

    #[inline]
    pub(crate) fn state(&self) -> PressureState {
        self.state
    }

    pub(crate) fn note_admission_reject(&mut self, now: Instant, cfg: &PressureConfig) {
        self.rotate_window_if_needed(now, cfg);
        self.admission_rejects_window = self.admission_rejects_window.saturating_add(1);
    }

    pub(crate) fn note_route_stall(&mut self, now: Instant, cfg: &PressureConfig) {
        self.rotate_window_if_needed(now, cfg);
        self.route_stalls_window = self.route_stalls_window.saturating_add(1);
    }

    pub(crate) fn maybe_evaluate(
        &mut self,
        now: Instant,
        cfg: &PressureConfig,
        max_total_queued_bytes: u64,
        signals: PressureSignals,
        force: bool,
    ) -> PressureState {
        self.rotate_window_if_needed(now, cfg);
        if !cfg.backpressure_enabled {
            self.state = PressureState::Normal;
            self.candidate_state = PressureState::Normal;
            self.candidate_hits = 0;
            self.rounds_since_eval = 0;
            return self.state;
        }
        self.rounds_since_eval = self.rounds_since_eval.saturating_add(1);
        if !force && self.rounds_since_eval < cfg.evaluate_every_rounds.max(1) {
            return self.state;
        }
        self.rounds_since_eval = 0;

        let target = self.derive_target_state(cfg, max_total_queued_bytes, signals);
        if target == self.state {
            self.candidate_state = target;
            self.candidate_hits = 0;
            return self.state;
        }

        if self.candidate_state == target {
            self.candidate_hits = self.candidate_hits.saturating_add(1);
        } else {
            self.candidate_state = target;
            self.candidate_hits = 1;
        }

        if self.candidate_hits >= cfg.transition_hysteresis_rounds.max(1) {
            self.state = target;
            self.candidate_hits = 0;
        }

        self.state
    }

    fn derive_target_state(
        &self,
        cfg: &PressureConfig,
        max_total_queued_bytes: u64,
        signals: PressureSignals,
    ) -> PressureState {
        if !cfg.backpressure_enabled {
            return PressureState::Normal;
        }

        let queue_ratio_pct = if max_total_queued_bytes == 0 {
            100
        } else {
            ((signals.total_queued_bytes.saturating_mul(100)) / max_total_queued_bytes).min(100)
                as u8
        };

        let standing_ratio_pct = if signals.active_flows == 0 {
            0
        } else {
            ((signals.standing_flows.saturating_mul(100)) / signals.active_flows).min(100) as u8
        };

        let mut pressure_score = 0u8;

        if queue_ratio_pct >= cfg.queue_ratio_pressured_pct {
            pressure_score = pressure_score.max(1);
        }
        if queue_ratio_pct >= cfg.queue_ratio_shedding_pct {
            pressure_score = pressure_score.max(2);
        }
        if queue_ratio_pct >= cfg.queue_ratio_saturated_pct {
            pressure_score = pressure_score.max(3);
        }

        if standing_ratio_pct >= cfg.standing_ratio_pressured_pct {
            pressure_score = pressure_score.max(1);
        }
        if standing_ratio_pct >= cfg.standing_ratio_shedding_pct {
            pressure_score = pressure_score.max(2);
        }
        if standing_ratio_pct >= cfg.standing_ratio_saturated_pct {
            pressure_score = pressure_score.max(3);
        }

        if self.admission_rejects_window >= cfg.rejects_pressured {
            pressure_score = pressure_score.max(1);
        }
        if self.admission_rejects_window >= cfg.rejects_shedding {
            pressure_score = pressure_score.max(2);
        }
        if self.admission_rejects_window >= cfg.rejects_saturated {
            pressure_score = pressure_score.max(3);
        }

        if self.route_stalls_window >= cfg.stalls_pressured {
            pressure_score = pressure_score.max(1);
        }
        if self.route_stalls_window >= cfg.stalls_shedding {
            pressure_score = pressure_score.max(2);
        }
        if self.route_stalls_window >= cfg.stalls_saturated {
            pressure_score = pressure_score.max(3);
        }

        if signals.backpressured_flows > signals.active_flows.saturating_div(2)
            && signals.active_flows > 0
        {
            pressure_score = pressure_score.max(2);
        }

        match pressure_score {
            0 => PressureState::Normal,
            1 => PressureState::Pressured,
            2 => PressureState::Shedding,
            _ => PressureState::Saturated,
        }
    }

    fn rotate_window_if_needed(&mut self, now: Instant, cfg: &PressureConfig) {
        if now.saturating_duration_since(self.window_started_at) < cfg.reject_window {
            return;
        }

        self.window_started_at = now;
        self.admission_rejects_window = 0;
        self.route_stalls_window = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn low_signals() -> PressureSignals {
        PressureSignals {
            active_flows: 10,
            total_queued_bytes: 100,
            standing_flows: 0,
            backpressured_flows: 0,
        }
    }

    fn default_cfg() -> PressureConfig {
        PressureConfig::default()
    }

    #[test]
    fn pressure_config_default_values() {
        let c = PressureConfig::default();
        assert!(c.backpressure_enabled);
        assert_eq!(c.evaluate_every_rounds, 8);
        assert_eq!(c.transition_hysteresis_rounds, 3);
        assert_eq!(c.standing_ratio_pressured_pct, 20);
        assert_eq!(c.standing_ratio_shedding_pct, 35);
        assert_eq!(c.standing_ratio_saturated_pct, 50);
        assert_eq!(c.queue_ratio_pressured_pct, 65);
        assert_eq!(c.queue_ratio_shedding_pct, 82);
        assert_eq!(c.queue_ratio_saturated_pct, 94);
        assert_eq!(c.reject_window, Duration::from_secs(2));
        assert_eq!(c.rejects_pressured, 32);
        assert_eq!(c.rejects_shedding, 96);
        assert_eq!(c.rejects_saturated, 256);
        assert_eq!(c.stalls_pressured, 32);
        assert_eq!(c.stalls_shedding, 96);
        assert_eq!(c.stalls_saturated, 256);
    }

    #[test]
    fn evaluator_new_initial_state_normal() {
        let ev = PressureEvaluator::new(Instant::now());
        assert_eq!(ev.state(), PressureState::Normal);
    }

    #[test]
    fn note_admission_reject_increments_observable() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        for _ in 0..cfg.rejects_saturated {
            ev.note_admission_reject(now, &cfg);
        }

        let sig = low_signals();
        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st, PressureState::Saturated);
    }

    #[test]
    fn note_route_stall_increments_observable() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        for _ in 0..cfg.stalls_saturated {
            ev.note_route_stall(now, &cfg);
        }

        let sig = low_signals();
        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st, PressureState::Saturated);
    }

    #[test]
    fn maybe_evaluate_disabled_always_normal() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let mut cfg = default_cfg();
        cfg.backpressure_enabled = false;

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 9999,
            standing_flows: 10,
            backpressured_flows: 10,
        };
        let st = ev.maybe_evaluate(now, &cfg, 100, sig, false);
        assert_eq!(st, PressureState::Normal);

        for _ in 0..256 {
            ev.note_admission_reject(now, &cfg);
        }
        let st = ev.maybe_evaluate(now, &cfg, 100, sig, true);
        assert_eq!(st, PressureState::Normal);
    }

    #[test]
    fn maybe_evaluate_rounds_guard_no_force() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 9999,
            standing_flows: 10,
            backpressured_flows: 10,
        };

        let st = ev.maybe_evaluate(now, &cfg, 100, sig, false);
        assert_eq!(st, PressureState::Normal);
    }

    #[test]
    fn maybe_evaluate_force_bypasses_guard() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 9999,
            standing_flows: 10,
            backpressured_flows: 10,
        };

        let mut st = PressureState::Normal;
        for _ in 0..cfg.transition_hysteresis_rounds {
            st = ev.maybe_evaluate(now, &cfg, 100, sig, true);
        }
        assert_ne!(st, PressureState::Normal);
    }

    #[test]
    fn hysteresis_same_target_three_times_transitions() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 660,
            standing_flows: 0,
            backpressured_flows: 0,
        };

        let st1 = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st1, PressureState::Normal);

        let st2 = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st2, PressureState::Normal);

        let st3 = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st3, PressureState::Pressured);

        let st4 = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st4, PressureState::Pressured);
    }

    #[test]
    fn derive_queue_ratio_pressured_crossing() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 660,
            standing_flows: 0,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st, PressureState::Pressured);
    }

    #[test]
    fn derive_queue_ratio_shedding_crossing() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 830,
            standing_flows: 0,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st, PressureState::Shedding);
    }

    #[test]
    fn derive_queue_ratio_saturated_crossing() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 950,
            standing_flows: 0,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1000, sig, true);
        assert_eq!(st, PressureState::Saturated);
    }

    #[test]
    fn derive_standing_ratio_pressured_crossing() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 0,
            standing_flows: 3,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1, sig, true);
        assert_eq!(st, PressureState::Pressured);
    }

    #[test]
    fn derive_standing_ratio_shedding_crossing() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 0,
            standing_flows: 4,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1, sig, true);
        assert_eq!(st, PressureState::Shedding);
    }

    #[test]
    fn derive_standing_ratio_saturated_crossing() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 0,
            standing_flows: 5,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1, sig, true);
        assert_eq!(st, PressureState::Saturated);
    }

    #[test]
    fn derive_empty_max_queued_bytes_saturated() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 0,
            total_queued_bytes: 0,
            standing_flows: 0,
            backpressured_flows: 0,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 0, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 0, sig, true);
        assert_eq!(st, PressureState::Saturated);
    }

    #[test]
    fn derive_backpressured_flows_majority_shedding() {
        let now = Instant::now();
        let mut ev = PressureEvaluator::new(now);
        let cfg = default_cfg();

        let sig = PressureSignals {
            active_flows: 10,
            total_queued_bytes: 0,
            standing_flows: 0,
            backpressured_flows: 6,
        };

        for _ in 0..cfg.transition_hysteresis_rounds {
            ev.maybe_evaluate(now, &cfg, 1, sig, true);
        }
        let st = ev.maybe_evaluate(now, &cfg, 1, sig, true);
        assert!(st >= PressureState::Shedding);
    }

    #[test]
    fn rotate_window_zero_duration_resets_counters() {
        let now = Instant::now();
        let later = now + Duration::from_secs(5);
        let mut ev = PressureEvaluator::new(now);
        let mut cfg = default_cfg();
        cfg.reject_window = Duration::ZERO;

        for _ in 0..300 {
            ev.note_admission_reject(now, &cfg);
        }

        let sig = low_signals();
        let st = ev.maybe_evaluate(later, &cfg, 1000, sig, true);
        assert_eq!(st, PressureState::Normal);
    }

}
