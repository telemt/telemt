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

        let mut pressured = false;
        let mut saturated = false;

        let queue_saturated_pct = cfg
            .queue_ratio_shedding_pct
            .min(cfg.queue_ratio_saturated_pct);
        if queue_ratio_pct >= cfg.queue_ratio_pressured_pct {
            pressured = true;
        }
        if queue_ratio_pct >= queue_saturated_pct {
            saturated = true;
        }

        let standing_saturated_pct = cfg
            .standing_ratio_shedding_pct
            .min(cfg.standing_ratio_saturated_pct);
        if standing_ratio_pct >= cfg.standing_ratio_pressured_pct {
            pressured = true;
        }
        if standing_ratio_pct >= standing_saturated_pct {
            saturated = true;
        }

        let rejects_saturated = cfg.rejects_shedding.min(cfg.rejects_saturated);
        if self.admission_rejects_window >= cfg.rejects_pressured {
            pressured = true;
        }
        if self.admission_rejects_window >= rejects_saturated {
            saturated = true;
        }

        let stalls_saturated = cfg.stalls_shedding.min(cfg.stalls_saturated);
        if self.route_stalls_window >= cfg.stalls_pressured {
            pressured = true;
        }
        if self.route_stalls_window >= stalls_saturated {
            saturated = true;
        }

        if signals.backpressured_flows > signals.active_flows.saturating_div(2)
            && signals.active_flows > 0
        {
            pressured = true;
        }

        if saturated {
            PressureState::Saturated
        } else if pressured {
            PressureState::Pressured
        } else {
            PressureState::Normal
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
