#![allow(dead_code)]

// Adaptive buffer policy is staged and retained for deterministic rollout.
// Keep definitions compiled for compatibility and security test scaffolding.

use dashmap::DashMap;
use std::cmp::max;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const EMA_ALPHA: f64 = 0.2;
const PROFILE_TTL: Duration = Duration::from_secs(300);
const THROUGHPUT_UP_BPS: f64 = 8_000_000.0;
const THROUGHPUT_DOWN_BPS: f64 = 2_000_000.0;
const RATIO_CONFIRM_THRESHOLD: f64 = 1.12;
const TIER1_HOLD_TICKS: u32 = 8;
const TIER2_HOLD_TICKS: u32 = 4;
const QUIET_DEMOTE_TICKS: u32 = 480;
const HARD_COOLDOWN_TICKS: u32 = 20;
const HARD_PENDING_THRESHOLD: u32 = 3;
const HARD_PARTIAL_RATIO_THRESHOLD: f64 = 0.25;
const DIRECT_C2S_CAP_BYTES: usize = 128 * 1024;
const DIRECT_S2C_CAP_BYTES: usize = 512 * 1024;
const ME_FRAMES_CAP: usize = 96;
const ME_BYTES_CAP: usize = 384 * 1024;
const ME_DELAY_MIN_US: u64 = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdaptiveTier {
    Base = 0,
    Tier1 = 1,
    Tier2 = 2,
    Tier3 = 3,
}

impl AdaptiveTier {
    pub fn promote(self) -> Self {
        match self {
            Self::Base => Self::Tier1,
            Self::Tier1 => Self::Tier2,
            Self::Tier2 => Self::Tier3,
            Self::Tier3 => Self::Tier3,
        }
    }

    pub fn demote(self) -> Self {
        match self {
            Self::Base => Self::Base,
            Self::Tier1 => Self::Base,
            Self::Tier2 => Self::Tier1,
            Self::Tier3 => Self::Tier2,
        }
    }

    fn ratio(self) -> (usize, usize) {
        match self {
            Self::Base => (1, 1),
            Self::Tier1 => (5, 4),
            Self::Tier2 => (3, 2),
            Self::Tier3 => (2, 1),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierTransitionReason {
    SoftConfirmed,
    HardPressure,
    QuietDemotion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierTransition {
    pub from: AdaptiveTier,
    pub to: AdaptiveTier,
    pub reason: TierTransitionReason,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RelaySignalSample {
    pub c2s_bytes: u64,
    pub s2c_requested_bytes: u64,
    pub s2c_written_bytes: u64,
    pub s2c_write_ops: u64,
    pub s2c_partial_writes: u64,
    pub s2c_consecutive_pending_writes: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SessionAdaptiveController {
    tier: AdaptiveTier,
    max_tier_seen: AdaptiveTier,
    throughput_ema_bps: f64,
    incoming_ema_bps: f64,
    outgoing_ema_bps: f64,
    tier1_hold_ticks: u32,
    tier2_hold_ticks: u32,
    quiet_ticks: u32,
    hard_cooldown_ticks: u32,
}

impl SessionAdaptiveController {
    pub fn new(initial_tier: AdaptiveTier) -> Self {
        Self {
            tier: initial_tier,
            max_tier_seen: initial_tier,
            throughput_ema_bps: 0.0,
            incoming_ema_bps: 0.0,
            outgoing_ema_bps: 0.0,
            tier1_hold_ticks: 0,
            tier2_hold_ticks: 0,
            quiet_ticks: 0,
            hard_cooldown_ticks: 0,
        }
    }

    pub fn max_tier_seen(&self) -> AdaptiveTier {
        self.max_tier_seen
    }

    pub fn observe(&mut self, sample: RelaySignalSample, tick_secs: f64) -> Option<TierTransition> {
        if tick_secs <= f64::EPSILON {
            return None;
        }

        if self.hard_cooldown_ticks > 0 {
            self.hard_cooldown_ticks -= 1;
        }

        let c2s_bps = (sample.c2s_bytes as f64 * 8.0) / tick_secs;
        let incoming_bps = (sample.s2c_requested_bytes as f64 * 8.0) / tick_secs;
        let outgoing_bps = (sample.s2c_written_bytes as f64 * 8.0) / tick_secs;
        let throughput = c2s_bps.max(outgoing_bps);

        self.throughput_ema_bps = ema(self.throughput_ema_bps, throughput);
        self.incoming_ema_bps = ema(self.incoming_ema_bps, incoming_bps);
        self.outgoing_ema_bps = ema(self.outgoing_ema_bps, outgoing_bps);

        let tier1_now = self.throughput_ema_bps >= THROUGHPUT_UP_BPS;
        if tier1_now {
            self.tier1_hold_ticks = self.tier1_hold_ticks.saturating_add(1);
        } else {
            self.tier1_hold_ticks = 0;
        }

        let ratio = if self.outgoing_ema_bps <= f64::EPSILON {
            0.0
        } else {
            self.incoming_ema_bps / self.outgoing_ema_bps
        };
        let tier2_now = ratio >= RATIO_CONFIRM_THRESHOLD;
        if tier2_now {
            self.tier2_hold_ticks = self.tier2_hold_ticks.saturating_add(1);
        } else {
            self.tier2_hold_ticks = 0;
        }

        let partial_ratio = if sample.s2c_write_ops == 0 {
            0.0
        } else {
            sample.s2c_partial_writes as f64 / sample.s2c_write_ops as f64
        };
        let hard_now = sample.s2c_consecutive_pending_writes >= HARD_PENDING_THRESHOLD
            || partial_ratio >= HARD_PARTIAL_RATIO_THRESHOLD;

        if hard_now && self.hard_cooldown_ticks == 0 {
            return self.promote(TierTransitionReason::HardPressure, HARD_COOLDOWN_TICKS);
        }

        if self.tier1_hold_ticks >= TIER1_HOLD_TICKS && self.tier2_hold_ticks >= TIER2_HOLD_TICKS {
            return self.promote(TierTransitionReason::SoftConfirmed, 0);
        }

        let demote_candidate =
            self.throughput_ema_bps < THROUGHPUT_DOWN_BPS && !tier2_now && !hard_now;
        if demote_candidate {
            self.quiet_ticks = self.quiet_ticks.saturating_add(1);
            if self.quiet_ticks >= QUIET_DEMOTE_TICKS {
                self.quiet_ticks = 0;
                return self.demote(TierTransitionReason::QuietDemotion);
            }
        } else {
            self.quiet_ticks = 0;
        }

        None
    }

    fn promote(
        &mut self,
        reason: TierTransitionReason,
        hard_cooldown_ticks: u32,
    ) -> Option<TierTransition> {
        let from = self.tier;
        let to = from.promote();
        if from == to {
            return None;
        }
        self.tier = to;
        self.max_tier_seen = max(self.max_tier_seen, to);
        self.hard_cooldown_ticks = hard_cooldown_ticks;
        self.tier1_hold_ticks = 0;
        self.tier2_hold_ticks = 0;
        self.quiet_ticks = 0;
        Some(TierTransition { from, to, reason })
    }

    fn demote(&mut self, reason: TierTransitionReason) -> Option<TierTransition> {
        let from = self.tier;
        let to = from.demote();
        if from == to {
            return None;
        }
        self.tier = to;
        self.tier1_hold_ticks = 0;
        self.tier2_hold_ticks = 0;
        Some(TierTransition { from, to, reason })
    }
}

#[derive(Debug, Clone, Copy)]
struct UserAdaptiveProfile {
    tier: AdaptiveTier,
    seen_at: Instant,
}

fn profiles() -> &'static DashMap<String, UserAdaptiveProfile> {
    static USER_PROFILES: OnceLock<DashMap<String, UserAdaptiveProfile>> = OnceLock::new();
    USER_PROFILES.get_or_init(DashMap::new)
}

pub fn seed_tier_for_user(user: &str) -> AdaptiveTier {
    let now = Instant::now();
    if let Some(entry) = profiles().get(user) {
        let value = entry.value();
        if now.duration_since(value.seen_at) <= PROFILE_TTL {
            return value.tier;
        }
    }
    AdaptiveTier::Base
}

pub fn record_user_tier(user: &str, tier: AdaptiveTier) {
    let now = Instant::now();
    if let Some(mut entry) = profiles().get_mut(user) {
        let existing = *entry;
        let effective = if now.duration_since(existing.seen_at) > PROFILE_TTL {
            tier
        } else {
            max(existing.tier, tier)
        };
        *entry = UserAdaptiveProfile {
            tier: effective,
            seen_at: now,
        };
        return;
    }
    profiles().insert(user.to_string(), UserAdaptiveProfile { tier, seen_at: now });
}

pub fn direct_copy_buffers_for_tier(
    tier: AdaptiveTier,
    base_c2s: usize,
    base_s2c: usize,
) -> (usize, usize) {
    let (num, den) = tier.ratio();
    (
        scale(base_c2s, num, den, DIRECT_C2S_CAP_BYTES),
        scale(base_s2c, num, den, DIRECT_S2C_CAP_BYTES),
    )
}

pub fn me_flush_policy_for_tier(
    tier: AdaptiveTier,
    base_frames: usize,
    base_bytes: usize,
    base_delay: Duration,
) -> (usize, usize, Duration) {
    let (num, den) = tier.ratio();
    let frames = scale(base_frames, num, den, ME_FRAMES_CAP).max(1);
    let bytes = scale(base_bytes, num, den, ME_BYTES_CAP).max(4096);
    let delay_us = base_delay.as_micros() as u64;
    let adjusted_delay_us = match tier {
        AdaptiveTier::Base => delay_us,
        AdaptiveTier::Tier1 => (delay_us.saturating_mul(7)).saturating_div(10),
        AdaptiveTier::Tier2 => delay_us.saturating_div(2),
        AdaptiveTier::Tier3 => (delay_us.saturating_mul(3)).saturating_div(10),
    }
    .max(ME_DELAY_MIN_US)
    .min(delay_us.max(ME_DELAY_MIN_US));
    (frames, bytes, Duration::from_micros(adjusted_delay_us))
}

fn ema(prev: f64, value: f64) -> f64 {
    if prev <= f64::EPSILON {
        value
    } else {
        (prev * (1.0 - EMA_ALPHA)) + (value * EMA_ALPHA)
    }
}

fn scale(base: usize, numerator: usize, denominator: usize, cap: usize) -> usize {
    let scaled = base
        .saturating_mul(numerator)
        .saturating_div(denominator.max(1));
    scaled.min(cap).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        c2s_bytes: u64,
        s2c_requested_bytes: u64,
        s2c_written_bytes: u64,
        s2c_write_ops: u64,
        s2c_partial_writes: u64,
        s2c_consecutive_pending_writes: u32,
    ) -> RelaySignalSample {
        RelaySignalSample {
            c2s_bytes,
            s2c_requested_bytes,
            s2c_written_bytes,
            s2c_write_ops,
            s2c_partial_writes,
            s2c_consecutive_pending_writes,
        }
    }

    #[test]
    fn test_soft_promotion_requires_tier1_and_tier2() {
        let mut ctrl = SessionAdaptiveController::new(AdaptiveTier::Base);
        let tick_secs = 0.25;
        let mut promoted = None;
        for _ in 0..8 {
            promoted = ctrl.observe(
                sample(
                    300_000, // ~9.6 Mbps
                    320_000, // incoming > outgoing to confirm tier2
                    250_000, 10, 0, 0,
                ),
                tick_secs,
            );
        }

        let transition = promoted.expect("expected soft promotion");
        assert_eq!(transition.from, AdaptiveTier::Base);
        assert_eq!(transition.to, AdaptiveTier::Tier1);
        assert_eq!(transition.reason, TierTransitionReason::SoftConfirmed);
    }

    #[test]
    fn test_hard_promotion_on_pending_pressure() {
        let mut ctrl = SessionAdaptiveController::new(AdaptiveTier::Base);
        let transition = ctrl
            .observe(sample(10_000, 20_000, 10_000, 4, 1, 3), 0.25)
            .expect("expected hard promotion");
        assert_eq!(transition.reason, TierTransitionReason::HardPressure);
        assert_eq!(transition.to, AdaptiveTier::Tier1);
    }

    #[test]
    fn test_quiet_demotion_is_slow_and_stepwise() {
        let mut ctrl = SessionAdaptiveController::new(AdaptiveTier::Tier2);
        let mut demotion = None;
        for _ in 0..QUIET_DEMOTE_TICKS {
            demotion = ctrl.observe(sample(1, 1, 1, 1, 0, 0), 0.25);
        }

        let transition = demotion.expect("expected quiet demotion");
        assert_eq!(transition.from, AdaptiveTier::Tier2);
        assert_eq!(transition.to, AdaptiveTier::Tier1);
        assert_eq!(transition.reason, TierTransitionReason::QuietDemotion);
    }
}
