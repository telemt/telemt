// Adaptive buffer policy shared by active Direct relay sessions.

use dashmap::DashMap;
use std::cmp::max;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const EMA_ALPHA: f64 = 0.2;
const PROFILE_TTL: Duration = Duration::from_secs(300);
const THROUGHPUT_UP_BPS: f64 = 8_000_000.0;
const THROUGHPUT_DOWN_BPS: f64 = 2_000_000.0;
const RATIO_CONFIRM_THRESHOLD: f64 = 1.12;
const TIER1_HOLD: Duration = Duration::from_secs(2);
const TIER2_HOLD: Duration = Duration::from_secs(1);
const QUIET_DEMOTE: Duration = Duration::from_secs(120);
const HARD_COOLDOWN: Duration = Duration::from_secs(5);
const SUSTAINED_PRESSURE_DEMOTE: Duration = Duration::from_secs(30);
const PRESSURE_DEMOTE_COOLDOWN: Duration = Duration::from_secs(60);
const HARD_PENDING_THRESHOLD: u32 = 3;
const HARD_PARTIAL_RATIO_THRESHOLD: f64 = 0.25;
#[cfg(test)]
const DIRECT_C2S_CAP_BYTES: usize = 128 * 1024;
#[cfg(test)]
const DIRECT_S2C_CAP_BYTES: usize = 512 * 1024;
#[cfg(test)]
const ME_FRAMES_CAP: usize = 96;
#[cfg(test)]
const ME_BYTES_CAP: usize = 384 * 1024;
#[cfg(test)]
const ME_DELAY_MIN_US: u64 = 150;
const MAX_USER_PROFILES_ENTRIES: usize = 50_000;
const MAX_USER_KEY_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Per-session Direct copy-buffer capacity tier.
pub enum AdaptiveTier {
    /// Conservative baseline capacity.
    Base = 0,
    /// First throughput promotion.
    Tier1 = 1,
    /// Sustained bidirectional pressure promotion.
    Tier2 = 2,
    /// Configured per-direction ceilings.
    Tier3 = 3,
}

impl AdaptiveTier {
    /// Returns the next larger tier, saturating at `Tier3`.
    pub fn promote(self) -> Self {
        match self {
            Self::Base => Self::Tier1,
            Self::Tier1 => Self::Tier2,
            Self::Tier2 => Self::Tier3,
            Self::Tier3 => Self::Tier3,
        }
    }

    /// Returns the next smaller tier, saturating at `Base`.
    pub fn demote(self) -> Self {
        match self {
            Self::Base => Self::Base,
            Self::Tier1 => Self::Base,
            Self::Tier2 => Self::Tier1,
            Self::Tier3 => Self::Tier2,
        }
    }

    #[cfg(test)]
    fn ratio(self) -> (usize, usize) {
        match self {
            Self::Base => (1, 1),
            Self::Tier1 => (5, 4),
            Self::Tier2 => (3, 2),
            Self::Tier3 => (2, 1),
        }
    }

    /// Returns the stable numeric tier used by bounded metrics.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Signal that caused an accepted adaptive tier transition.
pub enum TierTransitionReason {
    /// Sustained throughput and directional ratio confirmation.
    SoftConfirmed,
    /// Short pending or partial-write pressure burst.
    HardPressure,
    /// Sustained low-throughput period.
    QuietDemotion,
    /// Sustained pending or partial-write pressure.
    SustainedWritePressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Proposed transition emitted by the per-session controller.
pub struct TierTransition {
    /// Tier active before the observation.
    pub from: AdaptiveTier,
    /// Tier requested after the observation.
    pub to: AdaptiveTier,
    /// Pressure or throughput condition that requested the transition.
    pub reason: TierTransitionReason,
}

#[derive(Debug, Clone, Copy, Default)]
/// Directional byte and write-pressure deltas for one observation period.
pub struct RelaySignalSample {
    /// Client-to-DC bytes copied during the period.
    pub c2s_bytes: u64,
    /// Bytes offered to DC-to-client writes during the period.
    pub s2c_requested_bytes: u64,
    /// Bytes accepted by DC-to-client writes during the period.
    pub s2c_written_bytes: u64,
    /// Successful DC-to-client write operations during the period.
    pub s2c_write_ops: u64,
    /// Partial DC-to-client write operations during the period.
    pub s2c_partial_writes: u64,
    /// Consecutive pending DC-to-client writes at sample time.
    pub s2c_consecutive_pending_writes: u32,
}

#[derive(Debug, Clone, Copy)]
/// Stateful hysteresis controller for one active Direct session.
pub struct SessionAdaptiveController {
    tier: AdaptiveTier,
    max_tier_seen: AdaptiveTier,
    throughput_ema_bps: f64,
    incoming_ema_bps: f64,
    outgoing_ema_bps: f64,
    tier1_hold: Duration,
    tier2_hold: Duration,
    quiet: Duration,
    hard_cooldown: Duration,
    sustained_pressure: Duration,
}

impl SessionAdaptiveController {
    /// Creates a controller at the tier whose memory reservation was accepted.
    pub fn new(initial_tier: AdaptiveTier) -> Self {
        Self {
            tier: initial_tier,
            max_tier_seen: initial_tier,
            throughput_ema_bps: 0.0,
            incoming_ema_bps: 0.0,
            outgoing_ema_bps: 0.0,
            tier1_hold: Duration::ZERO,
            tier2_hold: Duration::ZERO,
            quiet: Duration::ZERO,
            hard_cooldown: Duration::ZERO,
            sustained_pressure: Duration::ZERO,
        }
    }

    /// Returns the highest tier proposed by controller observations.
    #[allow(dead_code)]
    pub fn max_tier_seen(&self) -> AdaptiveTier {
        self.max_tier_seen
    }

    /// Returns the controller's current logical tier.
    pub fn tier(&self) -> AdaptiveTier {
        self.tier
    }

    /// Observes one period and returns at most one hysteresis-controlled transition.
    pub fn observe(&mut self, sample: RelaySignalSample, tick_secs: f64) -> Option<TierTransition> {
        if tick_secs <= f64::EPSILON {
            return None;
        }

        let tick = Duration::from_secs_f64(tick_secs);
        self.hard_cooldown = self.hard_cooldown.saturating_sub(tick);

        let c2s_bps = (sample.c2s_bytes as f64 * 8.0) / tick_secs;
        let incoming_bps = (sample.s2c_requested_bytes as f64 * 8.0) / tick_secs;
        let outgoing_bps = (sample.s2c_written_bytes as f64 * 8.0) / tick_secs;
        let throughput = c2s_bps.max(outgoing_bps);

        self.throughput_ema_bps = ema(self.throughput_ema_bps, throughput);
        self.incoming_ema_bps = ema(self.incoming_ema_bps, incoming_bps);
        self.outgoing_ema_bps = ema(self.outgoing_ema_bps, outgoing_bps);

        let tier1_now = self.throughput_ema_bps >= THROUGHPUT_UP_BPS;
        if tier1_now {
            self.tier1_hold = self.tier1_hold.saturating_add(tick);
        } else {
            self.tier1_hold = Duration::ZERO;
        }

        let ratio = if self.outgoing_ema_bps <= f64::EPSILON {
            0.0
        } else {
            self.incoming_ema_bps / self.outgoing_ema_bps
        };
        let tier2_now = ratio >= RATIO_CONFIRM_THRESHOLD;
        if tier2_now {
            self.tier2_hold = self.tier2_hold.saturating_add(tick);
        } else {
            self.tier2_hold = Duration::ZERO;
        }

        let partial_ratio = if sample.s2c_write_ops == 0 {
            0.0
        } else {
            sample.s2c_partial_writes as f64 / sample.s2c_write_ops as f64
        };
        let hard_now = sample.s2c_consecutive_pending_writes >= HARD_PENDING_THRESHOLD
            || partial_ratio >= HARD_PARTIAL_RATIO_THRESHOLD;

        if hard_now {
            self.sustained_pressure = self.sustained_pressure.saturating_add(tick);
            if self.sustained_pressure >= SUSTAINED_PRESSURE_DEMOTE {
                self.sustained_pressure = Duration::ZERO;
                return self.demote(
                    TierTransitionReason::SustainedWritePressure,
                    PRESSURE_DEMOTE_COOLDOWN,
                );
            }
        } else {
            self.sustained_pressure = Duration::ZERO;
        }

        if hard_now && self.hard_cooldown.is_zero() {
            return self.promote(TierTransitionReason::HardPressure, HARD_COOLDOWN);
        }

        if self.tier1_hold >= TIER1_HOLD && self.tier2_hold >= TIER2_HOLD {
            return self.promote(TierTransitionReason::SoftConfirmed, Duration::ZERO);
        }

        let demote_candidate =
            self.throughput_ema_bps < THROUGHPUT_DOWN_BPS && !tier2_now && !hard_now;
        if demote_candidate {
            self.quiet = self.quiet.saturating_add(tick);
            if self.quiet >= QUIET_DEMOTE {
                self.quiet = Duration::ZERO;
                return self.demote(TierTransitionReason::QuietDemotion, Duration::ZERO);
            }
        } else {
            self.quiet = Duration::ZERO;
        }

        None
    }

    fn promote(
        &mut self,
        reason: TierTransitionReason,
        hard_cooldown: Duration,
    ) -> Option<TierTransition> {
        let from = self.tier;
        let to = from.promote();
        if from == to {
            return None;
        }
        self.tier = to;
        self.max_tier_seen = max(self.max_tier_seen, to);
        self.hard_cooldown = hard_cooldown;
        self.tier1_hold = Duration::ZERO;
        self.tier2_hold = Duration::ZERO;
        self.quiet = Duration::ZERO;
        Some(TierTransition { from, to, reason })
    }

    fn demote(
        &mut self,
        reason: TierTransitionReason,
        hard_cooldown: Duration,
    ) -> Option<TierTransition> {
        let from = self.tier;
        let to = from.demote();
        if from == to {
            return None;
        }
        self.tier = to;
        self.hard_cooldown = hard_cooldown;
        self.tier1_hold = Duration::ZERO;
        self.tier2_hold = Duration::ZERO;
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

/// Returns a fresh user's recent successful Direct tier, or `Base` when stale.
#[allow(dead_code)]
pub fn seed_tier_for_user(user: &str) -> AdaptiveTier {
    if user.len() > MAX_USER_KEY_BYTES {
        return AdaptiveTier::Base;
    }
    let now = Instant::now();
    if let Some(entry) = profiles().get(user) {
        let value = *entry.value();
        drop(entry);
        if now.saturating_duration_since(value.seen_at) <= PROFILE_TTL {
            return value.tier;
        }
        profiles().remove_if(user, |_, v| {
            now.saturating_duration_since(v.seen_at) > PROFILE_TTL
        });
    }
    AdaptiveTier::Base
}

/// Records the highest successfully allocated tier for bounded session seeding.
#[allow(dead_code)]
pub fn record_user_tier(user: &str, tier: AdaptiveTier) {
    if user.len() > MAX_USER_KEY_BYTES {
        return;
    }
    let now = Instant::now();
    let mut was_vacant = false;
    match profiles().entry(user.to_string()) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let existing = *entry.get();
            let effective = if now.saturating_duration_since(existing.seen_at) > PROFILE_TTL {
                tier
            } else {
                max(existing.tier, tier)
            };
            entry.insert(UserAdaptiveProfile {
                tier: effective,
                seen_at: now,
            });
        }
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(UserAdaptiveProfile { tier, seen_at: now });
            was_vacant = true;
        }
    }
    if was_vacant && profiles().len() > MAX_USER_PROFILES_ENTRIES {
        profiles().retain(|_, v| now.saturating_duration_since(v.seen_at) <= PROFILE_TTL);
    }
}

#[cfg(test)]
/// Returns the legacy staged scaling policy retained by security fixtures.
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

/// Maps an adaptive tier to independent capacities within configured ceilings.
pub(crate) fn direct_copy_buffers_for_tier_with_ceilings(
    tier: AdaptiveTier,
    base_c2s: usize,
    base_s2c: usize,
    ceiling_c2s: usize,
    ceiling_s2c: usize,
) -> (usize, usize) {
    (
        direct_direction_size(tier, base_c2s, ceiling_c2s),
        direct_direction_size(tier, base_s2c, ceiling_s2c),
    )
}

fn direct_direction_size(tier: AdaptiveTier, base: usize, ceiling: usize) -> usize {
    let target = match tier {
        AdaptiveTier::Base => base,
        AdaptiveTier::Tier1 => ceiling / 4,
        AdaptiveTier::Tier2 => ceiling / 2,
        AdaptiveTier::Tier3 => ceiling,
    };
    target.max(base).min(ceiling.max(base)).max(1)
}

#[cfg(test)]
/// Returns the staged Middle-End flush policy retained by security fixtures.
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

#[cfg(test)]
fn scale(base: usize, numerator: usize, denominator: usize, cap: usize) -> usize {
    let scaled = base
        .saturating_mul(numerator)
        .saturating_div(denominator.max(1));
    scaled.min(cap).max(1)
}

#[cfg(test)]
#[path = "tests/adaptive_buffers_security_tests.rs"]
mod adaptive_buffers_security_tests;

#[cfg(test)]
#[path = "tests/adaptive_buffers_record_race_security_tests.rs"]
mod adaptive_buffers_record_race_security_tests;

#[cfg(test)]
#[path = "tests/adaptive_direct_budget_policy_tests.rs"]
mod adaptive_direct_budget_policy_tests;

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
        for _ in 0..480 {
            demotion = ctrl.observe(sample(1, 1, 1, 1, 0, 0), 0.25);
        }

        let transition = demotion.expect("expected quiet demotion");
        assert_eq!(transition.from, AdaptiveTier::Tier2);
        assert_eq!(transition.to, AdaptiveTier::Tier1);
        assert_eq!(transition.reason, TierTransitionReason::QuietDemotion);
    }
}
