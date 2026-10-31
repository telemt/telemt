use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::ProfileKey;
use super::negotiation::{CarrierClientClass, CarrierLearningContext};
use crate::config::{WebCarrier, WebCarrierNegotiationAggressiveness};

#[path = "carrier_learning/status.rs"]
mod status;
pub(super) use status::{CarrierLearningEpoch, CarrierLearningRecordOutcome};

const PROFILE_WEIGHT: i16 = 32;
const USER_AGENT_WEIGHT: i16 = 32;
const IP_WEIGHT: i16 = 1;
const SCORE_MIN: i8 = -8;
const SCORE_MAX: i8 = 8;
const MAX_COHORTS: usize = 4;
const PRUNE_ENTRIES_PER_TICK: usize = 64;
const COHORT_CONTEXT: &[u8] = b"telemt-web-carrier-cohort-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum EvidenceKey {
    Profile(ProfileKey),
    UserAgent(ProfileKey, CarrierClientClass, [u8; 32]),
    Ip(ProfileKey, IpAddr),
}

#[derive(Clone, Copy, Default)]
struct Bucket {
    slot: u64,
    valid: bool,
    scores: [i8; 4],
    outcomes: u8,
    cohorts: [Option<[u8; 32]>; MAX_COHORTS],
}

impl Bucket {
    fn reset(&mut self, slot: u64) {
        *self = Self {
            slot,
            valid: true,
            ..Self::default()
        };
    }

    fn update(&mut self, deltas: [i8; 4], cohort: Option<[u8; 32]>) {
        for (score, delta) in self.scores.iter_mut().zip(deltas) {
            *score = score.saturating_add(delta).clamp(SCORE_MIN, SCORE_MAX);
        }
        self.outcomes = self.outcomes.saturating_add(1);
        if let Some(cohort) = cohort
            && !self.cohorts.contains(&Some(cohort))
            && let Some(slot) = self.cohorts.iter_mut().find(|slot| slot.is_none())
        {
            *slot = Some(cohort);
        }
    }
}

struct Evidence {
    insertion_sequence: u64,
    buckets: [Bucket; 2],
}

impl Evidence {
    fn new(insertion_sequence: u64) -> Self {
        Self {
            insertion_sequence,
            buckets: [Bucket::default(), Bucket::default()],
        }
    }

    fn update(&mut self, slot: u64, deltas: [i8; 4], cohort: Option<[u8; 32]>) {
        let index = slot as usize % self.buckets.len();
        if !self.buckets[index].valid || self.buckets[index].slot != slot {
            self.buckets[index].reset(slot);
        }
        self.buckets[index].update(deltas, cohort);
    }

    fn aggregate(&self, slot: u64) -> Aggregate {
        let mut aggregate = Aggregate::default();
        for bucket in &self.buckets {
            if !bucket.valid || (bucket.slot != slot && bucket.slot.saturating_add(1) != slot) {
                continue;
            }
            aggregate.outcomes = aggregate.outcomes.saturating_add(bucket.outcomes);
            for (score, value) in aggregate.scores.iter_mut().zip(bucket.scores) {
                *score = score.saturating_add(value).clamp(SCORE_MIN, SCORE_MAX);
            }
            for cohort in bucket.cohorts.iter().flatten() {
                if !aggregate.cohorts.contains(&Some(*cohort))
                    && let Some(target) = aggregate.cohorts.iter_mut().find(|slot| slot.is_none())
                {
                    *target = Some(*cohort);
                }
            }
        }
        aggregate
    }

    fn is_live(&self, slot: u64) -> bool {
        self.buckets.iter().any(|bucket| {
            bucket.valid && (bucket.slot == slot || bucket.slot.saturating_add(1) == slot)
        })
    }
}

#[derive(Default)]
struct Aggregate {
    scores: [i8; 4],
    outcomes: u8,
    cohorts: [Option<[u8; 32]>; MAX_COHORTS],
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LearningPolicy {
    enabled: bool,
    aggressiveness: WebCarrierNegotiationAggressiveness,
    lifetime: Duration,
    health_window: Duration,
}

/// Evidence detached under the policy lock and released by its caller.
pub(super) struct DetachedCarrierEvidence {
    entries: HashMap<EvidenceKey, Evidence>,
    insertion_order: VecDeque<(EvidenceKey, u64)>,
}

/// Result of one generation-fenced policy reconciliation.
pub(super) struct CarrierLearningPolicyOutcome {
    /// Current epoch after the reconciliation.
    #[cfg(test)]
    pub(super) epoch: Option<u64>,
    /// Whether this generation was current enough to apply.
    pub(super) applied: bool,
    /// Retired evidence whose allocation is released outside the policy lock.
    pub(super) detached: Option<DetachedCarrierEvidence>,
}

#[derive(Clone, Copy)]
struct Thresholds {
    user_agent: u8,
    ip: Option<u8>,
    profile_outcomes: u8,
    profile_cohorts: usize,
}

impl Thresholds {
    fn for_aggressiveness(value: WebCarrierNegotiationAggressiveness) -> Self {
        match value {
            WebCarrierNegotiationAggressiveness::Conservative => Self {
                user_agent: 3,
                ip: None,
                profile_outcomes: 8,
                profile_cohorts: 4,
            },
            WebCarrierNegotiationAggressiveness::Balanced => Self {
                user_agent: 2,
                ip: Some(3),
                profile_outcomes: 6,
                profile_cohorts: 3,
            },
            WebCarrierNegotiationAggressiveness::Aggressive => Self {
                user_agent: 1,
                ip: Some(1),
                profile_outcomes: 4,
                profile_cohorts: 2,
            },
        }
    }
}

/// Process-local bounded two-bucket carrier evidence store.
pub(super) struct CarrierLearning {
    entries: HashMap<EvidenceKey, Evidence>,
    insertion_order: VecDeque<(EvidenceKey, u64)>,
    capacity: usize,
    insertion_sequence: u64,
    epoch: Option<u64>,
    policy: Option<LearningPolicy>,
    applied_generation: Option<u64>,
    policy_started_at: Instant,
}

impl CarrierLearning {
    /// Creates an empty store under the restart-owned capacity ceiling.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            capacity,
            insertion_sequence: 1,
            epoch: Some(0),
            policy: None,
            applied_generation: None,
            policy_started_at: Instant::now(),
        }
    }

    /// Applies one semantic policy unless a newer generation already owns the store.
    pub(super) fn apply_policy(
        &mut self,
        now: Instant,
        generation: u64,
        enabled: bool,
        aggressiveness: WebCarrierNegotiationAggressiveness,
        lifetime: Duration,
        health_window: Duration,
    ) -> CarrierLearningPolicyOutcome {
        if self
            .applied_generation
            .is_some_and(|applied| generation < applied)
        {
            return CarrierLearningPolicyOutcome {
                #[cfg(test)]
                epoch: self.epoch,
                applied: false,
                detached: None,
            };
        }
        let policy = LearningPolicy {
            enabled,
            aggressiveness,
            lifetime,
            health_window,
        };
        self.applied_generation = Some(generation);
        let mut detached = None;
        if self.policy != Some(policy) {
            detached = Some(DetachedCarrierEvidence {
                entries: std::mem::take(&mut self.entries),
                insertion_order: std::mem::take(&mut self.insertion_order),
            });
            self.insertion_sequence = 1;
            self.epoch = self.epoch.and_then(|epoch| epoch.checked_add(1));
            self.policy = Some(policy);
            self.policy_started_at = now;
        }
        CarrierLearningPolicyOutcome {
            #[cfg(test)]
            epoch: self.epoch,
            applied: true,
            detached,
        }
    }

    /// Matches a request to the exact applied generation and semantic policy.
    pub(super) fn epoch_for_policy(
        &self,
        generation: u64,
        enabled: bool,
        aggressiveness: WebCarrierNegotiationAggressiveness,
        lifetime: Duration,
        health_window: Duration,
    ) -> CarrierLearningEpoch {
        if self.applied_generation != Some(generation)
            || self.policy
                != Some(LearningPolicy {
                    enabled,
                    aggressiveness,
                    lifetime,
                    health_window,
                })
        {
            return CarrierLearningEpoch::Pending;
        }
        self.epoch
            .map_or(CarrierLearningEpoch::Exhausted, CarrierLearningEpoch::Ready)
    }

    /// Ranks supported configured candidates without scanning the evidence store.
    pub(super) fn rank(
        &self,
        now: Instant,
        configured: &[WebCarrier],
        request: super::CarrierRequest,
        profile_key: ProfileKey,
        client_ip: IpAddr,
        ip_learning_eligible: bool,
    ) -> (Vec<WebCarrier>, [i16; 4]) {
        let Some(policy) = self.policy.filter(|policy| policy.enabled) else {
            return (supported(configured, request), [0; 4]);
        };
        let slot = bucket_slot(self.policy_started_at, now, policy.lifetime);
        let thresholds = Thresholds::for_aggressiveness(policy.aggressiveness);
        let profile = self
            .entries
            .get(&EvidenceKey::Profile(profile_key))
            .map(|entry| entry.aggregate(slot));
        let user_agent = self
            .entries
            .get(&EvidenceKey::UserAgent(
                profile_key,
                request.class(),
                request.user_agent_hash(),
            ))
            .map(|entry| entry.aggregate(slot));
        let ip = (ip_learning_eligible && thresholds.ip.is_some())
            .then(|| self.entries.get(&EvidenceKey::Ip(profile_key, client_ip)))
            .flatten()
            .map(|entry| entry.aggregate(slot));
        let profile_ready = profile.as_ref().is_some_and(|entry| {
            entry.outcomes >= thresholds.profile_outcomes
                && entry.cohorts.iter().flatten().count() >= thresholds.profile_cohorts
        });
        let user_agent_ready = user_agent
            .as_ref()
            .is_some_and(|entry| entry.outcomes >= thresholds.user_agent);
        let ip_ready = thresholds
            .ip
            .is_some_and(|minimum| ip.as_ref().is_some_and(|entry| entry.outcomes >= minimum));
        let mut scores = [0i16; 4];
        for carrier in WebCarrier::ALL {
            let index = carrier.index();
            if profile_ready {
                scores[index] += i16::from(profile.as_ref().map_or(0, |value| value.scores[index]))
                    * PROFILE_WEIGHT;
            }
            if user_agent_ready {
                scores[index] +=
                    i16::from(user_agent.as_ref().map_or(0, |value| value.scores[index]))
                        * USER_AGENT_WEIGHT;
            }
            if ip_ready {
                scores[index] +=
                    i16::from(ip.as_ref().map_or(0, |value| value.scores[index])) * IP_WEIGHT;
            }
        }
        let mut ranked = supported(configured, request);
        let fallback = configured
            .last()
            .copied()
            .filter(|carrier| request.supports(*carrier));
        if let Some(fallback) = fallback {
            ranked.retain(|carrier| *carrier != fallback);
        }
        ranked.sort_by_key(|carrier| std::cmp::Reverse(scores[carrier.index()]));
        if let Some(fallback) = fallback {
            ranked.push(fallback);
        }
        (ranked, scores)
    }

    /// Applies one complete attempt chain as one atomic evidence sample.
    pub(super) fn record_chain(
        &mut self,
        now: Instant,
        epoch: u64,
        context: CarrierLearningContext,
        failures: &[WebCarrier],
        winner: WebCarrier,
    ) -> CarrierLearningRecordOutcome {
        let Some(policy) = self.policy.filter(|policy| policy.enabled) else {
            return CarrierLearningRecordOutcome::PolicyDisabled;
        };
        if Some(epoch) != self.epoch {
            return CarrierLearningRecordOutcome::StaleEpoch;
        }
        let mut deltas = [0i8; 4];
        let _ = failures;
        deltas[winner.index()] = deltas[winner.index()].saturating_add(1);
        let thresholds = Thresholds::for_aggressiveness(policy.aggressiveness);
        let keys = [
            Some(EvidenceKey::Profile(context.profile_key)),
            Some(EvidenceKey::UserAgent(
                context.profile_key,
                context.class,
                context.user_agent_hash,
            )),
            (context.ip_learning_eligible && thresholds.ip.is_some())
                .then_some(EvidenceKey::Ip(context.profile_key, context.client_ip)),
        ];
        let missing = keys
            .iter()
            .flatten()
            .filter(|key| !self.entries.contains_key(key))
            .count();
        if self
            .insertion_sequence
            .checked_add(missing as u64)
            .is_none()
        {
            return CarrierLearningRecordOutcome::SequenceExhausted;
        }
        let evictions_needed = self
            .entries
            .len()
            .saturating_add(missing)
            .saturating_sub(self.capacity);
        let evictable = self
            .entries
            .keys()
            .filter(|key| !keys.contains(&Some(**key)))
            .count();
        if evictions_needed > evictable {
            return CarrierLearningRecordOutcome::CapacityRejected;
        }
        self.make_room(&keys);
        let slot = bucket_slot(self.policy_started_at, now, policy.lifetime);
        let cohort = cohort_hash(context);
        for (index, key) in keys.into_iter().enumerate() {
            let Some(key) = key else { continue };
            self.update_key(key, slot, deltas, (index == 0).then_some(cohort));
        }
        CarrierLearningRecordOutcome::Recorded
    }

    /// Reclaims a fixed number of entries outside both half-window buckets.
    pub(super) fn prune(&mut self, now: Instant) {
        let Some(policy) = self.policy else { return };
        let slot = bucket_slot(self.policy_started_at, now, policy.lifetime);
        let budget = self.insertion_order.len().min(PRUNE_ENTRIES_PER_TICK);
        for _ in 0..budget {
            let Some((key, sequence)) = self.insertion_order.pop_front() else {
                break;
            };
            let current = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.insertion_sequence == sequence);
            if !current {
                continue;
            }
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.is_live(slot))
            {
                self.insertion_order.push_back((key, sequence));
            } else {
                self.entries.remove(&key);
            }
        }
    }

    fn make_room(&mut self, keys: &[Option<EvidenceKey>; 3]) {
        let missing = keys
            .iter()
            .flatten()
            .filter(|key| !self.entries.contains_key(key))
            .count();
        let mut remaining = self.insertion_order.len();
        while self.entries.len().saturating_add(missing) > self.capacity && remaining > 0 {
            remaining -= 1;
            let Some((oldest, sequence)) = self.insertion_order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&oldest)
                .is_none_or(|entry| entry.insertion_sequence != sequence)
            {
                continue;
            }
            if keys.contains(&Some(oldest)) {
                self.insertion_order.push_back((oldest, sequence));
                continue;
            }
            self.entries.remove(&oldest);
        }
    }

    fn update_key(
        &mut self,
        key: EvidenceKey,
        slot: u64,
        deltas: [i8; 4],
        cohort: Option<[u8; 32]>,
    ) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.update(slot, deltas, cohort);
            return;
        }
        let insertion_sequence = self.insertion_sequence;
        self.insertion_sequence += 1;
        self.entries.insert(key, Evidence::new(insertion_sequence));
        self.insertion_order.push_back((key, insertion_sequence));
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.update(slot, deltas, cohort);
        }
    }
}

fn supported(configured: &[WebCarrier], request: super::CarrierRequest) -> Vec<WebCarrier> {
    configured
        .iter()
        .copied()
        .filter(|carrier| request.supports(*carrier))
        .collect()
}

fn bucket_slot(start: Instant, now: Instant, lifetime: Duration) -> u64 {
    let half = (lifetime / 2).max(Duration::from_nanos(1));
    let quotient = now.saturating_duration_since(start).as_nanos() / half.as_nanos();
    quotient.min(u128::from(u64::MAX)) as u64
}

fn cohort_hash(context: CarrierLearningContext) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COHORT_CONTEXT);
    digest.update(context.profile_key);
    digest.update([match context.class {
        CarrierClientClass::Legacy => 0,
        CarrierClientClass::Bridge => 1,
        CarrierClientClass::BrowserHint => 2,
        CarrierClientClass::Ios => 3,
    }]);
    digest.update(context.user_agent_hash);
    match context.client_ip {
        IpAddr::V4(address) => {
            digest.update([4]);
            digest.update(address.octets());
        }
        IpAddr::V6(address) => {
            digest.update([6]);
            digest.update(address.octets());
        }
    }
    digest.finalize().into()
}

#[cfg(test)]
#[path = "carrier_learning/tests.rs"]
mod tests;
