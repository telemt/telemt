use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{CarrierRequest, ProfileKey, TokenAuthenticator, TokenHash, TokenKind};
use crate::config::{WebCarrier, WebRuntimeConfig, WebRuntimeProfile, WebTimeoutsConfig};
use crate::maestro::generation::RuntimeGeneration;
use crate::proxy::user_admission::UserSessionRegistration;
use crate::web::session::WebSession;
use crate::web::telemetry::WebCarrierSelectionDisposition;

// Expiry sweeps preserve admission accounting while skipping maps with no due entries.
mod expiry;
pub(super) use expiry::remove_expired_locked;

const WEB_PROFILE_OWNER_CONTEXT: &[u8] = b"telemt-web-profile-owner-v1\0";

/// Manager-owned carrier progress used to fence provisional replacement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CarrierChainPhase {
    /// No carrier has committed verified application traffic yet.
    Provisional,
    /// A committed carrier still awaits the health observation window.
    CommittedPendingHealth,
    /// The committed carrier has satisfied the health observation window.
    Healthy,
}

impl CarrierChainPhase {
    /// Returns the stable carrier-state token exposed in negotiation responses.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Provisional => "provisional",
            Self::CommittedPendingHealth => "committed",
            Self::Healthy => "healthy",
        }
    }
}

/// One issued bootstrap and optional idempotent session-creation replay state.
pub(super) struct Bootstrap {
    /// User authority ownership retained for the credential lifetime.
    pub(super) user_registration: UserSessionRegistration,
    /// Credential and replay-state expiry deadline.
    pub(super) expires_at: Instant,
    /// Stable ordering point used for bounded eviction.
    pub(super) issued_at: Instant,
    /// Issuing address charged for the unused-bootstrap quota.
    pub(super) issuance_ip: IpAddr,
    /// Immutable profile selected during capability validation.
    pub(super) profile: Arc<WebRuntimeProfile>,
    /// Request and session deadlines frozen with the generated bridge.
    pub(super) timeouts: WebTimeoutsConfig,
    /// Process-unique non-secret identifier shared by bootstrap and session traces.
    pub(super) trace_session_id: u64,
    /// Whether this bridge was issued with the diagnostic sideband enabled.
    pub(super) bridge_diagnostics_enabled: bool,
    /// Fixed event slots already claimed by this bootstrap chain.
    pub(super) bridge_diagnostic_events: u16,
    /// Bounded display form of the issuing User-Agent.
    pub(super) user_agent: Option<Arc<str>>,
    /// Opaque non-secret identifier used for exact User-Agent filtering.
    pub(super) user_agent_id: Option<[u8; 16]>,
    /// Digest of the accepted HELLO body for idempotent retry matching.
    pub(super) body_digest: TokenHash,
    /// Zeroizing copy returned only for an exact session-creation retry.
    pub(super) session_token: Zeroizing<String>,
    /// Created session retained while retry replay remains valid.
    pub(super) session: Option<Arc<WebSession>>,
    /// Metadata that defines exact attempt replay and candidate advancement.
    pub(super) carrier_request: Option<CarrierRequest>,
    /// Learning-ranked carrier order frozen by the first automatic attempt.
    pub(super) carrier_candidates: Arc<[WebCarrier]>,
    /// Weighted learning scores captured when the candidate order was frozen.
    pub(super) carrier_scores: [i16; 4],
    /// Current one-based carrier attempt, or zero before session creation.
    pub(super) carrier_attempt: u8,
    /// Prevents concurrent retries from replacing the same attempt twice.
    pub(super) carrier_transitioning: bool,
    /// Manager-owned attempt-chain phase used for replacement linearization.
    pub(super) carrier_phase: CarrierChainPhase,
    /// Monotonic start of the first automatic session attempt.
    pub(super) carrier_started_at: Option<Instant>,
    /// Absolute server-side end of the automatic attempt chain.
    pub(super) carrier_deadline_at: Option<Instant>,
    /// Failed candidates staged until one winner becomes healthy.
    pub(super) carrier_failures: [Option<WebCarrier>; 3],
    /// Learning-policy epoch frozen by the first automatic attempt.
    pub(super) carrier_learning_epoch: u64,
    /// Frozen reason learning did or did not influence carrier ordering.
    pub(super) carrier_learning_disposition: WebCarrierSelectionDisposition,
    /// DELETE observed before an in-flight replacement committed its swap.
    pub(super) close_requested: bool,
    /// Effective address frozen by the first session-creation request.
    pub(super) session_client_ip: Option<IpAddr>,
    /// Whether the first request carried an authoritative public forwarded address.
    pub(super) session_ip_learning_eligible: bool,
    /// Distinguishes unused issuance quota from completed creation replay state.
    pub(super) used: bool,
    /// Whether this credential was issued by the post-commit recovery representation.
    pub(super) recovery: bool,
    /// Previous logical session authenticated by the recovery request, if current.
    pub(super) predecessor_session_id: Option<u64>,
}

/// Bounded replay marker for one explicitly or naturally closed session token.
pub(super) struct ClosedToken {
    /// Deadline after which the token hash may be forgotten.
    pub(super) expires_at: Instant,
    /// Canonical host that owned the session.
    pub(super) host: String,
    /// Carrier that owned the retired bearer.
    pub(super) carrier: WebCarrier,
}

/// Current logical-session owner stored without exposing bearer credentials.
pub(super) struct LiveSessionIndex {
    /// Current bearer hash used only for internal pointer revalidation.
    pub(super) session_hash: TokenHash,
    /// Bootstrap chain that owns carrier replacement and close intent.
    pub(super) bootstrap_hash: TokenHash,
    /// Current carrier incarnation in the logical trace session.
    pub(super) attempt: u8,
    /// Bounded display form of the issuing User-Agent.
    pub(super) user_agent: Option<Arc<str>>,
    /// Opaque non-secret identifier used for exact User-Agent filtering.
    pub(super) user_agent_id: Option<[u8; 16]>,
}

/// Bounded logical-session tombstone used for exact detail semantics.
pub(super) struct ClosedSession {
    /// Tombstone expiry deadline.
    pub(super) expires_at: Instant,
    /// Last carrier incarnation closed for this logical session.
    pub(super) attempt: u8,
    /// Last carrier owning this logical session.
    pub(super) carrier: WebCarrier,
    /// First-writer terminal close cause.
    pub(super) reason: crate::web::session::SessionCloseReason,
    /// Monotonic instant used only to report bounded close age.
    pub(super) closed_at: Instant,
}

/// Token-bucket state for one process-wide creation class.
#[derive(Default)]
pub(super) struct RateState {
    tokens: f64,
    last: Option<Instant>,
}

struct StreamPortState {
    active: HashSet<u16>,
    next: u16,
}

/// Stream admission and KDF tuple ownership isolated from credential transitions.
#[derive(Default)]
pub(super) struct StreamAdmissionState {
    /// Process shutdown admission latch.
    pub(super) closed: bool,
    /// Live stream counts by stable profile key.
    pub(super) streams_per_profile: HashMap<ProfileKey, usize>,
    /// Process-wide live relay-task count.
    pub(super) streams_live: usize,
    stream_ports: HashMap<(IpAddr, SocketAddr), StreamPortState>,
    /// Logical-stream creation rate limiter.
    pub(super) stream_rate: RateState,
}

/// Process-wide WEB registries and quota accounting protected by one short lock.
pub(super) struct ManagerState {
    /// Bootstrap credentials indexed by their SHA-256 token hash.
    pub(super) bootstraps: HashMap<TokenHash, Bootstrap>,
    /// Conservative earliest expiry; deletion and frozen-TTL renewal may leave it early.
    pub(super) bootstrap_expiry: Option<Instant>,
    /// Unused bootstrap ownership counts by forwarded client address.
    pub(super) bootstraps_per_ip: HashMap<IpAddr, usize>,
    /// Live sessions indexed by bearer-token hash.
    pub(super) sessions: HashMap<TokenHash, Arc<WebSession>>,
    /// Stable ordered logical-session lookup independent from bearer hashes.
    pub(super) session_index: BTreeMap<u64, LiveSessionIndex>,
    /// Recently closed logical sessions retained for exact detail responses.
    pub(super) closed_sessions: HashMap<u64, ClosedSession>,
    /// Insertion order for bounded logical-session tombstones.
    pub(super) closed_session_order: VecDeque<u64>,
    /// Recently closed token hashes retained for idempotent DELETE semantics.
    pub(super) closed_tokens: HashMap<TokenHash, ClosedToken>,
    /// Conservative earliest expiry, lowered on every insertion or overwrite.
    pub(super) closed_token_expiry: Option<Instant>,
    /// Live session counts by forwarded client address.
    pub(super) sessions_per_ip: HashMap<IpAddr, usize>,
    /// Live session counts by stable profile key.
    pub(super) sessions_per_profile: HashMap<ProfileKey, usize>,
    /// Bootstrap issuance rate limiter.
    pub(super) bootstrap_rate: RateState,
    /// Session creation rate limiter.
    pub(super) session_rate: RateState,
    /// Generation-fenced issuance gate mirrored from the effective WEB policy.
    pub(super) issuance_enabled: bool,
    /// Generation that last authored `issuance_enabled`.
    pub(super) issuance_generation: u64,
    /// Process shutdown admission latch.
    pub(super) closed: bool,
}

impl ManagerState {
    /// Initializes empty process-owned registries with a generation-fenced issuance policy.
    pub(super) fn new(issuance_generation: u64, issuance_enabled: bool) -> Self {
        Self {
            bootstraps: HashMap::new(),
            bootstrap_expiry: None,
            bootstraps_per_ip: HashMap::new(),
            sessions: HashMap::new(),
            session_index: BTreeMap::new(),
            closed_sessions: HashMap::new(),
            closed_session_order: VecDeque::new(),
            closed_tokens: HashMap::new(),
            closed_token_expiry: None,
            sessions_per_ip: HashMap::new(),
            sessions_per_profile: HashMap::new(),
            bootstrap_rate: RateState::default(),
            session_rate: RateState::default(),
            issuance_enabled,
            issuance_generation,
            closed: false,
        }
    }

    /// Applies only policies at least as recent as the last published generation.
    pub(super) fn apply_issuance_policy(&mut self, generation: u64, enabled: bool) {
        if generation >= self.issuance_generation {
            self.issuance_generation = generation;
            self.issuance_enabled = enabled;
        }
    }
}

impl Default for ManagerState {
    fn default() -> Self {
        Self::new(0, false)
    }
}

/// Generates one collision-checked credential and its stable hash key.
pub(super) fn new_unique_token(
    generation: &RuntimeGeneration,
    state: &ManagerState,
    authenticator: &TokenAuthenticator,
    kind: TokenKind,
) -> Option<(String, TokenHash)> {
    for _ in 0..8 {
        let mut nonce = [0u8; 16];
        generation.rng.fill(&mut nonce);
        let raw = authenticator.issue(kind, nonce);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let hash = Sha256::digest(raw).into();
        if !state.bootstraps.contains_key(&hash)
            && !state.sessions.contains_key(&hash)
            && !state.closed_tokens.contains_key(&hash)
        {
            return Some((token, hash));
        }
    }
    None
}

/// Derives a secret-independent quota owner stable across capability rotation.
pub(super) fn profile_key(profile: &WebRuntimeProfile) -> ProfileKey {
    let mut digest = Sha256::new();
    digest.update(WEB_PROFILE_OWNER_CONTEXT);
    digest.update((profile.host.len() as u64).to_be_bytes());
    digest.update(profile.host.as_bytes());
    digest.update((profile.user.len() as u64).to_be_bytes());
    digest.update(profile.user.as_bytes());
    digest.update([match profile.secret_mode {
        crate::config::WebSecretMode::Plain => 0,
        crate::config::WebSecretMode::Dd => 1,
    }]);
    digest.finalize().into()
}

/// Re-resolves an issued profile against the active generation without weakening identity.
pub(super) fn matching_profile(
    runtime: &WebRuntimeConfig,
    expected: &WebRuntimeProfile,
) -> Option<Arc<WebRuntimeProfile>> {
    runtime
        .profiles
        .iter()
        .find(|profile| {
            profile.host == expected.host
                && profile.public_addr == expected.public_addr
                && profile.user == expected.user
                && profile.credential_id == expected.credential_id
                && profile.secret_mode == expected.secret_mode
                && profile.carrier == expected.carrier
                && profile.carrier_negotiation_enabled == expected.carrier_negotiation_enabled
                && profile.carrier_learning == expected.carrier_learning
                && profile.carriers == expected.carriers
                && profile.carrier_negotiation_deadlines_secs
                    == expected.carrier_negotiation_deadlines_secs
                && profile.capability == expected.capability
                && profile.key_fingerprint == expected.key_fingerprint
        })
        .cloned()
}

/// Applies one token-bucket admission decision at a caller-supplied monotonic time.
pub(super) fn allow_rate(state: &mut RateState, now: Instant, per_minute: u32, burst: u32) -> bool {
    let burst = f64::from(burst);
    if let Some(last) = state.last {
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * f64::from(per_minute) / 60.0).min(burst);
    } else {
        state.tokens = burst;
    }
    state.last = Some(now);
    if state.tokens < 1.0 {
        return false;
    }
    state.tokens -= 1.0;
    true
}

/// Detaches the oldest unused bootstrap while preserving used retry state.
pub(super) fn evict_oldest_unused_bootstrap(state: &mut ManagerState) -> Option<Bootstrap> {
    let Some(hash) = state
        .bootstraps
        .iter()
        .filter(|(_, bootstrap)| !bootstrap.used)
        .min_by_key(|(_, bootstrap)| bootstrap.issued_at)
        .map(|(hash, _)| *hash)
    else {
        return None;
    };
    let bootstrap = state.bootstraps.remove(&hash)?;
    decrement_map(&mut state.bootstraps_per_ip, &bootstrap.issuance_ip);
    Some(bootstrap)
}

/// Removes one bootstrap and releases its per-address issuance quota when unused.
pub(super) fn remove_bootstrap_locked(state: &mut ManagerState, hash: TokenHash) {
    let Some(bootstrap) = state.bootstraps.remove(&hash) else {
        return;
    };
    if !bootstrap.used {
        decrement_map(&mut state.bootstraps_per_ip, &bootstrap.issuance_ip);
    }
}

/// Retains one bounded host-bound marker for an invalidated session credential.
pub(super) fn remember_closed_token_locked(
    state: &mut ManagerState,
    hash: TokenHash,
    host: &str,
    carrier: WebCarrier,
    lifetime: Duration,
    capacity: usize,
) {
    let expires_at = Instant::now() + lifetime;
    state.closed_token_expiry = Some(
        state
            .closed_token_expiry
            .unwrap_or(expires_at)
            .min(expires_at),
    );
    state.closed_tokens.insert(
        hash,
        ClosedToken {
            expires_at,
            host: host.to_string(),
            carrier,
        },
    );
    while state.closed_tokens.len() > capacity {
        let Some(oldest) = state
            .closed_tokens
            .iter()
            .min_by_key(|(_, closed)| closed.expires_at)
            .map(|(hash, _)| *hash)
        else {
            break;
        };
        state.closed_tokens.remove(&oldest);
    }
}

/// Retains one bounded logical-session marker without storing its bearer identity.
pub(super) fn remember_closed_session_locked(
    state: &mut ManagerState,
    trace_session_id: u64,
    attempt: u8,
    carrier: WebCarrier,
    reason: crate::web::session::SessionCloseReason,
    lifetime: Duration,
    capacity: usize,
) {
    if state
        .closed_sessions
        .insert(
            trace_session_id,
            ClosedSession {
                expires_at: Instant::now() + lifetime,
                attempt,
                carrier,
                reason,
                closed_at: Instant::now(),
            },
        )
        .is_none()
    {
        state.closed_session_order.push_back(trace_session_id);
    }
    while state.closed_sessions.len() > capacity {
        let Some(oldest) = state.closed_session_order.pop_front() else {
            break;
        };
        state.closed_sessions.remove(&oldest);
    }
}

/// Decrements one counted owner and removes its map entry at zero.
pub(super) fn decrement_map<K, Q>(values: &mut HashMap<K, usize>, key: &Q)
where
    K: std::borrow::Borrow<Q> + std::hash::Hash + Eq,
    Q: std::hash::Hash + Eq + ?Sized,
{
    let remove = if let Some(value) = values.get_mut(key) {
        *value = value.saturating_sub(1);
        *value == 0
    } else {
        false
    };
    if remove {
        values.remove(key);
    }
}

/// Allocates a non-zero source port unique among live streams for one KDF route.
pub(super) fn allocate_stream_port(
    state: &mut StreamAdmissionState,
    client_ip: IpAddr,
    public_addr: SocketAddr,
) -> Option<u16> {
    let ports = state
        .stream_ports
        .entry((client_ip, public_addr))
        .or_insert_with(|| StreamPortState {
            active: HashSet::new(),
            next: 1,
        });
    for _ in 0..u16::MAX {
        let candidate = ports.next;
        ports.next = ports.next.checked_add(1).unwrap_or(1);
        if ports.active.insert(candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Releases one source port and reclaims empty per-route allocator state.
pub(super) fn release_stream_port(
    state: &mut StreamAdmissionState,
    client_ip: IpAddr,
    public_addr: SocketAddr,
    peer_port: u16,
) -> bool {
    let key = (client_ip, public_addr);
    let Some(ports) = state.stream_ports.get_mut(&key) else {
        return false;
    };
    let removed = ports.active.remove(&peer_port);
    if ports.active.is_empty() {
        state.stream_ports.remove(&key);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_ports_are_unique_per_live_route_and_state_is_reclaimed() {
        let mut state = StreamAdmissionState::default();
        let client_ip = "192.0.2.10".parse().unwrap();
        let public_addr = "203.0.113.10:443".parse().unwrap();
        let first = allocate_stream_port(&mut state, client_ip, public_addr).unwrap();
        let second = allocate_stream_port(&mut state, client_ip, public_addr).unwrap();

        assert_ne!(first, second);
        assert!(release_stream_port(
            &mut state,
            client_ip,
            public_addr,
            first,
        ));
        assert!(release_stream_port(
            &mut state,
            client_ip,
            public_addr,
            second,
        ));
        assert!(state.stream_ports.is_empty());
    }
}
