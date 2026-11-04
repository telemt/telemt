use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RelayRouteMode {
    Direct = 0,
    Middle = 1,
}

impl RelayRouteMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Middle => "middle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RouteCutoverState {
    pub mode: RelayRouteMode,
    pub generation: u64,
    pub direct_since_epoch_secs: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct RouteRuntimeController {
    tx: watch::Sender<RouteCutoverState>,
}

impl RouteRuntimeController {
    pub(crate) fn new(initial_mode: RelayRouteMode) -> Self {
        let initial = RouteCutoverState {
            mode: initial_mode,
            generation: 0,
            direct_since_epoch_secs: matches!(initial_mode, RelayRouteMode::Direct)
                .then(now_epoch_secs),
        };
        let (tx, _rx) = watch::channel(initial);
        Self { tx }
    }

    pub(crate) fn snapshot(&self) -> RouteCutoverState {
        *self.tx.borrow()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<RouteCutoverState> {
        self.tx.subscribe()
    }

    pub(crate) fn set_mode(&self, mode: RelayRouteMode) -> Option<RouteCutoverState> {
        let mut next = None;
        let changed = self.tx.send_if_modified(|state| {
            if state.mode == mode {
                return false;
            }
            state.mode = mode;
            state.generation = state.generation.saturating_add(1);
            state.direct_since_epoch_secs =
                matches!(mode, RelayRouteMode::Direct).then(now_epoch_secs);
            next = Some(*state);
            true
        });

        if !changed {
            return None;
        }

        next
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

pub(crate) fn is_session_affected_by_cutover(
    current: RouteCutoverState,
    session_mode: RelayRouteMode,
    session_generation: u64,
) -> bool {
    current.generation > session_generation && current.mode != session_mode
}

pub(crate) fn affected_cutover_state(
    rx: &watch::Receiver<RouteCutoverState>,
    session_mode: RelayRouteMode,
    session_generation: u64,
) -> Option<RouteCutoverState> {
    let current = *rx.borrow();
    if is_session_affected_by_cutover(current, session_mode, session_generation) {
        return Some(current);
    }
    None
}

pub(crate) fn cutover_stagger_delay(session_id: u64, generation: u64) -> Duration {
    let mut value = session_id ^ generation.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    let ms = 1000 + (value % 1000);
    Duration::from_millis(ms)
}

#[cfg(test)]
#[path = "tests/route_mode_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/route_mode_coherence_adversarial_tests.rs"]
mod coherence_adversarial_tests;
