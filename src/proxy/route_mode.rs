use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

pub(crate) const ROUTE_SWITCH_ERROR_MSG: &str = "Route mode switched by cutover";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RelayRouteMode {
    Direct = 0,
    Middle = 1,
}

impl RelayRouteMode {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Middle,
            _ => Self::Direct,
        }
    }

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
}

#[derive(Clone)]
pub(crate) struct RouteRuntimeController {
    mode: Arc<AtomicU8>,
    generation: Arc<AtomicU64>,
    direct_since_epoch_secs: Arc<AtomicU64>,
    tx: watch::Sender<RouteCutoverState>,
}

impl RouteRuntimeController {
    pub(crate) fn new(initial_mode: RelayRouteMode) -> Self {
        let initial = RouteCutoverState {
            mode: initial_mode,
            generation: 0,
        };
        let (tx, _rx) = watch::channel(initial);
        let direct_since_epoch_secs = if matches!(initial_mode, RelayRouteMode::Direct) {
            now_epoch_secs()
        } else {
            0
        };
        Self {
            mode: Arc::new(AtomicU8::new(initial_mode.as_u8())),
            generation: Arc::new(AtomicU64::new(0)),
            direct_since_epoch_secs: Arc::new(AtomicU64::new(direct_since_epoch_secs)),
            tx,
        }
    }

    pub(crate) fn snapshot(&self) -> RouteCutoverState {
        RouteCutoverState {
            mode: RelayRouteMode::from_u8(self.mode.load(Ordering::Relaxed)),
            generation: self.generation.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<RouteCutoverState> {
        self.tx.subscribe()
    }

    pub(crate) fn direct_since_epoch_secs(&self) -> Option<u64> {
        let value = self.direct_since_epoch_secs.load(Ordering::Relaxed);
        (value > 0).then_some(value)
    }

    pub(crate) fn set_mode(&self, mode: RelayRouteMode) -> Option<RouteCutoverState> {
        let previous = self.mode.swap(mode.as_u8(), Ordering::Relaxed);
        if previous == mode.as_u8() {
            return None;
        }
        if matches!(mode, RelayRouteMode::Direct) {
            self.direct_since_epoch_secs
                .store(now_epoch_secs(), Ordering::Relaxed);
        } else {
            self.direct_since_epoch_secs.store(0, Ordering::Relaxed);
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let next = RouteCutoverState { mode, generation };
        self.tx.send_replace(next);
        Some(next)
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
    _session_mode: RelayRouteMode,
    session_generation: u64,
) -> bool {
    current.generation > session_generation
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
    let mut value = session_id
        ^ generation.rotate_left(17)
        ^ 0x9e37_79b9_7f4a_7c15;
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    let ms = 1000 + (value % 1000);
    Duration::from_millis(ms)
}
