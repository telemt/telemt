use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
}

#[derive(Clone)]
pub(crate) struct RouteRuntimeController {
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
            direct_since_epoch_secs: Arc::new(AtomicU64::new(direct_since_epoch_secs)),
            tx,
        }
    }

    pub(crate) fn snapshot(&self) -> RouteCutoverState {
        *self.tx.borrow()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<RouteCutoverState> {
        self.tx.subscribe()
    }

    pub(crate) fn direct_since_epoch_secs(&self) -> Option<u64> {
        let value = self.direct_since_epoch_secs.load(Ordering::Relaxed);
        (value > 0).then_some(value)
    }

    pub(crate) fn set_mode(&self, mode: RelayRouteMode) -> Option<RouteCutoverState> {
        let mut next = None;
        let changed = self.tx.send_if_modified(|state| {
            if state.mode == mode {
                return false;
            }
            if matches!(mode, RelayRouteMode::Direct) {
                self.direct_since_epoch_secs
                    .store(now_epoch_secs(), Ordering::Relaxed);
            } else {
                self.direct_since_epoch_secs.store(0, Ordering::Relaxed);
            }
            state.mode = mode;
            state.generation = state.generation.saturating_add(1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutover_stagger_delay_is_deterministic() {
        let a = cutover_stagger_delay(42, 7);
        let b = cutover_stagger_delay(42, 7);
        assert_eq!(a, b);
    }

    #[test]
    fn cutover_stagger_delay_range() {
        for sid in [0, 1, u64::MAX / 2, u64::MAX] {
            for g in [0, 1, 99, u64::MAX] {
                let d = cutover_stagger_delay(sid, g);
                assert!(d.as_millis() >= 1000, "min 1s for sid={sid} gen={g}");
                assert!(d.as_millis() < 2000, "max <2s for sid={sid} gen={g}");
            }
        }
    }

    #[test]
    fn cutover_stagger_delay_differs_for_different_inputs() {
        assert_ne!(
            cutover_stagger_delay(1, 0),
            cutover_stagger_delay(2, 0)
        );
    }

    #[test]
    fn affected_cutover_state_branch_table() {
        let ctrl = RouteRuntimeController::new(RelayRouteMode::Middle);
        let rx = ctrl.subscribe();

        assert!(affected_cutover_state(&rx, RelayRouteMode::Middle, 0).is_none());
        assert!(affected_cutover_state(&rx, RelayRouteMode::Direct, 0).is_none());

        ctrl.set_mode(RelayRouteMode::Direct);
        assert!(
            affected_cutover_state(&rx, RelayRouteMode::Middle, 0).is_some(),
            "same generation but different mode after cutover"
        );
        assert!(
            affected_cutover_state(&rx, RelayRouteMode::Direct, 0).is_none(),
            "same mode, not affected"
        );

        let snap = ctrl.snapshot();
        assert!(
            affected_cutover_state(&rx, RelayRouteMode::Direct, snap.generation).is_none(),
            "up-to-date generation"
        );
        assert!(
            affected_cutover_state(&rx, RelayRouteMode::Middle, snap.generation).is_none(),
            "up-to-date generation even with different mode"
        );
    }

    #[test]
    fn is_session_affected_by_cutover_branch_table() {
        let state = RouteCutoverState {
            mode: RelayRouteMode::Direct,
            generation: 5,
        };

        assert!(!is_session_affected_by_cutover(state, RelayRouteMode::Direct, 5));
        assert!(is_session_affected_by_cutover(state, RelayRouteMode::Middle, 4));
        assert!(!is_session_affected_by_cutover(state, RelayRouteMode::Middle, 5));
        assert!(!is_session_affected_by_cutover(state, RelayRouteMode::Direct, 6));
    }

    #[test]
    fn relay_route_mode_values() {
        assert_eq!(RelayRouteMode::Direct as u8, 0);
        assert_eq!(RelayRouteMode::Middle as u8, 1);
        assert_eq!(RelayRouteMode::Direct.as_str(), "direct");
        assert_eq!(RelayRouteMode::Middle.as_str(), "middle");
    }

    #[test]
    fn now_epoch_secs_returns_positive() {
        let t = now_epoch_secs();
        assert!(t > 1_700_000_000, "timestamp should be post-2023");
    }

    #[test]
    fn controller_set_mode_advances_generation() {
        let ctrl = RouteRuntimeController::new(RelayRouteMode::Direct);
        assert_eq!(ctrl.snapshot().generation, 0);

        ctrl.set_mode(RelayRouteMode::Middle);
        assert_eq!(ctrl.snapshot().generation, 1);
        assert_eq!(ctrl.snapshot().mode, RelayRouteMode::Middle);

        ctrl.set_mode(RelayRouteMode::Direct);
        assert_eq!(ctrl.snapshot().generation, 2);
        assert_eq!(ctrl.snapshot().mode, RelayRouteMode::Direct);
    }

    #[test]
    fn controller_set_same_mode_is_noop() {
        let ctrl = RouteRuntimeController::new(RelayRouteMode::Direct);
        assert!(ctrl.set_mode(RelayRouteMode::Direct).is_none());
        assert_eq!(ctrl.snapshot().generation, 0);
    }

    #[test]
    fn direct_since_epoch_secs_tracking() {
        let ctrl = RouteRuntimeController::new(RelayRouteMode::Middle);
        assert!(ctrl.direct_since_epoch_secs().is_none());

        ctrl.set_mode(RelayRouteMode::Direct);
        let t = ctrl.direct_since_epoch_secs().expect("set after direct");
        assert!(t > 1_700_000_000);

        ctrl.set_mode(RelayRouteMode::Middle);
        assert!(ctrl.direct_since_epoch_secs().is_none());
    }

    mod tier_assertions {
        use super::*;

        #[test]
        fn controller_new_initial_mode_direct() {
            let ctrl = RouteRuntimeController::new(RelayRouteMode::Direct);
            let snap = ctrl.snapshot();
            assert_eq!(snap.mode, RelayRouteMode::Direct);
            assert_eq!(snap.generation, 0);
            assert!(ctrl.direct_since_epoch_secs().is_some());
        }

        #[test]
        fn controller_new_initial_mode_middle() {
            let ctrl = RouteRuntimeController::new(RelayRouteMode::Middle);
            let snap = ctrl.snapshot();
            assert_eq!(snap.mode, RelayRouteMode::Middle);
            assert_eq!(snap.generation, 0);
            assert!(ctrl.direct_since_epoch_secs().is_none());
        }

        #[test]
        fn controller_subscribe_sees_initial_value() {
            let ctrl = RouteRuntimeController::new(RelayRouteMode::Middle);
            let rx = ctrl.subscribe();
            let observed = *rx.borrow();
            assert_eq!(observed.mode, RelayRouteMode::Middle);
            assert_eq!(observed.generation, 0);
        }

        #[test]
        fn controller_subscribe_sees_update_after_set_mode() {
            let ctrl = RouteRuntimeController::new(RelayRouteMode::Middle);
            let rx = ctrl.subscribe();

            ctrl.set_mode(RelayRouteMode::Direct);
            let observed = rx.borrow().clone();
            assert_eq!(observed.mode, RelayRouteMode::Direct);
            assert_eq!(observed.generation, 1);
        }

        #[test]
        fn controller_set_mode_returns_state_with_new_mode() {
            let ctrl = RouteRuntimeController::new(RelayRouteMode::Middle);
            let result = ctrl.set_mode(RelayRouteMode::Direct);
            let returned = result.expect("mode change must return Some");
            assert_eq!(returned.mode, RelayRouteMode::Direct);
            assert_eq!(returned.generation, 1);
        }

        #[test]
        fn controller_snapshot_returns_watch_state() {
            let ctrl = RouteRuntimeController::new(RelayRouteMode::Direct);
            let snap = ctrl.snapshot();
            let rx = ctrl.subscribe();
            assert_eq!(snap, *rx.borrow());
        }
    }
}
