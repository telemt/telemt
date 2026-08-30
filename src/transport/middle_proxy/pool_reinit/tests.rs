use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::{MePool, commit_reinit_state};
use crate::transport::middle_proxy::pool::{
    ReinitAttemptState, ReinitCoordinatorState, ReinitPendingState,
};

fn addr(octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)), port)
}

#[test]
fn coverage_ratio_counts_dc_coverage_not_floor() {
    let dc1 = addr(1, 2001);
    let dc2 = addr(2, 2002);

    let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
    desired_by_dc.insert(1, HashSet::from([dc1]));
    desired_by_dc.insert(2, HashSet::from([dc2]));

    let active_writer_addrs = HashSet::from([(1, dc1)]);
    let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &active_writer_addrs);

    assert_eq!(ratio, 0.5);
    assert_eq!(missing_dc, vec![2]);
}

#[test]
fn coverage_ratio_ignores_empty_dc_groups() {
    let dc1 = addr(1, 2001);

    let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
    desired_by_dc.insert(1, HashSet::from([dc1]));
    desired_by_dc.insert(2, HashSet::new());

    let active_writer_addrs = HashSet::from([(1, dc1)]);
    let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &active_writer_addrs);

    assert_eq!(ratio, 1.0);
    assert!(missing_dc.is_empty());
}

#[test]
fn coverage_ratio_reports_missing_dcs_sorted() {
    let dc1 = addr(1, 2001);
    let dc2 = addr(2, 2002);

    let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
    desired_by_dc.insert(2, HashSet::from([dc2]));
    desired_by_dc.insert(1, HashSet::from([dc1]));

    let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &HashSet::new());

    assert_eq!(ratio, 0.0);
    assert_eq!(missing_dc, vec![1, 2]);
}

#[test]
fn stale_concurrent_attempt_cannot_regress_active_generation() {
    let mut state = ReinitCoordinatorState {
        next_attempt_id: 3,
        active_generation: 1,
        desired_map_hash: 22,
        pending: Some(ReinitPendingState {
            generation: 3,
            started_at_epoch_secs: 1,
            map_hash: 22,
        }),
        attempts: HashMap::from([
            (
                1,
                ReinitAttemptState {
                    generation: 2,
                    map_hash: 11,
                    hardswap: true,
                    committed: false,
                },
            ),
            (
                2,
                ReinitAttemptState {
                    generation: 3,
                    map_hash: 22,
                    hardswap: true,
                    committed: false,
                },
            ),
        ]),
    };

    assert!(commit_reinit_state(&mut state, 2, 3, 22, true));
    assert_eq!(state.active_generation, 3);
    assert!(!commit_reinit_state(&mut state, 1, 2, 11, true));
    assert_eq!(state.active_generation, 3);
    assert!(state.pending.is_none());
}
