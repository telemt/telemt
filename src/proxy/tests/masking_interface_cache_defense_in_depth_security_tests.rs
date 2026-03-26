#![cfg(unix)]

use super::*;

#[test]
fn defense_in_depth_empty_refresh_preserves_previous_non_empty_interfaces() {
    let previous = vec![
        "192.168.100.7"
            .parse::<IpAddr>()
            .expect("must parse interface ip"),
    ];
    let refreshed = Vec::new();

    let next = choose_interface_snapshot(&previous, refreshed);

    assert_eq!(
        next, previous,
        "empty refresh should preserve previous non-empty snapshot to avoid fail-open loop-guard regressions"
    );
}

#[test]
fn defense_in_depth_non_empty_refresh_replaces_previous_snapshot() {
    let previous = vec![
        "192.168.100.7"
            .parse::<IpAddr>()
            .expect("must parse interface ip"),
    ];
    let refreshed = vec![
        "10.55.0.3"
            .parse::<IpAddr>()
            .expect("must parse refreshed interface ip"),
    ];

    let next = choose_interface_snapshot(&previous, refreshed.clone());

    assert_eq!(next, refreshed);
}

#[test]
fn defense_in_depth_empty_refresh_keeps_empty_when_no_previous_snapshot_exists() {
    let previous = Vec::new();
    let refreshed = Vec::new();

    let next = choose_interface_snapshot(&previous, refreshed);

    assert!(
        next.is_empty(),
        "empty refresh with no previous snapshot should remain empty"
    );
}
