use super::*;

#[test]
fn unknown_dc_log_is_deduplicated_per_dc_idx() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    assert!(should_log_unknown_dc(777));
    assert!(
        !should_log_unknown_dc(777),
        "same unknown dc_idx must not be logged repeatedly"
    );
    assert!(
        should_log_unknown_dc(778),
        "different unknown dc_idx must still be loggable"
    );
}

#[test]
fn unknown_dc_log_respects_distinct_limit() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    for dc in 1..=UNKNOWN_DC_LOG_DISTINCT_LIMIT {
        assert!(
            should_log_unknown_dc(dc as i16),
            "expected first-time unknown dc_idx to be loggable"
        );
    }

    assert!(
        !should_log_unknown_dc(i16::MAX),
        "distinct unknown dc_idx entries above limit must not be logged"
    );
}

#[test]
fn fallback_dc_never_panics_with_single_dc_list() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.default_dc = Some(42);

    let addr = get_dc_addr_static(999, &cfg).expect("fallback dc must resolve safely");
    let expected = SocketAddr::new(TG_DATACENTERS_V6[0], TG_DATACENTER_PORT);
    assert_eq!(addr, expected);
}
