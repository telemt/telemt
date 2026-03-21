use super::*;

const BEOBACHTEN_TTL_MAX_MINUTES: u64 = 24 * 60;

#[test]
fn beobachten_ttl_exact_upper_bound_is_preserved() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = BEOBACHTEN_TTL_MAX_MINUTES;

    let ttl = beobachten_ttl(&config);
    assert_eq!(
        ttl,
        Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60),
        "upper-bound TTL should remain unchanged"
    );
}

#[test]
fn beobachten_ttl_above_upper_bound_is_clamped() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = BEOBACHTEN_TTL_MAX_MINUTES + 1;

    let ttl = beobachten_ttl(&config);
    assert_eq!(
        ttl,
        Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60),
        "TTL above security cap must be clamped"
    );
}

#[test]
fn beobachten_ttl_u64_max_is_clamped_fail_safe() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = u64::MAX;

    let ttl = beobachten_ttl(&config);
    assert_eq!(
        ttl,
        Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60),
        "extreme configured TTL must not become multi-century retention"
    );
}

#[test]
fn positive_one_minute_maps_to_exact_60_seconds() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;

    assert_eq!(beobachten_ttl(&config), Duration::from_secs(60));
}

#[test]
fn adversarial_boundary_triplet_behaves_deterministically() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;

    config.general.beobachten_minutes = BEOBACHTEN_TTL_MAX_MINUTES - 1;
    assert_eq!(
        beobachten_ttl(&config),
        Duration::from_secs((BEOBACHTEN_TTL_MAX_MINUTES - 1) * 60)
    );

    config.general.beobachten_minutes = BEOBACHTEN_TTL_MAX_MINUTES;
    assert_eq!(
        beobachten_ttl(&config),
        Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60)
    );

    config.general.beobachten_minutes = BEOBACHTEN_TTL_MAX_MINUTES + 1;
    assert_eq!(
        beobachten_ttl(&config),
        Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60)
    );
}

#[test]
fn light_fuzz_random_minutes_match_fail_safe_model() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;

    let mut seed = 0xD15E_A5E5_F00D_BAADu64;
    for _ in 0..8192 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        config.general.beobachten_minutes = seed;
        let ttl = beobachten_ttl(&config);
        let expected = if seed == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(seed.min(BEOBACHTEN_TTL_MAX_MINUTES) * 60)
        };

        assert_eq!(ttl, expected, "ttl mismatch for minutes={seed}");
        assert!(ttl <= Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60));
    }
}

#[test]
fn stress_monotonic_minutes_remain_monotonic_until_cap_then_flat() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;

    let mut prev = Duration::from_secs(0);
    for minutes in 0..=(BEOBACHTEN_TTL_MAX_MINUTES + 4096) {
        config.general.beobachten_minutes = minutes;
        let ttl = beobachten_ttl(&config);

        assert!(ttl >= prev, "ttl must be non-decreasing as minutes grow");
        assert!(ttl <= Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60));

        if minutes > BEOBACHTEN_TTL_MAX_MINUTES {
            assert_eq!(
                ttl,
                Duration::from_secs(BEOBACHTEN_TTL_MAX_MINUTES * 60),
                "ttl must stay clamped once cap is exceeded"
            );
        }
        prev = ttl;
    }
}
