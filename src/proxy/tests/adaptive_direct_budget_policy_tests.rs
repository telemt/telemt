use super::*;

#[test]
fn configured_direct_sizes_are_strict_tier_ceilings() {
    let base = (4 * 1024, 8 * 1024);
    let ceilings = (64 * 1024, 256 * 1024);
    assert_eq!(
        direct_copy_buffers_for_tier_with_ceilings(
            AdaptiveTier::Base,
            base.0,
            base.1,
            ceilings.0,
            ceilings.1,
        ),
        base
    );
    assert_eq!(
        direct_copy_buffers_for_tier_with_ceilings(
            AdaptiveTier::Tier3,
            base.0,
            base.1,
            ceilings.0,
            ceilings.1,
        ),
        ceilings
    );
}

#[test]
fn sustained_pending_pressure_demotes_after_transient_promotion() {
    let mut controller = SessionAdaptiveController::new(AdaptiveTier::Tier1);
    let pressure = RelaySignalSample {
        c2s_bytes: 0,
        s2c_requested_bytes: 1024,
        s2c_written_bytes: 0,
        s2c_write_ops: 0,
        s2c_partial_writes: 0,
        s2c_consecutive_pending_writes: 3,
    };

    let first = controller
        .observe(pressure, 10.0)
        .expect("transient pressure must retain the staged promotion");
    assert_eq!(first.reason, TierTransitionReason::HardPressure);

    let second = controller
        .observe(pressure, 10.0)
        .expect("bounded transient pressure may promote one additional tier");
    assert_eq!(second.reason, TierTransitionReason::HardPressure);
    let sustained = controller
        .observe(pressure, 10.0)
        .expect("sustained pressure must release one tier");
    assert_eq!(
        sustained.reason,
        TierTransitionReason::SustainedWritePressure
    );
    assert_eq!(sustained.to, AdaptiveTier::Tier2);
}
