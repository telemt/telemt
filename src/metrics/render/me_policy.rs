use super::*;
use std::fmt::Write;

pub(super) fn render(
    out: &mut String,
    stats: &Stats,
    me_allows_normal: bool,
    me_allows_debug: bool,
) {
    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_byte_budget_reserved_bytes Aggregate ME writer memory reservations by lifecycle state"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_byte_budget_reserved_bytes gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_byte_budget_reserved_bytes{{state=\"queued\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_byte_budget_queued_bytes_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_byte_budget_reserved_bytes{{state=\"inflight\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_byte_budget_inflight_bytes_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_byte_budget_events_total ME writer byte-budget outcomes"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_byte_budget_events_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_byte_budget_events_total{{result=\"wait\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_byte_budget_wait_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_byte_budget_events_total{{result=\"timeout\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_byte_budget_timeout_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_byte_budget_events_total{{result=\"oversize\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_byte_budget_oversize_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_pick_total ME writer-pick outcomes by mode and result"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writer_pick_total counter");
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"success_try\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_success_try_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"success_fallback\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_success_fallback_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"full\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_full_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"closed\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_closed_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"no_candidate\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_no_candidate_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"success_try\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_success_try_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"success_fallback\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_success_fallback_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"full\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_full_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"closed\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_closed_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"no_candidate\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_no_candidate_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_pick_blocking_fallback_total ME writer-pick blocking fallback attempts"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_pick_blocking_fallback_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_blocking_fallback_total {}",
        if me_allows_normal {
            stats.get_me_writer_pick_blocking_fallback_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_pick_mode_switch_total Writer-pick mode switches via runtime updates"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_pick_mode_switch_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_mode_switch_total {}",
        if me_allows_normal {
            stats.get_me_writer_pick_mode_switch_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_socks_kdf_policy_total SOCKS KDF policy outcomes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_socks_kdf_policy_total counter");
    let _ = writeln!(
        out,
        "telemt_me_socks_kdf_policy_total{{policy=\"strict\",outcome=\"reject\"}} {}",
        if me_allows_normal {
            stats.get_me_socks_kdf_strict_reject()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_socks_kdf_policy_total{{policy=\"compat\",outcome=\"fallback\"}} {}",
        if me_allows_debug {
            stats.get_me_socks_kdf_compat_fallback()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_endpoint_quarantine_total ME endpoint quarantines due to rapid flaps"
    );
    let _ = writeln!(out, "# TYPE telemt_me_endpoint_quarantine_total counter");
    let _ = writeln!(
        out,
        "telemt_me_endpoint_quarantine_total {}",
        if me_allows_normal {
            stats.get_me_endpoint_quarantine_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_endpoint_quarantine_unexpected_total ME endpoint quarantines caused by unexpected writer removals"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_endpoint_quarantine_unexpected_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_endpoint_quarantine_unexpected_total {}",
        if me_allows_normal {
            stats.get_me_endpoint_quarantine_unexpected_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_endpoint_quarantine_draining_suppressed_total Draining writer removals that skipped endpoint quarantine"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_endpoint_quarantine_draining_suppressed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_endpoint_quarantine_draining_suppressed_total {}",
        if me_allows_normal {
            stats.get_me_endpoint_quarantine_draining_suppressed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_kdf_drift_total ME KDF input drift detections"
    );
    let _ = writeln!(out, "# TYPE telemt_me_kdf_drift_total counter");
    let _ = writeln!(
        out,
        "telemt_me_kdf_drift_total {}",
        if me_allows_normal {
            stats.get_me_kdf_drift_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_kdf_port_only_drift_total ME KDF client-port changes with stable non-port material"
    );
    let _ = writeln!(out, "# TYPE telemt_me_kdf_port_only_drift_total counter");
    let _ = writeln!(
        out,
        "telemt_me_kdf_port_only_drift_total {}",
        if me_allows_debug {
            stats.get_me_kdf_port_only_drift_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_hardswap_pending_reuse_total Hardswap cycles that reused an existing pending generation"
    );
    let _ = writeln!(out, "# TYPE telemt_me_hardswap_pending_reuse_total counter");
    let _ = writeln!(
        out,
        "telemt_me_hardswap_pending_reuse_total {}",
        if me_allows_debug {
            stats.get_me_hardswap_pending_reuse_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_hardswap_pending_ttl_expired_total Pending hardswap generations reset by TTL expiration"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_hardswap_pending_ttl_expired_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_hardswap_pending_ttl_expired_total {}",
        if me_allows_normal {
            stats.get_me_hardswap_pending_ttl_expired_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_enter_total Single-endpoint DC outage transitions to active state"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_enter_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_enter_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_enter_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_exit_total Single-endpoint DC outage recovery transitions"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_exit_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_exit_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_exit_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_reconnect_attempt_total Reconnect attempts performed during single-endpoint outages"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_reconnect_attempt_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_reconnect_attempt_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_reconnect_attempt_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_reconnect_success_total Successful reconnect attempts during single-endpoint outages"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_reconnect_success_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_reconnect_success_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_reconnect_success_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_quarantine_bypass_total Outage reconnect attempts that bypassed quarantine"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_quarantine_bypass_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_quarantine_bypass_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_quarantine_bypass_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_shadow_rotate_total Successful periodic shadow rotations for single-endpoint DC groups"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_shadow_rotate_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_shadow_rotate_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_shadow_rotate_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_shadow_rotate_skipped_quarantine_total Shadow rotations skipped because endpoint is quarantined"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_shadow_rotate_skipped_quarantine_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_shadow_rotate_skipped_quarantine_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_shadow_rotate_skipped_quarantine_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_floor_mode Runtime ME writer floor policy mode"
    );
    let _ = writeln!(out, "# TYPE telemt_me_floor_mode gauge");
}
