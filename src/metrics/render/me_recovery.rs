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
        "# HELP telemt_secure_padding_invalid_total Invalid secure frame lengths"
    );
    let _ = writeln!(out, "# TYPE telemt_secure_padding_invalid_total counter");
    let _ = writeln!(
        out,
        "telemt_secure_padding_invalid_total {}",
        if me_allows_normal {
            stats.get_secure_padding_invalid()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_total Total crypto-desync detections"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_total {}",
        if me_allows_normal {
            stats.get_desync_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_full_logged_total Full forensic desync logs emitted"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_full_logged_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_full_logged_total {}",
        if me_allows_normal {
            stats.get_desync_full_logged()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_suppressed_total Suppressed desync forensic events"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_suppressed_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_suppressed_total {}",
        if me_allows_normal {
            stats.get_desync_suppressed()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_frames_bucket_total Desync count by frames_ok bucket"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_frames_bucket_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"0\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_0()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"1_2\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_1_2()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"3_10\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_3_10()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"gt_10\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_gt_10()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_swap_total Successful ME pool swaps"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_swap_total counter");
    let _ = writeln!(
        out,
        "telemt_pool_swap_total {}",
        if me_allows_normal {
            stats.get_pool_swap_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_drain_active Active draining ME writers"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_drain_active gauge");
    let _ = writeln!(
        out,
        "telemt_pool_drain_active {}",
        if me_allows_debug {
            stats.get_pool_drain_active()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_force_close_total Forced close events for draining writers"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_force_close_total counter");
    let _ = writeln!(
        out,
        "telemt_pool_force_close_total {}",
        if me_allows_normal {
            stats.get_pool_force_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_stale_pick_total Stale writer fallback picks for new binds"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_stale_pick_total counter");
    let _ = writeln!(
        out,
        "telemt_pool_stale_pick_total {}",
        if me_allows_normal {
            stats.get_pool_stale_pick_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_removed_total Total ME writer removals"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writer_removed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_total {}",
        if me_allows_debug {
            stats.get_me_writer_removed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_removed_unexpected_total Unexpected ME writer removals that triggered refill"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_removed_unexpected_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_unexpected_total {}",
        if me_allows_normal {
            stats.get_me_writer_removed_unexpected_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_refill_triggered_total Immediate ME refill runs started"
    );
    let _ = writeln!(out, "# TYPE telemt_me_refill_triggered_total counter");
    let _ = writeln!(
        out,
        "telemt_me_refill_triggered_total {}",
        if me_allows_debug {
            stats.get_me_refill_triggered_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_refill_skipped_inflight_total Immediate ME refill skips due to inflight dedup"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_refill_skipped_inflight_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_refill_skipped_inflight_total {}",
        if me_allows_debug {
            stats.get_me_refill_skipped_inflight_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_refill_failed_total Immediate ME refill failures"
    );
    let _ = writeln!(out, "# TYPE telemt_me_refill_failed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_refill_failed_total {}",
        if me_allows_normal {
            stats.get_me_refill_failed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_restored_same_endpoint_total Refilled ME writer restored on the same endpoint"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_restored_same_endpoint_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_restored_same_endpoint_total {}",
        if me_allows_normal {
            stats.get_me_writer_restored_same_endpoint_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_restored_fallback_total Refilled ME writer restored via fallback endpoint"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_restored_fallback_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_restored_fallback_total {}",
        if me_allows_normal {
            stats.get_me_writer_restored_fallback_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_no_writer_failfast_total ME route failfast errors due to missing writer in bounded wait window"
    );
    let _ = writeln!(out, "# TYPE telemt_me_no_writer_failfast_total counter");
    let _ = writeln!(
        out,
        "telemt_me_no_writer_failfast_total {}",
        if me_allows_normal {
            stats.get_me_no_writer_failfast_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_hybrid_timeout_total ME hybrid route timeouts after bounded retry window"
    );
    let _ = writeln!(out, "# TYPE telemt_me_hybrid_timeout_total counter");
    let _ = writeln!(
        out,
        "telemt_me_hybrid_timeout_total {}",
        if me_allows_normal {
            stats.get_me_hybrid_timeout_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_async_recovery_trigger_total Async ME recovery trigger attempts from route path"
    );
    let _ = writeln!(out, "# TYPE telemt_me_async_recovery_trigger_total counter");
    let _ = writeln!(
        out,
        "telemt_me_async_recovery_trigger_total {}",
        if me_allows_normal {
            stats.get_me_async_recovery_trigger_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_inline_recovery_total Legacy inline ME recovery attempts from route path"
    );
    let _ = writeln!(out, "# TYPE telemt_me_inline_recovery_total counter");
    let _ = writeln!(
        out,
        "telemt_me_inline_recovery_total {}",
        if me_allows_normal {
            stats.get_me_inline_recovery_total()
        } else {
            0
        }
    );

    let unresolved_writer_losses = if me_allows_normal {
        stats
            .get_me_writer_removed_unexpected_total()
            .saturating_sub(
                stats
                    .get_me_writer_restored_same_endpoint_total()
                    .saturating_add(stats.get_me_writer_restored_fallback_total()),
            )
    } else {
        0
    };
    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_removed_unexpected_minus_restored_total Unexpected writer removals not yet compensated by restore"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_removed_unexpected_minus_restored_total gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_unexpected_minus_restored_total {}",
        unresolved_writer_losses
    );
}
