use super::*;
use std::fmt::Write;

pub(super) fn render(
    out: &mut String,
    stats: &Stats,
    core_enabled: bool,
    me_allows_normal: bool,
    me_allows_debug: bool,
) {
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"batch_bytes\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_batch_bytes_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"max_delay\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_max_delay_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"ack_immediate\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_ack_immediate_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"close\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_data_frames_total DC->Client data frames"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_data_frames_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_data_frames_total {}",
        if me_allows_normal {
            stats.get_me_d2c_data_frames_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_ack_frames_total DC->Client quick-ack frames"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_ack_frames_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_ack_frames_total {}",
        if me_allows_normal {
            stats.get_me_d2c_ack_frames_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_payload_bytes_total DC->Client payload bytes before transport framing"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_payload_bytes_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_payload_bytes_total {}",
        if me_allows_normal {
            stats.get_me_d2c_payload_bytes_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_write_mode_total DC->Client writer mode selection"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_write_mode_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_write_mode_total{{mode=\"coalesced\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_write_mode_coalesced_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_write_mode_total{{mode=\"split\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_write_mode_split_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_quota_reject_total DC->Client quota rejects"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_quota_reject_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_quota_reject_total{{stage=\"pre_write\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_quota_reject_pre_write_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_quota_reject_total{{stage=\"post_write\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_quota_reject_post_write_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_child_join_timeout_total Middle relay child tasks that did not join before cleanup deadline"
    );
    let _ = writeln!(out, "# TYPE telemt_me_child_join_timeout_total counter");
    let _ = writeln!(
        out,
        "telemt_me_child_join_timeout_total {}",
        if core_enabled {
            stats.get_me_child_join_timeout_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_child_abort_total Middle relay child tasks aborted after bounded cleanup timeout"
    );
    let _ = writeln!(out, "# TYPE telemt_me_child_abort_total counter");
    let _ = writeln!(
        out,
        "telemt_me_child_abort_total {}",
        if core_enabled {
            stats.get_me_child_abort_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_flow_wait_events_total Flow wait events by reason, direction, and outcome"
    );
    let _ = writeln!(out, "# TYPE telemt_flow_wait_events_total counter");
    let _ = writeln!(
        out,
        "telemt_flow_wait_events_total{{reason=\"middle_rate_limit\",direction=\"down\",outcome=\"waited\"}} {}",
        if core_enabled {
            stats.get_flow_wait_middle_rate_limit_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_flow_wait_events_total{{reason=\"middle_rate_limit\",direction=\"down\",outcome=\"cancelled\"}} {}",
        if core_enabled {
            stats.get_flow_wait_middle_rate_limit_cancelled_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_flow_wait_ms_total Flow wait time in milliseconds by reason and direction"
    );
    let _ = writeln!(out, "# TYPE telemt_flow_wait_ms_total counter");
    let _ = writeln!(
        out,
        "telemt_flow_wait_ms_total{{reason=\"middle_rate_limit\",direction=\"down\"}} {}",
        if core_enabled {
            stats.get_flow_wait_middle_rate_limit_ms_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_session_drop_fallback_total Session reservations cleaned by Drop instead of explicit async release"
    );
    let _ = writeln!(out, "# TYPE telemt_session_drop_fallback_total counter");
    let _ = writeln!(
        out,
        "telemt_session_drop_fallback_total {}",
        if core_enabled {
            stats.get_session_drop_fallback_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_frame_buf_shrink_total DC->Client reusable frame buffer shrink events"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_frame_buf_shrink_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_frame_buf_shrink_total {}",
        if me_allows_normal {
            stats.get_me_d2c_frame_buf_shrink_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_frame_buf_shrink_bytes_total DC->Client reusable frame buffer bytes released"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_frame_buf_shrink_bytes_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_frame_buf_shrink_bytes_total {}",
        if me_allows_normal {
            stats.get_me_d2c_frame_buf_shrink_bytes_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_frames_bucket_total DC->Client batch frame count buckets"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_batch_frames_bucket_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"1\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_1()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"2_4\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_2_4()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"5_8\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_5_8()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"9_16\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_9_16()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"17_32\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_17_32()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"gt_32\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_gt_32()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_bytes_bucket_total DC->Client batch byte size buckets"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batch_bytes_bucket_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"0_1k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_0_1k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"1k_4k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_1k_4k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"4k_16k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_4k_16k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"16k_64k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_16k_64k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"64k_128k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_64k_128k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"gt_128k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_gt_128k()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_flush_duration_us_bucket_total DC->Client flush duration buckets"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_flush_duration_us_bucket_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"0_50\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_0_50()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"51_200\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_51_200()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"201_1000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_201_1000()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"1001_5000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_1001_5000()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"5001_20000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_5001_20000()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"gt_20000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_gt_20000()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_timeout_armed_total DC->Client max-delay timer armed events"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_batch_timeout_armed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_timeout_armed_total {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_timeout_armed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_timeout_fired_total DC->Client max-delay timer fired events"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_batch_timeout_fired_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_timeout_fired_total {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_timeout_fired_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_byte_budget_limit_bytes Configured resident-memory budget per ME writer"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writer_byte_budget_limit_bytes gauge");
    let _ = writeln!(
        out,
        "telemt_me_writer_byte_budget_limit_bytes {}",
        if me_allows_normal {
            stats.get_me_writer_byte_budget_limit_bytes_gauge()
        } else {
            0
        }
    );
}
