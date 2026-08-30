use super::*;
use std::fmt::Write;

pub(super) fn render(out: &mut String, stats: &Stats, me_allows_normal: bool) {
    let _ = writeln!(
        out,
        "# HELP telemt_me_reconnect_attempts_total ME reconnect attempts"
    );
    let _ = writeln!(out, "# TYPE telemt_me_reconnect_attempts_total counter");
    let _ = writeln!(
        out,
        "telemt_me_reconnect_attempts_total {}",
        if me_allows_normal {
            stats.get_me_reconnect_attempts()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_reconnect_success_total ME reconnect successes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_reconnect_success_total counter");
    let _ = writeln!(
        out,
        "telemt_me_reconnect_success_total {}",
        if me_allows_normal {
            stats.get_me_reconnect_success()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_handshake_reject_total ME handshake rejects from upstream"
    );
    let _ = writeln!(out, "# TYPE telemt_me_handshake_reject_total counter");
    let _ = writeln!(
        out,
        "telemt_me_handshake_reject_total {}",
        if me_allows_normal {
            stats.get_me_handshake_reject_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_handshake_error_code_total ME handshake reject errors by code"
    );
    let _ = writeln!(out, "# TYPE telemt_me_handshake_error_code_total counter");
    if me_allows_normal {
        for (error_code, count) in stats.get_me_handshake_error_code_counts() {
            let _ = writeln!(
                out,
                "telemt_me_handshake_error_code_total{{error_code=\"{}\"}} {}",
                error_code, count
            );
        }
        let _ = writeln!(
            out,
            "telemt_me_handshake_error_code_total{{error_code=\"overflow\"}} {}",
            stats.get_me_handshake_error_code_overflow_total()
        );
    }

    let _ = writeln!(
        out,
        "# HELP telemt_me_reader_eof_total ME reader EOF terminations"
    );
    let _ = writeln!(out, "# TYPE telemt_me_reader_eof_total counter");
    let _ = writeln!(
        out,
        "telemt_me_reader_eof_total {}",
        if me_allows_normal {
            stats.get_me_reader_eof_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_idle_close_by_peer_total ME idle writers closed by peer"
    );
    let _ = writeln!(out, "# TYPE telemt_me_idle_close_by_peer_total counter");
    let _ = writeln!(
        out,
        "telemt_me_idle_close_by_peer_total {}",
        if me_allows_normal {
            stats.get_me_idle_close_by_peer_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_idle_soft_mark_total Middle-relay sessions marked as soft-idle candidates"
    );
    let _ = writeln!(out, "# TYPE telemt_relay_idle_soft_mark_total counter");
    let _ = writeln!(
        out,
        "telemt_relay_idle_soft_mark_total {}",
        if me_allows_normal {
            stats.get_relay_idle_soft_mark_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_idle_hard_close_total Middle-relay sessions closed by hard-idle policy"
    );
    let _ = writeln!(out, "# TYPE telemt_relay_idle_hard_close_total counter");
    let _ = writeln!(
        out,
        "telemt_relay_idle_hard_close_total {}",
        if me_allows_normal {
            stats.get_relay_idle_hard_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_pressure_evict_total Middle-relay sessions evicted under resource pressure"
    );
    let _ = writeln!(out, "# TYPE telemt_relay_pressure_evict_total counter");
    let _ = writeln!(
        out,
        "telemt_relay_pressure_evict_total {}",
        if me_allows_normal {
            stats.get_relay_pressure_evict_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_protocol_desync_close_total Middle-relay sessions closed due to protocol desync"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_relay_protocol_desync_close_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_relay_protocol_desync_close_total {}",
        if me_allows_normal {
            stats.get_relay_protocol_desync_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(out, "# HELP telemt_me_crc_mismatch_total ME CRC mismatches");
    let _ = writeln!(out, "# TYPE telemt_me_crc_mismatch_total counter");
    let _ = writeln!(
        out,
        "telemt_me_crc_mismatch_total {}",
        if me_allows_normal {
            stats.get_me_crc_mismatch()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_seq_mismatch_total ME sequence mismatches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_seq_mismatch_total counter");
    let _ = writeln!(
        out,
        "telemt_me_seq_mismatch_total {}",
        if me_allows_normal {
            stats.get_me_seq_mismatch()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_no_conn_total ME route drops: no conn"
    );
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_no_conn_total counter");
    let _ = writeln!(
        out,
        "telemt_me_route_drop_no_conn_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_no_conn()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_channel_closed_total ME route drops: channel closed"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_route_drop_channel_closed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_route_drop_channel_closed_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_channel_closed()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_queue_full_total ME route drops: queue full"
    );
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_queue_full_total counter");
    let _ = writeln!(
        out,
        "telemt_me_route_drop_queue_full_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_queue_full()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_queue_full_profile_total ME route drops: queue full by adaptive profile"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_route_drop_queue_full_profile_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_route_drop_queue_full_profile_total{{profile=\"base\"}} {}",
        if me_allows_normal {
            stats.get_me_route_drop_queue_full_base()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_route_drop_queue_full_profile_total{{profile=\"high\"}} {}",
        if me_allows_normal {
            stats.get_me_route_drop_queue_full_high()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_fair_pressure_state Worker-local fairness pressure state"
    );
    let _ = writeln!(out, "# TYPE telemt_me_fair_pressure_state gauge");
    let _ = writeln!(
        out,
        "telemt_me_fair_pressure_state {}",
        if me_allows_normal {
            stats.get_me_fair_pressure_state_gauge()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_fair_active_flows Fair-scheduler active flow count"
    );
    let _ = writeln!(out, "# TYPE telemt_me_fair_active_flows gauge");
    let _ = writeln!(
        out,
        "telemt_me_fair_active_flows {}",
        if me_allows_normal {
            stats.get_me_fair_active_flows_gauge()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_fair_queued_bytes Fair-scheduler queued bytes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_fair_queued_bytes gauge");
    let _ = writeln!(
        out,
        "telemt_me_fair_queued_bytes {}",
        if me_allows_normal {
            stats.get_me_fair_queued_bytes_gauge()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_fair_flow_state_gauge Fair-scheduler flow health classes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_fair_flow_state_gauge gauge");
    let _ = writeln!(
        out,
        "telemt_me_fair_flow_state_gauge{{class=\"standing\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_standing_flows_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_flow_state_gauge{{class=\"backpressured\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_backpressured_flows_gauge()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_fair_events_total Fair-scheduler event counters"
    );
    let _ = writeln!(out, "# TYPE telemt_me_fair_events_total counter");
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"scheduler_round\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_scheduler_rounds_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"deficit_grant\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_deficit_grants_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"deficit_skip\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_deficit_skips_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"enqueue_reject\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_enqueue_rejects_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"shed_drop\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_shed_drops_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"penalty\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_penalties_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_fair_events_total{{event=\"downstream_stall\"}} {}",
        if me_allows_normal {
            stats.get_me_fair_downstream_stalls_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_c2me_enqueue_events_total ME client->ME enqueue outcomes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_c2me_enqueue_events_total counter");
    let _ = writeln!(
        out,
        "telemt_me_c2me_enqueue_events_total{{event=\"full\"}} {}",
        if me_allows_normal {
            stats.get_me_c2me_send_full_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_c2me_enqueue_events_total{{event=\"high_water\"}} {}",
        if me_allows_normal {
            stats.get_me_c2me_send_high_water_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_c2me_enqueue_events_total{{event=\"timeout\"}} {}",
        if me_allows_normal {
            stats.get_me_c2me_send_timeout_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batches_total Total DC->Client flush batches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batches_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batches_total {}",
        if me_allows_normal {
            stats.get_me_d2c_batches_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_frames_total Total DC->Client frames flushed in batches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batch_frames_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_total {}",
        if me_allows_normal {
            stats.get_me_d2c_batch_frames_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_bytes_total Total DC->Client bytes flushed in batches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batch_bytes_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_total {}",
        if me_allows_normal {
            stats.get_me_d2c_batch_bytes_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_flush_reason_total DC->Client flush reasons"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_flush_reason_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"queue_drain\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_queue_drain_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"batch_frames\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_batch_frames_total()
        } else {
            0
        }
    );
}
