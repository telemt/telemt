use super::*;
use std::fmt::Write;

pub(super) fn render(
    out: &mut String,
    stats: &Stats,
    shared_state: &ProxySharedState,
    config: &ProxyConfig,
    core_enabled: bool,
    me_allows_normal: bool,
    me_allows_debug: bool,
) {
    let limiter_metrics = shared_state.traffic_limiter.metrics_snapshot();
    let _ = writeln!(
        out,
        "# HELP telemt_rate_limiter_burst_bound_bytes Configured upper bound for one direct relay rate-limit burst"
    );
    let _ = writeln!(out, "# TYPE telemt_rate_limiter_burst_bound_bytes gauge");
    let _ = writeln!(
        out,
        "telemt_rate_limiter_burst_bound_bytes{{direction=\"up\"}} {}",
        if core_enabled {
            config.general.direct_relay_copy_buf_c2s_bytes
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_burst_bound_bytes{{direction=\"down\"}} {}",
        if core_enabled {
            config.general.direct_relay_copy_buf_s2c_bytes
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_rate_limiter_throttle_total Traffic limiter throttle events by scope and direction"
    );
    let _ = writeln!(out, "# TYPE telemt_rate_limiter_throttle_total counter");
    let _ = writeln!(
        out,
        "telemt_rate_limiter_throttle_total{{scope=\"user\",direction=\"up\"}} {}",
        if core_enabled {
            limiter_metrics.user_throttle_up_total
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_throttle_total{{scope=\"user\",direction=\"down\"}} {}",
        if core_enabled {
            limiter_metrics.user_throttle_down_total
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_throttle_total{{scope=\"cidr\",direction=\"up\"}} {}",
        if core_enabled {
            limiter_metrics.cidr_throttle_up_total
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_throttle_total{{scope=\"cidr\",direction=\"down\"}} {}",
        if core_enabled {
            limiter_metrics.cidr_throttle_down_total
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_rate_limiter_wait_ms_total Traffic limiter accumulated wait time in milliseconds by scope and direction"
    );
    let _ = writeln!(out, "# TYPE telemt_rate_limiter_wait_ms_total counter");
    let _ = writeln!(
        out,
        "telemt_rate_limiter_wait_ms_total{{scope=\"user\",direction=\"up\"}} {}",
        if core_enabled {
            limiter_metrics.user_wait_up_ms_total
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_wait_ms_total{{scope=\"user\",direction=\"down\"}} {}",
        if core_enabled {
            limiter_metrics.user_wait_down_ms_total
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_wait_ms_total{{scope=\"cidr\",direction=\"up\"}} {}",
        if core_enabled {
            limiter_metrics.cidr_wait_up_ms_total
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_wait_ms_total{{scope=\"cidr\",direction=\"down\"}} {}",
        if core_enabled {
            limiter_metrics.cidr_wait_down_ms_total
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_rate_limiter_active_leases Active relay leases under rate limiting by scope"
    );
    let _ = writeln!(out, "# TYPE telemt_rate_limiter_active_leases gauge");
    let _ = writeln!(
        out,
        "telemt_rate_limiter_active_leases{{scope=\"user\"}} {}",
        if core_enabled {
            limiter_metrics.user_active_leases
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_active_leases{{scope=\"cidr\"}} {}",
        if core_enabled {
            limiter_metrics.cidr_active_leases
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_rate_limiter_policy_entries Active rate-limit policy entries by scope"
    );
    let _ = writeln!(out, "# TYPE telemt_rate_limiter_policy_entries gauge");
    let _ = writeln!(
        out,
        "telemt_rate_limiter_policy_entries{{scope=\"user\"}} {}",
        if core_enabled {
            limiter_metrics.user_policy_entries
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_rate_limiter_policy_entries{{scope=\"cidr\"}} {}",
        if core_enabled {
            limiter_metrics.cidr_policy_entries
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_attempt_total Upstream connect attempts across all requests"
    );
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_attempt_total counter");
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempt_total {}",
        if core_enabled {
            stats.get_upstream_connect_attempt_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_success_total Successful upstream connect request cycles"
    );
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_success_total counter");
    let _ = writeln!(
        out,
        "telemt_upstream_connect_success_total {}",
        if core_enabled {
            stats.get_upstream_connect_success_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_fail_total Failed upstream connect request cycles"
    );
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_fail_total counter");
    let _ = writeln!(
        out,
        "telemt_upstream_connect_fail_total {}",
        if core_enabled {
            stats.get_upstream_connect_fail_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_failfast_hard_error_total Hard errors that triggered upstream connect failfast"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_failfast_hard_error_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_failfast_hard_error_total {}",
        if core_enabled {
            stats.get_upstream_connect_failfast_hard_error_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_attempts_per_request Histogram-like buckets for attempts per upstream connect request cycle"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_attempts_per_request counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"1\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_1()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"2\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_2()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"3_4\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_3_4()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"gt_4\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_gt_4()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_duration_success_total Histogram-like buckets of successful upstream connect cycle duration"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_duration_success_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"le_100ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_le_100ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"101_500ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_101_500ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"501_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_501_1000ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"gt_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_gt_1000ms()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_duration_fail_total Histogram-like buckets of failed upstream connect cycle duration"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_duration_fail_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"le_100ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_le_100ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"101_500ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_101_500ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"501_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_501_1000ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"gt_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_gt_1000ms()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_sent_total ME keepalive frames sent"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_sent_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_sent_total {}",
        if me_allows_debug {
            stats.get_me_keepalive_sent()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_failed_total ME keepalive send failures"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_failed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_failed_total {}",
        if me_allows_normal {
            stats.get_me_keepalive_failed()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_pong_total ME keepalive pong replies"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_pong_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_pong_total {}",
        if me_allows_debug {
            stats.get_me_keepalive_pong()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_timeout_total ME keepalive ping timeouts"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_timeout_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_timeout_total {}",
        if me_allows_normal {
            stats.get_me_keepalive_timeout()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_sent_total Service RPC_PROXY_REQ activity signals sent"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_sent_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_sent_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_sent_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_failed_total Service RPC_PROXY_REQ activity signal failures"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_failed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_failed_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_failed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_skipped_no_meta_total Service RPC_PROXY_REQ skipped due to missing writer metadata"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_skipped_no_meta_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_skipped_no_meta_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_skipped_no_meta_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_response_total Service RPC_PROXY_REQ responses observed"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_response_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_response_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_response_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_close_sent_total Service RPC_CLOSE_EXT sent after activity signals"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_close_sent_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_close_sent_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_close_sent_total()
        } else {
            0
        }
    );
}
