use super::*;

impl Stats {
    pub fn get_me_handshake_error_code_counts(&self) -> Vec<(i32, u64)> {
        let mut out: Vec<(i32, u64)> = self
            .me_handshake_error_codes
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .collect();
        out.sort_by_key(|(code, _)| *code);
        out
    }
    pub fn get_me_route_drop_no_conn(&self) -> u64 {
        self.me_route_drop_no_conn.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_channel_closed(&self) -> u64 {
        self.me_route_drop_channel_closed.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full(&self) -> u64 {
        self.me_route_drop_queue_full.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full_base(&self) -> u64 {
        self.me_route_drop_queue_full_base.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full_high(&self) -> u64 {
        self.me_route_drop_queue_full_high.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_pressure_state_gauge(&self) -> u64 {
        self.me_fair_pressure_state_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_active_flows_gauge(&self) -> u64 {
        self.me_fair_active_flows_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_queued_bytes_gauge(&self) -> u64 {
        self.me_fair_queued_bytes_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_standing_flows_gauge(&self) -> u64 {
        self.me_fair_standing_flows_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_backpressured_flows_gauge(&self) -> u64 {
        self.me_fair_backpressured_flows_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_fair_scheduler_rounds_total(&self) -> u64 {
        self.me_fair_scheduler_rounds_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_deficit_grants_total(&self) -> u64 {
        self.me_fair_deficit_grants_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_deficit_skips_total(&self) -> u64 {
        self.me_fair_deficit_skips_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_enqueue_rejects_total(&self) -> u64 {
        self.me_fair_enqueue_rejects_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_shed_drops_total(&self) -> u64 {
        self.me_fair_shed_drops_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_penalties_total(&self) -> u64 {
        self.me_fair_penalties_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_downstream_stalls_total(&self) -> u64 {
        self.me_fair_downstream_stalls_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batches_total(&self) -> u64 {
        self.me_d2c_batches_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_total(&self) -> u64 {
        self.me_d2c_batch_frames_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_total(&self) -> u64 {
        self.me_d2c_batch_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_queue_drain_total(&self) -> u64 {
        self.me_d2c_flush_reason_queue_drain_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_batch_frames_total(&self) -> u64 {
        self.me_d2c_flush_reason_batch_frames_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_batch_bytes_total(&self) -> u64 {
        self.me_d2c_flush_reason_batch_bytes_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_max_delay_total(&self) -> u64 {
        self.me_d2c_flush_reason_max_delay_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_ack_immediate_total(&self) -> u64 {
        self.me_d2c_flush_reason_ack_immediate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_close_total(&self) -> u64 {
        self.me_d2c_flush_reason_close_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_data_frames_total(&self) -> u64 {
        self.me_d2c_data_frames_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_ack_frames_total(&self) -> u64 {
        self.me_d2c_ack_frames_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_payload_bytes_total(&self) -> u64 {
        self.me_d2c_payload_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_write_mode_coalesced_total(&self) -> u64 {
        self.me_d2c_write_mode_coalesced_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_write_mode_split_total(&self) -> u64 {
        self.me_d2c_write_mode_split_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_quota_reject_pre_write_total(&self) -> u64 {
        self.me_d2c_quota_reject_pre_write_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_quota_reject_post_write_total(&self) -> u64 {
        self.me_d2c_quota_reject_post_write_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_frame_buf_shrink_total(&self) -> u64 {
        self.me_d2c_frame_buf_shrink_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_frame_buf_shrink_bytes_total(&self) -> u64 {
        self.me_d2c_frame_buf_shrink_bytes_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_1(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_1.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_2_4(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_2_4.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_5_8(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_5_8.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_9_16(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_9_16.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_17_32(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_17_32
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_gt_32(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_gt_32
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_0_1k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_0_1k.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_1k_4k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_1k_4k.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_4k_16k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_4k_16k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_16k_64k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_16k_64k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_64k_128k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_64k_128k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_gt_128k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_gt_128k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_0_50(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_0_50
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_51_200(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_51_200
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_201_1000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_201_1000
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_1001_5000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_1001_5000
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_5001_20000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_5001_20000
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_gt_20000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_gt_20000
            .load(Ordering::Relaxed)
    }

    pub fn get_buffer_pool_pooled_gauge(&self) -> u64 {
        self.buffer_pool_pooled_gauge.load(Ordering::Relaxed)
    }

    pub fn get_buffer_pool_allocated_gauge(&self) -> u64 {
        self.buffer_pool_allocated_gauge.load(Ordering::Relaxed)
    }

    pub fn get_buffer_pool_in_use_gauge(&self) -> u64 {
        self.buffer_pool_in_use_gauge.load(Ordering::Relaxed)
    }

    /// Returns the count of non-standard buffers replaced before pooling.
    pub fn get_buffer_pool_replaced_nonstandard_total(&self) -> u64 {
        self.buffer_pool_replaced_nonstandard_total
            .load(Ordering::Relaxed)
    }

    pub fn get_me_c2me_send_full_total(&self) -> u64 {
        self.me_c2me_send_full_total.load(Ordering::Relaxed)
    }

    pub fn get_me_c2me_send_high_water_total(&self) -> u64 {
        self.me_c2me_send_high_water_total.load(Ordering::Relaxed)
    }

    pub fn get_me_c2me_send_timeout_total(&self) -> u64 {
        self.me_c2me_send_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_timeout_armed_total(&self) -> u64 {
        self.me_d2c_batch_timeout_armed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_timeout_fired_total(&self) -> u64 {
        self.me_d2c_batch_timeout_fired_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_success_try_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_success_try_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_success_fallback_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_success_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_full_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_full_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_closed_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_closed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_no_candidate_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_no_candidate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_success_try_total(&self) -> u64 {
        self.me_writer_pick_p2c_success_try_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_success_fallback_total(&self) -> u64 {
        self.me_writer_pick_p2c_success_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_full_total(&self) -> u64 {
        self.me_writer_pick_p2c_full_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_closed_total(&self) -> u64 {
        self.me_writer_pick_p2c_closed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_no_candidate_total(&self) -> u64 {
        self.me_writer_pick_p2c_no_candidate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_blocking_fallback_total(&self) -> u64 {
        self.me_writer_pick_blocking_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_mode_switch_total(&self) -> u64 {
        self.me_writer_pick_mode_switch_total
            .load(Ordering::Relaxed)
    }
    /// Returns the configured resident-memory limit per ME writer.
    pub fn get_me_writer_byte_budget_limit_bytes_gauge(&self) -> u64 {
        self.me_writer_byte_budget_limit_bytes_gauge
            .load(Ordering::Relaxed)
    }
    /// Returns aggregate queued or enqueueing writer memory reservations.
    pub fn get_me_writer_byte_budget_queued_bytes_gauge(&self) -> u64 {
        self.me_writer_byte_budget_queued_bytes_gauge
            .load(Ordering::Relaxed)
    }
    /// Returns aggregate writer reservations currently owned by socket writes.
    pub fn get_me_writer_byte_budget_inflight_bytes_gauge(&self) -> u64 {
        self.me_writer_byte_budget_inflight_bytes_gauge
            .load(Ordering::Relaxed)
    }
    /// Returns the count of blocking writer byte-budget waits.
    pub fn get_me_writer_byte_budget_wait_total(&self) -> u64 {
        self.me_writer_byte_budget_wait_total.load(Ordering::Relaxed)
    }
    /// Returns the count of writer byte-budget wait timeouts.
    pub fn get_me_writer_byte_budget_timeout_total(&self) -> u64 {
        self.me_writer_byte_budget_timeout_total
            .load(Ordering::Relaxed)
    }
    /// Returns the count of payloads that cannot fit the configured writer budget.
    pub fn get_me_writer_byte_budget_oversize_total(&self) -> u64 {
        self.me_writer_byte_budget_oversize_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_socks_kdf_strict_reject(&self) -> u64 {
        self.me_socks_kdf_strict_reject.load(Ordering::Relaxed)
    }
    pub fn get_me_socks_kdf_compat_fallback(&self) -> u64 {
        self.me_socks_kdf_compat_fallback.load(Ordering::Relaxed)
    }
    pub fn get_secure_padding_invalid(&self) -> u64 {
        self.secure_padding_invalid.load(Ordering::Relaxed)
    }
    pub fn get_desync_total(&self) -> u64 {
        self.desync_total.load(Ordering::Relaxed)
    }
    pub fn get_desync_full_logged(&self) -> u64 {
        self.desync_full_logged.load(Ordering::Relaxed)
    }
    pub fn get_desync_suppressed(&self) -> u64 {
        self.desync_suppressed.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_0(&self) -> u64 {
        self.desync_frames_bucket_0.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_1_2(&self) -> u64 {
        self.desync_frames_bucket_1_2.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_3_10(&self) -> u64 {
        self.desync_frames_bucket_3_10.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_gt_10(&self) -> u64 {
        self.desync_frames_bucket_gt_10.load(Ordering::Relaxed)
    }
    pub fn get_pool_swap_total(&self) -> u64 {
        self.pool_swap_total.load(Ordering::Relaxed)
    }
    pub fn get_pool_drain_active(&self) -> u64 {
        self.pool_drain_active.load(Ordering::Relaxed)
    }
    pub fn get_pool_force_close_total(&self) -> u64 {
        self.pool_force_close_total.load(Ordering::Relaxed)
    }
    pub fn get_pool_stale_pick_total(&self) -> u64 {
        self.pool_stale_pick_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_removed_total(&self) -> u64 {
        self.me_writer_removed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_removed_unexpected_total(&self) -> u64 {
        self.me_writer_removed_unexpected_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_refill_triggered_total(&self) -> u64 {
        self.me_refill_triggered_total.load(Ordering::Relaxed)
    }
    pub fn get_me_refill_skipped_inflight_total(&self) -> u64 {
        self.me_refill_skipped_inflight_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_refill_failed_total(&self) -> u64 {
        self.me_refill_failed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_restored_same_endpoint_total(&self) -> u64 {
        self.me_writer_restored_same_endpoint_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_restored_fallback_total(&self) -> u64 {
        self.me_writer_restored_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_no_writer_failfast_total(&self) -> u64 {
        self.me_no_writer_failfast_total.load(Ordering::Relaxed)
    }
    pub fn get_me_hybrid_timeout_total(&self) -> u64 {
        self.me_hybrid_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_me_async_recovery_trigger_total(&self) -> u64 {
        self.me_async_recovery_trigger_total.load(Ordering::Relaxed)
    }
    pub fn get_me_inline_recovery_total(&self) -> u64 {
        self.me_inline_recovery_total.load(Ordering::Relaxed)
    }
    pub fn get_ip_reservation_rollback_tcp_limit_total(&self) -> u64 {
        self.ip_reservation_rollback_tcp_limit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_ip_reservation_rollback_quota_limit_total(&self) -> u64 {
        self.ip_reservation_rollback_quota_limit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_quota_refund_bytes_total(&self) -> u64 {
        self.quota_refund_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_quota_contention_total(&self) -> u64 {
        self.quota_contention_total.load(Ordering::Relaxed)
    }
    pub fn get_quota_contention_timeout_total(&self) -> u64 {
        self.quota_contention_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_quota_acquire_cancelled_total(&self) -> u64 {
        self.quota_acquire_cancelled_total.load(Ordering::Relaxed)
    }
    pub fn get_quota_write_fail_bytes_total(&self) -> u64 {
        self.quota_write_fail_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_quota_write_fail_events_total(&self) -> u64 {
        self.quota_write_fail_events_total.load(Ordering::Relaxed)
    }
    pub fn get_me_child_join_timeout_total(&self) -> u64 {
        self.me_child_join_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_me_child_abort_total(&self) -> u64 {
        self.me_child_abort_total.load(Ordering::Relaxed)
    }
    pub fn get_flow_wait_middle_rate_limit_total(&self) -> u64 {
        self.flow_wait_middle_rate_limit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_flow_wait_middle_rate_limit_cancelled_total(&self) -> u64 {
        self.flow_wait_middle_rate_limit_cancelled_total
            .load(Ordering::Relaxed)
    }
    pub fn get_flow_wait_middle_rate_limit_ms_total(&self) -> u64 {
        self.flow_wait_middle_rate_limit_ms_total
            .load(Ordering::Relaxed)
    }
    pub fn get_session_drop_fallback_total(&self) -> u64 {
        self.session_drop_fallback_total.load(Ordering::Relaxed)
    }
}
