use super::*;

impl Stats {
    pub fn increment_me_keepalive_sent(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_keepalive_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_failed(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_keepalive_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_pong(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_keepalive_pong.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_timeout(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_keepalive_timeout.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_timeout_by(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_keepalive_timeout
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_sent_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_sent_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_failed_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_skipped_no_meta_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_skipped_no_meta_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_response_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_response_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_close_sent_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_close_sent_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_reconnect_attempt(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_reconnect_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_reconnect_success(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_reconnect_success.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_handshake_reject_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_handshake_reject_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_handshake_error_code(&self, code: i32) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        if let Some(entry) = self.me_handshake_error_codes.get(&code) {
            entry.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut slots = self.me_handshake_error_code_slots.load(Ordering::Acquire);
        loop {
            if slots >= ME_HANDSHAKE_ERROR_CODE_MAX {
                if let Some(entry) = self.me_handshake_error_codes.get(&code) {
                    entry.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.me_handshake_error_code_overflow_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            match self.me_handshake_error_code_slots.compare_exchange_weak(
                slots,
                slots + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => slots = observed,
            }
        }

        match self.me_handshake_error_codes.entry(code) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                self.me_handshake_error_code_slots
                    .fetch_sub(1, Ordering::AcqRel);
                entry.get().fetch_add(1, Ordering::Relaxed);
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(AtomicU64::new(1));
            }
        }
    }
    pub fn increment_me_reader_eof_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_reader_eof_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_idle_close_by_peer_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_idle_close_by_peer_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_idle_soft_mark_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_idle_soft_mark_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_idle_hard_close_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_idle_hard_close_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_pressure_evict_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_pressure_evict_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_protocol_desync_close_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_protocol_desync_close_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_crc_mismatch(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_crc_mismatch.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_seq_mismatch(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_seq_mismatch.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_no_conn(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_no_conn.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_channel_closed(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_channel_closed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_queue_full(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_queue_full
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_queue_full_base(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_queue_full_base
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_queue_full_high(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_queue_full_high
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_pressure_state_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_pressure_state_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_active_flows_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_active_flows_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_queued_bytes_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_queued_bytes_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_standing_flows_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_standing_flows_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_backpressured_flows_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_backpressured_flows_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_scheduler_rounds_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_scheduler_rounds_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_deficit_grants_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_deficit_grants_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_deficit_skips_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_deficit_skips_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_enqueue_rejects_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_enqueue_rejects_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_shed_drops_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_shed_drops_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_penalties_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_penalties_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_downstream_stalls_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_downstream_stalls_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_batches_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_batches_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn add_me_d2c_batch_frames_total(&self, frames: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_batch_frames_total
                .fetch_add(frames, Ordering::Relaxed);
        }
    }
    pub fn add_me_d2c_batch_bytes_total(&self, bytes: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_batch_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_flush_reason(&self, reason: MeD2cFlushReason) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match reason {
            MeD2cFlushReason::QueueDrain => {
                self.me_d2c_flush_reason_queue_drain_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::BatchFrames => {
                self.me_d2c_flush_reason_batch_frames_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::BatchBytes => {
                self.me_d2c_flush_reason_batch_bytes_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::MaxDelay => {
                self.me_d2c_flush_reason_max_delay_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::AckImmediate => {
                self.me_d2c_flush_reason_ack_immediate_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::Close => {
                self.me_d2c_flush_reason_close_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_d2c_data_frames_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_data_frames_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_ack_frames_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_ack_frames_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn add_me_d2c_payload_bytes_total(&self, bytes: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_payload_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_write_mode(&self, mode: MeD2cWriteMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeD2cWriteMode::Coalesced => {
                self.me_d2c_write_mode_coalesced_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cWriteMode::Split => {
                self.me_d2c_write_mode_split_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_d2c_quota_reject_total(&self, stage: MeD2cQuotaRejectStage) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match stage {
            MeD2cQuotaRejectStage::PreWrite => {
                self.me_d2c_quota_reject_pre_write_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cQuotaRejectStage::PostWrite => {
                self.me_d2c_quota_reject_post_write_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_me_d2c_frame_buf_shrink(&self, bytes_freed: u64) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        self.me_d2c_frame_buf_shrink_total
            .fetch_add(1, Ordering::Relaxed);
        self.me_d2c_frame_buf_shrink_bytes_total
            .fetch_add(bytes_freed, Ordering::Relaxed);
    }
    pub fn observe_me_d2c_batch_frames(&self, frames: u64) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        match frames {
            0 => {}
            1 => {
                self.me_d2c_batch_frames_bucket_1
                    .fetch_add(1, Ordering::Relaxed);
            }
            2..=4 => {
                self.me_d2c_batch_frames_bucket_2_4
                    .fetch_add(1, Ordering::Relaxed);
            }
            5..=8 => {
                self.me_d2c_batch_frames_bucket_5_8
                    .fetch_add(1, Ordering::Relaxed);
            }
            9..=16 => {
                self.me_d2c_batch_frames_bucket_9_16
                    .fetch_add(1, Ordering::Relaxed);
            }
            17..=32 => {
                self.me_d2c_batch_frames_bucket_17_32
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.me_d2c_batch_frames_bucket_gt_32
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_me_d2c_batch_bytes(&self, bytes: u64) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        match bytes {
            0..=1024 => {
                self.me_d2c_batch_bytes_bucket_0_1k
                    .fetch_add(1, Ordering::Relaxed);
            }
            1025..=4096 => {
                self.me_d2c_batch_bytes_bucket_1k_4k
                    .fetch_add(1, Ordering::Relaxed);
            }
            4097..=16_384 => {
                self.me_d2c_batch_bytes_bucket_4k_16k
                    .fetch_add(1, Ordering::Relaxed);
            }
            16_385..=65_536 => {
                self.me_d2c_batch_bytes_bucket_16k_64k
                    .fetch_add(1, Ordering::Relaxed);
            }
            65_537..=131_072 => {
                self.me_d2c_batch_bytes_bucket_64k_128k
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.me_d2c_batch_bytes_bucket_gt_128k
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_me_d2c_flush_duration_us(&self, duration_us: u64) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        match duration_us {
            0..=50 => {
                self.me_d2c_flush_duration_us_bucket_0_50
                    .fetch_add(1, Ordering::Relaxed);
            }
            51..=200 => {
                self.me_d2c_flush_duration_us_bucket_51_200
                    .fetch_add(1, Ordering::Relaxed);
            }
            201..=1000 => {
                self.me_d2c_flush_duration_us_bucket_201_1000
                    .fetch_add(1, Ordering::Relaxed);
            }
            1001..=5000 => {
                self.me_d2c_flush_duration_us_bucket_1001_5000
                    .fetch_add(1, Ordering::Relaxed);
            }
            5001..=20_000 => {
                self.me_d2c_flush_duration_us_bucket_5001_20000
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.me_d2c_flush_duration_us_bucket_gt_20000
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_d2c_batch_timeout_armed_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_d2c_batch_timeout_armed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_batch_timeout_fired_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_d2c_batch_timeout_fired_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn handshake_error_code_cardinality_is_bounded_under_concurrency() {
        const WORKERS: usize = 8;
        const CODES_PER_WORKER: usize = 128;

        let stats = Arc::new(Stats::new());
        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let stats = stats.clone();
                scope.spawn(move || {
                    for code in 0..CODES_PER_WORKER {
                        stats.increment_me_handshake_error_code(
                            (worker * CODES_PER_WORKER + code) as i32,
                        );
                    }
                });
            }
        });

        let counts = stats.get_me_handshake_error_code_counts();
        assert!(counts.len() <= ME_HANDSHAKE_ERROR_CODE_MAX);
        assert_eq!(
            counts.iter().map(|(_, total)| *total).sum::<u64>()
                + stats.get_me_handshake_error_code_overflow_total(),
            (WORKERS * CODES_PER_WORKER) as u64
        );
        assert_eq!(
            stats.me_handshake_error_code_slots.load(Ordering::Acquire),
            counts.len()
        );
    }
}
