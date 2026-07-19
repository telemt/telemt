use super::*;

impl Stats {
    pub fn get_connects_all(&self) -> u64 {
        self.connects_all.load(Ordering::Relaxed)
    }
    pub fn get_connects_bad(&self) -> u64 {
        self.connects_bad.load(Ordering::Relaxed)
    }

    pub fn get_connects_bad_class_counts(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .connects_bad_classes
            .iter()
            .map(|entry| {
                (
                    entry.key().to_string(),
                    entry.value().load(Ordering::Relaxed),
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn get_handshake_failure_class_counts(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .handshake_failure_classes
            .iter()
            .map(|entry| {
                (
                    entry.key().to_string(),
                    entry.value().load(Ordering::Relaxed),
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn get_accept_permit_timeout_total(&self) -> u64 {
        self.accept_permit_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_current_connections_direct(&self) -> u64 {
        self.current_connections_direct.load(Ordering::Relaxed)
    }
    pub fn get_current_connections_me(&self) -> u64 {
        self.current_connections_me.load(Ordering::Relaxed)
    }
    pub fn get_route_cutover_parked_direct_current(&self) -> u64 {
        self.route_cutover_parked_direct_current
            .load(Ordering::Relaxed)
    }
    pub fn get_route_cutover_parked_middle_current(&self) -> u64 {
        self.route_cutover_parked_middle_current
            .load(Ordering::Relaxed)
    }
    pub fn get_route_cutover_parked_direct_total(&self) -> u64 {
        self.route_cutover_parked_direct_total
            .load(Ordering::Relaxed)
    }
    pub fn get_route_cutover_parked_middle_total(&self) -> u64 {
        self.route_cutover_parked_middle_total
            .load(Ordering::Relaxed)
    }
    pub fn get_current_connections_total(&self) -> u64 {
        self.get_current_connections_direct()
            .saturating_add(self.get_current_connections_me())
    }
    pub fn get_conntrack_control_enabled(&self) -> bool {
        self.conntrack_control_enabled_gauge.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_control_available(&self) -> bool {
        self.conntrack_control_available_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_conntrack_pressure_active(&self) -> bool {
        self.conntrack_pressure_active_gauge.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_event_queue_depth(&self) -> u64 {
        self.conntrack_event_queue_depth_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_conntrack_rule_apply_ok(&self) -> bool {
        self.conntrack_rule_apply_ok_gauge.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_attempt_total(&self) -> u64 {
        self.conntrack_delete_attempt_total.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_success_total(&self) -> u64 {
        self.conntrack_delete_success_total.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_not_found_total(&self) -> u64 {
        self.conntrack_delete_not_found_total
            .load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_error_total(&self) -> u64 {
        self.conntrack_delete_error_total.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_close_event_drop_total(&self) -> u64 {
        self.conntrack_close_event_drop_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_sent(&self) -> u64 {
        self.me_keepalive_sent.load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_failed(&self) -> u64 {
        self.me_keepalive_failed.load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_pong(&self) -> u64 {
        self.me_keepalive_pong.load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_timeout(&self) -> u64 {
        self.me_keepalive_timeout.load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_sent_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_sent_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_failed_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_failed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_skipped_no_meta_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_skipped_no_meta_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_response_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_response_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_close_sent_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_close_sent_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_reconnect_attempts(&self) -> u64 {
        self.me_reconnect_attempts.load(Ordering::Relaxed)
    }
    pub fn get_me_reconnect_success(&self) -> u64 {
        self.me_reconnect_success.load(Ordering::Relaxed)
    }
    pub fn get_me_handshake_reject_total(&self) -> u64 {
        self.me_handshake_reject_total.load(Ordering::Relaxed)
    }
    pub fn get_me_reader_eof_total(&self) -> u64 {
        self.me_reader_eof_total.load(Ordering::Relaxed)
    }
    pub fn get_me_idle_close_by_peer_total(&self) -> u64 {
        self.me_idle_close_by_peer_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_idle_soft_mark_total(&self) -> u64 {
        self.relay_idle_soft_mark_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_idle_hard_close_total(&self) -> u64 {
        self.relay_idle_hard_close_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_pressure_evict_total(&self) -> u64 {
        self.relay_pressure_evict_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_protocol_desync_close_total(&self) -> u64 {
        self.relay_protocol_desync_close_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_crc_mismatch(&self) -> u64 {
        self.me_crc_mismatch.load(Ordering::Relaxed)
    }
    pub fn get_me_seq_mismatch(&self) -> u64 {
        self.me_seq_mismatch.load(Ordering::Relaxed)
    }
    pub fn get_me_endpoint_quarantine_total(&self) -> u64 {
        self.me_endpoint_quarantine_total.load(Ordering::Relaxed)
    }
    pub fn get_me_endpoint_quarantine_unexpected_total(&self) -> u64 {
        self.me_endpoint_quarantine_unexpected_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_endpoint_quarantine_draining_suppressed_total(&self) -> u64 {
        self.me_endpoint_quarantine_draining_suppressed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_kdf_drift_total(&self) -> u64 {
        self.me_kdf_drift_total.load(Ordering::Relaxed)
    }
    pub fn get_me_kdf_port_only_drift_total(&self) -> u64 {
        self.me_kdf_port_only_drift_total.load(Ordering::Relaxed)
    }
    pub fn get_me_hardswap_pending_reuse_total(&self) -> u64 {
        self.me_hardswap_pending_reuse_total.load(Ordering::Relaxed)
    }
    pub fn get_me_hardswap_pending_ttl_expired_total(&self) -> u64 {
        self.me_hardswap_pending_ttl_expired_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_enter_total(&self) -> u64 {
        self.me_single_endpoint_outage_enter_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_exit_total(&self) -> u64 {
        self.me_single_endpoint_outage_exit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_reconnect_attempt_total(&self) -> u64 {
        self.me_single_endpoint_outage_reconnect_attempt_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_reconnect_success_total(&self) -> u64 {
        self.me_single_endpoint_outage_reconnect_success_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_quarantine_bypass_total(&self) -> u64 {
        self.me_single_endpoint_quarantine_bypass_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_shadow_rotate_total(&self) -> u64 {
        self.me_single_endpoint_shadow_rotate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_shadow_rotate_skipped_quarantine_total(&self) -> u64 {
        self.me_single_endpoint_shadow_rotate_skipped_quarantine_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_mode_switch_total(&self) -> u64 {
        self.me_floor_mode_switch_total.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_mode_switch_static_to_adaptive_total(&self) -> u64 {
        self.me_floor_mode_switch_static_to_adaptive_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_mode_switch_adaptive_to_static_total(&self) -> u64 {
        self.me_floor_mode_switch_adaptive_to_static_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_cpu_cores_detected_gauge(&self) -> u64 {
        self.me_floor_cpu_cores_detected_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_cpu_cores_effective_gauge(&self) -> u64 {
        self.me_floor_cpu_cores_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_global_cap_raw_gauge(&self) -> u64 {
        self.me_floor_global_cap_raw_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_global_cap_effective_gauge(&self) -> u64 {
        self.me_floor_global_cap_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_target_writers_total_gauge(&self) -> u64 {
        self.me_floor_target_writers_total_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_active_cap_configured_gauge(&self) -> u64 {
        self.me_floor_active_cap_configured_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_active_cap_effective_gauge(&self) -> u64 {
        self.me_floor_active_cap_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_warm_cap_configured_gauge(&self) -> u64 {
        self.me_floor_warm_cap_configured_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_warm_cap_effective_gauge(&self) -> u64 {
        self.me_floor_warm_cap_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writers_active_current_gauge(&self) -> u64 {
        self.me_writers_active_current_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_writers_warm_current_gauge(&self) -> u64 {
        self.me_writers_warm_current_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_cap_block_total(&self) -> u64 {
        self.me_floor_cap_block_total.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_swap_idle_total(&self) -> u64 {
        self.me_floor_swap_idle_total.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_swap_idle_failed_total(&self) -> u64 {
        self.me_floor_swap_idle_failed_total.load(Ordering::Relaxed)
    }
}
