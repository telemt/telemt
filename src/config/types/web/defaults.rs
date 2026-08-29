pub(super) fn default_web_static_index() -> String {
    "index.html".to_string()
}

macro_rules! usize_default {
    ($name:ident, $value:expr) => {
        pub(super) fn $name() -> usize {
            $value
        }
    };
}

macro_rules! u32_default {
    ($name:ident, $value:expr) => {
        pub(super) fn $name() -> u32 {
            $value
        }
    };
}

macro_rules! u8_default {
    ($name:ident, $value:expr) => {
        pub(super) fn $name() -> u8 {
            $value
        }
    };
}

macro_rules! u64_default {
    ($name:ident, $value:expr) => {
        pub(super) fn $name() -> u64 {
            $value
        }
    };
}

usize_default!(default_web_max_header_bytes, 16 * 1024);
usize_default!(default_web_max_body_bytes, 2 * 1024 * 1024);
usize_default!(default_web_max_frame_payload_bytes, 1024 * 1024);
usize_default!(default_web_carrier_batch_bytes, 2 * 1024 * 1024);
usize_default!(default_web_max_frames_per_body, 4096);
usize_default!(default_web_max_http_connections, 1024);
usize_default!(default_web_max_http_overload_connections, 64);
usize_default!(default_web_max_http_handlers, 512);
usize_default!(default_web_max_lane_open_waits_per_session, 16);
usize_default!(default_web_pending_bytes_per_lane, 8 * 1024 * 1024);
usize_default!(default_web_pending_items_per_lane, 1024);
usize_default!(default_web_websocket_bytes_global, 256 * 1024 * 1024);
u8_default!(default_web_websocket_admission_watermark_pct, 75);
u8_default!(default_web_websocket_eviction_watermark_pct, 90);
usize_default!(default_web_websocket_http_connection_reserve, 64);
usize_default!(default_web_max_websocket_evictions_in_flight, 8);
usize_default!(default_web_max_carrier_learning_entries, 4096);
usize_default!(default_web_max_body_readers, 32);
usize_default!(default_web_max_body_bytes_global, 64 * 1024 * 1024);
usize_default!(default_web_max_sessions_global, 128);
usize_default!(default_web_max_sessions_per_ip, 16);
usize_default!(default_web_max_streams_per_session, 128);
usize_default!(default_web_max_streams_global, 4096);
usize_default!(default_web_max_stream_handshakes, 256);
usize_default!(default_web_max_tombstones, 4096);
usize_default!(default_web_pending_bytes_per_session, 32 * 1024 * 1024);
usize_default!(default_web_pending_bytes_global, 512 * 1024 * 1024);
usize_default!(default_web_pending_items_per_session, 16 * 1024);
usize_default!(default_web_pending_items_global, 256 * 1024);
usize_default!(default_web_control_bytes_per_session, 256 * 1024);
usize_default!(default_web_control_bytes_global, 16 * 1024 * 1024);
usize_default!(default_web_max_bootstraps_global, 512);
usize_default!(default_web_max_bootstraps_per_ip, 64);
usize_default!(default_web_max_vhosts, 8);
usize_default!(default_web_max_profiles, 32);
usize_default!(default_web_max_static_files, 4096);
usize_default!(default_web_max_static_file_bytes, 8 * 1024 * 1024);
usize_default!(default_web_max_static_bytes, 64 * 1024 * 1024);
usize_default!(default_web_debug_records_capacity, 65_536);
usize_default!(default_web_debug_bytes_global, 64 * 1024 * 1024);
usize_default!(default_web_memory_envelope_bytes, 1280 * 1024 * 1024);
u32_default!(default_web_new_bootstraps_per_minute, 1200);
u32_default!(default_web_new_bootstraps_burst, 256);
u32_default!(default_web_new_sessions_per_minute, 600);
u32_default!(default_web_new_sessions_burst, 128);
u32_default!(default_web_new_streams_per_minute, 6000);
u32_default!(default_web_new_streams_burst, 512);
u64_default!(default_web_header_timeout_secs, 10);
u64_default!(default_web_body_timeout_secs, 30);
u64_default!(default_web_stream_handshake_timeout_secs, 10);
u64_default!(default_web_stream_first_byte_secs, 30);
u64_default!(default_web_long_poll_timeout_secs, 25);
u64_default!(default_web_bridge_request_secs, 10);
u64_default!(default_web_bridge_retry_secs, 90);
u64_default!(default_web_carrier_probe_coalesce_ms, 0);
u64_default!(default_web_lane_open_wait_secs, 2);
u64_default!(default_web_carrier_health_secs, 30);
u64_default!(default_web_websocket_upgrade_secs, 5);
u64_default!(default_web_websocket_open_secs, 15);
u64_default!(default_web_websocket_write_secs, 30);
u64_default!(default_web_websocket_backpressure_secs, 30);
u64_default!(default_web_websocket_eviction_secs, 1);
pub(super) fn default_web_carrier_negotiation_deadlines_secs() -> [u64; 4] {
    [3, 5, 8, 12]
}
u64_default!(default_web_carrier_learning_secs, 600);
pub(super) fn default_web_carrier_learning() -> bool {
    true
}
u64_default!(default_web_bootstrap_lifetime_secs, 120);
u64_default!(default_web_reconnect_grace_secs, 120);
u64_default!(default_web_http_idle_secs, 75);
u64_default!(default_web_http_overload_timeout_ms, 250);
u64_default!(default_web_shutdown_secs, 15);
u64_default!(default_web_decoy_header_timeout_secs, 30);
