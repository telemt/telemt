use super::*;
use std::fmt::Write;

pub(super) fn render(
    out: &mut String,
    stats: &Stats,
    shared_state: &ProxySharedState,
    telemetry: crate::stats::telemetry::TelemetryPolicy,
    tls_full_cert_budget: &TlsFullCertBudget,
) {
    let core_enabled = telemetry.core_enabled;
    let user_enabled = telemetry.user_enabled;
    let _ = writeln!(
        out,
        "# HELP telemt_build_info Build information for the running telemt binary"
    );
    let _ = writeln!(out, "# TYPE telemt_build_info gauge");
    let _ = writeln!(
        out,
        "telemt_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    let _ = writeln!(out, "# HELP telemt_uptime_seconds Proxy uptime");
    let _ = writeln!(out, "# TYPE telemt_uptime_seconds gauge");
    let _ = writeln!(out, "telemt_uptime_seconds {:.1}", stats.uptime_secs());

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_core_enabled Runtime core telemetry switch"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_core_enabled gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_core_enabled {}",
        if core_enabled { 1 } else { 0 }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_user_enabled Runtime per-user telemetry switch"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_user_enabled gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_user_enabled {}",
        if user_enabled { 1 } else { 0 }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_stats_user_entries Retained per-user stats entries"
    );
    let _ = writeln!(out, "# TYPE telemt_stats_user_entries gauge");
    let _ = writeln!(out, "telemt_stats_user_entries {}", stats.user_stats_len());

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_me_level Runtime ME telemetry level flag"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_me_level gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_me_level{{level=\"silent\"}} {}",
        if matches!(telemetry.me_level, crate::config::MeTelemetryLevel::Silent) {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_me_level{{level=\"normal\"}} {}",
        if matches!(telemetry.me_level, crate::config::MeTelemetryLevel::Normal) {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_me_level{{level=\"debug\"}} {}",
        if matches!(telemetry.me_level, crate::config::MeTelemetryLevel::Debug) {
            1
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_buffer_pool_buffers_total Snapshot of pooled and allocated buffers"
    );
    let _ = writeln!(out, "# TYPE telemt_buffer_pool_buffers_total gauge");
    let _ = writeln!(
        out,
        "telemt_buffer_pool_buffers_total{{kind=\"pooled\"}} {}",
        stats.get_buffer_pool_pooled_gauge()
    );
    let _ = writeln!(
        out,
        "telemt_buffer_pool_buffers_total{{kind=\"allocated\"}} {}",
        stats.get_buffer_pool_allocated_gauge()
    );
    let _ = writeln!(
        out,
        "telemt_buffer_pool_buffers_total{{kind=\"in_use\"}} {}",
        stats.get_buffer_pool_in_use_gauge()
    );
    let _ = writeln!(
        out,
        "# HELP telemt_buffer_pool_events_total Buffer-pool allocation lifecycle events"
    );
    let _ = writeln!(out, "# TYPE telemt_buffer_pool_events_total counter");
    let _ = writeln!(
        out,
        "telemt_buffer_pool_events_total{{event=\"replaced_nonstandard\"}} {}",
        stats.get_buffer_pool_replaced_nonstandard_total()
    );

    let direct_budget = shared_state.direct_buffer_budget.snapshot();
    let _ = writeln!(
        out,
        "# HELP telemt_direct_relay_buffer_budget_bytes Direct relay copy-buffer budget and memory inputs"
    );
    let _ = writeln!(out, "# TYPE telemt_direct_relay_buffer_budget_bytes gauge");
    for (kind, value) in [
        ("hard_limit", direct_budget.hard_limit_bytes),
        ("target", direct_budget.target_bytes),
        ("reserved", direct_budget.reserved_bytes),
        ("memory_total", direct_budget.memory_total_bytes),
        ("memory_available", direct_budget.memory_available_bytes),
        ("process_rss", direct_budget.process_rss_bytes),
    ] {
        let _ = writeln!(
            out,
            "telemt_direct_relay_buffer_budget_bytes{{kind=\"{}\"}} {}",
            kind, value
        );
    }
    let _ = writeln!(
        out,
        "# HELP telemt_direct_relay_buffer_budget_events_total Direct relay buffer-budget lifecycle events"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_direct_relay_buffer_budget_events_total counter"
    );
    for (result, value) in [
        ("promotion", direct_budget.promotion_total),
        ("promotion_denied", direct_budget.promotion_denied_total),
        ("minimum_fallback", direct_budget.minimum_fallback_total),
        ("admission_rejected", direct_budget.admission_rejected_total),
        ("quiet_demotion", direct_budget.quiet_demotion_total),
        (
            "write_pressure_demotion",
            direct_budget.write_pressure_demotion_total,
        ),
        (
            "global_pressure_demotion",
            direct_budget.global_pressure_demotion_total,
        ),
    ] {
        let _ = writeln!(
            out,
            "telemt_direct_relay_buffer_budget_events_total{{result=\"{}\"}} {}",
            result, value
        );
    }
    let _ = writeln!(
        out,
        "# HELP telemt_direct_relay_buffer_sessions Current Direct relay sessions by adaptive tier"
    );
    let _ = writeln!(out, "# TYPE telemt_direct_relay_buffer_sessions gauge");
    for (tier, value) in ["base", "tier1", "tier2", "tier3"]
        .into_iter()
        .zip(direct_budget.tier_sessions)
    {
        let _ = writeln!(
            out,
            "telemt_direct_relay_buffer_sessions{{tier=\"{}\"}} {}",
            tier, value
        );
    }

    let _ = writeln!(
        out,
        "# HELP telemt_tls_fetch_profile_cache_entries Current adaptive TLS fetch profile-cache entries"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_fetch_profile_cache_entries gauge");
    let _ = writeln!(
        out,
        "telemt_tls_fetch_profile_cache_entries {}",
        fetcher::profile_cache_entries_for_metrics()
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_fetch_profile_cache_cap_drops_total Profile-cache winner inserts skipped because the cache cap was reached"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_fetch_profile_cache_cap_drops_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_tls_fetch_profile_cache_cap_drops_total {}",
        fetcher::profile_cache_cap_drops_for_metrics()
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_full_cert_budget_entries Current domain and IP entries tracked by the process-owned TLS full-cert budget"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_front_full_cert_budget_entries gauge"
    );
    let _ = writeln!(
        out,
        "telemt_tls_front_full_cert_budget_entries {}",
        tls_full_cert_budget.entries_for_metrics()
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_full_cert_budget_cap_drops_total New domain and IP entries denied full-cert budget tracking because a bound was reached"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_front_full_cert_budget_cap_drops_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_tls_front_full_cert_budget_cap_drops_total {}",
        tls_full_cert_budget.cap_drops_for_metrics()
    );
}
