use super::*;
use std::fmt::Write;

pub(super) async fn render(
    out: &mut String,
    stats: &Stats,
    config: &ProxyConfig,
    ip_tracker: &UserIpTracker,
    core_enabled: bool,
    user_enabled: bool,
) {
    let _ = writeln!(
        out,
        "# HELP telemt_user_connections_total Per-user total connections"
    );
    let _ = writeln!(out, "# TYPE telemt_user_connections_total counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_connections_current Per-user active connections"
    );
    let _ = writeln!(out, "# TYPE telemt_user_connections_current gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_user_octets_from_client_total Per-user total bytes received"
    );
    let _ = writeln!(out, "# TYPE telemt_user_octets_from_client_total counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_octets_to_client_total Per-user total bytes sent"
    );
    let _ = writeln!(out, "# TYPE telemt_user_octets_to_client_total counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_msgs_from_client_total Per-user total messages received"
    );
    let _ = writeln!(out, "# TYPE telemt_user_msgs_from_client_total counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_msgs_to_client_total Per-user total messages sent"
    );
    let _ = writeln!(out, "# TYPE telemt_user_msgs_to_client_total counter");
    let _ = writeln!(
        out,
        "# HELP telemt_ip_reservation_rollback_total IP reservation rollbacks caused by later limit checks"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_reservation_rollback_total counter");
    let _ = writeln!(
        out,
        "telemt_ip_reservation_rollback_total{{reason=\"tcp_limit\"}} {}",
        if core_enabled {
            stats.get_ip_reservation_rollback_tcp_limit_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_ip_reservation_rollback_total{{reason=\"quota_limit\"}} {}",
        if core_enabled {
            stats.get_ip_reservation_rollback_quota_limit_total()
        } else {
            0
        }
    );
    let ip_memory = ip_tracker.memory_stats().await;
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_users Number of users tracked by IP limiter state"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_users gauge");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_users{{scope=\"active\"}} {}",
        ip_memory.active_users
    );
    let _ = writeln!(
        out,
        "telemt_ip_tracker_users{{scope=\"recent\"}} {}",
        ip_memory.recent_users
    );
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_entries Number of IP entries tracked by limiter state"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_entries gauge");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_entries{{scope=\"active\"}} {}",
        ip_memory.active_entries
    );
    let _ = writeln!(
        out,
        "telemt_ip_tracker_entries{{scope=\"recent\"}} {}",
        ip_memory.recent_entries
    );
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_cleanup_queue_len Deferred disconnect cleanup queue length"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_cleanup_queue_len gauge");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_cleanup_queue_len {}",
        ip_memory.cleanup_queue_len
    );
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_cleanup_total Release cleanups deferred through the cleanup queue"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_cleanup_total counter");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_cleanup_total{{path=\"deferred\"}} {}",
        ip_memory.cleanup_deferred_releases
    );
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_cap_rejects_total New connection rejects caused by global IP tracker caps"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_cap_rejects_total counter");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_cap_rejects_total{{scope=\"active\"}} {}",
        ip_memory.active_cap_rejects
    );
    let _ = writeln!(
        out,
        "telemt_ip_tracker_cap_rejects_total{{scope=\"recent\"}} {}",
        ip_memory.recent_cap_rejects
    );

    let mut user_stats_emitted = 0usize;
    let mut user_stats_suppressed = 0usize;
    let mut unique_ip_emitted = 0usize;
    let mut unique_ip_suppressed = 0usize;

    if user_enabled {
        for entry in stats.iter_user_stats() {
            if user_stats_emitted >= USER_LABELED_METRICS_MAX_USERS {
                user_stats_suppressed = user_stats_suppressed.saturating_add(1);
                continue;
            }
            let user = entry.key();
            let s = entry.value();
            user_stats_emitted = user_stats_emitted.saturating_add(1);
            let _ = writeln!(
                out,
                "telemt_user_connections_total{{user=\"{}\"}} {}",
                user,
                s.connects.load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_connections_current{{user=\"{}\"}} {}",
                user,
                s.curr_connects.load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_octets_from_client_total{{user=\"{}\"}} {}",
                user,
                s.octets_from_client
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_octets_to_client_total{{user=\"{}\"}} {}",
                user,
                s.octets_to_client
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_msgs_from_client_total{{user=\"{}\"}} {}",
                user,
                s.msgs_from_client
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_msgs_to_client_total{{user=\"{}\"}} {}",
                user,
                s.msgs_to_client.load(std::sync::atomic::Ordering::Relaxed)
            );
        }

        let ip_stats = ip_tracker.get_stats_snapshot().await;
        let ip_counts: HashMap<String, usize> = ip_stats
            .into_iter()
            .map(|(user, count, _)| (user, count))
            .collect();

        let mut unique_users = BTreeSet::new();
        unique_users.extend(config.access.users.keys().cloned());
        unique_users.extend(config.access.user_max_unique_ips.keys().cloned());
        unique_users.extend(ip_counts.keys().cloned());
        let unique_users_vec: Vec<String> = unique_users.iter().cloned().collect();
        let recent_counts = ip_tracker
            .get_recent_counts_for_users_snapshot(&unique_users_vec)
            .await;

        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_current Per-user current number of unique active IPs"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_current gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_recent_window Per-user unique IPs seen in configured observation window"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_recent_window gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_limit Effective per-user unique IP limit (0 means unlimited)"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_limit gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_utilization Per-user unique IP usage ratio (0 for unlimited)"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_utilization gauge");

        for user in unique_users {
            if unique_ip_emitted >= USER_LABELED_METRICS_MAX_USERS {
                unique_ip_suppressed = unique_ip_suppressed.saturating_add(1);
                continue;
            }
            unique_ip_emitted = unique_ip_emitted.saturating_add(1);
            let current = ip_counts.get(&user).copied().unwrap_or(0);
            let limit = config
                .access
                .user_max_unique_ips
                .get(&user)
                .copied()
                .filter(|limit| *limit > 0)
                .or((config.access.user_max_unique_ips_global_each > 0)
                    .then_some(config.access.user_max_unique_ips_global_each))
                .unwrap_or(0);
            let utilization = if limit > 0 {
                current as f64 / limit as f64
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_current{{user=\"{}\"}} {}",
                user, current
            );
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_recent_window{{user=\"{}\"}} {}",
                user,
                recent_counts.get(&user).copied().unwrap_or(0)
            );
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_limit{{user=\"{}\"}} {}",
                user, limit
            );
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_utilization{{user=\"{}\"}} {:.6}",
                user, utilization
            );
        }
    }

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_user_series_suppressed User-labeled metric series suppression flag"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_user_series_suppressed gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_user_series_suppressed {}",
        if user_enabled && user_stats_suppressed == 0 && unique_ip_suppressed == 0 {
            0
        } else {
            1
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_user_series_users User-labeled metric users by export status"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_user_series_users gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_user_series_users{{family=\"stats\",status=\"emitted\"}} {}",
        user_stats_emitted
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_user_series_users{{family=\"stats\",status=\"suppressed\"}} {}",
        user_stats_suppressed
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_user_series_users{{family=\"unique_ip\",status=\"emitted\"}} {}",
        unique_ip_emitted
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_user_series_users{{family=\"unique_ip\",status=\"suppressed\"}} {}",
        unique_ip_suppressed
    );
}
