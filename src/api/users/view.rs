use super::*;

pub(in crate::api) async fn users_from_config(
    cfg: &ProxyConfig,
    stats: &Stats,
    ip_tracker: &UserIpTracker,
    startup_detected_ip_v4: Option<IpAddr>,
    startup_detected_ip_v6: Option<IpAddr>,
    runtime_cfg: Option<&ProxyConfig>,
) -> Vec<UserInfo> {
    let mut names = cfg.access.users.keys().cloned().collect::<Vec<_>>();
    names.sort();
    let active_ip_lists = ip_tracker.get_active_ips_for_users(&names).await;
    let recent_ip_lists = ip_tracker.get_recent_ips_for_users(&names).await;

    let mut users = Vec::with_capacity(names.len());
    for username in names {
        let active_ip_list = active_ip_lists
            .get(&username)
            .cloned()
            .unwrap_or_else(Vec::new);
        let recent_ip_list = recent_ip_lists
            .get(&username)
            .cloned()
            .unwrap_or_else(Vec::new);
        let links = cfg
            .access
            .users
            .get(&username)
            .map(|secret| {
                build_user_links(cfg, secret, startup_detected_ip_v4, startup_detected_ip_v6)
            })
            .unwrap_or_else(empty_user_links);
        users.push(UserInfo {
            enabled: cfg.access.is_user_enabled(&username),
            in_runtime: runtime_cfg
                .map(|runtime| runtime.access.users.contains_key(&username))
                .unwrap_or(false),
            user_ad_tag: cfg.access.user_ad_tags.get(&username).cloned(),
            max_tcp_conns: cfg
                .access
                .user_max_tcp_conns
                .get(&username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((cfg.access.user_max_tcp_conns_global_each > 0)
                    .then_some(cfg.access.user_max_tcp_conns_global_each)),
            expiration_rfc3339: cfg
                .access
                .user_expirations
                .get(&username)
                .map(chrono::DateTime::<chrono::Utc>::to_rfc3339),
            data_quota_bytes: cfg.access.user_data_quota.get(&username).copied(),
            quota_period: cfg.access.user_quota_periods.get(&username).copied(),
            rate_limit_up_bps: cfg
                .access
                .user_rate_limits
                .get(&username)
                .map(|limit| limit.up_bps)
                .filter(|limit| *limit > 0),
            rate_limit_down_bps: cfg
                .access
                .user_rate_limits
                .get(&username)
                .map(|limit| limit.down_bps)
                .filter(|limit| *limit > 0),
            max_unique_ips: cfg
                .access
                .user_max_unique_ips
                .get(&username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((cfg.access.user_max_unique_ips_global_each > 0)
                    .then_some(cfg.access.user_max_unique_ips_global_each)),
            current_connections: stats.get_process_user_curr_connects(&username),
            active_unique_ips: active_ip_list.len(),
            active_unique_ips_list: active_ip_list,
            recent_unique_ips: recent_ip_list.len(),
            recent_unique_ips_list: recent_ip_list,
            total_octets: stats.get_user_total_octets(&username),
            links,
            username,
        });
    }
    users
}

pub(in crate::api) fn build_user_quota_list(cfg: &ProxyConfig, stats: &Stats) -> UserQuotaListData {
    let mut names = cfg.access.users.keys().cloned().collect::<Vec<_>>();
    names.sort();

    let snapshot = stats.user_quota_snapshot();
    let mut users = Vec::with_capacity(names.len());
    for username in names {
        let Some(&data_quota_bytes) = cfg.access.user_data_quota.get(&username) else {
            continue;
        };
        if data_quota_bytes == 0 {
            continue;
        }
        let (used_bytes, last_reset_epoch_secs) = snapshot
            .get(&username)
            .map(|entry| (entry.used_bytes, entry.last_reset_epoch_secs))
            .unwrap_or((0, 0));
        users.push(UserQuotaEntry {
            username: username.clone(),
            quota_period: cfg.access.user_quota_periods.get(&username).copied(),
            schedule: crate::stats::QuotaScheduleStatus {
                quota_schedule_state: "disabled",
                ..Default::default()
            },
            data_quota_bytes,
            used_bytes,
            last_reset_epoch_secs,
        });
    }
    UserQuotaListData { users }
}
