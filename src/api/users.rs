use std::net::IpAddr;

use hyper::StatusCode;

use crate::config::ProxyConfig;
use crate::config::RateLimitBps;
use crate::ip_tracker::UserIpTracker;
use crate::stats::Stats;

use super::ApiShared;
use super::config_store::{
    AccessSection, current_revision, ensure_expected_revision, load_config_from_disk,
    save_access_sections_to_disk,
};
use super::model::{
    ApiFailure, CreateUserRequest, CreateUserResponse, PatchUserRequest, RotateSecretRequest,
    TlsDomainLink, UserInfo, UserLinks, UserQuotaEntry, UserQuotaListData, is_valid_ad_tag,
    is_valid_user_secret, is_valid_username, parse_optional_expiration, parse_patch_expiration,
    random_user_secret,
};
use super::patch::Patch;

pub(super) async fn create_user(
    body: CreateUserRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(CreateUserResponse, String), ApiFailure> {
    let touches_user_ad_tags = body.user_ad_tag.is_some();
    let touches_user_max_tcp_conns = body.max_tcp_conns.is_some();
    let touches_user_expirations = body.expiration_rfc3339.is_some();
    let touches_user_data_quota = body.data_quota_bytes.is_some();
    let touches_user_rate_limits =
        body.rate_limit_up_bps.is_some() || body.rate_limit_down_bps.is_some();
    let touches_user_max_unique_ips = body.max_unique_ips.is_some();

    if !is_valid_username(&body.username) {
        return Err(ApiFailure::bad_request(
            "username must match [A-Za-z0-9_.-] and be 1..64 chars",
        ));
    }

    let secret = match body.secret {
        Some(secret) => {
            if !is_valid_user_secret(&secret) {
                return Err(ApiFailure::bad_request(
                    "secret must be exactly 32 hex characters",
                ));
            }
            secret
        }
        None => random_user_secret(),
    };

    if let Some(ad_tag) = body.user_ad_tag.as_ref()
        && !is_valid_ad_tag(ad_tag)
    {
        return Err(ApiFailure::bad_request(
            "user_ad_tag must be exactly 32 hex characters",
        ));
    }

    let expiration = parse_optional_expiration(body.expiration_rfc3339.as_deref())?;
    let _guard = shared.mutation_lock.lock().await;
    let mut cfg = load_config_from_disk(&shared.config_path).await?;
    ensure_expected_revision(&shared.config_path, expected_revision.as_deref()).await?;

    if cfg.access.users.contains_key(&body.username) {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "user_exists",
            "User already exists",
        ));
    }

    cfg.access
        .users
        .insert(body.username.clone(), secret.clone());
    if let Some(ad_tag) = body.user_ad_tag {
        cfg.access
            .user_ad_tags
            .insert(body.username.clone(), ad_tag);
    }
    if let Some(limit) = body.max_tcp_conns {
        cfg.access
            .user_max_tcp_conns
            .insert(body.username.clone(), limit);
    }
    if let Some(expiration) = expiration {
        cfg.access
            .user_expirations
            .insert(body.username.clone(), expiration);
    }
    if let Some(quota) = body.data_quota_bytes {
        cfg.access
            .user_data_quota
            .insert(body.username.clone(), quota);
    }
    if touches_user_rate_limits {
        cfg.access.user_rate_limits.insert(
            body.username.clone(),
            RateLimitBps {
                up_bps: body.rate_limit_up_bps.unwrap_or(0),
                down_bps: body.rate_limit_down_bps.unwrap_or(0),
            },
        );
    }

    let updated_limit = body.max_unique_ips;
    if let Some(limit) = updated_limit {
        cfg.access
            .user_max_unique_ips
            .insert(body.username.clone(), limit);
    }

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;

    let mut touched_sections = vec![AccessSection::Users];
    if touches_user_ad_tags {
        touched_sections.push(AccessSection::UserAdTags);
    }
    if touches_user_max_tcp_conns {
        touched_sections.push(AccessSection::UserMaxTcpConns);
    }
    if touches_user_expirations {
        touched_sections.push(AccessSection::UserExpirations);
    }
    if touches_user_data_quota {
        touched_sections.push(AccessSection::UserDataQuota);
    }
    if touches_user_rate_limits {
        touched_sections.push(AccessSection::UserRateLimits);
    }
    if touches_user_max_unique_ips {
        touched_sections.push(AccessSection::UserMaxUniqueIps);
    }

    let revision =
        save_access_sections_to_disk(&shared.config_path, &cfg, &touched_sections).await?;
    drop(_guard);

    if let Some(limit) = updated_limit {
        shared
            .ip_tracker
            .set_user_limit(&body.username, limit)
            .await;
    }
    let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();

    let users = users_from_config(
        &cfg,
        &shared.stats,
        &shared.ip_tracker,
        detected_ip_v4,
        detected_ip_v6,
        None,
    )
    .await;
    let user = users
        .into_iter()
        .find(|entry| entry.username == body.username)
        .unwrap_or(UserInfo {
            username: body.username.clone(),
            in_runtime: false,
            user_ad_tag: None,
            max_tcp_conns: cfg
                .access
                .user_max_tcp_conns
                .get(&body.username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((cfg.access.user_max_tcp_conns_global_each > 0)
                    .then_some(cfg.access.user_max_tcp_conns_global_each)),
            expiration_rfc3339: None,
            data_quota_bytes: None,
            rate_limit_up_bps: body.rate_limit_up_bps.filter(|limit| *limit > 0),
            rate_limit_down_bps: body.rate_limit_down_bps.filter(|limit| *limit > 0),
            max_unique_ips: updated_limit,
            current_connections: 0,
            active_unique_ips: 0,
            active_unique_ips_list: Vec::new(),
            recent_unique_ips: 0,
            recent_unique_ips_list: Vec::new(),
            total_octets: 0,
            links: build_user_links(&cfg, &secret, detected_ip_v4, detected_ip_v6),
        });

    Ok((CreateUserResponse { user, secret }, revision))
}

pub(super) async fn patch_user(
    user: &str,
    body: PatchUserRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(UserInfo, String), ApiFailure> {
    let touches_users = body.secret.is_some();
    let touches_user_ad_tags = !matches!(&body.user_ad_tag, Patch::Unchanged);
    let touches_user_max_tcp_conns = !matches!(&body.max_tcp_conns, Patch::Unchanged);
    let touches_user_expirations = !matches!(&body.expiration_rfc3339, Patch::Unchanged);
    let touches_user_data_quota = !matches!(&body.data_quota_bytes, Patch::Unchanged);
    let touches_user_rate_limits = !matches!(&body.rate_limit_up_bps, Patch::Unchanged)
        || !matches!(&body.rate_limit_down_bps, Patch::Unchanged);
    let touches_user_max_unique_ips = !matches!(&body.max_unique_ips, Patch::Unchanged);

    if let Some(secret) = body.secret.as_ref()
        && !is_valid_user_secret(secret)
    {
        return Err(ApiFailure::bad_request(
            "secret must be exactly 32 hex characters",
        ));
    }
    if let Patch::Set(ad_tag) = &body.user_ad_tag
        && !is_valid_ad_tag(ad_tag)
    {
        return Err(ApiFailure::bad_request(
            "user_ad_tag must be exactly 32 hex characters",
        ));
    }
    let expiration = parse_patch_expiration(&body.expiration_rfc3339)?;
    let _guard = shared.mutation_lock.lock().await;
    let mut cfg = load_config_from_disk(&shared.config_path).await?;
    ensure_expected_revision(&shared.config_path, expected_revision.as_deref()).await?;

    if !cfg.access.users.contains_key(user) {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found",
        ));
    }

    if let Some(secret) = body.secret {
        cfg.access.users.insert(user.to_string(), secret);
    }
    match body.user_ad_tag {
        Patch::Unchanged => {}
        Patch::Remove => {
            cfg.access.user_ad_tags.remove(user);
        }
        Patch::Set(ad_tag) => {
            cfg.access.user_ad_tags.insert(user.to_string(), ad_tag);
        }
    }
    match body.max_tcp_conns {
        Patch::Unchanged => {}
        Patch::Remove => {
            cfg.access.user_max_tcp_conns.remove(user);
        }
        Patch::Set(limit) => {
            cfg.access
                .user_max_tcp_conns
                .insert(user.to_string(), limit);
        }
    }
    match expiration {
        Patch::Unchanged => {}
        Patch::Remove => {
            cfg.access.user_expirations.remove(user);
        }
        Patch::Set(expiration) => {
            cfg.access
                .user_expirations
                .insert(user.to_string(), expiration);
        }
    }
    match body.data_quota_bytes {
        Patch::Unchanged => {}
        Patch::Remove => {
            cfg.access.user_data_quota.remove(user);
        }
        Patch::Set(quota) => {
            cfg.access.user_data_quota.insert(user.to_string(), quota);
        }
    }
    if touches_user_rate_limits {
        let mut rate_limit = cfg
            .access
            .user_rate_limits
            .get(user)
            .copied()
            .unwrap_or_default();
        match body.rate_limit_up_bps {
            Patch::Unchanged => {}
            Patch::Remove => rate_limit.up_bps = 0,
            Patch::Set(limit) => rate_limit.up_bps = limit,
        }
        match body.rate_limit_down_bps {
            Patch::Unchanged => {}
            Patch::Remove => rate_limit.down_bps = 0,
            Patch::Set(limit) => rate_limit.down_bps = limit,
        }
        if rate_limit.up_bps == 0 && rate_limit.down_bps == 0 {
            cfg.access.user_rate_limits.remove(user);
        } else {
            cfg.access
                .user_rate_limits
                .insert(user.to_string(), rate_limit);
        }
    }
    // Capture how the per-user IP limit changed, so the in-memory ip_tracker
    // can be synced (set or removed) after the config is persisted.
    let max_unique_ips_change = match body.max_unique_ips {
        Patch::Unchanged => None,
        Patch::Remove => {
            cfg.access.user_max_unique_ips.remove(user);
            Some(None)
        }
        Patch::Set(limit) => {
            cfg.access
                .user_max_unique_ips
                .insert(user.to_string(), limit);
            Some(Some(limit))
        }
    };

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;

    let mut touched_sections = Vec::new();
    if touches_users {
        touched_sections.push(AccessSection::Users);
    }
    if touches_user_ad_tags {
        touched_sections.push(AccessSection::UserAdTags);
    }
    if touches_user_max_tcp_conns {
        touched_sections.push(AccessSection::UserMaxTcpConns);
    }
    if touches_user_expirations {
        touched_sections.push(AccessSection::UserExpirations);
    }
    if touches_user_data_quota {
        touched_sections.push(AccessSection::UserDataQuota);
    }
    if touches_user_rate_limits {
        touched_sections.push(AccessSection::UserRateLimits);
    }
    if touches_user_max_unique_ips {
        touched_sections.push(AccessSection::UserMaxUniqueIps);
    }

    let revision = if touched_sections.is_empty() {
        current_revision(&shared.config_path).await?
    } else {
        save_access_sections_to_disk(&shared.config_path, &cfg, &touched_sections).await?
    };
    drop(_guard);
    match max_unique_ips_change {
        Some(Some(limit)) => shared.ip_tracker.set_user_limit(user, limit).await,
        Some(None) => shared.ip_tracker.remove_user_limit(user).await,
        None => {}
    }
    let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
    let users = users_from_config(
        &cfg,
        &shared.stats,
        &shared.ip_tracker,
        detected_ip_v4,
        detected_ip_v6,
        None,
    )
    .await;
    let user_info = users
        .into_iter()
        .find(|entry| entry.username == user)
        .ok_or_else(|| ApiFailure::internal("failed to build updated user view"))?;

    Ok((user_info, revision))
}

pub(super) async fn rotate_secret(
    user: &str,
    body: RotateSecretRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(CreateUserResponse, String), ApiFailure> {
    let secret = body.secret.unwrap_or_else(random_user_secret);
    if !is_valid_user_secret(&secret) {
        return Err(ApiFailure::bad_request(
            "secret must be exactly 32 hex characters",
        ));
    }

    let _guard = shared.mutation_lock.lock().await;
    let mut cfg = load_config_from_disk(&shared.config_path).await?;
    ensure_expected_revision(&shared.config_path, expected_revision.as_deref()).await?;

    if !cfg.access.users.contains_key(user) {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found",
        ));
    }

    cfg.access.users.insert(user.to_string(), secret.clone());
    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let touched_sections = [
        AccessSection::Users,
        AccessSection::UserAdTags,
        AccessSection::UserMaxTcpConns,
        AccessSection::UserExpirations,
        AccessSection::UserDataQuota,
        AccessSection::UserRateLimits,
        AccessSection::UserMaxUniqueIps,
    ];
    let revision =
        save_access_sections_to_disk(&shared.config_path, &cfg, &touched_sections).await?;
    drop(_guard);

    let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
    let users = users_from_config(
        &cfg,
        &shared.stats,
        &shared.ip_tracker,
        detected_ip_v4,
        detected_ip_v6,
        None,
    )
    .await;
    let user_info = users
        .into_iter()
        .find(|entry| entry.username == user)
        .ok_or_else(|| ApiFailure::internal("failed to build updated user view"))?;

    Ok((
        CreateUserResponse {
            user: user_info,
            secret,
        },
        revision,
    ))
}

pub(super) async fn delete_user(
    user: &str,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(String, String), ApiFailure> {
    let _guard = shared.mutation_lock.lock().await;
    let mut cfg = load_config_from_disk(&shared.config_path).await?;
    ensure_expected_revision(&shared.config_path, expected_revision.as_deref()).await?;

    if !cfg.access.users.contains_key(user) {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found",
        ));
    }
    if cfg.access.users.len() <= 1 {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "last_user_forbidden",
            "Cannot delete the last configured user",
        ));
    }

    cfg.access.users.remove(user);
    cfg.access.user_ad_tags.remove(user);
    cfg.access.user_max_tcp_conns.remove(user);
    cfg.access.user_expirations.remove(user);
    cfg.access.user_data_quota.remove(user);
    cfg.access.user_rate_limits.remove(user);
    cfg.access.user_max_unique_ips.remove(user);

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let touched_sections = [
        AccessSection::Users,
        AccessSection::UserAdTags,
        AccessSection::UserMaxTcpConns,
        AccessSection::UserExpirations,
        AccessSection::UserDataQuota,
        AccessSection::UserRateLimits,
        AccessSection::UserMaxUniqueIps,
    ];
    let revision =
        save_access_sections_to_disk(&shared.config_path, &cfg, &touched_sections).await?;
    drop(_guard);
    shared.ip_tracker.remove_user_limit(user).await;
    shared.ip_tracker.clear_user_ips(user).await;

    Ok((user.to_string(), revision))
}

pub(super) async fn users_from_config(
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
            current_connections: stats.get_user_curr_connects(&username),
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

pub(super) fn build_user_quota_list(cfg: &ProxyConfig, stats: &Stats) -> UserQuotaListData {
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
            username,
            data_quota_bytes,
            used_bytes,
            last_reset_epoch_secs,
        });
    }
    UserQuotaListData { users }
}

fn empty_user_links() -> UserLinks {
    UserLinks {
        classic: Vec::new(),
        secure: Vec::new(),
        tls: Vec::new(),
        tls_domains: Vec::new(),
    }
}

fn build_user_links(
    cfg: &ProxyConfig,
    secret: &str,
    startup_detected_ip_v4: Option<IpAddr>,
    startup_detected_ip_v6: Option<IpAddr>,
) -> UserLinks {
    let hosts = resolve_link_hosts(cfg, startup_detected_ip_v4, startup_detected_ip_v6);
    let port = cfg
        .general
        .links
        .public_port
        .unwrap_or(resolve_default_link_port(cfg));
    let tls_domains = resolve_tls_domains(cfg);
    let extra_tls_domains = resolve_extra_tls_domains(cfg);

    let mut classic = Vec::new();
    let mut secure = Vec::new();
    let mut tls = Vec::new();
    let mut tls_domain_links = Vec::new();

    for host in &hosts {
        if cfg.general.modes.classic {
            classic.push(format!(
                "tg://proxy?server={}&port={}&secret={}",
                host, port, secret
            ));
        }
        if cfg.general.modes.secure {
            secure.push(format!(
                "tg://proxy?server={}&port={}&secret=dd{}",
                host, port, secret
            ));
        }
        if cfg.general.modes.tls {
            for domain in &tls_domains {
                let domain_hex = hex::encode(domain);
                tls.push(format!(
                    "tg://proxy?server={}&port={}&secret=ee{}{}",
                    host, port, secret, domain_hex
                ));
            }
            for domain in &extra_tls_domains {
                let domain_hex = hex::encode(domain);
                let link = format!(
                    "tg://proxy?server={}&port={}&secret=ee{}{}",
                    host, port, secret, domain_hex
                );
                tls_domain_links.push(TlsDomainLink {
                    domain: (*domain).to_string(),
                    link,
                });
            }
        }
    }

    UserLinks {
        classic,
        secure,
        tls,
        tls_domains: tls_domain_links,
    }
}

fn resolve_default_link_port(cfg: &ProxyConfig) -> u16 {
    cfg.server
        .listeners
        .first()
        .and_then(|listener| listener.port)
        .unwrap_or(cfg.server.port)
}

fn resolve_link_hosts(
    cfg: &ProxyConfig,
    startup_detected_ip_v4: Option<IpAddr>,
    startup_detected_ip_v6: Option<IpAddr>,
) -> Vec<String> {
    if let Some(host) = cfg
        .general
        .links
        .public_host
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return vec![host.to_string()];
    }

    let mut hosts = Vec::new();
    for listener in &cfg.server.listeners {
        if let Some(host) = listener
            .announce
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            push_unique_host(&mut hosts, host);
            continue;
        }
        if let Some(ip) = listener.announce_ip
            && !ip.is_unspecified()
        {
            push_unique_host(&mut hosts, &ip.to_string());
            continue;
        }
        if listener.ip.is_unspecified() {
            let detected_ip = if listener.ip.is_ipv4() {
                startup_detected_ip_v4
            } else {
                startup_detected_ip_v6
            };
            if let Some(ip) = detected_ip {
                push_unique_host(&mut hosts, &ip.to_string());
            } else {
                push_unique_host(&mut hosts, &listener.ip.to_string());
            }
            continue;
        }
        push_unique_host(&mut hosts, &listener.ip.to_string());
    }

    if !hosts.is_empty() {
        return hosts;
    }

    if let Some(ip) = startup_detected_ip_v4.or(startup_detected_ip_v6) {
        return vec![ip.to_string()];
    }

    if let Some(host) = cfg.server.listen_addr_ipv4.as_deref() {
        push_host_from_legacy_listen(&mut hosts, host);
    }
    if let Some(host) = cfg.server.listen_addr_ipv6.as_deref() {
        push_host_from_legacy_listen(&mut hosts, host);
    }
    if !hosts.is_empty() {
        return hosts;
    }

    vec!["UNKNOWN".to_string()]
}

fn push_host_from_legacy_listen(hosts: &mut Vec<String>, raw: &str) {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return;
    }

    match candidate.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => {}
        Ok(ip) => push_unique_host(hosts, &ip.to_string()),
        Err(_) => push_unique_host(hosts, candidate),
    }
}

fn push_unique_host(hosts: &mut Vec<String>, candidate: &str) {
    if !hosts.iter().any(|existing| existing == candidate) {
        hosts.push(candidate.to_string());
    }
}

fn resolve_tls_domains(cfg: &ProxyConfig) -> Vec<&str> {
    let mut domains = Vec::with_capacity(1 + cfg.censorship.tls_domains.len());
    let primary = cfg.censorship.tls_domain.as_str();
    if !primary.is_empty() {
        domains.push(primary);
    }
    for domain in &cfg.censorship.tls_domains {
        let value = domain.as_str();
        if value.is_empty() || domains.contains(&value) {
            continue;
        }
        domains.push(value);
    }
    domains
}

fn resolve_extra_tls_domains(cfg: &ProxyConfig) -> Vec<&str> {
    let mut domains = Vec::with_capacity(cfg.censorship.tls_domains.len());
    let primary = cfg.censorship.tls_domain.as_str();
    for domain in &cfg.censorship.tls_domains {
        let value = domain.as_str();
        if value.is_empty() || value == primary || domains.contains(&value) {
            continue;
        }
        domains.push(value);
    }
    domains
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_tracker::UserIpTracker;
    use crate::stats::Stats;

    #[tokio::test]
    async fn users_from_config_reports_effective_tcp_limit_with_global_fallback() {
        let mut cfg = ProxyConfig::default();
        cfg.access.users.insert(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );
        cfg.access.user_max_tcp_conns_global_each = 7;

        let stats = Stats::new();
        let tracker = UserIpTracker::new();

        let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");
        assert!(!alice.in_runtime);
        assert_eq!(alice.max_tcp_conns, Some(7));

        cfg.access.user_max_tcp_conns.insert("alice".to_string(), 5);
        let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");
        assert!(!alice.in_runtime);
        assert_eq!(alice.max_tcp_conns, Some(5));

        cfg.access.user_max_tcp_conns.insert("alice".to_string(), 0);
        let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");
        assert!(!alice.in_runtime);
        assert_eq!(alice.max_tcp_conns, Some(7));

        cfg.access.user_max_tcp_conns_global_each = 0;
        let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");
        assert!(!alice.in_runtime);
        assert_eq!(alice.max_tcp_conns, None);
    }

    #[tokio::test]
    async fn users_from_config_reports_user_rate_limits() {
        let mut cfg = ProxyConfig::default();
        cfg.access.users.insert(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );
        cfg.access.user_rate_limits.insert(
            "alice".to_string(),
            RateLimitBps {
                up_bps: 1024,
                down_bps: 0,
            },
        );

        let stats = Stats::new();
        let tracker = UserIpTracker::new();

        let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");

        assert_eq!(alice.rate_limit_up_bps, Some(1024));
        assert_eq!(alice.rate_limit_down_bps, None);
    }

    #[tokio::test]
    async fn users_from_config_marks_runtime_membership_when_snapshot_is_provided() {
        let mut disk_cfg = ProxyConfig::default();
        disk_cfg.access.users.insert(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );
        disk_cfg.access.users.insert(
            "bob".to_string(),
            "fedcba9876543210fedcba9876543210".to_string(),
        );

        let mut runtime_cfg = ProxyConfig::default();
        runtime_cfg.access.users.insert(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );

        let stats = Stats::new();
        let tracker = UserIpTracker::new();
        let users =
            users_from_config(&disk_cfg, &stats, &tracker, None, None, Some(&runtime_cfg)).await;

        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");
        let bob = users
            .iter()
            .find(|entry| entry.username == "bob")
            .expect("bob must be present");

        assert!(alice.in_runtime);
        assert!(!bob.in_runtime);
    }

    #[tokio::test]
    async fn users_from_config_returns_tls_link_for_each_tls_domain() {
        let mut cfg = ProxyConfig::default();
        cfg.access.users.insert(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );
        cfg.general.modes.classic = false;
        cfg.general.modes.secure = false;
        cfg.general.modes.tls = true;
        cfg.general.links.public_host = Some("proxy.example.net".to_string());
        cfg.general.links.public_port = Some(443);
        cfg.censorship.tls_domain = "front-a.example.com".to_string();
        cfg.censorship.tls_domains = vec![
            "front-b.example.com".to_string(),
            "front-c.example.com".to_string(),
            "front-b.example.com".to_string(),
            "front-a.example.com".to_string(),
        ];

        let stats = Stats::new();
        let tracker = UserIpTracker::new();
        let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
        let alice = users
            .iter()
            .find(|entry| entry.username == "alice")
            .expect("alice must be present");

        assert_eq!(alice.links.tls.len(), 3);
        assert!(
            alice
                .links
                .tls
                .iter()
                .any(|link| link.ends_with(&hex::encode("front-a.example.com")))
        );
        assert!(
            alice
                .links
                .tls
                .iter()
                .any(|link| link.ends_with(&hex::encode("front-b.example.com")))
        );
        assert!(
            alice
                .links
                .tls
                .iter()
                .any(|link| link.ends_with(&hex::encode("front-c.example.com")))
        );
        assert_eq!(alice.links.tls_domains.len(), 2);
        assert!(
            alice
                .links
                .tls_domains
                .iter()
                .any(|entry| entry.domain == "front-b.example.com"
                    && entry.link.ends_with(&hex::encode("front-b.example.com")))
        );
        assert!(
            alice
                .links
                .tls_domains
                .iter()
                .any(|entry| entry.domain == "front-c.example.com"
                    && entry.link.ends_with(&hex::encode("front-c.example.com")))
        );
        assert!(
            !alice
                .links
                .tls_domains
                .iter()
                .any(|entry| entry.domain == "front-a.example.com")
        );
    }

    #[test]
    fn build_user_quota_list_skips_users_without_positive_quota_and_sorts_by_username() {
        let mut cfg = ProxyConfig::default();
        cfg.access.users.insert(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );
        cfg.access.users.insert(
            "bob".to_string(),
            "fedcba9876543210fedcba9876543210".to_string(),
        );
        cfg.access.users.insert(
            "carol".to_string(),
            "aaaabbbbccccddddeeeeffff00001111".to_string(),
        );
        // alice has a positive quota and should be listed.
        cfg.access
            .user_data_quota
            .insert("alice".to_string(), 1 << 20);
        // bob has no quota entry at all (None) — should be skipped.
        // carol has an explicit zero quota — should be skipped.
        cfg.access.user_data_quota.insert("carol".to_string(), 0);

        let stats = Stats::new();
        // Charge some traffic against alice; carol gets traffic too but should
        // still be filtered out by the quota check.
        let alice_stats = stats.get_or_create_user_stats_handle("alice");
        stats.quota_charge_post_write(&alice_stats, 4096);
        let carol_stats = stats.get_or_create_user_stats_handle("carol");
        stats.quota_charge_post_write(&carol_stats, 99);

        let data = build_user_quota_list(&cfg, &stats);

        assert_eq!(data.users.len(), 1);
        let entry = &data.users[0];
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.data_quota_bytes, 1 << 20);
        assert_eq!(entry.used_bytes, 4096);
        assert_eq!(entry.last_reset_epoch_secs, 0);
    }

    #[test]
    fn build_user_quota_list_orders_multiple_users_by_username_ascending() {
        let mut cfg = ProxyConfig::default();
        for name in ["charlie", "alice", "bob"] {
            cfg.access.users.insert(
                name.to_string(),
                "0123456789abcdef0123456789abcdef".to_string(),
            );
            cfg.access.user_data_quota.insert(name.to_string(), 1 << 30);
        }

        let stats = Stats::new();
        let data = build_user_quota_list(&cfg, &stats);

        let names: Vec<&str> = data.users.iter().map(|e| e.username.as_str()).collect();
        assert_eq!(names, vec!["alice", "bob", "charlie"]);
        for entry in &data.users {
            assert_eq!(entry.used_bytes, 0);
            assert_eq!(entry.last_reset_epoch_secs, 0);
            assert_eq!(entry.data_quota_bytes, 1 << 30);
        }
    }
}
