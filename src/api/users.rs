use std::net::IpAddr;

use hyper::StatusCode;

use crate::config::ProxyConfig;
use crate::ip_tracker::UserIpTracker;
use crate::stats::Stats;

use super::ApiShared;
use super::config_store::{
    AccessSection, ensure_expected_revision, load_config_from_disk, save_access_sections_to_disk,
    save_config_to_disk,
};
use super::model::{
    ApiFailure, CreateUserRequest, CreateUserResponse, PatchUserRequest, RotateSecretRequest,
    UserInfo, UserLinks, is_valid_ad_tag, is_valid_user_secret, is_valid_username,
    parse_optional_expiration, random_user_secret,
};

pub(super) async fn create_user(
    body: CreateUserRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(CreateUserResponse, String), ApiFailure> {
    let touches_user_ad_tags = body.user_ad_tag.is_some();
    let touches_user_max_tcp_conns = body.max_tcp_conns.is_some();
    let touches_user_expirations = body.expiration_rfc3339.is_some();
    let touches_user_data_quota = body.data_quota_bytes.is_some();
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
    )
    .await;
    let user = users
        .into_iter()
        .find(|entry| entry.username == body.username)
        .unwrap_or(UserInfo {
            username: body.username.clone(),
            user_ad_tag: None,
            max_tcp_conns: None,
            expiration_rfc3339: None,
            data_quota_bytes: None,
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
    if let Some(secret) = body.secret.as_ref()
        && !is_valid_user_secret(secret)
    {
        return Err(ApiFailure::bad_request(
            "secret must be exactly 32 hex characters",
        ));
    }
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
    if let Some(ad_tag) = body.user_ad_tag {
        cfg.access.user_ad_tags.insert(user.to_string(), ad_tag);
    }
    if let Some(limit) = body.max_tcp_conns {
        cfg.access
            .user_max_tcp_conns
            .insert(user.to_string(), limit);
    }
    if let Some(expiration) = expiration {
        cfg.access
            .user_expirations
            .insert(user.to_string(), expiration);
    }
    if let Some(quota) = body.data_quota_bytes {
        cfg.access.user_data_quota.insert(user.to_string(), quota);
    }

    let mut updated_limit = None;
    if let Some(limit) = body.max_unique_ips {
        cfg.access
            .user_max_unique_ips
            .insert(user.to_string(), limit);
        updated_limit = Some(limit);
    }

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;

    let revision = save_config_to_disk(&shared.config_path, &cfg).await?;
    drop(_guard);
    if let Some(limit) = updated_limit {
        shared.ip_tracker.set_user_limit(user, limit).await;
    }
    let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
    let users = users_from_config(
        &cfg,
        &shared.stats,
        &shared.ip_tracker,
        detected_ip_v4,
        detected_ip_v6,
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
    cfg.access.user_max_unique_ips.remove(user);

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let touched_sections = [
        AccessSection::Users,
        AccessSection::UserAdTags,
        AccessSection::UserMaxTcpConns,
        AccessSection::UserExpirations,
        AccessSection::UserDataQuota,
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
            .unwrap_or(UserLinks {
                classic: Vec::new(),
                secure: Vec::new(),
                tls: Vec::new(),
            });
        users.push(UserInfo {
            user_ad_tag: cfg.access.user_ad_tags.get(&username).cloned(),
            max_tcp_conns: cfg.access.user_max_tcp_conns.get(&username).copied(),
            expiration_rfc3339: cfg
                .access
                .user_expirations
                .get(&username)
                .map(chrono::DateTime::<chrono::Utc>::to_rfc3339),
            data_quota_bytes: cfg.access.user_data_quota.get(&username).copied(),
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

fn build_user_links(
    cfg: &ProxyConfig,
    secret: &str,
    startup_detected_ip_v4: Option<IpAddr>,
    startup_detected_ip_v6: Option<IpAddr>,
) -> UserLinks {
    let hosts = resolve_link_hosts(cfg, startup_detected_ip_v4, startup_detected_ip_v6);
    let port = cfg.general.links.public_port.unwrap_or(cfg.server.port);
    let tls_domains = resolve_tls_domains(cfg);

    let mut classic = Vec::new();
    let mut secure = Vec::new();
    let mut tls = Vec::new();

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
        }
    }

    UserLinks {
        classic,
        secure,
        tls,
    }
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
