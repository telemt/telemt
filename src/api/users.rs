use std::net::IpAddr;

use hyper::StatusCode;

use crate::config::ProxyConfig;
use crate::ip_tracker::UserIpTracker;
use crate::stats::Stats;

use super::ApiShared;
use super::config_store::{
    AccessSection, current_revision, ensure_expected_revision, load_config_from_disk,
    save_access_sections_to_disk,
};
use super::model::{
    ApiFailure, CreateUserRequest, CreateUserResponse, PatchUserRequest, RotateSecretRequest,
    TlsDomainLink, UserInfo, UserLinks, is_valid_ad_tag, is_valid_user_secret, is_valid_username,
    parse_optional_expiration, parse_patch_expiration, random_user_secret,
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

    // ============= push_unique_host =============

    #[test]
    fn push_unique_host_appends_new_entry() {
        let mut hosts = vec!["a".to_string(), "b".to_string()];
        push_unique_host(&mut hosts, "c");
        assert_eq!(hosts, vec!["a", "b", "c"]);
    }

    #[test]
    fn push_unique_host_skips_existing_entry() {
        let mut hosts = vec!["a".to_string(), "b".to_string()];
        push_unique_host(&mut hosts, "a");
        assert_eq!(hosts, vec!["a", "b"]);
    }

    #[test]
    fn push_unique_host_distinguishes_case_sensitively() {
        // Function uses literal string equality — A and a are NOT collapsed.
        let mut hosts = vec!["A".to_string()];
        push_unique_host(&mut hosts, "a");
        assert_eq!(hosts, vec!["A", "a"]);
    }

    // ============= push_host_from_legacy_listen =============

    #[test]
    fn push_host_from_legacy_listen_skips_empty_and_unspecified() {
        let mut hosts = Vec::new();
        push_host_from_legacy_listen(&mut hosts, "");
        push_host_from_legacy_listen(&mut hosts, "   ");
        push_host_from_legacy_listen(&mut hosts, "0.0.0.0");
        push_host_from_legacy_listen(&mut hosts, "::");
        assert!(hosts.is_empty(), "wildcard binds must be filtered");
    }

    #[test]
    fn push_host_from_legacy_listen_keeps_concrete_ips_as_strings() {
        let mut hosts = Vec::new();
        push_host_from_legacy_listen(&mut hosts, "10.0.0.1");
        push_host_from_legacy_listen(&mut hosts, "::1");
        // Both are stored as their `to_string()` form.
        assert_eq!(hosts, vec!["10.0.0.1", "::1"]);
    }

    #[test]
    fn push_host_from_legacy_listen_passes_through_unparseable_as_hostname() {
        // Non-IP strings are treated as DNS hostnames, kept verbatim.
        let mut hosts = Vec::new();
        push_host_from_legacy_listen(&mut hosts, "proxy.example.net");
        push_host_from_legacy_listen(&mut hosts, "  proxy.example.net  ");
        // The second call must dedupe via trim → push_unique_host.
        assert_eq!(hosts, vec!["proxy.example.net"]);
    }

    #[test]
    fn push_host_from_legacy_listen_dedupes_repeated_concrete_ips() {
        let mut hosts = Vec::new();
        push_host_from_legacy_listen(&mut hosts, "10.0.0.1");
        push_host_from_legacy_listen(&mut hosts, "10.0.0.1");
        assert_eq!(hosts.len(), 1);
    }

    // ============= resolve_tls_domains =============

    fn cfg_with_tls_domains(primary: &str, extras: &[&str]) -> ProxyConfig {
        let mut cfg = ProxyConfig::default();
        cfg.censorship.tls_domain = primary.to_string();
        cfg.censorship.tls_domains = extras.iter().map(|s| s.to_string()).collect();
        cfg
    }

    #[test]
    fn resolve_tls_domains_starts_with_primary_when_set() {
        let cfg = cfg_with_tls_domains("a.example", &["b.example", "c.example"]);
        let r = resolve_tls_domains(&cfg);
        assert_eq!(r, vec!["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn resolve_tls_domains_skips_empty_primary() {
        let cfg = cfg_with_tls_domains("", &["b.example", "c.example"]);
        let r = resolve_tls_domains(&cfg);
        assert_eq!(r, vec!["b.example", "c.example"]);
    }

    #[test]
    fn resolve_tls_domains_dedupes_extras() {
        let cfg = cfg_with_tls_domains(
            "a.example",
            &["b.example", "b.example", "a.example", "c.example"],
        );
        let r = resolve_tls_domains(&cfg);
        // Order: primary first, then extras in original order, with duplicates dropped.
        assert_eq!(r, vec!["a.example", "b.example", "c.example"]);
    }

    // ============= resolve_extra_tls_domains =============

    #[test]
    fn resolve_extra_tls_domains_excludes_primary() {
        let cfg = cfg_with_tls_domains(
            "a.example",
            &["a.example", "b.example", "c.example", "a.example"],
        );
        let r = resolve_extra_tls_domains(&cfg);
        // Primary "a.example" is never included; duplicates are dropped.
        assert_eq!(r, vec!["b.example", "c.example"]);
    }

    #[test]
    fn resolve_extra_tls_domains_returns_empty_when_no_extras() {
        let cfg = cfg_with_tls_domains("a.example", &[]);
        assert!(resolve_extra_tls_domains(&cfg).is_empty());
    }
}
