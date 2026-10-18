use super::*;

pub(in crate::api) async fn create_user(
    body: CreateUserRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(CreateUserResponse, String), ApiFailure> {
    let shared = shared.clone();
    shared
        .clone()
        .run_mutation_completion(async move {
            create_user_to_completion(body, expected_revision, &shared).await
        })
        .await
}

async fn create_user_to_completion(
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
    let touches_user_enabled = matches!(body.enabled, Some(false));

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
    let credential_id = credential_id_from_hex(&secret)
        .ok_or_else(|| ApiFailure::internal("validated user secret could not be decoded"))?;
    let _guard = shared.mutation_lock.lock().await;
    let quota_guard = shared.quota_state.lock().await;
    let (mut cfg, base_revision) =
        load_config_for_mutation(&shared.config_path, expected_revision.as_deref()).await?;

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
    if matches!(body.enabled, Some(false)) {
        cfg.access.user_enabled.insert(body.username.clone(), false);
    }

    if let Some(period) = body.quota_period {
        cfg.access
            .user_quota_periods
            .insert(body.username.clone(), period);
    }
    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;

    let mut touched_sections = vec![AccessSection::Users];
    if body.quota_period.is_some() {
        touched_sections.push(AccessSection::UserQuotaPeriods);
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
    if touches_user_enabled {
        touched_sections.push(AccessSection::UserEnabled);
    }

    let revision = save_access_sections_to_disk_if_revision(
        &shared.config_path,
        &cfg,
        &touched_sections,
        Some(&base_revision),
    )
    .await?;
    shared.proxy_shared.stage_user_credential(
        &body.username,
        credential_id,
        cfg.access.is_user_enabled(&body.username),
    );

    shared.quota_state.fence_fresh_schedule(
        &body.username,
        &shared.active_runtime.load_full().config(),
        credential_id,
        cfg.access.user_quota_periods.get(&body.username).copied(),
        cfg.access.user_data_quota.get(&body.username).copied(),
    );
    drop(quota_guard);
    if let Some(limit) = updated_limit {
        shared
            .ip_tracker
            .set_user_limit(&body.username, limit)
            .await;
    }
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
    let user = users
        .into_iter()
        .find(|entry| entry.username == body.username)
        .unwrap_or(UserInfo {
            username: body.username.clone(),
            enabled: cfg.access.is_user_enabled(&body.username),
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
            quota_period: body.quota_period,
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
