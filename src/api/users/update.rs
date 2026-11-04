use super::*;

pub(in crate::api) async fn patch_user(
    user: &str,
    body: PatchUserRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(UserInfo, String), ApiFailure> {
    let shared = shared.clone();
    let user = user.to_string();
    shared
        .clone()
        .run_mutation_completion(async move {
            patch_user_to_completion(&user, body, expected_revision, &shared).await
        })
        .await
}

async fn patch_user_to_completion(
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
    let touches_user_enabled = !matches!(&body.enabled, Patch::Unchanged);

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
    let quota_guard = shared.quota_state.lock().await;
    let (mut cfg, base_revision) =
        load_config_for_mutation(&shared.config_path, expected_revision.as_deref()).await?;

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
    let touches_user_quota_periods = !matches!(body.quota_period, Patch::Unchanged);
    match body.quota_period {
        Patch::Unchanged => {}
        Patch::Remove => {
            cfg.access.user_quota_periods.remove(user);
        }
        Patch::Set(period) => {
            cfg.access
                .user_quota_periods
                .insert(user.to_string(), period);
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
    match body.enabled {
        Patch::Unchanged => {}
        Patch::Remove | Patch::Set(true) => {
            cfg.access.user_enabled.remove(user);
        }
        Patch::Set(false) => {
            cfg.access.user_enabled.insert(user.to_string(), false);
        }
    }

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let staged_credential =
        if touches_users || touches_user_enabled {
            let secret = cfg
                .access
                .users
                .get(user)
                .ok_or_else(|| ApiFailure::internal("updated user secret is missing"))?;
            Some(credential_id_from_hex(secret).ok_or_else(|| {
                ApiFailure::internal("validated user secret could not be decoded")
            })?)
        } else {
            None
        };

    let mut touched_sections = Vec::new();
    if touches_user_quota_periods {
        touched_sections.push(AccessSection::UserQuotaPeriods);
    }
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
    if touches_user_enabled {
        touched_sections.push(AccessSection::UserEnabled);
    }

    let revision = if touched_sections.is_empty() {
        current_revision(&shared.config_path).await?
    } else {
        save_access_sections_to_disk_if_revision(
            &shared.config_path,
            &cfg,
            &touched_sections,
            Some(&base_revision),
        )
        .await?
    };
    if let Some(credential_id) = staged_credential {
        shared.proxy_shared.stage_user_credential(
            user,
            credential_id,
            cfg.access.is_user_enabled(user),
        );
    }
    shared.quota_state.refresh_fresh_schedule(user, &cfg);
    drop(quota_guard);
    match max_unique_ips_change {
        Some(Some(limit)) => shared.ip_tracker.set_user_limit(user, limit).await,
        Some(None) => shared.ip_tracker.remove_user_limit(user).await,
        None => {}
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
    let user_info = users
        .into_iter()
        .find(|entry| entry.username == user)
        .ok_or_else(|| ApiFailure::internal("failed to build updated user view"))?;

    Ok((user_info, revision))
}

pub(in crate::api) async fn set_user_enabled(
    user: &str,
    enabled: bool,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(UserInfo, String), ApiFailure> {
    let shared = shared.clone();
    let user = user.to_string();
    shared
        .clone()
        .run_mutation_completion(async move {
            set_user_enabled_to_completion(&user, enabled, expected_revision, &shared).await
        })
        .await
}

async fn set_user_enabled_to_completion(
    user: &str,
    enabled: bool,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(UserInfo, String), ApiFailure> {
    let _guard = shared.mutation_lock.lock().await;
    let quota_guard = shared.quota_state.lock().await;
    let (mut cfg, base_revision) =
        load_config_for_mutation(&shared.config_path, expected_revision.as_deref()).await?;

    if !cfg.access.users.contains_key(user) {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found",
        ));
    }

    if enabled {
        cfg.access.user_enabled.remove(user);
    } else {
        cfg.access.user_enabled.insert(user.to_string(), false);
    }

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let credential_id = cfg
        .access
        .users
        .get(user)
        .and_then(|secret| credential_id_from_hex(secret))
        .ok_or_else(|| ApiFailure::internal("validated user secret could not be decoded"))?;
    let revision = save_access_sections_to_disk_if_revision(
        &shared.config_path,
        &cfg,
        &[AccessSection::UserEnabled],
        Some(&base_revision),
    )
    .await?;
    shared
        .proxy_shared
        .stage_user_credential(user, credential_id, enabled);
    shared.quota_state.refresh_fresh_schedule(user, &cfg);
    drop(quota_guard);
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

    Ok((user_info, revision))
}
