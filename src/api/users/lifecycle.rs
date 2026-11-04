use super::*;
use tracing::warn;

pub(in crate::api) async fn rotate_secret(
    user: &str,
    body: RotateSecretRequest,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(CreateUserResponse, String), ApiFailure> {
    let shared = shared.clone();
    let user = user.to_string();
    shared
        .clone()
        .run_mutation_completion(async move {
            rotate_secret_to_completion(&user, body, expected_revision, &shared).await
        })
        .await
}

async fn rotate_secret_to_completion(
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
    let credential_id = credential_id_from_hex(&secret)
        .ok_or_else(|| ApiFailure::internal("validated user secret could not be decoded"))?;

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

    cfg.access.users.insert(user.to_string(), secret.clone());
    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let revision = save_access_sections_to_disk_if_revision(
        &shared.config_path,
        &cfg,
        &[AccessSection::Users],
        Some(&base_revision),
    )
    .await?;
    shared.proxy_shared.stage_user_credential(
        user,
        credential_id,
        cfg.access.is_user_enabled(user),
    );
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

    Ok((
        CreateUserResponse {
            user: user_info,
            secret,
        },
        revision,
    ))
}

pub(in crate::api) async fn delete_user(
    user: &str,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(String, String), ApiFailure> {
    let shared = shared.clone();
    let user = user.to_string();
    shared
        .clone()
        .run_mutation_completion(async move {
            delete_user_to_completion(&user, expected_revision, &shared).await
        })
        .await
}

async fn delete_user_to_completion(
    user: &str,
    expected_revision: Option<String>,
    shared: &ApiShared,
) -> Result<(String, String), ApiFailure> {
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
    if cfg.access.users.len() <= 1 {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "last_user_forbidden",
            "Cannot delete the last configured user",
        ));
    }

    let mut touched_sections = vec![AccessSection::Users];
    cfg.access.users.remove(user);
    if cfg.access.user_enabled.remove(user).is_some() {
        touched_sections.push(AccessSection::UserEnabled);
    }
    if cfg.access.user_ad_tags.remove(user).is_some() {
        touched_sections.push(AccessSection::UserAdTags);
    }
    if cfg.access.user_max_tcp_conns.remove(user).is_some() {
        touched_sections.push(AccessSection::UserMaxTcpConns);
    }
    if cfg.access.user_expirations.remove(user).is_some() {
        touched_sections.push(AccessSection::UserExpirations);
    }
    if cfg.access.user_quota_periods.remove(user).is_some() {
        touched_sections.push(AccessSection::UserQuotaPeriods);
    }
    if cfg.access.user_data_quota.remove(user).is_some() {
        touched_sections.push(AccessSection::UserDataQuota);
    }
    if cfg.access.user_rate_limits.remove(user).is_some() {
        touched_sections.push(AccessSection::UserRateLimits);
    }
    if cfg.access.user_max_unique_ips.remove(user).is_some() {
        touched_sections.push(AccessSection::UserMaxUniqueIps);
    }

    cfg.validate()
        .map_err(|e| ApiFailure::bad_request(format!("config validation failed: {}", e)))?;
    let revision = save_access_sections_to_disk_if_revision(
        &shared.config_path,
        &cfg,
        &touched_sections,
        Some(&base_revision),
    )
    .await?;
    let deleted_incarnation = shared.proxy_shared.delete_user(user).incarnation;
    let configured_users = cfg.access.users.keys().cloned().collect();
    if let Err(error) = shared
        .quota_state
        .remove_user_locked(&configured_users, user, quota_guard)
        .await
    {
        warn!(
            user,
            error = %error,
            "Deleted user quota checkpoint cleanup will be reconciled on restart"
        );
    }
    shared.ip_tracker.remove_user_limit(user).await;
    shared
        .ip_tracker
        .clear_user_ips_if_not_newer(user, deleted_incarnation)
        .await;
    drop(_guard);

    Ok((user.to_string(), revision))
}
