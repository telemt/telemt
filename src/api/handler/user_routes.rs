use super::*;

pub(super) async fn handle(
    req: Request<Incoming>,
    method: &Method,
    path: &str,
    normalized_path: &str,
    shared: &Arc<ApiShared>,
    cfg: &ProxyConfig,
    config_rx: &watch::Receiver<Arc<ProxyConfig>>,
    request_id: u64,
    body_limit: usize,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let api_cfg = &cfg.server.api;
    if method == Method::GET
        && let Some(reload_id) = reload_status_route_id(normalized_path)
    {
        let revision = current_revision(&shared.config_path).await?;
        let status = shared
            .reload_control
            .status(reload_id)
            .await
            .ok_or_else(|| {
                ApiFailure::new(
                    StatusCode::NOT_FOUND,
                    "reload_not_found",
                    format!("Reload {} was not found", reload_id),
                )
            })?;
        return Ok(success_response(StatusCode::OK, status, revision));
    }
    if method == Method::POST
        && let Some(base_user) = normalized_path
            .strip_prefix("/v1/users/")
            .and_then(|path| path.strip_suffix("/enable"))
        && !base_user.is_empty()
        && !base_user.contains('/')
    {
        let base_user = parse_route_username(base_user)?;
        if api_cfg.read_only {
            return Ok(error_response(
                request_id,
                ApiFailure::new(
                    StatusCode::FORBIDDEN,
                    "read_only",
                    "API runs in read-only mode",
                ),
            ));
        }
        let expected_revision = parse_if_match(req.headers());
        let result = set_user_enabled(base_user, true, expected_revision, shared).await;
        let (mut data, revision) = match result {
            Ok(ok) => ok,
            Err(error) => {
                shared.runtime_events.record(
                    "api.user.enable.failed",
                    format!("username={} code={}", base_user, error.code),
                );
                return Err(error);
            }
        };
        let runtime_cfg = config_rx.borrow().clone();
        data.in_runtime = runtime_cfg.access.users.contains_key(&data.username);
        shared.proxy_shared.set_user_enabled(base_user, true);
        shared
            .runtime_events
            .record("api.user.enable.ok", format!("username={}", base_user));
        let status = if data.in_runtime {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        };
        return Ok(success_response(status, data, revision));
    }
    if method == Method::POST
        && let Some(base_user) = normalized_path
            .strip_prefix("/v1/users/")
            .and_then(|path| path.strip_suffix("/disable"))
        && !base_user.is_empty()
        && !base_user.contains('/')
    {
        let base_user = parse_route_username(base_user)?;
        if api_cfg.read_only {
            return Ok(error_response(
                request_id,
                ApiFailure::new(
                    StatusCode::FORBIDDEN,
                    "read_only",
                    "API runs in read-only mode",
                ),
            ));
        }
        let expected_revision = parse_if_match(req.headers());
        let result = set_user_enabled(base_user, false, expected_revision, shared).await;
        let (mut data, revision) = match result {
            Ok(ok) => ok,
            Err(error) => {
                shared.runtime_events.record(
                    "api.user.disable.failed",
                    format!("username={} code={}", base_user, error.code),
                );
                return Err(error);
            }
        };
        let runtime_cfg = config_rx.borrow().clone();
        data.in_runtime = runtime_cfg.access.users.contains_key(&data.username);
        let newly_disabled = shared.proxy_shared.set_user_enabled(base_user, false);
        let cancelled = shared.proxy_shared.cancel_user_sessions(base_user);
        shared.runtime_events.record(
            "api.user.disable.ok",
            format!(
                "username={} newly_disabled={} cancelled_sessions={}",
                base_user, newly_disabled, cancelled
            ),
        );
        let status = if data.in_runtime {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        };
        return Ok(success_response(status, data, revision));
    }
    if method == Method::POST
        && let Some(user) = normalized_path
            .strip_prefix("/v1/users/")
            .and_then(|path| path.strip_suffix("/reset-quota"))
        && !user.is_empty()
        && !user.contains('/')
    {
        let user = parse_route_username(user)?;
        if api_cfg.read_only {
            return Ok(error_response(
                request_id,
                ApiFailure::new(
                    StatusCode::FORBIDDEN,
                    "read_only",
                    "API runs in read-only mode",
                ),
            ));
        }
        let expected_revision = parse_if_match(req.headers());
        let _mutation_guard = shared.mutation_lock.lock().await;
        let disk_cfg = load_config_from_disk(&shared.config_path).await?;
        ensure_expected_revision(&shared.config_path, expected_revision.as_deref()).await?;
        if !disk_cfg.access.users.contains_key(user) {
            return Ok(error_response(
                request_id,
                ApiFailure::new(StatusCode::NOT_FOUND, "not_found", "User not found"),
            ));
        }
        let configured_users = disk_cfg
            .access
            .users
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let snapshot = match shared.quota_state.reset_user(&configured_users, user).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                shared.runtime_events.record(
                    "api.user.reset_quota.failed",
                    format!("username={} error={}", user, error),
                );
                return Err(ApiFailure::internal(format!(
                    "Failed to reset user quota: {}",
                    error
                )));
            }
        };
        shared
            .runtime_events
            .record("api.user.reset_quota.ok", format!("username={}", user));
        let revision = current_revision(&shared.config_path).await?;
        return Ok(success_response(
            StatusCode::OK,
            ResetUserQuotaResponse {
                username: user.to_string(),
                used_bytes: snapshot.used_bytes,
                last_reset_epoch_secs: snapshot.last_reset_epoch_secs,
            },
            revision,
        ));
    }
    if method == Method::POST
        && let Some(base_user) = normalized_path
            .strip_prefix("/v1/users/")
            .and_then(|path| path.strip_suffix("/rotate-secret"))
        && !base_user.is_empty()
        && !base_user.contains('/')
    {
        let base_user = parse_route_username(base_user)?;
        if api_cfg.read_only {
            return Ok(error_response(
                request_id,
                ApiFailure::new(
                    StatusCode::FORBIDDEN,
                    "read_only",
                    "API runs in read-only mode",
                ),
            ));
        }
        let expected_revision = parse_if_match(req.headers());
        let body = read_optional_json::<RotateSecretRequest>(req.into_body(), body_limit).await?;
        let result = rotate_secret(
            base_user,
            body.unwrap_or_default(),
            expected_revision,
            shared,
        )
        .await;
        let (mut data, revision) = match result {
            Ok(ok) => ok,
            Err(error) => {
                shared.runtime_events.record(
                    "api.user.rotate_secret.failed",
                    format!("username={} code={}", base_user, error.code),
                );
                return Err(error);
            }
        };
        let runtime_cfg = config_rx.borrow().clone();
        data.user.in_runtime = runtime_cfg.access.users.contains_key(&data.user.username);
        shared.runtime_events.record(
            "api.user.rotate_secret.ok",
            format!("username={}", base_user),
        );
        let status = if data.user.in_runtime {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        };
        return Ok(success_response(status, data, revision));
    }
    if let Some(user) = normalized_path.strip_prefix("/v1/users/")
        && !user.is_empty()
        && !user.contains('/')
    {
        let user = parse_route_username(user)?;
        if method == Method::GET {
            let revision = current_revision(&shared.config_path).await?;
            let disk_cfg = load_config_from_disk(&shared.config_path).await?;
            let runtime_cfg = config_rx.borrow().clone();
            let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
            let users = users_from_config(
                &disk_cfg,
                &shared.stats,
                &shared.ip_tracker,
                detected_ip_v4,
                detected_ip_v6,
                Some(runtime_cfg.as_ref()),
            )
            .await;
            if let Some(user_info) = users.into_iter().find(|entry| entry.username == user) {
                return Ok(success_response(StatusCode::OK, user_info, revision));
            }
            return Ok(error_response(
                request_id,
                ApiFailure::new(StatusCode::NOT_FOUND, "not_found", "User not found"),
            ));
        }
        if method == Method::PATCH {
            if api_cfg.read_only {
                return Ok(error_response(
                    request_id,
                    ApiFailure::new(
                        StatusCode::FORBIDDEN,
                        "read_only",
                        "API runs in read-only mode",
                    ),
                ));
            }
            let expected_revision = parse_if_match(req.headers());
            let body = read_json::<PatchUserRequest>(req.into_body(), body_limit).await?;
            let enabled_update = match &body.enabled {
                Patch::Unchanged => None,
                Patch::Remove => Some(true),
                Patch::Set(enabled) => Some(*enabled),
            };
            let result = patch_user(user, body, expected_revision, shared).await;
            let (mut data, revision) = match result {
                Ok(ok) => ok,
                Err(error) => {
                    shared.runtime_events.record(
                        "api.user.patch.failed",
                        format!("username={} code={}", user, error.code),
                    );
                    return Err(error);
                }
            };
            let runtime_cfg = config_rx.borrow().clone();
            data.in_runtime = runtime_cfg.access.users.contains_key(&data.username);
            if let Some(enabled) = enabled_update {
                shared
                    .proxy_shared
                    .set_user_enabled(&data.username, enabled);
                if !enabled {
                    let cancelled = shared.proxy_shared.cancel_user_sessions(&data.username);
                    shared.runtime_events.record(
                        "api.user.disable.runtime",
                        format!(
                            "username={} cancelled_sessions={}",
                            data.username, cancelled
                        ),
                    );
                }
            }
            shared
                .runtime_events
                .record("api.user.patch.ok", format!("username={}", data.username));
            let status = if data.in_runtime {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            return Ok(success_response(status, data, revision));
        }
        if method == Method::DELETE {
            if api_cfg.read_only {
                return Ok(error_response(
                    request_id,
                    ApiFailure::new(
                        StatusCode::FORBIDDEN,
                        "read_only",
                        "API runs in read-only mode",
                    ),
                ));
            }
            let expected_revision = parse_if_match(req.headers());
            let result = delete_user(user, expected_revision, shared).await;
            let (deleted_user, revision) = match result {
                Ok(ok) => ok,
                Err(error) => {
                    shared.runtime_events.record(
                        "api.user.delete.failed",
                        format!("username={} code={}", user, error.code),
                    );
                    return Err(error);
                }
            };
            shared.proxy_shared.set_user_enabled(&deleted_user, true);
            let cancelled = shared.proxy_shared.cancel_user_sessions(&deleted_user);
            shared.runtime_events.record(
                "api.user.delete.ok",
                format!("username={} cancelled_sessions={}", deleted_user, cancelled),
            );
            let runtime_cfg = config_rx.borrow().clone();
            let in_runtime = runtime_cfg.access.users.contains_key(&deleted_user);
            let response = DeleteUserResponse {
                username: deleted_user,
                in_runtime,
            };
            let status = if response.in_runtime {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            return Ok(success_response(status, response, revision));
        }
        if method == Method::POST {
            return Ok(error_response(
                request_id,
                ApiFailure::method_not_allowed(ALLOW_GET_PATCH_DELETE),
            ));
        }
        return Ok(error_response(
            request_id,
            ApiFailure::method_not_allowed(ALLOW_GET_PATCH_DELETE),
        ));
    }
    if let Some(allow) = allowed_methods_for_path(normalized_path) {
        return Ok(error_response(
            request_id,
            ApiFailure::method_not_allowed(allow),
        ));
    }
    debug!(
        method = method.as_str(),
        path = %path,
        normalized_path = %normalized_path,
        "API route not found"
    );
    Ok(error_response(
        request_id,
        ApiFailure::new(StatusCode::NOT_FOUND, "not_found", "Route not found"),
    ))
}
