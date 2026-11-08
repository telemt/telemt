use super::*;

pub(super) async fn create_user_route(
    req: Request<Incoming>,
    shared: &Arc<ApiShared>,
    cfg: &ProxyConfig,
    config_rx: &watch::Receiver<Arc<ProxyConfig>>,
    request_id: u64,
    body_limit: usize,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let api_cfg = &cfg.server.api;
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
    let body = read_json::<CreateUserRequest>(req.into_body(), body_limit).await?;
    let result = create_user(body, expected_revision, shared).await;
    let (mut data, revision) = match result {
        Ok(ok) => ok,
        Err(error) => {
            shared
                .runtime_events
                .record("api.user.create.failed", error.code);
            return Err(error);
        }
    };
    let runtime_cfg = config_rx.borrow().clone();
    users::refresh_runtime_view(&mut data.user, &runtime_cfg);
    shared.runtime_events.record(
        "api.user.create.ok",
        format!("username={}", data.user.username),
    );
    let status = if data.user.in_runtime {
        StatusCode::CREATED
    } else {
        StatusCode::ACCEPTED
    };
    Ok(success_response(status, data, revision))
}

pub(super) async fn get_config_route(
    shared: &Arc<ApiShared>,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let (value, revision) = config_edit::read_managed_config(&shared.config_path).await?;
    Ok(success_response(StatusCode::OK, value, revision))
}

pub(super) async fn reload_route(
    req: Request<Incoming>,
    shared: &Arc<ApiShared>,
    cfg: &ProxyConfig,
    request_id: u64,
    body_limit: usize,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let api_cfg = &cfg.server.api;
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
    let request = read_optional_json::<ReloadRequest>(req.into_body(), body_limit)
        .await?
        .unwrap_or_default();
    request.validate().map_err(ApiFailure::bad_request)?;

    let (accepted, revision) = submit_reload_from_disk(
        &shared.config_path,
        shared.mutation_lock.as_ref(),
        &shared.reload_control,
        expected_revision.as_deref(),
        request,
    )
    .await?;
    Ok(success_response(StatusCode::ACCEPTED, accepted, revision))
}

pub(super) async fn patch_config_route(
    req: Request<Incoming>,
    shared: &Arc<ApiShared>,
    cfg: &ProxyConfig,
    query: Option<&str>,
    request_id: u64,
    body_limit: usize,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let api_cfg = &cfg.server.api;
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
    let expected_runtime = config_edit::parse_runtime_match(req.headers())?;
    let reload_request = ReloadRequest::from_query(query).map_err(ApiFailure::bad_request)?;
    let body = read_json::<serde_json::Value>(req.into_body(), body_limit).await?;
    match config_edit::patch_config(
        body,
        expected_revision,
        expected_runtime,
        reload_request,
        shared,
    )
    .await
    {
        Ok(resp) => {
            let revision = resp.revision.clone();
            let status = if resp.reload.is_some() {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            Ok(success_response(status, resp, revision))
        }
        Err(error) => {
            shared
                .runtime_events
                .record("api.config.patch.failed", error.code);
            Err(error)
        }
    }
}

pub(super) async fn validate_config_route(
    req: Request<Incoming>,
    shared: &Arc<ApiShared>,
    query: Option<&str>,
    body_limit: usize,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let expected_revision = parse_if_match(req.headers());
    let expected_runtime = config_edit::parse_runtime_match(req.headers())?;
    let reload_request = ReloadRequest::from_query(query).map_err(ApiFailure::bad_request)?;
    let body = read_json::<serde_json::Value>(req.into_body(), body_limit).await?;
    let response = config_edit::validate_config(
        body,
        expected_revision,
        expected_runtime,
        reload_request,
        shared,
    )
    .await?;
    let revision = response.base_revision.clone();
    Ok(success_response(StatusCode::OK, response, revision))
}
