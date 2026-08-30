use super::*;

// Read-only fixed API endpoints.
mod read_routes;
// Fixed configuration and lifecycle mutations.
mod fixed_routes;
// Dynamic reload and user-resource routes.
mod user_routes;

pub(super) async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    shared: Arc<ApiShared>,
) -> Result<Response<Full<Bytes>>, IoError> {
    let runtime = shared.active_runtime.load_full();
    let previous_cache_generation = shared.cache_generation.swap(runtime.id, Ordering::AcqRel);
    if previous_cache_generation != runtime.id {
        *shared.minimal_cache.lock().await = None;
        *shared.runtime_edge_connections_cache.lock().await = None;
    }
    let shared = Arc::new(shared.for_runtime(runtime.as_ref()));
    let config_rx = runtime.config_rx.clone();
    shared
        .runtime_state
        .admission_open
        .store(*runtime.admission_rx.borrow(), Ordering::Relaxed);
    let request_id = shared.next_request_id();
    let cfg = config_rx.borrow().clone();
    let api_cfg = &cfg.server.api;

    if !api_cfg.enabled {
        return Ok(error_response(
            request_id,
            ApiFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "api_disabled",
                "API is disabled",
            ),
        ));
    }

    if !api_cfg.whitelist.is_empty() && !api_cfg.whitelist.iter().any(|net| net.contains(peer.ip()))
    {
        return match api_cfg.gray_action {
            ApiGrayAction::Api => Ok(error_response(
                request_id,
                ApiFailure::new(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "Source IP is not allowed",
                ),
            )),
            ApiGrayAction::Ok200 => Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::new()))
                .unwrap()),
            ApiGrayAction::Drop => Err(IoError::new(
                ErrorKind::ConnectionAborted,
                "api request dropped by gray_action=drop",
            )),
        };
    }

    if !api_cfg.auth_header.is_empty() {
        let auth_ok = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| auth_header_matches(v, &api_cfg.auth_header))
            .unwrap_or(false);
        if !auth_ok {
            return Ok(error_response(
                request_id,
                ApiFailure::new(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Missing or invalid Authorization header",
                ),
            ));
        }
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let normalized_path = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path.as_str()
    };
    let query = req.uri().query().map(str::to_string);
    let body_limit = api_cfg.request_body_limit_bytes;

    let result = dispatch(
        req,
        method,
        &path,
        normalized_path,
        query.as_deref(),
        body_limit,
        &shared,
        cfg.as_ref(),
        &config_rx,
        request_id,
    )
    .await;
    match result {
        Ok(resp) => Ok(resp),
        Err(error) => Ok(error_response(request_id, error)),
    }
}

async fn dispatch(
    req: Request<Incoming>,
    method: Method,
    path: &str,
    normalized_path: &str,
    query: Option<&str>,
    body_limit: usize,
    shared: &Arc<ApiShared>,
    cfg: &ProxyConfig,
    config_rx: &watch::Receiver<Arc<ProxyConfig>>,
    request_id: u64,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    if web_runtime::is_route(normalized_path) {
        let web_mutation = method == Method::POST;
        let result = web_runtime::handle(
            method,
            normalized_path,
            query,
            req,
            shared.as_ref(),
            cfg,
            request_id,
            body_limit,
        )
        .await;
        if web_mutation && let Err(error) = &result {
            shared.runtime_events.record(
                "api.web.control.failed",
                format!("path={} code={}", normalized_path, error.code),
            );
        }
        return result;
    }

    if let Some(response) = read_routes::handle(
        &method,
        normalized_path,
        query,
        shared.as_ref(),
        cfg,
        config_rx,
    )
    .await?
    {
        return Ok(response);
    }

    match (method.as_str(), normalized_path) {
        ("POST", "/v1/users") => {
            fixed_routes::create_user_route(req, shared, cfg, config_rx, request_id, body_limit)
                .await
        }
        ("GET", "/v1/config") => fixed_routes::get_config_route(shared).await,
        ("POST", "/v1/system/reload") => {
            fixed_routes::reload_route(req, shared, cfg, request_id, body_limit).await
        }
        ("PATCH", "/v1/config") => {
            fixed_routes::patch_config_route(req, shared, cfg, query, request_id, body_limit).await
        }
        _ => {
            user_routes::handle(
                req,
                &method,
                path,
                normalized_path,
                shared,
                cfg,
                config_rx,
                request_id,
                body_limit,
            )
            .await
        }
    }
}
