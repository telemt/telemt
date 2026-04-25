#![allow(clippy::too_many_arguments)]

use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::AUTHORIZATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, watch};
use tracing::{debug, info, warn};

use crate::config::{ApiGrayAction, ProxyConfig};
use crate::ip_tracker::UserIpTracker;
use crate::proxy::route_mode::RouteRuntimeController;
use crate::startup::StartupTracker;
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

mod config_store;
mod events;
mod http_utils;
mod model;
mod patch;
mod runtime_edge;
mod runtime_init;
mod runtime_min;
mod runtime_selftest;
mod runtime_stats;
mod runtime_watch;
mod runtime_zero;
mod users;

use config_store::{current_revision, load_config_from_disk, parse_if_match};
use events::ApiEventStore;
use http_utils::{error_response, read_json, read_optional_json, success_response};
use model::{
    ApiFailure, ClassCount, CreateUserRequest, DeleteUserResponse, HealthData, HealthReadyData,
    PatchUserRequest, RotateSecretRequest, SummaryData, UserActiveIps,
};
use runtime_edge::{
    EdgeConnectionsCacheEntry, build_runtime_connections_summary_data,
    build_runtime_events_recent_data,
};
use runtime_init::build_runtime_initialization_data;
use runtime_min::{
    build_runtime_me_pool_state_data, build_runtime_me_quality_data, build_runtime_nat_stun_data,
    build_runtime_upstream_quality_data, build_security_whitelist_data,
};
use runtime_selftest::build_runtime_me_selftest_data;
use runtime_stats::{
    MinimalCacheEntry, build_dcs_data, build_me_writers_data, build_minimal_all_data,
    build_upstreams_data, build_zero_all_data,
};
use runtime_watch::spawn_runtime_watchers;
use runtime_zero::{
    build_limits_effective_data, build_runtime_gates_data, build_security_posture_data,
    build_system_info_data,
};
use users::{create_user, delete_user, patch_user, rotate_secret, users_from_config};

pub(super) struct ApiRuntimeState {
    pub(super) process_started_at_epoch_secs: u64,
    pub(super) config_reload_count: AtomicU64,
    pub(super) last_config_reload_epoch_secs: AtomicU64,
    pub(super) admission_open: AtomicBool,
}

#[derive(Clone)]
pub(super) struct ApiShared {
    pub(super) stats: Arc<Stats>,
    pub(super) ip_tracker: Arc<UserIpTracker>,
    pub(super) me_pool: Arc<RwLock<Option<Arc<MePool>>>>,
    pub(super) upstream_manager: Arc<UpstreamManager>,
    pub(super) config_path: PathBuf,
    pub(super) detected_ips_rx: watch::Receiver<(Option<IpAddr>, Option<IpAddr>)>,
    pub(super) mutation_lock: Arc<Mutex<()>>,
    pub(super) minimal_cache: Arc<Mutex<Option<MinimalCacheEntry>>>,
    pub(super) runtime_edge_connections_cache: Arc<Mutex<Option<EdgeConnectionsCacheEntry>>>,
    pub(super) runtime_edge_recompute_lock: Arc<Mutex<()>>,
    pub(super) runtime_events: Arc<ApiEventStore>,
    pub(super) request_id: Arc<AtomicU64>,
    pub(super) runtime_state: Arc<ApiRuntimeState>,
    pub(super) startup_tracker: Arc<StartupTracker>,
    pub(super) route_runtime: Arc<RouteRuntimeController>,
}

impl ApiShared {
    fn next_request_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn detected_link_ips(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        *self.detected_ips_rx.borrow()
    }
}

pub async fn serve(
    listen: SocketAddr,
    stats: Arc<Stats>,
    ip_tracker: Arc<UserIpTracker>,
    me_pool: Arc<RwLock<Option<Arc<MePool>>>>,
    route_runtime: Arc<RouteRuntimeController>,
    upstream_manager: Arc<UpstreamManager>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    admission_rx: watch::Receiver<bool>,
    config_path: PathBuf,
    detected_ips_rx: watch::Receiver<(Option<IpAddr>, Option<IpAddr>)>,
    process_started_at_epoch_secs: u64,
    startup_tracker: Arc<StartupTracker>,
) {
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => {
            warn!(
                error = %error,
                listen = %listen,
                "Failed to bind API listener"
            );
            return;
        }
    };

    info!("API endpoint: http://{}/v1/*", listen);

    let runtime_state = Arc::new(ApiRuntimeState {
        process_started_at_epoch_secs,
        config_reload_count: AtomicU64::new(0),
        last_config_reload_epoch_secs: AtomicU64::new(0),
        admission_open: AtomicBool::new(*admission_rx.borrow()),
    });

    let shared = Arc::new(ApiShared {
        stats,
        ip_tracker,
        me_pool,
        upstream_manager,
        config_path,
        detected_ips_rx,
        mutation_lock: Arc::new(Mutex::new(())),
        minimal_cache: Arc::new(Mutex::new(None)),
        runtime_edge_connections_cache: Arc::new(Mutex::new(None)),
        runtime_edge_recompute_lock: Arc::new(Mutex::new(())),
        runtime_events: Arc::new(ApiEventStore::new(
            config_rx.borrow().server.api.runtime_edge_events_capacity,
        )),
        request_id: Arc::new(AtomicU64::new(1)),
        runtime_state: runtime_state.clone(),
        startup_tracker,
        route_runtime,
    });

    spawn_runtime_watchers(
        config_rx.clone(),
        admission_rx.clone(),
        runtime_state.clone(),
        shared.runtime_events.clone(),
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(error) => {
                warn!(error = %error, "API accept error");
                continue;
            }
        };

        let shared_conn = shared.clone();
        let config_rx_conn = config_rx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let shared_req = shared_conn.clone();
                let config_rx_req = config_rx_conn.clone();
                async move { handle(req, peer, shared_req, config_rx_req).await }
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await
            {
                if !error.is_user() {
                    debug!(error = %error, "API connection error");
                }
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    shared: Arc<ApiShared>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
) -> Result<Response<Full<Bytes>>, IoError> {
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
            .map(|v| v == api_cfg.auth_header)
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

    let result: Result<Response<Full<Bytes>>, ApiFailure> = async {
        match (method.as_str(), normalized_path) {
            ("GET", "/v1/health") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = HealthData {
                    status: "ok",
                    read_only: api_cfg.read_only,
                };
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/health/ready") => {
                let revision = current_revision(&shared.config_path).await?;
                let admission_open = shared.runtime_state.admission_open.load(Ordering::Relaxed);
                let upstream_health = shared.upstream_manager.api_health_summary().await;
                let ready = admission_open && upstream_health.healthy_total > 0;
                let reason = if ready {
                    None
                } else if !admission_open {
                    Some("admission_closed")
                } else {
                    Some("no_healthy_upstreams")
                };
                let data = HealthReadyData {
                    ready,
                    status: if ready { "ready" } else { "not_ready" },
                    reason,
                    admission_open,
                    healthy_upstreams: upstream_health.healthy_total,
                    total_upstreams: upstream_health.configured_total,
                };
                let status_code = if ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                Ok(success_response(status_code, data, revision))
            }
            ("GET", "/v1/system/info") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_system_info_data(shared.as_ref(), cfg.as_ref(), &revision);
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/gates") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_gates_data(shared.as_ref(), cfg.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/initialization") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_initialization_data(shared.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/limits/effective") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_limits_effective_data(cfg.as_ref());
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/security/posture") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_security_posture_data(cfg.as_ref());
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/security/whitelist") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_security_whitelist_data(cfg.as_ref());
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/summary") => {
                let revision = current_revision(&shared.config_path).await?;
                let connections_bad_by_class = shared
                    .stats
                    .get_connects_bad_class_counts()
                    .into_iter()
                    .map(|(class, total)| ClassCount { class, total })
                    .collect();
                let handshake_failures_by_class = shared
                    .stats
                    .get_handshake_failure_class_counts()
                    .into_iter()
                    .map(|(class, total)| ClassCount { class, total })
                    .collect();
                let data = SummaryData {
                    uptime_seconds: shared.stats.uptime_secs(),
                    connections_total: shared.stats.get_connects_all(),
                    connections_bad_total: shared.stats.get_connects_bad(),
                    connections_bad_by_class,
                    handshake_failures_by_class,
                    handshake_timeouts_total: shared.stats.get_handshake_timeouts(),
                    configured_users: cfg.access.users.len(),
                };
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/zero/all") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_zero_all_data(&shared.stats, cfg.access.users.len());
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/upstreams") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_upstreams_data(shared.as_ref(), api_cfg);
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/minimal/all") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_minimal_all_data(shared.as_ref(), api_cfg).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/me-writers") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_me_writers_data(shared.as_ref(), api_cfg).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/dcs") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_dcs_data(shared.as_ref(), api_cfg).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/me_pool_state") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_me_pool_state_data(shared.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/me_quality") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_me_quality_data(shared.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/upstream_quality") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_upstream_quality_data(shared.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/nat_stun") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_nat_stun_data(shared.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/me-selftest") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_me_selftest_data(shared.as_ref(), cfg.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/connections/summary") => {
                let revision = current_revision(&shared.config_path).await?;
                let data =
                    build_runtime_connections_summary_data(shared.as_ref(), cfg.as_ref()).await;
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/runtime/events/recent") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = build_runtime_events_recent_data(
                    shared.as_ref(),
                    cfg.as_ref(),
                    query.as_deref(),
                );
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/users/active-ips") => {
                let revision = current_revision(&shared.config_path).await?;
                let usernames: Vec<_> = cfg.access.users.keys().cloned().collect();
                let active_ips_map = shared.ip_tracker.get_active_ips_for_users(&usernames).await;
                let mut data: Vec<UserActiveIps> = active_ips_map
                    .into_iter()
                    .filter(|(_, ips)| !ips.is_empty())
                    .map(|(username, active_ips)| UserActiveIps {
                        username,
                        active_ips,
                    })
                    .collect();
                data.sort_by(|a, b| a.username.cmp(&b.username));
                Ok(success_response(StatusCode::OK, data, revision))
            }
            ("GET", "/v1/stats/users") | ("GET", "/v1/users") => {
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
                Ok(success_response(StatusCode::OK, users, revision))
            }
            ("POST", "/v1/users") => {
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
                let result = create_user(body, expected_revision, &shared).await;
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
                data.user.in_runtime = runtime_cfg.access.users.contains_key(&data.user.username);
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
            _ => {
                if let Some(user) = normalized_path.strip_prefix("/v1/users/")
                    && !user.is_empty()
                    && !user.contains('/')
                {
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
                        if let Some(user_info) =
                            users.into_iter().find(|entry| entry.username == user)
                        {
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
                        let body =
                            read_json::<PatchUserRequest>(req.into_body(), body_limit).await?;
                        let result = patch_user(user, body, expected_revision, &shared).await;
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
                        let result = delete_user(user, expected_revision, &shared).await;
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
                        shared
                            .runtime_events
                            .record("api.user.delete.ok", format!("username={}", deleted_user));
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
                    if method == Method::POST
                        && let Some(base_user) = user.strip_suffix("/rotate-secret")
                        && !base_user.is_empty()
                        && !base_user.contains('/')
                    {
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
                        let body =
                            read_optional_json::<RotateSecretRequest>(req.into_body(), body_limit)
                                .await?;
                        let result = rotate_secret(
                            base_user,
                            body.unwrap_or_default(),
                            expected_revision,
                            &shared,
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
                        data.user.in_runtime =
                            runtime_cfg.access.users.contains_key(&data.user.username);
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
                    if method == Method::POST {
                        return Ok(error_response(
                            request_id,
                            ApiFailure::new(StatusCode::NOT_FOUND, "not_found", "Route not found"),
                        ));
                    }
                    return Ok(error_response(
                        request_id,
                        ApiFailure::new(
                            StatusCode::METHOD_NOT_ALLOWED,
                            "method_not_allowed",
                            "Unsupported HTTP method for this route",
                        ),
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
        }
    }
    .await;

    match result {
        Ok(resp) => Ok(resp),
        Err(error) => Ok(error_response(request_id, error)),
    }
}
