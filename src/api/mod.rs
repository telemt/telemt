#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::AUTHORIZATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, Semaphore, watch};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{ApiGrayAction, ProxyConfig};
use crate::ip_tracker::UserIpTracker;
use crate::maestro::control_plane::ProcessControlPlane;
use crate::maestro::generation::{RuntimeGeneration, RuntimeWatchState};
use crate::maestro::reload::{ReloadAccepted, ReloadControl, ReloadRequest, ReloadSubmitError};
use crate::proxy::route_mode::RouteRuntimeController;
use crate::proxy::shared_state::ProxySharedState;
use crate::quota_state::QuotaStateOwner;
use crate::startup::StartupTracker;
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;
use crate::web::control::WebRuntimePublication;
use crate::web::trace::WebTraceStore;

mod config_edit;
pub(crate) mod config_store;
mod events;
mod http_utils;
// Authenticated request admission and route dispatch.
mod handler;
mod model;
mod patch;
#[cfg(test)]
mod reload_tests;
mod runtime_edge;
mod runtime_init;
mod runtime_min;
mod runtime_selftest;
mod runtime_stats;
mod runtime_watch;
mod runtime_zero;
mod users;
// WEB runtime status and bounded controls remain separate from general API DTOs.
mod web_runtime;
mod web_status;

use config_store::{
    current_revision, ensure_expected_revision, load_config_for_reload, load_config_from_disk,
    parse_if_match,
};
use events::ApiEventStore;
use handler::handle;
use http_utils::{error_response, read_json, read_optional_json, success_response};
use model::{
    ApiFailure, ClassCount, CreateUserRequest, DeleteUserResponse, HealthData, HealthReadyData,
    PatchUserRequest, ResetUserQuotaResponse, RotateSecretRequest, SummaryData, UserActiveIps,
    is_valid_username,
};
use patch::Patch;
use runtime_edge::{
    EdgeConnectionsCacheEntry, build_runtime_connections_summary_data,
    build_runtime_events_recent_data, build_runtime_tls_fingerprints_data,
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
use users::{
    build_user_quota_list, create_user, delete_user, patch_user, rotate_secret, set_user_enabled,
    users_from_config,
};

const API_MAX_CONTROL_CONNECTIONS: usize = 1024;
const API_HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const ROUTE_USERNAME_ERROR: &str = "username must match [A-Za-z0-9_.-] and be 1..64 chars";
const ALLOW_GET: &str = "GET";
const ALLOW_POST: &str = "POST";
const ALLOW_GET_POST: &str = "GET, POST";
const ALLOW_GET_PATCH_DELETE: &str = "GET, PATCH, DELETE";
const ALLOW_GET_PATCH: &str = "GET, PATCH";

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
    pub(super) quota_state: Arc<QuotaStateOwner>,
    pub(super) detected_ips_rx: watch::Receiver<(Option<IpAddr>, Option<IpAddr>)>,
    pub(super) mutation_lock: Arc<Mutex<()>>,
    pub(super) minimal_cache: Arc<Mutex<Option<MinimalCacheEntry>>>,
    pub(super) runtime_edge_connections_cache: Arc<Mutex<Option<EdgeConnectionsCacheEntry>>>,
    pub(super) runtime_edge_recompute_lock: Arc<Mutex<()>>,
    pub(super) cache_generation: Arc<AtomicU64>,
    pub(super) runtime_events: Arc<ApiEventStore>,
    pub(super) request_id: Arc<AtomicU64>,
    pub(super) runtime_state: Arc<ApiRuntimeState>,
    pub(super) startup_tracker: Arc<StartupTracker>,
    pub(super) route_runtime: Arc<RouteRuntimeController>,
    pub(super) proxy_shared: Arc<ProxySharedState>,
    pub(super) reload_control: ReloadControl,
    pub(super) active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    pub(super) web_trace: Arc<WebTraceStore>,
    pub(super) web_runtime_rx: watch::Receiver<WebRuntimePublication>,
}

impl ApiShared {
    fn next_request_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn detected_link_ips(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        *self.detected_ips_rx.borrow()
    }

    fn for_runtime(&self, runtime: &RuntimeGeneration) -> Self {
        Self {
            stats: runtime.stats.clone(),
            ip_tracker: runtime.ip_tracker.clone(),
            me_pool: runtime.me_pool_runtime.clone(),
            upstream_manager: runtime.upstream_manager.clone(),
            config_path: self.config_path.clone(),
            quota_state: self.quota_state.clone(),
            detected_ips_rx: self.detected_ips_rx.clone(),
            mutation_lock: self.mutation_lock.clone(),
            minimal_cache: self.minimal_cache.clone(),
            runtime_edge_connections_cache: self.runtime_edge_connections_cache.clone(),
            runtime_edge_recompute_lock: self.runtime_edge_recompute_lock.clone(),
            cache_generation: self.cache_generation.clone(),
            runtime_events: self.runtime_events.clone(),
            request_id: self.request_id.clone(),
            runtime_state: self.runtime_state.clone(),
            startup_tracker: self.startup_tracker.clone(),
            route_runtime: runtime.route_runtime.clone(),
            proxy_shared: runtime.proxy_shared.clone(),
            reload_control: self.reload_control.clone(),
            active_runtime: self.active_runtime.clone(),
            web_trace: self.web_trace.clone(),
            web_runtime_rx: self.web_runtime_rx.clone(),
        }
    }
}

fn auth_header_matches(actual: &str, expected: &str) -> bool {
    actual.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn parse_route_username(user: &str) -> Result<&str, ApiFailure> {
    if is_valid_username(user) {
        Ok(user)
    } else {
        Err(ApiFailure::bad_request(ROUTE_USERNAME_ERROR))
    }
}

fn user_action_route_matches(path: &str, suffix: &str) -> bool {
    path.strip_prefix("/v1/users/")
        .and_then(|path| path.strip_suffix(suffix))
        .map(|user| !user.is_empty() && !user.contains('/'))
        .unwrap_or(false)
}

fn reload_status_route_id(path: &str) -> Option<u64> {
    path.strip_prefix("/v1/system/reload/")
        .filter(|id| !id.is_empty() && !id.contains('/'))
        .and_then(|id| id.parse().ok())
}

async fn submit_reload_from_disk(
    config_path: &std::path::Path,
    mutation_lock: &Mutex<()>,
    reload_control: &ReloadControl,
    expected_revision: Option<&str>,
    request: ReloadRequest,
) -> Result<(ReloadAccepted, String), ApiFailure> {
    let _guard = mutation_lock.lock().await;
    let (config, revision) = load_config_for_reload(config_path).await?;
    if expected_revision.is_some_and(|expected| expected != revision) {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "revision_conflict",
            "Config revision mismatch",
        ));
    }
    let config = Arc::new(config);
    let accepted = reload_control
        .submit(config, revision.clone(), request)
        .await
        .map_err(|error| match error {
            ReloadSubmitError::InProgress(reload_id) => ApiFailure::new(
                StatusCode::CONFLICT,
                "reload_in_progress",
                format!("Reload {} is already in progress", reload_id),
            ),
            ReloadSubmitError::MaestroUnavailable => ApiFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "maestro_unavailable",
                "Maestro reload coordinator is unavailable",
            ),
        })?;
    Ok((accepted, revision))
}

fn allowed_methods_for_path(path: &str) -> Option<&'static str> {
    if let Some(allow) = web_runtime::allowed_methods(path) {
        return Some(allow);
    }
    match path {
        "/v1/health"
        | "/v1/health/ready"
        | "/v1/system/info"
        | "/v1/runtime/gates"
        | "/v1/runtime/initialization"
        | "/v1/limits/effective"
        | "/v1/security/posture"
        | "/v1/security/whitelist"
        | "/v1/stats/summary"
        | "/v1/stats/zero/all"
        | "/v1/stats/upstreams"
        | "/v1/stats/minimal/all"
        | "/v1/stats/me-writers"
        | "/v1/stats/dcs"
        | "/v1/runtime/me-pool-state"
        | "/v1/runtime/me_pool_state"
        | "/v1/runtime/me-quality"
        | "/v1/runtime/me_quality"
        | "/v1/runtime/upstream-quality"
        | "/v1/runtime/upstream_quality"
        | "/v1/runtime/nat-stun"
        | "/v1/runtime/nat_stun"
        | "/v1/runtime/me-selftest"
        | "/v1/runtime/connections/summary"
        | "/v1/runtime/events/recent"
        | "/v1/runtime/tls-fingerprints"
        | "/v1/stats/users/active-ips"
        | "/v1/stats/users/quota"
        | "/v1/stats/users"
        | "/web-status" => Some(ALLOW_GET),
        "/v1/system/reload" => Some(ALLOW_POST),
        "/v1/users" => Some(ALLOW_GET_POST),
        "/v1/config" => Some(ALLOW_GET_PATCH),
        _ if user_action_route_matches(path, "/reset-quota") => Some(ALLOW_POST),
        _ if user_action_route_matches(path, "/rotate-secret") => Some(ALLOW_POST),
        _ if user_action_route_matches(path, "/enable") => Some(ALLOW_POST),
        _ if user_action_route_matches(path, "/disable") => Some(ALLOW_POST),
        _ if reload_status_route_id(path).is_some() => Some(ALLOW_GET),
        _ if path
            .strip_prefix("/v1/users/")
            .map(|user| !user.is_empty() && !user.contains('/'))
            .unwrap_or(false) =>
        {
            Some(ALLOW_GET_PATCH_DELETE)
        }
        _ => None,
    }
}

/// Serves the API on a process-owned listener and task scope.
pub(crate) async fn serve(
    listener: TcpListener,
    stats: Arc<Stats>,
    ip_tracker: Arc<UserIpTracker>,
    me_pool: Arc<RwLock<Option<Arc<MePool>>>>,
    route_runtime: Arc<RouteRuntimeController>,
    proxy_shared: Arc<ProxySharedState>,
    upstream_manager: Arc<UpstreamManager>,
    config_path: PathBuf,
    quota_state: Arc<QuotaStateOwner>,
    detected_ips_rx: watch::Receiver<(Option<IpAddr>, Option<IpAddr>)>,
    process_started_at_epoch_secs: u64,
    startup_tracker: Arc<StartupTracker>,
    reload_control: ReloadControl,
    mut active_runtime_rx: watch::Receiver<Option<Arc<ArcSwap<RuntimeGeneration>>>>,
    mut runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
    web_trace: Arc<WebTraceStore>,
    web_runtime_rx: watch::Receiver<WebRuntimePublication>,
    control_plane: ProcessControlPlane,
) {
    let active_runtime = loop {
        if let Some(active_runtime) = active_runtime_rx.borrow().clone() {
            break active_runtime;
        }
        if active_runtime_rx.changed().await.is_err() {
            warn!("Runtime generation channel closed before API bootstrap");
            return;
        }
    };
    let initial_watch_state = loop {
        if let Some(watch_state) = runtime_watch_rx.borrow().clone() {
            break watch_state;
        }
        if runtime_watch_rx.changed().await.is_err() {
            warn!("Runtime watch channel closed before API bootstrap");
            return;
        }
    };
    let config_rx = initial_watch_state.config_rx.clone();
    let admission_rx = initial_watch_state.admission_rx.clone();
    let listen = listener.local_addr().ok();

    info!(listen = ?listen, "API endpoint ready at /v1/* and /web-status");

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
        quota_state,
        detected_ips_rx,
        mutation_lock: Arc::new(Mutex::new(())),
        minimal_cache: Arc::new(Mutex::new(None)),
        runtime_edge_connections_cache: Arc::new(Mutex::new(None)),
        runtime_edge_recompute_lock: Arc::new(Mutex::new(())),
        cache_generation: Arc::new(AtomicU64::new(1)),
        runtime_events: Arc::new(ApiEventStore::new(
            config_rx.borrow().server.api.runtime_edge_events_capacity,
        )),
        request_id: Arc::new(AtomicU64::new(1)),
        runtime_state: runtime_state.clone(),
        startup_tracker,
        route_runtime,
        proxy_shared,
        reload_control,
        active_runtime,
        web_trace,
        web_runtime_rx,
    });

    spawn_runtime_watchers(
        runtime_watch_rx,
        runtime_state.clone(),
        shared.runtime_events.clone(),
        &control_plane,
    );

    let connection_permits = Arc::new(Semaphore::new(API_MAX_CONTROL_CONNECTIONS));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(error) => {
                warn!(error = %error, "API accept error");
                continue;
            }
        };

        let connection_permit = match connection_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(
                    peer = %peer,
                    max_connections = API_MAX_CONTROL_CONNECTIONS,
                    "Dropping API connection: control-plane connection budget exhausted"
                );
                continue;
            }
        };

        let shared_conn = shared.clone();
        let _ = control_plane.spawn(async move {
            let _connection_permit = connection_permit;
            let svc = service_fn(move |req: Request<Incoming>| {
                let shared_req = shared_conn.clone();
                async move { handle(req, peer, shared_req).await }
            });
            match timeout(
                API_HTTP_CONNECTION_TIMEOUT,
                http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if !error.is_user() {
                        debug!(error = %error, "API connection error");
                    }
                }
                Err(_) => {
                    debug!(
                        peer = %peer,
                        timeout_ms = API_HTTP_CONNECTION_TIMEOUT.as_millis() as u64,
                        "API connection timed out"
                    );
                }
            }
        });
    }
}
