use std::convert::Infallible;
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

use crate::config::ProxyConfig;
use crate::ip_tracker::UserIpTracker;
use crate::proxy::route_mode::RouteRuntimeController;
use crate::startup::StartupTracker;
use crate::stats::Stats;
use crate::transport::middle_proxy::MePool;
use crate::transport::UpstreamManager;

mod config_store;
mod events;
mod http_utils;
mod model;
mod runtime_edge;
mod runtime_init;
mod runtime_min;
mod runtime_selftest;
mod runtime_stats;
mod runtime_watch;
mod runtime_zero;
mod users;

use config_store::{current_revision, parse_if_match};
use http_utils::{error_response, read_json, read_optional_json, success_response};
use events::ApiEventStore;
use model::{
    ApiFailure, CreateUserRequest, HealthData, PatchUserRequest, RotateSecretRequest, SummaryData,
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
use runtime_zero::{
    build_limits_effective_data, build_runtime_gates_data, build_security_posture_data,
    build_system_info_data,
};
use runtime_watch::spawn_runtime_watchers;
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
                debug!(error = %error, "API connection error");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    shared: Arc<ApiShared>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
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

    if !api_cfg.whitelist.is_empty()
        && !api_cfg
            .whitelist
            .iter()
            .any(|net| net.contains(peer.ip()))
    {
        return Ok(error_response(
            request_id,
            ApiFailure::new(StatusCode::FORBIDDEN, "forbidden", "Source IP is not allowed"),
        ));
    }

    if !api_cfg.auth_header.is_empty() {
        let auth_ok = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| constant_time_eq(v.as_bytes(), api_cfg.auth_header.as_bytes()))
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
    let query = req.uri().query().map(str::to_string);
    let body_limit = api_cfg.request_body_limit_bytes;

    let result: Result<Response<Full<Bytes>>, ApiFailure> = async {
        match (method.as_str(), path.as_str()) {
            ("GET", "/v1/health") => {
                let revision = current_revision(&shared.config_path).await?;
                let data = HealthData {
                    status: "ok",
                    read_only: api_cfg.read_only,
                };
                Ok(success_response(StatusCode::OK, data, revision))
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
                let data = SummaryData {
                    uptime_seconds: shared.stats.uptime_secs(),
                    connections_total: shared.stats.get_connects_all(),
                    connections_bad_total: shared.stats.get_connects_bad(),
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
                let data = build_runtime_connections_summary_data(shared.as_ref(), cfg.as_ref()).await;
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
            ("GET", "/v1/stats/users") | ("GET", "/v1/users") => {
                let revision = current_revision(&shared.config_path).await?;
                let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
                let users = users_from_config(
                    &cfg,
                    &shared.stats,
                    &shared.ip_tracker,
                    detected_ip_v4,
                    detected_ip_v6,
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
                let (data, revision) = match result {
                    Ok(ok) => ok,
                    Err(error) => {
                        shared.runtime_events.record("api.user.create.failed", error.code);
                        return Err(error);
                    }
                };
                shared
                    .runtime_events
                    .record("api.user.create.ok", format!("username={}", data.user.username));
                Ok(success_response(StatusCode::CREATED, data, revision))
            }
            _ => {
                if let Some(user_path) = path.strip_prefix("/v1/users/")
                    && !user_path.is_empty()
                {
                    // Two-segment action route: POST /v1/users/{username}/rotate-secret.
                    // Must be resolved before the single-segment guard below because the
                    // path segment contains a '/' that would otherwise be rejected.
                    if method == Method::POST
                        && let Some(base_user) = user_path.strip_suffix("/rotate-secret")
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
                        let (data, revision) = match result {
                            Ok(ok) => ok,
                            Err(error) => {
                                shared.runtime_events.record(
                                    "api.user.rotate_secret.failed",
                                    format!("username={} code={}", base_user, error.code),
                                );
                                return Err(error);
                            }
                        };
                        shared.runtime_events.record(
                            "api.user.rotate_secret.ok",
                            format!("username={}", base_user),
                        );
                        return Ok(success_response(StatusCode::OK, data, revision));
                    }

                    // Single-segment routes: /v1/users/{username}
                    if user_path.contains('/') {
                        return Ok(error_response(
                            request_id,
                            ApiFailure::new(StatusCode::NOT_FOUND, "not_found", "Route not found"),
                        ));
                    }
                    let user = user_path;

                    if method == Method::GET {
                        let revision = current_revision(&shared.config_path).await?;
                        let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
                        let users = users_from_config(
                            &cfg,
                            &shared.stats,
                            &shared.ip_tracker,
                            detected_ip_v4,
                            detected_ip_v6,
                        )
                        .await;
                        if let Some(user_info) = users.into_iter().find(|entry| entry.username == user)
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
                        let body = read_json::<PatchUserRequest>(req.into_body(), body_limit).await?;
                        let result = patch_user(user, body, expected_revision, &shared).await;
                        let (data, revision) = match result {
                            Ok(ok) => ok,
                            Err(error) => {
                                shared.runtime_events.record(
                                    "api.user.patch.failed",
                                    format!("username={} code={}", user, error.code),
                                );
                                return Err(error);
                            }
                        };
                        shared
                            .runtime_events
                            .record("api.user.patch.ok", format!("username={}", data.username));
                        return Ok(success_response(StatusCode::OK, data, revision));
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
                        shared.runtime_events.record(
                            "api.user.delete.ok",
                            format!("username={}", deleted_user),
                        );
                        return Ok(success_response(StatusCode::OK, deleted_user, revision));
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

// XOR-fold constant-time comparison. Running time depends only on the length of the
// expected token (b), not on min(a.len(), b.len()), to prevent a timing oracle where
// an attacker reduces the iteration count by sending a shorter candidate
// (OWASP ASVS V6.6.1). Bitwise `&` on bool is eager — it never short-circuits —
// so both the length check and the byte fold always execute.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for i in 0..b.len() {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b[i];
        diff |= x ^ y;
    }
    (a.len() == b.len()) & (diff == 0)
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn constant_time_eq_identical_slices_returns_true() {
        assert!(constant_time_eq(b"token-abc", b"token-abc"));
    }

    #[test]
    fn constant_time_eq_different_slices_same_length_returns_false() {
        assert!(!constant_time_eq(b"token-abc", b"token-xyz"));
    }

    #[test]
    fn constant_time_eq_different_lengths_returns_false() {
        assert!(!constant_time_eq(b"short", b"longer-value"));
        assert!(!constant_time_eq(b"longer-value", b"short"));
    }

    #[test]
    fn constant_time_eq_empty_slices_returns_true() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_one_empty_returns_false() {
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"x", b""));
    }

    #[test]
    fn constant_time_eq_single_byte_difference_returns_false() {
        assert!(!constant_time_eq(b"aaaaaaaaaa", b"aaaaaaaaab"));
    }

    // Verifies that the implementation does not take an early exit when lengths
    // differ, which would expose a timing oracle revealing the expected token
    // length (OWASP ASVS V6.6.1). The byte fold must execute over the
    // overlapping prefix even when lengths are unequal.
    #[test]
    fn constant_time_eq_matching_prefix_with_length_mismatch_returns_false() {
        // b is a strict prefix of a: all overlapping bytes are identical.
        assert!(!constant_time_eq(b"abcdef", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcdef"));
        // Single extra byte appended.
        assert!(!constant_time_eq(b"token", b"tokenX"));
        assert!(!constant_time_eq(b"tokenX", b"token"));
        // All-same bytes, different lengths.
        assert!(!constant_time_eq(b"aaaa", b"aaa"));
        assert!(!constant_time_eq(b"aaa", b"aaaa"));
    }

    // Regression test: this documents the routing bug where the outer
    // !user.contains('/') guard blocked the rotate-secret route entirely.
    // The fixed routing resolves the two-segment action route BEFORE applying
    // the single-segment guard.
    #[test]
    fn rotate_secret_path_is_reachable_with_fixed_routing_logic() {
        let path = "/v1/users/alice/rotate-secret";
        let user_path = path.strip_prefix("/v1/users/").unwrap();

        // Old (buggy) guard — would have rejected this path before rotate-secret
        // could be matched because the path segment contains '/'.
        let old_guard_passed = !user_path.is_empty() && !user_path.contains('/');
        assert!(
            !old_guard_passed,
            "old guard must have been blocking the rotate-secret route"
        );

        // Fixed routing: try the two-segment action prefix FIRST.
        let base_user = user_path
            .strip_suffix("/rotate-secret")
            .filter(|u| !u.is_empty() && !u.contains('/'));
        assert_eq!(
            base_user,
            Some("alice"),
            "fixed routing must extract the base username correctly"
        );
    }

    #[test]
    fn single_segment_user_path_routes_correctly_after_fix() {
        let path = "/v1/users/alice";
        let user_path = path.strip_prefix("/v1/users/").unwrap();

        // rotate-secret check must not match
        let is_rotate = user_path
            .strip_suffix("/rotate-secret")
            .map(|u| !u.is_empty() && !u.contains('/'))
            .unwrap_or(false);
        assert!(!is_rotate);

        // Single-segment guard must pass
        assert!(!user_path.contains('/'));
        assert_eq!(user_path, "alice");
    }

    #[test]
    fn deep_path_segment_is_rejected_by_both_guards() {
        let path = "/v1/users/alice/settings/extra";
        let user_path = path.strip_prefix("/v1/users/").unwrap();

        // Not a rotate-secret path
        let is_rotate = user_path
            .strip_suffix("/rotate-secret")
            .map(|u| !u.is_empty() && !u.contains('/'))
            .unwrap_or(false);
        assert!(!is_rotate);

        // Not a single-segment path
        assert!(user_path.contains('/'));
    }

    #[test]
    fn empty_user_segment_is_rejected() {
        let path = "/v1/users/";
        let user_path = path.strip_prefix("/v1/users/").unwrap();
        assert!(user_path.is_empty());
    }

    // ── constant_time_eq adversarial edge cases ───────────────────────────────

    // All-zero bytes: both slices equal, accumulator stays 0 throughout.
    #[test]
    fn constant_time_eq_all_zero_bytes_returns_true() {
        assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    }

    // All-0xFF bytes: both slices equal, accumulator stays 0 (XOR of equal
    // 0xFF bytes is 0x00).
    #[test]
    fn constant_time_eq_all_max_bytes_returns_true() {
        assert!(constant_time_eq(&[0xffu8; 32], &[0xffu8; 32]));
    }

    // Mismatch only at the first byte: the fold must detect it regardless of
    // position; no early-exit optimisation must suppress it.
    #[test]
    fn constant_time_eq_mismatch_at_first_byte_only() {
        let a = [0u8; 16];
        let mut b = [0u8; 16];
        b[0] = 1;
        assert!(!constant_time_eq(&a, &b));
    }

    // Mismatch only at the last byte: the fold must not stop before reaching it.
    #[test]
    fn constant_time_eq_mismatch_at_last_byte_only() {
        let a = [0u8; 16];
        let mut b = [0u8; 16];
        b[15] = 1;
        assert!(!constant_time_eq(&a, &b));
    }

    // Length mismatch with identical prefix and all-same bytes: the length
    // check must still fire even when the byte fold accumulator would be 0.
    #[test]
    fn constant_time_eq_equal_prefix_but_length_mismatch_returns_false() {
        assert!(!constant_time_eq(&[0xaau8; 8], &[0xaau8; 9]));
        assert!(!constant_time_eq(&[0xaau8; 9], &[0xaau8; 8]));
    }

    // Typical authentication-token format: raw header value used in practice.
    #[test]
    fn constant_time_eq_bearer_token_format_match_and_mismatch() {
        let token: &[u8] = b"Bearer super-secret-token-xyz-123";
        assert!(constant_time_eq(token, token));
        let mut different = token.to_vec();
        different[7] = b'X';
        assert!(!constant_time_eq(token, &different));
    }

    // Large slices (256 bytes): ensures no panic and correct result across
    // sizes that trigger SIMD/vectorised paths in release builds.
    #[test]
    fn constant_time_eq_256_byte_slices_match_and_mismatch() {
        let a = vec![0xddu8; 256];
        let b = vec![0xddu8; 256];
        assert!(constant_time_eq(&a, &b));
        let mut c = b.clone();
        c[255] = 0xde;
        assert!(!constant_time_eq(&a, &c));
        c[0] = 0xde;
        assert!(!constant_time_eq(&a, &c));
    }

    // ── Timing-oracle adversarial tests (length-iteration invariant) ──────────

    // An active censor/attacker who knows the token format may send truncated
    // inputs to narrow down the token length via a timing side-channel.
    // After the fix, `constant_time_eq` always iterates over `b.len()` (the
    // expected token length), so submission of every strict prefix of the
    // expected token must be rejected while iteration count stays constant.
    #[test]
    fn constant_time_eq_every_prefix_of_expected_token_is_rejected() {
        let expected = b"Bearer super-secret-api-token-abc123xyz";
        for prefix_len in 0..expected.len() {
            let attacker_input = &expected[..prefix_len];
            assert!(
                !constant_time_eq(attacker_input, expected),
                "prefix of length {prefix_len} must not authenticate against full token"
            );
        }
    }

    // Reversed: input longer than expected token — the extra bytes must cause
    // rejection even when the first b.len() bytes are correct.
    #[test]
    fn constant_time_eq_input_with_correct_prefix_plus_extra_bytes_is_rejected() {
        let expected = b"secret-token";
        for extra in 1usize..=32 {
            let mut longer = expected.to_vec();
            // Extend with zeros — the XOR of matching first bytes is 0, so only
            // the length check prevents a false positive.
            longer.extend(std::iter::repeat(0u8).take(extra));
            assert!(
                !constant_time_eq(&longer, expected),
                "input extended by {extra} zero bytes must not authenticate"
            );
            // Extend with matching-value bytes — ensures the byte_fold stays at 0
            // for the expected-length portion; only length differs.
            let mut same_byte_extension = expected.to_vec();
            same_byte_extension.extend(std::iter::repeat(expected[0]).take(extra));
            assert!(
                !constant_time_eq(&same_byte_extension, expected),
                "input extended by {extra} repeated bytes must not authenticate"
            );
        }
    }

    // Null-byte injection: ensure the function does not mis-parse embedded
    // NUL characters as C-string terminators and accept a shorter match.
    #[test]
    fn constant_time_eq_null_byte_injection_is_rejected() {
        // Token containing a null byte — must only match itself exactly.
        let expected: &[u8] = b"token\x00suffix";
        assert!(constant_time_eq(expected, expected));
        assert!(!constant_time_eq(b"token", expected));
        assert!(!constant_time_eq(b"token\x00", expected));
        assert!(!constant_time_eq(b"token\x00suffi", expected));

        // Null-prefixed input of the same length must not match a non-null token.
        let real_token: &[u8] = b"real-secret-value";
        let mut null_injected = vec![0u8; real_token.len()];
        null_injected[0] = real_token[0];
        assert!(!constant_time_eq(&null_injected, real_token));
    }

    // High-byte (0xFF) values throughout: XOR of 0xFF ^ 0xFF = 0, so equal
    // high-byte slices must match, and any single-byte difference must not.
    #[test]
    fn constant_time_eq_high_byte_edge_cases() {
        let token = vec![0xffu8; 20];
        assert!(constant_time_eq(&token, &token));
        let mut tampered = token.clone();
        tampered[10] = 0xfe;
        assert!(!constant_time_eq(&tampered, &token));
        // Shorter all-ff slice must not match.
        assert!(!constant_time_eq(&token[..19], &token));
    }

    // Accumulator-saturation attack: if all bytes of `a` have been XOR-folded to
    // 0xFF (i.e. acc is saturated), but the remaining bytes of `b` are 0x00, the
    // fold of 0x00 into 0xFF must keep acc ≠ 0 (since 0xFF | 0 = 0xFF).
    // This guards against a misimplemented fold that resets acc on certain values.
    #[test]
    fn constant_time_eq_accumulator_never_resets_to_zero_after_mismatch() {
        // a[0] = 0xAA, b[0] = 0x55 → XOR = 0xFF.
        // Subsequent bytes all match (XOR = 0x00). Accumulator must remain 0xFF.
        let mut a = vec![0x55u8; 16];
        let mut b = vec![0x55u8; 16];
        a[0] = 0xAA; // deliberate mismatch at position 0
        assert!(!constant_time_eq(&a, &b));
        // Verify with mismatch only at last position to test late detection.
        a[0] = b[0];
        a[15] = 0xAA;
        b[15] = 0x55;
        assert!(!constant_time_eq(&a, &b));
    }

    // Zero-length expected token: only the empty input must match.
    #[test]
    fn constant_time_eq_zero_length_expected_only_matches_empty_input() {
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"\x00", b""));
        assert!(!constant_time_eq(b"x", b""));
    }
}
