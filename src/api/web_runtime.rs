use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;

use super::config_store::current_revision;
use super::http_utils::{read_json, success_response};
use super::model::ApiFailure;
use super::{ALLOW_GET, ALLOW_POST, ApiShared};
use crate::config::ProxyConfig;
use crate::web::control::{WebRuntimeLifecycle, WebRuntimePublication};
use crate::web::manager::{ControlError, OperatorLifecycleError, SessionDetail, WebProcessRuntime};

// Exact JSON DTOs and strict query parsing stay independent from route dispatch.
mod request;
// Ingress, capacity, and decoy telemetry remain separate availability planes.
mod observability;
use observability::{WebCapacityStatus, WebDecoyUpstreamStatus, WebIngressStatus};
use request::{
    CloseRequest, DrainRequest, RuntimeInstanceRequest, parse_session_query, parse_session_ref,
    valid_runtime_instance,
};

const STATUS_PATH: &str = "/v1/runtime/web/status";
const SESSIONS_PATH: &str = "/v1/runtime/web/sessions";
const CLOSE_PATH: &str = "/v1/runtime/web/sessions/close";
const DEBUG_CLEAR_PATH: &str = "/v1/runtime/web/debug/clear";
const LEARNING_RESET_PATH: &str = "/v1/runtime/web/carrier-learning/reset";
const LIFECYCLE_PAUSE_PATH: &str = "/v1/runtime/web/lifecycle/pause";
const LIFECYCLE_DRAIN_PATH: &str = "/v1/runtime/web/lifecycle/drain";
const LIFECYCLE_RESUME_PATH: &str = "/v1/runtime/web/lifecycle/resume";
const SESSION_DETAIL_PREFIX: &str = "/v1/runtime/web/sessions/";
const OPERATION_PREFIX: &str = "/v1/runtime/web/operations/";
const MAX_CONTROL_BODY_BYTES: usize = 64 * 1024;

/// Returns the exact allowed method set for a WEB runtime route.
pub(super) fn allowed_methods(path: &str) -> Option<&'static str> {
    match path {
        STATUS_PATH | SESSIONS_PATH => Some(ALLOW_GET),
        CLOSE_PATH
        | DEBUG_CLEAR_PATH
        | LEARNING_RESET_PATH
        | LIFECYCLE_PAUSE_PATH
        | LIFECYCLE_DRAIN_PATH
        | LIFECYCLE_RESUME_PATH => Some(ALLOW_POST),
        _ if detail_ref(path).is_some() || operation_ref(path).is_some() => Some(ALLOW_GET),
        _ => None,
    }
}

/// Returns whether the normalized API path belongs to WEB runtime control.
pub(super) fn is_route(path: &str) -> bool {
    allowed_methods(path).is_some()
}

/// Dispatches one authenticated WEB runtime status or control request.
pub(super) async fn handle(
    method: Method,
    path: &str,
    query: Option<&str>,
    request: Request<Incoming>,
    shared: &ApiShared,
    config: &ProxyConfig,
    _request_id: u64,
    body_limit: usize,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let revision = current_revision(&shared.config_path).await?;
    match (method.as_str(), path) {
        ("GET", STATUS_PATH) => {
            reject_query(query)?;
            let publication = shared.web_runtime_rx.borrow().clone();
            let runtime = publication.runtime.upgrade();
            let data = WebStatusData::new(publication, runtime.as_deref(), config);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", SESSIONS_PATH) => {
            let runtime = readable_runtime(shared)?;
            let request = parse_session_query(&runtime, query)?;
            let page = runtime.list_sessions(request);
            Ok(success_response(StatusCode::OK, page, revision))
        }
        ("GET", _) if detail_ref(path).is_some() => {
            reject_query(query)?;
            let runtime = readable_runtime(shared)?;
            let session_ref = detail_ref(path).expect("route guard checked detail reference");
            let trace_session_id = parse_session_ref(&runtime, session_ref)?;
            match runtime.session_detail(trace_session_id) {
                SessionDetail::Active(row) => Ok(success_response(StatusCode::OK, row, revision)),
                SessionDetail::Gone { attempt } => Ok(success_response(
                    StatusCode::GONE,
                    GoneSessionData {
                        session_ref: session_ref.to_string(),
                        state: "closed",
                        attempt,
                    },
                    revision,
                )),
                SessionDetail::Busy => Err(snapshot_busy()),
                SessionDetail::NotFound => Err(ApiFailure::new(
                    StatusCode::NOT_FOUND,
                    "web_session_not_found",
                    "WEB session was not found",
                )),
            }
        }
        ("GET", _) if operation_ref(path).is_some() => {
            reject_query(query)?;
            let runtime = readable_runtime(shared)?;
            let operation_id = operation_ref(path).expect("route guard checked operation id");
            let status = runtime
                .control_operation(operation_id)
                .map_err(control_failure)?;
            Ok(success_response(StatusCode::OK, status, revision))
        }
        ("POST", LIFECYCLE_PAUSE_PATH) => {
            require_mutable(config)?;
            reject_query(query)?;
            require_json_content_type(&request)?;
            let request = read_json::<RuntimeInstanceRequest>(
                request.into_body(),
                body_limit.min(MAX_CONTROL_BODY_BYTES),
            )
            .await?;
            let runtime = control_runtime(shared)?;
            require_runtime_instance(&runtime, &request.runtime_instance)?;
            let status = runtime.pause_operator().await.map_err(lifecycle_failure)?;
            shared.runtime_events.record(
                "api.web.lifecycle.pause.ok",
                format!("epoch={}", status.epoch),
            );
            Ok(success_response(StatusCode::OK, status, revision))
        }
        ("POST", LIFECYCLE_DRAIN_PATH) => {
            require_mutable(config)?;
            reject_query(query)?;
            require_json_content_type(&request)?;
            let request = read_json::<DrainRequest>(
                request.into_body(),
                body_limit.min(MAX_CONTROL_BODY_BYTES),
            )
            .await?;
            let timeout = drain_timeout(request.timeout_secs)?;
            let runtime = control_runtime(shared)?;
            require_runtime_instance(&runtime, &request.runtime_instance)?;
            let status = runtime
                .drain_operator(timeout)
                .await
                .map_err(lifecycle_failure)?;
            shared.runtime_events.record(
                "api.web.lifecycle.drain.accepted",
                format!(
                    "epoch={} timeout_secs={}",
                    status.epoch, request.timeout_secs
                ),
            );
            Ok(success_response(StatusCode::ACCEPTED, status, revision))
        }
        ("POST", LIFECYCLE_RESUME_PATH) => {
            require_mutable(config)?;
            reject_query(query)?;
            require_json_content_type(&request)?;
            let request = read_json::<RuntimeInstanceRequest>(
                request.into_body(),
                body_limit.min(MAX_CONTROL_BODY_BYTES),
            )
            .await?;
            let runtime = control_runtime(shared)?;
            require_runtime_instance(&runtime, &request.runtime_instance)?;
            let status = runtime.resume_operator().await.map_err(lifecycle_failure)?;
            shared.runtime_events.record(
                "api.web.lifecycle.resume.ok",
                format!("epoch={}", status.epoch),
            );
            Ok(success_response(StatusCode::OK, status, revision))
        }
        ("POST", CLOSE_PATH) => {
            require_mutable(config)?;
            reject_query(query)?;
            require_json_content_type(&request)?;
            let request = read_json::<CloseRequest>(
                request.into_body(),
                body_limit.min(MAX_CONTROL_BODY_BYTES),
            )
            .await?;
            let runtime = control_runtime(shared)?;
            require_runtime_instance(&runtime, &request.runtime_instance)?;
            let selector = request.selector.resolve(&runtime)?;
            let status = runtime
                .start_close_operation(&request.runtime_instance, selector)
                .map_err(control_failure)?;
            shared.runtime_events.record(
                "api.web.sessions.close.accepted",
                format!(
                    "operation_id={} requested={}",
                    status.operation_id, status.requested
                ),
            );
            Ok(success_response(StatusCode::ACCEPTED, status, revision))
        }
        ("POST", DEBUG_CLEAR_PATH) => {
            require_mutable(config)?;
            reject_query(query)?;
            require_json_content_type(&request)?;
            let request = read_json::<RuntimeInstanceRequest>(
                request.into_body(),
                body_limit.min(MAX_CONTROL_BODY_BYTES),
            )
            .await?;
            let runtime = control_runtime(shared)?;
            require_runtime_instance(&runtime, &request.runtime_instance)?;
            let outcome = runtime.clear_debug().map_err(control_failure)?;
            let data = DebugClearData {
                runtime_instance: runtime.runtime_instance().to_string(),
                records_cleared: outcome.records_cleared,
                leased_bytes: outcome.leased_bytes,
                epoch: outcome.epoch,
            };
            shared.runtime_events.record(
                "api.web.debug.clear.ok",
                format!("records={} epoch={}", data.records_cleared, data.epoch),
            );
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("POST", LEARNING_RESET_PATH) => {
            require_mutable(config)?;
            reject_query(query)?;
            require_json_content_type(&request)?;
            let request = read_json::<RuntimeInstanceRequest>(
                request.into_body(),
                body_limit.min(MAX_CONTROL_BODY_BYTES),
            )
            .await?;
            let runtime = control_runtime(shared)?;
            require_runtime_instance(&runtime, &request.runtime_instance)?;
            let outcome = runtime
                .reset_carrier_learning()
                .map_err(|_| runtime_unavailable(WebRuntimeLifecycle::Draining))?;
            let data = LearningResetData {
                runtime_instance: runtime.runtime_instance().to_string(),
                entries_cleared: outcome.entries_cleared,
                epoch: outcome.epoch,
            };
            shared.runtime_events.record(
                "api.web.carrier_learning.reset.ok",
                format!("entries={} epoch={}", data.entries_cleared, data.epoch),
            );
            Ok(success_response(StatusCode::OK, data, revision))
        }
        _ => Err(ApiFailure::method_not_allowed(
            allowed_methods(path).unwrap_or(ALLOW_GET),
        )),
    }
}

#[derive(Serialize)]
struct WebStatusData {
    lifecycle: &'static str,
    lifecycle_epoch: u64,
    lifecycle_age_ms: u64,
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    listeners: Vec<String>,
    effective_config_enabled: bool,
    ingress: WebIngressStatus,
    capacity: WebCapacityStatus,
    decoy_upstream: WebDecoyUpstreamStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    operator_lifecycle: Option<crate::web::manager::OperatorLifecycleStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<crate::web::manager::WebRuntimeStatus>,
}

impl WebStatusData {
    fn new(
        publication: WebRuntimePublication,
        runtime: Option<&WebProcessRuntime>,
        config: &ProxyConfig,
    ) -> Self {
        let available = runtime.is_some()
            && matches!(
                publication.lifecycle,
                WebRuntimeLifecycle::Running | WebRuntimeLifecycle::Draining
            );
        let reason = if available {
            None
        } else {
            Some(match publication.lifecycle {
                WebRuntimeLifecycle::Starting => "starting",
                WebRuntimeLifecycle::NoWebListener => "no_web_listener",
                WebRuntimeLifecycle::Running => "runtime_released",
                WebRuntimeLifecycle::Draining => "runtime_released",
                WebRuntimeLifecycle::Drained => "drained",
                WebRuntimeLifecycle::DeadlineExceeded => "deadline_exceeded",
            })
        };
        let operator_lifecycle = runtime.map(WebProcessRuntime::operator_lifecycle_status);
        let ingress = WebIngressStatus::new(&publication, runtime.is_some());
        let capacity = WebCapacityStatus::new(&publication, runtime, config);
        let decoy_upstream = WebDecoyUpstreamStatus::new(&publication);
        Self {
            lifecycle: publication.lifecycle.as_str(),
            lifecycle_epoch: publication.epoch,
            lifecycle_age_ms: millis(Instant::now().saturating_duration_since(publication.since)),
            available,
            reason,
            listeners: publication
                .listeners
                .iter()
                .map(ToString::to_string)
                .collect(),
            effective_config_enabled: config.web.enabled,
            ingress,
            capacity,
            decoy_upstream,
            operator_lifecycle,
            runtime: runtime.map(WebProcessRuntime::try_status),
        }
    }
}

#[derive(Serialize)]
struct GoneSessionData {
    session_ref: String,
    state: &'static str,
    attempt: u8,
}

#[derive(Serialize)]
struct DebugClearData {
    runtime_instance: String,
    records_cleared: usize,
    leased_bytes: usize,
    epoch: u64,
}

#[derive(Serialize)]
struct LearningResetData {
    runtime_instance: String,
    entries_cleared: usize,
    epoch: u64,
}

fn readable_runtime(shared: &ApiShared) -> Result<Arc<WebProcessRuntime>, ApiFailure> {
    let publication = shared.web_runtime_rx.borrow().clone();
    if !matches!(
        publication.lifecycle,
        WebRuntimeLifecycle::Running | WebRuntimeLifecycle::Draining
    ) {
        return Err(runtime_unavailable(publication.lifecycle));
    }
    publication
        .runtime
        .upgrade()
        .ok_or_else(|| runtime_unavailable(publication.lifecycle))
}

fn control_runtime(shared: &ApiShared) -> Result<Arc<WebProcessRuntime>, ApiFailure> {
    let publication = shared.web_runtime_rx.borrow().clone();
    if publication.lifecycle != WebRuntimeLifecycle::Running {
        return Err(runtime_unavailable(publication.lifecycle));
    }
    publication
        .runtime
        .upgrade()
        .ok_or_else(|| runtime_unavailable(publication.lifecycle))
}

fn runtime_unavailable(lifecycle: WebRuntimeLifecycle) -> ApiFailure {
    ApiFailure::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "web_runtime_unavailable",
        format!("WEB runtime is unavailable: {}", lifecycle.as_str()),
    )
}

fn require_mutable(config: &ProxyConfig) -> Result<(), ApiFailure> {
    if config.server.api.read_only {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "read_only",
            "API runs in read-only mode",
        ));
    }
    Ok(())
}

fn require_json_content_type<B>(request: &Request<B>) -> Result<(), ApiFailure> {
    let mut values = request.headers().get_all(CONTENT_TYPE).iter();
    let exact = values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "application/json")
        && values.next().is_none();
    if !exact {
        return Err(ApiFailure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Content-Type must be exactly application/json",
        ));
    }
    Ok(())
}

fn require_runtime_instance(
    runtime: &WebProcessRuntime,
    runtime_instance: &str,
) -> Result<(), ApiFailure> {
    if !valid_runtime_instance(runtime_instance) {
        return Err(ApiFailure::bad_request(
            "runtime_instance must be 32 lowercase hexadecimal characters",
        ));
    }
    if runtime.runtime_instance() != runtime_instance {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "web_runtime_mismatch",
            "WEB runtime instance no longer matches",
        ));
    }
    Ok(())
}

fn control_failure(error: ControlError) -> ApiFailure {
    match error {
        ControlError::StaleInstance => ApiFailure::new(
            StatusCode::CONFLICT,
            "web_runtime_mismatch",
            "WEB runtime instance no longer matches",
        ),
        ControlError::InvalidSelector | ControlError::InvalidOperation => {
            ApiFailure::bad_request("Invalid WEB control request")
        }
        ControlError::IssuanceEnabled => ApiFailure::new(
            StatusCode::CONFLICT,
            "web_issuance_enabled",
            "Close-all requires effective WEB issuance to be disabled",
        ),
        ControlError::OperationInProgress => ApiFailure::new(
            StatusCode::CONFLICT,
            "web_operation_in_progress",
            "Another WEB close operation is active",
        ),
        ControlError::OperationNotFound => ApiFailure::new(
            StatusCode::NOT_FOUND,
            "web_operation_not_found",
            "WEB control operation was not found",
        ),
        ControlError::Closed => runtime_unavailable(WebRuntimeLifecycle::Draining),
    }
}

fn lifecycle_failure(error: OperatorLifecycleError) -> ApiFailure {
    match error {
        OperatorLifecycleError::Closed => runtime_unavailable(WebRuntimeLifecycle::Draining),
        OperatorLifecycleError::OperationInProgress => ApiFailure::new(
            StatusCode::CONFLICT,
            "web_lifecycle_in_progress",
            "Another WEB drain operation is active",
        ),
    }
}

fn snapshot_busy() -> ApiFailure {
    ApiFailure::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "web_snapshot_busy",
        "WEB runtime snapshot is temporarily busy",
    )
}

fn drain_timeout(timeout_secs: u64) -> Result<Duration, ApiFailure> {
    if !(1..=3600).contains(&timeout_secs) {
        return Err(ApiFailure::bad_request(
            "timeout_secs must be within 1..=3600",
        ));
    }
    Ok(Duration::from_secs(timeout_secs))
}

fn reject_query(query: Option<&str>) -> Result<(), ApiFailure> {
    if query.is_some_and(|query| !query.is_empty()) {
        return Err(ApiFailure::bad_request(
            "This endpoint does not accept query parameters",
        ));
    }
    Ok(())
}

fn detail_ref(path: &str) -> Option<&str> {
    path.strip_prefix(SESSION_DETAIL_PREFIX)
        .filter(|value| !value.is_empty() && !value.contains('/') && *value != "close")
}

fn operation_ref(path: &str) -> Option<&str> {
    path.strip_prefix(OPERATION_PREFIX)
        .filter(|value| !value.is_empty() && !value.contains('/'))
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
#[path = "web_runtime/tests.rs"]
mod tests;
