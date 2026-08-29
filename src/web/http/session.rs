use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode};

use super::body::{CollectBodyError, CollectedBody, RequestBody, collect_body};
use super::decoy::serve_decoy;
use super::request::{binary_content_type, carrier_ip_learning_eligible, carrier_request};
use super::response::{
    carrier_empty, carrier_headers, full_response, insert_header, service_unavailable,
};
use super::{HttpResponse, request_trace};
use crate::config::WebRuntimeVhost;
use crate::web::frame::{self, FrameType};
use crate::web::manager::{ManagerError, TokenHash, WebProcessRuntime};
use crate::web::trace::{TraceDirection, TraceLifecycleEvent, TraceRoute};

const CREATE_BODY_LIMIT: usize = 64;

/// Handles session creation, replacement replay, and authenticated closure.
pub(super) async fn handle_session(
    request: Request<RequestBody>,
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
    token_hash: TokenHash,
    client_ip: IpAddr,
) -> HttpResponse {
    if request.headers().contains_key("x-lane-id") {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    if request.method() == Method::DELETE {
        if request.headers().contains_key(header::CONTENT_TYPE) {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
        let session = runtime.get_session(token_hash, &vhost.host).ok();
        if let Some(trace) = request_trace(&request)
            && let Some(session) = &session
        {
            trace.set_route(TraceRoute::Session);
            trace.bind_identity(session.trace_identity());
        }
        let body_timeout = session.as_ref().map_or_else(
            || Duration::from_secs(runtime.active_generation().config().web.timeouts.body_secs),
            |session| Duration::from_secs(session.timeouts().body_secs),
        );
        let CollectedBody {
            request,
            body,
            _body_budget,
        } = match collect_body(request, &runtime, body_timeout, 1, true).await {
            Ok(result) => result,
            Err(CollectBodyError::Limit) => return service_unavailable(),
            Err(CollectBodyError::Invalid(request)) => {
                return serve_decoy(request, vhost, true, &runtime).await;
            }
        };
        if !body.is_empty() || runtime.close_token(token_hash, &vhost.host).is_err() {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
        return carrier_empty(StatusCode::NO_CONTENT);
    }
    if request.method() != Method::POST || !binary_content_type(&request) {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(carrier_request) = carrier_request(&request, &vhost.host) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let ip_learning_eligible = carrier_ip_learning_eligible(&request, client_ip);
    let Some((trace_session_id, profile, body_timeout)) =
        runtime.bootstrap_trace_identity(token_hash, &vhost.host)
    else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Session);
        trace.bind_profile(&profile, trace_session_id);
    }
    let CollectedBody {
        request,
        body,
        _body_budget,
    } = match collect_body(request, &runtime, body_timeout, CREATE_BODY_LIMIT, false).await {
        Ok(result) => result,
        Err(CollectBodyError::Limit) => return service_unavailable(),
        Err(CollectBodyError::Invalid(request)) => {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    if let Some(trace) = request_trace(&request) {
        trace.record_frames(
            TraceDirection::Request,
            &body,
            &runtime.active_generation().config().web.limits,
        );
    }
    match runtime.create_session(
        token_hash,
        &vhost.host,
        client_ip,
        &body,
        carrier_request,
        ip_learning_eligible,
    ) {
        Ok(result) => {
            let welcome = frame::encode(FrameType::Welcome, 0, &[]);
            if let Some(trace) = request_trace(&request) {
                trace.register_redaction(result.token.as_bytes());
                trace.record_frames(
                    TraceDirection::Response,
                    &welcome,
                    &runtime.active_generation().config().web.limits,
                );
            }
            let mut response = full_response(StatusCode::OK, welcome);
            carrier_headers(&mut response);
            insert_header(
                &mut response,
                HeaderName::from_static("x-session-token"),
                &result.token,
            );
            response.headers_mut().insert(
                HeaderName::from_static("x-carrier-mode"),
                HeaderValue::from_static(result.carrier.as_str()),
            );
            response.headers_mut().insert(
                HeaderName::from_static("x-down-cursor"),
                HeaderValue::from_static("0"),
            );
            if let Some(attempt) = result.attempt {
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-attempt"),
                    &attempt.to_string(),
                );
            }
            if let Some(candidate_count) = result.candidate_count {
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-candidate-count"),
                    &candidate_count.to_string(),
                );
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-deadline"),
                    &result.deadline_secs.unwrap_or_default().to_string(),
                );
                if let Some(state) = result.carrier_state {
                    insert_header(
                        &mut response,
                        HeaderName::from_static("x-carrier-state"),
                        state,
                    );
                }
            }
            response
        }
        Err(ManagerError::Committed) => {
            let mut response = carrier_empty(StatusCode::CONFLICT);
            if let Some(echo) =
                runtime.carrier_echo(token_hash, &vhost.host, client_ip, carrier_request)
            {
                response.headers_mut().insert(
                    HeaderName::from_static("x-carrier-mode"),
                    HeaderValue::from_static(echo.carrier.as_str()),
                );
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-attempt"),
                    &echo.attempt.to_string(),
                );
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-candidate-count"),
                    &echo.candidate_count.to_string(),
                );
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-deadline"),
                    &echo.deadline_secs.to_string(),
                );
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-state"),
                    echo.state,
                );
            }
            response
        }
        Err(
            error @ (ManagerError::Limit
            | ManagerError::Backpressure
            | ManagerError::Concurrent
            | ManagerError::AdmissionPaused),
        ) => {
            runtime.trace().record_profile_lifecycle(
                client_ip,
                Some(trace_session_id),
                &profile,
                TraceLifecycleEvent::SessionRejected,
                None,
                Some(error.as_str()),
            );
            service_unavailable()
        }
        Err(error) => {
            runtime.trace().record_profile_lifecycle(
                client_ip,
                Some(trace_session_id),
                &profile,
                TraceLifecycleEvent::SessionRejected,
                None,
                Some(error.as_str()),
            );
            serve_decoy(request, vhost, true, &runtime).await
        }
    }
}
