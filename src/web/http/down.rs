use std::sync::Arc;
use std::time::Duration;

use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Request, StatusCode};

use super::body::{CollectBodyError, CollectedBody, RequestBody, collect_body};
use super::decoy::serve_decoy;
use super::request::canonical_u64_header;
use super::{
    HttpResponse, carrier_empty, carrier_headers, carrier_lane, full_response, insert_header,
    request_trace, service_unavailable,
};
use crate::config::WebRuntimeVhost;
use crate::web::manager::{ManagerError, TokenHash, WebProcessRuntime};
use crate::web::trace::{TraceDirection, TraceRoute};

/// Handles one authenticated long-poll downlink exchange.
pub(super) async fn handle_down(
    request: Request<RequestBody>,
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
    host: &str,
    token_hash: TokenHash,
) -> HttpResponse {
    if !matches!(*request.method(), hyper::Method::POST | hyper::Method::PUT)
        || request.headers().contains_key(header::CONTENT_TYPE)
    {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(cursor) = canonical_u64_header(&request, "x-down-cursor") else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let Ok(session) = runtime.get_session(token_hash, host) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if session.carrier().uses_websocket() {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Downlink);
        trace.bind_identity(session.trace_identity());
    }
    let Some(lane_id) = carrier_lane(&request, session.carrier()) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let CollectedBody {
        request,
        body,
        _body_budget,
    } = match collect_body(
        request,
        &runtime,
        Duration::from_secs(session.timeouts().body_secs),
        1,
        true,
    )
    .await
    {
        Ok(result) => result,
        Err(CollectBodyError::Limit) => return service_unavailable(),
        Err(CollectBodyError::Invalid(request)) => {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    if !body.is_empty() {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    // Empty polls must not retain even one byte from a conveyor head's body reserve.
    drop(_body_budget);
    let Some(_down_poll) = runtime.try_lane_poll(false) else {
        return service_unavailable();
    };
    let _control_lane_poll = if lane_id == Some(0) {
        let Some(permit) = runtime.try_lane_poll(true) else {
            return service_unavailable();
        };
        Some(permit)
    } else {
        None
    };
    let poll_timeout = match lane_id {
        Some(_) => Duration::from_secs(session.timeouts().lane_open_wait_secs)
            .checked_add(Duration::from_secs(session.timeouts().long_poll_secs)),
        None => Some(Duration::from_secs(session.timeouts().long_poll_secs)),
    };
    let Some(poll_timeout) = poll_timeout else {
        return service_unavailable();
    };
    let _deadline_lease = match super::request_deadline(&request) {
        Some(deadline) => match deadline.lease_for(poll_timeout) {
            Some(lease) => Some(lease),
            None => return service_unavailable(),
        },
        None => None,
    };
    let result = match lane_id {
        Some(lane_id) => session.poll_down_lane(lane_id, cursor).await,
        None => session.poll_down(cursor).await,
    };
    drop(_deadline_lease);
    match result {
        Ok(result) if result.body.is_empty() => {
            let mut response = carrier_empty(StatusCode::NO_CONTENT);
            insert_header(
                &mut response,
                HeaderName::from_static("x-down-cursor"),
                &result.next_cursor.to_string(),
            );
            if result.lane_closed {
                response.headers_mut().insert(
                    HeaderName::from_static("x-lane-closed"),
                    HeaderValue::from_static("1"),
                );
            }
            response
        }
        Ok(result) => {
            if let Some(trace) = request_trace(&request) {
                trace.record_frames(TraceDirection::Response, &result.body, session.limits());
            }
            let mut response = full_response(StatusCode::OK, result.body);
            carrier_headers(&mut response);
            insert_header(
                &mut response,
                HeaderName::from_static("x-down-cursor"),
                &result.next_cursor.to_string(),
            );
            response
        }
        Err(ManagerError::Concurrent | ManagerError::Backpressure | ManagerError::Limit) => {
            service_unavailable()
        }
        Err(_) => serve_decoy(request, vhost, true, &runtime).await,
    }
}
