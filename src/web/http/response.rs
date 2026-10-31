use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::request::canonical_u64_header;
use super::{BoxError, HttpResponse};
use crate::config::WebCarrier;
use crate::web::frame;

/// Validates and resolves the optional carrier lane header.
pub(super) fn carrier_lane<B>(request: &Request<B>, carrier: WebCarrier) -> Option<Option<u32>> {
    match carrier {
        WebCarrier::Https => (!request.headers().contains_key("x-lane-id")).then_some(None),
        WebCarrier::HttpsLanes => canonical_u64_header(request, "x-lane-id")
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value <= frame::MAX_STREAM_ID)
            .map(Some),
        WebCarrier::Websocket | WebCarrier::WebsocketLanes => None,
    }
}

/// Applies common binary carrier response headers.
pub(super) fn carrier_headers(response: &mut HttpResponse) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// Builds an empty no-store carrier response.
pub(super) fn carrier_empty(status: StatusCode) -> HttpResponse {
    let mut response = empty_response(status);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Builds the bounded retryable carrier saturation response.
pub(super) fn service_unavailable() -> HttpResponse {
    let mut response = carrier_empty(StatusCode::SERVICE_UNAVAILABLE);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    // Keep whole-second HTTP guidance for clients without the Telemt extension.
    response.headers_mut().insert(
        HeaderName::from_static("x-telemt-retry-after-ms"),
        HeaderValue::from_static("250"),
    );
    response
}

/// Builds the ordinary decoy upstream failure response.
pub(super) fn bad_gateway() -> HttpResponse {
    full_response(
        StatusCode::BAD_GATEWAY,
        Bytes::from_static(b"site unavailable\n"),
    )
}

/// Builds the ordinary unmatched-host response.
pub(super) fn generic_not_found() -> HttpResponse {
    full_response(StatusCode::NOT_FOUND, Bytes::from_static(b"not found\n"))
}

/// Builds a non-cacheable local rejection for misplaced internal credentials.
pub(super) fn private_not_found() -> HttpResponse {
    let mut response = generic_not_found();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Builds one in-memory response with an exact content length.
pub(super) fn full_response(status: StatusCode, body: Bytes) -> HttpResponse {
    let length = body.len();
    let body = Full::new(body)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    insert_header(&mut response, header::CONTENT_LENGTH, &length.to_string());
    response
}

fn empty_response(status: StatusCode) -> HttpResponse {
    full_response(status, Bytes::new())
}

/// Inserts one validated dynamic response header value.
pub(super) fn insert_header(response: &mut HttpResponse, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(name, value);
    }
}
