use bytes::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Request, StatusCode};
use serde::Serialize;

use super::request::{bearer_token_hash, compatible_cookie_header};
use super::response::{full_response, insert_header};
use super::{HttpResponse, RequestBody};
use crate::config::{WebRuntimeProfile, WebRuntimeVhost};
use crate::web::manager::{BootstrapResult, TokenHash};

pub(super) const MEDIA_TYPE: &str = "application/vnd.telemt.web-recovery+json";
const MAX_RESPONSE_BYTES: usize = 1024;

/// Positive representation selected by exact recovery headers.
#[derive(Clone, Copy)]
pub(super) enum RootRepresentation {
    /// Render the ordinary transient bridge document.
    Bridge,
    /// Return fresh recovery policy and optionally retire one current bearer.
    Recovery(Option<TokenHash>),
    /// Hide malformed recovery material behind the configured decoy.
    Invalid,
}

/// Classifies recovery headers without changing capability authentication.
pub(super) fn classify(request: &Request<RequestBody>) -> RootRepresentation {
    let accepts = request.headers().get_all(header::ACCEPT);
    let mut values = accepts.iter();
    let first = values.next();
    let exact = first.is_some_and(|value| value.as_bytes() == MEDIA_TYPE.as_bytes())
        && values.next().is_none();
    let recovery_present = has_media_type(request);
    let authorization_present = request.headers().contains_key(header::AUTHORIZATION);
    if !exact {
        return if authorization_present || recovery_present {
            RootRepresentation::Invalid
        } else {
            RootRepresentation::Bridge
        };
    }
    if !compatible_cookie_header(request) {
        return RootRepresentation::Invalid;
    }
    if !authorization_present {
        return RootRepresentation::Recovery(None);
    }
    bearer_token_hash(request)
        .map(|hash| RootRepresentation::Recovery(Some(hash)))
        .unwrap_or(RootRepresentation::Invalid)
}

/// Detects a recovery media token even when its Accept syntax is noncanonical.
pub(super) fn has_media_type(request: &Request<RequestBody>) -> bool {
    request
        .headers()
        .get_all(header::ACCEPT)
        .iter()
        .any(|value| {
            value.to_str().ok().is_some_and(|value| {
                value.split(',').any(|entry| {
                    entry
                        .split(';')
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case(MEDIA_TYPE))
                })
            })
        })
}

/// Builds the bounded no-store recovery representation.
pub(super) fn response(
    bootstrap: &BootstrapResult,
    vhost: &WebRuntimeVhost,
    profile: &WebRuntimeProfile,
    limits: &crate::config::WebLimitsConfig,
    timeouts: &crate::config::WebTimeoutsConfig,
) -> Option<HttpResponse> {
    let document = RecoveryDocument {
        version: 1,
        bootstrap: &bootstrap.token,
        limits: RecoveryLimits {
            carrier_batch_bytes: limits.carrier_batch_bytes,
            pending_bytes_per_session: limits.pending_bytes_per_session,
            pending_items_per_session: limits.pending_items_per_session,
            max_streams_per_session: profile.shared.max_streams_per_session,
        },
        timeouts: RecoveryTimeouts {
            long_poll_secs: timeouts.long_poll_secs,
            bridge_request_secs: timeouts.bridge_request_secs,
            bridge_retry_secs: timeouts.bridge_retry_secs,
            bridge_recovery_secs: timeouts.bridge_recovery_secs,
            websocket_open_secs: timeouts.websocket_open_secs,
            reconnect_grace_secs: timeouts.reconnect_grace_secs,
        },
        negotiation: RecoveryNegotiation {
            enabled: profile.shared.carrier_negotiation_enabled,
            candidate_count: profile.shared.carriers.len(),
            deadlines_secs: profile.shared.carrier_negotiation_deadlines_secs,
            carrier_probe_coalesce_ms: timeouts.carrier_probe_coalesce_ms,
        },
    };
    let body = serde_json::to_vec(&document).ok()?;
    if body.len() > MAX_RESPONSE_BYTES || profile.host != vhost.host {
        return None;
    }
    let mut response = full_response(StatusCode::OK, Bytes::from(body));
    insert_header(&mut response, header::CONTENT_TYPE, MEDIA_TYPE);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Some(response)
}

#[derive(Serialize)]
struct RecoveryDocument<'a> {
    #[serde(rename = "v")]
    version: u8,
    bootstrap: &'a str,
    limits: RecoveryLimits,
    timeouts: RecoveryTimeouts,
    negotiation: RecoveryNegotiation,
}

#[derive(Serialize)]
struct RecoveryLimits {
    carrier_batch_bytes: usize,
    pending_bytes_per_session: usize,
    pending_items_per_session: usize,
    max_streams_per_session: usize,
}

#[derive(Serialize)]
struct RecoveryTimeouts {
    long_poll_secs: u64,
    bridge_request_secs: u64,
    bridge_retry_secs: u64,
    bridge_recovery_secs: u64,
    websocket_open_secs: u64,
    reconnect_grace_secs: u64,
}

#[derive(Serialize)]
struct RecoveryNegotiation {
    enabled: bool,
    candidate_count: usize,
    deadlines_secs: [u64; 4],
    carrier_probe_coalesce_ms: u64,
}
