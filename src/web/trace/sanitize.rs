use hyper::header;
use zeroize::Zeroizing;

use super::types::{TraceHeader, TraceRoute};
use crate::config::{WebDebugBodyCapture, WebDebugConfig};
use crate::web::frame::{FrameError, FrameType};

const USER_AGENT_MAX_BYTES: usize = 512;
const MIN_REDACTION_BYTES: usize = 8;
const MAX_REDACTION_BYTES: usize = 512;
const MAX_HEADER_REDACTIONS: usize = 16;
const DIAGNOSTIC_BODY_CAPTURE_MAX_BYTES: usize = 64;

/// Calculates a conservative request metadata and credential lease.
pub(super) fn request_dynamic_bytes<B>(
    request: &hyper::Request<B>,
    policy: &WebDebugConfig,
) -> usize {
    request
        .method()
        .as_str()
        .len()
        .saturating_add(request.uri().path().len())
        .saturating_add(
            request
                .headers()
                .get(header::USER_AGENT)
                .map_or(0, |value| {
                    lossy_text_reservation(value.as_bytes(), USER_AGENT_MAX_BYTES)
                }),
        )
        .saturating_add(if policy.capture_headers {
            sanitized_header_bytes(request.headers())
        } else {
            0
        })
        .saturating_add(sensitive_value_bytes(
            request.headers(),
            request.uri().query(),
        ))
}

/// Calculates a conservative response metadata and credential lease.
pub(super) fn response_dynamic_bytes<B>(
    response: &hyper::Response<B>,
    policy: &WebDebugConfig,
) -> usize {
    if policy.capture_headers {
        sanitized_header_bytes(response.headers())
    } else {
        0
    }
    .saturating_add(sensitive_value_bytes(response.headers(), None))
}

/// Copies header names and only allowlisted bounded values.
pub(super) fn sanitized_headers(headers: &hyper::HeaderMap, wildcard: bool) -> Vec<TraceHeader> {
    headers
        .iter()
        .map(|(name, value)| {
            let mut copied = TraceHeader {
                name: name.as_str().to_string(),
                value: header_value_allowed(name).then(|| bounded_text(value.as_bytes(), 4096)),
            };
            if wildcard {
                super::wildcard::scrub_text(&mut copied.name, false);
                if let Some(text) = &mut copied.value {
                    super::wildcard::scrub_text(text, value.len() > 4096);
                }
            }
            copied
        })
        .collect()
}

/// Copies a bounded set of ephemeral credentials into zeroizing scrub patterns.
pub(super) fn sensitive_values(
    headers: &hyper::HeaderMap,
    query: Option<&str>,
) -> Vec<Zeroizing<Vec<u8>>> {
    let mut values = Vec::new();
    for name in [
        "authorization",
        "proxy-authorization",
        "x-session-token",
        "sec-websocket-protocol",
    ] {
        for value in headers.get_all(name) {
            push_redaction(&mut values, value.as_bytes());
            if let Some(token) = value.as_bytes().strip_prefix(b"Bearer ") {
                push_redaction(&mut values, token);
            }
            if values.len() >= MAX_HEADER_REDACTIONS {
                break;
            }
        }
        if values.len() >= MAX_HEADER_REDACTIONS {
            break;
        }
    }
    if let Some(capability) = query.and_then(|query| query.strip_prefix("bridge=")) {
        push_redaction(&mut values, capability.as_bytes());
    }
    values
}

/// Converts at most `limit` raw bytes into loss-tolerant display text.
pub(super) fn bounded_text(value: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(&value[..value.len().min(limit)]).into_owned()
}

/// Overwrites complete credentials and a prefix cut by body truncation.
pub(super) fn scrub_body(body: &mut [u8], redactions: &[Zeroizing<Vec<u8>>]) {
    for secret in redactions.iter().filter(|secret| !secret.is_empty()) {
        if secret.len() <= body.len() {
            for offset in 0..=body.len() - secret.len() {
                if body[offset..].starts_with(secret) {
                    body[offset..offset + secret.len()].fill(b'*');
                }
            }
        }
        let overlap = secret.len().min(body.len());
        for length in (1..=overlap).rev() {
            if body.ends_with(&secret[..length]) {
                let start = body.len() - length;
                body[start..].fill(b'*');
                break;
            }
        }
    }
}

/// Resolves the route-sensitive retained body allocation ceiling.
pub(super) fn capture_limit(
    policy: &WebDebugConfig,
    route: TraceRoute,
    max_carrier_body_bytes: usize,
) -> Option<usize> {
    let limit = match policy.body_capture {
        WebDebugBodyCapture::Off | WebDebugBodyCapture::Metadata => None,
        WebDebugBodyCapture::Prefix => Some(if decoy_route(route) {
            policy.decoy_body_prefix_bytes
        } else {
            policy.body_prefix_bytes
        }),
        WebDebugBodyCapture::Full => Some(if decoy_route(route) {
            policy.decoy_body_prefix_bytes
        } else {
            max_carrier_body_bytes
        }),
    };
    limit.map(|limit| {
        if route == TraceRoute::Diagnostic {
            limit.min(DIAGNOSTIC_BODY_CAPTURE_MAX_BYTES)
        } else {
            limit
        }
    })
}

/// Returns a closed display label for one parsed frame type.
pub(super) fn frame_type_name(frame_type: FrameType) -> &'static str {
    match frame_type {
        FrameType::Open => "OPEN",
        FrameType::Data => "DATA",
        FrameType::Close => "CLOSE",
        FrameType::Window => "WINDOW",
        FrameType::Ping => "PING",
        FrameType::Pong => "PONG",
        FrameType::Hello => "HELLO",
        FrameType::Welcome => "WELCOME",
        FrameType::Bye => "BYE",
    }
}

/// Returns a closed display label for one frame parse failure.
pub(super) fn frame_error_name(error: FrameError) -> &'static str {
    match error {
        FrameError::EmptyBatch => "empty_batch",
        FrameError::TooManyFrames => "too_many_frames",
        FrameError::Incomplete => "incomplete",
        FrameError::PayloadLimit => "payload_limit",
        FrameError::UnknownType => "unknown_type",
        FrameError::InvalidShape => "invalid_shape",
    }
}

fn sanitized_header_bytes(headers: &hyper::HeaderMap) -> usize {
    headers.iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(std::mem::size_of::<TraceHeader>())
            .saturating_add(name.as_str().len())
            .saturating_add(if header_value_allowed(name) {
                lossy_text_reservation(value.as_bytes(), 4096)
            } else {
                0
            })
    })
}

fn header_value_allowed(name: &hyper::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "user-agent"
            | "content-type"
            | "content-length"
            | "origin"
            | "x-forwarded-for"
            | "x-up-seq"
            | "x-up-ack"
            | "x-down-cursor"
            | "x-lane-id"
            | "x-lane-closed"
            | "x-carrier-attempt"
            | "x-carrier-failure"
            | "x-carrier-mode"
            | "retry-after"
            | "cache-control"
            | "etag"
            | "if-none-match"
            | "accept"
            | "accept-encoding"
    )
}

fn sensitive_value_bytes(headers: &hyper::HeaderMap, query: Option<&str>) -> usize {
    let mut total = 0usize;
    let mut retained = 0usize;
    for name in [
        "authorization",
        "proxy-authorization",
        "x-session-token",
        "sec-websocket-protocol",
    ] {
        for value in headers.get_all(name) {
            for candidate in [
                Some(value.as_bytes()),
                value.as_bytes().strip_prefix(b"Bearer "),
            ]
            .into_iter()
            .flatten()
            {
                if (MIN_REDACTION_BYTES..=MAX_REDACTION_BYTES).contains(&candidate.len()) {
                    total = total
                        .saturating_add(std::mem::size_of::<Vec<u8>>())
                        .saturating_add(candidate.len());
                    retained += 1;
                    if retained >= MAX_HEADER_REDACTIONS {
                        break;
                    }
                }
            }
            if retained >= MAX_HEADER_REDACTIONS {
                break;
            }
        }
        if retained >= MAX_HEADER_REDACTIONS {
            break;
        }
    }
    if let Some(capability) = query.and_then(|query| query.strip_prefix("bridge="))
        && (MIN_REDACTION_BYTES..=MAX_REDACTION_BYTES).contains(&capability.len())
    {
        total = total
            .saturating_add(std::mem::size_of::<Vec<u8>>())
            .saturating_add(capability.len());
    }
    total
}

fn lossy_text_reservation(value: &[u8], limit: usize) -> usize {
    value.len().min(limit).saturating_mul(3)
}

fn decoy_route(route: TraceRoute) -> bool {
    matches!(route, TraceRoute::Unknown | TraceRoute::Decoy)
}

fn push_redaction(values: &mut Vec<Zeroizing<Vec<u8>>>, value: &[u8]) {
    if value.len() < MIN_REDACTION_BYTES || value.len() > MAX_REDACTION_BYTES {
        return;
    }
    if !values.iter().any(|existing| existing.as_slice() == value) {
        values.push(Zeroizing::new(value.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_capture_keeps_decoy_bodies_prefix_bounded() {
        let policy = WebDebugConfig {
            body_capture: WebDebugBodyCapture::Full,
            decoy_body_prefix_bytes: 123,
            ..Default::default()
        };
        assert_eq!(capture_limit(&policy, TraceRoute::Decoy, 4096), Some(123));
        assert_eq!(capture_limit(&policy, TraceRoute::Uplink, 4096), Some(4096));
    }

    #[test]
    fn diagnostic_body_capture_never_reserves_the_carrier_ceiling() {
        let full = WebDebugConfig {
            body_capture: WebDebugBodyCapture::Full,
            ..Default::default()
        };
        assert_eq!(capture_limit(&full, TraceRoute::Diagnostic, 4096), Some(64));

        let prefix = WebDebugConfig {
            body_capture: WebDebugBodyCapture::Prefix,
            body_prefix_bytes: 32,
            ..Default::default()
        };
        assert_eq!(
            capture_limit(&prefix, TraceRoute::Diagnostic, 4096),
            Some(32)
        );
    }

    #[test]
    fn scrub_removes_complete_and_prefix_truncated_credentials() {
        let secret = Zeroizing::new(b"credential-value".to_vec());
        let mut complete = b"before credential-value after".to_vec();
        scrub_body(&mut complete, std::slice::from_ref(&secret));
        assert!(
            !complete
                .windows(secret.len())
                .any(|value| value == secret.as_slice())
        );

        let mut truncated = b"before credent".to_vec();
        scrub_body(&mut truncated, &[secret]);
        assert!(truncated.ends_with(b"*******"));
    }
}
