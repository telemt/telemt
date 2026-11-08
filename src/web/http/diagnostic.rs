use std::net::IpAddr;
use std::sync::Arc;

use hyper::header;
use hyper::{Method, Request, StatusCode};

use super::body::{CollectBodyError, CollectedBody, RequestBody, collect_body};
use super::decoy::serve_decoy;
use super::response::{carrier_empty, service_unavailable};
use super::{HttpResponse, request_trace};
use crate::config::WebRuntimeVhost;
use crate::web::manager::{BridgeDiagnosticEvent, TokenHash, WebProcessRuntime};
use crate::web::trace::{TraceLifecycleEvent, TraceRoute};

const DIAGNOSTIC_BODY_LIMIT: usize = 64;

/// Handles one bounded generated-bridge diagnostic report.
pub(super) async fn handle(
    request: Request<RequestBody>,
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
    host: &str,
    token_hash: TokenHash,
    client_ip: IpAddr,
) -> HttpResponse {
    if request.method() != Method::POST || !json_content_type(&request) {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some((trace_session_id, profile, body_timeout)) =
        runtime.bootstrap_trace_identity(token_hash, host)
    else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Diagnostic);
        trace.bind_profile(&profile, trace_session_id);
    }
    let CollectedBody {
        request,
        body,
        _body_budget,
    } = match collect_body(
        request,
        &runtime,
        body_timeout,
        DIAGNOSTIC_BODY_LIMIT,
        false,
    )
    .await
    {
        Ok(result) => result,
        Err(CollectBodyError::Limit) => return service_unavailable(),
        Err(CollectBodyError::Invalid(request)) => {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    let Some(event) = parse_event(&body) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    match runtime.claim_bridge_diagnostic(token_hash, host, event) {
        Ok(first) => {
            if first {
                runtime.trace().record_profile_lifecycle(
                    client_ip,
                    Some(trace_session_id),
                    &profile,
                    TraceLifecycleEvent::BridgeDiagnostic,
                    None,
                    Some(event.as_str()),
                );
            }
            carrier_empty(StatusCode::NO_CONTENT)
        }
        Err(_) => serve_decoy(request, vhost, true, &runtime).await,
    }
}

fn json_content_type<B>(request: &Request<B>) -> bool {
    let mut values = request.headers().get_all(header::CONTENT_TYPE).iter();
    let value = values.next().and_then(|value| value.to_str().ok());
    values.next().is_none()
        && value.is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

fn parse_event(body: &[u8]) -> Option<BridgeDiagnosticEvent> {
    match body {
        br#"{"v":1,"event":"runtime_started"}"# => Some(BridgeDiagnosticEvent::RuntimeStarted),
        br#"{"v":1,"event":"status_posted"}"# => Some(BridgeDiagnosticEvent::StatusPosted),
        br#"{"v":1,"event":"hello_received"}"# => Some(BridgeDiagnosticEvent::HelloReceived),
        br#"{"v":1,"event":"boundary_timeout"}"# => Some(BridgeDiagnosticEvent::BoundaryTimeout),
        br#"{"v":1,"event":"hello_timeout"}"# => Some(BridgeDiagnosticEvent::HelloTimeout),
        br#"{"v":1,"event":"client_close_before_hello"}"# => {
            Some(BridgeDiagnosticEvent::ClientCloseBeforeHello)
        }
        br#"{"v":1,"event":"document_unloaded_before_hello"}"# => {
            Some(BridgeDiagnosticEvent::DocumentUnloadedBeforeHello)
        }
        br#"{"v":1,"event":"runtime_error_before_hello"}"# => {
            Some(BridgeDiagnosticEvent::RuntimeErrorBeforeHello)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_parser_accepts_only_canonical_v1_documents() {
        for (body, event) in [
            (
                br#"{"v":1,"event":"runtime_started"}"#.as_slice(),
                BridgeDiagnosticEvent::RuntimeStarted,
            ),
            (
                br#"{"v":1,"event":"status_posted"}"#.as_slice(),
                BridgeDiagnosticEvent::StatusPosted,
            ),
            (
                br#"{"v":1,"event":"hello_received"}"#.as_slice(),
                BridgeDiagnosticEvent::HelloReceived,
            ),
            (
                br#"{"v":1,"event":"boundary_timeout"}"#.as_slice(),
                BridgeDiagnosticEvent::BoundaryTimeout,
            ),
            (
                br#"{"v":1,"event":"hello_timeout"}"#.as_slice(),
                BridgeDiagnosticEvent::HelloTimeout,
            ),
            (
                br#"{"v":1,"event":"client_close_before_hello"}"#.as_slice(),
                BridgeDiagnosticEvent::ClientCloseBeforeHello,
            ),
            (
                br#"{"v":1,"event":"document_unloaded_before_hello"}"#.as_slice(),
                BridgeDiagnosticEvent::DocumentUnloadedBeforeHello,
            ),
            (
                br#"{"v":1,"event":"runtime_error_before_hello"}"#.as_slice(),
                BridgeDiagnosticEvent::RuntimeErrorBeforeHello,
            ),
        ] {
            assert!(body.len() <= DIAGNOSTIC_BODY_LIMIT);
            assert_eq!(parse_event(body), Some(event));
        }
        assert_eq!(parse_event(br#"{"event":"hello_timeout","v":1}"#), None);
        assert_eq!(
            parse_event(br#"{"v":1,"event":"hello_timeout","detail":"x"}"#),
            None
        );
    }
}
