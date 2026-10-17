use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use ipnetwork::IpNetwork;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::config::{WebClientIpSource, WebDecoyFastTrackMode, WebRuntimeVhost};
use crate::maestro::generation::RuntimeGeneration;
use crate::web::bridge;
use crate::web::manager::{ManagerError, WebProcessRuntime};
use crate::web::telemetry::WebDecoyFastTrackDisposition;

// Response-body activity keeps connection idle accounting lifecycle-correct.
mod activity;
// Body collection retains allocation permits through request processing.
mod body;
// Canonical capability parsing and complete scans remain isolated from HTTP routing.
mod capability;
// Lazy wildcard derivation shares one table between containment and bridge authentication.
mod wildcard;
// Authentic credential containment stays independent from carrier routing.
mod secrets;
// Decoy routing and upstream proxying are isolated from carrier authentication.
mod decoy;
// Authenticated generated-bridge diagnostics remain outside carrier framing.
mod diagnostic;
// Downlink long-poll handling remains isolated from request routing.
mod down;
// Uplink admission and conveyor waits own their bounded request bodies.
mod up;
// Canonical request parsing rejects ambiguous credentials before routing.
mod request;
// Positive-only recovery representation stays separate from ordinary bridge rendering.
mod recovery;
// Carrier response construction and lane-header helpers are shared by handlers.
mod response;
// Session creation and replacement negotiation remain separate from request routing.
mod session;
#[cfg(test)]
mod tests;
// RFC 6455 upgrade validation and carrier drivers remain isolated from HTTP routing.
mod websocket;
// Enabled-debug integration coverage remains separate from carrier behavior tests.
#[cfg(test)]
#[path = "http/trace_tests.rs"]
mod trace_tests;

use crate::web::trace::{HttpTraceExchange, TraceDirection, TraceLifecycleEvent, TraceRoute};
use activity::{ActivityBody, ConnectionActivity, RequestActivity, RequestDeadlineHandle};
use body::{CollectBodyError, CollectedBody, RequestBody, collect_body};
use capability::bridge_candidate;
use decoy::serve_decoy;
use down::handle_down;
use request::{
    bearer_token_hash, binary_content_type, canonical_request_host, canonical_u64_header,
    client_ip, compatible_cookie_header, match_profile,
};
use response::{
    bad_gateway, carrier_empty, carrier_headers, carrier_lane, full_response, generic_not_found,
    insert_header, service_unavailable,
};
use session::handle_session;
use up::handle_up;

type BoxError = Box<dyn Error + Send + Sync>;
type HttpBody = UnsyncBoxBody<Bytes, BoxError>;
type HttpResponse = Response<HttpBody>;

const TRANSPORT_SUFFIXES: [&str; 4] = [
    "api/v1/session",
    "api/v1/up",
    "api/v1/down",
    "api/v1/diagnostic",
];
const WEBSOCKET_SUFFIX: &str = "api/v1/ws";

/// Serves one bounded HTTP/1.1 connection accepted from an external TLS terminator.
pub(crate) async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: Arc<[IpNetwork]>,
    runtime: Arc<WebProcessRuntime>,
    cancellation: CancellationToken,
    connection_permit: tokio::sync::OwnedSemaphorePermit,
) {
    let config = runtime.active_generation().config();
    let max_header_bytes = config.web.limits.max_header_bytes;
    let header_timeout = Duration::from_secs(config.web.timeouts.header_secs);
    let idle_timeout = Duration::from_secs(config.web.timeouts.http_idle_secs);
    let connection_activity = ConnectionActivity::new();
    let service_activity = connection_activity.clone();
    let service = service_fn(move |mut request| {
        let runtime = Arc::clone(&runtime);
        let trusted_proxy_cidrs = Arc::clone(&trusted_proxy_cidrs);
        let connection_activity = service_activity.clone();
        let client_ip_source = client_ip_source;
        async move {
            let Some(activity) = RequestActivity::begin(connection_activity) else {
                let mut response = service_unavailable();
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                return Ok::<_, Infallible>(response);
            };
            request.extensions_mut().insert(activity.deadline_handle());
            let trace = runtime.trace().begin_http(&request, peer.ip());
            if let Some(trace) = &trace {
                request.extensions_mut().insert(Arc::clone(trace));
            }
            let request = request.map(|body| RequestBody::new(body, trace.clone()));
            let response = if let Some(_handler_permit) = runtime.try_http_handler() {
                handle_request(
                    request,
                    peer,
                    client_ip_source,
                    &trusted_proxy_cidrs,
                    runtime,
                )
                .await
            } else {
                service_unavailable()
            };
            if let Some(trace) = &trace {
                trace.response_ready(&response);
            }
            let response =
                response.map(|body| ActivityBody::new(body, activity, trace).boxed_unsync());
            Ok::<_, Infallible>(response)
        }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .max_buf_size(max_header_bytes)
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(websocket::ConnectionIo::new(stream, connection_permit)),
            service,
        )
        .with_upgrades();
    tokio::pin!(connection);
    let mut idle_check = tokio::time::interval((idle_timeout / 2).max(Duration::from_secs(1)));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = &mut connection => break,
            _ = idle_check.tick() => {
                if connection_activity.should_close(tokio::time::Instant::now(), idle_timeout) {
                    break;
                }
            }
        }
    }
}

async fn handle_request(
    mut request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
) -> HttpResponse {
    set_trace_route(&request, TraceRoute::Decoy);
    if let Some(trace) = request_trace(&request)
        && let Some(client_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs)
    {
        trace.set_effective_ip(client_ip);
    }
    let generation = runtime.active_generation();
    let config = generation.config();
    let Some(web_runtime) = config.web.runtime.as_ref() else {
        return generic_not_found();
    };
    let mut host_storage = [0u8; 253];
    // Keep the header owner independent from the moved request on the legacy path.
    let host_header = request.headers().get(header::HOST).cloned();
    let host = if config.web.allow_wildcard_hosts {
        let Some(host) = request::wildcard_request_host(&request, &mut host_storage) else {
            return generic_not_found();
        };
        host
    } else {
        if canonical_request_host(&request).is_none() {
            return generic_not_found();
        }
        let Some(value) = host_header.as_ref().and_then(|value| value.to_str().ok()) else {
            return generic_not_found();
        };
        value.strip_suffix(":443").unwrap_or(value)
    };
    let Some(vhost) = web_runtime.route(host).cloned() else {
        return generic_not_found();
    };
    let table = match wildcard::prepare(&mut request, &config, &vhost, host, &runtime) {
        Ok(table) => table,
        Err(()) => return service_unavailable(),
    };
    let suffix = request.uri().path().strip_prefix(&vhost.base);
    if suffix == Some(WEBSOCKET_SUFFIX) {
        return websocket::handle(
            request,
            peer,
            client_ip_source,
            trusted_proxy_cidrs,
            runtime,
            vhost,
            host,
        )
        .await;
    }
    if suffix.is_some_and(|suffix| TRANSPORT_SUFFIXES.contains(&suffix)) {
        return handle_api(
            request,
            peer,
            client_ip_source,
            trusted_proxy_cidrs,
            runtime,
            vhost,
            host,
        )
        .await;
    }
    if suffix == Some("") && matches!(*request.method(), Method::GET | Method::HEAD) {
        return handle_root(
            request,
            peer,
            client_ip_source,
            trusted_proxy_cidrs,
            runtime,
            generation,
            vhost,
            host,
            table,
            web_runtime.snapshot_id,
        )
        .await;
    }
    let sanitize_recovery = recovery::has_media_type(&request);
    if sanitize_recovery {
        strip_query(&mut request);
    }
    serve_decoy(request, vhost, sanitize_recovery, &runtime).await
}

async fn handle_root(
    mut request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
    generation: Arc<RuntimeGeneration>,
    vhost: Arc<WebRuntimeVhost>,
    host: &str,
    table: Option<crate::web::manager::wildcard::CapabilityTable>,
    snapshot_id: u64,
) -> HttpResponse {
    let representation = recovery::classify(&request);
    if matches!(representation, recovery::RootRepresentation::Invalid) {
        strip_query(&mut request);
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let candidate = bridge_candidate(request.uri().query());
    let canonical = candidate.is_canonical();
    let plausible_candidate = canonical && request.method() == Method::GET;
    let fasttrack_mode = vhost.decoy_fasttrack_mode;
    match fasttrack_mode {
        WebDecoyFastTrackMode::Off => {}
        WebDecoyFastTrackMode::Shadow => {
            runtime
                .telemetry()
                .record_decoy_fasttrack(if plausible_candidate {
                    WebDecoyFastTrackDisposition::ShadowCandidateFullScan
                } else {
                    WebDecoyFastTrackDisposition::ShadowWouldFastTrack
                });
        }
        WebDecoyFastTrackMode::Enforce if !plausible_candidate => {
            runtime
                .telemetry()
                .record_decoy_fasttrack(WebDecoyFastTrackDisposition::EnforceFastTrack);
            let recovery_requested =
                matches!(representation, recovery::RootRepresentation::Recovery(_));
            if recovery_requested {
                strip_query(&mut request);
            }
            return serve_decoy(request, vhost, recovery_requested, &runtime).await;
        }
        WebDecoyFastTrackMode::Enforce => {
            runtime
                .telemetry()
                .record_decoy_fasttrack(WebDecoyFastTrackDisposition::EnforceCandidateFullScan);
        }
    }
    let matched_profile =
        wildcard::match_profile(&vhost, host, table.as_ref(), candidate.scan_bytes());
    let recovery_requested = matches!(representation, recovery::RootRepresentation::Recovery(_));
    let profile = matched_profile.filter(|_| canonical && request.method() == Method::GET);
    let Some(profile) = profile else {
        if recovery_requested {
            strip_query(&mut request);
        }
        return serve_decoy(request, vhost, recovery_requested, &runtime).await;
    };
    let Some(client_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs) else {
        strip_query(&mut request);
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Bridge);
        trace.set_effective_ip(client_ip);
    }
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let recovery_session = match representation {
        recovery::RootRepresentation::Recovery(Some(hash)) => {
            runtime.bridge_recovery_session(hash, host, &profile)
        }
        _ => None,
    };
    let bootstrap = match match representation {
        recovery::RootRepresentation::Bridge => runtime.issue_bootstrap_for_request(
            &generation,
            Arc::clone(&profile),
            client_ip,
            user_agent,
        ),
        recovery::RootRepresentation::Recovery(_) => runtime.issue_recovery_bootstrap_for_request(
            &generation,
            Arc::clone(&profile),
            client_ip,
            user_agent,
            recovery_session
                .as_ref()
                .map(|session| session.trace_session_id()),
        ),
        recovery::RootRepresentation::Invalid => {
            strip_query(&mut request);
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    } {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            runtime.trace().record_profile_lifecycle(
                client_ip,
                None,
                &profile,
                TraceLifecycleEvent::BootstrapRejected,
                None,
                Some(error.as_str()),
            );
            strip_query(&mut request);
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    if let (Some(cache), Some(table)) = (&runtime.wildcard, table) {
        cache.publish(snapshot_id, &vhost, host, table, || {
            runtime
                .active_generation()
                .config()
                .web
                .runtime
                .as_ref()
                .is_some_and(|current| current.snapshot_id == snapshot_id)
        });
    }
    if let Some(trace) = request_trace(&request) {
        trace.bind_profile(&profile, bootstrap.trace_session_id);
        trace.register_redaction(bootstrap.token.as_bytes());
    }
    let config = generation.config();
    if let recovery::RootRepresentation::Recovery(_) = representation {
        if let Some(session) = recovery_session {
            let outcome = session.close(crate::web::session::SessionCloseReason::BridgeRecovery);
            if outcome != crate::web::session::SessionCloseOutcome::Closed
                && tokio::time::timeout(
                    Duration::from_secs(config.web.timeouts.bridge_request_secs),
                    session.wait_close_complete(),
                )
                .await
                .is_err()
            {
                strip_query(&mut request);
                return serve_decoy(request, vhost, true, &runtime).await;
            }
        }
        let Some(response) = recovery::response(
            &bootstrap,
            host,
            &profile,
            &config.web.limits,
            &config.web.timeouts,
        ) else {
            strip_query(&mut request);
            return serve_decoy(request, vhost, true, &runtime).await;
        };
        return response;
    }
    let page = bridge::render(
        host,
        &vhost.base,
        &bootstrap.token,
        config.web.limits.carrier_batch_bytes,
        config.web.limits.pending_bytes_per_session,
        config.web.limits.pending_items_per_session,
        profile.shared.max_streams_per_session,
        profile.shared.carrier_negotiation_enabled,
        profile.shared.carriers.len(),
        profile.shared.carrier_negotiation_deadlines_secs,
        config.web.timeouts.long_poll_secs,
        config.web.timeouts.bridge_request_secs,
        config.web.timeouts.bridge_retry_secs,
        config.web.timeouts.bridge_recovery_secs,
        config.web.timeouts.websocket_open_secs,
        config.web.timeouts.reconnect_grace_secs,
        config.web.timeouts.carrier_probe_coalesce_ms,
        config.web.debug.bridge_diagnostics_enabled(),
        config.web.carrier_method,
        &generation.rng,
    );
    let mut response = full_response(StatusCode::OK, Bytes::from(page.body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    insert_header(
        &mut response,
        header::CONTENT_SECURITY_POLICY,
        &page.content_security_policy,
    );
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
    response.headers_mut().insert(
        HeaderName::from_static("x-dns-prefetch-control"),
        HeaderValue::from_static("off"),
    );
    insert_header(
        &mut response,
        HeaderName::from_static("permissions-policy"),
        bridge::PERMISSIONS_POLICY,
    );
    response
}

async fn handle_api(
    request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
    host: &str,
) -> HttpResponse {
    if request.uri().query().is_some() || !compatible_cookie_header(&request) {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(client_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_effective_ip(client_ip);
    }
    let Some(token_hash) = bearer_token_hash(&request) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    match request.uri().path().strip_prefix(&vhost.base) {
        Some("api/v1/session") => {
            handle_session(request, runtime, vhost, host, token_hash, client_ip).await
        }
        Some("api/v1/up") => handle_up(request, runtime, vhost, host, token_hash).await,
        Some("api/v1/down") => handle_down(request, runtime, vhost, host, token_hash).await,
        Some("api/v1/diagnostic") => {
            diagnostic::handle(request, runtime, vhost, host, token_hash, client_ip).await
        }
        _ => serve_decoy(request, vhost, true, &runtime).await,
    }
}
fn strip_query<B>(request: &mut Request<B>) {
    if request.uri().query().is_some()
        && let Ok(uri) = request.uri().path().parse()
    {
        *request.uri_mut() = uri;
    }
}

fn request_trace<B>(request: &Request<B>) -> Option<&Arc<HttpTraceExchange>> {
    request.extensions().get::<Arc<HttpTraceExchange>>()
}

fn request_deadline<B>(request: &Request<B>) -> Option<RequestDeadlineHandle> {
    request.extensions().get::<RequestDeadlineHandle>().cloned()
}

fn set_trace_route<B>(request: &Request<B>, route: TraceRoute) {
    if let Some(trace) = request_trace(request) {
        trace.set_route(route);
    }
}
