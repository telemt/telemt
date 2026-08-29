use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::{
    BoxError, HttpBody, HttpResponse, bad_gateway, full_response, generic_not_found, insert_header,
};
use crate::config::{WebRuntimeDecoy, WebRuntimeVhost};
use crate::web::manager::WebProcessRuntime;
use crate::web::telemetry::WebDecoyUpstreamOutcome;

/// Serves the configured ordinary site after optionally removing carrier material.
/// Transport-sanitized static fallbacks remain uncacheable after query removal.
pub(super) async fn serve_decoy<B>(
    mut request: Request<B>,
    vhost: Arc<WebRuntimeVhost>,
    sanitize_transport: bool,
    runtime: &WebProcessRuntime,
) -> HttpResponse
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    super::set_trace_route(&request, crate::web::trace::TraceRoute::Decoy);
    if sanitize_transport {
        sanitize_transport_request(&mut request);
    }
    let (parts, body) = request.into_parts();
    let body = if sanitize_transport {
        Empty::<Bytes>::new()
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync()
    } else {
        body.map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync()
    };
    let request = Request::from_parts(parts, body);
    match &vhost.decoy {
        WebRuntimeDecoy::StaticDirectory(site) => {
            let mut response = serve_static(request, site);
            if sanitize_transport {
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
            response
        }
        WebRuntimeDecoy::HttpUpstream { addr, authority } => {
            proxy_to_upstream(
                request,
                *addr,
                authority,
                Duration::from_secs(vhost.decoy_header_secs),
                runtime,
            )
            .await
        }
    }
}

fn serve_static<B>(request: Request<B>, site: &crate::config::WebStaticSite) -> HttpResponse {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return static_entry(request, site, None, StatusCode::NOT_FOUND);
    }
    let path = request.uri().path();
    let resolved = resolve_static_path(path, site);
    let status = if resolved.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    static_entry(request, site, resolved, status)
}

fn static_entry<B>(
    request: Request<B>,
    site: &crate::config::WebStaticSite,
    route: Option<&str>,
    status: StatusCode,
) -> HttpResponse {
    let fallback = format!("/{}", site.index);
    let not_found = site.assets.contains_key("/404.html").then_some("/404.html");
    let route = route.or(not_found).unwrap_or(&fallback);
    let Some(asset) = site.assets.get(route) else {
        return generic_not_found();
    };
    let not_modified = status == StatusCode::OK
        && request
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            == Some(asset.etag.as_str());
    let response_body = if request.method() == Method::HEAD || not_modified {
        Bytes::new()
    } else {
        asset.body.clone()
    };
    let mut response = full_response(
        if not_modified {
            StatusCode::NOT_MODIFIED
        } else {
            status
        },
        response_body,
    );
    insert_header(&mut response, header::CONTENT_TYPE, asset.content_type);
    insert_header(&mut response, header::ETAG, &asset.etag);
    insert_header(
        &mut response,
        header::CONTENT_LENGTH,
        &asset.body.len().to_string(),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        if status.is_client_error() || request.uri().query().is_some() {
            HeaderValue::from_static("no-store")
        } else {
            HeaderValue::from_static("public, max-age=300")
        },
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; style-src 'self'; img-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

fn resolve_static_path<'a>(path: &str, site: &'a crate::config::WebStaticSite) -> Option<&'a str> {
    if !path.starts_with('/')
        || path.contains('\\')
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return None;
    }
    let root;
    let route = if path == "/" {
        root = format!("/{}", site.index);
        root.as_str()
    } else {
        path
    };
    if site.assets.contains_key(route) {
        return site
            .assets
            .get_key_value(route)
            .map(|(key, _)| key.as_str());
    }
    if route == "/favicon.ico" && site.assets.contains_key("/favicon.svg") {
        return Some("/favicon.svg");
    }
    if !route.rsplit('/').next().unwrap_or_default().contains('.') {
        let html = format!("{route}.html");
        return site
            .assets
            .get_key_value(&html)
            .map(|(key, _)| key.as_str());
    }
    None
}

async fn proxy_to_upstream(
    mut request: Request<HttpBody>,
    addr: SocketAddr,
    authority: &str,
    header_timeout: Duration,
    runtime: &WebProcessRuntime,
) -> HttpResponse {
    let request_deadline = super::request_deadline(&request);
    remove_hop_by_hop(request.headers_mut());
    if let Ok(host) = HeaderValue::from_str(authority) {
        request.headers_mut().insert(header::HOST, host);
    }
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let Ok(uri) = path_and_query.parse::<Uri>() else {
        return decoy_failure(runtime, WebDecoyUpstreamOutcome::RequestError);
    };
    *request.uri_mut() = uri;
    let _deadline_lease = match lease_deadline(request_deadline.as_ref(), header_timeout) {
        Ok(lease) => lease,
        Err(()) => {
            return decoy_failure(runtime, WebDecoyUpstreamOutcome::DeadlineExhausted);
        }
    };
    let stream = match connect_upstream(addr, header_timeout).await {
        Ok(stream) => stream,
        Err(outcome) => return decoy_failure(runtime, outcome),
    };
    drop(_deadline_lease);
    let max_header_bytes = runtime
        .active_generation()
        .config()
        .web
        .limits
        .max_header_bytes;
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(max_header_bytes);
    let _deadline_lease = match lease_deadline(request_deadline.as_ref(), header_timeout) {
        Ok(lease) => lease,
        Err(()) => {
            return decoy_failure(runtime, WebDecoyUpstreamOutcome::DeadlineExhausted);
        }
    };
    let (mut sender, connection) =
        match tokio::time::timeout(header_timeout, builder.handshake(TokioIo::new(stream))).await {
            Ok(Ok(parts)) => parts,
            Ok(Err(_)) => {
                return decoy_failure(runtime, WebDecoyUpstreamOutcome::HttpHandshakeError);
            }
            Err(_) => {
                return decoy_failure(runtime, WebDecoyUpstreamOutcome::HttpHandshakeTimeout);
            }
        };
    drop(_deadline_lease);
    runtime.spawn_auxiliary(async move {
        let _ = connection.await;
    });
    let _deadline_lease = match lease_deadline(request_deadline.as_ref(), header_timeout) {
        Ok(lease) => lease,
        Err(()) => {
            return decoy_failure(runtime, WebDecoyUpstreamOutcome::DeadlineExhausted);
        }
    };
    let mut response =
        match tokio::time::timeout(header_timeout, sender.send_request(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                return decoy_failure(runtime, WebDecoyUpstreamOutcome::RequestError);
            }
            Err(_) => {
                return decoy_failure(runtime, WebDecoyUpstreamOutcome::ResponseHeadTimeout);
            }
        };
    drop(_deadline_lease);
    runtime
        .telemetry()
        .record_decoy(WebDecoyUpstreamOutcome::Success);
    remove_hop_by_hop(response.headers_mut());
    response.map(|body| {
        body.map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync()
    })
}

async fn connect_upstream(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, WebDecoyUpstreamOutcome> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Err(WebDecoyUpstreamOutcome::ConnectRefused)
        }
        Ok(Err(_)) => Err(WebDecoyUpstreamOutcome::ConnectError),
        Err(_) => Err(WebDecoyUpstreamOutcome::ConnectTimeout),
    }
}

fn decoy_failure(runtime: &WebProcessRuntime, outcome: WebDecoyUpstreamOutcome) -> HttpResponse {
    runtime.telemetry().record_decoy(outcome);
    bad_gateway()
}

fn lease_deadline(
    deadline: Option<&super::activity::RequestDeadlineHandle>,
    timeout: Duration,
) -> Result<Option<super::activity::RequestDeadlineLease>, ()> {
    match deadline {
        Some(deadline) => deadline.lease_for(timeout).map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn sanitize_transport_request<B>(request: &mut Request<B>) {
    for name in [
        header::AUTHORIZATION,
        header::CONTENT_LENGTH,
        header::CONTENT_TYPE,
        header::UPGRADE,
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-extensions"),
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-version"),
        HeaderName::from_static("x-down-cursor"),
        HeaderName::from_static("x-lane-id"),
        HeaderName::from_static("x-up-seq"),
    ] {
        request.headers_mut().remove(name);
    }
    request
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
}

fn remove_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let nominated = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_resolver_rejects_rewritten_paths() {
        let site = crate::config::WebStaticSite {
            assets: std::collections::BTreeMap::new(),
            index: "index.html".to_string(),
        };
        assert!(resolve_static_path("/../index.html", &site).is_none());
        assert!(resolve_static_path("//index.html", &site).is_none());
    }

    #[tokio::test]
    async fn closed_loopback_origin_is_classified_as_connect_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        assert_eq!(
            connect_upstream(addr, Duration::from_secs(1)).await.err(),
            Some(WebDecoyUpstreamOutcome::ConnectRefused)
        );
    }
}
