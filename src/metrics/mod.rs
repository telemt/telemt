// Metrics HTTP server, request dispatch, and beobachten renderer.
// Submodules:
// - render: Prometheus metrics rendering (render_metrics)
// - tls_front: TLS front profile health rendering helpers
// - tests: integration tests for the metrics endpoint

mod render;
mod tls_front;

#[cfg(test)]
mod tests;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ipnetwork::IpNetwork;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::ip_tracker::UserIpTracker;
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::Stats;
use crate::stats::beobachten::BeobachtenStore;
use crate::tls_front::TlsFrontCache;
use crate::transport::{ListenOptions, create_listener};

use render::render_metrics;

const METRICS_MAX_CONTROL_CONNECTIONS: usize = 512;
const METRICS_HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn serve(
    port: u16,
    listen: Option<String>,
    listen_backlog: u32,
    stats: Arc<Stats>,
    beobachten: Arc<BeobachtenStore>,
    shared_state: Arc<ProxySharedState>,
    ip_tracker: Arc<UserIpTracker>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    config_rx: tokio::sync::watch::Receiver<Arc<ProxyConfig>>,
    whitelist: Vec<IpNetwork>,
) {
    let whitelist = Arc::new(whitelist);

    // If `metrics_listen` is set, bind on that single address only.
    if let Some(ref listen_addr) = listen {
        let addr: SocketAddr = match listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "Invalid metrics_listen address: {}", listen_addr);
                return;
            }
        };
        // Match `server.api.listen`: `[::]:port` is a dual-stack wildcard
        // on Linux when `net.ipv6.bindv6only=0`.
        let ipv6_only = addr.is_ipv6() && !addr.ip().is_unspecified();
        match bind_metrics_listener(addr, ipv6_only, listen_backlog) {
            Ok(listener) => {
                info!("Metrics endpoint: http://{}/metrics and /beobachten", addr);
                serve_listener(
                    listener,
                    stats,
                    beobachten,
                    shared_state,
                    ip_tracker,
                    tls_cache,
                    config_rx,
                    whitelist,
                )
                .await;
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind metrics on {}", addr);
            }
        }
        return;
    }

    // Fallback: keep metrics local unless an explicit metrics_listen is configured.
    let mut listener_v4 = None;
    let mut listener_v6 = None;

    let addr_v4 = SocketAddr::from(([127, 0, 0, 1], port));
    match bind_metrics_listener(addr_v4, false, listen_backlog) {
        Ok(listener) => {
            info!(
                "Metrics endpoint: http://{}/metrics and /beobachten",
                addr_v4
            );
            listener_v4 = Some(listener);
        }
        Err(e) => {
            warn!(error = %e, "Failed to bind metrics on {}", addr_v4);
        }
    }

    let addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port));
    match bind_metrics_listener(addr_v6, true, listen_backlog) {
        Ok(listener) => {
            info!(
                "Metrics endpoint: http://[::1]:{}/metrics and /beobachten",
                port
            );
            listener_v6 = Some(listener);
        }
        Err(e) => {
            warn!(error = %e, "Failed to bind metrics on {}", addr_v6);
        }
    }

    match (listener_v4, listener_v6) {
        (None, None) => {
            warn!("Metrics listener is unavailable on both IPv4 and IPv6");
        }
        (Some(listener), None) | (None, Some(listener)) => {
            serve_listener(
                listener,
                stats,
                beobachten,
                shared_state,
                ip_tracker,
                tls_cache,
                config_rx,
                whitelist,
            )
            .await;
        }
        (Some(listener4), Some(listener6)) => {
            let stats_v6 = stats.clone();
            let beobachten_v6 = beobachten.clone();
            let shared_state_v6 = shared_state.clone();
            let ip_tracker_v6 = ip_tracker.clone();
            let tls_cache_v6 = tls_cache.clone();
            let config_rx_v6 = config_rx.clone();
            let whitelist_v6 = whitelist.clone();
            tokio::spawn(async move {
                serve_listener(
                    listener6,
                    stats_v6,
                    beobachten_v6,
                    shared_state_v6,
                    ip_tracker_v6,
                    tls_cache_v6,
                    config_rx_v6,
                    whitelist_v6,
                )
                .await;
            });
            serve_listener(
                listener4,
                stats,
                beobachten,
                shared_state,
                ip_tracker,
                tls_cache,
                config_rx,
                whitelist,
            )
            .await;
        }
    }
}

fn bind_metrics_listener(
    addr: SocketAddr,
    ipv6_only: bool,
    listen_backlog: u32,
) -> std::io::Result<TcpListener> {
    let options = ListenOptions {
        reuse_port: false,
        ipv6_only,
        backlog: listen_backlog,
        ..Default::default()
    };
    let socket = create_listener(addr, &options)?;
    TcpListener::from_std(socket.into())
}

async fn serve_listener(
    listener: TcpListener,
    stats: Arc<Stats>,
    beobachten: Arc<BeobachtenStore>,
    shared_state: Arc<ProxySharedState>,
    ip_tracker: Arc<UserIpTracker>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    config_rx: tokio::sync::watch::Receiver<Arc<ProxyConfig>>,
    whitelist: Arc<Vec<IpNetwork>>,
) {
    let connection_permits = Arc::new(Semaphore::new(METRICS_MAX_CONTROL_CONNECTIONS));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Metrics accept error");
                continue;
            }
        };

        if !whitelist.is_empty() && !whitelist.iter().any(|net| net.contains(peer.ip())) {
            debug!(peer = %peer, "Metrics request denied by whitelist");
            continue;
        }

        let connection_permit = match connection_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(
                    peer = %peer,
                    max_connections = METRICS_MAX_CONTROL_CONNECTIONS,
                    "Dropping metrics connection: control-plane connection budget exhausted"
                );
                continue;
            }
        };

        let stats = stats.clone();
        let beobachten = beobachten.clone();
        let shared_state = shared_state.clone();
        let ip_tracker = ip_tracker.clone();
        let tls_cache = tls_cache.clone();
        let config_rx_conn = config_rx.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let svc = service_fn(move |req| {
                let stats = stats.clone();
                let beobachten = beobachten.clone();
                let shared_state = shared_state.clone();
                let ip_tracker = ip_tracker.clone();
                let tls_cache = tls_cache.clone();
                let config = config_rx_conn.borrow().clone();
                async move {
                    handle(
                        req,
                        &stats,
                        &beobachten,
                        &shared_state,
                        &ip_tracker,
                        tls_cache.as_deref(),
                        &config,
                    )
                    .await
                }
            });
            match timeout(
                METRICS_HTTP_CONNECTION_TIMEOUT,
                http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    debug!(error = %e, "Metrics connection error");
                }
                Err(_) => {
                    debug!(
                        peer = %peer,
                        timeout_ms = METRICS_HTTP_CONNECTION_TIMEOUT.as_millis() as u64,
                        "Metrics connection timed out"
                    );
                }
            }
        });
    }
}

async fn handle<B>(
    req: Request<B>,
    stats: &Stats,
    beobachten: &BeobachtenStore,
    shared_state: &ProxySharedState,
    ip_tracker: &UserIpTracker,
    tls_cache: Option<&TlsFrontCache>,
    config: &ProxyConfig,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/metrics" {
        let body = render_metrics(stats, shared_state, config, ip_tracker, tls_cache).await;
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        return Ok(resp);
    }

    if req.uri().path() == "/beobachten" {
        let body = render_beobachten(stats, beobachten, config);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        return Ok(resp);
    }

    let resp = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("Not Found\n")))
        .unwrap();
    Ok(resp)
}

fn render_beobachten(stats: &Stats, beobachten: &BeobachtenStore, config: &ProxyConfig) -> String {
    if !config.general.beobachten {
        return "beobachten disabled\n".to_string();
    }

    let ttl = Duration::from_secs(config.general.beobachten_minutes.saturating_mul(60));
    let mut body = beobachten.snapshot_text(ttl);
    let tls_text = stats.tls_fingerprint_snapshot_text(ttl, 20);
    if !tls_text.is_empty() {
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push('\n');
        body.push_str(&tls_text);
    }
    body
}
