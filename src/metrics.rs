use std::collections::{BTreeSet, HashMap};
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
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::ip_tracker::UserIpTracker;
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::Stats;
use crate::stats::beobachten::BeobachtenStore;
use crate::transport::{ListenOptions, create_listener};

pub async fn serve(
    port: u16,
    listen: Option<String>,
    listen_backlog: u32,
    stats: Arc<Stats>,
    beobachten: Arc<BeobachtenStore>,
    shared_state: Arc<ProxySharedState>,
    ip_tracker: Arc<UserIpTracker>,
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
        let is_ipv6 = addr.is_ipv6();
        match bind_metrics_listener(addr, is_ipv6, listen_backlog) {
            Ok(listener) => {
                info!("Metrics endpoint: http://{}/metrics and /beobachten", addr);
                serve_listener(
                    listener,
                    stats,
                    beobachten,
                    shared_state,
                    ip_tracker,
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

    // Fallback: bind on 0.0.0.0 and [::] using metrics_port.
    let mut listener_v4 = None;
    let mut listener_v6 = None;

    let addr_v4 = SocketAddr::from(([0, 0, 0, 0], port));
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

    let addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    match bind_metrics_listener(addr_v6, true, listen_backlog) {
        Ok(listener) => {
            info!(
                "Metrics endpoint: http://[::]:{}/metrics and /beobachten",
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
            let config_rx_v6 = config_rx.clone();
            let whitelist_v6 = whitelist.clone();
            tokio::spawn(async move {
                serve_listener(
                    listener6,
                    stats_v6,
                    beobachten_v6,
                    shared_state_v6,
                    ip_tracker_v6,
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
    config_rx: tokio::sync::watch::Receiver<Arc<ProxyConfig>>,
    whitelist: Arc<Vec<IpNetwork>>,
) {
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

        let stats = stats.clone();
        let beobachten = beobachten.clone();
        let shared_state = shared_state.clone();
        let ip_tracker = ip_tracker.clone();
        let config_rx_conn = config_rx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let stats = stats.clone();
                let beobachten = beobachten.clone();
                let shared_state = shared_state.clone();
                let ip_tracker = ip_tracker.clone();
                let config = config_rx_conn.borrow().clone();
                async move {
                    handle(req, &stats, &beobachten, &shared_state, &ip_tracker, &config).await
                }
            });
            if let Err(e) = http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await
            {
                debug!(error = %e, "Metrics connection error");
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
    config: &ProxyConfig,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/metrics" {
        let body = render_metrics(stats, shared_state, config, ip_tracker).await;
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        return Ok(resp);
    }

    if req.uri().path() == "/beobachten" {
        let body = render_beobachten(beobachten, config);
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

fn render_beobachten(beobachten: &BeobachtenStore, config: &ProxyConfig) -> String {
    if !config.general.beobachten {
        return "beobachten disabled\n".to_string();
    }

    let ttl = Duration::from_secs(config.general.beobachten_minutes.saturating_mul(60));
    beobachten.snapshot_text(ttl)
}

async fn render_metrics(
    stats: &Stats,
    shared_state: &ProxySharedState,
    config: &ProxyConfig,
    ip_tracker: &UserIpTracker,
) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(4096);
    let telemetry = stats.telemetry_policy();
    let core_enabled = telemetry.core_enabled;
    let user_enabled = telemetry.user_enabled;
    let me_allows_normal = telemetry.me_level.allows_normal();
    let me_allows_debug = telemetry.me_level.allows_debug();

    let _ = writeln!(
        out,
        "# HELP telemt_build_info Build information for the running telemt binary"
    );
    let _ = writeln!(out, "# TYPE telemt_build_info gauge");
    let _ = writeln!(
        out,
        "telemt_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    let _ = writeln!(out, "# HELP telemt_uptime_seconds Proxy uptime");
    let _ = writeln!(out, "# TYPE telemt_uptime_seconds gauge");
    let _ = writeln!(out, "telemt_uptime_seconds {:.1}", stats.uptime_secs());

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_core_enabled Runtime core telemetry switch"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_core_enabled gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_core_enabled {}",
        if core_enabled { 1 } else { 0 }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_user_enabled Runtime per-user telemetry switch"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_user_enabled gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_user_enabled {}",
        if user_enabled { 1 } else { 0 }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_me_level Runtime ME telemetry level flag"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_me_level gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_me_level{{level=\"silent\"}} {}",
        if matches!(telemetry.me_level, crate::config::MeTelemetryLevel::Silent) {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_me_level{{level=\"normal\"}} {}",
        if matches!(telemetry.me_level, crate::config::MeTelemetryLevel::Normal) {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_telemetry_me_level{{level=\"debug\"}} {}",
        if matches!(telemetry.me_level, crate::config::MeTelemetryLevel::Debug) {
            1
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_buffer_pool_buffers_total Snapshot of pooled and allocated buffers"
    );
    let _ = writeln!(out, "# TYPE telemt_buffer_pool_buffers_total gauge");
    let _ = writeln!(
        out,
        "telemt_buffer_pool_buffers_total{{kind=\"pooled\"}} {}",
        stats.get_buffer_pool_pooled_gauge()
    );
    let _ = writeln!(
        out,
        "telemt_buffer_pool_buffers_total{{kind=\"allocated\"}} {}",
        stats.get_buffer_pool_allocated_gauge()
    );
    let _ = writeln!(
        out,
        "telemt_buffer_pool_buffers_total{{kind=\"in_use\"}} {}",
        stats.get_buffer_pool_in_use_gauge()
    );

    let _ = writeln!(
        out,
        "# HELP telemt_connections_total Total accepted connections"
    );
    let _ = writeln!(out, "# TYPE telemt_connections_total counter");
    let _ = writeln!(
        out,
        "telemt_connections_total {}",
        if core_enabled {
            stats.get_connects_all()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_connections_bad_total Bad/rejected connections"
    );
    let _ = writeln!(out, "# TYPE telemt_connections_bad_total counter");
    let _ = writeln!(
        out,
        "telemt_connections_bad_total {}",
        if core_enabled {
            stats.get_connects_bad()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_handshake_timeouts_total Handshake timeouts"
    );
    let _ = writeln!(out, "# TYPE telemt_handshake_timeouts_total counter");
    let _ = writeln!(
        out,
        "telemt_handshake_timeouts_total {}",
        if core_enabled {
            stats.get_handshake_timeouts()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_auth_expensive_checks_total Expensive authentication candidate checks executed during handshake validation"
    );
    let _ = writeln!(out, "# TYPE telemt_auth_expensive_checks_total counter");
    let _ = writeln!(
        out,
        "telemt_auth_expensive_checks_total {}",
        if core_enabled {
            shared_state
                .handshake
                .auth_expensive_checks_total
                .load(std::sync::atomic::Ordering::Relaxed)
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_auth_budget_exhausted_total Handshake validations that hit authentication candidate budget limits"
    );
    let _ = writeln!(out, "# TYPE telemt_auth_budget_exhausted_total counter");
    let _ = writeln!(
        out,
        "telemt_auth_budget_exhausted_total {}",
        if core_enabled {
            shared_state
                .handshake
                .auth_budget_exhausted_total
                .load(std::sync::atomic::Ordering::Relaxed)
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_accept_permit_timeout_total Accepted connections dropped due to permit wait timeout"
    );
    let _ = writeln!(out, "# TYPE telemt_accept_permit_timeout_total counter");
    let _ = writeln!(
        out,
        "telemt_accept_permit_timeout_total {}",
        if core_enabled {
            stats.get_accept_permit_timeout_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_conntrack_control_state Runtime conntrack control state flags"
    );
    let _ = writeln!(out, "# TYPE telemt_conntrack_control_state gauge");
    let _ = writeln!(
        out,
        "telemt_conntrack_control_state{{flag=\"enabled\"}} {}",
        if stats.get_conntrack_control_enabled() {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_control_state{{flag=\"available\"}} {}",
        if stats.get_conntrack_control_available() {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_control_state{{flag=\"pressure_active\"}} {}",
        if stats.get_conntrack_pressure_active() {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_control_state{{flag=\"rule_apply_ok\"}} {}",
        if stats.get_conntrack_rule_apply_ok() {
            1
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_conntrack_event_queue_depth Pending close events in conntrack control queue"
    );
    let _ = writeln!(out, "# TYPE telemt_conntrack_event_queue_depth gauge");
    let _ = writeln!(
        out,
        "telemt_conntrack_event_queue_depth {}",
        stats.get_conntrack_event_queue_depth()
    );

    let _ = writeln!(
        out,
        "# HELP telemt_conntrack_delete_total Conntrack delete attempts by outcome"
    );
    let _ = writeln!(out, "# TYPE telemt_conntrack_delete_total counter");
    let _ = writeln!(
        out,
        "telemt_conntrack_delete_total{{result=\"attempt\"}} {}",
        if core_enabled {
            stats.get_conntrack_delete_attempt_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_delete_total{{result=\"success\"}} {}",
        if core_enabled {
            stats.get_conntrack_delete_success_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_delete_total{{result=\"not_found\"}} {}",
        if core_enabled {
            stats.get_conntrack_delete_not_found_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_delete_total{{result=\"error\"}} {}",
        if core_enabled {
            stats.get_conntrack_delete_error_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_conntrack_close_event_drop_total Dropped conntrack close events due to queue pressure or unavailable sender"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_conntrack_close_event_drop_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_conntrack_close_event_drop_total {}",
        if core_enabled {
            stats.get_conntrack_close_event_drop_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_attempt_total Upstream connect attempts across all requests"
    );
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_attempt_total counter");
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempt_total {}",
        if core_enabled {
            stats.get_upstream_connect_attempt_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_success_total Successful upstream connect request cycles"
    );
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_success_total counter");
    let _ = writeln!(
        out,
        "telemt_upstream_connect_success_total {}",
        if core_enabled {
            stats.get_upstream_connect_success_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_fail_total Failed upstream connect request cycles"
    );
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_fail_total counter");
    let _ = writeln!(
        out,
        "telemt_upstream_connect_fail_total {}",
        if core_enabled {
            stats.get_upstream_connect_fail_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_failfast_hard_error_total Hard errors that triggered upstream connect failfast"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_failfast_hard_error_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_failfast_hard_error_total {}",
        if core_enabled {
            stats.get_upstream_connect_failfast_hard_error_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_attempts_per_request Histogram-like buckets for attempts per upstream connect request cycle"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_attempts_per_request counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"1\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_1()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"2\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_2()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"3_4\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_3_4()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_attempts_per_request{{bucket=\"gt_4\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_attempts_bucket_gt_4()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_duration_success_total Histogram-like buckets of successful upstream connect cycle duration"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_duration_success_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"le_100ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_le_100ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"101_500ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_101_500ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"501_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_501_1000ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_success_total{{bucket=\"gt_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_success_bucket_gt_1000ms()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_upstream_connect_duration_fail_total Histogram-like buckets of failed upstream connect cycle duration"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_upstream_connect_duration_fail_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"le_100ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_le_100ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"101_500ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_101_500ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"501_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_501_1000ms()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_upstream_connect_duration_fail_total{{bucket=\"gt_1000ms\"}} {}",
        if core_enabled {
            stats.get_upstream_connect_duration_fail_bucket_gt_1000ms()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_sent_total ME keepalive frames sent"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_sent_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_sent_total {}",
        if me_allows_debug {
            stats.get_me_keepalive_sent()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_failed_total ME keepalive send failures"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_failed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_failed_total {}",
        if me_allows_normal {
            stats.get_me_keepalive_failed()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_pong_total ME keepalive pong replies"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_pong_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_pong_total {}",
        if me_allows_debug {
            stats.get_me_keepalive_pong()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_keepalive_timeout_total ME keepalive ping timeouts"
    );
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_timeout_total counter");
    let _ = writeln!(
        out,
        "telemt_me_keepalive_timeout_total {}",
        if me_allows_normal {
            stats.get_me_keepalive_timeout()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_sent_total Service RPC_PROXY_REQ activity signals sent"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_sent_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_sent_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_sent_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_failed_total Service RPC_PROXY_REQ activity signal failures"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_failed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_failed_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_failed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_skipped_no_meta_total Service RPC_PROXY_REQ skipped due to missing writer metadata"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_skipped_no_meta_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_skipped_no_meta_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_skipped_no_meta_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_response_total Service RPC_PROXY_REQ responses observed"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_response_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_response_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_response_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_rpc_proxy_req_signal_close_sent_total Service RPC_CLOSE_EXT sent after activity signals"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_rpc_proxy_req_signal_close_sent_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_rpc_proxy_req_signal_close_sent_total {}",
        if me_allows_normal {
            stats.get_me_rpc_proxy_req_signal_close_sent_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_reconnect_attempts_total ME reconnect attempts"
    );
    let _ = writeln!(out, "# TYPE telemt_me_reconnect_attempts_total counter");
    let _ = writeln!(
        out,
        "telemt_me_reconnect_attempts_total {}",
        if me_allows_normal {
            stats.get_me_reconnect_attempts()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_reconnect_success_total ME reconnect successes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_reconnect_success_total counter");
    let _ = writeln!(
        out,
        "telemt_me_reconnect_success_total {}",
        if me_allows_normal {
            stats.get_me_reconnect_success()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_handshake_reject_total ME handshake rejects from upstream"
    );
    let _ = writeln!(out, "# TYPE telemt_me_handshake_reject_total counter");
    let _ = writeln!(
        out,
        "telemt_me_handshake_reject_total {}",
        if me_allows_normal {
            stats.get_me_handshake_reject_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_handshake_error_code_total ME handshake reject errors by code"
    );
    let _ = writeln!(out, "# TYPE telemt_me_handshake_error_code_total counter");
    if me_allows_normal {
        for (error_code, count) in stats.get_me_handshake_error_code_counts() {
            let _ = writeln!(
                out,
                "telemt_me_handshake_error_code_total{{error_code=\"{}\"}} {}",
                error_code, count
            );
        }
    }

    let _ = writeln!(
        out,
        "# HELP telemt_me_reader_eof_total ME reader EOF terminations"
    );
    let _ = writeln!(out, "# TYPE telemt_me_reader_eof_total counter");
    let _ = writeln!(
        out,
        "telemt_me_reader_eof_total {}",
        if me_allows_normal {
            stats.get_me_reader_eof_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_idle_close_by_peer_total ME idle writers closed by peer"
    );
    let _ = writeln!(out, "# TYPE telemt_me_idle_close_by_peer_total counter");
    let _ = writeln!(
        out,
        "telemt_me_idle_close_by_peer_total {}",
        if me_allows_normal {
            stats.get_me_idle_close_by_peer_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_idle_soft_mark_total Middle-relay sessions marked as soft-idle candidates"
    );
    let _ = writeln!(out, "# TYPE telemt_relay_idle_soft_mark_total counter");
    let _ = writeln!(
        out,
        "telemt_relay_idle_soft_mark_total {}",
        if me_allows_normal {
            stats.get_relay_idle_soft_mark_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_idle_hard_close_total Middle-relay sessions closed by hard-idle policy"
    );
    let _ = writeln!(out, "# TYPE telemt_relay_idle_hard_close_total counter");
    let _ = writeln!(
        out,
        "telemt_relay_idle_hard_close_total {}",
        if me_allows_normal {
            stats.get_relay_idle_hard_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_pressure_evict_total Middle-relay sessions evicted under resource pressure"
    );
    let _ = writeln!(out, "# TYPE telemt_relay_pressure_evict_total counter");
    let _ = writeln!(
        out,
        "telemt_relay_pressure_evict_total {}",
        if me_allows_normal {
            stats.get_relay_pressure_evict_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_relay_protocol_desync_close_total Middle-relay sessions closed due to protocol desync"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_relay_protocol_desync_close_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_relay_protocol_desync_close_total {}",
        if me_allows_normal {
            stats.get_relay_protocol_desync_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(out, "# HELP telemt_me_crc_mismatch_total ME CRC mismatches");
    let _ = writeln!(out, "# TYPE telemt_me_crc_mismatch_total counter");
    let _ = writeln!(
        out,
        "telemt_me_crc_mismatch_total {}",
        if me_allows_normal {
            stats.get_me_crc_mismatch()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_seq_mismatch_total ME sequence mismatches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_seq_mismatch_total counter");
    let _ = writeln!(
        out,
        "telemt_me_seq_mismatch_total {}",
        if me_allows_normal {
            stats.get_me_seq_mismatch()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_no_conn_total ME route drops: no conn"
    );
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_no_conn_total counter");
    let _ = writeln!(
        out,
        "telemt_me_route_drop_no_conn_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_no_conn()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_channel_closed_total ME route drops: channel closed"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_route_drop_channel_closed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_route_drop_channel_closed_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_channel_closed()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_queue_full_total ME route drops: queue full"
    );
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_queue_full_total counter");
    let _ = writeln!(
        out,
        "telemt_me_route_drop_queue_full_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_queue_full()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_route_drop_queue_full_profile_total ME route drops: queue full by adaptive profile"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_route_drop_queue_full_profile_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_route_drop_queue_full_profile_total{{profile=\"base\"}} {}",
        if me_allows_normal {
            stats.get_me_route_drop_queue_full_base()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_route_drop_queue_full_profile_total{{profile=\"high\"}} {}",
        if me_allows_normal {
            stats.get_me_route_drop_queue_full_high()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_c2me_enqueue_events_total ME client->ME enqueue outcomes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_c2me_enqueue_events_total counter");
    let _ = writeln!(
        out,
        "telemt_me_c2me_enqueue_events_total{{event=\"full\"}} {}",
        if me_allows_normal {
            stats.get_me_c2me_send_full_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_c2me_enqueue_events_total{{event=\"high_water\"}} {}",
        if me_allows_normal {
            stats.get_me_c2me_send_high_water_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_c2me_enqueue_events_total{{event=\"timeout\"}} {}",
        if me_allows_normal {
            stats.get_me_c2me_send_timeout_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batches_total Total DC->Client flush batches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batches_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batches_total {}",
        if me_allows_normal {
            stats.get_me_d2c_batches_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_frames_total Total DC->Client frames flushed in batches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batch_frames_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_total {}",
        if me_allows_normal {
            stats.get_me_d2c_batch_frames_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_bytes_total Total DC->Client bytes flushed in batches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batch_bytes_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_total {}",
        if me_allows_normal {
            stats.get_me_d2c_batch_bytes_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_flush_reason_total DC->Client flush reasons"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_flush_reason_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"queue_drain\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_queue_drain_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"batch_frames\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_batch_frames_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"batch_bytes\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_batch_bytes_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"max_delay\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_max_delay_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"ack_immediate\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_ack_immediate_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_reason_total{{reason=\"close\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_flush_reason_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_data_frames_total DC->Client data frames"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_data_frames_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_data_frames_total {}",
        if me_allows_normal {
            stats.get_me_d2c_data_frames_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_ack_frames_total DC->Client quick-ack frames"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_ack_frames_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_ack_frames_total {}",
        if me_allows_normal {
            stats.get_me_d2c_ack_frames_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_payload_bytes_total DC->Client payload bytes before transport framing"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_payload_bytes_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_payload_bytes_total {}",
        if me_allows_normal {
            stats.get_me_d2c_payload_bytes_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_write_mode_total DC->Client writer mode selection"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_write_mode_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_write_mode_total{{mode=\"coalesced\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_write_mode_coalesced_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_write_mode_total{{mode=\"split\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_write_mode_split_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_quota_reject_total DC->Client quota rejects"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_quota_reject_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_quota_reject_total{{stage=\"pre_write\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_quota_reject_pre_write_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_quota_reject_total{{stage=\"post_write\"}} {}",
        if me_allows_normal {
            stats.get_me_d2c_quota_reject_post_write_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_frame_buf_shrink_total DC->Client reusable frame buffer shrink events"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_frame_buf_shrink_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_frame_buf_shrink_total {}",
        if me_allows_normal {
            stats.get_me_d2c_frame_buf_shrink_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_frame_buf_shrink_bytes_total DC->Client reusable frame buffer bytes released"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_frame_buf_shrink_bytes_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_frame_buf_shrink_bytes_total {}",
        if me_allows_normal {
            stats.get_me_d2c_frame_buf_shrink_bytes_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_frames_bucket_total DC->Client batch frame count buckets"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_batch_frames_bucket_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"1\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_1()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"2_4\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_2_4()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"5_8\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_5_8()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"9_16\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_9_16()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"17_32\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_17_32()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_frames_bucket_total{{bucket=\"gt_32\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_frames_bucket_gt_32()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_bytes_bucket_total DC->Client batch byte size buckets"
    );
    let _ = writeln!(out, "# TYPE telemt_me_d2c_batch_bytes_bucket_total counter");
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"0_1k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_0_1k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"1k_4k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_1k_4k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"4k_16k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_4k_16k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"16k_64k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_16k_64k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"64k_128k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_64k_128k()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_bytes_bucket_total{{bucket=\"gt_128k\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_bytes_bucket_gt_128k()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_flush_duration_us_bucket_total DC->Client flush duration buckets"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_flush_duration_us_bucket_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"0_50\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_0_50()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"51_200\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_51_200()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"201_1000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_201_1000()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"1001_5000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_1001_5000()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"5001_20000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_5001_20000()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_flush_duration_us_bucket_total{{bucket=\"gt_20000\"}} {}",
        if me_allows_debug {
            stats.get_me_d2c_flush_duration_us_bucket_gt_20000()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_timeout_armed_total DC->Client max-delay timer armed events"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_batch_timeout_armed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_timeout_armed_total {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_timeout_armed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_d2c_batch_timeout_fired_total DC->Client max-delay timer fired events"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_d2c_batch_timeout_fired_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_d2c_batch_timeout_fired_total {}",
        if me_allows_debug {
            stats.get_me_d2c_batch_timeout_fired_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_pick_total ME writer-pick outcomes by mode and result"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writer_pick_total counter");
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"success_try\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_success_try_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"success_fallback\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_success_fallback_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"full\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_full_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"closed\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_closed_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"sorted_rr\",result=\"no_candidate\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_sorted_rr_no_candidate_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"success_try\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_success_try_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"success_fallback\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_success_fallback_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"full\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_full_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"closed\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_closed_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_total{{mode=\"p2c\",result=\"no_candidate\"}} {}",
        if me_allows_normal {
            stats.get_me_writer_pick_p2c_no_candidate_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_pick_blocking_fallback_total ME writer-pick blocking fallback attempts"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_pick_blocking_fallback_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_blocking_fallback_total {}",
        if me_allows_normal {
            stats.get_me_writer_pick_blocking_fallback_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_pick_mode_switch_total Writer-pick mode switches via runtime updates"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_pick_mode_switch_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_pick_mode_switch_total {}",
        if me_allows_normal {
            stats.get_me_writer_pick_mode_switch_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_socks_kdf_policy_total SOCKS KDF policy outcomes"
    );
    let _ = writeln!(out, "# TYPE telemt_me_socks_kdf_policy_total counter");
    let _ = writeln!(
        out,
        "telemt_me_socks_kdf_policy_total{{policy=\"strict\",outcome=\"reject\"}} {}",
        if me_allows_normal {
            stats.get_me_socks_kdf_strict_reject()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_socks_kdf_policy_total{{policy=\"compat\",outcome=\"fallback\"}} {}",
        if me_allows_debug {
            stats.get_me_socks_kdf_compat_fallback()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_endpoint_quarantine_total ME endpoint quarantines due to rapid flaps"
    );
    let _ = writeln!(out, "# TYPE telemt_me_endpoint_quarantine_total counter");
    let _ = writeln!(
        out,
        "telemt_me_endpoint_quarantine_total {}",
        if me_allows_normal {
            stats.get_me_endpoint_quarantine_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_endpoint_quarantine_unexpected_total ME endpoint quarantines caused by unexpected writer removals"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_endpoint_quarantine_unexpected_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_endpoint_quarantine_unexpected_total {}",
        if me_allows_normal {
            stats.get_me_endpoint_quarantine_unexpected_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_endpoint_quarantine_draining_suppressed_total Draining writer removals that skipped endpoint quarantine"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_endpoint_quarantine_draining_suppressed_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_endpoint_quarantine_draining_suppressed_total {}",
        if me_allows_normal {
            stats.get_me_endpoint_quarantine_draining_suppressed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_kdf_drift_total ME KDF input drift detections"
    );
    let _ = writeln!(out, "# TYPE telemt_me_kdf_drift_total counter");
    let _ = writeln!(
        out,
        "telemt_me_kdf_drift_total {}",
        if me_allows_normal {
            stats.get_me_kdf_drift_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_kdf_port_only_drift_total ME KDF client-port changes with stable non-port material"
    );
    let _ = writeln!(out, "# TYPE telemt_me_kdf_port_only_drift_total counter");
    let _ = writeln!(
        out,
        "telemt_me_kdf_port_only_drift_total {}",
        if me_allows_debug {
            stats.get_me_kdf_port_only_drift_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_hardswap_pending_reuse_total Hardswap cycles that reused an existing pending generation"
    );
    let _ = writeln!(out, "# TYPE telemt_me_hardswap_pending_reuse_total counter");
    let _ = writeln!(
        out,
        "telemt_me_hardswap_pending_reuse_total {}",
        if me_allows_debug {
            stats.get_me_hardswap_pending_reuse_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_hardswap_pending_ttl_expired_total Pending hardswap generations reset by TTL expiration"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_hardswap_pending_ttl_expired_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_hardswap_pending_ttl_expired_total {}",
        if me_allows_normal {
            stats.get_me_hardswap_pending_ttl_expired_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_enter_total Single-endpoint DC outage transitions to active state"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_enter_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_enter_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_enter_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_exit_total Single-endpoint DC outage recovery transitions"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_exit_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_exit_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_exit_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_reconnect_attempt_total Reconnect attempts performed during single-endpoint outages"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_reconnect_attempt_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_reconnect_attempt_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_reconnect_attempt_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_outage_reconnect_success_total Successful reconnect attempts during single-endpoint outages"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_outage_reconnect_success_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_outage_reconnect_success_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_outage_reconnect_success_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_quarantine_bypass_total Outage reconnect attempts that bypassed quarantine"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_quarantine_bypass_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_quarantine_bypass_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_quarantine_bypass_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_shadow_rotate_total Successful periodic shadow rotations for single-endpoint DC groups"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_shadow_rotate_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_shadow_rotate_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_shadow_rotate_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_single_endpoint_shadow_rotate_skipped_quarantine_total Shadow rotations skipped because endpoint is quarantined"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_single_endpoint_shadow_rotate_skipped_quarantine_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_single_endpoint_shadow_rotate_skipped_quarantine_total {}",
        if me_allows_normal {
            stats.get_me_single_endpoint_shadow_rotate_skipped_quarantine_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_floor_mode Runtime ME writer floor policy mode"
    );
    let _ = writeln!(out, "# TYPE telemt_me_floor_mode gauge");
    let floor_mode = config.general.me_floor_mode;
    let _ = writeln!(
        out,
        "telemt_me_floor_mode{{mode=\"static\"}} {}",
        if matches!(floor_mode, crate::config::MeFloorMode::Static) {
            1
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_floor_mode{{mode=\"adaptive\"}} {}",
        if matches!(floor_mode, crate::config::MeFloorMode::Adaptive) {
            1
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_floor_mode_switch_all_total Runtime ME floor mode switches"
    );
    let _ = writeln!(out, "# TYPE telemt_me_floor_mode_switch_all_total counter");
    let _ = writeln!(
        out,
        "telemt_me_floor_mode_switch_all_total {}",
        if me_allows_normal {
            stats.get_me_floor_mode_switch_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_floor_mode_switch_total{{from=\"static\",to=\"adaptive\"}} {}",
        if me_allows_normal {
            stats.get_me_floor_mode_switch_static_to_adaptive_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_me_floor_mode_switch_total{{from=\"adaptive\",to=\"static\"}} {}",
        if me_allows_normal {
            stats.get_me_floor_mode_switch_adaptive_to_static_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_cpu_cores_detected Runtime detected logical CPU cores for adaptive floor"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_cpu_cores_detected gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_cpu_cores_detected {}",
        if me_allows_normal {
            stats.get_me_floor_cpu_cores_detected_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_cpu_cores_effective Runtime effective logical CPU cores for adaptive floor"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_cpu_cores_effective gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_cpu_cores_effective {}",
        if me_allows_normal {
            stats.get_me_floor_cpu_cores_effective_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_global_cap_raw Runtime raw global adaptive floor cap"
    );
    let _ = writeln!(out, "# TYPE telemt_me_adaptive_floor_global_cap_raw gauge");
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_global_cap_raw {}",
        if me_allows_normal {
            stats.get_me_floor_global_cap_raw_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_global_cap_effective Runtime effective global adaptive floor cap"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_global_cap_effective gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_global_cap_effective {}",
        if me_allows_normal {
            stats.get_me_floor_global_cap_effective_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_target_writers_total Runtime adaptive floor target writers total"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_target_writers_total gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_target_writers_total {}",
        if me_allows_normal {
            stats.get_me_floor_target_writers_total_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_active_cap_configured Runtime configured active writer cap"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_active_cap_configured gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_active_cap_configured {}",
        if me_allows_normal {
            stats.get_me_floor_active_cap_configured_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_active_cap_effective Runtime effective active writer cap"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_active_cap_effective gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_active_cap_effective {}",
        if me_allows_normal {
            stats.get_me_floor_active_cap_effective_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_warm_cap_configured Runtime configured warm writer cap"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_warm_cap_configured gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_warm_cap_configured {}",
        if me_allows_normal {
            stats.get_me_floor_warm_cap_configured_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_adaptive_floor_warm_cap_effective Runtime effective warm writer cap"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_warm_cap_effective gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_adaptive_floor_warm_cap_effective {}",
        if me_allows_normal {
            stats.get_me_floor_warm_cap_effective_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_writers_active_current Current non-draining active ME writers"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writers_active_current gauge");
    let _ = writeln!(
        out,
        "telemt_me_writers_active_current {}",
        if me_allows_normal {
            stats.get_me_writers_active_current_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_writers_warm_current Current non-draining warm ME writers"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writers_warm_current gauge");
    let _ = writeln!(
        out,
        "telemt_me_writers_warm_current {}",
        if me_allows_normal {
            stats.get_me_writers_warm_current_gauge()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_floor_cap_block_total Reconnect attempts blocked by adaptive floor caps"
    );
    let _ = writeln!(out, "# TYPE telemt_me_floor_cap_block_total counter");
    let _ = writeln!(
        out,
        "telemt_me_floor_cap_block_total {}",
        if me_allows_normal {
            stats.get_me_floor_cap_block_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_floor_swap_idle_total Adaptive floor cap recovery via idle writer swap"
    );
    let _ = writeln!(out, "# TYPE telemt_me_floor_swap_idle_total counter");
    let _ = writeln!(
        out,
        "telemt_me_floor_swap_idle_total {}",
        if me_allows_normal {
            stats.get_me_floor_swap_idle_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_floor_swap_idle_failed_total Failed idle swap attempts under adaptive floor caps"
    );
    let _ = writeln!(out, "# TYPE telemt_me_floor_swap_idle_failed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_floor_swap_idle_failed_total {}",
        if me_allows_normal {
            stats.get_me_floor_swap_idle_failed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_secure_padding_invalid_total Invalid secure frame lengths"
    );
    let _ = writeln!(out, "# TYPE telemt_secure_padding_invalid_total counter");
    let _ = writeln!(
        out,
        "telemt_secure_padding_invalid_total {}",
        if me_allows_normal {
            stats.get_secure_padding_invalid()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_total Total crypto-desync detections"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_total {}",
        if me_allows_normal {
            stats.get_desync_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_full_logged_total Full forensic desync logs emitted"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_full_logged_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_full_logged_total {}",
        if me_allows_normal {
            stats.get_desync_full_logged()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_suppressed_total Suppressed desync forensic events"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_suppressed_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_suppressed_total {}",
        if me_allows_normal {
            stats.get_desync_suppressed()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_desync_frames_bucket_total Desync count by frames_ok bucket"
    );
    let _ = writeln!(out, "# TYPE telemt_desync_frames_bucket_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"0\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_0()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"1_2\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_1_2()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"3_10\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_3_10()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"gt_10\"}} {}",
        if me_allows_normal {
            stats.get_desync_frames_bucket_gt_10()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_swap_total Successful ME pool swaps"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_swap_total counter");
    let _ = writeln!(
        out,
        "telemt_pool_swap_total {}",
        if me_allows_normal {
            stats.get_pool_swap_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_drain_active Active draining ME writers"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_drain_active gauge");
    let _ = writeln!(
        out,
        "telemt_pool_drain_active {}",
        if me_allows_debug {
            stats.get_pool_drain_active()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_force_close_total Forced close events for draining writers"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_force_close_total counter");
    let _ = writeln!(
        out,
        "telemt_pool_force_close_total {}",
        if me_allows_normal {
            stats.get_pool_force_close_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_pool_stale_pick_total Stale writer fallback picks for new binds"
    );
    let _ = writeln!(out, "# TYPE telemt_pool_stale_pick_total counter");
    let _ = writeln!(
        out,
        "telemt_pool_stale_pick_total {}",
        if me_allows_normal {
            stats.get_pool_stale_pick_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_removed_total Total ME writer removals"
    );
    let _ = writeln!(out, "# TYPE telemt_me_writer_removed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_total {}",
        if me_allows_debug {
            stats.get_me_writer_removed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_removed_unexpected_total Unexpected ME writer removals that triggered refill"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_removed_unexpected_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_unexpected_total {}",
        if me_allows_normal {
            stats.get_me_writer_removed_unexpected_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_refill_triggered_total Immediate ME refill runs started"
    );
    let _ = writeln!(out, "# TYPE telemt_me_refill_triggered_total counter");
    let _ = writeln!(
        out,
        "telemt_me_refill_triggered_total {}",
        if me_allows_debug {
            stats.get_me_refill_triggered_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_refill_skipped_inflight_total Immediate ME refill skips due to inflight dedup"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_refill_skipped_inflight_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_refill_skipped_inflight_total {}",
        if me_allows_debug {
            stats.get_me_refill_skipped_inflight_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_refill_failed_total Immediate ME refill failures"
    );
    let _ = writeln!(out, "# TYPE telemt_me_refill_failed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_refill_failed_total {}",
        if me_allows_normal {
            stats.get_me_refill_failed_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_restored_same_endpoint_total Refilled ME writer restored on the same endpoint"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_restored_same_endpoint_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_restored_same_endpoint_total {}",
        if me_allows_normal {
            stats.get_me_writer_restored_same_endpoint_total()
        } else {
            0
        }
    );

    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_restored_fallback_total Refilled ME writer restored via fallback endpoint"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_restored_fallback_total counter"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_restored_fallback_total {}",
        if me_allows_normal {
            stats.get_me_writer_restored_fallback_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_no_writer_failfast_total ME route failfast errors due to missing writer in bounded wait window"
    );
    let _ = writeln!(out, "# TYPE telemt_me_no_writer_failfast_total counter");
    let _ = writeln!(
        out,
        "telemt_me_no_writer_failfast_total {}",
        if me_allows_normal {
            stats.get_me_no_writer_failfast_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_hybrid_timeout_total ME hybrid route timeouts after bounded retry window"
    );
    let _ = writeln!(out, "# TYPE telemt_me_hybrid_timeout_total counter");
    let _ = writeln!(
        out,
        "telemt_me_hybrid_timeout_total {}",
        if me_allows_normal {
            stats.get_me_hybrid_timeout_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_async_recovery_trigger_total Async ME recovery trigger attempts from route path"
    );
    let _ = writeln!(out, "# TYPE telemt_me_async_recovery_trigger_total counter");
    let _ = writeln!(
        out,
        "telemt_me_async_recovery_trigger_total {}",
        if me_allows_normal {
            stats.get_me_async_recovery_trigger_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_me_inline_recovery_total Legacy inline ME recovery attempts from route path"
    );
    let _ = writeln!(out, "# TYPE telemt_me_inline_recovery_total counter");
    let _ = writeln!(
        out,
        "telemt_me_inline_recovery_total {}",
        if me_allows_normal {
            stats.get_me_inline_recovery_total()
        } else {
            0
        }
    );

    let unresolved_writer_losses = if me_allows_normal {
        stats
            .get_me_writer_removed_unexpected_total()
            .saturating_sub(
                stats
                    .get_me_writer_restored_same_endpoint_total()
                    .saturating_add(stats.get_me_writer_restored_fallback_total()),
            )
    } else {
        0
    };
    let _ = writeln!(
        out,
        "# HELP telemt_me_writer_removed_unexpected_minus_restored_total Unexpected writer removals not yet compensated by restore"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_me_writer_removed_unexpected_minus_restored_total gauge"
    );
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_unexpected_minus_restored_total {}",
        unresolved_writer_losses
    );

    let _ = writeln!(
        out,
        "# HELP telemt_user_connections_total Per-user total connections"
    );
    let _ = writeln!(out, "# TYPE telemt_user_connections_total counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_connections_current Per-user active connections"
    );
    let _ = writeln!(out, "# TYPE telemt_user_connections_current gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_user_octets_from_client Per-user bytes received"
    );
    let _ = writeln!(out, "# TYPE telemt_user_octets_from_client counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_octets_to_client Per-user bytes sent"
    );
    let _ = writeln!(out, "# TYPE telemt_user_octets_to_client counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_msgs_from_client Per-user messages received"
    );
    let _ = writeln!(out, "# TYPE telemt_user_msgs_from_client counter");
    let _ = writeln!(
        out,
        "# HELP telemt_user_msgs_to_client Per-user messages sent"
    );
    let _ = writeln!(out, "# TYPE telemt_user_msgs_to_client counter");
    let _ = writeln!(
        out,
        "# HELP telemt_ip_reservation_rollback_total IP reservation rollbacks caused by later limit checks"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_reservation_rollback_total counter");
    let _ = writeln!(
        out,
        "telemt_ip_reservation_rollback_total{{reason=\"tcp_limit\"}} {}",
        if core_enabled {
            stats.get_ip_reservation_rollback_tcp_limit_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "telemt_ip_reservation_rollback_total{{reason=\"quota_limit\"}} {}",
        if core_enabled {
            stats.get_ip_reservation_rollback_quota_limit_total()
        } else {
            0
        }
    );
    let _ = writeln!(
        out,
        "# HELP telemt_telemetry_user_series_suppressed User-labeled metric series suppression flag"
    );
    let _ = writeln!(out, "# TYPE telemt_telemetry_user_series_suppressed gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_user_series_suppressed {}",
        if user_enabled { 0 } else { 1 }
    );

    let ip_memory = ip_tracker.memory_stats().await;
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_users Number of users tracked by IP limiter state"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_users gauge");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_users{{scope=\"active\"}} {}",
        ip_memory.active_users
    );
    let _ = writeln!(
        out,
        "telemt_ip_tracker_users{{scope=\"recent\"}} {}",
        ip_memory.recent_users
    );
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_entries Number of IP entries tracked by limiter state"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_entries gauge");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_entries{{scope=\"active\"}} {}",
        ip_memory.active_entries
    );
    let _ = writeln!(
        out,
        "telemt_ip_tracker_entries{{scope=\"recent\"}} {}",
        ip_memory.recent_entries
    );
    let _ = writeln!(
        out,
        "# HELP telemt_ip_tracker_cleanup_queue_len Deferred disconnect cleanup queue length"
    );
    let _ = writeln!(out, "# TYPE telemt_ip_tracker_cleanup_queue_len gauge");
    let _ = writeln!(
        out,
        "telemt_ip_tracker_cleanup_queue_len {}",
        ip_memory.cleanup_queue_len
    );

    if user_enabled {
        for entry in stats.iter_user_stats() {
            let user = entry.key();
            let s = entry.value();
            let _ = writeln!(
                out,
                "telemt_user_connections_total{{user=\"{}\"}} {}",
                user,
                s.connects.load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_connections_current{{user=\"{}\"}} {}",
                user,
                s.curr_connects.load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_octets_from_client{{user=\"{}\"}} {}",
                user,
                s.octets_from_client
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_octets_to_client{{user=\"{}\"}} {}",
                user,
                s.octets_to_client
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_msgs_from_client{{user=\"{}\"}} {}",
                user,
                s.msgs_from_client
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "telemt_user_msgs_to_client{{user=\"{}\"}} {}",
                user,
                s.msgs_to_client.load(std::sync::atomic::Ordering::Relaxed)
            );
        }

        let ip_stats = ip_tracker.get_stats().await;
        let ip_counts: HashMap<String, usize> = ip_stats
            .into_iter()
            .map(|(user, count, _)| (user, count))
            .collect();

        let mut unique_users = BTreeSet::new();
        unique_users.extend(config.access.users.keys().cloned());
        unique_users.extend(config.access.user_max_unique_ips.keys().cloned());
        unique_users.extend(ip_counts.keys().cloned());
        let unique_users_vec: Vec<String> = unique_users.iter().cloned().collect();
        let recent_counts = ip_tracker
            .get_recent_counts_for_users(&unique_users_vec)
            .await;

        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_current Per-user current number of unique active IPs"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_current gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_recent_window Per-user unique IPs seen in configured observation window"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_recent_window gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_limit Effective per-user unique IP limit (0 means unlimited)"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_limit gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_utilization Per-user unique IP usage ratio (0 for unlimited)"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_utilization gauge");

        for user in unique_users {
            let current = ip_counts.get(&user).copied().unwrap_or(0);
            let limit = config
                .access
                .user_max_unique_ips
                .get(&user)
                .copied()
                .filter(|limit| *limit > 0)
                .or((config.access.user_max_unique_ips_global_each > 0)
                    .then_some(config.access.user_max_unique_ips_global_each))
                .unwrap_or(0);
            let utilization = if limit > 0 {
                current as f64 / limit as f64
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_current{{user=\"{}\"}} {}",
                user, current
            );
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_recent_window{{user=\"{}\"}} {}",
                user,
                recent_counts.get(&user).copied().unwrap_or(0)
            );
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_limit{{user=\"{}\"}} {}",
                user, limit
            );
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_utilization{{user=\"{}\"}} {:.6}",
                user, utilization
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_render_metrics_format() {
        let stats = Arc::new(Stats::new());
        let shared_state = ProxySharedState::new();
        let tracker = UserIpTracker::new();
        let mut config = ProxyConfig::default();
        config
            .access
            .user_max_unique_ips
            .insert("alice".to_string(), 4);

        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_bad();
        stats.increment_handshake_timeouts();
        shared_state
            .handshake
            .auth_expensive_checks_total
            .fetch_add(9, std::sync::atomic::Ordering::Relaxed);
        shared_state
            .handshake
            .auth_budget_exhausted_total
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        stats.increment_upstream_connect_attempt_total();
        stats.increment_upstream_connect_attempt_total();
        stats.increment_upstream_connect_success_total();
        stats.increment_upstream_connect_fail_total();
        stats.increment_upstream_connect_failfast_hard_error_total();
        stats.observe_upstream_connect_attempts_per_request(2);
        stats.observe_upstream_connect_duration_ms(220, true);
        stats.observe_upstream_connect_duration_ms(1500, false);
        stats.increment_me_rpc_proxy_req_signal_sent_total();
        stats.increment_me_rpc_proxy_req_signal_failed_total();
        stats.increment_me_rpc_proxy_req_signal_skipped_no_meta_total();
        stats.increment_me_rpc_proxy_req_signal_response_total();
        stats.increment_me_rpc_proxy_req_signal_close_sent_total();
        stats.increment_me_idle_close_by_peer_total();
        stats.increment_relay_idle_soft_mark_total();
        stats.increment_relay_idle_hard_close_total();
        stats.increment_relay_pressure_evict_total();
        stats.increment_relay_protocol_desync_close_total();
        stats.increment_me_d2c_batches_total();
        stats.add_me_d2c_batch_frames_total(3);
        stats.add_me_d2c_batch_bytes_total(2048);
        stats.increment_me_d2c_flush_reason(crate::stats::MeD2cFlushReason::AckImmediate);
        stats.increment_me_d2c_data_frames_total();
        stats.increment_me_d2c_ack_frames_total();
        stats.add_me_d2c_payload_bytes_total(1800);
        stats.increment_me_d2c_write_mode(crate::stats::MeD2cWriteMode::Coalesced);
        stats.increment_me_d2c_quota_reject_total(crate::stats::MeD2cQuotaRejectStage::PostWrite);
        stats.observe_me_d2c_frame_buf_shrink(4096);
        stats.increment_me_endpoint_quarantine_total();
        stats.increment_me_endpoint_quarantine_unexpected_total();
        stats.increment_me_endpoint_quarantine_draining_suppressed_total();
        stats.increment_user_connects("alice");
        stats.increment_user_curr_connects("alice");
        stats.add_user_octets_from("alice", 1024);
        stats.add_user_octets_to("alice", 2048);
        stats.increment_user_msgs_from("alice");
        stats.increment_user_msgs_to("alice");
        stats.increment_user_msgs_to("alice");
        tracker
            .check_and_add("alice", "203.0.113.10".parse().unwrap())
            .await
            .unwrap();

        let output = render_metrics(&stats, shared_state.as_ref(), &config, &tracker).await;

        assert!(output.contains(&format!(
            "telemt_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(output.contains("telemt_connections_total 2"));
        assert!(output.contains("telemt_connections_bad_total 1"));
        assert!(output.contains("telemt_handshake_timeouts_total 1"));
        assert!(output.contains("telemt_auth_expensive_checks_total 9"));
        assert!(output.contains("telemt_auth_budget_exhausted_total 2"));
        assert!(output.contains("telemt_upstream_connect_attempt_total 2"));
        assert!(output.contains("telemt_upstream_connect_success_total 1"));
        assert!(output.contains("telemt_upstream_connect_fail_total 1"));
        assert!(output.contains("telemt_upstream_connect_failfast_hard_error_total 1"));
        assert!(output.contains("telemt_upstream_connect_attempts_per_request{bucket=\"2\"} 1"));
        assert!(
            output
                .contains("telemt_upstream_connect_duration_success_total{bucket=\"101_500ms\"} 1")
        );
        assert!(
            output.contains("telemt_upstream_connect_duration_fail_total{bucket=\"gt_1000ms\"} 1")
        );
        assert!(output.contains("telemt_me_rpc_proxy_req_signal_sent_total 1"));
        assert!(output.contains("telemt_me_rpc_proxy_req_signal_failed_total 1"));
        assert!(output.contains("telemt_me_rpc_proxy_req_signal_skipped_no_meta_total 1"));
        assert!(output.contains("telemt_me_rpc_proxy_req_signal_response_total 1"));
        assert!(output.contains("telemt_me_rpc_proxy_req_signal_close_sent_total 1"));
        assert!(output.contains("telemt_me_idle_close_by_peer_total 1"));
        assert!(output.contains("telemt_relay_idle_soft_mark_total 1"));
        assert!(output.contains("telemt_relay_idle_hard_close_total 1"));
        assert!(output.contains("telemt_relay_pressure_evict_total 1"));
        assert!(output.contains("telemt_relay_protocol_desync_close_total 1"));
        assert!(output.contains("telemt_me_d2c_batches_total 1"));
        assert!(output.contains("telemt_me_d2c_batch_frames_total 3"));
        assert!(output.contains("telemt_me_d2c_batch_bytes_total 2048"));
        assert!(output.contains("telemt_me_d2c_flush_reason_total{reason=\"ack_immediate\"} 1"));
        assert!(output.contains("telemt_me_d2c_data_frames_total 1"));
        assert!(output.contains("telemt_me_d2c_ack_frames_total 1"));
        assert!(output.contains("telemt_me_d2c_payload_bytes_total 1800"));
        assert!(output.contains("telemt_me_d2c_write_mode_total{mode=\"coalesced\"} 1"));
        assert!(output.contains("telemt_me_d2c_quota_reject_total{stage=\"post_write\"} 1"));
        assert!(output.contains("telemt_me_d2c_frame_buf_shrink_total 1"));
        assert!(output.contains("telemt_me_d2c_frame_buf_shrink_bytes_total 4096"));
        assert!(output.contains("telemt_me_endpoint_quarantine_total 1"));
        assert!(output.contains("telemt_me_endpoint_quarantine_unexpected_total 1"));
        assert!(output.contains("telemt_me_endpoint_quarantine_draining_suppressed_total 1"));
        assert!(output.contains("telemt_user_connections_total{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_connections_current{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_octets_from_client{user=\"alice\"} 1024"));
        assert!(output.contains("telemt_user_octets_to_client{user=\"alice\"} 2048"));
        assert!(output.contains("telemt_user_msgs_from_client{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_msgs_to_client{user=\"alice\"} 2"));
        assert!(output.contains("telemt_user_unique_ips_current{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_unique_ips_recent_window{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_unique_ips_limit{user=\"alice\"} 4"));
        assert!(output.contains("telemt_user_unique_ips_utilization{user=\"alice\"} 0.250000"));
        assert!(output.contains("telemt_ip_tracker_users{scope=\"active\"} 1"));
        assert!(output.contains("telemt_ip_tracker_entries{scope=\"active\"} 1"));
        assert!(output.contains("telemt_ip_tracker_cleanup_queue_len 0"));
    }

    #[tokio::test]
    async fn test_render_empty_stats() {
        let stats = Stats::new();
        let shared_state = ProxySharedState::new();
        let tracker = UserIpTracker::new();
        let config = ProxyConfig::default();
        let output = render_metrics(&stats, &shared_state, &config, &tracker).await;
        assert!(output.contains("telemt_connections_total 0"));
        assert!(output.contains("telemt_connections_bad_total 0"));
        assert!(output.contains("telemt_handshake_timeouts_total 0"));
        assert!(output.contains("telemt_auth_expensive_checks_total 0"));
        assert!(output.contains("telemt_auth_budget_exhausted_total 0"));
        assert!(output.contains("telemt_user_unique_ips_current{user="));
        assert!(output.contains("telemt_user_unique_ips_recent_window{user="));
    }

    #[tokio::test]
    async fn test_render_uses_global_each_unique_ip_limit() {
        let stats = Stats::new();
        let shared_state = ProxySharedState::new();
        stats.increment_user_connects("alice");
        stats.increment_user_curr_connects("alice");
        let tracker = UserIpTracker::new();
        tracker
            .check_and_add("alice", "203.0.113.10".parse().unwrap())
            .await
            .unwrap();
        let mut config = ProxyConfig::default();
        config.access.user_max_unique_ips_global_each = 2;

        let output = render_metrics(&stats, &shared_state, &config, &tracker).await;

        assert!(output.contains("telemt_user_unique_ips_limit{user=\"alice\"} 2"));
        assert!(output.contains("telemt_user_unique_ips_utilization{user=\"alice\"} 0.500000"));
    }

    #[tokio::test]
    async fn test_render_has_type_annotations() {
        let stats = Stats::new();
        let shared_state = ProxySharedState::new();
        let tracker = UserIpTracker::new();
        let config = ProxyConfig::default();
        let output = render_metrics(&stats, &shared_state, &config, &tracker).await;
        assert!(output.contains("# TYPE telemt_uptime_seconds gauge"));
        assert!(output.contains("# TYPE telemt_connections_total counter"));
        assert!(output.contains("# TYPE telemt_connections_bad_total counter"));
        assert!(output.contains("# TYPE telemt_handshake_timeouts_total counter"));
        assert!(output.contains("# TYPE telemt_auth_expensive_checks_total counter"));
        assert!(output.contains("# TYPE telemt_auth_budget_exhausted_total counter"));
        assert!(output.contains("# TYPE telemt_upstream_connect_attempt_total counter"));
        assert!(output.contains("# TYPE telemt_me_rpc_proxy_req_signal_sent_total counter"));
        assert!(output.contains("# TYPE telemt_me_idle_close_by_peer_total counter"));
        assert!(output.contains("# TYPE telemt_relay_idle_soft_mark_total counter"));
        assert!(output.contains("# TYPE telemt_relay_idle_hard_close_total counter"));
        assert!(output.contains("# TYPE telemt_relay_pressure_evict_total counter"));
        assert!(output.contains("# TYPE telemt_relay_protocol_desync_close_total counter"));
        assert!(output.contains("# TYPE telemt_me_d2c_batches_total counter"));
        assert!(output.contains("# TYPE telemt_me_d2c_flush_reason_total counter"));
        assert!(output.contains("# TYPE telemt_me_d2c_write_mode_total counter"));
        assert!(output.contains("# TYPE telemt_me_d2c_batch_frames_bucket_total counter"));
        assert!(output.contains("# TYPE telemt_me_d2c_flush_duration_us_bucket_total counter"));
        assert!(output.contains("# TYPE telemt_me_endpoint_quarantine_total counter"));
        assert!(output.contains("# TYPE telemt_me_endpoint_quarantine_unexpected_total counter"));
        assert!(
            output
                .contains("# TYPE telemt_me_endpoint_quarantine_draining_suppressed_total counter")
        );
        assert!(output.contains("# TYPE telemt_me_writer_removed_total counter"));
        assert!(
            output
                .contains("# TYPE telemt_me_writer_removed_unexpected_minus_restored_total gauge")
        );
        assert!(output.contains("# TYPE telemt_user_unique_ips_current gauge"));
        assert!(output.contains("# TYPE telemt_user_unique_ips_recent_window gauge"));
        assert!(output.contains("# TYPE telemt_user_unique_ips_limit gauge"));
        assert!(output.contains("# TYPE telemt_user_unique_ips_utilization gauge"));
        assert!(output.contains("# TYPE telemt_ip_tracker_users gauge"));
        assert!(output.contains("# TYPE telemt_ip_tracker_entries gauge"));
        assert!(output.contains("# TYPE telemt_ip_tracker_cleanup_queue_len gauge"));
    }

    #[tokio::test]
    async fn test_endpoint_integration() {
        let stats = Arc::new(Stats::new());
        let beobachten = Arc::new(BeobachtenStore::new());
        let shared_state = ProxySharedState::new();
        let tracker = UserIpTracker::new();
        let mut config = ProxyConfig::default();
        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_all();

        let req = Request::builder().uri("/metrics").body(()).unwrap();
        let resp = handle(req, &stats, &beobachten, shared_state.as_ref(), &tracker, &config)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            std::str::from_utf8(body.as_ref())
                .unwrap()
                .contains("telemt_connections_total 3")
        );
        assert!(
            std::str::from_utf8(body.as_ref())
                .unwrap()
                .contains(&format!(
                    "telemt_build_info{{version=\"{}\"}} 1",
                    env!("CARGO_PKG_VERSION")
                ))
        );

        config.general.beobachten = true;
        config.general.beobachten_minutes = 10;
        beobachten.record(
            "TLS-scanner",
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            Duration::from_secs(600),
        );
        let req_beob = Request::builder().uri("/beobachten").body(()).unwrap();
        let resp_beob = handle(
            req_beob,
            &stats,
            &beobachten,
            shared_state.as_ref(),
            &tracker,
            &config,
        )
            .await
            .unwrap();
        assert_eq!(resp_beob.status(), StatusCode::OK);
        let body_beob = resp_beob.into_body().collect().await.unwrap().to_bytes();
        let beob_text = std::str::from_utf8(body_beob.as_ref()).unwrap();
        assert!(beob_text.contains("[TLS-scanner]"));
        assert!(beob_text.contains("203.0.113.10-1"));

        let req404 = Request::builder().uri("/other").body(()).unwrap();
        let resp404 = handle(
            req404,
            &stats,
            &beobachten,
            shared_state.as_ref(),
            &tracker,
            &config,
        )
            .await
            .unwrap();
        assert_eq!(resp404.status(), StatusCode::NOT_FOUND);
    }
}
