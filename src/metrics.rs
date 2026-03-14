use std::convert::Infallible;
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ipnetwork::IpNetwork;
use tokio::net::TcpListener;
use tracing::{info, warn, debug};

use crate::config::ProxyConfig;
use crate::ip_tracker::UserIpTracker;
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::Stats;
use crate::transport::{ListenOptions, create_listener};

pub async fn serve(
    port: u16,
    stats: Arc<Stats>,
    beobachten: Arc<BeobachtenStore>,
    ip_tracker: Arc<UserIpTracker>,
    config_rx: tokio::sync::watch::Receiver<Arc<ProxyConfig>>,
    whitelist: Vec<IpNetwork>,
) {
    let whitelist = Arc::new(whitelist);
    let mut listener_v4 = None;
    let mut listener_v6 = None;

    let addr_v4 = SocketAddr::from(([0, 0, 0, 0], port));
    match bind_metrics_listener(addr_v4, false) {
        Ok(listener) => {
            info!("Metrics endpoint: http://{}/metrics and /beobachten", addr_v4);
            listener_v4 = Some(listener);
        }
        Err(e) => {
            warn!(error = %e, "Failed to bind metrics on {}", addr_v4);
        }
    }

    let addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    match bind_metrics_listener(addr_v6, true) {
        Ok(listener) => {
            info!("Metrics endpoint: http://[::]:{}/metrics and /beobachten", port);
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
                listener, stats, beobachten, ip_tracker, config_rx, whitelist,
            )
            .await;
        }
        (Some(listener4), Some(listener6)) => {
            let stats_v6 = stats.clone();
            let beobachten_v6 = beobachten.clone();
            let ip_tracker_v6 = ip_tracker.clone();
            let config_rx_v6 = config_rx.clone();
            let whitelist_v6 = whitelist.clone();
            tokio::spawn(async move {
                serve_listener(
                    listener6,
                    stats_v6,
                    beobachten_v6,
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
                ip_tracker,
                config_rx,
                whitelist,
            )
            .await;
        }
    }
}

fn bind_metrics_listener(addr: SocketAddr, ipv6_only: bool) -> std::io::Result<TcpListener> {
    let options = ListenOptions {
        reuse_port: false,
        ipv6_only,
        ..Default::default()
    };
    let socket = create_listener(addr, &options)?;
    TcpListener::from_std(socket.into())
}

async fn serve_listener(
    listener: TcpListener,
    stats: Arc<Stats>,
    beobachten: Arc<BeobachtenStore>,
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
        let ip_tracker = ip_tracker.clone();
        let config_rx_conn = config_rx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let stats = stats.clone();
                let beobachten = beobachten.clone();
                let ip_tracker = ip_tracker.clone();
                let config = config_rx_conn.borrow().clone();
                async move { handle(req, &stats, &beobachten, &ip_tracker, &config).await }
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
    ip_tracker: &UserIpTracker,
    config: &ProxyConfig,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/metrics" {
        let body = render_metrics(stats, config, ip_tracker).await;
        let resp = build_plain_response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            Bytes::from(body),
        );
        return Ok(resp);
    }

    if req.uri().path() == "/beobachten" {
        let body = render_beobachten(beobachten, config);
        let resp = build_plain_response(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            Bytes::from(body),
        );
        return Ok(resp);
    }

    let resp = build_plain_response(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        Bytes::from_static(b"Not Found\n"),
    );
    Ok(resp)
}

fn build_plain_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(Full::new(body))
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(Full::new(Bytes::from_static(b"internal error\n")));
            *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fallback.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            fallback
        })
}

// Escapes a string for use as a Prometheus text-format label value.
// Per the exposition format spec, `\`, `"`, and newlines must be escaped.
fn escape_prometheus_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn render_beobachten(beobachten: &BeobachtenStore, config: &ProxyConfig) -> String {
    if !config.general.beobachten {
        return "beobachten disabled\n".to_string();
    }

    let ttl = Duration::from_secs(config.general.beobachten_minutes.saturating_mul(60));
    beobachten.snapshot_text(ttl)
}

async fn render_metrics(stats: &Stats, config: &ProxyConfig, ip_tracker: &UserIpTracker) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(4096);
    let telemetry = stats.telemetry_policy();
    let core_enabled = telemetry.core_enabled;
    let user_enabled = telemetry.user_enabled;
    let me_allows_normal = telemetry.me_level.allows_normal();
    let me_allows_debug = telemetry.me_level.allows_debug();

    let _ = writeln!(out, "# HELP telemt_uptime_seconds Proxy uptime");
    let _ = writeln!(out, "# TYPE telemt_uptime_seconds gauge");
    let _ = writeln!(out, "telemt_uptime_seconds {:.1}", stats.uptime_secs());

    let _ = writeln!(out, "# HELP telemt_telemetry_core_enabled Runtime core telemetry switch");
    let _ = writeln!(out, "# TYPE telemt_telemetry_core_enabled gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_core_enabled {}",
        if core_enabled { 1 } else { 0 }
    );

    let _ = writeln!(out, "# HELP telemt_telemetry_user_enabled Runtime per-user telemetry switch");
    let _ = writeln!(out, "# TYPE telemt_telemetry_user_enabled gauge");
    let _ = writeln!(
        out,
        "telemt_telemetry_user_enabled {}",
        if user_enabled { 1 } else { 0 }
    );

    let _ = writeln!(out, "# HELP telemt_telemetry_me_level Runtime ME telemetry level flag");
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

    let _ = writeln!(out, "# HELP telemt_connections_total Total accepted connections");
    let _ = writeln!(out, "# TYPE telemt_connections_total counter");
    let _ = writeln!(
        out,
        "telemt_connections_total {}",
        if core_enabled { stats.get_connects_all() } else { 0 }
    );

    let _ = writeln!(out, "# HELP telemt_connections_bad_total Bad/rejected connections");
    let _ = writeln!(out, "# TYPE telemt_connections_bad_total counter");
    let _ = writeln!(
        out,
        "telemt_connections_bad_total {}",
        if core_enabled { stats.get_connects_bad() } else { 0 }
    );

    let _ = writeln!(out, "# HELP telemt_handshake_timeouts_total Handshake timeouts");
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
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_attempts_per_request counter");
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
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_duration_success_total counter");
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
    let _ = writeln!(out, "# TYPE telemt_upstream_connect_duration_fail_total counter");
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

    let _ = writeln!(out, "# HELP telemt_me_keepalive_sent_total ME keepalive frames sent");
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

    let _ = writeln!(out, "# HELP telemt_me_keepalive_failed_total ME keepalive send failures");
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

    let _ = writeln!(out, "# HELP telemt_me_keepalive_pong_total ME keepalive pong replies");
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

    let _ = writeln!(out, "# HELP telemt_me_keepalive_timeout_total ME keepalive ping timeouts");
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
    let _ = writeln!(out, "# TYPE telemt_me_rpc_proxy_req_signal_sent_total counter");
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

    let _ = writeln!(out, "# HELP telemt_me_reconnect_attempts_total ME reconnect attempts");
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

    let _ = writeln!(out, "# HELP telemt_me_reconnect_success_total ME reconnect successes");
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

    let _ = writeln!(out, "# HELP telemt_me_handshake_reject_total ME handshake rejects from upstream");
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

    let _ = writeln!(out, "# HELP telemt_me_handshake_error_code_total ME handshake reject errors by code");
    let _ = writeln!(out, "# TYPE telemt_me_handshake_error_code_total counter");
    if me_allows_normal {
        for (error_code, count) in stats.get_me_handshake_error_code_counts() {
            let _ = writeln!(
                out,
                "telemt_me_handshake_error_code_total{{error_code=\"{}\"}} {}",
                error_code,
                count
            );
        }
    }

    let _ = writeln!(out, "# HELP telemt_me_reader_eof_total ME reader EOF terminations");
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

    let _ = writeln!(out, "# HELP telemt_me_seq_mismatch_total ME sequence mismatches");
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

    let _ = writeln!(out, "# HELP telemt_me_route_drop_no_conn_total ME route drops: no conn");
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

    let _ = writeln!(out, "# HELP telemt_me_route_drop_channel_closed_total ME route drops: channel closed");
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_channel_closed_total counter");
    let _ = writeln!(
        out,
        "telemt_me_route_drop_channel_closed_total {}",
        if me_allows_normal {
            stats.get_me_route_drop_channel_closed()
        } else {
            0
        }
    );

    let _ = writeln!(out, "# HELP telemt_me_route_drop_queue_full_total ME route drops: queue full");
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
    let _ = writeln!(out, "# TYPE telemt_me_writer_pick_mode_switch_total counter");
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

    let _ = writeln!(out, "# HELP telemt_me_kdf_drift_total ME KDF input drift detections");
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
    let _ = writeln!(out, "# TYPE telemt_me_hardswap_pending_ttl_expired_total counter");
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
    let _ = writeln!(
        out,
        "# TYPE telemt_me_adaptive_floor_global_cap_raw gauge"
    );
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

    let _ = writeln!(out, "# HELP telemt_secure_padding_invalid_total Invalid secure frame lengths");
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

    let _ = writeln!(out, "# HELP telemt_desync_total Total crypto-desync detections");
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

    let _ = writeln!(out, "# HELP telemt_desync_full_logged_total Full forensic desync logs emitted");
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

    let _ = writeln!(out, "# HELP telemt_desync_suppressed_total Suppressed desync forensic events");
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

    let _ = writeln!(out, "# HELP telemt_desync_frames_bucket_total Desync count by frames_ok bucket");
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

    let _ = writeln!(out, "# HELP telemt_pool_swap_total Successful ME pool swaps");
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

    let _ = writeln!(out, "# HELP telemt_pool_drain_active Active draining ME writers");
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

    let _ = writeln!(out, "# HELP telemt_pool_force_close_total Forced close events for draining writers");
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

    let _ = writeln!(out, "# HELP telemt_pool_stale_pick_total Stale writer fallback picks for new binds");
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

    let _ = writeln!(out, "# HELP telemt_me_writer_removed_total Total ME writer removals");
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
    let _ = writeln!(out, "# TYPE telemt_me_writer_removed_unexpected_total counter");
    let _ = writeln!(
        out,
        "telemt_me_writer_removed_unexpected_total {}",
        if me_allows_normal {
            stats.get_me_writer_removed_unexpected_total()
        } else {
            0
        }
    );

    let _ = writeln!(out, "# HELP telemt_me_refill_triggered_total Immediate ME refill runs started");
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
    let _ = writeln!(out, "# TYPE telemt_me_refill_skipped_inflight_total counter");
    let _ = writeln!(
        out,
        "telemt_me_refill_skipped_inflight_total {}",
        if me_allows_debug {
            stats.get_me_refill_skipped_inflight_total()
        } else {
            0
        }
    );

    let _ = writeln!(out, "# HELP telemt_me_refill_failed_total Immediate ME refill failures");
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
    let _ = writeln!(out, "# TYPE telemt_me_writer_restored_same_endpoint_total counter");
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
    let _ = writeln!(out, "# TYPE telemt_me_writer_restored_fallback_total counter");
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

    let _ = writeln!(out, "# HELP telemt_user_connections_total Per-user total connections");
    let _ = writeln!(out, "# TYPE telemt_user_connections_total counter");
    let _ = writeln!(out, "# HELP telemt_user_connections_current Per-user active connections");
    let _ = writeln!(out, "# TYPE telemt_user_connections_current gauge");
    let _ = writeln!(out, "# HELP telemt_user_octets_from_client Per-user bytes received");
    let _ = writeln!(out, "# TYPE telemt_user_octets_from_client counter");
    let _ = writeln!(out, "# HELP telemt_user_octets_to_client Per-user bytes sent");
    let _ = writeln!(out, "# TYPE telemt_user_octets_to_client counter");
    let _ = writeln!(out, "# HELP telemt_user_msgs_from_client Per-user messages received");
    let _ = writeln!(out, "# TYPE telemt_user_msgs_from_client counter");
    let _ = writeln!(out, "# HELP telemt_user_msgs_to_client Per-user messages sent");
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

    if user_enabled {
        for entry in stats.iter_user_stats() {
            let user = escape_prometheus_label_value(entry.key());
            let s = entry.value();
            let _ = writeln!(out, "telemt_user_connections_total{{user=\"{}\"}} {}", user, s.connects.load(std::sync::atomic::Ordering::Relaxed));
            let _ = writeln!(out, "telemt_user_connections_current{{user=\"{}\"}} {}", user, s.curr_connects.load(std::sync::atomic::Ordering::Relaxed));
            let _ = writeln!(out, "telemt_user_octets_from_client{{user=\"{}\"}} {}", user, s.octets_from_client.load(std::sync::atomic::Ordering::Relaxed));
            let _ = writeln!(out, "telemt_user_octets_to_client{{user=\"{}\"}} {}", user, s.octets_to_client.load(std::sync::atomic::Ordering::Relaxed));
            let _ = writeln!(out, "telemt_user_msgs_from_client{{user=\"{}\"}} {}", user, s.msgs_from_client.load(std::sync::atomic::Ordering::Relaxed));
            let _ = writeln!(out, "telemt_user_msgs_to_client{{user=\"{}\"}} {}", user, s.msgs_to_client.load(std::sync::atomic::Ordering::Relaxed));
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

        let _ = writeln!(out, "# HELP telemt_user_unique_ips_current Per-user current number of unique active IPs");
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_current gauge");
        let _ = writeln!(
            out,
            "# HELP telemt_user_unique_ips_recent_window Per-user unique IPs seen in configured observation window"
        );
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_recent_window gauge");
        let _ = writeln!(out, "# HELP telemt_user_unique_ips_limit Per-user configured unique IP limit (0 means unlimited)");
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_limit gauge");
        let _ = writeln!(out, "# HELP telemt_user_unique_ips_utilization Per-user unique IP usage ratio (0 for unlimited)");
        let _ = writeln!(out, "# TYPE telemt_user_unique_ips_utilization gauge");

        for user in unique_users {
            let current = ip_counts.get(&user).copied().unwrap_or(0);
            let limit = config.access.user_max_unique_ips.get(&user).copied().unwrap_or(0);
            let utilization = if limit > 0 {
                current as f64 / limit as f64
            } else {
                0.0
            };
            let recent = recent_counts.get(&user).copied().unwrap_or(0);
            let user_escaped = escape_prometheus_label_value(&user);
            let _ = writeln!(out, "telemt_user_unique_ips_current{{user=\"{}\"}} {}", user_escaped, current);
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_recent_window{{user=\"{}\"}} {}",
                user_escaped,
                recent
            );
            let _ = writeln!(out, "telemt_user_unique_ips_limit{{user=\"{}\"}} {}", user_escaped, limit);
            let _ = writeln!(
                out,
                "telemt_user_unique_ips_utilization{{user=\"{}\"}} {:.6}",
                user_escaped,
                utilization
            );
        }
    }

    out
}

#[cfg(test)]
mod response_tests {
    use super::build_plain_response;
    use http_body_util::BodyExt;
    use hyper::StatusCode;
    use hyper::body::Bytes;

    #[tokio::test]
    async fn build_plain_response_keeps_status_and_content_type() {
        let response = build_plain_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found\n"),
        );

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );

        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(body_bytes.as_ref(), b"not found\n");
    }

    #[tokio::test]
    async fn build_plain_response_falls_back_to_500_on_invalid_header_value() {
        let response = build_plain_response(
            StatusCode::OK,
            "text/plain\r\nX-Injection: bad",
            Bytes::from_static(b"secret-like-body\n"),
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );

        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(body_bytes.as_ref(), b"internal error\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_render_metrics_format() {
        let stats = Arc::new(Stats::new());
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

        let output = render_metrics(&stats, &config, &tracker).await;

        assert!(output.contains("telemt_connections_total 2"));
        assert!(output.contains("telemt_connections_bad_total 1"));
        assert!(output.contains("telemt_handshake_timeouts_total 1"));
        assert!(output.contains("telemt_upstream_connect_attempt_total 2"));
        assert!(output.contains("telemt_upstream_connect_success_total 1"));
        assert!(output.contains("telemt_upstream_connect_fail_total 1"));
        assert!(output.contains("telemt_upstream_connect_failfast_hard_error_total 1"));
        assert!(
            output.contains("telemt_upstream_connect_attempts_per_request{bucket=\"2\"} 1")
        );
        assert!(
            output.contains(
                "telemt_upstream_connect_duration_success_total{bucket=\"101_500ms\"} 1"
            )
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
    }

    #[tokio::test]
    async fn test_render_empty_stats() {
        let stats = Stats::new();
        let tracker = UserIpTracker::new();
        let config = ProxyConfig::default();
        let output = render_metrics(&stats, &config, &tracker).await;
        assert!(output.contains("telemt_connections_total 0"));
        assert!(output.contains("telemt_connections_bad_total 0"));
        assert!(output.contains("telemt_handshake_timeouts_total 0"));
        assert!(output.contains("telemt_user_unique_ips_current{user="));
        assert!(output.contains("telemt_user_unique_ips_recent_window{user="));
    }

    #[tokio::test]
    async fn test_render_has_type_annotations() {
        let stats = Stats::new();
        let tracker = UserIpTracker::new();
        let config = ProxyConfig::default();
        let output = render_metrics(&stats, &config, &tracker).await;
        assert!(output.contains("# TYPE telemt_uptime_seconds gauge"));
        assert!(output.contains("# TYPE telemt_connections_total counter"));
        assert!(output.contains("# TYPE telemt_connections_bad_total counter"));
        assert!(output.contains("# TYPE telemt_handshake_timeouts_total counter"));
        assert!(output.contains("# TYPE telemt_upstream_connect_attempt_total counter"));
        assert!(output.contains("# TYPE telemt_me_rpc_proxy_req_signal_sent_total counter"));
        assert!(output.contains("# TYPE telemt_me_idle_close_by_peer_total counter"));
        assert!(output.contains("# TYPE telemt_me_writer_removed_total counter"));
        assert!(output.contains(
            "# TYPE telemt_me_writer_removed_unexpected_minus_restored_total gauge"
        ));
        assert!(output.contains("# TYPE telemt_user_unique_ips_current gauge"));
        assert!(output.contains("# TYPE telemt_user_unique_ips_recent_window gauge"));
        assert!(output.contains("# TYPE telemt_user_unique_ips_limit gauge"));
        assert!(output.contains("# TYPE telemt_user_unique_ips_utilization gauge"));
    }

    #[tokio::test]
    async fn test_endpoint_integration() {
        let stats = Arc::new(Stats::new());
        let beobachten = Arc::new(BeobachtenStore::new());
        let tracker = UserIpTracker::new();
        let mut config = ProxyConfig::default();
        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_all();

        let req = Request::builder()
            .uri("/metrics")
            .body(())
            .unwrap();
        let resp = handle(req, &stats, &beobachten, &tracker, &config).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(body.as_ref()).unwrap().contains("telemt_connections_total 3"));

        config.general.beobachten = true;
        config.general.beobachten_minutes = 10;
        beobachten.record(
            "TLS-scanner",
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            Duration::from_secs(600),
        );
        let req_beob = Request::builder()
            .uri("/beobachten")
            .body(())
            .unwrap();
        let resp_beob = handle(req_beob, &stats, &beobachten, &tracker, &config)
            .await
            .unwrap();
        assert_eq!(resp_beob.status(), StatusCode::OK);
        let body_beob = resp_beob.into_body().collect().await.unwrap().to_bytes();
        let beob_text = std::str::from_utf8(body_beob.as_ref()).unwrap();
        assert!(beob_text.contains("[TLS-scanner]"));
        assert!(beob_text.contains("203.0.113.10-1"));

        let req404 = Request::builder()
            .uri("/other")
            .body(())
            .unwrap();
        let resp404 = handle(req404, &stats, &beobachten, &tracker, &config)
            .await
            .unwrap();
        assert_eq!(resp404.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
mod label_escape_tests {
    use super::escape_prometheus_label_value;

    // ── Unit tests for the escaping primitive ─────────────────────────────────

    #[test]
    fn clean_name_unchanged() {
        assert_eq!(escape_prometheus_label_value("alice"), "alice");
    }

    #[test]
    fn double_quote_is_escaped() {
        // A raw " would close the label value early in Prometheus text format.
        assert_eq!(escape_prometheus_label_value(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn backslash_is_doubled() {
        assert_eq!(escape_prometheus_label_value(r"a\b"), r"a\\b");
    }

    #[test]
    fn newline_becomes_backslash_n() {
        assert_eq!(escape_prometheus_label_value("a\nb"), r"a\nb");
    }

    #[test]
    fn combined_special_chars() {
        // Backslash followed by quote followed by newline — common injection payload.
        let input = "a\\\"\n";
        let got = escape_prometheus_label_value(input);
        assert_eq!(got, r#"a\\\"\n"#);
    }

    #[test]
    fn empty_string_unchanged() {
        assert_eq!(escape_prometheus_label_value(""), "");
    }

    #[test]
    fn unicode_passthrough() {
        // Non-ASCII is allowed verbatim; only the three control chars are escaped.
        assert_eq!(escape_prometheus_label_value("Ärger"), "Ärger");
    }
}

#[cfg(test)]
mod label_injection_tests {
    use std::sync::Arc;
    use crate::config::ProxyConfig;
    use crate::ip_tracker::UserIpTracker;
    use crate::stats::Stats;
    use super::render_metrics;

    // ── Prometheus label injection via crafted user names ─────────────────────
    //
    // Without escaping, a user name containing `"` terminates the label value
    // early in the Prometheus text-format line, allowing an attacker who controls
    // the config file to inject arbitrary fake metric lines into the scrape.

    #[tokio::test]
    async fn double_quote_in_username_does_not_inject_fake_metric() {
        // Without escaping, a `"` in the user name terminates the label value
        // early, turning the rest of the string into arbitrary metric lines.
        // The payload below would, if unescaped, inject:
        //   telemt_user_connections_total{user="x"} 99999
        //   telemt_injected_metric 1          ← fake standalone line
        let injected = "x\"} 99999\ntelemt_injected_metric 1\ntelemt_user_connections_total{user=\"dummy";

        let stats = Arc::new(Stats::new());
        stats.increment_user_connects(injected);

        let output = render_metrics(&stats, &ProxyConfig::default(), &UserIpTracker::new()).await;

        // The raw unescaped payload must not appear verbatim.
        assert!(
            !output.contains(injected),
            "Raw injection payload found verbatim in Prometheus output — escaping is broken"
        );

        // The injected fake metric name must not appear as a standalone line.
        for line in output.lines() {
            let trimmed = line.trim();
            assert!(
                !trimmed.starts_with("telemt_injected_metric"),
                "Injected fake metric appeared as a standalone Prometheus line: {trimmed}"
            );
        }

        // The global (label-less) connections total is 0 because we only called
        // increment_user_connects, not increment_connects_all.
        // If injection had succeeded, a line "telemt_connections_total 99999" would exist.
        assert!(
            !output.lines().any(|l| l.trim() == "telemt_connections_total 99999"),
            "Injected count '99999' appeared as a standalone metric value"
        );
        assert!(
            output.lines().any(|l| l.trim() == "telemt_connections_total 0"),
            "Expected 'telemt_connections_total 0' to be present"
        );
    }

    #[tokio::test]
    async fn backslash_in_username_is_escaped_in_output() {
        let user = r"user\name";

        let stats = Arc::new(Stats::new());
        stats.increment_user_connects(user);

        let output = render_metrics(&stats, &ProxyConfig::default(), &UserIpTracker::new()).await;

        // The correctly escaped form must appear.
        assert!(
            output.contains(r#"user="user\\name""#),
            "Backslash not properly escaped in output:\n{output}"
        );
        // The unescaped form must not appear as a label boundary-breaker.
        assert!(
            !output.contains(r#"user="user\name""#),
            "Unescaped backslash found in output"
        );
    }

    #[tokio::test]
    async fn newline_in_username_does_not_split_metric_line() {
        // A newline in a label value would physically split the output line,
        // making the second half look like an independent metric line.
        let user = "legit\ntelemt_spoofed_counter 1";

        let stats = Arc::new(Stats::new());
        stats.increment_user_connects(user);

        let output = render_metrics(&stats, &ProxyConfig::default(), &UserIpTracker::new()).await;

        for line in output.lines() {
            let trimmed = line.trim();
            assert!(
                !trimmed.starts_with("telemt_spoofed_counter"),
                "Newline injection created a fake metric line: {trimmed}"
            );
        }

        assert!(
            output.contains(r#"user="legit\ntelemt_spoofed_counter 1""#),
            "Newline not escaped as \\n in label value"
        );
    }

    #[tokio::test]
    async fn unique_ips_block_also_escapes_user_labels() {
        // Verify the second rendering path (per-user IP counters) is equally hardened.
        let user = r#"evil"}0 fake"#;

        let mut config = ProxyConfig::default();
        config.access.user_max_unique_ips.insert(user.to_string(), 5);

        let output = render_metrics(&Arc::new(Stats::new()), &config, &UserIpTracker::new()).await;

        // The raw payload must not appear verbatim as it would break label syntax.
        assert!(
            !output.contains(user),
            "Unescaped user name found in unique-IPs metric block"
        );

        // The correctly escaped form must be present.
        let expected_escaped = r#"user="evil\"}0 fake""#;
        assert!(
            output.contains(expected_escaped),
            "Escaped user name not found in unique-IPs metric block.\nExpected substring: {expected_escaped}\nFull output:\n{output}"
        );
    }

    #[tokio::test]
    async fn clean_username_passthrough_unmodified() {
        // Regression guard: normal user names must not be corrupted by the escaping.
        let user = "alice_01";

        let mut config = ProxyConfig::default();
        config.access.users.insert(user.to_string(), "deadbeef".to_string());

        let stats = Arc::new(Stats::new());
        stats.increment_user_connects(user);

        let output = render_metrics(&stats, &config, &UserIpTracker::new()).await;

        assert!(
            output.contains(r#"telemt_user_connections_total{user="alice_01"} 1"#),
            "Clean user name was altered by escaping: {output}"
        );
    }

    // ── Whitelist enforcement ─────────────────────────────────────────────────

    #[test]
    fn whitelist_blocks_non_matching_ip() {
        use std::net::SocketAddr;
        use ipnetwork::IpNetwork;
        let whitelist: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: SocketAddr = "203.0.113.99:12345".parse().unwrap();
        let allowed = whitelist.iter().any(|net| net.contains(peer.ip()));
        assert!(!allowed, "Non-whitelist IP was not blocked");
    }

    #[test]
    fn whitelist_allows_matching_ip() {
        use std::net::SocketAddr;
        use ipnetwork::IpNetwork;
        let whitelist: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: SocketAddr = "10.1.2.3:12345".parse().unwrap();
        let allowed = whitelist.iter().any(|net| net.contains(peer.ip()));
        assert!(allowed, "Whitelisted IP was incorrectly blocked");
    }

    #[test]
    fn empty_whitelist_allows_all() {
        use std::net::SocketAddr;
        use ipnetwork::IpNetwork;
        let whitelist: Vec<IpNetwork> = vec![];
        let peer: SocketAddr = "198.51.100.1:9999".parse().unwrap();
        // The serve_listener logic: if whitelist is empty, skip the whitelist check.
        let gated = !whitelist.is_empty() && !whitelist.iter().any(|net| net.contains(peer.ip()));
        assert!(!gated, "Non-empty whitelist check fired on empty whitelist");
    }
}
