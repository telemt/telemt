use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{Full, BodyExt};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use ipnetwork::IpNetwork;
use tokio::net::TcpListener;
use tracing::{info, warn, debug};

use crate::stats::Stats;

pub async fn serve(port: u16, stats: Arc<Stats>, whitelist: Vec<IpNetwork>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "Failed to bind metrics on {}", addr);
            return;
        }
    };
    info!("Metrics endpoint: http://{}/metrics", addr);

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
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let stats = stats.clone();
                async move { handle(req, &stats) }
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

fn handle<B>(req: Request<B>, stats: &Stats) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/metrics" {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found\n")))
            .unwrap();
        return Ok(resp);
    }

    let body = render_metrics(stats);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    Ok(resp)
}

fn render_metrics(stats: &Stats) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(4096);

    let _ = writeln!(out, "# HELP telemt_uptime_seconds Proxy uptime");
    let _ = writeln!(out, "# TYPE telemt_uptime_seconds gauge");
    let _ = writeln!(out, "telemt_uptime_seconds {:.1}", stats.uptime_secs());

    let _ = writeln!(out, "# HELP telemt_connections_total Total accepted connections");
    let _ = writeln!(out, "# TYPE telemt_connections_total counter");
    let _ = writeln!(out, "telemt_connections_total {}", stats.get_connects_all());

    let _ = writeln!(out, "# HELP telemt_connections_bad_total Bad/rejected connections");
    let _ = writeln!(out, "# TYPE telemt_connections_bad_total counter");
    let _ = writeln!(out, "telemt_connections_bad_total {}", stats.get_connects_bad());

    let _ = writeln!(out, "# HELP telemt_handshake_timeouts_total Handshake timeouts");
    let _ = writeln!(out, "# TYPE telemt_handshake_timeouts_total counter");
    let _ = writeln!(out, "telemt_handshake_timeouts_total {}", stats.get_handshake_timeouts());

    let _ = writeln!(out, "# HELP telemt_me_keepalive_sent_total ME keepalive frames sent");
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_sent_total counter");
    let _ = writeln!(out, "telemt_me_keepalive_sent_total {}", stats.get_me_keepalive_sent());

    let _ = writeln!(out, "# HELP telemt_me_keepalive_failed_total ME keepalive send failures");
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_failed_total counter");
    let _ = writeln!(out, "telemt_me_keepalive_failed_total {}", stats.get_me_keepalive_failed());

    let _ = writeln!(out, "# HELP telemt_me_keepalive_pong_total ME keepalive pong replies");
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_pong_total counter");
    let _ = writeln!(out, "telemt_me_keepalive_pong_total {}", stats.get_me_keepalive_pong());

    let _ = writeln!(out, "# HELP telemt_me_keepalive_timeout_total ME keepalive ping timeouts");
    let _ = writeln!(out, "# TYPE telemt_me_keepalive_timeout_total counter");
    let _ = writeln!(out, "telemt_me_keepalive_timeout_total {}", stats.get_me_keepalive_timeout());

    let _ = writeln!(out, "# HELP telemt_me_reconnect_attempts_total ME reconnect attempts");
    let _ = writeln!(out, "# TYPE telemt_me_reconnect_attempts_total counter");
    let _ = writeln!(out, "telemt_me_reconnect_attempts_total {}", stats.get_me_reconnect_attempts());

    let _ = writeln!(out, "# HELP telemt_me_reconnect_success_total ME reconnect successes");
    let _ = writeln!(out, "# TYPE telemt_me_reconnect_success_total counter");
    let _ = writeln!(out, "telemt_me_reconnect_success_total {}", stats.get_me_reconnect_success());

    let _ = writeln!(out, "# HELP telemt_me_crc_mismatch_total ME CRC mismatches");
    let _ = writeln!(out, "# TYPE telemt_me_crc_mismatch_total counter");
    let _ = writeln!(out, "telemt_me_crc_mismatch_total {}", stats.get_me_crc_mismatch());

    let _ = writeln!(out, "# HELP telemt_me_seq_mismatch_total ME sequence mismatches");
    let _ = writeln!(out, "# TYPE telemt_me_seq_mismatch_total counter");
    let _ = writeln!(out, "telemt_me_seq_mismatch_total {}", stats.get_me_seq_mismatch());

    let _ = writeln!(out, "# HELP telemt_me_route_drop_no_conn_total ME route drops: no conn");
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_no_conn_total counter");
    let _ = writeln!(out, "telemt_me_route_drop_no_conn_total {}", stats.get_me_route_drop_no_conn());

    let _ = writeln!(out, "# HELP telemt_me_route_drop_channel_closed_total ME route drops: channel closed");
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_channel_closed_total counter");
    let _ = writeln!(out, "telemt_me_route_drop_channel_closed_total {}", stats.get_me_route_drop_channel_closed());

    let _ = writeln!(out, "# HELP telemt_me_route_drop_queue_full_total ME route drops: queue full");
    let _ = writeln!(out, "# TYPE telemt_me_route_drop_queue_full_total counter");
    let _ = writeln!(out, "telemt_me_route_drop_queue_full_total {}", stats.get_me_route_drop_queue_full());

    let _ = writeln!(out, "# HELP telemt_secure_padding_invalid_total Invalid secure frame lengths");
    let _ = writeln!(out, "# TYPE telemt_secure_padding_invalid_total counter");
    let _ = writeln!(out, "telemt_secure_padding_invalid_total {}", stats.get_secure_padding_invalid());

    let _ = writeln!(out, "# HELP telemt_desync_total Total crypto-desync detections");
    let _ = writeln!(out, "# TYPE telemt_desync_total counter");
    let _ = writeln!(out, "telemt_desync_total {}", stats.get_desync_total());

    let _ = writeln!(out, "# HELP telemt_desync_full_logged_total Full forensic desync logs emitted");
    let _ = writeln!(out, "# TYPE telemt_desync_full_logged_total counter");
    let _ = writeln!(out, "telemt_desync_full_logged_total {}", stats.get_desync_full_logged());

    let _ = writeln!(out, "# HELP telemt_desync_suppressed_total Suppressed desync forensic events");
    let _ = writeln!(out, "# TYPE telemt_desync_suppressed_total counter");
    let _ = writeln!(out, "telemt_desync_suppressed_total {}", stats.get_desync_suppressed());

    let _ = writeln!(out, "# HELP telemt_desync_frames_bucket_total Desync count by frames_ok bucket");
    let _ = writeln!(out, "# TYPE telemt_desync_frames_bucket_total counter");
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"0\"}} {}",
        stats.get_desync_frames_bucket_0()
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"1_2\"}} {}",
        stats.get_desync_frames_bucket_1_2()
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"3_10\"}} {}",
        stats.get_desync_frames_bucket_3_10()
    );
    let _ = writeln!(
        out,
        "telemt_desync_frames_bucket_total{{bucket=\"gt_10\"}} {}",
        stats.get_desync_frames_bucket_gt_10()
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

    for entry in stats.iter_user_stats() {
        let user = entry.key();
        let s = entry.value();
        let _ = writeln!(out, "telemt_user_connections_total{{user=\"{}\"}} {}", user, s.connects.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(out, "telemt_user_connections_current{{user=\"{}\"}} {}", user, s.curr_connects.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(out, "telemt_user_octets_from_client{{user=\"{}\"}} {}", user, s.octets_from_client.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(out, "telemt_user_octets_to_client{{user=\"{}\"}} {}", user, s.octets_to_client.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(out, "telemt_user_msgs_from_client{{user=\"{}\"}} {}", user, s.msgs_from_client.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(out, "telemt_user_msgs_to_client{{user=\"{}\"}} {}", user, s.msgs_to_client.load(std::sync::atomic::Ordering::Relaxed));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_metrics_format() {
        let stats = Arc::new(Stats::new());
        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_bad();
        stats.increment_handshake_timeouts();
        stats.increment_user_connects("alice");
        stats.increment_user_curr_connects("alice");
        stats.add_user_octets_from("alice", 1024);
        stats.add_user_octets_to("alice", 2048);
        stats.increment_user_msgs_from("alice");
        stats.increment_user_msgs_to("alice");
        stats.increment_user_msgs_to("alice");

        let output = render_metrics(&stats);

        assert!(output.contains("telemt_connections_total 2"));
        assert!(output.contains("telemt_connections_bad_total 1"));
        assert!(output.contains("telemt_handshake_timeouts_total 1"));
        assert!(output.contains("telemt_user_connections_total{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_connections_current{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_octets_from_client{user=\"alice\"} 1024"));
        assert!(output.contains("telemt_user_octets_to_client{user=\"alice\"} 2048"));
        assert!(output.contains("telemt_user_msgs_from_client{user=\"alice\"} 1"));
        assert!(output.contains("telemt_user_msgs_to_client{user=\"alice\"} 2"));
    }

    #[test]
    fn test_render_empty_stats() {
        let stats = Stats::new();
        let output = render_metrics(&stats);
        assert!(output.contains("telemt_connections_total 0"));
        assert!(output.contains("telemt_connections_bad_total 0"));
        assert!(output.contains("telemt_handshake_timeouts_total 0"));
        assert!(!output.contains("user="));
    }

    #[test]
    fn test_render_has_type_annotations() {
        let stats = Stats::new();
        let output = render_metrics(&stats);
        assert!(output.contains("# TYPE telemt_uptime_seconds gauge"));
        assert!(output.contains("# TYPE telemt_connections_total counter"));
        assert!(output.contains("# TYPE telemt_connections_bad_total counter"));
        assert!(output.contains("# TYPE telemt_handshake_timeouts_total counter"));
    }

    #[tokio::test]
    async fn test_endpoint_integration() {
        let stats = Arc::new(Stats::new());
        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_all();

        let req = Request::builder()
            .uri("/metrics")
            .body(())
            .unwrap();
        let resp = handle(req, &stats).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(body.as_ref()).unwrap().contains("telemt_connections_total 3"));

        let req404 = Request::builder()
            .uri("/other")
            .body(())
            .unwrap();
        let resp404 = handle(req404, &stats).unwrap();
        assert_eq!(resp404.status(), StatusCode::NOT_FOUND);
    }
}
