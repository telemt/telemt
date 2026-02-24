use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::crypto::SecureRandom;
use crate::error::ProxyError;

use super::MePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MePingFamily {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct MePingSample {
    pub dc: i32,
    pub addr: SocketAddr,
    pub connect_ms: Option<f64>,
    pub handshake_ms: Option<f64>,
    pub error: Option<String>,
    pub family: MePingFamily,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MePingReport {
    pub dc: i32,
    pub family: MePingFamily,
    pub samples: Vec<MePingSample>,
}

pub fn format_sample_line(sample: &MePingSample) -> String {
    let sign = if sample.dc >= 0 { "+" } else { "-" };
    let addr = format!("{}:{}", sample.addr.ip(), sample.addr.port());

    match (sample.connect_ms, sample.handshake_ms.as_ref(), sample.error.as_ref()) {
        (Some(conn), Some(hs), None) => format!(
            "     {sign} {addr}\tPing: {:.0} ms / RPC: {:.0} ms / OK",
            conn, hs
        ),
        (Some(conn), None, Some(err)) => format!(
            "     {sign} {addr}\tPing: {:.0} ms / RPC: FAIL ({err})",
            conn
        ),
        (None, _, Some(err)) => format!("     {sign} {addr}\tPing: FAIL ({err})"),
        (Some(conn), None, None) => format!("     {sign} {addr}\tPing: {:.0} ms / RPC: FAIL", conn),
        _ => format!("     {sign} {addr}\tPing: FAIL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample(base: MePingSample) -> MePingSample {
        base
    }

    #[test]
    fn ok_line_contains_both_timings() {
        let s = sample(MePingSample {
            dc: 4,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8888),
            connect_ms: Some(12.3),
            handshake_ms: Some(34.7),
            error: None,
            family: MePingFamily::V4,
        });
        let line = format_sample_line(&s);
        assert!(line.contains("Ping: 12 ms"));
        assert!(line.contains("RPC: 35 ms"));
        assert!(line.contains("OK"));
    }

    #[test]
    fn error_line_mentions_reason() {
        let s = sample(MePingSample {
            dc: -5,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 80),
            connect_ms: Some(10.0),
            handshake_ms: None,
            error: Some("handshake timeout".to_string()),
            family: MePingFamily::V4,
        });
        let line = format_sample_line(&s);
        assert!(line.contains("- 5.6.7.8:80"));
        assert!(line.contains("handshake timeout"));
    }
}

pub async fn run_me_ping(pool: &Arc<MePool>, rng: &SecureRandom) -> Vec<MePingReport> {
    let mut reports = Vec::new();

    let v4_map = if pool.decision.ipv4_me {
        pool.proxy_map_v4.read().await.clone()
    } else {
        HashMap::new()
    };
    let v6_map = if pool.decision.ipv6_me {
        pool.proxy_map_v6.read().await.clone()
    } else {
        HashMap::new()
    };

    let mut grouped: Vec<(MePingFamily, i32, Vec<(IpAddr, u16)>)> = Vec::new();
    for (dc, addrs) in v4_map {
        grouped.push((MePingFamily::V4, dc, addrs));
    }
    for (dc, addrs) in v6_map {
        grouped.push((MePingFamily::V6, dc, addrs));
    }

    for (family, dc, addrs) in grouped {
        let mut samples = Vec::new();
        for (ip, port) in addrs {
            let addr = SocketAddr::new(ip, port);
            let mut connect_ms = None;
            let mut handshake_ms = None;
            let mut error = None;

            match pool.connect_tcp(addr).await {
                Ok((stream, conn_rtt)) => {
                    connect_ms = Some(conn_rtt);
                    match pool.handshake_only(stream, addr, rng).await {
                        Ok(hs) => {
                            handshake_ms = Some(hs.handshake_ms);
                            // drop halves to close
                            drop(hs.rd);
                            drop(hs.wr);
                        }
                        Err(e) => {
                            error = Some(short_err(&e));
                        }
                    }
                }
                Err(e) => {
                    error = Some(short_err(&e));
                }
            }

            samples.push(MePingSample {
                dc,
                addr,
                connect_ms,
                handshake_ms,
                error,
                family,
            });
        }

        reports.push(MePingReport {
            dc,
            family,
            samples,
        });
    }

    reports
}

fn short_err(err: &ProxyError) -> String {
    match err {
        ProxyError::ConnectionTimeout { .. } => "connect timeout".to_string(),
        ProxyError::TgHandshakeTimeout => "handshake timeout".to_string(),
        ProxyError::InvalidHandshake(e) => format!("bad handshake: {e}"),
        ProxyError::Crypto(e) => format!("crypto: {e}"),
        ProxyError::Proxy(e) => format!("proxy: {e}"),
        ProxyError::Io(e) => format!("io: {e}"),
        _ => format!("{err}"),
    }
}
