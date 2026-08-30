use super::*;

pub(super) async fn connect_with_dns_override(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    Ok(timeout(connect_timeout, TcpStream::connect((host, port))).await??)
}

pub(super) async fn connect_tcp_with_upstream(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    strict_route: bool,
) -> Result<UpstreamStream> {
    if let Some(manager) = upstream {
        let resolved = match manager.resolve_hostname(host, port).await {
            Ok(addr) => Some(addr),
            Err(e) => {
                if strict_route {
                    return Err(anyhow!(
                        "upstream route DNS resolution failed for {host}:{port}: {e}"
                    ));
                }
                warn!(
                    host = %host,
                    port = port,
                    scope = ?scope,
                    error = %e,
                    "Upstream DNS resolution failed, using direct connect"
                );
                None
            }
        };

        if let Some(addr) = resolved {
            match manager.connect(addr, None, scope).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    if strict_route {
                        return Err(anyhow!(
                            "upstream route connect failed for {host}:{port}: {e}"
                        ));
                    }
                    warn!(
                        host = %host,
                        port = port,
                        scope = ?scope,
                        error = %e,
                        "Upstream connect failed, using direct connect"
                    );
                    return Ok(UpstreamStream::Tcp(
                        timeout(connect_timeout, TcpStream::connect(addr)).await??,
                    ));
                }
            }
        } else if strict_route {
            return Err(anyhow!(
                "upstream route resolution produced no usable address for {host}:{port}"
            ));
        }
    }
    Ok(UpstreamStream::Tcp(
        connect_with_dns_override(host, port, connect_timeout).await?,
    ))
}

pub(super) fn socket_addrs_from_upstream_stream(
    stream: &UpstreamStream,
) -> (Option<SocketAddr>, Option<SocketAddr>) {
    match stream {
        UpstreamStream::Tcp(tcp) => (tcp.local_addr().ok(), tcp.peer_addr().ok()),
        UpstreamStream::Shadowsocks(_) => (None, None),
    }
}

pub(super) fn build_tls_fetch_proxy_header(
    proxy_protocol: u8,
    src_addr: Option<SocketAddr>,
    dst_addr: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    match proxy_protocol {
        0 => None,
        2 => {
            let header = match (src_addr, dst_addr) {
                (Some(src @ SocketAddr::V4(_)), Some(dst @ SocketAddr::V4(_)))
                | (Some(src @ SocketAddr::V6(_)), Some(dst @ SocketAddr::V6(_))) => {
                    ProxyProtocolV2Builder::new().with_addrs(src, dst).build()
                }
                _ => ProxyProtocolV2Builder::new().build(),
            };
            Some(header)
        }
        _ => {
            let header = match (src_addr, dst_addr) {
                (Some(SocketAddr::V4(src)), Some(SocketAddr::V4(dst))) => {
                    ProxyProtocolV1Builder::new()
                        .tcp4(src.into(), dst.into())
                        .build()
                }
                (Some(SocketAddr::V6(src)), Some(SocketAddr::V6(dst))) => {
                    ProxyProtocolV1Builder::new()
                        .tcp6(src.into(), dst.into())
                        .build()
                }
                _ => ProxyProtocolV1Builder::new().build(),
            };
            Some(header)
        }
    }
}
