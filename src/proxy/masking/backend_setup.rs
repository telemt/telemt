use super::*;

pub(super) fn masking_beobachten_ttl(config: &ProxyConfig) -> Duration {
    let minutes = config.general.beobachten_minutes;
    let clamped = minutes.clamp(1, 24 * 60);
    Duration::from_secs(clamped.saturating_mul(60))
}

pub(super) fn build_mask_proxy_header(
    version: u8,
    peer: SocketAddr,
    local_addr: SocketAddr,
) -> Option<Vec<u8>> {
    match version {
        0 => None,
        2 => Some(
            ProxyProtocolV2Builder::new()
                .with_addrs(peer, local_addr)
                .build(),
        ),
        _ => {
            let header = match (peer, local_addr) {
                (SocketAddr::V4(src), SocketAddr::V4(dst)) => ProxyProtocolV1Builder::new()
                    .tcp4(src.into(), dst.into())
                    .build(),
                (SocketAddr::V6(src), SocketAddr::V6(dst)) => ProxyProtocolV1Builder::new()
                    .tcp6(src.into(), dst.into())
                    .build(),
                _ => ProxyProtocolV1Builder::new().build(),
            };
            Some(header)
        }
    }
}

pub(super) fn configure_mask_backend_socket(stream: &TcpStream) {
    if let Err(e) = configure_tcp_socket(stream, false, Duration::from_secs(0)) {
        debug!(error = %e, "Failed to configure mask backend socket");
    }
}

/// Handles a bad client by forwarding it to the configured mask target.
#[cfg(test)]
pub async fn handle_bad_client<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    local_addr: SocketAddr,
    config: &ProxyConfig,
    beobachten: &BeobachtenStore,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let shared = ProxySharedState::new();
    handle_bad_client_with_shared(
        reader,
        writer,
        initial_data,
        peer,
        local_addr,
        config,
        beobachten,
        shared.as_ref(),
    )
    .await;
}
