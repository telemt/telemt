//! Masking - forward unrecognized traffic to mask host

use std::str;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::debug;
use crate::config::ProxyConfig;
use crate::stats::beobachten::BeobachtenStore;
use crate::transport::proxy_protocol::{ProxyProtocolV1Builder, ProxyProtocolV2Builder};

const MASK_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum duration for the entire masking relay.
/// Limits resource consumption from slow-loris attacks and port scanners.
const MASK_RELAY_TIMEOUT: Duration = Duration::from_secs(60);
const MASK_BUFFER_SIZE: usize = 8192;

/// Detect client type based on initial data
fn detect_client_type(data: &[u8]) -> &'static str {
    // Check for HTTP request
    if data.len() > 4
        && (data.starts_with(b"GET ") || data.starts_with(b"POST") ||
           data.starts_with(b"HEAD") || data.starts_with(b"PUT ") ||
           data.starts_with(b"DELETE") || data.starts_with(b"OPTIONS"))
    {
        return "HTTP";
    }

    // Check for TLS ClientHello (0x16 = handshake, 0x03 0x01-0x03 = TLS version)
    if data.len() > 3 && data[0] == 0x16 && data[1] == 0x03 {
        return "TLS-scanner";
    }

    // Check for SSH
    if data.starts_with(b"SSH-") {
        return "SSH";
    }

    // Port scanner (very short data)
    if data.len() < 10 {
        return "port-scanner";
    }

    "unknown"
}

/// Handle a bad client by forwarding to mask host
pub async fn handle_bad_client<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    config: &ProxyConfig,
    beobachten: &BeobachtenStore,
)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let client_type = detect_client_type(initial_data);
    if config.general.beobachten {
        let ttl = Duration::from_secs(config.general.beobachten_minutes.saturating_mul(60));
        beobachten.record(client_type, peer.ip(), ttl);
    }

    if !config.censorship.mask {
        // Masking disabled, just consume data
        consume_client_data(reader).await;
        return;
    }

    // Connect via Unix socket or TCP
    #[cfg(unix)]
    if let Some(ref sock_path) = config.censorship.mask_unix_sock {
        debug!(
            client_type = client_type,
            sock = %sock_path,
            data_len = initial_data.len(),
            "Forwarding bad client to mask unix socket"
        );

        let connect_result = timeout(MASK_TIMEOUT, UnixStream::connect(sock_path)).await;
        match connect_result {
            Ok(Ok(stream)) => {
                let (mask_read, mask_write) = stream.into_split();
                if timeout(MASK_RELAY_TIMEOUT, relay_to_mask(reader, writer, mask_read, mask_write, initial_data)).await.is_err() {
                    debug!("Mask relay timed out (unix socket)");
                }
            }
            Ok(Err(e)) => {
                debug!(error = %e, "Failed to connect to mask unix socket");
                consume_client_data(reader).await;
            }
            Err(_) => {
                debug!("Timeout connecting to mask unix socket");
                consume_client_data(reader).await;
            }
        }
        return;
    }

    let mask_host = config.censorship.mask_host.as_deref()
        .unwrap_or(&config.censorship.tls_domain);
    let mask_port = config.censorship.mask_port;

    debug!(
        client_type = client_type,
        host = %mask_host,
        port = mask_port,
        data_len = initial_data.len(),
        "Forwarding bad client to mask host"
    );

    // Connect to mask host
    let mask_addr = format!("{}:{}", mask_host, mask_port);
    let connect_result = timeout(MASK_TIMEOUT, TcpStream::connect(&mask_addr)).await;
    match connect_result {
        Ok(Ok(stream)) => {
            let proxy_header: Option<Vec<u8>> = match config.censorship.mask_proxy_protocol {
                0 => None,
                version => {
                    let header = if let Ok(local_addr) = stream.local_addr() {
                        match version {
                            2 => ProxyProtocolV2Builder::new().with_addrs(peer, local_addr).build(),
                            _ => match (peer, local_addr) {
                                (SocketAddr::V4(src), SocketAddr::V4(dst)) =>
                                    ProxyProtocolV1Builder::new().tcp4(src.into(), dst.into()).build(),
                                (SocketAddr::V6(src), SocketAddr::V6(dst)) =>
                                    ProxyProtocolV1Builder::new().tcp6(src.into(), dst.into()).build(),
                                _ =>
                                    ProxyProtocolV1Builder::new().build(),
                            },
                        }
                    } else {
                        match version {
                            2 => ProxyProtocolV2Builder::new().build(),
                            _ => ProxyProtocolV1Builder::new().build(),
                        }
                    };
                    Some(header)
                }
            };

            let (mask_read, mut mask_write) = stream.into_split();
            if let Some(header) = proxy_header {
                if mask_write.write_all(&header).await.is_err() {
                    return;
                }
            }
            if timeout(MASK_RELAY_TIMEOUT, relay_to_mask(reader, writer, mask_read, mask_write, initial_data)).await.is_err() {
                debug!("Mask relay timed out");
            }
        }
        Ok(Err(e)) => {
            debug!(error = %e, "Failed to connect to mask host");
            consume_client_data(reader).await;
        }
        Err(_) => {
            debug!("Timeout connecting to mask host");
            consume_client_data(reader).await;
        }
    }
}

/// Relay traffic between client and mask backend
async fn relay_to_mask<R, W, MR, MW>(
    mut reader: R,
    mut writer: W,
    mut mask_read: MR,
    mut mask_write: MW,
    initial_data: &[u8],
)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    MR: AsyncRead + Unpin + Send + 'static,
    MW: AsyncWrite + Unpin + Send + 'static,
{
    // Send initial data to mask host
    if mask_write.write_all(initial_data).await.is_err() {
        return;
    }

    // Relay traffic
    let c2m = tokio::spawn(async move {
        let mut buf = vec![0u8; MASK_BUFFER_SIZE];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = mask_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if mask_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let m2c = tokio::spawn(async move {
        let mut buf = vec![0u8; MASK_BUFFER_SIZE];
        loop {
            match mask_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = writer.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Wait for either to complete
    tokio::select! {
        _ = c2m => {}
        _ = m2c => {}
    }
}

/// Just consume all data from client without responding
async fn consume_client_data<R: AsyncRead + Unpin>(mut reader: R) {
    let mut buf = vec![0u8; MASK_BUFFER_SIZE];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
}
