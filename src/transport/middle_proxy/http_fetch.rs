use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::header::{CONNECTION, DATE, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::{ProxyError, Result};
use crate::network::dns_overrides::resolve_socket_addr;
use crate::transport::{UpstreamManager, UpstreamStream};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct HttpsGetResponse {
    pub(crate) status: u16,
    pub(crate) date_header: Option<String>,
    pub(crate) body: Vec<u8>,
}

fn build_tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("HTTPS fetch rustls protocol versions must be valid")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
}

fn extract_host_port_path(url: &str) -> Result<(String, u16, String)> {
    let parsed =
        url::Url::parse(url).map_err(|e| ProxyError::Proxy(format!("invalid URL '{url}': {e}")))?;
    if parsed.scheme() != "https" {
        return Err(ProxyError::Proxy(format!(
            "unsupported URL scheme '{}': only https is supported",
            parsed.scheme()
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Proxy(format!("URL has no host: {url}")))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ProxyError::Proxy(format!("URL has no known port: {url}")))?;

    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }

    Ok((host, port, path))
}

async fn resolve_target_addr(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    if let Some(addr) = resolve_socket_addr(host, port) {
        return Ok(addr);
    }

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ProxyError::Proxy(format!("DNS resolve failed for {host}:{port}: {e}")))?
        .collect();

    if let Some(addr) = addrs.iter().copied().find(|addr| addr.is_ipv4()) {
        return Ok(addr);
    }

    addrs
        .first()
        .copied()
        .ok_or_else(|| ProxyError::Proxy(format!("DNS returned no addresses for {host}:{port}")))
}

async fn connect_https_transport(
    host: &str,
    port: u16,
    upstream: Option<Arc<UpstreamManager>>,
) -> Result<UpstreamStream> {
    if let Some(manager) = upstream {
        let target = resolve_target_addr(host, port).await?;
        return timeout(HTTP_CONNECT_TIMEOUT, manager.connect(target, None, None))
            .await
            .map_err(|_| ProxyError::Proxy(format!("upstream connect timeout for {host}:{port}")))?
            .map_err(|e| {
                ProxyError::Proxy(format!("upstream connect failed for {host}:{port}: {e}"))
            });
    }

    if let Some(addr) = resolve_socket_addr(host, port) {
        let stream = timeout(HTTP_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| ProxyError::Proxy(format!("connect timeout for {host}:{port}")))?
            .map_err(|e| ProxyError::Proxy(format!("connect failed for {host}:{port}: {e}")))?;
        return Ok(UpstreamStream::Tcp(stream));
    }

    let stream = timeout(HTTP_CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| ProxyError::Proxy(format!("connect timeout for {host}:{port}")))?
        .map_err(|e| ProxyError::Proxy(format!("connect failed for {host}:{port}: {e}")))?;
    Ok(UpstreamStream::Tcp(stream))
}

pub(crate) async fn https_get(
    url: &str,
    upstream: Option<Arc<UpstreamManager>>,
) -> Result<HttpsGetResponse> {
    let (host, port, path_and_query) = extract_host_port_path(url)?;
    let stream = connect_https_transport(&host, port, upstream).await?;

    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| ProxyError::Proxy(format!("invalid TLS server name: {host}")))?;
    let connector = TlsConnector::from(build_tls_client_config());
    let tls_stream = timeout(HTTP_REQUEST_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| ProxyError::Proxy(format!("TLS handshake timeout for {host}:{port}")))?
        .map_err(|e| ProxyError::Proxy(format!("TLS handshake failed for {host}:{port}: {e}")))?;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .map_err(|e| ProxyError::Proxy(format!("HTTP handshake failed for {host}:{port}: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            debug!(error = %e, "HTTPS fetch connection task failed");
        }
    });

    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    let request = Request::builder()
        .method(Method::GET)
        .uri(path_and_query)
        .header(HOST, host_header)
        .header(USER_AGENT, "telemt-middle-proxy/1")
        .header(CONNECTION, "close")
        .body(Empty::<bytes::Bytes>::new())
        .map_err(|e| ProxyError::Proxy(format!("build HTTP request failed for {url}: {e}")))?;

    let response = timeout(HTTP_REQUEST_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| ProxyError::Proxy(format!("HTTP request timeout for {url}")))?
        .map_err(|e| ProxyError::Proxy(format!("HTTP request failed for {url}: {e}")))?;

    let status = response.status().as_u16();
    let date_header = response
        .headers()
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let body = timeout(HTTP_REQUEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| ProxyError::Proxy(format!("HTTP body read timeout for {url}")))?
        .map_err(|e| ProxyError::Proxy(format!("HTTP body read failed for {url}: {e}")))?
        .to_bytes()
        .to_vec();

    Ok(HttpsGetResponse {
        status,
        date_header,
        body,
    })
}
