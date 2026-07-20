//! TLS-terminating HTTP masking fallback.
//!
//! This module is used after the TeleMT/FakeTLS classifier has already decided
//! that a TLS client is not an authenticated Telegram proxy client. Instead of
//! TCP-forwarding the still-encrypted stream to an HTTPS mask backend, TeleMT can
//! terminate TLS itself with a real certificate and relay the decrypted HTTP/1.1
//! stream to a plain HTTP upstream inside the same Docker network.

use crate::config::{HttpMaskConfig, ProxyConfig};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use std::fs;
use std::io::{Cursor, Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

/// Handle a non-TeleMT TLS client by completing a normal TLS handshake and
/// relaying decrypted HTTP bytes to the configured plain HTTP upstream.
pub async fn handle_http_mask_client<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    config: &ProxyConfig,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let http_mask = &config.censorship.http_mask;
    let outcome = handle_http_mask_client_inner(
        reader,
        writer,
        initial_data,
        peer,
        http_mask,
        Duration::from_millis(config.censorship.mask_relay_timeout_ms),
    )
    .await;

    if let Err(error) = outcome {
        debug!(error = %error, "HTTP mask fallback failed");
    }
}

async fn handle_http_mask_client_inner<R, W>(
    reader: R,
    writer: W,
    initial_data: &[u8],
    peer: SocketAddr,
    http_mask: &HttpMaskConfig,
    relay_timeout: Duration,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let tls_config = build_tls_server_config(http_mask)?;
    let acceptor = TlsAcceptor::from(tls_config);
    let stream = PreloadedStream::new(reader, writer, initial_data.to_vec());

    let mut tls_stream = acceptor.accept(stream).await.map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("http_mask TLS accept failed for {peer}: {error}"),
        )
    })?;

    let (host, port) = parse_http_upstream(http_mask.upstream.as_deref())?;
    let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port)).await?.collect();
    if addrs.is_empty() {
        return Err(IoError::new(
            ErrorKind::AddrNotAvailable,
            format!("http_mask upstream {host}:{port} did not resolve"),
        ));
    }

    let mut upstream = TcpStream::connect(addrs.as_slice()).await?;
    debug!(peer = %peer, upstream = %format_args!("{host}:{port}"), "Relaying HTTP mask client");

    match timeout(
        relay_timeout,
        tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(IoError::new(
            ErrorKind::TimedOut,
            "http_mask relay timed out",
        )),
    }
}

fn build_tls_server_config(
    http_mask: &HttpMaskConfig,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let cert_file = required_setting(http_mask.cert_file.as_deref(), "cert_file")?;
    let key_file = required_setting(http_mask.key_file.as_deref(), "key_file")?;
    let certs = load_certs(cert_file)?;
    let key = load_private_key(key_file)?;

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| IoError::new(ErrorKind::InvalidInput, error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| IoError::new(ErrorKind::InvalidInput, error.to_string()))?;

    config.alpn_protocols = http_mask
        .alpn
        .iter()
        .map(|alpn| alpn.as_bytes().to_vec())
        .collect();

    if config.alpn_protocols.is_empty() {
        config.alpn_protocols.push(b"http/1.1".to_vec());
    }

    Ok(Arc::new(config))
}

fn required_setting<'a>(value: Option<&'a str>, name: &str) -> std::io::Result<&'a str> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => Ok(value),
        None => Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("censorship.http_mask.{name} is required"),
        )),
    }
}

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path)?;
    let certs = if looks_like_pem(&bytes) {
        pem_blocks(&bytes, "CERTIFICATE")?
            .into_iter()
            .map(CertificateDer::from)
            .collect()
    } else {
        vec![CertificateDer::from(bytes)]
    };

    if certs.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!("no certificates found in {path}"),
        ));
    }

    Ok(certs)
}

fn load_private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path)?;

    if looks_like_pem(&bytes) {
        if let Some(key) = pem_blocks(&bytes, "PRIVATE KEY")?.into_iter().next() {
            return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)));
        }
        if let Some(key) = pem_blocks(&bytes, "RSA PRIVATE KEY")?.into_iter().next() {
            return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key)));
        }
        if let Some(key) = pem_blocks(&bytes, "EC PRIVATE KEY")?.into_iter().next() {
            return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key)));
        }

        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!("no supported private key found in {path}"),
        ));
    }

    // DER key files do not carry their key type. Most ACME/modern tooling writes
    // PKCS#8, so try it as a sensible default when the file is not PEM encoded.
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes)))
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN ".len())
        .any(|window| window == b"-----BEGIN ")
}

fn pem_blocks(bytes: &[u8], label: &str) -> std::io::Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("PEM file is not valid UTF-8: {error}"),
        )
    })?;

    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut rest = text;

    while let Some(begin_pos) = rest.find(&begin) {
        let after_begin = &rest[begin_pos + begin.len()..];
        let Some(end_pos) = after_begin.find(&end) else {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("unterminated PEM block {label}"),
            ));
        };

        let body = &after_begin[..end_pos];
        blocks.push(decode_base64_pem_body(body)?);
        rest = &after_begin[end_pos + end.len()..];
    }

    Ok(blocks)
}

fn decode_base64_pem_body(body: &str) -> std::io::Result<Vec<u8>> {
    let mut clean = Vec::with_capacity(body.len());
    for byte in body.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        clean.push(byte);
    }

    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut chunk = [0u8; 4];
    let mut chunk_len = 0usize;

    for byte in clean {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            _ => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "invalid base64 byte in PEM block",
                ));
            }
        };

        chunk[chunk_len] = value;
        chunk_len += 1;

        if chunk_len == 4 {
            decode_base64_quad(chunk, &mut out)?;
            chunk_len = 0;
        }
    }

    if chunk_len != 0 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "invalid base64 length in PEM block",
        ));
    }

    Ok(out)
}

fn decode_base64_quad(chunk: [u8; 4], out: &mut Vec<u8>) -> std::io::Result<()> {
    if chunk[0] == 64 || chunk[1] == 64 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "invalid base64 padding in PEM block",
        ));
    }

    out.push((chunk[0] << 2) | (chunk[1] >> 4));

    if chunk[2] != 64 {
        out.push((chunk[1] << 4) | (chunk[2] >> 2));
    }

    if chunk[3] != 64 {
        if chunk[2] == 64 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "invalid base64 padding in PEM block",
            ));
        }
        out.push((chunk[2] << 6) | chunk[3]);
    }

    Ok(())
}

fn parse_http_upstream(upstream: Option<&str>) -> std::io::Result<(String, u16)> {
    let upstream = required_setting(upstream, "upstream")?;
    let normalized = if upstream.contains("://") {
        upstream.to_string()
    } else {
        format!("http://{upstream}")
    };

    let url = url::Url::parse(&normalized).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!("invalid censorship.http_mask.upstream: {error}"),
        )
    })?;

    if url.scheme() != "http" {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "censorship.http_mask.upstream must use http://",
        ));
    }

    let host = url.host_str().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidInput,
            "censorship.http_mask.upstream host is empty",
        )
    })?;
    let port = url.port_or_known_default().unwrap_or(80);
    Ok((host.to_string(), port))
}

struct PreloadedStream<R, W> {
    reader: R,
    writer: W,
    initial: Cursor<Vec<u8>>,
}

impl<R, W> PreloadedStream<R, W> {
    fn new(reader: R, writer: W, initial: Vec<u8>) -> Self {
        Self {
            reader,
            writer,
            initial: Cursor::new(initial),
        }
    }
}

impl<R, W> AsyncRead for PreloadedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.initial.position() < self.initial.get_ref().len() as u64 && buf.remaining() > 0 {
            let remaining_initial = self.initial.get_ref().len() - self.initial.position() as usize;
            let copy_len = remaining_initial.min(buf.remaining());
            let start = self.initial.position() as usize;
            let end = start + copy_len;
            let chunk = self.initial.get_ref()[start..end].to_vec();
            self.initial.set_position(end as u64);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for PreloadedStream<R, W>
where
    R: Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
