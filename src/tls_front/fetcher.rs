use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use rustls::client::{ClientConfig, ServerCertVerifier, ServerName};
use rustls::{DigitallySignedStruct, Error as RustlsError};
use rustls::pki_types::{ServerName as PkiServerName, UnixTime, CertificateDer};

use crate::tls_front::types::{ParsedServerHello, TlsFetchResult};

/// No-op verifier: accept any certificate (we only need lengths and metadata).
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &PkiServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::ServerCertVerified, RustlsError> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, RustlsError> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, RustlsError> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }
}

fn build_client_config() -> Arc<ClientConfig> {
    let mut root = rustls::RootCertStore::empty();
    // Optionally load system roots; failure is non-fatal.
    let _ = root.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Arc::new(
        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_root_certificates(root)
            .with_no_client_auth(),
    )
}

/// Try to fetch real TLS metadata for the given SNI.
pub async fn fetch_real_tls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
) -> anyhow::Result<TlsFetchResult> {
    let addr = format!("{}:{}", host, port);
    let stream = timeout(connect_timeout, TcpStream::connect(addr)).await??;

    let config = build_client_config();
    let connector = TlsConnector::from(config);

    let server_name = ServerName::try_from(sni)
        .or_else(|_| ServerName::try_from(host))
        .map_err(|_| RustlsError::General("invalid SNI".into()))?;

    let mut tls_stream: TlsStream<TcpStream> = connector.connect(server_name, stream).await?;

    // Extract negotiated parameters and certificates
    let (session, _io) = tls_stream.get_ref();
    let cipher_suite = session
        .negotiated_cipher_suite()
        .map(|s| s.suite().get_u16().to_be_bytes())
        .unwrap_or([0x13, 0x01]);

    let certs: Vec<CertificateDer<'static>> = session
        .peer_certificates()
        .map(|slice| slice.iter().cloned().collect())
        .unwrap_or_default();

    let total_cert_len: usize = certs.iter().map(|c| c.len()).sum::<usize>().max(1024);

    // Heuristic: split across two records if large to mimic real servers a bit.
    let app_data_records_sizes = if total_cert_len > 3000 {
        vec![total_cert_len / 2, total_cert_len - total_cert_len / 2]
    } else {
        vec![total_cert_len]
    };

    let parsed = ParsedServerHello {
        version: [0x03, 0x03],
        random: [0u8; 32],
        session_id: Vec::new(),
        cipher_suite,
        compression: 0,
        extensions: Vec::new(),
    };

    debug!(
        sni = %sni,
        len = total_cert_len,
        cipher = format!("0x{:04x}", u16::from_be_bytes(cipher_suite)),
        "Fetched TLS metadata"
    );

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes: app_data_records_sizes.clone(),
        total_app_data_len: app_data_records_sizes.iter().sum(),
    })
}
