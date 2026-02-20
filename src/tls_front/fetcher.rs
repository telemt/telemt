use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError};

use crate::crypto::SecureRandom;
use crate::protocol::constants::{TLS_RECORD_APPLICATION, TLS_RECORD_HANDSHAKE, TLS_VERSION};
use crate::tls_front::types::{ParsedServerHello, TlsExtension, TlsFetchResult};

/// No-op verifier: accept any certificate (we only need lengths and metadata).
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PSS_SHA256,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
        ]
    }
}

fn build_client_config() -> Arc<ClientConfig> {
    let root = rustls::RootCertStore::empty();

    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("protocol versions")
        .with_root_certificates(root)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerify));

    Arc::new(config)
}

fn build_client_hello(sni: &str, rng: &SecureRandom) -> Vec<u8> {
    // === ClientHello body ===
    let mut body = Vec::new();

    // Legacy version (TLS 1.0) as in real ClientHello headers
    body.extend_from_slice(&[0x03, 0x03]);

    // Random
    body.extend_from_slice(&rng.bytes(32));

    // Session ID: empty
    body.push(0);

    // Cipher suites (common minimal set, TLS1.3 + a few 1.2 fallbacks)
    let cipher_suites: [u8; 10] = [
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA (legacy)
        0x00, 0xff, // RENEGOTIATION_INFO_SCSV
    ];
    body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_suites);

    // Compression methods: null only
    body.push(1);
    body.push(0);

    // === Extensions ===
    let mut exts = Vec::new();

    // server_name (SNI)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::with_capacity(5 + sni_bytes.len());
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16 + 3).to_be_bytes());
    sni_ext.push(0); // host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);

    // supported_groups
    let groups: [u16; 2] = [0x001d, 0x0017]; // x25519, secp256r1
    exts.extend_from_slice(&0x000au16.to_be_bytes());
    exts.extend_from_slice(&((2 + groups.len() * 2) as u16).to_be_bytes());
    exts.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
    for g in groups { exts.extend_from_slice(&g.to_be_bytes()); }

    // signature_algorithms
    let sig_algs: [u16; 4] = [0x0804, 0x0805, 0x0403, 0x0503]; // rsa_pss_rsae_sha256/384, ecdsa_secp256r1_sha256, rsa_pkcs1_sha256
    exts.extend_from_slice(&0x000du16.to_be_bytes());
    exts.extend_from_slice(&((2 + sig_algs.len() * 2) as u16).to_be_bytes());
    exts.extend_from_slice(&(sig_algs.len() as u16 * 2).to_be_bytes());
    for a in sig_algs { exts.extend_from_slice(&a.to_be_bytes()); }

    // supported_versions (TLS1.3 + TLS1.2)
    let versions: [u16; 2] = [0x0304, 0x0303];
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&((1 + versions.len() * 2) as u16).to_be_bytes());
    exts.push((versions.len() * 2) as u8);
    for v in versions { exts.extend_from_slice(&v.to_be_bytes()); }

    // key_share (x25519)
    let key = gen_key_share(rng);
    let mut keyshare = Vec::with_capacity(4 + key.len());
    keyshare.extend_from_slice(&0x001du16.to_be_bytes()); // group
    keyshare.extend_from_slice(&(key.len() as u16).to_be_bytes());
    keyshare.extend_from_slice(&key);
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    exts.extend_from_slice(&((2 + keyshare.len()) as u16).to_be_bytes());
    exts.extend_from_slice(&(keyshare.len() as u16).to_be_bytes());
    exts.extend_from_slice(&keyshare);

    // ALPN (http/1.1)
    let alpn_proto = b"http/1.1";
    exts.extend_from_slice(&0x0010u16.to_be_bytes());
    exts.extend_from_slice(&((2 + 1 + alpn_proto.len()) as u16).to_be_bytes());
    exts.extend_from_slice(&((1 + alpn_proto.len()) as u16).to_be_bytes());
    exts.push(alpn_proto.len() as u8);
    exts.extend_from_slice(alpn_proto);

    // padding to reduce recognizability and keep length ~500 bytes
    if exts.len() < 180 {
        let pad_len = 180 - exts.len();
        exts.extend_from_slice(&0x0015u16.to_be_bytes()); // padding extension
        exts.extend_from_slice(&(pad_len as u16 + 2).to_be_bytes());
        exts.extend_from_slice(&(pad_len as u16).to_be_bytes());
        exts.resize(exts.len() + pad_len, 0);
    }

    // Extensions length prefix
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // === Handshake wrapper ===
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len_bytes = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&len_bytes[1..4]);
    handshake.extend_from_slice(&body);

    // === Record ===
    let mut record = Vec::new();
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // legacy record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

fn gen_key_share(rng: &SecureRandom) -> [u8; 32] {
    let mut key = [0u8; 32];
    key.copy_from_slice(&rng.bytes(32));
    key
}

async fn read_tls_record(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok((header[0], body))
}

fn parse_server_hello(body: &[u8]) -> Option<ParsedServerHello> {
    if body.len() < 4 || body[0] != 0x02 {
        return None;
    }

    let msg_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    if msg_len + 4 > body.len() {
        return None;
    }

    let mut pos = 4;
    let version = [*body.get(pos)?, *body.get(pos + 1)?];
    pos += 2;

    let mut random = [0u8; 32];
    random.copy_from_slice(body.get(pos..pos + 32)?);
    pos += 32;

    let session_len = *body.get(pos)? as usize;
    pos += 1;
    let session_id = body.get(pos..pos + session_len)?.to_vec();
    pos += session_len;

    let cipher_suite = [*body.get(pos)?, *body.get(pos + 1)?];
    pos += 2;

    let compression = *body.get(pos)?;
    pos += 1;

    let ext_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let ext_end = pos.checked_add(ext_len)?;
    if ext_end > body.len() {
        return None;
    }

    let mut extensions = Vec::new();
    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let data = body.get(pos..pos + elen)?.to_vec();
        pos += elen;
        extensions.push(TlsExtension { ext_type: etype, data });
    }

    Some(ParsedServerHello {
        version,
        random,
        session_id,
        cipher_suite,
        compression,
        extensions,
    })
}

async fn fetch_via_raw_tls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
) -> Result<TlsFetchResult> {
    let addr = format!("{host}:{port}");
    let mut stream = timeout(connect_timeout, TcpStream::connect(addr)).await??;

    let rng = SecureRandom::new();
    let client_hello = build_client_hello(sni, &rng);
    timeout(connect_timeout, async {
        stream.write_all(&client_hello).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await??;

    let mut records = Vec::new();
    // Read up to 4 records: ServerHello, CCS, and up to two ApplicationData.
    for _ in 0..4 {
        match timeout(connect_timeout, read_tls_record(&mut stream)).await {
            Ok(Ok(rec)) => records.push(rec),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        }
        if records.len() >= 3 && records.iter().any(|(t, _)| *t == TLS_RECORD_APPLICATION) {
            break;
        }
    }

    let mut app_sizes = Vec::new();
    let mut server_hello = None;
    for (t, body) in &records {
        if *t == TLS_RECORD_HANDSHAKE && server_hello.is_none() {
            server_hello = parse_server_hello(body);
        } else if *t == TLS_RECORD_APPLICATION {
            app_sizes.push(body.len());
        }
    }

    let parsed = server_hello.ok_or_else(|| anyhow!("ServerHello not received"))?;
    let total_app_data_len = app_sizes.iter().sum::<usize>().max(1024);

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes: if app_sizes.is_empty() {
            vec![total_app_data_len]
        } else {
            app_sizes
        },
        total_app_data_len,
    })
}

/// Fetch real TLS metadata for the given SNI: negotiated cipher and cert lengths.
pub async fn fetch_real_tls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
) -> Result<TlsFetchResult> {
    // Preferred path: raw TLS probe for accurate record sizing
    match fetch_via_raw_tls(host, port, sni, connect_timeout).await {
        Ok(res) => return Ok(res),
        Err(e) => {
            warn!(sni = %sni, error = %e, "Raw TLS fetch failed, falling back to rustls");
        }
    }

    // Fallback: rustls handshake to at least get certificate sizes
    let addr = format!("{host}:{port}");
    let stream = timeout(connect_timeout, TcpStream::connect(addr)).await??;

    let config = build_client_config();
    let connector = TlsConnector::from(config);

    let server_name = ServerName::try_from(sni.to_owned())
        .or_else(|_| ServerName::try_from(host.to_owned()))
        .map_err(|_| RustlsError::General("invalid SNI".into()))?;

    let tls_stream: TlsStream<TcpStream> = connector.connect(server_name, stream).await?;

    // Extract negotiated parameters and certificates
    let (_io, session) = tls_stream.get_ref();
    let cipher_suite = session
        .negotiated_cipher_suite()
        .map(|s| u16::from(s.suite()).to_be_bytes())
        .unwrap_or([0x13, 0x01]);

    let certs: Vec<CertificateDer<'static>> = session
        .peer_certificates()
        .map(|slice| slice.to_vec())
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
        "Fetched TLS metadata via rustls"
    );

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes: app_data_records_sizes.clone(),
        total_app_data_len: app_data_records_sizes.iter().sum(),
    })
}
