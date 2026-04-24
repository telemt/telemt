#![allow(clippy::too_many_arguments)]

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{debug, warn};

use rustls::client::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::config::TlsFetchProfile;
use crate::crypto::{SecureRandom, sha256};
use crate::network::dns_overrides::resolve_socket_addr;
use crate::protocol::constants::{
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
};
use crate::tls_front::types::{
    ParsedCertificateInfo, ParsedServerHello, TlsBehaviorProfile, TlsCertPayload, TlsExtension,
    TlsFetchResult, TlsProfileSource,
};
use crate::transport::UpstreamStream;
use crate::transport::proxy_protocol::{ProxyProtocolV1Builder, ProxyProtocolV2Builder};

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

#[derive(Debug, Clone)]
pub struct TlsFetchStrategy {
    pub profiles: Vec<TlsFetchProfile>,
    pub strict_route: bool,
    pub attempt_timeout: Duration,
    pub total_budget: Duration,
    pub grease_enabled: bool,
    pub deterministic: bool,
    pub profile_cache_ttl: Duration,
}

impl TlsFetchStrategy {
    #[allow(dead_code)]
    pub fn single_attempt(connect_timeout: Duration) -> Self {
        Self {
            profiles: vec![TlsFetchProfile::CompatTls12],
            strict_route: false,
            attempt_timeout: connect_timeout.max(Duration::from_millis(1)),
            total_budget: connect_timeout.max(Duration::from_millis(1)),
            grease_enabled: false,
            deterministic: false,
            profile_cache_ttl: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProfileCacheKey {
    host: String,
    port: u16,
    sni: String,
    scope: Option<String>,
    proxy_protocol: u8,
    route_hint: RouteHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RouteHint {
    Direct,
    Upstream,
    Unix,
}

#[derive(Debug, Clone, Copy)]
struct ProfileCacheValue {
    profile: TlsFetchProfile,
    updated_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchErrorKind {
    Connect,
    Route,
    EarlyEof,
    Timeout,
    ServerHelloMissing,
    TlsAlert,
    Parse,
    Other,
}

static PROFILE_CACHE: OnceLock<DashMap<ProfileCacheKey, ProfileCacheValue>> = OnceLock::new();

fn profile_cache() -> &'static DashMap<ProfileCacheKey, ProfileCacheValue> {
    PROFILE_CACHE.get_or_init(DashMap::new)
}

fn route_hint(
    upstream: Option<&std::sync::Arc<crate::transport::UpstreamManager>>,
    unix_sock: Option<&str>,
) -> RouteHint {
    if unix_sock.is_some() {
        RouteHint::Unix
    } else if upstream.is_some() {
        RouteHint::Upstream
    } else {
        RouteHint::Direct
    }
}

fn profile_cache_key(
    host: &str,
    port: u16,
    sni: &str,
    upstream: Option<&std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
) -> ProfileCacheKey {
    ProfileCacheKey {
        host: host.to_string(),
        port,
        sni: sni.to_string(),
        scope: scope.map(ToString::to_string),
        proxy_protocol,
        route_hint: route_hint(upstream, unix_sock),
    }
}

fn classify_fetch_error(err: &anyhow::Error) -> FetchErrorKind {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::TimedOut => FetchErrorKind::Timeout,
                std::io::ErrorKind::UnexpectedEof => FetchErrorKind::EarlyEof,
                std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::AddrNotAvailable => FetchErrorKind::Connect,
                _ => FetchErrorKind::Other,
            };
        }
    }

    let message = err.to_string().to_lowercase();
    if message.contains("upstream route") {
        FetchErrorKind::Route
    } else if message.contains("serverhello not received") {
        FetchErrorKind::ServerHelloMissing
    } else if message.contains("alert") {
        FetchErrorKind::TlsAlert
    } else if message.contains("parse") {
        FetchErrorKind::Parse
    } else if message.contains("timed out") || message.contains("deadline has elapsed") {
        FetchErrorKind::Timeout
    } else if message.contains("eof") {
        FetchErrorKind::EarlyEof
    } else {
        FetchErrorKind::Other
    }
}

fn order_profiles(
    strategy: &TlsFetchStrategy,
    cache_key: Option<&ProfileCacheKey>,
    now: Instant,
) -> Vec<TlsFetchProfile> {
    let mut ordered = if strategy.profiles.is_empty() {
        vec![TlsFetchProfile::CompatTls12]
    } else {
        strategy.profiles.clone()
    };

    if strategy.profile_cache_ttl.is_zero() {
        return ordered;
    }

    let Some(key) = cache_key else {
        return ordered;
    };

    if let Some(cached) = profile_cache().get(key) {
        let age = now.saturating_duration_since(cached.updated_at);
        if age > strategy.profile_cache_ttl {
            drop(cached);
            profile_cache().remove(key);
            return ordered;
        }

        if let Some(pos) = ordered
            .iter()
            .position(|profile| *profile == cached.profile)
            && pos != 0
        {
            ordered.swap(0, pos);
        }
    }

    ordered
}

fn remember_profile_success(
    strategy: &TlsFetchStrategy,
    cache_key: Option<ProfileCacheKey>,
    profile: TlsFetchProfile,
    now: Instant,
) {
    if strategy.profile_cache_ttl.is_zero() {
        return;
    }
    let Some(key) = cache_key else {
        return;
    };
    profile_cache().insert(
        key,
        ProfileCacheValue {
            profile,
            updated_at: now,
        },
    );
}

fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
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
    config.alpn_protocols = alpn_protocols.iter().map(|proto| proto.to_vec()).collect();

    Arc::new(config)
}

fn deterministic_bytes(seed: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut chunk_seed = Vec::with_capacity(seed.len() + std::mem::size_of::<u32>());
        chunk_seed.extend_from_slice(seed.as_bytes());
        chunk_seed.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&sha256(&chunk_seed));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

fn profile_cipher_suites(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN_CHROME: &[u16] = &[
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0x009e, 0x00ff,
    ];
    const MODERN_FIREFOX: &[u16] = &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xcca9, 0xc02c, 0xc02f, 0xcca8, 0xc030, 0x009e, 0x00ff,
    ];
    const COMPAT_TLS12: &[u16] = &[
        0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca9, 0xcca8, 0x1301, 0x1302, 0x1303, 0x009e, 0x00ff,
    ];
    const LEGACY_MINIMAL: &[u16] = &[0xc02b, 0xc02f, 0x1301, 0x1302, 0x00ff];

    match profile {
        TlsFetchProfile::ModernChromeLike => MODERN_CHROME,
        TlsFetchProfile::ModernFirefoxLike => MODERN_FIREFOX,
        TlsFetchProfile::CompatTls12 => COMPAT_TLS12,
        TlsFetchProfile::LegacyMinimal => LEGACY_MINIMAL,
    }
}

fn profile_groups(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN: &[u16] = &[0x001d, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
    const COMPAT: &[u16] = &[0x001d, 0x0017];
    const LEGACY: &[u16] = &[0x0017];

    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => MODERN,
        TlsFetchProfile::CompatTls12 => COMPAT,
        TlsFetchProfile::LegacyMinimal => LEGACY,
    }
}

fn profile_sig_algs(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN: &[u16] = &[0x0804, 0x0805, 0x0403, 0x0503, 0x0806];
    const COMPAT: &[u16] = &[0x0403, 0x0503, 0x0804, 0x0805];
    const LEGACY: &[u16] = &[0x0403, 0x0804];

    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => MODERN,
        TlsFetchProfile::CompatTls12 => COMPAT,
        TlsFetchProfile::LegacyMinimal => LEGACY,
    }
}

fn profile_alpn(profile: TlsFetchProfile) -> &'static [&'static [u8]] {
    const H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];
    const HTTP11: &[&[u8]] = &[b"http/1.1"];
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => H2_HTTP11,
        TlsFetchProfile::CompatTls12 | TlsFetchProfile::LegacyMinimal => HTTP11,
    }
}

fn profile_alpn_labels(profile: TlsFetchProfile) -> &'static [&'static str] {
    const H2_HTTP11: &[&str] = &["h2", "http/1.1"];
    const HTTP11: &[&str] = &["http/1.1"];
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => H2_HTTP11,
        TlsFetchProfile::CompatTls12 | TlsFetchProfile::LegacyMinimal => HTTP11,
    }
}

fn profile_session_id_len(profile: TlsFetchProfile) -> usize {
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => 32,
        TlsFetchProfile::CompatTls12 | TlsFetchProfile::LegacyMinimal => 0,
    }
}

fn profile_supported_versions(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN: &[u16] = &[0x0304, 0x0303];
    const COMPAT: &[u16] = &[0x0303, 0x0304];
    const LEGACY: &[u16] = &[0x0303];
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => MODERN,
        TlsFetchProfile::CompatTls12 => COMPAT,
        TlsFetchProfile::LegacyMinimal => LEGACY,
    }
}

fn profile_padding_target(profile: TlsFetchProfile) -> usize {
    match profile {
        TlsFetchProfile::ModernChromeLike => 220,
        TlsFetchProfile::ModernFirefoxLike => 200,
        TlsFetchProfile::CompatTls12 => 180,
        TlsFetchProfile::LegacyMinimal => 64,
    }
}

fn grease_value(rng: &SecureRandom, deterministic: bool, seed: &str) -> u16 {
    const GREASE_VALUES: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    if deterministic {
        let idx = deterministic_bytes(seed, 1)[0] as usize % GREASE_VALUES.len();
        GREASE_VALUES[idx]
    } else {
        let idx = (rng.bytes(1)[0] as usize) % GREASE_VALUES.len();
        GREASE_VALUES[idx]
    }
}

fn build_client_hello(
    sni: &str,
    rng: &SecureRandom,
    profile: TlsFetchProfile,
    grease_enabled: bool,
    deterministic: bool,
) -> Vec<u8> {
    // === ClientHello body ===
    let mut body = Vec::new();

    // Legacy version (TLS 1.0) as in real ClientHello headers
    body.extend_from_slice(&[0x03, 0x03]);

    // Random
    if deterministic {
        body.extend_from_slice(&deterministic_bytes(&format!("tls-fetch-random:{sni}"), 32));
    } else {
        body.extend_from_slice(&rng.bytes(32));
    }

    // Use non-empty Session ID for modern TLS 1.3-like profiles to reduce middlebox friction.
    let session_id_len = profile_session_id_len(profile);
    let session_id = if session_id_len == 0 {
        Vec::new()
    } else if deterministic {
        deterministic_bytes(
            &format!("tls-fetch-session:{sni}:{}", profile.as_str()),
            session_id_len,
        )
    } else {
        rng.bytes(session_id_len)
    };
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);

    let mut cipher_suites = profile_cipher_suites(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("cipher:{sni}"));
        cipher_suites.insert(0, grease);
    }
    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    // Compression methods: null only
    body.push(1);
    body.push(0);

    // === Extensions ===
    let mut exts = Vec::new();

    let mut push_extension = |ext_type: u16, data: &[u8]| {
        exts.extend_from_slice(&ext_type.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    };

    // server_name (SNI)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::with_capacity(5 + sni_bytes.len());
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16 + 3).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    push_extension(0x0000, &sni_ext);

    // Chrome-like profile keeps browser-like ordering and extension set.
    if matches!(profile, TlsFetchProfile::ModernChromeLike) {
        // ec_point_formats: uncompressed only.
        push_extension(0x000b, &[0x01, 0x00]);
    }

    // supported_groups
    let mut groups = profile_groups(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("group:{sni}"));
        groups.insert(0, grease);
    }
    let mut groups_ext = Vec::with_capacity(2 + groups.len() * 2);
    groups_ext.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
    for g in groups {
        groups_ext.extend_from_slice(&g.to_be_bytes());
    }
    push_extension(0x000a, &groups_ext);

    if matches!(profile, TlsFetchProfile::ModernChromeLike) {
        // session_ticket
        push_extension(0x0023, &[]);
    }

    // signature_algorithms
    let mut sig_algs = profile_sig_algs(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("sigalg:{sni}"));
        sig_algs.insert(0, grease);
    }
    let mut sig_algs_ext = Vec::with_capacity(2 + sig_algs.len() * 2);
    sig_algs_ext.extend_from_slice(&(sig_algs.len() as u16 * 2).to_be_bytes());
    for a in sig_algs {
        sig_algs_ext.extend_from_slice(&a.to_be_bytes());
    }
    push_extension(0x000d, &sig_algs_ext);

    // supported_versions
    let mut versions = profile_supported_versions(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("version:{sni}"));
        versions.insert(0, grease);
    }
    let mut versions_ext = Vec::with_capacity(1 + versions.len() * 2);
    versions_ext.push((versions.len() * 2) as u8);
    for v in versions {
        versions_ext.extend_from_slice(&v.to_be_bytes());
    }
    push_extension(0x002b, &versions_ext);

    if matches!(profile, TlsFetchProfile::ModernChromeLike) {
        // psk_key_exchange_modes: psk_dhe_ke
        push_extension(0x002d, &[0x01, 0x01]);
    }

    // key_share (x25519)
    let key = gen_key_share(
        rng,
        deterministic,
        &format!("tls-fetch-keyshare:{sni}:{}", profile.as_str()),
    );
    let mut keyshare = Vec::with_capacity(4 + key.len());
    keyshare.extend_from_slice(&0x001du16.to_be_bytes());
    keyshare.extend_from_slice(&(key.len() as u16).to_be_bytes());
    keyshare.extend_from_slice(&key);
    let mut keyshare_ext = Vec::with_capacity(2 + keyshare.len());
    keyshare_ext.extend_from_slice(&(keyshare.len() as u16).to_be_bytes());
    keyshare_ext.extend_from_slice(&keyshare);
    push_extension(0x0033, &keyshare_ext);

    // ALPN
    let mut alpn_list = Vec::new();
    for proto in profile_alpn(profile) {
        alpn_list.push(proto.len() as u8);
        alpn_list.extend_from_slice(proto);
    }
    if !alpn_list.is_empty() {
        let mut alpn_ext = Vec::with_capacity(2 + alpn_list.len());
        alpn_ext.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&alpn_list);
        push_extension(0x0010, &alpn_ext);
    }

    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("ext:{sni}"));
        push_extension(grease, &[]);
    }

    // padding to reduce recognizability and keep length ~500 bytes
    let target_ext_len = profile_padding_target(profile);
    if exts.len() < target_ext_len {
        let remaining = target_ext_len - exts.len();
        if remaining > 4 {
            let pad_len = remaining - 4; // minus type+len
            exts.extend_from_slice(&0x0015u16.to_be_bytes()); // padding extension
            exts.extend_from_slice(&(pad_len as u16).to_be_bytes());
            exts.resize(exts.len() + pad_len, 0);
        }
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

fn gen_key_share(rng: &SecureRandom, deterministic: bool, seed: &str) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    if deterministic {
        scalar.copy_from_slice(&deterministic_bytes(seed, 32));
    } else {
        scalar.copy_from_slice(&rng.bytes(32));
    }
    x25519(scalar, X25519_BASEPOINT_BYTES)
}

async fn read_tls_record<S>(stream: &mut S) -> Result<(u8, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
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
        extensions.push(TlsExtension {
            ext_type: etype,
            data,
        });
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

fn derive_behavior_profile(records: &[(u8, Vec<u8>)]) -> TlsBehaviorProfile {
    let mut change_cipher_spec_count = 0u8;
    let mut app_data_record_sizes = Vec::new();

    for (record_type, body) in records {
        match *record_type {
            TLS_RECORD_CHANGE_CIPHER => {
                change_cipher_spec_count = change_cipher_spec_count.saturating_add(1);
            }
            TLS_RECORD_APPLICATION => {
                app_data_record_sizes.push(body.len());
            }
            _ => {}
        }
    }

    let mut ticket_record_sizes = Vec::new();
    while app_data_record_sizes
        .last()
        .is_some_and(|size| *size <= 256 && ticket_record_sizes.len() < 2)
    {
        if let Some(size) = app_data_record_sizes.pop() {
            ticket_record_sizes.push(size);
        }
    }
    ticket_record_sizes.reverse();

    TlsBehaviorProfile {
        change_cipher_spec_count: change_cipher_spec_count.max(1),
        app_data_record_sizes,
        ticket_record_sizes,
        source: TlsProfileSource::Raw,
    }
}

fn parse_cert_info(certs: &[CertificateDer<'static>]) -> Option<ParsedCertificateInfo> {
    let first = certs.first()?;
    let (_rem, cert) = X509Certificate::from_der(first.as_ref()).ok()?;

    let not_before = Some(cert.validity().not_before.to_datetime().unix_timestamp());
    let not_after = Some(cert.validity().not_after.to_datetime().unix_timestamp());

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let san_names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(ParsedCertificateInfo {
        not_after_unix: not_after,
        not_before_unix: not_before,
        issuer_cn,
        subject_cn,
        san_names,
    })
}

fn u24_bytes(value: usize) -> Option<[u8; 3]> {
    if value > 0x00ff_ffff {
        return None;
    }
    Some([
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ])
}

async fn connect_with_dns_override(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    if let Some(addr) = resolve_socket_addr(host, port) {
        return Ok(timeout(connect_timeout, TcpStream::connect(addr)).await??);
    }
    Ok(timeout(connect_timeout, TcpStream::connect((host, port))).await??)
}

async fn connect_tcp_with_upstream(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    strict_route: bool,
) -> Result<UpstreamStream> {
    if let Some(manager) = upstream {
        let resolved = if let Some(addr) = resolve_socket_addr(host, port) {
            Some(addr)
        } else {
            match tokio::net::lookup_host((host, port)).await {
                Ok(mut addrs) => addrs.find(|a| a.is_ipv4()),
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

fn socket_addrs_from_upstream_stream(
    stream: &UpstreamStream,
) -> (Option<SocketAddr>, Option<SocketAddr>) {
    match stream {
        UpstreamStream::Tcp(tcp) => (tcp.local_addr().ok(), tcp.peer_addr().ok()),
        UpstreamStream::Shadowsocks(_) => (None, None),
    }
}

fn build_tls_fetch_proxy_header(
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

fn encode_tls13_certificate_message(cert_chain_der: &[Vec<u8>]) -> Option<Vec<u8>> {
    if cert_chain_der.is_empty() {
        return None;
    }

    let mut certificate_list = Vec::new();
    for cert in cert_chain_der {
        if cert.is_empty() {
            return None;
        }
        certificate_list.extend_from_slice(&u24_bytes(cert.len())?);
        certificate_list.extend_from_slice(cert);
        certificate_list.extend_from_slice(&0u16.to_be_bytes()); // cert_entry extensions
    }

    // Certificate = context_len(1) + certificate_list_len(3) + entries
    let body_len = 1usize.checked_add(3)?.checked_add(certificate_list.len())?;

    let mut message = Vec::with_capacity(4 + body_len);
    message.push(0x0b); // HandshakeType::certificate
    message.extend_from_slice(&u24_bytes(body_len)?);
    message.push(0x00); // certificate_request_context length
    message.extend_from_slice(&u24_bytes(certificate_list.len())?);
    message.extend_from_slice(&certificate_list);
    Some(message)
}

async fn fetch_via_raw_tls_stream<S>(
    mut stream: S,
    sni: &str,
    connect_timeout: Duration,
    proxy_header: Option<Vec<u8>>,
    profile: TlsFetchProfile,
    grease_enabled: bool,
    deterministic: bool,
) -> Result<TlsFetchResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let rng = SecureRandom::new();
    let client_hello = build_client_hello(sni, &rng, profile, grease_enabled, deterministic);
    timeout(connect_timeout, async {
        if let Some(header) = proxy_header.as_ref() {
            stream.write_all(&header).await?;
        }
        stream.write_all(&client_hello).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await??;

    let mut records = Vec::new();
    let mut app_records_seen = 0usize;
    // Read a bounded encrypted flight: ServerHello, CCS, certificate-like data,
    // and a small number of ticket-like tail records.
    for _ in 0..8 {
        match timeout(connect_timeout, read_tls_record(&mut stream)).await {
            Ok(Ok(rec)) => {
                if rec.0 == TLS_RECORD_APPLICATION {
                    app_records_seen += 1;
                }
                records.push(rec);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
        if app_records_seen >= 4 {
            break;
        }
    }

    let mut server_hello = None;
    for (t, body) in &records {
        if *t == TLS_RECORD_HANDSHAKE && server_hello.is_none() {
            server_hello = parse_server_hello(body);
        }
    }

    let parsed = server_hello.ok_or_else(|| anyhow!("ServerHello not received"))?;
    let behavior_profile = derive_behavior_profile(&records);
    let mut app_sizes = behavior_profile.app_data_record_sizes.clone();
    app_sizes.extend_from_slice(&behavior_profile.ticket_record_sizes);
    let total_app_data_len = app_sizes.iter().sum::<usize>().max(1024);
    let app_data_records_sizes = behavior_profile
        .app_data_record_sizes
        .first()
        .copied()
        .or_else(|| behavior_profile.ticket_record_sizes.first().copied())
        .map(|size| vec![size])
        .unwrap_or_else(|| vec![total_app_data_len]);

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes,
        total_app_data_len,
        behavior_profile,
        cert_info: None,
        cert_payload: None,
    })
}

async fn fetch_via_raw_tls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
    strict_route: bool,
    profile: TlsFetchProfile,
    grease_enabled: bool,
    deterministic: bool,
) -> Result<TlsFetchResult> {
    #[cfg(unix)]
    if let Some(sock_path) = unix_sock {
        match timeout(connect_timeout, UnixStream::connect(sock_path)).await {
            Ok(Ok(stream)) => {
                debug!(
                    sni = %sni,
                    sock = %sock_path,
                    "Raw TLS fetch using mask unix socket"
                );
                let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, None, None);
                return fetch_via_raw_tls_stream(
                    stream,
                    sni,
                    connect_timeout,
                    proxy_header,
                    profile,
                    grease_enabled,
                    deterministic,
                )
                .await;
            }
            Ok(Err(e)) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    error = %e,
                    "Raw TLS unix socket connect failed, falling back to TCP"
                );
            }
            Err(_) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    "Raw TLS unix socket connect timed out, falling back to TCP"
                );
            }
        }
    }

    #[cfg(not(unix))]
    let _ = unix_sock;

    let stream =
        connect_tcp_with_upstream(host, port, connect_timeout, upstream, scope, strict_route)
            .await?;
    let (src_addr, dst_addr) = socket_addrs_from_upstream_stream(&stream);
    let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, src_addr, dst_addr);
    fetch_via_raw_tls_stream(
        stream,
        sni,
        connect_timeout,
        proxy_header,
        profile,
        grease_enabled,
        deterministic,
    )
    .await
}

async fn fetch_via_rustls_stream<S>(
    mut stream: S,
    host: &str,
    sni: &str,
    proxy_header: Option<Vec<u8>>,
    alpn_protocols: &[&[u8]],
) -> Result<TlsFetchResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // rustls handshake path for certificate and basic negotiated metadata.
    if let Some(header) = proxy_header.as_ref() {
        stream.write_all(&header).await?;
        stream.flush().await?;
    }

    let config = build_client_config(alpn_protocols);
    let connector = TlsConnector::from(config);

    let server_name = ServerName::try_from(sni.to_owned())
        .or_else(|_| ServerName::try_from(host.to_owned()))
        .map_err(|_| RustlsError::General("invalid SNI".into()))?;

    let tls_stream: TlsStream<S> = connector.connect(server_name, stream).await?;

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
    let cert_chain_der: Vec<Vec<u8>> = certs.iter().map(|c| c.as_ref().to_vec()).collect();
    let cert_payload =
        encode_tls13_certificate_message(&cert_chain_der).map(|certificate_message| {
            TlsCertPayload {
                cert_chain_der: cert_chain_der.clone(),
                certificate_message,
            }
        });

    let total_cert_len = cert_payload
        .as_ref()
        .map(|payload| payload.certificate_message.len())
        .unwrap_or_else(|| cert_chain_der.iter().map(Vec::len).sum::<usize>())
        .max(1024);
    let cert_info = parse_cert_info(&certs);

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
        has_cert_payload = cert_payload.is_some(),
        "Fetched TLS metadata via rustls"
    );

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes: app_data_records_sizes.clone(),
        total_app_data_len: app_data_records_sizes.iter().sum(),
        behavior_profile: TlsBehaviorProfile {
            change_cipher_spec_count: 1,
            app_data_record_sizes: app_data_records_sizes,
            ticket_record_sizes: Vec::new(),
            source: TlsProfileSource::Rustls,
        },
        cert_info,
        cert_payload,
    })
}

async fn fetch_via_rustls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
    strict_route: bool,
    alpn_protocols: &[&[u8]],
) -> Result<TlsFetchResult> {
    #[cfg(unix)]
    if let Some(sock_path) = unix_sock {
        match timeout(connect_timeout, UnixStream::connect(sock_path)).await {
            Ok(Ok(stream)) => {
                debug!(
                    sni = %sni,
                    sock = %sock_path,
                    "Rustls fetch using mask unix socket"
                );
                let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, None, None);
                return fetch_via_rustls_stream(stream, host, sni, proxy_header, alpn_protocols)
                    .await;
            }
            Ok(Err(e)) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    error = %e,
                    "Rustls unix socket connect failed, falling back to TCP"
                );
            }
            Err(_) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    "Rustls unix socket connect timed out, falling back to TCP"
                );
            }
        }
    }

    #[cfg(not(unix))]
    let _ = unix_sock;

    let stream =
        connect_tcp_with_upstream(host, port, connect_timeout, upstream, scope, strict_route)
            .await?;
    let (src_addr, dst_addr) = socket_addrs_from_upstream_stream(&stream);
    let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, src_addr, dst_addr);
    fetch_via_rustls_stream(stream, host, sni, proxy_header, alpn_protocols).await
}

/// Fetch real TLS metadata with an adaptive multi-profile strategy.
pub async fn fetch_real_tls_with_strategy(
    host: &str,
    port: u16,
    sni: &str,
    strategy: &TlsFetchStrategy,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
) -> Result<TlsFetchResult> {
    let attempt_timeout = strategy.attempt_timeout.max(Duration::from_millis(1));
    let total_budget = strategy.total_budget.max(Duration::from_millis(1));
    let started_at = Instant::now();
    let cache_key = profile_cache_key(
        host,
        port,
        sni,
        upstream.as_ref(),
        scope,
        proxy_protocol,
        unix_sock,
    );
    let profiles = order_profiles(strategy, Some(&cache_key), started_at);

    let mut raw_result = None;
    let mut raw_last_error: Option<anyhow::Error> = None;
    let mut raw_last_error_kind = FetchErrorKind::Other;
    let mut selected_profile = None;

    for profile in profiles {
        let elapsed = started_at.elapsed();
        if elapsed >= total_budget {
            break;
        }
        let timeout_for_attempt = attempt_timeout.min(total_budget - elapsed);
        debug!(
            sni = %sni,
            profile = profile.as_str(),
            alpn = ?profile_alpn_labels(profile),
            grease_enabled = strategy.grease_enabled,
            deterministic = strategy.deterministic,
            "TLS fetch ClientHello params (raw)"
        );

        match fetch_via_raw_tls(
            host,
            port,
            sni,
            timeout_for_attempt,
            upstream.clone(),
            scope,
            proxy_protocol,
            unix_sock,
            strategy.strict_route,
            profile,
            strategy.grease_enabled,
            strategy.deterministic,
        )
        .await
        {
            Ok(res) => {
                selected_profile = Some(profile);
                raw_result = Some(res);
                break;
            }
            Err(err) => {
                let kind = classify_fetch_error(&err);
                warn!(
                    sni = %sni,
                    profile = profile.as_str(),
                    error_kind = ?kind,
                    error = %err,
                    "Raw TLS fetch attempt failed"
                );
                raw_last_error_kind = kind;
                raw_last_error = Some(err);
                if strategy.strict_route && matches!(kind, FetchErrorKind::Route) {
                    break;
                }
            }
        }
    }

    if let Some(profile) = selected_profile {
        remember_profile_success(strategy, Some(cache_key), profile, Instant::now());
    }

    if raw_result.is_none()
        && strategy.strict_route
        && matches!(raw_last_error_kind, FetchErrorKind::Route)
    {
        if let Some(err) = raw_last_error {
            return Err(err);
        }
        return Err(anyhow!("TLS fetch strict-route failure"));
    }

    let elapsed = started_at.elapsed();
    if elapsed >= total_budget {
        return match raw_result {
            Some(raw) => Ok(raw),
            None => {
                Err(raw_last_error.unwrap_or_else(|| anyhow!("TLS fetch total budget exhausted")))
            }
        };
    }

    let rustls_timeout = attempt_timeout.min(total_budget - elapsed);
    let rustls_profile = selected_profile.unwrap_or(TlsFetchProfile::ModernChromeLike);
    let rustls_alpn_protocols = profile_alpn(rustls_profile);
    debug!(
        sni = %sni,
        profile = rustls_profile.as_str(),
        alpn = ?profile_alpn_labels(rustls_profile),
        grease_enabled = strategy.grease_enabled,
        deterministic = strategy.deterministic,
        "TLS fetch ClientHello params (rustls)"
    );
    let rustls_result = fetch_via_rustls(
        host,
        port,
        sni,
        rustls_timeout,
        upstream,
        scope,
        proxy_protocol,
        unix_sock,
        strategy.strict_route,
        rustls_alpn_protocols,
    )
    .await;

    match rustls_result {
        Ok(rustls) => {
            if let Some(mut raw) = raw_result {
                raw.cert_info = rustls.cert_info;
                raw.cert_payload = rustls.cert_payload;
                raw.behavior_profile.source = TlsProfileSource::Merged;
                debug!(sni = %sni, "Fetched TLS metadata via adaptive raw probe + rustls cert chain");
                Ok(raw)
            } else {
                Ok(rustls)
            }
        }
        Err(err) => {
            if let Some(raw) = raw_result {
                warn!(sni = %sni, error = %err, "Rustls cert fetch failed, using raw TLS metadata only");
                Ok(raw)
            } else if let Some(raw_err) = raw_last_error {
                Err(anyhow!("TLS fetch failed (raw: {raw_err}; rustls: {err})"))
            } else {
                Err(err)
            }
        }
    }
}

/// Fetch real TLS metadata for the given SNI using a single-attempt compatibility strategy.
#[allow(dead_code)]
pub async fn fetch_real_tls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
) -> Result<TlsFetchResult> {
    let strategy = TlsFetchStrategy::single_attempt(connect_timeout);
    fetch_real_tls_with_strategy(
        host,
        port,
        sni,
        &strategy,
        upstream,
        scope,
        proxy_protocol,
        unix_sock,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::{
        ProfileCacheValue, TlsFetchStrategy, build_client_hello, build_tls_fetch_proxy_header,
        derive_behavior_profile, encode_tls13_certificate_message, fetch_via_rustls_stream,
        order_profiles, profile_alpn, profile_cache, profile_cache_key,
    };
    use crate::config::TlsFetchProfile;
    use crate::crypto::SecureRandom;
    use crate::protocol::constants::{
        TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
    };
    use crate::tls_front::types::TlsProfileSource;
    use tokio::io::AsyncReadExt;

    struct ParsedClientHelloForTest {
        session_id: Vec<u8>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn read_u24(bytes: &[u8]) -> usize {
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize)
    }

    fn parse_client_hello_for_test(record: &[u8]) -> ParsedClientHelloForTest {
        assert!(record.len() >= 9, "record too short");
        assert_eq!(record[0], TLS_RECORD_HANDSHAKE, "not a handshake record");
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), 5 + record_len, "record length mismatch");

        let handshake = &record[5..];
        assert_eq!(handshake[0], 0x01, "not a ClientHello handshake");
        let hello_len = read_u24(&handshake[1..4]);
        assert_eq!(handshake.len(), 4 + hello_len, "handshake length mismatch");
        let hello = &handshake[4..];

        let mut pos = 0usize;
        pos += 2;
        pos += 32;

        let session_len = hello[pos] as usize;
        pos += 1;
        let session_id = hello[pos..pos + session_len].to_vec();
        pos += session_len;

        let cipher_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        pos += 2 + cipher_len;

        let compression_len = hello[pos] as usize;
        pos += 1 + compression_len;

        let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_len;
        assert_eq!(ext_end, hello.len(), "extensions length mismatch");

        let mut extensions = Vec::new();
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let data_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
            pos += 4;
            let data = hello[pos..pos + data_len].to_vec();
            pos += data_len;
            extensions.push((ext_type, data));
        }
        assert_eq!(pos, ext_end, "extension parse did not consume all bytes");

        ParsedClientHelloForTest {
            session_id,
            extensions,
        }
    }

    fn parse_alpn_protocols(data: &[u8]) -> Vec<Vec<u8>> {
        assert!(data.len() >= 2, "ALPN extension is too short");
        let protocols_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        assert_eq!(protocols_len + 2, data.len(), "ALPN list length mismatch");
        let mut pos = 2usize;
        let mut out = Vec::new();
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            out.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        out
    }

    async fn capture_rustls_client_hello_record(
        alpn_protocols: &'static [&'static [u8]],
    ) -> Vec<u8> {
        let (client, mut server) = tokio::io::duplex(32 * 1024);
        let fetch_task = tokio::spawn(async move {
            fetch_via_rustls_stream(client, "example.com", "example.com", None, alpn_protocols)
                .await
        });

        let mut header = [0u8; 5];
        server
            .read_exact(&mut header)
            .await
            .expect("must read client hello record header");
        let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; body_len];
        server
            .read_exact(&mut body)
            .await
            .expect("must read client hello record body");
        drop(server);

        let result = fetch_task.await.expect("fetch task must join");
        assert!(
            result.is_err(),
            "capture task should end with handshake error"
        );

        let mut record = Vec::with_capacity(5 + body_len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn test_encode_tls13_certificate_message_single_cert() {
        let cert = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let message =
            encode_tls13_certificate_message(std::slice::from_ref(&cert)).expect("message");

        assert_eq!(message[0], 0x0b);
        assert_eq!(read_u24(&message[1..4]), message.len() - 4);
        assert_eq!(message[4], 0x00);

        let cert_list_len = read_u24(&message[5..8]);
        assert_eq!(cert_list_len, cert.len() + 5);

        let cert_len = read_u24(&message[8..11]);
        assert_eq!(cert_len, cert.len());
        assert_eq!(&message[11..11 + cert.len()], cert.as_slice());
        assert_eq!(&message[11 + cert.len()..13 + cert.len()], &[0x00, 0x00]);
    }

    #[test]
    fn test_encode_tls13_certificate_message_empty_chain() {
        assert!(encode_tls13_certificate_message(&[]).is_none());
    }

    #[test]
    fn test_derive_behavior_profile_splits_ticket_like_tail_records() {
        let profile = derive_behavior_profile(&[
            (TLS_RECORD_HANDSHAKE, vec![0u8; 90]),
            (TLS_RECORD_CHANGE_CIPHER, vec![0x01]),
            (TLS_RECORD_APPLICATION, vec![0u8; 1400]),
            (TLS_RECORD_APPLICATION, vec![0u8; 220]),
            (TLS_RECORD_APPLICATION, vec![0u8; 180]),
        ]);

        assert_eq!(profile.change_cipher_spec_count, 1);
        assert_eq!(profile.app_data_record_sizes, vec![1400]);
        assert_eq!(profile.ticket_record_sizes, vec![220, 180]);
        assert_eq!(profile.source, TlsProfileSource::Raw);
    }

    #[test]
    fn test_order_profiles_prioritizes_fresh_cached_winner() {
        let strategy = TlsFetchStrategy {
            profiles: vec![
                TlsFetchProfile::ModernChromeLike,
                TlsFetchProfile::CompatTls12,
                TlsFetchProfile::LegacyMinimal,
            ],
            strict_route: true,
            attempt_timeout: Duration::from_secs(1),
            total_budget: Duration::from_secs(2),
            grease_enabled: false,
            deterministic: false,
            profile_cache_ttl: Duration::from_secs(60),
        };
        let cache_key = profile_cache_key(
            "mask.example",
            443,
            "tls.example",
            None,
            Some("tls"),
            0,
            None,
        );
        profile_cache().remove(&cache_key);
        profile_cache().insert(
            cache_key.clone(),
            ProfileCacheValue {
                profile: TlsFetchProfile::CompatTls12,
                updated_at: Instant::now(),
            },
        );

        let ordered = order_profiles(&strategy, Some(&cache_key), Instant::now());
        assert_eq!(ordered[0], TlsFetchProfile::CompatTls12);
        profile_cache().remove(&cache_key);
    }

    #[test]
    fn test_order_profiles_drops_expired_cached_winner() {
        let strategy = TlsFetchStrategy {
            profiles: vec![
                TlsFetchProfile::ModernFirefoxLike,
                TlsFetchProfile::CompatTls12,
            ],
            strict_route: true,
            attempt_timeout: Duration::from_secs(1),
            total_budget: Duration::from_secs(2),
            grease_enabled: false,
            deterministic: false,
            profile_cache_ttl: Duration::from_secs(5),
        };
        let cache_key =
            profile_cache_key("mask2.example", 443, "tls2.example", None, None, 0, None);
        profile_cache().remove(&cache_key);
        profile_cache().insert(
            cache_key.clone(),
            ProfileCacheValue {
                profile: TlsFetchProfile::CompatTls12,
                updated_at: Instant::now() - Duration::from_secs(6),
            },
        );

        let ordered = order_profiles(&strategy, Some(&cache_key), Instant::now());
        assert_eq!(ordered[0], TlsFetchProfile::ModernFirefoxLike);
        assert!(profile_cache().get(&cache_key).is_none());
    }

    #[test]
    fn test_deterministic_client_hello_is_stable() {
        let rng = SecureRandom::new();
        let first = build_client_hello(
            "stable.example",
            &rng,
            TlsFetchProfile::ModernChromeLike,
            true,
            true,
        );
        let second = build_client_hello(
            "stable.example",
            &rng,
            TlsFetchProfile::ModernChromeLike,
            true,
            true,
        );

        assert_eq!(first, second);
    }

    #[test]
    fn test_raw_client_hello_alpn_matches_profile() {
        let rng = SecureRandom::new();
        for profile in [
            TlsFetchProfile::ModernChromeLike,
            TlsFetchProfile::ModernFirefoxLike,
            TlsFetchProfile::CompatTls12,
            TlsFetchProfile::LegacyMinimal,
        ] {
            let hello = build_client_hello("alpn.example", &rng, profile, false, true);
            let parsed = parse_client_hello_for_test(&hello);
            let alpn_ext = parsed
                .extensions
                .iter()
                .find(|(ext_type, _)| *ext_type == 0x0010)
                .expect("ALPN extension must exist");
            let parsed_alpn = parse_alpn_protocols(&alpn_ext.1);
            let expected_alpn = profile_alpn(profile)
                .iter()
                .map(|proto| proto.to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                parsed_alpn,
                expected_alpn,
                "ALPN mismatch for {}",
                profile.as_str()
            );
        }
    }

    #[test]
    fn test_modern_chrome_like_browser_extension_layout() {
        let rng = SecureRandom::new();
        let hello = build_client_hello(
            "chrome.example",
            &rng,
            TlsFetchProfile::ModernChromeLike,
            false,
            true,
        );
        let parsed = parse_client_hello_for_test(&hello);
        assert_eq!(
            parsed.session_id.len(),
            32,
            "modern chrome must use non-empty session id"
        );

        let extension_ids = parsed
            .extensions
            .iter()
            .map(|(ext_type, _)| *ext_type)
            .collect::<Vec<_>>();
        let expected_prefix = [
            0x0000, 0x000b, 0x000a, 0x0023, 0x000d, 0x002b, 0x002d, 0x0033, 0x0010,
        ];
        assert!(
            extension_ids.as_slice().starts_with(&expected_prefix),
            "unexpected extension order: {extension_ids:?}"
        );
        assert!(
            extension_ids.contains(&0x0015),
            "modern chrome profile should include padding extension"
        );

        let key_share = parsed
            .extensions
            .iter()
            .find(|(ext_type, _)| *ext_type == 0x0033)
            .expect("key_share extension must exist");
        let key_share_data = &key_share.1;
        assert!(
            key_share_data.len() >= 2 + 4 + 32,
            "key_share payload is too short"
        );
        let entry_len = u16::from_be_bytes([key_share_data[0], key_share_data[1]]) as usize;
        assert_eq!(
            entry_len,
            key_share_data.len() - 2,
            "key_share list length mismatch"
        );
        let group = u16::from_be_bytes([key_share_data[2], key_share_data[3]]);
        let key_len = u16::from_be_bytes([key_share_data[4], key_share_data[5]]) as usize;
        let key = &key_share_data[6..6 + key_len];
        assert_eq!(group, 0x001d, "key_share group must be x25519");
        assert_eq!(key_len, 32, "x25519 key length must be 32");
        assert!(
            key.iter().any(|b| *b != 0),
            "x25519 key must not be all zero"
        );
    }

    #[test]
    fn test_fallback_profiles_keep_compat_extension_set() {
        let rng = SecureRandom::new();
        for profile in [
            TlsFetchProfile::ModernFirefoxLike,
            TlsFetchProfile::CompatTls12,
            TlsFetchProfile::LegacyMinimal,
        ] {
            let hello = build_client_hello("fallback.example", &rng, profile, false, true);
            let parsed = parse_client_hello_for_test(&hello);
            let extension_ids = parsed
                .extensions
                .iter()
                .map(|(ext_type, _)| *ext_type)
                .collect::<Vec<_>>();

            assert!(extension_ids.contains(&0x0000), "SNI extension must exist");
            assert!(
                extension_ids.contains(&0x000a),
                "supported_groups extension must exist"
            );
            assert!(
                extension_ids.contains(&0x000d),
                "signature_algorithms extension must exist"
            );
            assert!(
                extension_ids.contains(&0x002b),
                "supported_versions extension must exist"
            );
            assert!(
                extension_ids.contains(&0x0033),
                "key_share extension must exist"
            );
            assert!(extension_ids.contains(&0x0010), "ALPN extension must exist");
            assert!(
                !extension_ids.contains(&0x000b),
                "ec_point_formats must stay chrome-only"
            );
            assert!(
                !extension_ids.contains(&0x0023),
                "session_ticket must stay chrome-only"
            );
            assert!(
                !extension_ids.contains(&0x002d),
                "psk_key_exchange_modes must stay chrome-only"
            );

            let expected_session_len = if matches!(profile, TlsFetchProfile::ModernFirefoxLike) {
                32
            } else {
                0
            };
            assert_eq!(
                parsed.session_id.len(),
                expected_session_len,
                "unexpected session id length for {}",
                profile.as_str()
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_rustls_client_hello_alpn_matches_selected_profile() {
        for profile in [
            TlsFetchProfile::ModernChromeLike,
            TlsFetchProfile::CompatTls12,
            TlsFetchProfile::LegacyMinimal,
        ] {
            let record = capture_rustls_client_hello_record(profile_alpn(profile)).await;
            let parsed = parse_client_hello_for_test(&record);
            let alpn_ext = parsed
                .extensions
                .iter()
                .find(|(ext_type, _)| *ext_type == 0x0010)
                .expect("ALPN extension must exist");
            let parsed_alpn = parse_alpn_protocols(&alpn_ext.1);
            let expected_alpn = profile_alpn(profile)
                .iter()
                .map(|proto| proto.to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                parsed_alpn,
                expected_alpn,
                "rustls ALPN mismatch for {}",
                profile.as_str()
            );
        }
    }

    #[test]
    fn test_build_tls_fetch_proxy_header_v2_with_tcp_addrs() {
        let src: SocketAddr = "198.51.100.10:42000".parse().expect("valid src");
        let dst: SocketAddr = "203.0.113.20:443".parse().expect("valid dst");
        let header = build_tls_fetch_proxy_header(2, Some(src), Some(dst)).expect("header");

        assert_eq!(
            &header[..12],
            &[
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
            ]
        );
        assert_eq!(header[12], 0x21);
        assert_eq!(header[13], 0x11);
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);
        assert_eq!(&header[16..20], &[198, 51, 100, 10]);
        assert_eq!(&header[20..24], &[203, 0, 113, 20]);
        assert_eq!(u16::from_be_bytes([header[24], header[25]]), 42000);
        assert_eq!(u16::from_be_bytes([header[26], header[27]]), 443);
    }

    #[test]
    fn test_build_tls_fetch_proxy_header_v2_mixed_family_falls_back_to_local_command() {
        let src: SocketAddr = "198.51.100.10:42000".parse().expect("valid src");
        let dst: SocketAddr = "[2001:db8::20]:443".parse().expect("valid dst");
        let header = build_tls_fetch_proxy_header(2, Some(src), Some(dst)).expect("header");

        assert_eq!(header[12], 0x20);
        assert_eq!(header[13], 0x00);
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 0);
    }

    #[test]
    fn test_build_tls_fetch_proxy_header_v1_with_tcp_addrs() {
        let src: SocketAddr = "198.51.100.10:42000".parse().expect("valid src");
        let dst: SocketAddr = "203.0.113.20:443".parse().expect("valid dst");
        let header = build_tls_fetch_proxy_header(1, Some(src), Some(dst)).expect("header");

        assert_eq!(
            header,
            b"PROXY TCP4 198.51.100.10 203.0.113.20 42000 443\r\n"
        );
    }
}
