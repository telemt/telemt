#![allow(clippy::too_many_arguments)]

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use ml_kem::{DecapsulationKey as MlKemDecapsulationKey, KeyExport, MlKem768, Seed as MlKemSeed};
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
use crate::protocol::constants::{
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
};
use crate::protocol::tls::{TLS_NAMED_GROUP_X25519, TLS_NAMED_GROUP_X25519MLKEM768};
use crate::tls_front::types::{
    ParsedCertificateInfo, ParsedServerHello, TlsBehaviorProfile, TlsCertPayload, TlsExtension,
    TlsFetchResult, TlsProfileSource,
};
use crate::transport::UpstreamStream;
use crate::transport::proxy_protocol::{ProxyProtocolV1Builder, ProxyProtocolV2Builder};

#[cfg(test)]
const X25519_KEY_SHARE_LEN: usize = 32;
const MLKEM768_CLIENT_ENCAPSULATION_KEY_LEN: usize = 1184;

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

const PROFILE_CACHE_MAX_ENTRIES: usize = 4096;

static PROFILE_CACHE: OnceLock<DashMap<ProfileCacheKey, ProfileCacheValue>> = OnceLock::new();
static PROFILE_CACHE_INSERT_GUARD: OnceLock<Mutex<()>> = OnceLock::new();
static PROFILE_CACHE_CAP_DROPS: AtomicU64 = AtomicU64::new(0);

fn profile_cache() -> &'static DashMap<ProfileCacheKey, ProfileCacheValue> {
    PROFILE_CACHE.get_or_init(DashMap::new)
}

fn profile_cache_insert_guard() -> &'static Mutex<()> {
    PROFILE_CACHE_INSERT_GUARD.get_or_init(|| Mutex::new(()))
}

fn sweep_expired_profile_cache(ttl: Duration, now: Instant) {
    if ttl.is_zero() {
        return;
    }
    profile_cache().retain(|_, value| now.saturating_duration_since(value.updated_at) <= ttl);
}

/// Current number of adaptive TLS fetch profile-cache entries.
pub(crate) fn profile_cache_entries_for_metrics() -> usize {
    profile_cache().len()
}

/// Number of fresh profile-cache winners skipped because the cache was full.
pub(crate) fn profile_cache_cap_drops_for_metrics() -> u64 {
    PROFILE_CACHE_CAP_DROPS.load(Ordering::Relaxed)
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
    remember_profile_success_with_cap(strategy, key, profile, now, PROFILE_CACHE_MAX_ENTRIES);
}

fn remember_profile_success_with_cap(
    strategy: &TlsFetchStrategy,
    key: ProfileCacheKey,
    profile: TlsFetchProfile,
    now: Instant,
    max_entries: usize,
) {
    let Ok(_guard) = profile_cache_insert_guard().lock() else {
        PROFILE_CACHE_CAP_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if max_entries == 0 {
        PROFILE_CACHE_CAP_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if profile_cache().contains_key(&key) {
        profile_cache().insert(
            key,
            ProfileCacheValue {
                profile,
                updated_at: now,
            },
        );
        return;
    }
    if profile_cache().len() >= max_entries {
        // TLS fetch is control-plane work; sweeping under a tiny mutex keeps
        // profile-cache cardinality hard-bounded without touching relay hot paths.
        sweep_expired_profile_cache(strategy.profile_cache_ttl, now);
    }
    if profile_cache().len() >= max_entries {
        PROFILE_CACHE_CAP_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    profile_cache().insert(
        key,
        ProfileCacheValue {
            profile,
            updated_at: now,
        },
    );
}

// TLS client configuration and wire-compatible ClientHello construction.
mod client_hello;
// TLS record and certificate metadata parsing.
mod records;
// TCP, upstream, and PROXY-protocol connection setup.
mod connection;
// Raw TLS fetch transport.
mod raw_fetch;
// Rustls-backed fetch transport.
mod rustls_fetch;
// Adaptive profile selection and public fetch entry points.
mod strategy;

use client_hello::*;
use connection::*;
use raw_fetch::*;
use records::*;
use rustls_fetch::*;
pub use strategy::fetch_real_tls_with_strategy;

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
mod tests;
