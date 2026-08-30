//! Client Handler

use ipnetwork::IpNetwork;
use rand::RngExt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Post-handshake future (relay phase, runs outside handshake timeout)
type PostHandshakeFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Result of the handshake phase
enum HandshakeOutcome {
    /// Handshake succeeded, relay work to do (outside timeout)
    NeedsRelay(PostHandshakeFuture),
    /// Handshake failed and masking must run outside handshake timeout budget
    NeedsMasking(PostHandshakeFuture),
}

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{HandshakeResult, ProxyError, Result, StreamError};
use crate::ip_tracker::UserIpTracker;
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::protocol::tls_fingerprint::{self, TlsClientFingerprint};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::tls_front::TlsFrontCache;
use crate::transport::middle_proxy::MePool;
use crate::transport::socket::normalize_ip;
use crate::transport::{UpstreamManager, configure_client_socket, parse_proxy_protocol};

use crate::proxy::authenticated::{ClientRuntimeDeps, run_authenticated};
#[cfg(test)]
use crate::proxy::authenticated::{UserConnectionReservation, acquire_user_connection_reservation};
use crate::proxy::handshake::{
    HandshakeSuccess, TlsResponseWriteOptions, handle_mtproto_handshake_with_shared,
    handle_tls_handshake_with_shared, handle_tls_handshake_with_shared_and_options,
};
#[cfg(test)]
use crate::proxy::handshake::{handle_mtproto_handshake, handle_tls_handshake};
#[cfg(test)]
use crate::proxy::route_mode::RelayRouteMode;
use crate::proxy::route_mode::RouteRuntimeController;
use crate::proxy::shared_state::{ConntrackClosePolicy, ProxySharedState};

// Handshake classification, telemetry, and masking helpers.
mod handshake_support;
// Stream-level handshake timeout and relay dispatch entry points.
mod stream_entry;
// Running client socket setup and first-stage handshake.
mod running_lifecycle;
// TLS client handshake and authenticated dispatch.
mod tls_client;
// Direct MTProxy handshake and authenticated dispatch.
mod direct_client;
// Shared authenticated relay and user-admission helpers.
mod authenticated;

use handshake_support::*;
#[cfg(test)]
pub use stream_entry::handle_client_stream;
pub use stream_entry::{
    handle_client_stream_with_shared, handle_client_stream_with_shared_and_pool_runtime,
};

pub struct ClientHandler;

pub struct RunningClientHandler {
    stream: TcpStream,
    peer: SocketAddr,
    real_peer_from_proxy: Option<SocketAddr>,
    real_peer_report: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    replay_checker: Arc<ReplayChecker>,
    upstream_manager: Arc<UpstreamManager>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    me_pool_runtime: Option<Arc<RwLock<Option<Arc<MePool>>>>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    shared: Arc<ProxySharedState>,
    proxy_protocol_enabled: bool,
    #[cfg(unix)]
    raw_fd: std::os::unix::io::RawFd,
    rst_on_close: crate::config::RstOnCloseMode,
    tls_response_fragment_size: Option<u16>,
}

impl ClientHandler {
    #[cfg(test)]
    pub fn new(
        stream: TcpStream,
        peer: SocketAddr,
        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
        upstream_manager: Arc<UpstreamManager>,
        replay_checker: Arc<ReplayChecker>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        me_pool: Option<Arc<MePool>>,
        route_runtime: Arc<RouteRuntimeController>,
        tls_cache: Option<Arc<TlsFrontCache>>,
        ip_tracker: Arc<UserIpTracker>,
        beobachten: Arc<BeobachtenStore>,
        proxy_protocol_enabled: bool,
        real_peer_report: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    ) -> RunningClientHandler {
        #[cfg(unix)]
        let raw_fd = {
            use std::os::unix::io::AsRawFd;
            stream.as_raw_fd()
        };
        Self::new_with_shared(
            stream,
            peer,
            config,
            stats,
            upstream_manager,
            replay_checker,
            buffer_pool,
            rng,
            me_pool,
            None,
            route_runtime,
            tls_cache,
            ip_tracker,
            beobachten,
            ProxySharedState::new(),
            proxy_protocol_enabled,
            real_peer_report,
            #[cfg(unix)]
            raw_fd,
            crate::config::RstOnCloseMode::Off,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_shared(
        stream: TcpStream,
        peer: SocketAddr,
        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
        upstream_manager: Arc<UpstreamManager>,
        replay_checker: Arc<ReplayChecker>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        me_pool: Option<Arc<MePool>>,
        me_pool_runtime: Option<Arc<RwLock<Option<Arc<MePool>>>>>,
        route_runtime: Arc<RouteRuntimeController>,
        tls_cache: Option<Arc<TlsFrontCache>>,
        ip_tracker: Arc<UserIpTracker>,
        beobachten: Arc<BeobachtenStore>,
        shared: Arc<ProxySharedState>,
        proxy_protocol_enabled: bool,
        real_peer_report: Arc<std::sync::Mutex<Option<SocketAddr>>>,
        #[cfg(unix)] raw_fd: std::os::unix::io::RawFd,
        rst_on_close: crate::config::RstOnCloseMode,
        tls_response_fragment_size: Option<u16>,
    ) -> RunningClientHandler {
        let normalized_peer = normalize_ip(peer);
        RunningClientHandler {
            stream,
            peer: normalized_peer,
            real_peer_from_proxy: None,
            real_peer_report,
            config,
            stats,
            replay_checker,
            upstream_manager,
            buffer_pool,
            rng,
            me_pool,
            me_pool_runtime,
            route_runtime,
            tls_cache,
            ip_tracker,
            beobachten,
            shared,
            proxy_protocol_enabled,
            #[cfg(unix)]
            raw_fd,
            rst_on_close,
            tls_response_fragment_size,
        }
    }
}

#[cfg(test)]
#[path = "tests/client_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/client_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/client_tls_mtproto_fallback_security_tests.rs"]
mod tls_mtproto_fallback_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_clienthello_size_security_tests.rs"]
mod tls_clienthello_size_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_clienthello_truncation_adversarial_tests.rs"]
mod tls_clienthello_truncation_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_timing_profile_adversarial_tests.rs"]
mod timing_profile_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_budget_security_tests.rs"]
mod masking_budget_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_redteam_expected_fail_tests.rs"]
mod masking_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/client_masking_hard_adversarial_tests.rs"]
mod masking_hard_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_stress_adversarial_tests.rs"]
mod masking_stress_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_blackhat_campaign_tests.rs"]
mod masking_blackhat_campaign_tests;

#[cfg(test)]
#[path = "tests/client_masking_diagnostics_security_tests.rs"]
mod masking_diagnostics_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_hardening_security_tests.rs"]
mod masking_shape_hardening_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_hardening_adversarial_tests.rs"]
mod masking_shape_hardening_adversarial_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_hardening_redteam_expected_fail_tests.rs"]
mod masking_shape_hardening_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/client_masking_shape_classifier_fuzz_redteam_expected_fail_tests.rs"]
mod masking_shape_classifier_fuzz_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/client_masking_probe_evasion_blackhat_tests.rs"]
mod masking_probe_evasion_blackhat_tests;

#[cfg(test)]
#[path = "tests/client_masking_fragmented_classifier_security_tests.rs"]
mod masking_fragmented_classifier_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_replay_timing_security_tests.rs"]
mod masking_replay_timing_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_http2_fragmented_preface_security_tests.rs"]
mod masking_http2_fragmented_preface_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_invariant_security_tests.rs"]
mod masking_prefetch_invariant_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_timing_matrix_security_tests.rs"]
mod masking_prefetch_timing_matrix_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_config_runtime_security_tests.rs"]
mod masking_prefetch_config_runtime_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_config_pipeline_integration_security_tests.rs"]
mod masking_prefetch_config_pipeline_integration_security_tests;

#[cfg(test)]
#[path = "tests/client_masking_prefetch_strict_boundary_security_tests.rs"]
mod masking_prefetch_strict_boundary_security_tests;

#[cfg(test)]
#[path = "tests/client_beobachten_ttl_bounds_security_tests.rs"]
mod beobachten_ttl_bounds_security_tests;

#[cfg(test)]
#[path = "tests/client_tls_record_wrap_hardening_security_tests.rs"]
mod tls_record_wrap_hardening_security_tests;

#[cfg(test)]
#[path = "tests/client_clever_advanced_tests.rs"]
mod client_clever_advanced_tests;

#[cfg(test)]
#[path = "tests/client_more_advanced_tests.rs"]
mod client_more_advanced_tests;

#[cfg(test)]
#[path = "tests/client_deep_invariants_tests.rs"]
mod client_deep_invariants_tests;
