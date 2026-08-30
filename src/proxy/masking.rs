//! Masking - forward unrecognized traffic to mask host

use crate::config::ProxyConfig;
use crate::protocol::tls;
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::beobachten::BeobachtenStore;
use crate::transport::proxy_protocol::{ProxyProtocolV1Builder, ProxyProtocolV2Builder};
use crate::transport::socket::configure_tcp_socket;
#[cfg(unix)]
use nix::ifaddrs::getifaddrs;
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::str;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpStream, lookup_host};
#[cfg(unix)]
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{Instant, timeout};
use tracing::debug;

#[cfg(not(test))]
const MASK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const MASK_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum duration for the entire masking relay under test (replaced by config at runtime).
#[cfg(test)]
const MASK_RELAY_TIMEOUT: Duration = Duration::from_millis(200);
/// Per-read idle timeout for masking relay and drain paths under test (replaced by config at runtime).
#[cfg(test)]
const MASK_RELAY_IDLE_TIMEOUT: Duration = Duration::from_millis(100);
const MASK_BUFFER_SIZE: usize = 8192;
const MASK_BUFFER_GROW_AFTER_BYTES: usize = 256 * 1024;
const MASK_BUFFER_MAX_SIZE: usize = 64 * 1024;
const MASK_DNS_RESULT_MAX_ADDRESSES: usize = 64;
#[cfg(unix)]
#[cfg(not(test))]
const LOCAL_INTERFACE_CACHE_TTL: Duration = Duration::from_secs(300);
#[cfg(all(unix, test))]
const LOCAL_INTERFACE_CACHE_TTL: Duration = Duration::from_secs(1);

struct CopyOutcome {
    total: usize,
    ended_by_eof: bool,
}

#[derive(Clone, Copy)]
struct MaskTcpTarget<'a> {
    host: &'a str,
    port: u16,
}

// Bounded relay-copy, probe classification, and failure draining.
mod copy;
// Masking delay distribution and outcome normalization.
mod timing;
// SNI-aware mask-target selection and bounded DNS resolution.
mod target;
// Local-interface snapshots and self-target rejection.
mod interfaces;
// Beobachten TTL, PROXY header, and backend socket setup.
mod backend_setup;
// Mask backend connection orchestration.
mod handler;
// Bidirectional masking relay.
mod relay;

#[cfg(test)]
pub use backend_setup::handle_bad_client;
use backend_setup::*;
use copy::*;
pub(crate) use handler::handle_bad_client_with_shared;
pub(in crate::proxy) use handler::handle_bad_client_with_shared_resolver;
use interfaces::*;
use relay::*;
use target::*;
pub(crate) use timing::sample_lognormal_percentile_bounded;
use timing::{
    mask_outcome_target_budget, wait_mask_connect_budget_if_needed, wait_mask_outcome_budget,
};

#[cfg(test)]
#[path = "tests/masking_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/masking_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_hardening_adversarial_tests.rs"]
mod masking_shape_hardening_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_above_cap_blur_security_tests.rs"]
mod masking_shape_above_cap_blur_security_tests;

#[cfg(test)]
#[path = "tests/masking_timing_normalization_security_tests.rs"]
mod masking_timing_normalization_security_tests;

#[cfg(test)]
#[path = "tests/masking_timing_budget_coupling_security_tests.rs"]
mod masking_timing_budget_coupling_security_tests;

#[cfg(test)]
#[path = "tests/masking_ab_envelope_blur_integration_security_tests.rs"]
mod masking_ab_envelope_blur_integration_security_tests;

#[cfg(test)]
#[path = "tests/masking_shape_guard_security_tests.rs"]
mod masking_shape_guard_security_tests;

#[cfg(test)]
#[path = "tests/masking_shape_guard_adversarial_tests.rs"]
mod masking_shape_guard_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_classifier_resistance_adversarial_tests.rs"]
mod masking_shape_classifier_resistance_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_shape_bypass_blackhat_tests.rs"]
mod masking_shape_bypass_blackhat_tests;

#[cfg(test)]
#[path = "tests/masking_aggressive_mode_security_tests.rs"]
mod masking_aggressive_mode_security_tests;

#[cfg(test)]
#[path = "tests/masking_timing_sidechannel_redteam_expected_fail_tests.rs"]
mod masking_timing_sidechannel_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/masking_self_target_loop_security_tests.rs"]
mod masking_self_target_loop_security_tests;

#[cfg(test)]
#[path = "tests/masking_classification_completeness_security_tests.rs"]
mod masking_classification_completeness_security_tests;

#[cfg(test)]
#[path = "tests/masking_relay_guardrails_security_tests.rs"]
mod masking_relay_guardrails_security_tests;

#[cfg(test)]
#[path = "tests/masking_connect_failure_close_matrix_security_tests.rs"]
mod masking_connect_failure_close_matrix_security_tests;

#[cfg(test)]
#[path = "tests/masking_additional_hardening_security_tests.rs"]
mod masking_additional_hardening_security_tests;

#[cfg(test)]
#[path = "tests/masking_consume_idle_timeout_security_tests.rs"]
mod masking_consume_idle_timeout_security_tests;

#[cfg(test)]
#[path = "tests/masking_http2_probe_classification_security_tests.rs"]
mod masking_http2_probe_classification_security_tests;

#[cfg(test)]
#[path = "tests/masking_http_probe_boundary_security_tests.rs"]
mod masking_http_probe_boundary_security_tests;

#[cfg(test)]
#[path = "tests/masking_rng_hoist_perf_regression_tests.rs"]
mod masking_rng_hoist_perf_regression_tests;

#[cfg(test)]
#[path = "tests/masking_http2_preface_integration_security_tests.rs"]
mod masking_http2_preface_integration_security_tests;

#[cfg(test)]
#[path = "tests/masking_consume_stress_adversarial_tests.rs"]
mod masking_consume_stress_adversarial_tests;

#[cfg(test)]
#[path = "tests/masking_interface_cache_security_tests.rs"]
mod masking_interface_cache_security_tests;

#[cfg(test)]
#[path = "tests/masking_interface_cache_defense_in_depth_security_tests.rs"]
mod masking_interface_cache_defense_in_depth_security_tests;

#[cfg(test)]
#[path = "tests/masking_interface_cache_concurrency_security_tests.rs"]
mod masking_interface_cache_concurrency_security_tests;

#[cfg(test)]
#[path = "tests/masking_production_cap_regression_security_tests.rs"]
mod masking_production_cap_regression_security_tests;

#[cfg(test)]
#[path = "tests/masking_relay_manual_perf_tests.rs"]
mod masking_relay_manual_perf_tests;

#[cfg(test)]
#[path = "tests/masking_extended_attack_surface_security_tests.rs"]
mod masking_extended_attack_surface_security_tests;

#[cfg(test)]
#[path = "tests/masking_padding_timeout_adversarial_tests.rs"]
mod masking_padding_timeout_adversarial_tests;

#[cfg(all(test, feature = "redteam_offline_expected_fail"))]
#[path = "tests/masking_offline_target_redteam_expected_fail_tests.rs"]
mod masking_offline_target_redteam_expected_fail_tests;

#[cfg(test)]
#[path = "tests/masking_baseline_invariant_tests.rs"]
mod masking_baseline_invariant_tests;

#[cfg(test)]
#[path = "tests/masking_lognormal_timing_security_tests.rs"]
mod masking_lognormal_timing_security_tests;
