//! MTProto handshake authentication, TLS fronting, and nonce derivation.

#![allow(dead_code)]

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
#[cfg(test)]
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
#[cfg(test)]
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, trace, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{ProxyConfig, UnknownSniAction, WebSecretMode};
use crate::crypto::{AesCtr, SecureRandom, sha256};
use crate::error::{HandshakeResult, ProxyError};
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::ReplayChecker;
use crate::stream::{CryptoReader, CryptoWriter, FakeTlsReader, FakeTlsWriter};
use crate::tls_front::{TlsFrontCache, emulator};
#[cfg(test)]
use rand::RngExt;

// Handshake submodules.
// - auth_candidates: access-secret decoding and candidate selection.
// - auth_probe: scanner throttling and sticky authentication state.
// - mtproto: direct MTProto obfuscation handshake.
// - nonce: Telegram-side nonce generation and encryption.
// - session: authenticated session key ownership.
// - tls_auth: FakeTLS authentication material parsing.
// - tls_handshake: FakeTLS policy and response orchestration.
// - tls_validation: bounded user candidate validation.
mod auth_candidates;
mod auth_probe;
mod mtproto;
mod nonce;
mod session;
mod tls_auth;
mod tls_handshake;
mod tls_validation;

use self::auth_candidates::*;
use self::auth_probe::*;
use self::tls_auth::{parse_tls_auth_material, validate_tls_secret_candidate};

pub(crate) use self::auth_probe::{AuthProbeSaturationState, AuthProbeState};
#[cfg(test)]
pub use self::mtproto::handle_mtproto_handshake;
pub(crate) use self::mtproto::handle_mtproto_handshake_for_web_user;
pub use self::mtproto::handle_mtproto_handshake_with_shared;
#[allow(unused_imports)]
pub use self::nonce::{encrypt_tg_nonce, encrypt_tg_nonce_with_ciphers, generate_tg_nonce};
pub use self::session::HandshakeSuccess;
#[cfg(test)]
pub use self::tls_handshake::handle_tls_handshake;
pub use self::tls_handshake::handle_tls_handshake_with_shared;
pub(crate) use self::tls_handshake::handle_tls_handshake_with_shared_and_options;

#[cfg(test)]
pub(crate) use self::auth_probe::{
    auth_probe_fail_streak_for_testing_in_shared, auth_probe_is_throttled_for_testing_in_shared,
    auth_probe_record_failure_for_testing,
    auth_probe_saturation_is_throttled_at_for_testing_in_shared,
    auth_probe_saturation_is_throttled_for_testing_in_shared,
    auth_probe_saturation_state_for_testing_in_shared,
    auth_probe_saturation_state_lock_for_testing_in_shared, auth_probe_slots_for_testing_in_shared,
    auth_probe_state_for_testing_in_shared, clear_auth_probe_state_for_testing_in_shared,
    clear_unknown_sni_warn_state_for_testing_in_shared, clear_warned_secrets_for_testing_in_shared,
    insert_auth_probe_state_for_testing_in_shared,
    should_emit_unknown_sni_warn_for_testing_in_shared, warned_secrets_for_testing_in_shared,
};

const ACCESS_SECRET_BYTES: usize = 16;
const UNKNOWN_SNI_WARN_COOLDOWN_SECS: u64 = 5;
#[cfg(test)]
const WARNED_SECRET_MAX_ENTRIES: usize = 64;
#[cfg(not(test))]
const WARNED_SECRET_MAX_ENTRIES: usize = 1_024;

const AUTH_PROBE_TRACK_RETENTION_SECS: u64 = 10 * 60;
#[cfg(test)]
pub(super) const AUTH_PROBE_TRACK_MAX_ENTRIES: usize = 256;
#[cfg(not(test))]
pub(super) const AUTH_PROBE_TRACK_MAX_ENTRIES: usize = 65_536;
const AUTH_PROBE_PRUNE_SCAN_LIMIT: usize = 1_024;
const AUTH_PROBE_BACKOFF_START_FAILS: u32 = 4;
const AUTH_PROBE_SATURATION_GRACE_FAILS: u32 = 2;
#[cfg(test)]
pub(super) const STICKY_HINT_MAX_ENTRIES: usize = 256;
#[cfg(not(test))]
pub(super) const STICKY_HINT_MAX_ENTRIES: usize = 65_536;
const CANDIDATE_HINT_TRACK_CAP: usize = 64;
const OVERLOAD_CANDIDATE_BUDGET_HINTED: usize = 16;
const OVERLOAD_CANDIDATE_BUDGET_UNHINTED: usize = 8;
const EXPENSIVE_INVALID_SCAN_SATURATION_THRESHOLD: usize = 64;
const RECENT_USER_RING_SCAN_LIMIT: usize = 32;

#[cfg(test)]
const AUTH_PROBE_BACKOFF_BASE_MS: u64 = 1;
#[cfg(not(test))]
const AUTH_PROBE_BACKOFF_BASE_MS: u64 = 25;

#[cfg(test)]
const AUTH_PROBE_BACKOFF_MAX_MS: u64 = 16;
#[cfg(not(test))]
const AUTH_PROBE_BACKOFF_MAX_MS: u64 = 1_000;

/// Best-effort chunking profile for the authenticated FakeTLS response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TlsResponseFragmentation {
    /// Handshake MSS (`client_mss`) that bounds each chunk of the prefix.
    pub(crate) fragment_size: u16,
    /// Leading part of the response that is chunked; the rest is written at
    /// the bulk MSS.
    pub(crate) prefix: crate::config::ClientMssPrefix,
}

/// Controls how the authenticated FakeTLS response is written to a client.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TlsResponseWriteOptions {
    #[cfg(target_os = "linux")]
    socket_fd: Option<std::os::unix::io::RawFd>,
    #[cfg(target_os = "linux")]
    fragmentation: Option<TlsResponseFragmentation>,
}

impl TlsResponseWriteOptions {
    /// Creates Linux best-effort response chunking options for an accepted socket.
    #[cfg(target_os = "linux")]
    pub(crate) fn tcp(
        fd: std::os::unix::io::RawFd,
        fragmentation: Option<TlsResponseFragmentation>,
    ) -> Self {
        Self {
            socket_fd: fragmentation.map(|_| fd),
            fragmentation,
        }
    }
}

#[cfg(test)]
#[path = "tests/handshake_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/handshake_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/handshake_fuzz_security_tests.rs"]
mod fuzz_security_tests;

#[cfg(test)]
#[path = "tests/handshake_saturation_poison_security_tests.rs"]
mod saturation_poison_security_tests;

#[cfg(test)]
#[path = "tests/handshake_auth_probe_hardening_adversarial_tests.rs"]
mod auth_probe_hardening_adversarial_tests;

#[cfg(test)]
#[path = "tests/handshake_auth_probe_scan_budget_security_tests.rs"]
mod auth_probe_scan_budget_security_tests;

#[cfg(test)]
#[path = "tests/handshake_auth_probe_scan_offset_stress_tests.rs"]
mod auth_probe_scan_offset_stress_tests;

#[cfg(test)]
#[path = "tests/handshake_auth_probe_eviction_bias_security_tests.rs"]
mod auth_probe_eviction_bias_security_tests;

#[cfg(test)]
#[path = "tests/handshake_advanced_clever_tests.rs"]
mod advanced_clever_tests;

#[cfg(test)]
#[path = "tests/handshake_more_clever_tests.rs"]
mod more_clever_tests;

#[cfg(test)]
#[path = "tests/handshake_real_bug_stress_tests.rs"]
mod real_bug_stress_tests;

#[cfg(test)]
#[path = "tests/handshake_timing_manual_bench_tests.rs"]
mod timing_manual_bench_tests;

#[cfg(test)]
#[path = "tests/handshake_key_material_zeroization_security_tests.rs"]
mod handshake_key_material_zeroization_security_tests;

#[cfg(test)]
#[path = "tests/handshake_baseline_invariant_tests.rs"]
mod handshake_baseline_invariant_tests;

/// Compile-time guard preventing silent duplication of session key material.
mod compile_time_security_checks {
    use super::HandshakeSuccess;
    use static_assertions::assert_not_impl_all;

    assert_not_impl_all!(HandshakeSuccess: Copy, Clone);
}
