//! MTProto Handshake

#![allow(dead_code)]

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::config::ProxyConfig;
use crate::crypto::{AesCtr, SecureRandom, sha256};
use crate::error::{HandshakeResult, ProxyError};
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stats::ReplayChecker;
use crate::stream::{CryptoReader, CryptoWriter, FakeTlsReader, FakeTlsWriter};
use crate::tls_front::{TlsFrontCache, emulator};
use rand::RngExt;

const ACCESS_SECRET_BYTES: usize = 16;
static INVALID_SECRET_WARNED: OnceLock<Mutex<HashSet<(String, String)>>> = OnceLock::new();
#[cfg(test)]
const WARNED_SECRET_MAX_ENTRIES: usize = 64;
#[cfg(not(test))]
const WARNED_SECRET_MAX_ENTRIES: usize = 1_024;

const AUTH_PROBE_TRACK_RETENTION_SECS: u64 = 10 * 60;
#[cfg(test)]
const AUTH_PROBE_TRACK_MAX_ENTRIES: usize = 256;
#[cfg(not(test))]
const AUTH_PROBE_TRACK_MAX_ENTRIES: usize = 65_536;
const AUTH_PROBE_PRUNE_SCAN_LIMIT: usize = 1_024;
const AUTH_PROBE_BACKOFF_START_FAILS: u32 = 4;
const AUTH_PROBE_SATURATION_GRACE_FAILS: u32 = 2;

#[cfg(test)]
const AUTH_PROBE_BACKOFF_BASE_MS: u64 = 1;
#[cfg(not(test))]
const AUTH_PROBE_BACKOFF_BASE_MS: u64 = 25;

#[cfg(test)]
const AUTH_PROBE_BACKOFF_MAX_MS: u64 = 16;
#[cfg(not(test))]
const AUTH_PROBE_BACKOFF_MAX_MS: u64 = 1_000;

#[derive(Clone, Copy)]
struct AuthProbeState {
    fail_streak: u32,
    blocked_until: Instant,
    last_seen: Instant,
}

#[derive(Clone, Copy)]
struct AuthProbeSaturationState {
    fail_streak: u32,
    blocked_until: Instant,
    last_seen: Instant,
}

static AUTH_PROBE_STATE: OnceLock<DashMap<IpAddr, AuthProbeState>> = OnceLock::new();
static AUTH_PROBE_SATURATION_STATE: OnceLock<Mutex<Option<AuthProbeSaturationState>>> =
    OnceLock::new();
static AUTH_PROBE_EVICTION_HASHER: OnceLock<RandomState> = OnceLock::new();

fn auth_probe_state_map() -> &'static DashMap<IpAddr, AuthProbeState> {
    AUTH_PROBE_STATE.get_or_init(DashMap::new)
}

fn auth_probe_saturation_state() -> &'static Mutex<Option<AuthProbeSaturationState>> {
    AUTH_PROBE_SATURATION_STATE.get_or_init(|| Mutex::new(None))
}

fn auth_probe_saturation_state_lock()
-> std::sync::MutexGuard<'static, Option<AuthProbeSaturationState>> {
    auth_probe_saturation_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn normalize_auth_probe_ip(peer_ip: IpAddr) -> IpAddr {
    match peer_ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => {
            let [a, b, c, d, _, _, _, _] = ip.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
    }
}

fn auth_probe_backoff(fail_streak: u32) -> Duration {
    if fail_streak < AUTH_PROBE_BACKOFF_START_FAILS {
        return Duration::ZERO;
    }
    let shift = (fail_streak - AUTH_PROBE_BACKOFF_START_FAILS).min(10);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let ms = AUTH_PROBE_BACKOFF_BASE_MS
        .saturating_mul(multiplier)
        .min(AUTH_PROBE_BACKOFF_MAX_MS);
    Duration::from_millis(ms)
}

fn auth_probe_state_expired(state: &AuthProbeState, now: Instant) -> bool {
    let retention = Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS);
    now.duration_since(state.last_seen) > retention
}

fn auth_probe_eviction_offset(peer_ip: IpAddr, now: Instant) -> usize {
    let hasher_state = AUTH_PROBE_EVICTION_HASHER.get_or_init(RandomState::new);
    let mut hasher = hasher_state.build_hasher();
    peer_ip.hash(&mut hasher);
    now.hash(&mut hasher);
    hasher.finish() as usize
}

fn auth_probe_is_throttled(peer_ip: IpAddr, now: Instant) -> bool {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = auth_probe_state_map();
    let Some(entry) = state.get(&peer_ip) else {
        return false;
    };
    if auth_probe_state_expired(&entry, now) {
        drop(entry);
        state.remove(&peer_ip);
        return false;
    }
    now < entry.blocked_until
}

fn auth_probe_saturation_grace_exhausted(peer_ip: IpAddr, now: Instant) -> bool {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = auth_probe_state_map();
    let Some(entry) = state.get(&peer_ip) else {
        return false;
    };
    if auth_probe_state_expired(&entry, now) {
        drop(entry);
        state.remove(&peer_ip);
        return false;
    }

    entry.fail_streak >= AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS
}

fn auth_probe_should_apply_preauth_throttle(peer_ip: IpAddr, now: Instant) -> bool {
    if !auth_probe_is_throttled(peer_ip, now) {
        return false;
    }

    if !auth_probe_saturation_is_throttled(now) {
        return true;
    }

    auth_probe_saturation_grace_exhausted(peer_ip, now)
}

fn auth_probe_saturation_is_throttled(now: Instant) -> bool {
    let mut guard = auth_probe_saturation_state_lock();

    let Some(state) = guard.as_mut() else {
        return false;
    };

    if now.duration_since(state.last_seen) > Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS) {
        *guard = None;
        return false;
    }

    if now < state.blocked_until {
        return true;
    }

    false
}

fn auth_probe_note_saturation(now: Instant) {
    let mut guard = auth_probe_saturation_state_lock();

    match guard.as_mut() {
        Some(state)
            if now.duration_since(state.last_seen)
                <= Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS) =>
        {
            state.fail_streak = state.fail_streak.saturating_add(1);
            state.last_seen = now;
            state.blocked_until = now + auth_probe_backoff(state.fail_streak);
        }
        _ => {
            let fail_streak = AUTH_PROBE_BACKOFF_START_FAILS;
            *guard = Some(AuthProbeSaturationState {
                fail_streak,
                blocked_until: now + auth_probe_backoff(fail_streak),
                last_seen: now,
            });
        }
    }
}

fn auth_probe_record_failure(peer_ip: IpAddr, now: Instant) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = auth_probe_state_map();
    auth_probe_record_failure_with_state(state, peer_ip, now);
}

fn auth_probe_record_failure_with_state(
    state: &DashMap<IpAddr, AuthProbeState>,
    peer_ip: IpAddr,
    now: Instant,
) {
    let make_new_state = || AuthProbeState {
        fail_streak: 1,
        blocked_until: now + auth_probe_backoff(1),
        last_seen: now,
    };

    let update_existing = |entry: &mut AuthProbeState| {
        if auth_probe_state_expired(entry, now) {
            *entry = make_new_state();
        } else {
            entry.fail_streak = entry.fail_streak.saturating_add(1);
            entry.last_seen = now;
            entry.blocked_until = now + auth_probe_backoff(entry.fail_streak);
        }
    };

    match state.entry(peer_ip) {
        Entry::Occupied(mut entry) => {
            update_existing(entry.get_mut());
            return;
        }
        Entry::Vacant(_) => {}
    }

    if state.len() >= AUTH_PROBE_TRACK_MAX_ENTRIES {
        let mut rounds = 0usize;
        while state.len() >= AUTH_PROBE_TRACK_MAX_ENTRIES {
            rounds += 1;
            if rounds > 8 {
                auth_probe_note_saturation(now);
                let mut eviction_candidate: Option<(IpAddr, u32, Instant)> = None;
                for entry in state.iter().take(AUTH_PROBE_PRUNE_SCAN_LIMIT) {
                    let key = *entry.key();
                    let fail_streak = entry.value().fail_streak;
                    let last_seen = entry.value().last_seen;
                    match eviction_candidate {
                        Some((_, current_fail, current_seen))
                            if fail_streak > current_fail
                                || (fail_streak == current_fail && last_seen >= current_seen) => {}
                        _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                    }
                }

                let Some((evict_key, _, _)) = eviction_candidate else {
                    return;
                };
                state.remove(&evict_key);
                break;
            }

            let mut stale_keys = Vec::new();
            let mut eviction_candidate: Option<(IpAddr, u32, Instant)> = None;
            let state_len = state.len();
            let scan_limit = state_len.min(AUTH_PROBE_PRUNE_SCAN_LIMIT);
            let start_offset = if state_len == 0 {
                0
            } else {
                auth_probe_eviction_offset(peer_ip, now) % state_len
            };

            let mut scanned = 0usize;
            for entry in state.iter().skip(start_offset) {
                let key = *entry.key();
                let fail_streak = entry.value().fail_streak;
                let last_seen = entry.value().last_seen;
                match eviction_candidate {
                    Some((_, current_fail, current_seen))
                        if fail_streak > current_fail
                            || (fail_streak == current_fail && last_seen >= current_seen) => {}
                    _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                }
                if auth_probe_state_expired(entry.value(), now) {
                    stale_keys.push(key);
                }
                scanned += 1;
                if scanned >= scan_limit {
                    break;
                }
            }

            if scanned < scan_limit {
                for entry in state.iter().take(scan_limit - scanned) {
                    let key = *entry.key();
                    let fail_streak = entry.value().fail_streak;
                    let last_seen = entry.value().last_seen;
                    match eviction_candidate {
                        Some((_, current_fail, current_seen))
                            if fail_streak > current_fail
                                || (fail_streak == current_fail && last_seen >= current_seen) => {}
                        _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                    }
                    if auth_probe_state_expired(entry.value(), now) {
                        stale_keys.push(key);
                    }
                }
            }

            for stale_key in stale_keys {
                state.remove(&stale_key);
            }

            if state.len() < AUTH_PROBE_TRACK_MAX_ENTRIES {
                break;
            }

            let Some((evict_key, _, _)) = eviction_candidate else {
                auth_probe_note_saturation(now);
                return;
            };
            state.remove(&evict_key);
            auth_probe_note_saturation(now);
        }
    }

    match state.entry(peer_ip) {
        Entry::Occupied(mut entry) => {
            update_existing(entry.get_mut());
        }
        Entry::Vacant(entry) => {
            entry.insert(make_new_state());
        }
    }
}

fn auth_probe_record_success(peer_ip: IpAddr) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = auth_probe_state_map();
    state.remove(&peer_ip);
}

#[cfg(test)]
fn clear_auth_probe_state_for_testing() {
    if let Some(state) = AUTH_PROBE_STATE.get() {
        state.clear();
    }
    if AUTH_PROBE_SATURATION_STATE.get().is_some() {
        let mut guard = auth_probe_saturation_state_lock();
        *guard = None;
    }
}

#[cfg(test)]
fn auth_probe_fail_streak_for_testing(peer_ip: IpAddr) -> Option<u32> {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = AUTH_PROBE_STATE.get()?;
    state.get(&peer_ip).map(|entry| entry.fail_streak)
}

#[cfg(test)]
fn auth_probe_is_throttled_for_testing(peer_ip: IpAddr) -> bool {
    auth_probe_is_throttled(peer_ip, Instant::now())
}

#[cfg(test)]
fn auth_probe_saturation_is_throttled_for_testing() -> bool {
    auth_probe_saturation_is_throttled(Instant::now())
}

#[cfg(test)]
fn auth_probe_saturation_is_throttled_at_for_testing(now: Instant) -> bool {
    auth_probe_saturation_is_throttled(now)
}

#[cfg(test)]
fn auth_probe_test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
fn clear_warned_secrets_for_testing() {
    if let Some(warned) = INVALID_SECRET_WARNED.get()
        && let Ok(mut guard) = warned.lock()
    {
        guard.clear();
    }
}

#[cfg(test)]
fn warned_secrets_test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

fn warn_invalid_secret_once(name: &str, reason: &str, expected: usize, got: Option<usize>) {
    let key = (name.to_string(), reason.to_string());
    let warned = INVALID_SECRET_WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let should_warn = match warned.lock() {
        Ok(mut guard) => {
            if !guard.contains(&key) && guard.len() >= WARNED_SECRET_MAX_ENTRIES {
                false
            } else {
                guard.insert(key)
            }
        }
        Err(_) => true,
    };

    if !should_warn {
        return;
    }

    match got {
        Some(actual) => {
            warn!(
                user = %name,
                expected = expected,
                got = actual,
                "Skipping user: access secret has unexpected length"
            );
        }
        None => {
            warn!(
                user = %name,
                "Skipping user: access secret is not valid hex"
            );
        }
    }
}

fn decode_user_secret(name: &str, secret_hex: &str) -> Option<Vec<u8>> {
    match hex::decode(secret_hex) {
        Ok(bytes) if bytes.len() == ACCESS_SECRET_BYTES => Some(bytes),
        Ok(bytes) => {
            warn_invalid_secret_once(
                name,
                "invalid_length",
                ACCESS_SECRET_BYTES,
                Some(bytes.len()),
            );
            None
        }
        Err(_) => {
            warn_invalid_secret_once(name, "invalid_hex", ACCESS_SECRET_BYTES, None);
            None
        }
    }
}

// Decide whether a client-supplied proto tag is allowed given the configured
// proxy modes and the transport that carried the handshake.
//
// A common mistake is to treat `modes.tls` and `modes.secure` as interchangeable
// even though they correspond to different transport profiles: `modes.tls` is
// for the TLS-fronted (EE-TLS) path, while `modes.secure` is for direct MTProto
// over TCP (DD). Enforcing this separation prevents an attacker from using a
// TLS-capable client to bypass the operator intent for the direct MTProto mode,
// and vice versa.
fn mode_enabled_for_proto(config: &ProxyConfig, proto_tag: ProtoTag, is_tls: bool) -> bool {
    match proto_tag {
        ProtoTag::Secure => {
            if is_tls {
                config.general.modes.tls
            } else {
                config.general.modes.secure
            }
        }
        ProtoTag::Intermediate | ProtoTag::Abridged => config.general.modes.classic,
    }
}

fn decode_user_secrets(
    config: &ProxyConfig,
    preferred_user: Option<&str>,
) -> Vec<(String, Vec<u8>)> {
    let mut secrets = Vec::with_capacity(config.access.users.len());

    if let Some(preferred) = preferred_user
        && let Some(secret_hex) = config.access.users.get(preferred)
        && let Some(bytes) = decode_user_secret(preferred, secret_hex)
    {
        secrets.push((preferred.to_string(), bytes));
    }

    for (name, secret_hex) in &config.access.users {
        if preferred_user.is_some_and(|preferred| preferred == name.as_str()) {
            continue;
        }
        if let Some(bytes) = decode_user_secret(name, secret_hex) {
            secrets.push((name.clone(), bytes));
        }
    }

    secrets
}

async fn maybe_apply_server_hello_delay(config: &ProxyConfig) {
    if config.censorship.server_hello_delay_max_ms == 0 {
        return;
    }

    let min = config.censorship.server_hello_delay_min_ms;
    let max = config.censorship.server_hello_delay_max_ms.max(min);
    let delay_ms = if max == min {
        max
    } else {
        rand::rng().random_range(min..=max)
    };

    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

/// Result of successful handshake
///
/// Key material (`dec_key`, `dec_iv`, `enc_key`, `enc_iv`) is
/// zeroized on drop.
#[derive(Debug)]
pub struct HandshakeSuccess {
    /// Authenticated user name
    pub user: String,
    /// Target datacenter index
    pub dc_idx: i16,
    /// Protocol variant (abridged/intermediate/secure)
    pub proto_tag: ProtoTag,
    /// Decryption key and IV (for reading from client)
    pub dec_key: [u8; 32],
    pub dec_iv: u128,
    /// Encryption key and IV (for writing to client)
    pub enc_key: [u8; 32],
    pub enc_iv: u128,
    /// Client address
    pub peer: SocketAddr,
    /// Whether TLS was used
    pub is_tls: bool,
}

impl Drop for HandshakeSuccess {
    fn drop(&mut self) {
        self.dec_key.zeroize();
        self.dec_iv.zeroize();
        self.enc_key.zeroize();
        self.enc_iv.zeroize();
    }
}

/// Handle fake TLS handshake
pub async fn handle_tls_handshake<R, W>(
    handshake: &[u8],
    reader: R,
    mut writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    debug!(peer = %peer, handshake_len = handshake.len(), "Processing TLS handshake");

    let throttle_now = Instant::now();
    if auth_probe_should_apply_preauth_throttle(peer.ip(), throttle_now) {
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "TLS handshake rejected by pre-auth probe throttle");
        return HandshakeResult::BadClient { reader, writer };
    }

    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        auth_probe_record_failure(peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "TLS handshake too short");
        return HandshakeResult::BadClient { reader, writer };
    }

    let client_sni = tls::extract_sni_from_client_hello(handshake);
    let secrets = decode_user_secrets(config, client_sni.as_deref());

    let validation = match tls::validate_tls_handshake_with_replay_window(
        handshake,
        &secrets,
        config.access.ignore_time_skew,
        config.access.replay_window_secs,
    ) {
        Some(v) => v,
        None => {
            auth_probe_record_failure(peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            debug!(
                peer = %peer,
                ignore_time_skew = config.access.ignore_time_skew,
                "TLS handshake validation failed - no matching user or time skew"
            );
            return HandshakeResult::BadClient { reader, writer };
        }
    };

    // Replay tracking is applied only after successful authentication to avoid
    // letting unauthenticated probes evict valid entries from the replay cache.
    let digest_half = &validation.digest[..tls::TLS_DIGEST_HALF_LEN];
    if replay_checker.check_and_add_tls_digest(digest_half) {
        auth_probe_record_failure(peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        warn!(peer = %peer, "TLS replay attack detected (duplicate digest)");
        return HandshakeResult::BadClient { reader, writer };
    }

    let secret = match secrets.iter().find(|(name, _)| *name == validation.user) {
        Some((_, s)) => s,
        None => {
            maybe_apply_server_hello_delay(config).await;
            return HandshakeResult::BadClient { reader, writer };
        }
    };

    let cached = if config.censorship.tls_emulation {
        if let Some(cache) = tls_cache.as_ref() {
            let selected_domain = if let Some(sni) = client_sni.as_ref() {
                if cache.contains_domain(sni).await {
                    sni.clone()
                } else {
                    config.censorship.tls_domain.clone()
                }
            } else {
                config.censorship.tls_domain.clone()
            };
            let cached_entry = cache.get(&selected_domain).await;
            let use_full_cert_payload = cache
                .take_full_cert_budget_for_ip(
                    peer.ip(),
                    Duration::from_secs(config.censorship.tls_full_cert_ttl_secs),
                )
                .await;
            Some((cached_entry, use_full_cert_payload))
        } else {
            None
        }
    } else {
        None
    };

    let alpn_list = if config.censorship.alpn_enforce {
        tls::extract_alpn_from_client_hello(handshake)
    } else {
        Vec::new()
    };
    let selected_alpn = if config.censorship.alpn_enforce {
        if alpn_list.iter().any(|p| p == b"h2") {
            Some(b"h2".to_vec())
        } else if alpn_list.iter().any(|p| p == b"http/1.1") {
            Some(b"http/1.1".to_vec())
        } else if !alpn_list.is_empty() {
            maybe_apply_server_hello_delay(config).await;
            debug!(peer = %peer, "Client ALPN list has no supported protocol; using masking fallback");
            return HandshakeResult::BadClient { reader, writer };
        } else {
            None
        }
    } else {
        None
    };

    let response = if let Some((cached_entry, use_full_cert_payload)) = cached {
        emulator::build_emulated_server_hello(
            secret,
            &validation.digest,
            &validation.session_id,
            &cached_entry,
            use_full_cert_payload,
            rng,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    } else {
        tls::build_server_hello(
            secret,
            &validation.digest,
            &validation.session_id,
            config.censorship.fake_cert_len,
            rng,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    };

    // Apply the same optional delay budget used by reject paths to reduce
    // distinguishability between success and fail-closed handshakes.
    maybe_apply_server_hello_delay(config).await;

    debug!(peer = %peer, response_len = response.len(), "Sending TLS ServerHello");

    if let Err(e) = writer.write_all(&response).await {
        warn!(peer = %peer, error = %e, "Failed to write TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    if let Err(e) = writer.flush().await {
        warn!(peer = %peer, error = %e, "Failed to flush TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    debug!(
        peer = %peer,
        user = %validation.user,
        "TLS handshake successful"
    );

    auth_probe_record_success(peer.ip());

    HandshakeResult::Success((
        FakeTlsReader::new(reader),
        FakeTlsWriter::new(writer),
        validation.user,
    ))
}

/// Handle MTProto obfuscation handshake
pub async fn handle_mtproto_handshake<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let handshake_fingerprint = {
        let digest = sha256(&handshake[..8]);
        hex::encode(&digest[..4])
    };
    trace!(
        peer = %peer,
        handshake_fingerprint = %handshake_fingerprint,
        "MTProto handshake prefix"
    );

    let throttle_now = Instant::now();
    if auth_probe_should_apply_preauth_throttle(peer.ip(), throttle_now) {
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "MTProto handshake rejected by pre-auth probe throttle");
        return HandshakeResult::BadClient { reader, writer };
    }

    let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let enc_prekey_iv: Vec<u8> = dec_prekey_iv.iter().rev().copied().collect();

    let decoded_users = decode_user_secrets(config, preferred_user);

    for (user, secret) in decoded_users {
        let dec_prekey = &dec_prekey_iv[..PREKEY_LEN];
        let dec_iv_bytes = &dec_prekey_iv[PREKEY_LEN..];

        let mut dec_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
        dec_key_input.extend_from_slice(dec_prekey);
        dec_key_input.extend_from_slice(&secret);
        let dec_key = sha256(&dec_key_input);

        let mut dec_iv_arr = [0u8; IV_LEN];
        dec_iv_arr.copy_from_slice(dec_iv_bytes);
        let dec_iv = u128::from_be_bytes(dec_iv_arr);

        let mut decryptor = AesCtr::new(&dec_key, dec_iv);
        let decrypted = decryptor.decrypt(handshake);

        let tag_bytes: [u8; 4] = [
            decrypted[PROTO_TAG_POS],
            decrypted[PROTO_TAG_POS + 1],
            decrypted[PROTO_TAG_POS + 2],
            decrypted[PROTO_TAG_POS + 3],
        ];

        let proto_tag = match ProtoTag::from_bytes(tag_bytes) {
            Some(tag) => tag,
            None => continue,
        };

        let mode_ok = mode_enabled_for_proto(config, proto_tag, is_tls);

        if !mode_ok {
            debug!(peer = %peer, user = %user, proto = ?proto_tag, "Mode not enabled");
            continue;
        }

        let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);

        let enc_prekey = &enc_prekey_iv[..PREKEY_LEN];
        let enc_iv_bytes = &enc_prekey_iv[PREKEY_LEN..];

        let mut enc_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
        enc_key_input.extend_from_slice(enc_prekey);
        enc_key_input.extend_from_slice(&secret);
        let enc_key = sha256(&enc_key_input);

        let mut enc_iv_arr = [0u8; IV_LEN];
        enc_iv_arr.copy_from_slice(enc_iv_bytes);
        let enc_iv = u128::from_be_bytes(enc_iv_arr);

        let encryptor = AesCtr::new(&enc_key, enc_iv);

        // Apply replay tracking only after successful authentication.
        //
        // This ordering prevents an attacker from producing invalid handshakes that
        // still collide with a valid handshake's replay slot and thus evict a valid
        // entry from the cache. We accept the cost of performing the full
        // authentication check first to avoid poisoning the replay cache.
        if replay_checker.check_and_add_handshake(dec_prekey_iv) {
            auth_probe_record_failure(peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            warn!(peer = %peer, user = %user, "MTProto replay attack detected");
            return HandshakeResult::BadClient { reader, writer };
        }

        let success = HandshakeSuccess {
            user: user.clone(),
            dc_idx,
            proto_tag,
            dec_key,
            dec_iv,
            enc_key,
            enc_iv,
            peer,
            is_tls,
        };

        debug!(
            peer = %peer,
            user = %user,
            dc = dc_idx,
            proto = ?proto_tag,
            tls = is_tls,
            "MTProto handshake successful"
        );

        auth_probe_record_success(peer.ip());

        let max_pending = config.general.crypto_pending_buffer;
        return HandshakeResult::Success((
            CryptoReader::new(reader, decryptor),
            CryptoWriter::new(writer, encryptor, max_pending),
            success,
        ));
    }

    auth_probe_record_failure(peer.ip(), Instant::now());
    maybe_apply_server_hello_delay(config).await;
    debug!(peer = %peer, "MTProto handshake: no matching user found");
    HandshakeResult::BadClient { reader, writer }
}

/// Generate nonce for Telegram connection
pub fn generate_tg_nonce(
    proto_tag: ProtoTag,
    dc_idx: i16,
    client_enc_key: &[u8; 32],
    client_enc_iv: u128,
    rng: &SecureRandom,
    fast_mode: bool,
) -> ([u8; HANDSHAKE_LEN], [u8; 32], u128, [u8; 32], u128) {
    loop {
        let bytes = rng.bytes(HANDSHAKE_LEN);
        let Ok(mut nonce): Result<[u8; HANDSHAKE_LEN], _> = bytes.try_into() else {
            continue;
        };

        if RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]) {
            continue;
        }

        let first_four: [u8; 4] = [nonce[0], nonce[1], nonce[2], nonce[3]];
        if RESERVED_NONCE_BEGINNINGS.contains(&first_four) {
            continue;
        }

        let continue_four: [u8; 4] = [nonce[4], nonce[5], nonce[6], nonce[7]];
        if RESERVED_NONCE_CONTINUES.contains(&continue_four) {
            continue;
        }

        nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());
        // CRITICAL: write dc_idx so upstream DC knows where to route
        nonce[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

        if fast_mode {
            let mut key_iv = Zeroizing::new(Vec::with_capacity(KEY_LEN + IV_LEN));
            key_iv.extend_from_slice(client_enc_key);
            key_iv.extend_from_slice(&client_enc_iv.to_be_bytes());
            key_iv.reverse(); // Python/C behavior: reversed enc_key+enc_iv in nonce
            nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN].copy_from_slice(&key_iv);
        }

        let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
        let dec_key_iv = Zeroizing::new(enc_key_iv.iter().rev().copied().collect::<Vec<u8>>());

        let mut tg_enc_key = [0u8; 32];
        tg_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
        let mut tg_enc_iv_arr = [0u8; IV_LEN];
        tg_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
        let tg_enc_iv = u128::from_be_bytes(tg_enc_iv_arr);

        let mut tg_dec_key = [0u8; 32];
        tg_dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
        let mut tg_dec_iv_arr = [0u8; IV_LEN];
        tg_dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
        let tg_dec_iv = u128::from_be_bytes(tg_dec_iv_arr);

        return (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv);
    }
}

/// Encrypt nonce for sending to Telegram and return cipher objects with correct counter state
pub fn encrypt_tg_nonce_with_ciphers(nonce: &[u8; HANDSHAKE_LEN]) -> (Vec<u8>, AesCtr, AesCtr) {
    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv = Zeroizing::new(enc_key_iv.iter().rev().copied().collect::<Vec<u8>>());

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut enc_iv_arr = [0u8; IV_LEN];
    enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);

    let mut dec_key = [0u8; 32];
    dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
    let mut dec_iv_arr = [0u8; IV_LEN];
    dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let mut encryptor = AesCtr::new(&enc_key, enc_iv);
    let encrypted_full = encryptor.encrypt(nonce); // counter: 0 → 4

    let mut result = nonce[..PROTO_TAG_POS].to_vec();
    result.extend_from_slice(&encrypted_full[PROTO_TAG_POS..]);

    let decryptor = AesCtr::new(&dec_key, dec_iv);
    enc_key.zeroize();
    dec_key.zeroize();

    (result, encryptor, decryptor)
}

/// Encrypt nonce for sending to Telegram (legacy function for compatibility)
pub fn encrypt_tg_nonce(nonce: &[u8; HANDSHAKE_LEN]) -> Vec<u8> {
    let (encrypted, _, _) = encrypt_tg_nonce_with_ciphers(nonce);
    encrypted
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

/// Compile-time guard: HandshakeSuccess holds cryptographic key material and
/// must never be Copy.  A Copy impl would allow silent key duplication,
/// undermining the zeroize-on-drop guarantee.
mod compile_time_security_checks {
    use super::HandshakeSuccess;
    use static_assertions::assert_not_impl_all;

    assert_not_impl_all!(HandshakeSuccess: Copy, Clone);
}
