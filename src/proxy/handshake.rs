//! MTProto Handshake

#![allow(dead_code)]

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use hmac::{Hmac, Mac};
#[cfg(test)]
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
#[cfg(test)]
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, trace, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{ProxyConfig, UnknownSniAction};
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
use sha2::Sha256;
use subtle::ConstantTimeEq;

const ACCESS_SECRET_BYTES: usize = 16;
const UNKNOWN_SNI_WARN_COOLDOWN_SECS: u64 = 5;
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
const STICKY_HINT_MAX_ENTRIES: usize = 65_536;
const CANDIDATE_HINT_TRACK_CAP: usize = 64;
const OVERLOAD_CANDIDATE_BUDGET_HINTED: usize = 16;
const OVERLOAD_CANDIDATE_BUDGET_UNHINTED: usize = 8;
const RECENT_USER_RING_SCAN_LIMIT: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
const AUTH_PROBE_BACKOFF_BASE_MS: u64 = 1;
#[cfg(not(test))]
const AUTH_PROBE_BACKOFF_BASE_MS: u64 = 25;

#[cfg(test)]
const AUTH_PROBE_BACKOFF_MAX_MS: u64 = 16;
#[cfg(not(test))]
const AUTH_PROBE_BACKOFF_MAX_MS: u64 = 1_000;

#[derive(Clone, Copy)]
pub(crate) struct AuthProbeState {
    fail_streak: u32,
    blocked_until: Instant,
    last_seen: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthProbeSaturationState {
    fail_streak: u32,
    blocked_until: Instant,
    last_seen: Instant,
}
fn unknown_sni_warn_state_lock_in(
    shared: &ProxySharedState,
) -> std::sync::MutexGuard<'_, Option<Instant>> {
    shared
        .handshake
        .unknown_sni_warn_next_allowed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn should_emit_unknown_sni_warn_in(shared: &ProxySharedState, now: Instant) -> bool {
    let mut guard = unknown_sni_warn_state_lock_in(shared);
    if let Some(next_allowed) = *guard
        && now < next_allowed
    {
        return false;
    }
    *guard = Some(now + Duration::from_secs(UNKNOWN_SNI_WARN_COOLDOWN_SECS));
    true
}

#[derive(Clone, Copy)]
struct ParsedTlsAuthMaterial {
    digest: [u8; tls::TLS_DIGEST_LEN],
    session_id: [u8; 32],
    session_id_len: usize,
    now: i64,
    ignore_time_skew: bool,
    boot_time_cap_secs: u32,
}

#[derive(Clone, Copy)]
struct TlsCandidateValidation {
    digest: [u8; tls::TLS_DIGEST_LEN],
    session_id: [u8; 32],
    session_id_len: usize,
}

struct MtprotoCandidateValidation {
    proto_tag: ProtoTag,
    dc_idx: i16,
    dec_key: [u8; 32],
    dec_iv: u128,
    enc_key: [u8; 32],
    enc_iv: u128,
    decryptor: AesCtr,
    encryptor: AesCtr,
}

fn sni_hint_hash(sni: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    for byte in sni.bytes() {
        hasher.write_u8(byte.to_ascii_lowercase());
    }
    hasher.finish()
}

fn ip_prefix_hint_key(peer_ip: IpAddr) -> u64 {
    match peer_ip {
        // Keep /24 granularity for IPv4 to avoid over-merging unrelated clients.
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            u64::from_be_bytes([0x04, a, b, c, 0, 0, 0, 0])
        }
        // Keep /56 granularity for IPv6 to retain stability while limiting bucket size.
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            u64::from_be_bytes([
                0x06, octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
            ])
        }
    }
}

fn sticky_hint_get_by_ip(shared: &ProxySharedState, peer_ip: IpAddr) -> Option<u32> {
    shared
        .handshake
        .sticky_user_by_ip
        .get(&peer_ip)
        .map(|entry| *entry)
}

fn sticky_hint_get_by_ip_prefix(shared: &ProxySharedState, peer_ip: IpAddr) -> Option<u32> {
    shared
        .handshake
        .sticky_user_by_ip_prefix
        .get(&ip_prefix_hint_key(peer_ip))
        .map(|entry| *entry)
}

fn sticky_hint_get_by_sni(shared: &ProxySharedState, sni: &str) -> Option<u32> {
    let key = sni_hint_hash(sni);
    shared
        .handshake
        .sticky_user_by_sni_hash
        .get(&key)
        .map(|entry| *entry)
}

fn sticky_hint_record_success_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    user_id: u32,
    sni: Option<&str>,
) {
    if shared.handshake.sticky_user_by_ip.len() > STICKY_HINT_MAX_ENTRIES {
        shared.handshake.sticky_user_by_ip.clear();
    }
    shared.handshake.sticky_user_by_ip.insert(peer_ip, user_id);

    if shared.handshake.sticky_user_by_ip_prefix.len() > STICKY_HINT_MAX_ENTRIES {
        shared.handshake.sticky_user_by_ip_prefix.clear();
    }
    shared
        .handshake
        .sticky_user_by_ip_prefix
        .insert(ip_prefix_hint_key(peer_ip), user_id);

    if let Some(sni) = sni {
        if shared.handshake.sticky_user_by_sni_hash.len() > STICKY_HINT_MAX_ENTRIES {
            shared.handshake.sticky_user_by_sni_hash.clear();
        }
        shared
            .handshake
            .sticky_user_by_sni_hash
            .insert(sni_hint_hash(sni), user_id);
    }
}

fn record_recent_user_success_in(shared: &ProxySharedState, user_id: u32) {
    let ring = &shared.handshake.recent_user_ring;
    if ring.is_empty() {
        return;
    }
    let seq = shared
        .handshake
        .recent_user_ring_seq
        .fetch_add(1, Ordering::Relaxed);
    let idx = (seq as usize) % ring.len();
    ring[idx].store(user_id.saturating_add(1), Ordering::Relaxed);
}

fn mark_candidate_if_new(tried_user_ids: &mut [u32], tried_len: &mut usize, user_id: u32) -> bool {
    if tried_user_ids[..*tried_len].contains(&user_id) {
        return false;
    }
    if *tried_len < tried_user_ids.len() {
        tried_user_ids[*tried_len] = user_id;
        *tried_len += 1;
    }
    true
}

fn budget_for_validation(total_users: usize, overload: bool, has_hint: bool) -> usize {
    if total_users == 0 {
        return 0;
    }
    if !overload {
        return total_users;
    }
    let cap = if has_hint {
        OVERLOAD_CANDIDATE_BUDGET_HINTED
    } else {
        OVERLOAD_CANDIDATE_BUDGET_UNHINTED
    };
    total_users.min(cap.max(1))
}

fn parse_tls_auth_material(
    handshake: &[u8],
    ignore_time_skew: bool,
    replay_window_secs: u64,
) -> Option<ParsedTlsAuthMaterial> {
    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        return None;
    }

    let digest: [u8; tls::TLS_DIGEST_LEN] = handshake
        [tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .try_into()
        .ok()?;

    let session_id_len_pos = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN;
    let session_id_len = usize::from(handshake.get(session_id_len_pos).copied()?);
    if session_id_len > 32 {
        return None;
    }
    let session_id_start = session_id_len_pos + 1;
    if handshake.len() < session_id_start + session_id_len {
        return None;
    }

    let mut session_id = [0u8; 32];
    session_id[..session_id_len]
        .copy_from_slice(&handshake[session_id_start..session_id_start + session_id_len]);

    let now = if !ignore_time_skew {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        i64::try_from(d.as_secs()).ok()?
    } else {
        0_i64
    };

    let replay_window_u32 = u32::try_from(replay_window_secs).unwrap_or(u32::MAX);
    let boot_time_cap_secs = if ignore_time_skew {
        0
    } else {
        tls::BOOT_TIME_MAX_SECS
            .min(replay_window_u32)
            .min(tls::BOOT_TIME_COMPAT_MAX_SECS)
    };

    Some(ParsedTlsAuthMaterial {
        digest,
        session_id,
        session_id_len,
        now,
        ignore_time_skew,
        boot_time_cap_secs,
    })
}

fn compute_tls_hmac_zeroed_digest(secret: &[u8], handshake: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&handshake[..tls::TLS_DIGEST_POS]);
    mac.update(&[0u8; tls::TLS_DIGEST_LEN]);
    mac.update(&handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN..]);
    mac.finalize().into_bytes().into()
}

fn validate_tls_secret_candidate(
    parsed: &ParsedTlsAuthMaterial,
    handshake: &[u8],
    secret: &[u8],
) -> Option<TlsCandidateValidation> {
    let computed = compute_tls_hmac_zeroed_digest(secret, handshake);
    if !bool::from(parsed.digest[..28].ct_eq(&computed[..28])) {
        return None;
    }

    let timestamp = u32::from_le_bytes([
        parsed.digest[28] ^ computed[28],
        parsed.digest[29] ^ computed[29],
        parsed.digest[30] ^ computed[30],
        parsed.digest[31] ^ computed[31],
    ]);

    if !parsed.ignore_time_skew {
        let is_boot_time = parsed.boot_time_cap_secs > 0 && timestamp < parsed.boot_time_cap_secs;
        if !is_boot_time {
            let time_diff = parsed.now - i64::from(timestamp);
            if !(tls::TIME_SKEW_MIN..=tls::TIME_SKEW_MAX).contains(&time_diff) {
                return None;
            }
        }
    }

    Some(TlsCandidateValidation {
        digest: parsed.digest,
        session_id: parsed.session_id,
        session_id_len: parsed.session_id_len,
    })
}

fn validate_mtproto_secret_candidate(
    handshake: &[u8; HANDSHAKE_LEN],
    dec_prekey: &[u8; PREKEY_LEN],
    dec_iv: u128,
    enc_prekey: &[u8; PREKEY_LEN],
    enc_iv: u128,
    secret: &[u8; ACCESS_SECRET_BYTES],
    config: &ProxyConfig,
    is_tls: bool,
) -> Option<MtprotoCandidateValidation> {
    let mut dec_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
    dec_key_input.extend_from_slice(dec_prekey);
    dec_key_input.extend_from_slice(secret);
    let dec_key = Zeroizing::new(sha256(&dec_key_input));

    let mut decryptor = AesCtr::new(&dec_key, dec_iv);
    let mut decrypted = *handshake;
    decryptor.apply(&mut decrypted);

    let tag_bytes: [u8; 4] = [
        decrypted[PROTO_TAG_POS],
        decrypted[PROTO_TAG_POS + 1],
        decrypted[PROTO_TAG_POS + 2],
        decrypted[PROTO_TAG_POS + 3],
    ];
    let proto_tag = ProtoTag::from_bytes(tag_bytes)?;
    if !mode_enabled_for_proto(config, proto_tag, is_tls) {
        return None;
    }

    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);

    let mut enc_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
    enc_key_input.extend_from_slice(enc_prekey);
    enc_key_input.extend_from_slice(secret);
    let enc_key = Zeroizing::new(sha256(&enc_key_input));

    let encryptor = AesCtr::new(&enc_key, enc_iv);

    Some(MtprotoCandidateValidation {
        proto_tag,
        dc_idx,
        dec_key: *dec_key,
        dec_iv,
        enc_key: *enc_key,
        enc_iv,
        decryptor,
        encryptor,
    })
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

fn auth_probe_eviction_offset_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> usize {
    let hasher_state = &shared.handshake.auth_probe_eviction_hasher;
    let mut hasher = hasher_state.build_hasher();
    peer_ip.hash(&mut hasher);
    now.hash(&mut hasher);
    hasher.finish() as usize
}

fn auth_probe_scan_start_offset_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
    state_len: usize,
    scan_limit: usize,
) -> usize {
    if state_len == 0 || scan_limit == 0 {
        return 0;
    }

    auth_probe_eviction_offset_in(shared, peer_ip, now) % state_len
}

fn auth_probe_is_throttled_in(shared: &ProxySharedState, peer_ip: IpAddr, now: Instant) -> bool {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
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

fn auth_probe_saturation_grace_exhausted_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> bool {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
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

fn auth_probe_should_apply_preauth_throttle_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> bool {
    if !auth_probe_is_throttled_in(shared, peer_ip, now) {
        return false;
    }

    if !auth_probe_saturation_is_throttled_in(shared, now) {
        return true;
    }

    auth_probe_saturation_grace_exhausted_in(shared, peer_ip, now)
}

fn auth_probe_saturation_is_throttled_in(shared: &ProxySharedState, now: Instant) -> bool {
    let mut guard = shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

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

fn auth_probe_note_saturation_in(shared: &ProxySharedState, now: Instant) {
    let mut guard = shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

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

fn auth_probe_record_failure_in(shared: &ProxySharedState, peer_ip: IpAddr, now: Instant) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
    auth_probe_record_failure_with_state_in(shared, state, peer_ip, now);
}

fn auth_probe_record_failure_with_state_in(
    shared: &ProxySharedState,
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
                auth_probe_note_saturation_in(shared, now);
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

            if state_len <= AUTH_PROBE_PRUNE_SCAN_LIMIT {
                for entry in state.iter() {
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
            } else {
                let start_offset =
                    auth_probe_scan_start_offset_in(shared, peer_ip, now, state_len, scan_limit);
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
                                    || (fail_streak == current_fail
                                        && last_seen >= current_seen) => {}
                            _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                        }
                        if auth_probe_state_expired(entry.value(), now) {
                            stale_keys.push(key);
                        }
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
                auth_probe_note_saturation_in(shared, now);
                return;
            };
            state.remove(&evict_key);
            auth_probe_note_saturation_in(shared, now);
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

fn auth_probe_record_success_in(shared: &ProxySharedState, peer_ip: IpAddr) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
    state.remove(&peer_ip);
}

#[cfg(test)]
pub(crate) fn auth_probe_record_failure_for_testing(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) {
    auth_probe_record_failure_in(shared, peer_ip, now);
}

#[cfg(test)]
pub(crate) fn auth_probe_fail_streak_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> Option<u32> {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    shared
        .handshake
        .auth_probe
        .get(&peer_ip)
        .map(|entry| entry.fail_streak)
}

#[cfg(test)]
pub(crate) fn clear_auth_probe_state_for_testing_in_shared(shared: &ProxySharedState) {
    shared.handshake.auth_probe.clear();
    match shared.handshake.auth_probe_saturation.lock() {
        Ok(mut saturation) => {
            *saturation = None;
        }
        Err(poisoned) => {
            let mut saturation = poisoned.into_inner();
            *saturation = None;
            shared.handshake.auth_probe_saturation.clear_poison();
        }
    }
}

fn warn_invalid_secret_once_in(
    shared: &ProxySharedState,
    name: &str,
    reason: &str,
    expected: usize,
    got: Option<usize>,
) {
    let key = (name.to_string(), reason.to_string());
    let should_warn = match shared.handshake.invalid_secret_warned.lock() {
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

fn decode_user_secret(shared: &ProxySharedState, name: &str, secret_hex: &str) -> Option<Vec<u8>> {
    match hex::decode(secret_hex) {
        Ok(bytes) if bytes.len() == ACCESS_SECRET_BYTES => Some(bytes),
        Ok(bytes) => {
            warn_invalid_secret_once_in(
                shared,
                name,
                "invalid_length",
                ACCESS_SECRET_BYTES,
                Some(bytes.len()),
            );
            None
        }
        Err(_) => {
            warn_invalid_secret_once_in(shared, name, "invalid_hex", ACCESS_SECRET_BYTES, None);
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

fn decode_user_secrets_in(
    shared: &ProxySharedState,
    config: &ProxyConfig,
    preferred_user: Option<&str>,
) -> Vec<(String, Vec<u8>)> {
    let mut secrets = Vec::with_capacity(config.access.users.len());

    if let Some(preferred) = preferred_user
        && let Some(secret_hex) = config.access.users.get(preferred)
        && let Some(bytes) = decode_user_secret(shared, preferred, secret_hex)
    {
        secrets.push((preferred.to_string(), bytes));
    }

    for (name, secret_hex) in &config.access.users {
        if preferred_user.is_some_and(|preferred| preferred == name.as_str()) {
            continue;
        }
        if let Some(bytes) = decode_user_secret(shared, name, secret_hex) {
            secrets.push((name.clone(), bytes));
        }
    }

    secrets
}

#[cfg(test)]
pub(crate) fn auth_probe_state_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &DashMap<IpAddr, AuthProbeState> {
    &shared.handshake.auth_probe
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_state_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &Mutex<Option<AuthProbeSaturationState>> {
    &shared.handshake.auth_probe_saturation
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_state_lock_for_testing_in_shared(
    shared: &ProxySharedState,
) -> std::sync::MutexGuard<'_, Option<AuthProbeSaturationState>> {
    shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) fn clear_unknown_sni_warn_state_for_testing_in_shared(shared: &ProxySharedState) {
    let mut guard = shared
        .handshake
        .unknown_sni_warn_next_allowed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}

#[cfg(test)]
pub(crate) fn should_emit_unknown_sni_warn_for_testing_in_shared(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    should_emit_unknown_sni_warn_in(shared, now)
}

#[cfg(test)]
pub(crate) fn clear_warned_secrets_for_testing_in_shared(shared: &ProxySharedState) {
    if let Ok(mut guard) = shared.handshake.invalid_secret_warned.lock() {
        guard.clear();
    }
}

#[cfg(test)]
pub(crate) fn warned_secrets_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &Mutex<HashSet<(String, String)>> {
    &shared.handshake.invalid_secret_warned
}

#[cfg(test)]
pub(crate) fn auth_probe_is_throttled_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> bool {
    auth_probe_is_throttled_in(shared, peer_ip, Instant::now())
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_is_throttled_for_testing_in_shared(
    shared: &ProxySharedState,
) -> bool {
    auth_probe_saturation_is_throttled_in(shared, Instant::now())
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_is_throttled_at_for_testing_in_shared(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    auth_probe_saturation_is_throttled_in(shared, now)
}

#[inline]
fn find_matching_tls_domain<'a>(config: &'a ProxyConfig, sni: &str) -> Option<&'a str> {
    if config.censorship.tls_domain.eq_ignore_ascii_case(sni) {
        return Some(config.censorship.tls_domain.as_str());
    }

    for domain in &config.censorship.tls_domains {
        if domain.eq_ignore_ascii_case(sni) {
            return Some(domain.as_str());
        }
    }

    None
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
        crate::proxy::masking::sample_lognormal_percentile_bounded(min, max, &mut rand::rng())
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
#[cfg(test)]
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
    let shared = ProxySharedState::new();
    handle_tls_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        rng,
        tls_cache,
        shared.as_ref(),
    )
    .await
}

pub async fn handle_tls_handshake_with_shared<R, W>(
    handshake: &[u8],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
    shared: &ProxySharedState,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    handle_tls_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        rng,
        tls_cache,
        shared,
    )
    .await
}

async fn handle_tls_handshake_impl<R, W>(
    handshake: &[u8],
    reader: R,
    mut writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
    shared: &ProxySharedState,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    debug!(peer = %peer, handshake_len = handshake.len(), "Processing TLS handshake");

    let throttle_now = Instant::now();
    if auth_probe_should_apply_preauth_throttle_in(shared, peer.ip(), throttle_now) {
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "TLS handshake rejected by pre-auth probe throttle");
        return HandshakeResult::BadClient { reader, writer };
    }

    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "TLS handshake too short");
        return HandshakeResult::BadClient { reader, writer };
    }

    let client_sni = tls::extract_sni_from_client_hello(handshake);
    let preferred_user_hint = client_sni
        .as_deref()
        .filter(|sni| config.access.users.contains_key(*sni));
    let matched_tls_domain = client_sni
        .as_deref()
        .and_then(|sni| find_matching_tls_domain(config, sni));

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
    // Fail-closed to TLS 1.3 semantics when ClientHello version is ambiguous:
    // this avoids leaking certificate payload on malformed probes.
    let client_tls_version = tls::detect_client_hello_tls_version(handshake)
        .unwrap_or(tls::ClientHelloTlsVersion::Tls13);

    if client_sni.is_some() && matched_tls_domain.is_none() && preferred_user_hint.is_none() {
        let sni = client_sni.as_deref().unwrap_or_default();
        match config.censorship.unknown_sni_action {
            UnknownSniAction::Accept => {
                debug!(
                    peer = %peer,
                    sni = %sni,
                    unknown_sni = true,
                    unknown_sni_action = ?config.censorship.unknown_sni_action,
                    "TLS handshake accepted by unknown SNI policy"
                );
            }
            action @ (UnknownSniAction::Drop
            | UnknownSniAction::Mask
            | UnknownSniAction::RejectHandshake) => {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                // For Drop/Mask we apply the synthetic ServerHello delay so
                // the fail-closed path is timing-indistinguishable from the
                // success path. For RejectHandshake we deliberately skip the
                // delay: a stock modern nginx with `ssl_reject_handshake on;`
                // responds with the alert essentially immediately, so
                // injecting 8-24ms here would itself become a distinguisher
                // against the public baseline we are trying to blend into.
                if !matches!(action, UnknownSniAction::RejectHandshake) {
                    maybe_apply_server_hello_delay(config).await;
                }
                let log_now = Instant::now();
                if should_emit_unknown_sni_warn_in(shared, log_now) {
                    warn!(
                        peer = %peer,
                        sni = %sni,
                        unknown_sni = true,
                        unknown_sni_action = ?action,
                        "TLS handshake rejected by unknown SNI policy"
                    );
                } else {
                    info!(
                        peer = %peer,
                        sni = %sni,
                        unknown_sni = true,
                        unknown_sni_action = ?action,
                        "TLS handshake rejected by unknown SNI policy"
                    );
                }
                if matches!(action, UnknownSniAction::RejectHandshake) {
                    // TLS alert record layer:
                    //   0x15            ContentType.alert
                    //   0x03 0x03       legacy_record_version = TLS 1.2
                    //                   (matches what modern nginx emits in
                    //                   the first server -> client record,
                    //                   per RFC 8446 5.1 guidance)
                    //   0x00 0x02       length = 2
                    // Alert payload:
                    //   0x02            AlertLevel.fatal
                    //   0x70            AlertDescription.unrecognized_name (112, RFC 6066)
                    const TLS_ALERT_UNRECOGNIZED_NAME: [u8; 7] =
                        [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];
                    if let Err(e) = writer.write_all(&TLS_ALERT_UNRECOGNIZED_NAME).await {
                        debug!(
                            peer = %peer,
                            error = %e,
                            "Failed to write unrecognized_name TLS alert"
                        );
                    } else {
                        let _ = writer.flush().await;
                    }
                }
                return match action {
                    UnknownSniAction::Drop | UnknownSniAction::RejectHandshake => {
                        HandshakeResult::Error(ProxyError::UnknownTlsSni)
                    }
                    UnknownSniAction::Mask => HandshakeResult::BadClient { reader, writer },
                    UnknownSniAction::Accept => unreachable!(),
                };
            }
        }
    }

    let mut validation_digest = [0u8; tls::TLS_DIGEST_LEN];
    let mut validation_session_id = [0u8; 32];
    let mut validation_session_id_len = 0usize;
    let mut validated_user = String::new();
    let mut validated_secret = [0u8; ACCESS_SECRET_BYTES];
    let mut validated_user_id: Option<u32> = None;

    if let Some(snapshot) = config.runtime_user_auth() {
        let parsed = match parse_tls_auth_material(
            handshake,
            config.access.ignore_time_skew,
            config.access.replay_window_secs,
        ) {
            Some(parsed) => parsed,
            None => {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                debug!(peer = %peer, "TLS handshake auth material parsing failed");
                return HandshakeResult::BadClient { reader, writer };
            }
        };

        let sticky_ip_hint = sticky_hint_get_by_ip(shared, peer.ip());
        let preferred_user_id = preferred_user_hint.and_then(|user| snapshot.user_id_by_name(user));
        let sticky_sni_hint = client_sni
            .as_deref()
            .and_then(|sni| sticky_hint_get_by_sni(shared, sni));
        let sticky_prefix_hint = sticky_hint_get_by_ip_prefix(shared, peer.ip());
        let sni_candidates = client_sni
            .as_deref()
            .and_then(|sni| snapshot.sni_candidates(sni));
        let sni_initial_candidates = client_sni
            .as_deref()
            .and_then(|sni| snapshot.sni_initial_candidates(sni));

        let has_hint = sticky_ip_hint.is_some()
            || preferred_user_id.is_some()
            || sticky_sni_hint.is_some()
            || sticky_prefix_hint.is_some()
            || sni_candidates.is_some_and(|ids| !ids.is_empty())
            || sni_initial_candidates.is_some_and(|ids| !ids.is_empty());
        let overload = auth_probe_saturation_is_throttled_in(shared, Instant::now());
        let candidate_budget = budget_for_validation(snapshot.entries().len(), overload, has_hint);

        let mut tried_user_ids = [u32::MAX; CANDIDATE_HINT_TRACK_CAP];
        let mut tried_len = 0usize;
        let mut validation_checks = 0usize;
        let mut budget_exhausted = false;

        macro_rules! try_user_id {
            ($user_id:expr) => {{
                if validation_checks >= candidate_budget {
                    budget_exhausted = true;
                    false
                } else if !mark_candidate_if_new(&mut tried_user_ids, &mut tried_len, $user_id) {
                    false
                } else if let Some(entry) = snapshot.entry_by_id($user_id) {
                    validation_checks = validation_checks.saturating_add(1);
                    if let Some(candidate) =
                        validate_tls_secret_candidate(&parsed, handshake, &entry.secret)
                    {
                        validation_digest = candidate.digest;
                        validation_session_id = candidate.session_id;
                        validation_session_id_len = candidate.session_id_len;
                        validated_secret.copy_from_slice(&entry.secret);
                        validated_user = entry.user.clone();
                        validated_user_id = Some($user_id);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }};
        }

        let mut matched = false;
        if let Some(user_id) = sticky_ip_hint {
            matched = try_user_id!(user_id);
        }

        if !matched && let Some(user_id) = preferred_user_id {
            matched = try_user_id!(user_id);
        }

        if !matched && let Some(user_id) = sticky_sni_hint {
            matched = try_user_id!(user_id);
        }

        if !matched && let Some(user_id) = sticky_prefix_hint {
            matched = try_user_id!(user_id);
        }

        if !matched
            && !budget_exhausted
            && let Some(candidate_ids) = sni_candidates
        {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched
            && !budget_exhausted
            && let Some(candidate_ids) = sni_initial_candidates
        {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched && !budget_exhausted {
            let ring = &shared.handshake.recent_user_ring;
            if !ring.is_empty() {
                let next_seq = shared
                    .handshake
                    .recent_user_ring_seq
                    .load(Ordering::Relaxed);
                let scan_limit = ring.len().min(RECENT_USER_RING_SCAN_LIMIT);
                for offset in 0..scan_limit {
                    let idx = (next_seq as usize + ring.len() - 1 - offset) % ring.len();
                    let encoded_user_id = ring[idx].load(Ordering::Relaxed);
                    if encoded_user_id == 0 {
                        continue;
                    }
                    if try_user_id!(encoded_user_id - 1) {
                        matched = true;
                        break;
                    }
                    if budget_exhausted {
                        break;
                    }
                }
            }
        }

        if !matched && !budget_exhausted {
            for idx in 0..snapshot.entries().len() {
                let Some(user_id) = u32::try_from(idx).ok() else {
                    break;
                };
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        shared
            .handshake
            .auth_expensive_checks_total
            .fetch_add(validation_checks as u64, Ordering::Relaxed);
        if budget_exhausted {
            shared
                .handshake
                .auth_budget_exhausted_total
                .fetch_add(1, Ordering::Relaxed);
        }

        if !matched {
            auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            debug!(
                peer = %peer,
                ignore_time_skew = config.access.ignore_time_skew,
                budget_exhausted = budget_exhausted,
                candidate_budget = candidate_budget,
                validation_checks = validation_checks,
                "TLS handshake validation failed - no matching user, time skew, or budget exhausted"
            );
            return HandshakeResult::BadClient { reader, writer };
        }
    } else {
        let secrets = decode_user_secrets_in(shared, config, preferred_user_hint);
        let validation = match tls::validate_tls_handshake_with_replay_window(
            handshake,
            &secrets,
            config.access.ignore_time_skew,
            config.access.replay_window_secs,
        ) {
            Some(v) => v,
            None => {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                debug!(
                    peer = %peer,
                    ignore_time_skew = config.access.ignore_time_skew,
                    "TLS handshake validation failed - no matching user or time skew"
                );
                return HandshakeResult::BadClient { reader, writer };
            }
        };
        let secret = match secrets.iter().find(|(name, _)| *name == validation.user) {
            Some((_, s)) if s.len() == ACCESS_SECRET_BYTES => s,
            _ => {
                maybe_apply_server_hello_delay(config).await;
                return HandshakeResult::BadClient { reader, writer };
            }
        };

        validation_digest = validation.digest;
        validation_session_id_len = validation.session_id.len();
        if validation_session_id_len > validation_session_id.len() {
            maybe_apply_server_hello_delay(config).await;
            return HandshakeResult::BadClient { reader, writer };
        }
        validation_session_id[..validation_session_id_len].copy_from_slice(&validation.session_id);
        validated_user = validation.user;
        validated_secret.copy_from_slice(secret);
    }

    // Reject known replay digests before expensive cache/domain/ALPN policy work.
    let digest_half = &validation_digest[..tls::TLS_DIGEST_HALF_LEN];
    if replay_checker.check_tls_digest(digest_half) {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        warn!(peer = %peer, "TLS replay attack detected (duplicate digest)");
        return HandshakeResult::BadClient { reader, writer };
    }

    let cached = if config.censorship.tls_emulation {
        if let Some(cache) = tls_cache.as_ref() {
            let selected_domain =
                matched_tls_domain.unwrap_or(config.censorship.tls_domain.as_str());
            let cached_entry = cache.get(selected_domain).await;
            let use_full_cert_payload = if config.censorship.serverhello_compact
                && matches!(client_tls_version, tls::ClientHelloTlsVersion::Tls12)
            {
                cache
                    .take_full_cert_budget_for_ip(
                        peer.ip(),
                        Duration::from_secs(config.censorship.tls_full_cert_ttl_secs),
                    )
                    .await
            } else {
                true
            };
            Some((cached_entry, use_full_cert_payload))
        } else {
            None
        }
    } else {
        None
    };

    // Add replay digest only for policy-valid handshakes.
    replay_checker.add_tls_digest(digest_half);

    let validation_session_id_slice = &validation_session_id[..validation_session_id_len];

    let response = if let Some((cached_entry, use_full_cert_payload)) = cached {
        emulator::build_emulated_server_hello(
            &validated_secret,
            &validation_digest,
            validation_session_id_slice,
            &cached_entry,
            use_full_cert_payload,
            config.censorship.serverhello_compact,
            client_tls_version,
            rng,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    } else {
        tls::build_server_hello(
            &validated_secret,
            &validation_digest,
            validation_session_id_slice,
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
        user = %validated_user,
        "TLS handshake successful"
    );

    auth_probe_record_success_in(shared, peer.ip());

    if let Some(user_id) = validated_user_id {
        sticky_hint_record_success_in(shared, peer.ip(), user_id, client_sni.as_deref());
        record_recent_user_success_in(shared, user_id);
    }

    HandshakeResult::Success((
        FakeTlsReader::new(reader),
        FakeTlsWriter::new(writer),
        validated_user,
    ))
}

/// Handle MTProto obfuscation handshake
#[cfg(test)]
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
    let shared = ProxySharedState::new();
    handle_mtproto_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        is_tls,
        preferred_user,
        shared.as_ref(),
    )
    .await
}

pub async fn handle_mtproto_handshake_with_shared<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
    shared: &ProxySharedState,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    handle_mtproto_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        is_tls,
        preferred_user,
        shared,
    )
    .await
}

async fn handle_mtproto_handshake_impl<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
    shared: &ProxySharedState,
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
    if auth_probe_should_apply_preauth_throttle_in(shared, peer.ip(), throttle_now) {
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "MTProto handshake rejected by pre-auth probe throttle");
        return HandshakeResult::BadClient { reader, writer };
    }

    let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut dec_prekey = [0u8; PREKEY_LEN];
    dec_prekey.copy_from_slice(&dec_prekey_iv[..PREKEY_LEN]);
    let mut dec_iv_arr = [0u8; IV_LEN];
    dec_iv_arr.copy_from_slice(&dec_prekey_iv[PREKEY_LEN..]);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let mut enc_prekey_iv = [0u8; PREKEY_LEN + IV_LEN];
    for idx in 0..enc_prekey_iv.len() {
        enc_prekey_iv[idx] = dec_prekey_iv[dec_prekey_iv.len() - 1 - idx];
    }
    let mut enc_prekey = [0u8; PREKEY_LEN];
    enc_prekey.copy_from_slice(&enc_prekey_iv[..PREKEY_LEN]);
    let mut enc_iv_arr = [0u8; IV_LEN];
    enc_iv_arr.copy_from_slice(&enc_prekey_iv[PREKEY_LEN..]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);

    if let Some(snapshot) = config.runtime_user_auth() {
        let sticky_ip_hint = sticky_hint_get_by_ip(shared, peer.ip());
        let sticky_prefix_hint = sticky_hint_get_by_ip_prefix(shared, peer.ip());
        let preferred_user_id = preferred_user.and_then(|user| snapshot.user_id_by_name(user));
        let has_hint =
            sticky_ip_hint.is_some() || sticky_prefix_hint.is_some() || preferred_user_id.is_some();
        let overload = auth_probe_saturation_is_throttled_in(shared, Instant::now());
        let candidate_budget = budget_for_validation(snapshot.entries().len(), overload, has_hint);

        let mut tried_user_ids = [u32::MAX; CANDIDATE_HINT_TRACK_CAP];
        let mut tried_len = 0usize;
        let mut validation_checks = 0usize;
        let mut budget_exhausted = false;

        let mut matched_user = String::new();
        let mut matched_user_id = None;
        let mut matched_validation = None;

        macro_rules! try_user_id {
            ($user_id:expr) => {{
                if validation_checks >= candidate_budget {
                    budget_exhausted = true;
                    false
                } else if !mark_candidate_if_new(&mut tried_user_ids, &mut tried_len, $user_id) {
                    false
                } else if let Some(entry) = snapshot.entry_by_id($user_id) {
                    validation_checks = validation_checks.saturating_add(1);
                    if let Some(validation) = validate_mtproto_secret_candidate(
                        handshake,
                        &dec_prekey,
                        dec_iv,
                        &enc_prekey,
                        enc_iv,
                        &entry.secret,
                        config,
                        is_tls,
                    ) {
                        matched_user = entry.user.clone();
                        matched_user_id = Some($user_id);
                        matched_validation = Some(validation);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }};
        }

        let mut matched = false;
        if let Some(user_id) = sticky_ip_hint {
            matched = try_user_id!(user_id);
        }

        if !matched && let Some(user_id) = preferred_user_id {
            matched = try_user_id!(user_id);
        }

        if !matched && let Some(user_id) = sticky_prefix_hint {
            matched = try_user_id!(user_id);
        }

        if !matched && !budget_exhausted {
            let ring = &shared.handshake.recent_user_ring;
            if !ring.is_empty() {
                let next_seq = shared
                    .handshake
                    .recent_user_ring_seq
                    .load(Ordering::Relaxed);
                let scan_limit = ring.len().min(RECENT_USER_RING_SCAN_LIMIT);
                for offset in 0..scan_limit {
                    let idx = (next_seq as usize + ring.len() - 1 - offset) % ring.len();
                    let encoded_user_id = ring[idx].load(Ordering::Relaxed);
                    if encoded_user_id == 0 {
                        continue;
                    }
                    if try_user_id!(encoded_user_id - 1) {
                        matched = true;
                        break;
                    }
                    if budget_exhausted {
                        break;
                    }
                }
            }
        }

        if !matched && !budget_exhausted {
            for idx in 0..snapshot.entries().len() {
                let Some(user_id) = u32::try_from(idx).ok() else {
                    break;
                };
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        shared
            .handshake
            .auth_expensive_checks_total
            .fetch_add(validation_checks as u64, Ordering::Relaxed);
        if budget_exhausted {
            shared
                .handshake
                .auth_budget_exhausted_total
                .fetch_add(1, Ordering::Relaxed);
        }

        if !matched {
            auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            debug!(
                peer = %peer,
                budget_exhausted = budget_exhausted,
                candidate_budget = candidate_budget,
                validation_checks = validation_checks,
                "MTProto handshake: no matching user found"
            );
            return HandshakeResult::BadClient { reader, writer };
        }

        let validation = matched_validation.expect("validation must exist when matched");

        // Apply replay tracking only after successful authentication.
        //
        // This ordering prevents an attacker from producing invalid handshakes that
        // still collide with a valid handshake's replay slot and thus evict a valid
        // entry from the cache. We accept the cost of performing the full
        // authentication check first to avoid poisoning the replay cache.
        if replay_checker.check_and_add_handshake(dec_prekey_iv) {
            auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            warn!(peer = %peer, user = %matched_user, "MTProto replay attack detected");
            return HandshakeResult::BadClient { reader, writer };
        }

        let dec_key = Zeroizing::new(validation.dec_key);
        let enc_key = Zeroizing::new(validation.enc_key);
        let success = HandshakeSuccess {
            user: matched_user.clone(),
            dc_idx: validation.dc_idx,
            proto_tag: validation.proto_tag,
            dec_key: *dec_key,
            dec_iv: validation.dec_iv,
            enc_key: *enc_key,
            enc_iv: validation.enc_iv,
            peer,
            is_tls,
        };

        debug!(
            peer = %peer,
            user = %matched_user,
            dc = validation.dc_idx,
            proto = ?validation.proto_tag,
            tls = is_tls,
            "MTProto handshake successful"
        );

        auth_probe_record_success_in(shared, peer.ip());
        if let Some(user_id) = matched_user_id {
            sticky_hint_record_success_in(shared, peer.ip(), user_id, None);
            record_recent_user_success_in(shared, user_id);
        }

        let max_pending = config.general.crypto_pending_buffer;
        return HandshakeResult::Success((
            CryptoReader::new(reader, validation.decryptor),
            CryptoWriter::new(writer, validation.encryptor, max_pending),
            success,
        ));
    } else {
        let decoded_users = decode_user_secrets_in(shared, config, preferred_user);
        let mut validation_checks = 0usize;

        for (user, secret) in decoded_users {
            if secret.len() != ACCESS_SECRET_BYTES {
                continue;
            }
            validation_checks = validation_checks.saturating_add(1);

            let mut secret_arr = [0u8; ACCESS_SECRET_BYTES];
            secret_arr.copy_from_slice(&secret);
            let Some(validation) = validate_mtproto_secret_candidate(
                handshake,
                &dec_prekey,
                dec_iv,
                &enc_prekey,
                enc_iv,
                &secret_arr,
                config,
                is_tls,
            ) else {
                continue;
            };

            shared
                .handshake
                .auth_expensive_checks_total
                .fetch_add(validation_checks as u64, Ordering::Relaxed);

            // Apply replay tracking only after successful authentication.
            //
            // This ordering prevents an attacker from producing invalid handshakes that
            // still collide with a valid handshake's replay slot and thus evict a valid
            // entry from the cache. We accept the cost of performing the full
            // authentication check first to avoid poisoning the replay cache.
            if replay_checker.check_and_add_handshake(dec_prekey_iv) {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                warn!(peer = %peer, user = %user, "MTProto replay attack detected");
                return HandshakeResult::BadClient { reader, writer };
            }

            let dec_key = Zeroizing::new(validation.dec_key);
            let enc_key = Zeroizing::new(validation.enc_key);
            let success = HandshakeSuccess {
                user: user.clone(),
                dc_idx: validation.dc_idx,
                proto_tag: validation.proto_tag,
                dec_key: *dec_key,
                dec_iv: validation.dec_iv,
                enc_key: *enc_key,
                enc_iv: validation.enc_iv,
                peer,
                is_tls,
            };

            debug!(
                peer = %peer,
                user = %user,
                dc = validation.dc_idx,
                proto = ?validation.proto_tag,
                tls = is_tls,
                "MTProto handshake successful"
            );

            auth_probe_record_success_in(shared, peer.ip());

            let max_pending = config.general.crypto_pending_buffer;
            return HandshakeResult::Success((
                CryptoReader::new(reader, validation.decryptor),
                CryptoWriter::new(writer, validation.encryptor, max_pending),
                success,
            ));
        }

        shared
            .handshake
            .auth_expensive_checks_total
            .fetch_add(validation_checks as u64, Ordering::Relaxed);
    }

    auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
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

/// Compile-time guard: HandshakeSuccess holds cryptographic key material and
/// must never be Copy.  A Copy impl would allow silent key duplication,
/// undermining the zeroize-on-drop guarantee.
mod compile_time_security_checks {
    use super::HandshakeSuccess;
    use static_assertions::assert_not_impl_all;

    assert_not_impl_all!(HandshakeSuccess: Copy, Clone);
}
