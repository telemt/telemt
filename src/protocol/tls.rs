//! Fake TLS 1.3 Handshake
//!
//! This module handles the fake TLS 1.3 handshake used by MTProto proxy
//! for domain fronting. The handshake looks like valid TLS 1.3 but
//! actually carries MTProto authentication data.

#![allow(dead_code)]
#![cfg_attr(not(test), forbid(clippy::undocumented_unsafe_blocks))]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::correctness,
        clippy::option_if_let_else,
        clippy::or_fun_call,
        clippy::branches_sharing_code,
        clippy::single_option_map,
        clippy::useless_let_if_seq,
        clippy::redundant_locals,
        clippy::cloned_ref_to_slice_refs,
        unsafe_code,
        clippy::await_holding_lock,
        clippy::await_holding_refcell_ref,
        clippy::debug_assert_with_mut_call,
        clippy::macro_use_imports,
        clippy::cast_ptr_alignment,
        clippy::cast_lossless,
        clippy::ptr_as_ptr,
        clippy::large_stack_arrays,
        clippy::same_functions_in_if_condition,
        trivial_casts,
        trivial_numeric_casts,
        unused_extern_crates,
        unused_import_braces,
        rust_2018_idioms
    )
)]
#![cfg_attr(
    not(test),
    allow(
        clippy::use_self,
        clippy::redundant_closure,
        clippy::too_many_arguments,
        clippy::doc_markdown,
        clippy::missing_const_for_fn,
        clippy::unnecessary_operation,
        clippy::redundant_pub_crate,
        clippy::derive_partial_eq_without_eq,
        clippy::type_complexity,
        clippy::new_ret_no_self,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::significant_drop_tightening,
        clippy::significant_drop_in_scrutinee,
        clippy::float_cmp,
        clippy::nursery
    )
)]

use super::constants::*;
use crate::crypto::{SecureRandom, sha256_hmac};
#[cfg(test)]
use crate::error::ProxyError;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

// ============= Public Constants =============

/// TLS handshake digest length
pub const TLS_DIGEST_LEN: usize = 32;

/// Position of digest in TLS ClientHello
pub const TLS_DIGEST_POS: usize = 11;

/// Length to store for replay protection (first 16 bytes of digest)
pub const TLS_DIGEST_HALF_LEN: usize = 16;

/// Time skew limits for anti-replay (in seconds)
///
/// The default window is intentionally narrow to reduce replay acceptance.
/// Operators with known clock-drifted clients should tune deployment config
/// (for example replay-window policy) to match their environment.
pub const TIME_SKEW_MIN: i64 = -2 * 60; // 2 minutes before
pub const TIME_SKEW_MAX: i64 = 2 * 60; // 2 minutes after
/// Maximum accepted boot-time timestamp (seconds) before skew checks are enforced.
pub const BOOT_TIME_MAX_SECS: u32 = 7 * 24 * 60 * 60;
/// Hard cap for boot-time compatibility bypass to avoid oversized acceptance
/// windows when replay TTL is configured very large.
pub const BOOT_TIME_COMPAT_MAX_SECS: u32 = 2 * 60;

// ============= Private Constants =============

/// TLS Extension types
mod extension_type {
    pub const KEY_SHARE: u16 = 0x0033;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const ALPN: u16 = 0x0010;
}

/// TLS Cipher Suites
mod cipher_suite {
    pub const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
}

/// TLS Named Curves
mod named_curve {
    pub const X25519: u16 = 0x001d;
}

// ============= TLS Validation Result =============

/// Result of validating TLS handshake
#[derive(Debug)]
pub struct TlsValidation {
    /// Username that validated
    pub user: String,
    /// Session ID from ClientHello
    pub session_id: Vec<u8>,
    /// Client digest for response generation
    pub digest: [u8; TLS_DIGEST_LEN],
    /// Timestamp extracted from digest
    pub timestamp: u32,
}

// ============= TLS Extension Builder =============

/// Builder for TLS extensions with correct length calculation
#[derive(Clone)]
struct TlsExtensionBuilder {
    extensions: Vec<u8>,
}

impl TlsExtensionBuilder {
    fn new() -> Self {
        Self {
            extensions: Vec::with_capacity(128),
        }
    }

    /// Add Key Share extension with X25519 key
    fn add_key_share(&mut self, public_key: &[u8; 32]) -> &mut Self {
        // Extension type: key_share (0x0033)
        self.extensions
            .extend_from_slice(&extension_type::KEY_SHARE.to_be_bytes());

        // Key share entry: curve (2) + key_len (2) + key (32) = 36 bytes
        // Extension data length
        let entry_len: u16 = 2 + 2 + 32; // curve + length + key
        self.extensions.extend_from_slice(&entry_len.to_be_bytes());

        // Named curve: x25519
        self.extensions
            .extend_from_slice(&named_curve::X25519.to_be_bytes());

        // Key length
        self.extensions.extend_from_slice(&(32u16).to_be_bytes());

        // Key data
        self.extensions.extend_from_slice(public_key);

        self
    }

    /// Add Supported Versions extension
    fn add_supported_versions(&mut self, version: u16) -> &mut Self {
        // Extension type: supported_versions (0x002b)
        self.extensions
            .extend_from_slice(&extension_type::SUPPORTED_VERSIONS.to_be_bytes());

        // Extension data: length (2) + version (2)
        self.extensions.extend_from_slice(&(2u16).to_be_bytes());

        // Selected version
        self.extensions.extend_from_slice(&version.to_be_bytes());

        self
    }

    /// Build final extensions with length prefix
    fn build(self) -> Vec<u8> {
        let Ok(len) = u16::try_from(self.extensions.len()) else {
            return Vec::new();
        };
        let mut result = Vec::with_capacity(2 + self.extensions.len());

        // Extensions length (2 bytes)
        result.extend_from_slice(&len.to_be_bytes());

        // Extensions data
        result.extend_from_slice(&self.extensions);

        result
    }

    /// Get current extensions without length prefix (for calculation)
    fn as_bytes(&self) -> &[u8] {
        &self.extensions
    }
}

// ============= ServerHello Builder =============

/// Builder for TLS ServerHello with correct structure
struct ServerHelloBuilder {
    /// Random bytes (32 bytes, will contain digest)
    random: [u8; 32],
    /// Session ID (echoed from ClientHello)
    session_id: Vec<u8>,
    /// Cipher suite
    cipher_suite: [u8; 2],
    /// Compression method
    compression: u8,
    /// Extensions
    extensions: TlsExtensionBuilder,
}

impl ServerHelloBuilder {
    fn new(session_id: Vec<u8>) -> Self {
        Self {
            random: [0u8; 32],
            session_id,
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
            compression: 0x00,
            extensions: TlsExtensionBuilder::new(),
        }
    }

    fn with_x25519_key(mut self, key: &[u8; 32]) -> Self {
        self.extensions.add_key_share(key);
        self
    }

    fn with_tls13_version(mut self) -> Self {
        // TLS 1.3 = 0x0304
        self.extensions.add_supported_versions(0x0304);
        self
    }

    /// Build ServerHello message (without record header)
    fn build_message(&self) -> Vec<u8> {
        let Ok(session_id_len) = u8::try_from(self.session_id.len()) else {
            return Vec::new();
        };
        let extensions = self.extensions.extensions.clone();
        let Ok(extensions_len) = u16::try_from(extensions.len()) else {
            return Vec::new();
        };

        // Calculate total length
        let body_len = 2 + // version
                       32 + // random
                       1 + self.session_id.len() + // session_id length + data
                       2 + // cipher suite
                       1 + // compression
                       2 + extensions.len(); // extensions length + data
        if body_len > 0x00ff_ffff {
            return Vec::new();
        }

        let mut message = Vec::with_capacity(4 + body_len);

        // Handshake header
        message.push(0x02); // ServerHello message type

        // 3-byte length
        let Ok(body_len_u32) = u32::try_from(body_len) else {
            return Vec::new();
        };
        let len_bytes = body_len_u32.to_be_bytes();
        message.extend_from_slice(&len_bytes[1..4]);

        // Server version (TLS 1.2 in header, actual version in extension)
        message.extend_from_slice(&TLS_VERSION);

        // Random (32 bytes) - placeholder, will be replaced with digest
        message.extend_from_slice(&self.random);

        // Session ID
        message.push(session_id_len);
        message.extend_from_slice(&self.session_id);

        // Cipher suite
        message.extend_from_slice(&self.cipher_suite);

        // Compression method
        message.push(self.compression);

        // Extensions length
        message.extend_from_slice(&extensions_len.to_be_bytes());

        // Extensions data
        message.extend_from_slice(&extensions);

        message
    }

    /// Build complete ServerHello TLS record
    fn build_record(&self) -> Vec<u8> {
        let message = self.build_message();
        if message.is_empty() {
            return Vec::new();
        }
        let Ok(message_len) = u16::try_from(message.len()) else {
            return Vec::new();
        };

        let mut record = Vec::with_capacity(5 + message.len());

        // TLS record header
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&message_len.to_be_bytes());

        // Message
        record.extend_from_slice(&message);

        record
    }
}

// ============= Public Functions =============

/// Validate TLS ClientHello against user secrets.
///
/// Returns validation result if a matching user is found.
/// The result **must** be used — ignoring it silently bypasses authentication.
#[must_use]
pub fn validate_tls_handshake(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
) -> Option<TlsValidation> {
    validate_tls_handshake_with_replay_window(
        handshake,
        secrets,
        ignore_time_skew,
        u64::from(BOOT_TIME_MAX_SECS),
    )
}

/// Validate TLS ClientHello and cap the boot-time bypass by replay-cache TTL.
///
/// A boot-time timestamp is only accepted when it falls below all three
/// bounds: `BOOT_TIME_MAX_SECS`, configured replay window, and
/// `BOOT_TIME_COMPAT_MAX_SECS`, preventing oversized compatibility windows.
#[must_use]
pub fn validate_tls_handshake_with_replay_window(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
    replay_window_secs: u64,
) -> Option<TlsValidation> {
    // Only pay the clock syscall when we will actually compare against it.
    // If `ignore_time_skew` is set, a broken or unavailable system clock
    // must not block legitimate clients — that would be a DoS via clock failure.
    let now = if !ignore_time_skew {
        system_time_to_unix_secs(SystemTime::now())?
    } else {
        0_i64
    };

    let replay_window_u32 = u32::try_from(replay_window_secs).unwrap_or(u32::MAX);
    // Boot-time bypass and ignore_time_skew serve different compatibility paths.
    // When skew checks are disabled, force boot-time cap to zero to prevent
    // accidental future coupling of boot-time logic into the ignore-skew path.
    let boot_time_cap_secs = if ignore_time_skew {
        0
    } else {
        BOOT_TIME_MAX_SECS
            .min(replay_window_u32)
            .min(BOOT_TIME_COMPAT_MAX_SECS)
    };

    validate_tls_handshake_at_time_with_boot_cap(
        handshake,
        secrets,
        ignore_time_skew,
        now,
        boot_time_cap_secs,
    )
}

fn system_time_to_unix_secs(now: SystemTime) -> Option<i64> {
    // `try_from` rejects values that overflow i64 (> ~292 billion years CE),
    // whereas `as i64` would silently wrap to a negative timestamp and corrupt
    // every subsequent time-skew comparison.
    let d = now.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_secs()).ok()
}

fn validate_tls_handshake_at_time(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
    now: i64,
) -> Option<TlsValidation> {
    validate_tls_handshake_at_time_with_boot_cap(
        handshake,
        secrets,
        ignore_time_skew,
        now,
        BOOT_TIME_MAX_SECS,
    )
}

fn validate_tls_handshake_at_time_with_boot_cap(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
    now: i64,
    boot_time_cap_secs: u32,
) -> Option<TlsValidation> {
    if handshake.len() < TLS_DIGEST_POS + TLS_DIGEST_LEN + 1 {
        return None;
    }

    // Extract digest
    let digest: [u8; TLS_DIGEST_LEN] = handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
        .try_into()
        .ok()?;

    // Extract session ID
    let session_id_len_pos = TLS_DIGEST_POS + TLS_DIGEST_LEN;
    let session_id_len = handshake.get(session_id_len_pos).copied()? as usize;
    if session_id_len > 32 {
        return None;
    }
    let session_id_start = session_id_len_pos + 1;

    if handshake.len() < session_id_start + session_id_len {
        return None;
    }

    let session_id = handshake[session_id_start..session_id_start + session_id_len].to_vec();

    // Build message for HMAC (with zeroed digest)
    let mut msg = handshake.to_vec();
    msg[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);

    let mut first_match: Option<(&String, u32)> = None;

    for (user, secret) in secrets {
        let computed = sha256_hmac(secret, &msg);

        // Constant-time equality check on the 28-byte HMAC window.
        // A variable-time short-circuit here lets an active censor measure how many
        // bytes matched, enabling secret brute-force via timing side-channels.
        // Direct comparison on the original arrays avoids a heap allocation and
        // removes the `try_into().unwrap()` that the intermediate Vec would require.
        if !bool::from(digest[..28].ct_eq(&computed[..28])) {
            continue;
        }

        // The last 4 bytes encode the timestamp as XOR(digest[28..32], computed[28..32]).
        // Inline array construction is infallible: both slices are [u8; 32] by construction.
        let timestamp = u32::from_le_bytes([
            digest[28] ^ computed[28],
            digest[29] ^ computed[29],
            digest[30] ^ computed[30],
            digest[31] ^ computed[31],
        ]);

        // time_diff is only meaningful (and `now` is only valid) when we are
        // actually checking the window.  Keep both inside the guard to make
        // the dead-code path explicit and prevent accidental future use of
        // a sentinel `now` value outside its intended scope.
        if !ignore_time_skew {
            // Allow very small timestamps (boot time instead of unix time)
            // This is a quirk in some clients that use uptime instead of real time
            let is_boot_time = boot_time_cap_secs > 0 && timestamp < boot_time_cap_secs;
            if !is_boot_time {
                let time_diff = now - i64::from(timestamp);
                if !(TIME_SKEW_MIN..=TIME_SKEW_MAX).contains(&time_diff) {
                    continue;
                }
            }
        }

        if first_match.is_none() {
            first_match = Some((user, timestamp));
        }
    }

    first_match.map(|(user, timestamp)| TlsValidation {
        user: user.clone(),
        session_id,
        digest,
        timestamp,
    })
}

/// Generate a fake X25519 public key for TLS
///
/// Uses RFC 7748 X25519 scalar multiplication over the canonical basepoint,
/// yielding distribution-consistent public keys for anti-fingerprinting.
pub fn gen_fake_x25519_key(rng: &SecureRandom) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&rng.bytes(32));
    x25519(scalar, X25519_BASEPOINT_BYTES)
}

/// Build TLS ServerHello response
///
/// This builds a complete TLS 1.3-like response including:
/// - ServerHello record with extensions
/// - Change Cipher Spec record
/// - Fake encrypted certificate (Application Data record)
///
/// The response includes an HMAC digest that the client can verify.
pub fn build_server_hello(
    secret: &[u8],
    client_digest: &[u8; TLS_DIGEST_LEN],
    session_id: &[u8],
    fake_cert_len: usize,
    rng: &SecureRandom,
    alpn: Option<Vec<u8>>,
    new_session_tickets: u8,
) -> Vec<u8> {
    const MIN_APP_DATA: usize = 64;
    const MAX_APP_DATA: usize = MAX_TLS_CIPHERTEXT_SIZE;
    let fake_cert_len = fake_cert_len.clamp(MIN_APP_DATA, MAX_APP_DATA);
    let x25519_key = gen_fake_x25519_key(rng);

    // Build ServerHello
    let server_hello = ServerHelloBuilder::new(session_id.to_vec())
        .with_x25519_key(&x25519_key)
        .with_tls13_version()
        .build_record();

    // Build Change Cipher Spec record
    let change_cipher_spec = [
        TLS_RECORD_CHANGE_CIPHER,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x01, // length = 1
        0x01, // CCS byte
    ];

    // Build first encrypted flight mimic as opaque ApplicationData bytes.
    // Embed a compact EncryptedExtensions-like ALPN block when selected.
    let mut fake_cert = Vec::with_capacity(fake_cert_len);
    if let Some(proto) = alpn
        .as_ref()
        .filter(|p| !p.is_empty() && p.len() <= u8::MAX as usize)
    {
        let proto_list_len = 1usize + proto.len();
        let ext_data_len = 2usize + proto_list_len;
        let marker_len = 4usize + ext_data_len;
        if marker_len <= fake_cert_len {
            fake_cert.extend_from_slice(&0x0010u16.to_be_bytes());
            fake_cert.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
            fake_cert.extend_from_slice(&(proto_list_len as u16).to_be_bytes());
            fake_cert.push(proto.len() as u8);
            fake_cert.extend_from_slice(proto);
        }
    }
    if fake_cert.len() < fake_cert_len {
        fake_cert.extend_from_slice(&rng.bytes(fake_cert_len - fake_cert.len()));
    } else if fake_cert.len() > fake_cert_len {
        fake_cert.truncate(fake_cert_len);
    }

    let mut app_data_record = Vec::with_capacity(5 + fake_cert_len);
    app_data_record.push(TLS_RECORD_APPLICATION);
    app_data_record.extend_from_slice(&TLS_VERSION);
    app_data_record.extend_from_slice(&(fake_cert_len as u16).to_be_bytes());
    // Fill ApplicationData with fully random bytes of desired length to avoid
    // deterministic DPI fingerprints (fixed inner content type markers).
    app_data_record.extend_from_slice(&fake_cert);

    // Build optional NewSessionTicket records (TLS 1.3 handshake messages are encrypted;
    // here we mimic with opaque ApplicationData records of plausible size).
    let mut tickets = Vec::new();
    let ticket_count = new_session_tickets.min(4);
    if ticket_count > 0 {
        for _ in 0..ticket_count {
            let ticket_len: usize = rng.range(48) + 48; // 48-95 bytes
            let mut record = Vec::with_capacity(5 + ticket_len);
            record.push(TLS_RECORD_APPLICATION);
            record.extend_from_slice(&TLS_VERSION);
            record.extend_from_slice(&(ticket_len as u16).to_be_bytes());
            record.extend_from_slice(&rng.bytes(ticket_len));
            tickets.push(record);
        }
    }

    // Combine all records
    let mut response = Vec::with_capacity(
        server_hello.len()
            + change_cipher_spec.len()
            + app_data_record.len()
            + tickets.iter().map(|r| r.len()).sum::<usize>(),
    );
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&change_cipher_spec);
    response.extend_from_slice(&app_data_record);
    for t in &tickets {
        response.extend_from_slice(t);
    }

    // Compute HMAC for the response
    let mut hmac_input = Vec::with_capacity(TLS_DIGEST_LEN + response.len());
    hmac_input.extend_from_slice(client_digest);
    hmac_input.extend_from_slice(&response);
    let response_digest = sha256_hmac(secret, &hmac_input);

    // Insert computed digest into ServerHello
    // Position: record header (5) + message type (1) + length (3) + version (2) = 11
    response[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&response_digest);

    response
}

/// Extract SNI (server_name) from a TLS ClientHello.
pub fn extract_sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 43 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
    if handshake.len() < 5 + record_len {
        return None;
    }

    let mut pos = 5; // after record header
    if handshake.get(pos).copied()? != 0x01 {
        return None; // not ClientHello
    }

    // Handshake length bytes
    pos += 4; // type + len (3)

    // version (2) + random (32)
    pos += 2 + 32;
    if pos + 1 > handshake.len() {
        return None;
    }

    let session_id_len = *handshake.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > handshake.len() {
        return None;
    }

    let comp_len = *handshake.get(pos)? as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return None;
    }

    let mut saw_sni_extension = false;
    let mut extracted_sni = None;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == 0x0000 {
            if saw_sni_extension {
                return None;
            }
            saw_sni_extension = true;
        }
        if etype == 0x0000 && elen >= 5 {
            // server_name extension
            let list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            let mut sn_pos = pos + 2;
            let sn_end = std::cmp::min(sn_pos + list_len, pos + elen);
            while sn_pos + 3 <= sn_end {
                let name_type = handshake[sn_pos];
                let name_len =
                    u16::from_be_bytes([handshake[sn_pos + 1], handshake[sn_pos + 2]]) as usize;
                sn_pos += 3;
                if sn_pos + name_len > sn_end {
                    break;
                }
                if name_type == 0
                    && name_len > 0
                    && let Ok(host) = std::str::from_utf8(&handshake[sn_pos..sn_pos + name_len])
                    && is_valid_sni_hostname(host)
                {
                    extracted_sni = Some(host.to_string());
                    break;
                }
                sn_pos += name_len;
            }
        }
        pos += elen;
    }

    extracted_sni
}

fn is_valid_sni_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    true
}

/// Extract ALPN protocol list from ClientHello, return in offered order.
pub fn extract_alpn_from_client_hello(handshake: &[u8]) -> Vec<Vec<u8>> {
    if handshake.len() < 5 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return Vec::new();
    }

    let record_len = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
    if handshake.len() < 5 + record_len {
        return Vec::new();
    }

    let mut pos = 5; // after record header
    if handshake.get(pos) != Some(&0x01) {
        return Vec::new();
    }
    pos += 4; // type + len
    pos += 2 + 32; // version + random
    if pos >= handshake.len() {
        return Vec::new();
    }
    let session_id_len = *handshake.get(pos).unwrap_or(&0) as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return Vec::new();
    }
    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= handshake.len() {
        return Vec::new();
    }
    let comp_len = *handshake.get(pos).unwrap_or(&0) as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return Vec::new();
    }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == extension_type::ALPN && elen >= 3 {
            let list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            let mut lp = pos + 2;
            let list_end = (pos + 2).saturating_add(list_len).min(pos + elen);
            while lp < list_end {
                let plen = handshake[lp] as usize;
                lp += 1;
                if lp + plen > list_end {
                    break;
                }
                out.push(handshake[lp..lp + plen].to_vec());
                lp += plen;
            }
            break;
        }
        pos += elen;
    }
    out
}

/// ClientHello TLS generation inferred from handshake fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHelloTlsVersion {
    Tls12,
    Tls13,
}

/// Detect TLS generation from a ClientHello.
///
/// The parser prefers `supported_versions` (0x002b) when present and falls back
/// to `legacy_version` for compatibility with TLS 1.2 style hellos.
pub fn detect_client_hello_tls_version(handshake: &[u8]) -> Option<ClientHelloTlsVersion> {
    if handshake.len() < 5 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
    if handshake.len() < 5 + record_len {
        return None;
    }

    let mut pos = 5; // after record header
    if handshake.get(pos) != Some(&0x01) {
        return None; // not ClientHello
    }
    pos += 1; // message type

    if pos + 3 > handshake.len() {
        return None;
    }
    let handshake_len = ((handshake[pos] as usize) << 16)
        | ((handshake[pos + 1] as usize) << 8)
        | handshake[pos + 2] as usize;
    pos += 3; // handshake length bytes
    if pos + handshake_len > 5 + record_len {
        return None;
    }

    if pos + 2 + 32 > handshake.len() {
        return None;
    }
    let legacy_version = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
    pos += 2 + 32; // version + random

    let session_id_len = *handshake.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= handshake.len() {
        return None;
    }

    let comp_len = *handshake.get(pos)? as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            return None;
        }

        if etype == extension_type::SUPPORTED_VERSIONS {
            if elen < 1 {
                return None;
            }
            let list_len = handshake[pos] as usize;
            if list_len == 0 || list_len % 2 != 0 || 1 + list_len > elen {
                return None;
            }

            let mut has_tls12 = false;
            let mut ver_pos = pos + 1;
            let ver_end = ver_pos + list_len;
            while ver_pos + 1 < ver_end {
                let version = u16::from_be_bytes([handshake[ver_pos], handshake[ver_pos + 1]]);
                if version == 0x0304 {
                    return Some(ClientHelloTlsVersion::Tls13);
                }
                if version == 0x0303 || version == 0x0302 || version == 0x0301 {
                    has_tls12 = true;
                }
                ver_pos += 2;
            }

            if has_tls12 {
                return Some(ClientHelloTlsVersion::Tls12);
            }
            return None;
        }

        pos += elen;
    }

    if legacy_version >= 0x0303 {
        Some(ClientHelloTlsVersion::Tls12)
    } else {
        None
    }
}

/// Check if bytes look like a TLS ClientHello
pub fn is_tls_handshake(first_bytes: &[u8]) -> bool {
    if first_bytes.len() < 3 {
        return false;
    }

    // TLS ClientHello commonly uses legacy record versions 0x0301 or 0x0303.
    first_bytes[0] == TLS_RECORD_HANDSHAKE
        && first_bytes[1] == 0x03
        && (first_bytes[2] == 0x01 || first_bytes[2] == 0x03)
}

/// Parse TLS record header, returns (record_type, length)
pub fn parse_tls_record_header(header: &[u8; 5]) -> Option<(u8, u16)> {
    let record_type = header[0];
    let version = [header[1], header[2]];

    // We accept both TLS 1.0 header (for ClientHello) and TLS 1.2/1.3
    if version != [0x03, 0x01] && version != TLS_VERSION {
        return None;
    }

    let length = u16::from_be_bytes([header[3], header[4]]);
    Some((record_type, length))
}

/// Validate a ServerHello response structure
///
/// This is useful for testing that our ServerHello is well-formed.
#[cfg(test)]
fn validate_server_hello_structure(data: &[u8]) -> Result<(), ProxyError> {
    if data.len() < 5 {
        return Err(ProxyError::InvalidTlsRecord {
            record_type: 0,
            version: [0, 0],
        });
    }

    // Check record header
    if data[0] != TLS_RECORD_HANDSHAKE {
        return Err(ProxyError::InvalidTlsRecord {
            record_type: data[0],
            version: [data[1], data[2]],
        });
    }

    // Check version
    if data[1..3] != TLS_VERSION {
        return Err(ProxyError::InvalidTlsRecord {
            record_type: data[0],
            version: [data[1], data[2]],
        });
    }

    // Check record length
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return Err(ProxyError::InvalidHandshake(format!(
            "ServerHello record truncated: expected {}, got {}",
            5 + record_len,
            data.len()
        )));
    }

    // Check message type
    if data[5] != 0x02 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Expected ServerHello (0x02), got 0x{:02x}",
            data[5]
        )));
    }

    // Parse message length
    let msg_len = u32::from_be_bytes([0, data[6], data[7], data[8]]) as usize;
    if msg_len + 4 != record_len {
        return Err(ProxyError::InvalidHandshake(format!(
            "Message length mismatch: {} + 4 != {}",
            msg_len, record_len
        )));
    }

    Ok(())
}

// ============= Compile-time Security Invariants =============

/// Compile-time checks that enforce invariants the rest of the code relies on.
/// Using `static_assertions` ensures these can never silently break across
/// refactors without a compile error.
mod compile_time_security_checks {
    use super::{TLS_DIGEST_HALF_LEN, TLS_DIGEST_LEN};
    use static_assertions::const_assert;

    // The digest must be exactly one SHA-256 output.
    const_assert!(TLS_DIGEST_LEN == 32);

    // Replay-dedup stores the first half; verify it is literally half.
    const_assert!(TLS_DIGEST_HALF_LEN * 2 == TLS_DIGEST_LEN);

    // The HMAC check window (28 bytes) plus the embedded timestamp (4 bytes)
    // must exactly fill the digest.  If TLS_DIGEST_LEN ever changes, these
    // assertions will catch the mismatch before any timing-oracle fix is broke.
    const_assert!(28 + 4 == TLS_DIGEST_LEN);
}

// ============= Security-focused regression tests =============

#[cfg(test)]
#[path = "tests/tls_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/tls_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/tls_fuzz_security_tests.rs"]
mod fuzz_security_tests;

#[cfg(test)]
#[path = "tests/tls_length_cast_hardening_security_tests.rs"]
mod length_cast_hardening_security_tests;
