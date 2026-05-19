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

// ============= Pure-parser unit tests =============

#[cfg(test)]
mod pure_parser_tests {
    use super::*;

    // ---- ClientHello builder helper ----
    //
    // Hand-written ClientHello layout (TLS 1.3-style record). Lets the
    // tests below craft hellos with specific SNI / ALPN / supported_versions
    // extensions without dragging in rustls or other dependencies.
    //
    // RFC 8446 §4.1.2 reference layout:
    //   handshake type | uint24 len | legacy_version | random | sid | cipher | comp | extensions
    pub(super) fn build_client_hello(
        sni: Option<&str>,
        alpn: &[&[u8]],
        supported_versions: &[u16],
        legacy_version: u16,
    ) -> Vec<u8> {
        let mut exts: Vec<u8> = Vec::new();

        // ---- server_name extension (0x0000) ----
        if let Some(host) = sni {
            let mut ext_body = Vec::new();
            let entry_len = 1 + 2 + host.len();
            ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list len
            ext_body.push(0); // name_type = host_name
            ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
            ext_body.extend_from_slice(host.as_bytes());
            exts.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type
            exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&ext_body);
        }

        // ---- ALPN extension (0x0010) ----
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for proto in alpn {
                list.push(proto.len() as u8);
                list.extend_from_slice(proto);
            }
            let mut ext_body = Vec::new();
            ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext_body.extend_from_slice(&list);
            exts.extend_from_slice(&0x0010u16.to_be_bytes());
            exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&ext_body);
        }

        // ---- supported_versions extension (0x002b) ----
        if !supported_versions.is_empty() {
            let mut list = Vec::new();
            list.push((supported_versions.len() * 2) as u8);
            for &v in supported_versions {
                list.extend_from_slice(&v.to_be_bytes());
            }
            exts.extend_from_slice(&0x002bu16.to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&legacy_version.to_be_bytes()); // legacy_version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id_len = 0
        hs_body.extend_from_slice(&2u16.to_be_bytes()); // 2 bytes of ciphers
        hs_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hs_body.push(1); // compression methods len
        hs_body.push(0); // null compression
        hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = hs_body.len() as u32;
        handshake.extend_from_slice(&[
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]); // uint24
        handshake.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    // ============= is_tls_handshake =============

    #[test]
    fn is_tls_handshake_accepts_legacy_and_tls12_record_versions() {
        // 0x16, 0x03, 0x01 (legacy TLS 1.0 record version, used by ClientHello).
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01, 0x00, 0x00]));
        // 0x16, 0x03, 0x03 (TLS 1.2 record version, what TLS 1.3 sends).
        assert!(is_tls_handshake(&[0x16, 0x03, 0x03, 0x00, 0x00]));
    }

    #[test]
    fn is_tls_handshake_rejects_non_handshake_record_types() {
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x03])); // ApplicationData
        assert!(!is_tls_handshake(&[0x14, 0x03, 0x03])); // ChangeCipherSpec
        assert!(!is_tls_handshake(&[0x15, 0x03, 0x03])); // Alert
    }

    #[test]
    fn is_tls_handshake_rejects_wrong_record_versions() {
        // 0x16 + 0x03 + 0x02 is not in {0x01, 0x03}.
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x02]));
        // 0x16 + 0x04 + ... rejects because second byte must be 0x03.
        assert!(!is_tls_handshake(&[0x16, 0x04, 0x03]));
    }

    #[test]
    fn is_tls_handshake_rejects_short_input() {
        assert!(!is_tls_handshake(&[]));
        assert!(!is_tls_handshake(&[0x16]));
        assert!(!is_tls_handshake(&[0x16, 0x03]));
    }

    // ============= parse_tls_record_header =============

    #[test]
    fn parse_tls_record_header_accepts_tls10_and_tls12_versions() {
        // TLS 1.0 record header (used by initial ClientHello).
        let h = [0x16u8, 0x03, 0x01, 0x01, 0x00];
        let (ty, len) = parse_tls_record_header(&h).unwrap();
        assert_eq!(ty, TLS_RECORD_HANDSHAKE);
        assert_eq!(len, 256);
        // TLS 1.2 / 1.3 record header.
        let h = [0x17u8, 0x03, 0x03, 0x00, 0x0a];
        let (ty, len) = parse_tls_record_header(&h).unwrap();
        assert_eq!(ty, TLS_RECORD_APPLICATION);
        assert_eq!(len, 10);
    }

    #[test]
    fn parse_tls_record_header_rejects_unknown_versions() {
        // 0x03, 0x02 — TLS 1.1 — not accepted.
        assert!(parse_tls_record_header(&[0x16, 0x03, 0x02, 0, 0]).is_none());
        // 0x02, 0x00 — SSL 2.0 — not accepted.
        assert!(parse_tls_record_header(&[0x16, 0x02, 0x00, 0, 0]).is_none());
    }

    // ============= is_valid_sni_hostname =============

    #[test]
    fn is_valid_sni_hostname_accepts_typical_hosts() {
        assert!(is_valid_sni_hostname("example.com"));
        assert!(is_valid_sni_hostname("a"));
        assert!(is_valid_sni_hostname("api.v3.example.co.uk"));
        assert!(is_valid_sni_hostname("xn--de-eka1c"));
        // 63-byte label (max allowed).
        let label = "a".repeat(63);
        assert!(is_valid_sni_hostname(&format!("{label}.com")));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_obvious_invalid() {
        assert!(!is_valid_sni_hostname(""));
        // 64-byte label (over max).
        let too_long_label = "a".repeat(64);
        assert!(!is_valid_sni_hostname(&too_long_label));
        // Whole hostname >253 bytes.
        let huge = "a.".repeat(200);
        assert!(!is_valid_sni_hostname(&huge));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_ip_literals() {
        assert!(!is_valid_sni_hostname("127.0.0.1"));
        assert!(!is_valid_sni_hostname("8.8.8.8"));
        assert!(!is_valid_sni_hostname("::1"));
        assert!(!is_valid_sni_hostname("2001:db8::1"));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_leading_trailing_dots_or_dashes() {
        assert!(!is_valid_sni_hostname(".example.com"));
        assert!(!is_valid_sni_hostname("example.com."));
        assert!(!is_valid_sni_hostname("-bad.example.com"));
        assert!(!is_valid_sni_hostname("bad-.example.com"));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_non_alnum_bytes() {
        assert!(!is_valid_sni_hostname("ex_ample.com"));
        assert!(!is_valid_sni_hostname("ex ample.com"));
        // Non-ASCII (uppercase Cyrillic) bytes must be rejected — SNI is ASCII/punycode.
        assert!(!is_valid_sni_hostname("привет.com"));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_empty_label() {
        assert!(!is_valid_sni_hostname("foo..bar"));
    }

    // ============= extract_sni_from_client_hello =============

    #[test]
    fn extract_sni_returns_hostname_when_present() {
        let ch = build_client_hello(Some("api.example.com"), &[], &[0x0304], 0x0303);
        let sni = extract_sni_from_client_hello(&ch);
        assert_eq!(sni.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn extract_sni_returns_none_when_extension_absent() {
        let ch = build_client_hello(None, &[], &[0x0304], 0x0303);
        assert!(extract_sni_from_client_hello(&ch).is_none());
    }

    #[test]
    fn extract_sni_rejects_invalid_hostname_inside_extension() {
        // Real-world malformed SNI: trailing dot must fail validation.
        let ch = build_client_hello(Some("api.example.com."), &[], &[0x0304], 0x0303);
        assert!(extract_sni_from_client_hello(&ch).is_none());
    }

    #[test]
    fn extract_sni_rejects_non_tls_handshake_byte() {
        let mut ch = build_client_hello(Some("a.example"), &[], &[0x0304], 0x0303);
        ch[0] = 0x17; // ApplicationData record
        assert!(extract_sni_from_client_hello(&ch).is_none());
    }

    #[test]
    fn extract_sni_handles_truncated_input_gracefully() {
        let ch = build_client_hello(Some("a.example"), &[], &[0x0304], 0x0303);
        for cut in 0..ch.len().min(50) {
            // Must not panic; result is best-effort.
            let _ = extract_sni_from_client_hello(&ch[..cut]);
        }
    }

    // ============= extract_alpn_from_client_hello =============

    #[test]
    fn extract_alpn_returns_protocols_in_offered_order() {
        let alpn: &[&[u8]] = &[b"h2", b"http/1.1"];
        let ch = build_client_hello(None, alpn, &[0x0304], 0x0303);
        let got = extract_alpn_from_client_hello(&ch);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], b"h2");
        assert_eq!(got[1], b"http/1.1");
    }

    #[test]
    fn extract_alpn_returns_empty_when_extension_absent() {
        let ch = build_client_hello(Some("a.example"), &[], &[0x0304], 0x0303);
        let got = extract_alpn_from_client_hello(&ch);
        assert!(got.is_empty());
    }

    #[test]
    fn extract_alpn_returns_empty_for_non_handshake_record() {
        let mut ch = build_client_hello(None, &[b"h2"], &[0x0304], 0x0303);
        ch[0] = 0x17; // Not a Handshake record.
        assert!(extract_alpn_from_client_hello(&ch).is_empty());
    }

    // ============= detect_client_hello_tls_version =============

    #[test]
    fn detect_tls_version_returns_tls13_when_supported_versions_contains_0304() {
        let ch = build_client_hello(None, &[], &[0x0303, 0x0304], 0x0303);
        assert_eq!(
            detect_client_hello_tls_version(&ch),
            Some(ClientHelloTlsVersion::Tls13)
        );
    }

    #[test]
    fn detect_tls_version_returns_tls12_when_only_legacy_versions_in_supported_versions() {
        let ch = build_client_hello(None, &[], &[0x0303, 0x0302, 0x0301], 0x0303);
        assert_eq!(
            detect_client_hello_tls_version(&ch),
            Some(ClientHelloTlsVersion::Tls12)
        );
    }

    #[test]
    fn detect_tls_version_falls_back_to_legacy_version_when_extension_absent() {
        // No supported_versions extension → use legacy_version.
        let ch = build_client_hello(None, &[], &[], 0x0303);
        assert_eq!(
            detect_client_hello_tls_version(&ch),
            Some(ClientHelloTlsVersion::Tls12)
        );
    }

    #[test]
    fn detect_tls_version_returns_none_for_pre_tls12_legacy_with_no_extension() {
        // legacy_version 0x0301 (TLS 1.0) without supported_versions ext.
        let ch = build_client_hello(None, &[], &[], 0x0301);
        assert!(detect_client_hello_tls_version(&ch).is_none());
    }

    #[test]
    fn detect_tls_version_rejects_non_handshake_record() {
        let mut ch = build_client_hello(None, &[], &[0x0304], 0x0303);
        ch[0] = 0x17;
        assert!(detect_client_hello_tls_version(&ch).is_none());
    }

    // ============= Combined invariants =============

    #[test]
    fn full_client_hello_roundtrip_parses_all_three_extensions_independently() {
        // The opt.md §6.1 finding is that SNI/ALPN/version are parsed in
        // three separate linear scans. They must agree on the same hello.
        let ch = build_client_hello(
            Some("svc.example.org"),
            &[b"h2", b"http/1.1"],
            &[0x0304],
            0x0303,
        );

        assert_eq!(
            extract_sni_from_client_hello(&ch).as_deref(),
            Some("svc.example.org")
        );
        let alpn = extract_alpn_from_client_hello(&ch);
        assert_eq!(alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(
            detect_client_hello_tls_version(&ch),
            Some(ClientHelloTlsVersion::Tls13)
        );
    }

    // ============= system_time_to_unix_secs =============

    #[test]
    fn system_time_to_unix_secs_returns_some_for_epoch() {
        let r = system_time_to_unix_secs(UNIX_EPOCH);
        assert_eq!(r, Some(0));
    }

    #[test]
    fn system_time_to_unix_secs_returns_some_for_known_future() {
        // 2030-01-01 00:00:00 UTC = 1_893_456_000 seconds since epoch.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000);
        assert_eq!(system_time_to_unix_secs(t), Some(1_893_456_000));
    }

    #[test]
    fn system_time_to_unix_secs_returns_none_for_pre_epoch() {
        // Times before UNIX_EPOCH cause duration_since to fail.
        let pre = UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("UNIX_EPOCH - 1s must be representable");
        assert!(system_time_to_unix_secs(pre).is_none());
    }

    // ============= validate_tls_handshake_at_time =============

    /// Builds a 64-byte ClientHello that the validator can succeed on:
    /// at offset TLS_DIGEST_POS lives a 32-byte digest = HMAC(secret, msg)
    /// where bytes 28..32 carry `timestamp` XOR'd against the HMAC output.
    /// Layout: 11 header bytes, 32 digest bytes, 1 session_id_len = 0, rest is padding.
    fn build_validatable_handshake(secret: &[u8], timestamp: u32) -> Vec<u8> {
        // 64 bytes total covers minimum size required by the validator.
        let mut hs = vec![0u8; 64];
        // Set a session_id_len of 0 right after the digest position.
        hs[TLS_DIGEST_POS + TLS_DIGEST_LEN] = 0;

        // Step 1: compute HMAC over the message that has the digest slot zeroed.
        let computed = sha256_hmac(secret, &hs);

        // Step 2: write digest into the handshake:
        // - first 28 bytes = HMAC[0..28] (so ct_eq match succeeds).
        // - last 4 bytes = HMAC[28..32] XOR timestamp_le.
        let ts_le = timestamp.to_le_bytes();
        hs[TLS_DIGEST_POS..TLS_DIGEST_POS + 28].copy_from_slice(&computed[..28]);
        for i in 0..4 {
            hs[TLS_DIGEST_POS + 28 + i] = computed[28 + i] ^ ts_le[i];
        }
        hs
    }

    #[test]
    fn validate_at_time_accepts_handshake_with_in_window_timestamp() {
        let secret = b"super-secret-bytes-xyz";
        let now = 1_700_000_000_i64;
        let hs = build_validatable_handshake(secret, now as u32);

        let secrets = vec![("alice".to_string(), secret.to_vec())];
        let res = validate_tls_handshake_at_time(&hs, &secrets, false, now)
            .expect("validation must accept in-window handshake");
        assert_eq!(res.user, "alice");
        assert_eq!(res.timestamp, now as u32);
        assert_eq!(res.digest.len(), TLS_DIGEST_LEN);
        assert_eq!(res.session_id.len(), 0);
    }

    #[test]
    fn validate_at_time_rejects_out_of_window_timestamp() {
        let secret = b"abc";
        let now = 1_700_000_000_i64;
        // Timestamp 1 hour in the future — well outside TIME_SKEW_MAX (120 s).
        let hs = build_validatable_handshake(secret, (now + 3600) as u32);

        let secrets = vec![("alice".to_string(), secret.to_vec())];
        assert!(validate_tls_handshake_at_time(&hs, &secrets, false, now).is_none());
    }

    #[test]
    fn validate_at_time_ignore_skew_accepts_any_timestamp() {
        let secret = b"abc";
        // Wildly off — but ignore_time_skew skips the check.
        let hs = build_validatable_handshake(secret, 1);
        let now = 1_700_000_000_i64;

        let secrets = vec![("alice".to_string(), secret.to_vec())];
        let res = validate_tls_handshake_at_time(&hs, &secrets, true, now)
            .expect("ignore_time_skew must accept any timestamp");
        assert_eq!(res.timestamp, 1);
    }

    #[test]
    fn validate_at_time_accepts_boot_time_under_cap() {
        let secret = b"abc";
        // Timestamp < BOOT_TIME_MAX_SECS is treated as boot uptime, not unix epoch.
        let boot_ts = BOOT_TIME_MAX_SECS - 100;
        let hs = build_validatable_handshake(secret, boot_ts);
        // `now` doesn't matter for boot-time path — but the validator needs a value.
        let now = 1_700_000_000_i64;
        let secrets = vec![("alice".to_string(), secret.to_vec())];
        let res = validate_tls_handshake_at_time(&hs, &secrets, false, now)
            .expect("boot-time timestamp under cap must be accepted");
        assert_eq!(res.timestamp, boot_ts);
    }

    #[test]
    fn validate_at_time_rejects_when_no_secret_matches() {
        let secret = b"correct";
        let now = 1_700_000_000_i64;
        let hs = build_validatable_handshake(secret, now as u32);
        // Different secret in the table.
        let secrets = vec![("eve".to_string(), b"wrong".to_vec())];
        assert!(validate_tls_handshake_at_time(&hs, &secrets, false, now).is_none());
    }

    #[test]
    fn validate_at_time_rejects_truncated_input() {
        let short = vec![0u8; TLS_DIGEST_POS + 10]; // way below required length
        let secrets = vec![("alice".to_string(), b"x".to_vec())];
        assert!(validate_tls_handshake_at_time(&short, &secrets, false, 0).is_none());
    }

    #[test]
    fn validate_at_time_rejects_oversized_session_id() {
        // session_id_len byte = 33 (above the 32 cap).
        let mut hs = vec![0u8; 64];
        hs[TLS_DIGEST_POS + TLS_DIGEST_LEN] = 33;
        let secrets = vec![("alice".to_string(), b"x".to_vec())];
        assert!(validate_tls_handshake_at_time(&hs, &secrets, false, 0).is_none());
    }

    #[test]
    fn validate_with_boot_cap_zero_disables_boot_time_path() {
        let secret = b"abc";
        // boot_ts is small — would be accepted with cap > ts, but with cap = 0
        // the validator must fall through to the regular time-skew check and
        // reject (since boot_ts is way out of the ±120 s window).
        let boot_ts = 1234u32;
        let hs = build_validatable_handshake(secret, boot_ts);
        let now = 1_700_000_000_i64;
        let secrets = vec![("alice".to_string(), secret.to_vec())];
        assert!(
            validate_tls_handshake_at_time_with_boot_cap(&hs, &secrets, false, now, 0).is_none()
        );
    }

    #[test]
    fn validate_picks_first_matching_secret_among_many() {
        let secret_a = b"alpha-key";
        let secret_b = b"beta-key";
        let now = 1_700_000_000_i64;
        let hs = build_validatable_handshake(secret_b, now as u32);

        // `alpha` doesn't match the digest; `beta` does.
        let secrets = vec![
            ("alpha".to_string(), secret_a.to_vec()),
            ("beta".to_string(), secret_b.to_vec()),
        ];
        let res = validate_tls_handshake_at_time(&hs, &secrets, false, now).unwrap();
        assert_eq!(res.user, "beta");
    }

    // ============= gen_fake_x25519_key =============

    #[test]
    fn gen_fake_x25519_key_not_all_zero() {
        // The basepoint × random scalar is overwhelmingly likely to be
        // non-zero. If it IS all-zero, that's catastrophic for our
        // anti-fingerprinting goal.
        let rng = SecureRandom::new();
        let k = gen_fake_x25519_key(&rng);
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn gen_fake_x25519_key_differs_across_calls() {
        let rng = SecureRandom::new();
        let a = gen_fake_x25519_key(&rng);
        let b = gen_fake_x25519_key(&rng);
        assert_ne!(a, b);
    }

    // ============= build_server_hello =============

    fn fixed_secret() -> Vec<u8> {
        b"super-secret-bytes-xyz".to_vec()
    }

    fn fixed_client_digest() -> [u8; TLS_DIGEST_LEN] {
        let mut d = [0u8; TLS_DIGEST_LEN];
        for (i, slot) in d.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(7);
        }
        d
    }

    #[test]
    fn build_server_hello_starts_with_well_formed_serverhello_record() {
        let rng = SecureRandom::new();
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[],
            128,
            &rng,
            None,
            0,
        );
        // The first record must pass our own ServerHello validator.
        // (Validator is `#[cfg(test)]`-only; this is the contract test.)
        validate_server_hello_structure(&resp).expect("ServerHello header must be well-formed");
        // Record header layout: HANDSHAKE | TLS_VERSION | u16 length.
        assert_eq!(resp[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(&resp[1..3], &TLS_VERSION);
    }

    #[test]
    fn build_server_hello_contains_change_cipher_spec_record() {
        let rng = SecureRandom::new();
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[1, 2, 3],
            128,
            &rng,
            None,
            0,
        );
        // CCS record is a fixed 6-byte sequence; find it inside the response.
        let ccs = [TLS_RECORD_CHANGE_CIPHER, TLS_VERSION[0], TLS_VERSION[1], 0x00, 0x01, 0x01];
        assert!(
            resp.windows(6).any(|w| w == ccs),
            "expected ChangeCipherSpec record sequence inside response"
        );
    }

    #[test]
    fn build_server_hello_contains_application_data_record_of_requested_size() {
        let rng = SecureRandom::new();
        let fake_cert_len = 256;
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[],
            fake_cert_len,
            &rng,
            None,
            0,
        );
        // Scan for an ApplicationData record with the requested length.
        // Layout: 0x17 | 0x03 0x03 | u16 length.
        let mut found = false;
        let mut i = 0;
        while i + 5 <= resp.len() {
            if resp[i] == TLS_RECORD_APPLICATION
                && resp[i + 1..i + 3] == TLS_VERSION
                && u16::from_be_bytes([resp[i + 3], resp[i + 4]]) as usize == fake_cert_len
            {
                found = true;
                break;
            }
            i += 1;
        }
        assert!(found, "no ApplicationData record of length {fake_cert_len} found");
    }

    #[test]
    fn build_server_hello_clamps_fake_cert_len_to_minimum() {
        let rng = SecureRandom::new();
        // Requested below MIN_APP_DATA (64); the produced AppData record
        // must still be >= 64 bytes long.
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[],
            8, // below the 64-byte floor
            &rng,
            None,
            0,
        );
        let mut max_app_data_len: u16 = 0;
        let mut i = 0;
        while i + 5 <= resp.len() {
            if resp[i] == TLS_RECORD_APPLICATION && resp[i + 1..i + 3] == TLS_VERSION {
                let n = u16::from_be_bytes([resp[i + 3], resp[i + 4]]);
                if n > max_app_data_len {
                    max_app_data_len = n;
                }
            }
            i += 1;
        }
        assert!(
            max_app_data_len >= 64,
            "AppData record must be clamped to >= 64 bytes, got {max_app_data_len}"
        );
    }

    #[test]
    fn build_server_hello_clamps_fake_cert_len_to_maximum() {
        let rng = SecureRandom::new();
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[],
            usize::MAX,
            &rng,
            None,
            0,
        );
        // Every AppData record length must fit in u16 and not exceed
        // MAX_TLS_CIPHERTEXT_SIZE.
        let mut i = 0;
        while i + 5 <= resp.len() {
            if resp[i] == TLS_RECORD_APPLICATION && resp[i + 1..i + 3] == TLS_VERSION {
                let n = u16::from_be_bytes([resp[i + 3], resp[i + 4]]) as usize;
                assert!(n <= MAX_TLS_CIPHERTEXT_SIZE);
            }
            i += 1;
        }
    }

    #[test]
    fn build_server_hello_clamps_session_ticket_count_to_four() {
        let rng = SecureRandom::new();
        // Ask for 10 tickets — the implementation caps at 4.
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[],
            64,
            &rng,
            None,
            10,
        );
        // Count ApplicationData records. The first AppData record is the
        // fake-cert. Anything beyond it is a NewSessionTicket-like record.
        let mut app_data_records = 0;
        let mut i = 0;
        while i + 5 <= resp.len() {
            if resp[i] == TLS_RECORD_APPLICATION && resp[i + 1..i + 3] == TLS_VERSION {
                let n = u16::from_be_bytes([resp[i + 3], resp[i + 4]]) as usize;
                if i + 5 + n <= resp.len() {
                    app_data_records += 1;
                    i += 5 + n;
                    continue;
                }
            }
            i += 1;
        }
        // 1 (fake_cert) + up to 4 (tickets) = 5 max.
        assert!(
            app_data_records <= 5,
            "expected at most 5 ApplicationData records (1 cert + 4 tickets), got {app_data_records}"
        );
    }

    #[test]
    fn build_server_hello_emits_zero_tickets_when_count_is_zero() {
        let rng = SecureRandom::new();
        let resp = build_server_hello(
            &fixed_secret(),
            &fixed_client_digest(),
            &[],
            64,
            &rng,
            None,
            0,
        );
        let mut app_data_records = 0;
        let mut i = 0;
        while i + 5 <= resp.len() {
            if resp[i] == TLS_RECORD_APPLICATION && resp[i + 1..i + 3] == TLS_VERSION {
                let n = u16::from_be_bytes([resp[i + 3], resp[i + 4]]) as usize;
                if i + 5 + n <= resp.len() {
                    app_data_records += 1;
                    i += 5 + n;
                    continue;
                }
            }
            i += 1;
        }
        // Exactly one AppData record (the fake_cert) when no tickets are requested.
        assert_eq!(app_data_records, 1);
    }

    #[test]
    fn build_server_hello_embeds_hmac_digest_at_fixed_offset() {
        let rng = SecureRandom::new();
        let secret = fixed_secret();
        let client_digest = fixed_client_digest();
        let resp = build_server_hello(&secret, &client_digest, &[], 128, &rng, None, 0);

        // Compute the expected HMAC the same way the function does and
        // verify it landed in the right slot. The function fills the
        // digest slot *after* concatenating the whole response, so we
        // re-derive the expected digest from a copy with that slot zeroed.
        let mut input_view = Vec::with_capacity(TLS_DIGEST_LEN + resp.len());
        input_view.extend_from_slice(&client_digest);
        input_view.extend_from_slice(&resp);
        // Zero out the digest slot in the appended copy.
        let zero_start = TLS_DIGEST_LEN + TLS_DIGEST_POS;
        for b in &mut input_view[zero_start..zero_start + TLS_DIGEST_LEN] {
            *b = 0;
        }
        let expected = sha256_hmac(&secret, &input_view);
        assert_eq!(&resp[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN], &expected[..]);
    }

    // ============= validate_server_hello_structure =============

    #[test]
    fn validate_server_hello_structure_rejects_truncated() {
        for n in 0..5 {
            let buf = vec![0u8; n];
            assert!(validate_server_hello_structure(&buf).is_err());
        }
    }

    #[test]
    fn validate_server_hello_structure_rejects_wrong_record_type() {
        let mut buf = [0u8; 16];
        buf[0] = 0x17; // ApplicationData, not Handshake
        buf[1..3].copy_from_slice(&TLS_VERSION);
        buf[3..5].copy_from_slice(&11u16.to_be_bytes());
        let err = validate_server_hello_structure(&buf).unwrap_err();
        assert!(
            matches!(err, ProxyError::InvalidTlsRecord { .. }),
            "expected InvalidTlsRecord, got {:?}",
            err
        );
    }

    #[test]
    fn validate_server_hello_structure_rejects_wrong_version() {
        let mut buf = [0u8; 16];
        buf[0] = TLS_RECORD_HANDSHAKE;
        buf[1] = 0x03;
        buf[2] = 0x02; // not TLS 1.2/1.3 record version
        buf[3..5].copy_from_slice(&11u16.to_be_bytes());
        assert!(validate_server_hello_structure(&buf).is_err());
    }

    #[test]
    fn validate_server_hello_structure_rejects_record_truncation() {
        let mut buf = [0u8; 10];
        buf[0] = TLS_RECORD_HANDSHAKE;
        buf[1..3].copy_from_slice(&TLS_VERSION);
        // Claim 100 record bytes but provide only 5 after the header.
        buf[3..5].copy_from_slice(&100u16.to_be_bytes());
        assert!(validate_server_hello_structure(&buf).is_err());
    }

    #[test]
    fn validate_server_hello_structure_rejects_non_serverhello_message_type() {
        // ClientHello byte 0x01 instead of ServerHello 0x02.
        let mut buf = vec![0u8; 16];
        buf[0] = TLS_RECORD_HANDSHAKE;
        buf[1..3].copy_from_slice(&TLS_VERSION);
        buf[3..5].copy_from_slice(&11u16.to_be_bytes());
        buf[5] = 0x01; // ClientHello
        buf[6] = 0;
        buf[7] = 0;
        buf[8] = 7;
        let err = validate_server_hello_structure(&buf).unwrap_err();
        match err {
            ProxyError::InvalidHandshake(msg) => assert!(msg.contains("ServerHello")),
            _ => panic!("expected InvalidHandshake"),
        }
    }

    #[test]
    fn validate_server_hello_structure_rejects_message_length_mismatch() {
        let mut buf = vec![0u8; 16];
        buf[0] = TLS_RECORD_HANDSHAKE;
        buf[1..3].copy_from_slice(&TLS_VERSION);
        buf[3..5].copy_from_slice(&11u16.to_be_bytes());
        buf[5] = 0x02; // ServerHello
        // Claim message length 99 (≠ record_len - 4 = 7).
        buf[6] = 0;
        buf[7] = 0;
        buf[8] = 99;
        let err = validate_server_hello_structure(&buf).unwrap_err();
        match err {
            ProxyError::InvalidHandshake(msg) => {
                assert!(msg.contains("Message length mismatch"));
            }
            _ => panic!("expected InvalidHandshake"),
        }
    }
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

#[cfg(test)]
mod builder_tests {
    use super::*;
    use crate::protocol::constants::TLS_RECORD_HANDSHAKE;

    #[test]
    fn tls_extension_builder_build_has_length_prefix() {
        let mut builder = TlsExtensionBuilder::new();
        let key = [0x42u8; 32];
        builder.add_key_share(&key);
        let built = builder.build();
        let len = u16::from_be_bytes([built[0], built[1]]) as usize;
        assert_eq!(len + 2, built.len());
    }

    #[test]
    fn tls_extension_builder_supported_versions() {
        // Extension layout: type (2) + ext-data-len (2) + version (2) = 6 bytes.
        // The header makes 4 fixed bytes; only one version is currently supported.
        let mut builder = TlsExtensionBuilder::new();
        builder.add_supported_versions(0x0304);
        let bytes = builder.as_bytes();
        assert_eq!(bytes.len(), 6);
        // Type bytes are the supported_versions marker (0x002b).
        assert_eq!(&bytes[0..2], &[0x00, 0x2b]);
        // Ext data length declares 2 bytes of payload (the version).
        assert_eq!(&bytes[2..4], &(2u16).to_be_bytes());
        // Payload is the requested TLS 1.3 version.
        assert_eq!(&bytes[4..6], &(0x0304u16).to_be_bytes());
    }

    #[test]
    fn server_hello_builder_record_has_tls_header() {
        let builder = ServerHelloBuilder::new(vec![]);
        let record = builder.build_record();
        assert!(record.len() >= 5);
        assert_eq!(record[0], TLS_RECORD_HANDSHAKE);
    }

    #[test]
    fn server_hello_builder_session_id_echoed() {
        let session_id = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let builder = ServerHelloBuilder::new(session_id.clone());
        let msg = builder.build_message();
        let sid_len = msg[4 + 2 + 32] as usize;
        assert_eq!(sid_len, 4);
        assert_eq!(&msg[4 + 2 + 32 + 1..4 + 2 + 32 + 1 + 4], &session_id);
    }

    #[test]
    fn validate_server_hello_structure_accepts_valid() {
        let builder = ServerHelloBuilder::new(vec![]);
        let record = builder.build_record();
        assert!(validate_server_hello_structure(&record).is_ok());
    }

    // `validate_server_hello_structure_rejects_too_short` removed in
    // favor of `pure_parser_tests::validate_server_hello_structure_rejects_truncated`,
    // which iterates `n in 0..5` and subsumes both inputs.

    #[test]
    fn validate_server_hello_structure_rejects_truncated() {
        // Distinct from the pure_parser_tests variant: that one truncates
        // *before* a valid record header is even written. This one starts
        // with a fully-built ServerHello and chops the last byte, so it
        // exercises the body-truncation branch (header parses, body short).
        let builder = ServerHelloBuilder::new(vec![]);
        let mut record = builder.build_record();
        record.truncate(record.len() - 1);
        assert!(validate_server_hello_structure(&record).is_err());
    }

    #[test]
    fn validate_server_hello_structure_rejects_wrong_msg_type() {
        let mut record = vec![
            TLS_RECORD_HANDSHAKE,
            0x03, 0x03,
        ];
        let msg = vec![0x01u8, 0x00, 0x00, 0x02, 0x03, 0x03];
        let msg_len = msg.len() as u16;
        record.extend_from_slice(&msg_len.to_be_bytes());
        record.extend_from_slice(&msg);
        assert!(validate_server_hello_structure(&record).is_err());
    }

    #[test]
    fn build_server_hello_produces_valid_structure() {
        let rng = crate::crypto::SecureRandom::new();
        let secret = b"0123456789abcdef";
        let digest = [0x42u8; 32];
        let session_id = vec![0xAA; 32];

        let response = super::build_server_hello(
            secret,
            &digest,
            &session_id,
            0,
            &rng,
            None,
            0,
        );

        assert!(validate_server_hello_structure(&response).is_ok());
    }

    #[test]
    fn build_server_hello_contains_ccs_and_app_data() {
        let rng = crate::crypto::SecureRandom::new();
        let response = super::build_server_hello(
            b"0123456789abcdef",
            &[0x42u8; 32],
            &vec![0; 32],
            0,
            &rng,
            None,
            0,
        );
        assert!(response.len() > 5);
        assert!(response.windows(2).any(|w| w == &[0x14, 0x03]));
    }
}

// ============= Tail coverage: edge-case pure parsers & predicates =============

#[cfg(test)]
mod tail_coverage_tests {
    use super::*;
    // Re-use the ClientHello builder from pure_parser_tests (identical layout).
    use super::pure_parser_tests::build_client_hello;

    // Helper: build ClientHello with a non-zero session_id.
    fn build_client_hello_with_session_id(
        sni: Option<&str>,
        session_id: &[u8],
        supported_versions: &[u16],
        legacy_version: u16,
    ) -> Vec<u8> {
        let mut exts: Vec<u8> = Vec::new();

        if let Some(host) = sni {
            let mut ext_body = Vec::new();
            let entry_len = 1 + 2 + host.len();
            ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes());
            ext_body.push(0);
            ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
            ext_body.extend_from_slice(host.as_bytes());
            exts.extend_from_slice(&0x0000u16.to_be_bytes());
            exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&ext_body);
        }

        if !supported_versions.is_empty() {
            let mut list = Vec::new();
            list.push((supported_versions.len() * 2) as u8);
            for &v in supported_versions {
                list.extend_from_slice(&v.to_be_bytes());
            }
            exts.extend_from_slice(&0x002bu16.to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&legacy_version.to_be_bytes());
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(session_id.len() as u8);
        hs_body.extend_from_slice(session_id);
        hs_body.extend_from_slice(&2u16.to_be_bytes());
        hs_body.extend_from_slice(&[0x13, 0x01]);
        hs_body.push(1);
        hs_body.push(0);
        hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = hs_body.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    // ---- is_valid_sni_hostname boundary tests ----

    #[test]
    fn is_valid_sni_hostname_accepts_exactly_253_chars() {
        let label63 = "a".repeat(63);
        let label61 = "a".repeat(61);
        let host = format!("{label63}.{label63}.{label63}.{label61}");
        assert_eq!(host.len(), 253);
        assert!(is_valid_sni_hostname(&host));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_254_chars() {
        let label63 = "a".repeat(63);
        let label62 = "a".repeat(62);
        let host = format!("{label63}.{label63}.{label63}.{label62}");
        assert_eq!(host.len(), 254);
        assert!(!is_valid_sni_hostname(&host));
    }

    #[test]
    fn is_valid_sni_hostname_accepts_numeric_only_label() {
        assert!(is_valid_sni_hostname("12345.example.com"));
    }

    #[test]
    fn is_valid_sni_hostname_accepts_single_char_label() {
        assert!(is_valid_sni_hostname("a"));
    }

    #[test]
    fn is_valid_sni_hostname_rejects_label_with_underscore() {
        assert!(!is_valid_sni_hostname("ex_ample.com"));
    }

    #[test]
    fn is_valid_sni_hostname_accepts_consecutive_dashes_in_middle() {
        assert!(is_valid_sni_hostname("a--b.example.com"));
    }

    // ---- extract_sni edge cases ----

    #[test]
    fn extract_sni_with_nonzero_session_id() {
        let sid: Vec<u8> = (0u8..16).collect();
        let ch = build_client_hello_with_session_id(
            Some("telemt.example.com"),
            &sid,
            &[0x0304],
            0x0303,
        );
        assert_eq!(
            extract_sni_from_client_hello(&ch).as_deref(),
            Some("telemt.example.com")
        );
    }

    #[test]
    fn extract_sni_with_max_32_byte_session_id() {
        let sid: Vec<u8> = (0u8..32).collect();
        let ch = build_client_hello_with_session_id(
            Some("a.example"),
            &sid,
            &[0x0304],
            0x0303,
        );
        assert_eq!(
            extract_sni_from_client_hello(&ch).as_deref(),
            Some("a.example")
        );
    }

    #[test]
    fn extract_sni_rejects_non_host_name_type() {
        let mut exts: Vec<u8> = Vec::new();
        let mut ext_body = Vec::new();
        let host = "example.com";
        let entry_len = 1 + 2 + host.len();
        ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes());
        ext_body.push(1); // name_type = 1 (not hostname)
        ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(host.as_bytes());
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let ch = build_client_hello_with_raw_extensions(&exts);
        assert!(extract_sni_from_client_hello(&ch).is_none());
    }

    #[test]
    fn extract_sni_rejects_zero_length_hostname_in_extension() {
        let mut exts: Vec<u8> = Vec::new();
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&3u16.to_be_bytes()); // list_len = 3 (type + len)
        ext_body.push(0); // name_type = 0
        ext_body.extend_from_slice(&0u16.to_be_bytes()); // name_len = 0
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let ch = build_client_hello_with_raw_extensions(&exts);
        assert!(extract_sni_from_client_hello(&ch).is_none());
    }

    #[test]
    fn extract_sni_with_multiple_extensions_before_sni() {
        let mut exts: Vec<u8> = Vec::new();

        // Non-SNI extension first (e.g., supported_groups = 0x000a)
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x1d]); // x25519

        // SNI extension second
        let host = "delayed.example.com";
        let mut ext_body = Vec::new();
        let entry_len = 1 + 2 + host.len();
        ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes());
        ext_body.push(0);
        ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(host.as_bytes());
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let ch = build_client_hello_with_raw_extensions(&exts);
        assert_eq!(
            extract_sni_from_client_hello(&ch).as_deref(),
            Some("delayed.example.com")
        );
    }

    fn build_client_hello_with_raw_extensions(ext_blob: &[u8]) -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&0x0303u16.to_be_bytes());
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(0); // session_id_len = 0
        hs_body.extend_from_slice(&2u16.to_be_bytes());
        hs_body.extend_from_slice(&[0x13, 0x01]);
        hs_body.push(1);
        hs_body.push(0);
        hs_body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(ext_blob);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = hs_body.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    // ---- extract_alpn edge cases ----

    #[test]
    fn extract_alpn_single_protocol() {
        let ch = build_client_hello(None, &[b"h2"], &[0x0304], 0x0303);
        let got = extract_alpn_from_client_hello(&ch);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"h2");
    }

    #[test]
    fn extract_alpn_empty_protocol_name_yields_empty_entry() {
        let mut exts: Vec<u8> = Vec::new();
        let mut list = Vec::new();
        list.push(0); // zero-length protocol
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(&list);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let ch = build_client_hello_with_raw_extensions(&exts);
        let got = extract_alpn_from_client_hello(&ch);
        assert_eq!(got.len(), 1);
        assert!(got[0].is_empty());
    }

    #[test]
    fn extract_alpn_with_extensions_before_alpn() {
        let mut exts: Vec<u8> = Vec::new();

        // Non-ALPN extension first
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x1d]);

        // ALPN extension second
        let mut list = Vec::new();
        list.push(2);
        list.extend_from_slice(b"h2");
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(&list);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let ch = build_client_hello_with_raw_extensions(&exts);
        let got = extract_alpn_from_client_hello(&ch);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"h2");
    }

    #[test]
    fn extract_alpn_truncated_mid_protocol_stops_cleanly() {
        let mut exts: Vec<u8> = Vec::new();
        let mut list = Vec::new();
        list.push(10); // claims 10-byte protocol but only 2 follow
        list.extend_from_slice(b"ht");
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(&list);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let ch = build_client_hello_with_raw_extensions(&exts);
        let got = extract_alpn_from_client_hello(&ch);
        assert!(got.is_empty());
    }

    // ---- detect_client_hello_tls_version edge cases ----

    #[test]
    fn detect_tls_version_empty_supported_versions_list_returns_none() {
        let mut exts: Vec<u8> = Vec::new();
        let mut list = Vec::new();
        list.push(0); // list_len = 0 (empty)
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&list);

        let ch = build_client_hello_with_raw_extensions(&exts);
        assert!(detect_client_hello_tls_version(&ch).is_none());
    }

    #[test]
    fn detect_tls_version_odd_length_version_list_returns_none() {
        let mut exts: Vec<u8> = Vec::new();
        let mut list = Vec::new();
        list.push(3); // odd length
        list.extend_from_slice(&[0x03, 0x03, 0x03]); // 3 bytes (not even)
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&list);

        let ch = build_client_hello_with_raw_extensions(&exts);
        assert!(detect_client_hello_tls_version(&ch).is_none());
    }

    #[test]
    fn detect_tls_version_unknown_versions_only_returns_none() {
        let mut exts: Vec<u8> = Vec::new();
        let mut list = Vec::new();
        list.push(4); // 2 version entries
        list.extend_from_slice(&0x0f0fu16.to_be_bytes()); // unknown
        list.extend_from_slice(&0x0e0eu16.to_be_bytes()); // unknown
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&list);

        let ch = build_client_hello_with_raw_extensions(&exts);
        assert!(detect_client_hello_tls_version(&ch).is_none());
    }

    #[test]
    fn detect_tls_version_tls13_first_among_many() {
        let ch = build_client_hello(None, &[], &[0x0304, 0x0303, 0x0302], 0x0303);
        assert_eq!(
            detect_client_hello_tls_version(&ch),
            Some(ClientHelloTlsVersion::Tls13)
        );
    }

    #[test]
    fn detect_tls_version_with_nonzero_session_id() {
        let sid: Vec<u8> = (0u8..16).collect();
        let ch = build_client_hello_with_session_id(None, &sid, &[0x0304], 0x0303);
        assert_eq!(
            detect_client_hello_tls_version(&ch),
            Some(ClientHelloTlsVersion::Tls13)
        );
    }

    // ---- parse_tls_record_header additional coverage ----

    #[test]
    fn parse_tls_record_header_accepts_alert_record_type() {
        let h = [0x15u8, 0x03, 0x03, 0x00, 0x02];
        let (ty, len) = parse_tls_record_header(&h).unwrap();
        assert_eq!(ty, 0x15);
        assert_eq!(len, 2);
    }

    #[test]
    fn parse_tls_record_header_accepts_change_cipher_spec_record() {
        let h = [0x14u8, 0x03, 0x03, 0x00, 0x01];
        let (ty, len) = parse_tls_record_header(&h).unwrap();
        assert_eq!(ty, 0x14);
        assert_eq!(len, 1);
    }

    #[test]
    fn parse_tls_record_header_accepts_max_record_length() {
        let h = [0x16u8, 0x03, 0x03, 0xff, 0xff];
        let (ty, len) = parse_tls_record_header(&h).unwrap();
        assert_eq!(ty, 0x16);
        assert_eq!(len, 0xffff);
    }

    // ---- TlsExtensionBuilder edge cases ----

    #[test]
    fn tls_extension_builder_empty_produces_zero_length_prefix() {
        let builder = TlsExtensionBuilder::new();
        let built = builder.build();
        assert_eq!(built.len(), 2);
        assert_eq!(u16::from_be_bytes([built[0], built[1]]), 0);
    }

    #[test]
    fn tls_extension_builder_as_bytes_empty() {
        let builder = TlsExtensionBuilder::new();
        assert!(builder.as_bytes().is_empty());
    }

    #[test]
    fn tls_extension_builder_key_share_embeds_exact_32_byte_key() {
        let mut builder = TlsExtensionBuilder::new();
        let key = [0xABu8; 32];
        builder.add_key_share(&key);
        let bytes = builder.as_bytes();

        // Extension type = 0x0033
        assert_eq!(&bytes[0..2], &extension_type::KEY_SHARE.to_be_bytes());
        // Extension data length = 36 (2 curve + 2 key_len + 32 key)
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 36);
        // Curve = X25519
        assert_eq!(&bytes[4..6], &named_curve::X25519.to_be_bytes());
        // Key length = 32
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 32);
        // Key data
        assert_eq!(&bytes[8..40], &[0xABu8; 32]);
    }

    // ---- ServerHelloBuilder edge cases ----

    #[test]
    fn server_hello_builder_oversized_session_id_returns_empty_message() {
        let long_sid = vec![0u8; 256]; // > 255
        let builder = ServerHelloBuilder::new(long_sid);
        assert!(builder.build_message().is_empty());
    }

    #[test]
    fn server_hello_builder_max_session_id() {
        let sid = vec![0xAA; 32]; // RFC max
        let builder = ServerHelloBuilder::new(sid.clone());
        let msg = builder.build_message();
        assert!(!msg.is_empty());
        // Verify session_id_len at the expected offset
        let sid_len_pos = 4 + 2 + 32; // header(1+3) + version(2) + random(32)
        assert_eq!(msg[sid_len_pos], 32);
        assert_eq!(&msg[sid_len_pos + 1..sid_len_pos + 1 + 32], &sid);
    }

    #[test]
    fn server_hello_builder_message_type_is_server_hello() {
        let builder = ServerHelloBuilder::new(vec![]);
        let msg = builder.build_message();
        assert_eq!(msg[0], 0x02); // ServerHello handshake type
    }

    #[test]
    fn server_hello_builder_cipher_suite_is_aes_128_gcm() {
        let builder = ServerHelloBuilder::new(vec![]);
        let msg = builder.build_message();
        // After: header(1+3) + version(2) + random(32) + sid_len(1) = 39
        let cipher_pos = 39;
        assert_eq!(&msg[cipher_pos..cipher_pos + 2], &cipher_suite::TLS_AES_128_GCM_SHA256);
    }

    #[test]
    fn server_hello_builder_compression_is_null() {
        let builder = ServerHelloBuilder::new(vec![]);
        let msg = builder.build_message();
        // 1(type) + 3(len) + 2(ver) + 32(rand) + 1(sid_len=0) + 2(cipher) = 41
        let comp_pos = 41;
        assert_eq!(msg[comp_pos], 0x00);
    }

    // ---- extract_sni / extract_alpn / detect_version on all-zeros input ----

    #[test]
    fn extract_sni_all_zeros_no_panic() {
        let zero = vec![0u8; 256];
        let result = extract_sni_from_client_hello(&zero);
        assert!(result.is_none());
    }

    #[test]
    fn extract_alpn_all_zeros_no_panic() {
        let zero = vec![0u8; 256];
        let got = extract_alpn_from_client_hello(&zero);
        assert!(got.is_empty());
    }

    #[test]
    fn detect_tls_version_all_zeros_no_panic() {
        let zero = vec![0u8; 256];
        let result = detect_client_hello_tls_version(&zero);
        assert!(result.is_none());
    }

    // ---- parse_tls_record_header on adversarial bytes ----

    #[test]
    fn parse_tls_record_header_all_zeros_returns_none() {
        assert!(parse_tls_record_header(&[0u8; 5]).is_none());
    }

    #[test]
    fn parse_tls_record_header_all_ones_returns_none() {
        assert!(parse_tls_record_header(&[0xFFu8; 5]).is_none());
    }

    // ---- validate_tls_handshake delegation ----

    #[test]
    fn validate_tls_handshake_delegates_with_default_boot_cap() {
        let secret = b"deleg-test";
        let now_offset = 60_i64;
        let ts = (system_time_to_unix_secs(SystemTime::now()).unwrap() + now_offset) as u32;
        let mut hs = vec![0u8; 64];
        let computed = sha256_hmac(secret, &hs);
        let ts_le = ts.to_le_bytes();
        hs[TLS_DIGEST_POS..TLS_DIGEST_POS + 28].copy_from_slice(&computed[..28]);
        for i in 0..4 {
            hs[TLS_DIGEST_POS + 28 + i] = computed[28 + i] ^ ts_le[i];
        }

        let secrets = vec![("user1".to_string(), secret.to_vec())];
        let res = validate_tls_handshake(&hs, &secrets, false);
        assert!(res.is_some());
        assert_eq!(res.unwrap().user, "user1");
    }

    // ---- is_tls_handshake with exactly 3 bytes ----

    #[test]
    fn is_tls_handshake_exact_three_bytes_accepted() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
    }

    #[test]
    fn is_tls_handshake_exact_three_bytes_rejected() {
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x02]));
    }
}
