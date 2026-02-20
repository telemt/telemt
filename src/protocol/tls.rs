//! Fake TLS 1.3 Handshake
//!
//! This module handles the fake TLS 1.3 handshake used by MTProto proxy
//! for domain fronting. The handshake looks like valid TLS 1.3 but
//! actually carries MTProto authentication data.

use crate::crypto::{sha256_hmac, SecureRandom};
use crate::error::{ProxyError, Result};
use super::constants::*;
use std::time::{SystemTime, UNIX_EPOCH};
use num_bigint::BigUint;
use num_traits::One;

// ============= Public Constants =============

/// TLS handshake digest length
pub const TLS_DIGEST_LEN: usize = 32;

/// Position of digest in TLS ClientHello
pub const TLS_DIGEST_POS: usize = 11;

/// Length to store for replay protection (first 16 bytes of digest)
pub const TLS_DIGEST_HALF_LEN: usize = 16;

/// Time skew limits for anti-replay (in seconds)
pub const TIME_SKEW_MIN: i64 = -20 * 60; // 20 minutes before
pub const TIME_SKEW_MAX: i64 = 10 * 60;  // 10 minutes after

// ============= Private Constants =============

/// TLS Extension types
mod extension_type {
    pub const KEY_SHARE: u16 = 0x0033;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
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
        self.extensions.extend_from_slice(&extension_type::KEY_SHARE.to_be_bytes());
        
        // Key share entry: curve (2) + key_len (2) + key (32) = 36 bytes
        // Extension data length
        let entry_len: u16 = 2 + 2 + 32; // curve + length + key
        self.extensions.extend_from_slice(&entry_len.to_be_bytes());
        
        // Named curve: x25519
        self.extensions.extend_from_slice(&named_curve::X25519.to_be_bytes());
        
        // Key length
        self.extensions.extend_from_slice(&(32u16).to_be_bytes());
        
        // Key data
        self.extensions.extend_from_slice(public_key);
        
        self
    }
    
    /// Add Supported Versions extension
    fn add_supported_versions(&mut self, version: u16) -> &mut Self {
        // Extension type: supported_versions (0x002b)
        self.extensions.extend_from_slice(&extension_type::SUPPORTED_VERSIONS.to_be_bytes());
        
        // Extension data: length (2) + version (2)
        self.extensions.extend_from_slice(&(2u16).to_be_bytes());
        
        // Selected version
        self.extensions.extend_from_slice(&version.to_be_bytes());
        
        self
    }
    
    /// Build final extensions with length prefix
    fn build(self) -> Vec<u8> {
        let mut result = Vec::with_capacity(2 + self.extensions.len());
        
        // Extensions length (2 bytes)
        let len = self.extensions.len() as u16;
        result.extend_from_slice(&len.to_be_bytes());
        
        // Extensions data
        result.extend_from_slice(&self.extensions);
        
        result
    }
    
    /// Get current extensions without length prefix (for calculation)
    #[allow(dead_code)]
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
        let extensions = self.extensions.extensions.clone();
        let extensions_len = extensions.len() as u16;
        
        // Calculate total length
        let body_len = 2 + // version
                       32 + // random
                       1 + self.session_id.len() + // session_id length + data
                       2 + // cipher suite
                       1 + // compression
                       2 + extensions.len(); // extensions length + data
        
        let mut message = Vec::with_capacity(4 + body_len);
        
        // Handshake header
        message.push(0x02); // ServerHello message type
        
        // 3-byte length
        let len_bytes = (body_len as u32).to_be_bytes();
        message.extend_from_slice(&len_bytes[1..4]);
        
        // Server version (TLS 1.2 in header, actual version in extension)
        message.extend_from_slice(&TLS_VERSION);
        
        // Random (32 bytes) - placeholder, will be replaced with digest
        message.extend_from_slice(&self.random);
        
        // Session ID
        message.push(self.session_id.len() as u8);
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
        
        let mut record = Vec::with_capacity(5 + message.len());
        
        // TLS record header
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        
        // Message
        record.extend_from_slice(&message);
        
        record
    }
}

// ============= Public Functions =============

/// Validate TLS ClientHello against user secrets
///
/// Returns validation result if a matching user is found.
pub fn validate_tls_handshake(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
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
    let session_id_start = session_id_len_pos + 1;
    
    if handshake.len() < session_id_start + session_id_len {
        return None;
    }
    
    let session_id = handshake[session_id_start..session_id_start + session_id_len].to_vec();
    
    // Build message for HMAC (with zeroed digest)
    let mut msg = handshake.to_vec();
    msg[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);
    
    // Get current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    for (user, secret) in secrets {
        let computed = sha256_hmac(secret, &msg);
        
        // XOR digests
        let xored: Vec<u8> = digest.iter()
            .zip(computed.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        
        // Check that first 28 bytes are zeros (timestamp in last 4)
        if !xored[..28].iter().all(|&b| b == 0) {
            continue;
        }
        
        // Extract timestamp
        let timestamp = u32::from_le_bytes(xored[28..32].try_into().unwrap());
        let time_diff = now - timestamp as i64;
        
        // Check time skew
        if !ignore_time_skew {
            // Allow very small timestamps (boot time instead of unix time)
            // This is a quirk in some clients that use uptime instead of real time
            let is_boot_time = timestamp < 60 * 60 * 24 * 1000; // < ~2.7 years in seconds
            
            if !is_boot_time && (time_diff < TIME_SKEW_MIN || time_diff > TIME_SKEW_MAX) {
                continue;
            }
        }
        
        return Some(TlsValidation {
            user: user.clone(),
            session_id,
            digest,
            timestamp,
        });
    }
    
    None
}

fn curve25519_prime() -> BigUint {
    (BigUint::one() << 255) - BigUint::from(19u32)
}

/// Generate a fake X25519 public key for TLS
///
/// Produces a quadratic residue mod p = 2^255 - 19 by computing n² mod p,
/// which matches Python/C behavior and avoids DPI fingerprinting.
pub fn gen_fake_x25519_key(rng: &SecureRandom) -> [u8; 32] {
    let mut n_bytes = [0u8; 32];
    n_bytes.copy_from_slice(&rng.bytes(32));

    let n = BigUint::from_bytes_le(&n_bytes);
    let p = curve25519_prime();
    let pk = (&n * &n) % &p;

    let mut out = pk.to_bytes_le();
    out.resize(32, 0);
    let mut result = [0u8; 32];
    result.copy_from_slice(&out[..32]);
    result
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
) -> Vec<u8> {
    let x25519_key = gen_fake_x25519_key(rng);
    
    // Build ServerHello
    let server_hello = ServerHelloBuilder::new(session_id.to_vec())
        .with_x25519_key(&x25519_key)
        .with_tls13_version()
        .build_record();
    
    // Build Change Cipher Spec record
    let change_cipher_spec = [
        TLS_RECORD_CHANGE_CIPHER,
        TLS_VERSION[0], TLS_VERSION[1],
        0x00, 0x01, // length = 1
        0x01,       // CCS byte
    ];
    
    // Build fake certificate (Application Data record)
    let fake_cert = rng.bytes(fake_cert_len);
    let mut app_data_record = Vec::with_capacity(5 + fake_cert_len);
    app_data_record.push(TLS_RECORD_APPLICATION);
    app_data_record.extend_from_slice(&TLS_VERSION);
    app_data_record.extend_from_slice(&(fake_cert_len as u16).to_be_bytes());
    app_data_record.extend_from_slice(&fake_cert);
    
    // Combine all records
    let mut response = Vec::with_capacity(
        server_hello.len() + change_cipher_spec.len() + app_data_record.len()
    );
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&change_cipher_spec);
    response.extend_from_slice(&app_data_record);
    
    // Compute HMAC for the response
    let mut hmac_input = Vec::with_capacity(TLS_DIGEST_LEN + response.len());
    hmac_input.extend_from_slice(client_digest);
    hmac_input.extend_from_slice(&response);
    let response_digest = sha256_hmac(secret, &hmac_input);
    
    // Insert computed digest into ServerHello
    // Position: record header (5) + message type (1) + length (3) + version (2) = 11
    response[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
        .copy_from_slice(&response_digest);
    
    response
}

/// Extract SNI (server_name) from a TLS ClientHello.
pub fn extract_sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 43 || handshake[0] != TLS_RECORD_HANDSHAKE {
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

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == 0x0000 && elen >= 5 {
            // server_name extension
            let list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            let mut sn_pos = pos + 2;
            let sn_end = std::cmp::min(sn_pos + list_len, pos + elen);
            while sn_pos + 3 <= sn_end {
                let name_type = handshake[sn_pos];
                let name_len = u16::from_be_bytes([handshake[sn_pos + 1], handshake[sn_pos + 2]]) as usize;
                sn_pos += 3;
                if sn_pos + name_len > sn_end {
                    break;
                }
                if name_type == 0 && name_len > 0 {
                    if let Ok(host) = std::str::from_utf8(&handshake[sn_pos..sn_pos + name_len]) {
                        return Some(host.to_string());
                    }
                }
                sn_pos += name_len;
            }
        }
        pos += elen;
    }

    None
}

/// Check if bytes look like a TLS ClientHello
pub fn is_tls_handshake(first_bytes: &[u8]) -> bool {
    if first_bytes.len() < 3 {
        return false;
    }
    
    // TLS record header: 0x16 (handshake) 0x03 0x01 (TLS 1.0)
    first_bytes[0] == TLS_RECORD_HANDSHAKE 
        && first_bytes[1] == 0x03 
        && first_bytes[2] == 0x01
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
fn validate_server_hello_structure(data: &[u8]) -> Result<()> {
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
        return Err(ProxyError::InvalidHandshake(
            format!("ServerHello record truncated: expected {}, got {}", 
                5 + record_len, data.len())
        ));
    }
    
    // Check message type
    if data[5] != 0x02 {
        return Err(ProxyError::InvalidHandshake(
            format!("Expected ServerHello (0x02), got 0x{:02x}", data[5])
        ));
    }
    
    // Parse message length
    let msg_len = u32::from_be_bytes([0, data[6], data[7], data[8]]) as usize;
    if msg_len + 4 != record_len {
        return Err(ProxyError::InvalidHandshake(
            format!("Message length mismatch: {} + 4 != {}", msg_len, record_len)
        ));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_tls_handshake() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01, 0x02, 0x00]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x01])); // Application data
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x02])); // Wrong version
        assert!(!is_tls_handshake(&[0x16, 0x03])); // Too short
    }
    
    #[test]
    fn test_parse_tls_record_header() {
        let header = [0x16, 0x03, 0x01, 0x02, 0x00];
        let result = parse_tls_record_header(&header).unwrap();
        assert_eq!(result.0, TLS_RECORD_HANDSHAKE);
        assert_eq!(result.1, 512);
        
        let header = [0x17, 0x03, 0x03, 0x40, 0x00];
        let result = parse_tls_record_header(&header).unwrap();
        assert_eq!(result.0, TLS_RECORD_APPLICATION);
        assert_eq!(result.1, 16384);
    }
    
    #[test]
    fn test_gen_fake_x25519_key() {
        let rng = SecureRandom::new();
        let key1 = gen_fake_x25519_key(&rng);
        let key2 = gen_fake_x25519_key(&rng);
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Should be random
    }

    #[test]
    fn test_fake_x25519_key_is_quadratic_residue() {
        let rng = SecureRandom::new();
        let key = gen_fake_x25519_key(&rng);
        let p = curve25519_prime();
        let k_num = BigUint::from_bytes_le(&key);
        let exponent = (&p - BigUint::one()) >> 1;
        let legendre = k_num.modpow(&exponent, &p);
        assert_eq!(legendre, BigUint::one());
    }
    
    #[test]
    fn test_tls_extension_builder() {
        let key = [0x42u8; 32];
        
        let mut builder = TlsExtensionBuilder::new();
        builder.add_key_share(&key);
        builder.add_supported_versions(0x0304);
        
        let result = builder.build();
        
        // Check length prefix
        let len = u16::from_be_bytes([result[0], result[1]]) as usize;
        assert_eq!(len, result.len() - 2);
        
        // Check key_share extension is present
        assert!(result.len() > 40); // At least key share
    }
    
    #[test]
    fn test_server_hello_builder() {
        let session_id = vec![0x01, 0x02, 0x03, 0x04];
        let key = [0x55u8; 32];
        
        let builder = ServerHelloBuilder::new(session_id.clone())
            .with_x25519_key(&key)
            .with_tls13_version();
        
        let record = builder.build_record();
        
        // Validate structure
        validate_server_hello_structure(&record).expect("Invalid ServerHello structure");
        
        // Check record type
        assert_eq!(record[0], TLS_RECORD_HANDSHAKE);
        
        // Check version
        assert_eq!(&record[1..3], &TLS_VERSION);
        
        // Check message type (ServerHello = 0x02)
        assert_eq!(record[5], 0x02);
    }
    
    #[test]
    fn test_build_server_hello_structure() {
        let secret = b"test secret";
        let client_digest = [0x42u8; 32];
        let session_id = vec![0xAA; 32];
        
        let rng = SecureRandom::new();
        let response = build_server_hello(secret, &client_digest, &session_id, 2048, &rng);
        
        // Should have at least 3 records
        assert!(response.len() > 100);
        
        // First record should be ServerHello
        assert_eq!(response[0], TLS_RECORD_HANDSHAKE);
        
        // Validate ServerHello structure
        validate_server_hello_structure(&response).expect("Invalid ServerHello");
        
        // Find Change Cipher Spec
        let server_hello_len = 5 + u16::from_be_bytes([response[3], response[4]]) as usize;
        let ccs_start = server_hello_len;
        
        assert!(response.len() > ccs_start + 6);
        assert_eq!(response[ccs_start], TLS_RECORD_CHANGE_CIPHER);
        
        // Find Application Data
        let ccs_len = 5 + u16::from_be_bytes([response[ccs_start + 3], response[ccs_start + 4]]) as usize;
        let app_start = ccs_start + ccs_len;
        
        assert!(response.len() > app_start + 5);
        assert_eq!(response[app_start], TLS_RECORD_APPLICATION);
    }
    
    #[test]
    fn test_build_server_hello_digest() {
        let secret = b"test secret key here";
        let client_digest = [0x42u8; 32];
        let session_id = vec![0xAA; 32];
        
        let rng = SecureRandom::new();
        let response1 = build_server_hello(secret, &client_digest, &session_id, 1024, &rng);
        let response2 = build_server_hello(secret, &client_digest, &session_id, 1024, &rng);
        
        // Digest position should have non-zero data
        let digest1 = &response1[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN];
        assert!(!digest1.iter().all(|&b| b == 0));
        
        // Different calls should have different digests (due to random cert)
        let digest2 = &response2[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN];
        assert_ne!(digest1, digest2);
    }
    
    #[test]
    fn test_server_hello_extensions_length() {
        let session_id = vec![0x01; 32];
        let key = [0x55u8; 32];
        
        let builder = ServerHelloBuilder::new(session_id)
            .with_x25519_key(&key)
            .with_tls13_version();
        
        let record = builder.build_record();
        
        // Parse to find extensions
        let msg_start = 5; // After record header
        let msg_len = u32::from_be_bytes([0, record[6], record[7], record[8]]) as usize;
        
        // Skip to session ID
        let session_id_pos = msg_start + 4 + 2 + 32; // header(4) + version(2) + random(32)
        let session_id_len = record[session_id_pos] as usize;
        
        // Skip to extensions
        let ext_len_pos = session_id_pos + 1 + session_id_len + 2 + 1; // session_id + cipher(2) + compression(1)
        let ext_len = u16::from_be_bytes([record[ext_len_pos], record[ext_len_pos + 1]]) as usize;
        
        // Verify extensions length matches actual data
        let extensions_data = &record[ext_len_pos + 2..msg_start + 4 + msg_len];
        assert_eq!(ext_len, extensions_data.len(), 
            "Extension length mismatch: declared {}, actual {}", ext_len, extensions_data.len());
    }
    
    #[test]
    fn test_validate_tls_handshake_format() {
        // Build a minimal ClientHello-like structure
        let mut handshake = vec![0u8; 100];
        
        // Put a valid-looking digest at position 11
        handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
            .copy_from_slice(&[0x42; 32]);
        
        // Session ID length
        handshake[TLS_DIGEST_POS + TLS_DIGEST_LEN] = 32;
        
        // This won't validate (wrong HMAC) but shouldn't panic
        let secrets = vec![("test".to_string(), b"secret".to_vec())];
        let result = validate_tls_handshake(&handshake, &secrets, true);
        
        // Should return None (no match) but not panic
        assert!(result.is_none());
    }
}
