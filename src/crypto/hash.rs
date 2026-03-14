//! Cryptographic hash functions
//!
//! ## Protocol-required algorithms
//!
//! This module exposes MD5 and SHA-1 alongside SHA-256. These weaker
//! hash functions are **required by the Telegram Middle Proxy protocol**
//! (`derive_middleproxy_keys`) and cannot be replaced without breaking
//! compatibility. They are NOT used for any security-sensitive purpose
//! outside of that specific key derivation scheme mandated by Telegram.
//!
//! Static analysis tools (`CodeQL`, cargo-audit) may flag them — the
//! usages are intentional and protocol-mandated.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;

type HmacSha256 = Hmac<Sha256>;

/// SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 HMAC
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(mac) => mac,
        // new_from_slice for HMAC accepts any key length; this branch is structurally unreachable.
        Err(_) => unreachable!("HMAC-SHA256 new_from_slice must not fail: HMAC accepts any key length"),
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// SHA-1 — **protocol-required** by Telegram Middle Proxy key derivation.
/// Not used for general-purpose hashing.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// MD5 — **protocol-required** by Telegram Middle Proxy key derivation.
/// Not used for general-purpose hashing.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// CRC32
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// CRC32C (Castagnoli)
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Build the exact prekey buffer used by Telegram Middle Proxy KDF.
///
/// Returned buffer layout (IPv4):
/// `nonce_srv` | `nonce_clt` | `clt_ts` | `srv_ip` | `clt_port` | `purpose` | `clt_ip` | `srv_port` | `secret` | `nonce_srv` | [`clt_v6` | `srv_v6`] | `nonce_clt`
#[allow(clippy::too_many_arguments)]
pub fn build_middleproxy_prekey(
    nonce_srv: &[u8; 16],
    nonce_clt: &[u8; 16],
    clt_ts: &[u8; 4],
    srv_ip: Option<&[u8]>,
    clt_port: &[u8; 2],
    purpose: &[u8],
    clt_ip: Option<&[u8]>,
    srv_port: &[u8; 2],
    secret: &[u8],
    clt_ipv6: Option<&[u8; 16]>,
    srv_ipv6: Option<&[u8; 16]>,
) -> Vec<u8> {
    const EMPTY_IP: [u8; 4] = [0, 0, 0, 0];

    let srv_ip = srv_ip.unwrap_or(&EMPTY_IP);
    let clt_ip = clt_ip.unwrap_or(&EMPTY_IP);

    let mut s = Vec::with_capacity(256);
    s.extend_from_slice(nonce_srv);
    s.extend_from_slice(nonce_clt);
    s.extend_from_slice(clt_ts);
    s.extend_from_slice(srv_ip);
    s.extend_from_slice(clt_port);
    s.extend_from_slice(purpose);
    s.extend_from_slice(clt_ip);
    s.extend_from_slice(srv_port);
    s.extend_from_slice(secret);
    s.extend_from_slice(nonce_srv);

    if let (Some(clt_v6), Some(srv_v6)) = (clt_ipv6, srv_ipv6) {
        s.extend_from_slice(clt_v6);
        s.extend_from_slice(srv_v6);
    }

    s.extend_from_slice(nonce_clt);
    s
}

/// Middle Proxy key derivation
///
/// Uses MD5 + SHA-1 as mandated by the Telegram Middle Proxy protocol.
/// These algorithms are NOT replaceable here — changing them would break
/// interoperability with Telegram's middle proxy infrastructure.
#[allow(clippy::too_many_arguments)]
pub fn derive_middleproxy_keys(
    nonce_srv: &[u8; 16],
    nonce_clt: &[u8; 16],
    clt_ts: &[u8; 4],
    srv_ip: Option<&[u8]>,
    clt_port: &[u8; 2],
    purpose: &[u8],
    clt_ip: Option<&[u8]>,
    srv_port: &[u8; 2],
    secret: &[u8],
    clt_ipv6: Option<&[u8; 16]>,
    srv_ipv6: Option<&[u8; 16]>,
) -> ([u8; 32], [u8; 16]) {
    let s = build_middleproxy_prekey(
        nonce_srv,
        nonce_clt,
        clt_ts,
        srv_ip,
        clt_port,
        purpose,
        clt_ip,
        srv_port,
        secret,
        clt_ipv6,
        srv_ipv6,
    );

    let md5_1 = md5(&s[1..]);
    let sha1_sum = sha1(&s);
    let md5_2 = md5(&s[2..]);
    
    let mut key = [0u8; 32];
    key[..12].copy_from_slice(&md5_1[..12]);
    key[12..].copy_from_slice(&sha1_sum);
    
    (key, md5_2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hmac_matches_rfc4231_test_vector_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let digest = sha256_hmac(&key, data);
        assert_eq!(
            hex::encode(digest),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn sha256_hmac_is_not_all_zero_for_nonempty_inputs() {
        let digest = sha256_hmac(b"key", b"message");
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn middleproxy_prekey_sha_is_stable() {
        let nonce_srv = [0x11u8; 16];
        let nonce_clt = [0x22u8; 16];
        let clt_ts = 0x44332211u32.to_le_bytes();
        let srv_ip = Some([149u8, 154, 175, 50].as_ref());
        let clt_ip = Some([10u8, 0, 0, 1].as_ref());
        let clt_port = 0x1f90u16.to_le_bytes(); // 8080
        let srv_port = 0x22b8u16.to_le_bytes(); // 8888
        let secret = vec![0x55u8; 128];

        let prekey = build_middleproxy_prekey(
            &nonce_srv,
            &nonce_clt,
            &clt_ts,
            srv_ip,
            &clt_port,
            b"CLIENT",
            clt_ip,
            &srv_port,
            &secret,
            None,
            None,
        );
        let digest = sha256(&prekey);
        assert_eq!(
            hex::encode(digest),
            "934f5facdafd65a44d5c2df90d2f35ddc81faaaeb337949dfeef817c8a7c1e00"
        );
    }

    #[test]
    fn sha256_empty_input_known_nist_value() {
        // SHA-256("") is a widely-published constant used for empty-input testing.
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_single_byte_known_value() {
        // SHA-256("a") — standard one-byte test vector.
        assert_eq!(
            hex::encode(sha256(b"a")),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
    }

    #[test]
    fn sha256_hmac_rfc4231_test_case_3() {
        // RFC 4231 Test Case 3: key = 0xaa*20, data = 0xdd*50.
        let digest = sha256_hmac(&[0xaau8; 20], &[0xddu8; 50]);
        assert_eq!(
            hex::encode(digest),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn sha256_hmac_does_not_panic_for_empty_inputs() {
        // HMAC-SHA256 is defined for any key length including zero; must not abort.
        let _ = sha256_hmac(b"", b"");
        let _ = sha256_hmac(b"key", b"");
        let _ = sha256_hmac(b"", b"data");
    }

    #[test]
    fn crc32_empty_input_returns_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_nonempty_input_is_nonzero() {
        // Any non-empty input must produce a non-zero CRC-32.
        assert_ne!(crc32(b"hello world"), 0);
        assert_ne!(crc32(b"a"), 0);
    }

    #[test]
    fn crc32c_empty_input_returns_zero() {
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn middleproxy_prekey_is_sensitive_to_nonce_srv() {
        // Changing any input field must change the derived prekey; tests field isolation.
        let base = build_middleproxy_prekey(
            &[0x11u8; 16], &[0x22u8; 16], &[0u8; 4],
            None, &[0u8; 2], b"CLIENT", None, &[0u8; 2], &[0u8; 16],
            None, None,
        );
        let mut alt_nonce = [0x11u8; 16];
        alt_nonce[0] ^= 0xFF;
        let alt = build_middleproxy_prekey(
            &alt_nonce, &[0x22u8; 16], &[0u8; 4],
            None, &[0u8; 2], b"CLIENT", None, &[0u8; 2], &[0u8; 16],
            None, None,
        );
        assert_ne!(sha256(&base), sha256(&alt),
            "Changing nonce_srv must change the prekey hash");
    }

    #[test]
    fn derive_middleproxy_keys_is_deterministic() {
        // Identical inputs must always produce identical keys (no hidden randomness).
        let args = (
            [0xAAu8; 16], [0xBBu8; 16], [0x01u8; 4],
            [10u8, 0, 0, 1], [0x1Fu8, 0x90], [192u8, 168, 1, 1], [0x01u8, 0xBB],
            [0x55u8; 32],
        );
        let (k1, iv1) = derive_middleproxy_keys(
            &args.0, &args.1, &args.2, Some(&args.3), &args.4,
            b"CLIENT", Some(&args.5), &args.6, &args.7, None, None,
        );
        let (k2, iv2) = derive_middleproxy_keys(
            &args.0, &args.1, &args.2, Some(&args.3), &args.4,
            b"CLIENT", Some(&args.5), &args.6, &args.7, None, None,
        );
        assert_eq!(k1, k2, "Key derivation must be deterministic");
        assert_eq!(iv1, iv2, "IV derivation must be deterministic");
    }

    #[test]
    fn derive_middleproxy_keys_sensitive_to_secret() {
        // A 1-byte change in the shared secret must produce completely different keys.
        let (k1, iv1) = derive_middleproxy_keys(
            &[0x11u8; 16], &[0x22u8; 16], &[0u8; 4], None, &[0u8; 2],
            b"CLIENT", None, &[0u8; 2], &[0x01u8; 16], None, None,
        );
        let (k2, iv2) = derive_middleproxy_keys(
            &[0x11u8; 16], &[0x22u8; 16], &[0u8; 4], None, &[0u8; 2],
            b"CLIENT", None, &[0u8; 2], &[0x02u8; 16], None, None,
        );
        assert_ne!(k1, k2, "Different secrets must produce different keys");
        assert_ne!(iv1, iv2, "Different secrets must produce different IVs");
    }

    #[test]
    fn derive_middleproxy_keys_ipv6_differs_from_ipv4_only() {
        // Including IPv6 addresses changes the prekey layout and must change the output.
        let (k_v4, iv_v4) = derive_middleproxy_keys(
            &[0x11u8; 16], &[0x22u8; 16], &[0u8; 4], None, &[0u8; 2],
            b"CLIENT", None, &[0u8; 2], &[0x55u8; 32], None, None,
        );
        let (k_v6, iv_v6) = derive_middleproxy_keys(
            &[0x11u8; 16], &[0x22u8; 16], &[0u8; 4], None, &[0u8; 2],
            b"CLIENT", None, &[0u8; 2], &[0x55u8; 32],
            Some(&[0xFEu8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Some(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        );
        assert_ne!(k_v4, k_v6, "IPv4 and IPv6 derivation must produce different keys");
        assert_ne!(iv_v4, iv_v6);
    }

    #[test]
    fn sha256_hmac_rfc4231_long_key_exceeds_block_size() {
        // RFC 4231 Test Case 6: key length (131 B) exceeds SHA-256 block size (64 B).
        // When new_from_slice receives an over-length key, HMAC hashes it internally.
        // This proves the unreachable! branch is truly unreachable — HMAC accepts any
        // key length and must not call abort/unreachable for valid inputs here.
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let digest = sha256_hmac(&key, data);
        assert_eq!(
            hex::encode(digest),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "RFC 4231 Test Case 6 mismatch"
        );
    }

    #[test]
    fn sha256_hmac_rfc4231_long_key_long_data() {
        // RFC 4231 Test Case 7: both key and data are long; exercises full HMAC paths.
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key \
                      and a larger than block-size data. The key needs to be \
                      hashed before being used by the HMAC algorithm.";
        let digest = sha256_hmac(&key, data);
        assert_eq!(
            hex::encode(digest),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "RFC 4231 Test Case 7 mismatch"
        );
    }

    #[test]
    fn sha256_hmac_single_byte_key_and_data() {
        // Minimal non-empty inputs; verifies HMAC is well-defined for the smallest valid case.
        let digest = sha256_hmac(b"k", b"d");
        assert_ne!(digest, [0u8; 32], "HMAC of single-byte inputs must not be all-zero");
    }
}
