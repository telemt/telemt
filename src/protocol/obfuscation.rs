//! MTProto Obfuscation

#![allow(dead_code)]

use super::constants::*;
use crate::crypto::{AesCtr, sha256};
use zeroize::Zeroize;

/// Obfuscation parameters from handshake
///
/// Key material is zeroized on drop.
#[derive(Debug, Clone)]
pub struct ObfuscationParams {
    /// Key for decrypting client -> proxy traffic
    pub decrypt_key: [u8; 32],
    /// IV for decrypting client -> proxy traffic
    pub decrypt_iv: u128,
    /// Key for encrypting proxy -> client traffic
    pub encrypt_key: [u8; 32],
    /// IV for encrypting proxy -> client traffic
    pub encrypt_iv: u128,
    /// Protocol tag (abridged/intermediate/secure)
    pub proto_tag: ProtoTag,
    /// Datacenter index
    pub dc_idx: i16,
}

impl Drop for ObfuscationParams {
    fn drop(&mut self) {
        self.decrypt_key.zeroize();
        self.decrypt_iv.zeroize();
        self.encrypt_key.zeroize();
        self.encrypt_iv.zeroize();
    }
}

impl ObfuscationParams {
    /// Parse obfuscation parameters from handshake bytes
    /// Returns None if handshake doesn't match any user secret
    pub fn from_handshake(
        handshake: &[u8; HANDSHAKE_LEN],
        secrets: &[(String, Vec<u8>)],
    ) -> Option<(Self, String)> {
        let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let dec_prekey = &dec_prekey_iv[..PREKEY_LEN];
        let dec_iv_bytes = &dec_prekey_iv[PREKEY_LEN..];

        let enc_prekey_iv: Vec<u8> = dec_prekey_iv.iter().rev().copied().collect();
        let enc_prekey = &enc_prekey_iv[..PREKEY_LEN];
        let enc_iv_bytes = &enc_prekey_iv[PREKEY_LEN..];

        for (username, secret) in secrets {
            let mut dec_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
            dec_key_input.extend_from_slice(dec_prekey);
            dec_key_input.extend_from_slice(secret);
            let decrypt_key = sha256(&dec_key_input);

            let decrypt_iv = u128::from_be_bytes(dec_iv_bytes.try_into().unwrap());

            let mut decryptor = AesCtr::new(&decrypt_key, decrypt_iv);
            let decrypted = decryptor.decrypt(handshake);

            let tag_bytes: [u8; 4] = decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]
                .try_into()
                .unwrap();

            let proto_tag = match ProtoTag::from_bytes(tag_bytes) {
                Some(tag) => tag,
                None => continue,
            };

            let dc_idx =
                i16::from_le_bytes(decrypted[DC_IDX_POS..DC_IDX_POS + 2].try_into().unwrap());

            let mut enc_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
            enc_key_input.extend_from_slice(enc_prekey);
            enc_key_input.extend_from_slice(secret);
            let encrypt_key = sha256(&enc_key_input);
            let encrypt_iv = u128::from_be_bytes(enc_iv_bytes.try_into().unwrap());

            return Some((
                ObfuscationParams {
                    decrypt_key,
                    decrypt_iv,
                    encrypt_key,
                    encrypt_iv,
                    proto_tag,
                    dc_idx,
                },
                username.clone(),
            ));
        }

        None
    }

    /// Create AES-CTR decryptor for client -> proxy direction
    pub fn create_decryptor(&self) -> AesCtr {
        AesCtr::new(&self.decrypt_key, self.decrypt_iv)
    }

    /// Create AES-CTR encryptor for proxy -> client direction
    pub fn create_encryptor(&self) -> AesCtr {
        AesCtr::new(&self.encrypt_key, self.encrypt_iv)
    }

    /// Get the combined encrypt key and IV for fast mode
    pub fn enc_key_iv(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(KEY_LEN + IV_LEN);
        result.extend_from_slice(&self.encrypt_key);
        result.extend_from_slice(&self.encrypt_iv.to_be_bytes());
        result
    }
}

/// Generate a valid random nonce for Telegram handshake
pub fn generate_nonce<R: FnMut(usize) -> Vec<u8>>(mut random_bytes: R) -> [u8; HANDSHAKE_LEN] {
    loop {
        let nonce_vec = random_bytes(HANDSHAKE_LEN);
        let mut nonce = [0u8; HANDSHAKE_LEN];
        nonce.copy_from_slice(&nonce_vec);

        if is_valid_nonce(&nonce) {
            return nonce;
        }
    }
}

/// Check if nonce is valid (not matching reserved patterns)
pub fn is_valid_nonce(nonce: &[u8; HANDSHAKE_LEN]) -> bool {
    if RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]) {
        return false;
    }

    let first_four: [u8; 4] = nonce[..4].try_into().unwrap();
    if RESERVED_NONCE_BEGINNINGS.contains(&first_four) {
        return false;
    }

    let continue_four: [u8; 4] = nonce[4..8].try_into().unwrap();
    if RESERVED_NONCE_CONTINUES.contains(&continue_four) {
        return false;
    }

    true
}

/// Prepare nonce for sending to Telegram
pub fn prepare_tg_nonce(
    nonce: &mut [u8; HANDSHAKE_LEN],
    proto_tag: ProtoTag,
    enc_key_iv: Option<&[u8]>,
) {
    nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());

    if let Some(key_iv) = enc_key_iv {
        let reversed: Vec<u8> = key_iv.iter().rev().copied().collect();
        nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN].copy_from_slice(&reversed);
    }
}

/// Encrypt the outgoing nonce for Telegram
/// Legacy helper — **do not use**.
/// WARNING: logic diverges from Python/C reference (SHA256 of 48 bytes, IV from head).
/// Kept only to avoid breaking external callers; prefer `encrypt_tg_nonce_with_ciphers`.
#[deprecated(
    note = "Incorrect MTProto obfuscation KDF; use proxy::handshake::encrypt_tg_nonce_with_ciphers"
)]
pub fn encrypt_nonce(nonce: &[u8; HANDSHAKE_LEN]) -> Vec<u8> {
    let key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let enc_key = sha256(key_iv);
    let enc_iv = u128::from_be_bytes(key_iv[..IV_LEN].try_into().unwrap());

    let mut encryptor = AesCtr::new(&enc_key, enc_iv);

    let mut result = nonce.to_vec();
    let encrypted_part = encryptor.encrypt(&nonce[PROTO_TAG_POS..]);
    result[PROTO_TAG_POS..].copy_from_slice(&encrypted_part);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_nonce() {
        let mut valid = [0x42u8; HANDSHAKE_LEN];
        valid[4..8].copy_from_slice(&[1, 2, 3, 4]);
        assert!(is_valid_nonce(&valid));

        let mut invalid = [0x00u8; HANDSHAKE_LEN];
        invalid[0] = 0xef;
        assert!(!is_valid_nonce(&invalid));

        let mut invalid = [0x00u8; HANDSHAKE_LEN];
        invalid[..4].copy_from_slice(b"HEAD");
        assert!(!is_valid_nonce(&invalid));

        let mut invalid = [0x42u8; HANDSHAKE_LEN];
        invalid[4..8].copy_from_slice(&[0, 0, 0, 0]);
        assert!(!is_valid_nonce(&invalid));
    }

    #[test]
    fn test_generate_nonce() {
        let mut counter = 0u8;
        let nonce = generate_nonce(|n| {
            counter = counter.wrapping_add(1);
            vec![counter; n]
        });

        assert!(is_valid_nonce(&nonce));
        assert_eq!(nonce.len(), HANDSHAKE_LEN);
    }

    fn nonce_with_prefix(prefix: &[u8]) -> [u8; HANDSHAKE_LEN] {
        let mut n = [0x42u8; HANDSHAKE_LEN];
        n[..prefix.len()].copy_from_slice(prefix);
        // Make the continuation block (bytes 4..8) non-reserved.
        n[4..8].copy_from_slice(&[1, 2, 3, 4]);
        n
    }

    #[test]
    fn is_valid_nonce_rejects_each_reserved_beginning() {
        // Every entry in RESERVED_NONCE_BEGINNINGS must be flagged.
        for &reserved in RESERVED_NONCE_BEGINNINGS {
            let n = nonce_with_prefix(&reserved);
            assert!(
                !is_valid_nonce(&n),
                "is_valid_nonce should reject prefix {:02x?}",
                reserved
            );
        }
    }

    #[test]
    fn is_valid_nonce_rejects_each_reserved_continuation() {
        // Every entry in RESERVED_NONCE_CONTINUES must be flagged when it
        // appears at bytes 4..8 (with a non-reserved prefix at 0..4).
        for &cont in RESERVED_NONCE_CONTINUES {
            let mut n = [0x42u8; HANDSHAKE_LEN];
            n[..4].copy_from_slice(&[1, 2, 3, 4]);
            n[4..8].copy_from_slice(&cont);
            assert!(
                !is_valid_nonce(&n),
                "is_valid_nonce should reject continuation {:02x?}",
                cont
            );
        }
    }

    #[test]
    fn is_valid_nonce_rejects_first_byte_only_collisions() {
        // Only the first byte equals a reserved value (0xef), continuation
        // and rest fine — must still be flagged.
        for &b in RESERVED_NONCE_FIRST_BYTES {
            let mut n = [0x42u8; HANDSHAKE_LEN];
            n[0] = b;
            n[4..8].copy_from_slice(&[1, 2, 3, 4]);
            assert!(!is_valid_nonce(&n), "first byte {:02x} must be rejected", b);
        }
    }

    #[test]
    fn generate_nonce_does_not_loop_forever_with_valid_rng() {
        // A trivial "RNG" that always returns a non-reserved nonce must
        // succeed on the first iteration.
        let calls = std::cell::Cell::new(0u32);
        let nonce = generate_nonce(|n| {
            calls.set(calls.get() + 1);
            let mut v = vec![0x55u8; n];
            v[4..8].copy_from_slice(&[1, 2, 3, 4]);
            v
        });
        assert!(is_valid_nonce(&nonce));
        assert_eq!(calls.get(), 1, "expected exactly one rng call");
    }

    #[test]
    fn generate_nonce_retries_on_reserved_outputs() {
        // First call returns a reserved nonce (0xef prefix), second call
        // returns a valid one — generate_nonce must retry.
        let calls = std::cell::Cell::new(0u32);
        let nonce = generate_nonce(|n| {
            let attempt = calls.get();
            calls.set(attempt + 1);
            let mut v = vec![0x33u8; n];
            if attempt == 0 {
                v[0] = 0xef; // reserved first byte
            }
            v[4..8].copy_from_slice(&[1, 2, 3, 4]);
            v
        });
        assert!(is_valid_nonce(&nonce));
        assert!(calls.get() >= 2, "expected retry on reserved nonce");
    }

    #[test]
    fn prepare_tg_nonce_writes_proto_tag_at_fixed_offset() {
        let mut nonce = [0x42u8; HANDSHAKE_LEN];
        prepare_tg_nonce(&mut nonce, ProtoTag::Intermediate, None);
        assert_eq!(
            &nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4],
            &ProtoTag::Intermediate.to_bytes()
        );
        // Bytes outside the proto-tag slot must remain untouched when
        // `enc_key_iv` is None.
        for (i, &b) in nonce.iter().enumerate() {
            if !(PROTO_TAG_POS..PROTO_TAG_POS + 4).contains(&i) {
                assert_eq!(b, 0x42, "byte {} should be untouched", i);
            }
        }
    }

    #[test]
    fn prepare_tg_nonce_writes_reversed_key_iv_at_skip_offset() {
        let mut nonce = [0x42u8; HANDSHAKE_LEN];
        let key_iv: Vec<u8> = (0u8..(KEY_LEN + IV_LEN) as u8).collect();
        prepare_tg_nonce(&mut nonce, ProtoTag::Secure, Some(&key_iv));

        // Bytes [SKIP_LEN..SKIP_LEN+48] must equal the reverse of key_iv.
        let mut expected = key_iv.clone();
        expected.reverse();
        assert_eq!(
            &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN],
            expected.as_slice()
        );
        // proto_tag block still set correctly.
        assert_eq!(
            &nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4],
            &ProtoTag::Secure.to_bytes()
        );
    }

    #[test]
    fn enc_key_iv_layout_is_key_then_iv_be() {
        // Build params without going through the handshake parser — that
        // keeps this test isolated from the crypto-derivation logic.
        let params = ObfuscationParams {
            decrypt_key: [0; 32],
            decrypt_iv: 0,
            encrypt_key: [0x11; 32],
            encrypt_iv: 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128,
            proto_tag: ProtoTag::Intermediate,
            dc_idx: 2,
        };
        let blob = params.enc_key_iv();
        assert_eq!(blob.len(), KEY_LEN + IV_LEN);
        assert_eq!(&blob[..KEY_LEN], &[0x11u8; 32]);
        assert_eq!(&blob[KEY_LEN..], &params.encrypt_iv.to_be_bytes());
    }

}
