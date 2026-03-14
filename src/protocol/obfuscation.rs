//! `MTProto` Obfuscation

#![allow(dead_code)]

use zeroize::{Zeroize, Zeroizing};
use crate::crypto::{sha256, AesCtr};
use super::constants::*;

/// Obfuscation parameters from handshake
///
/// Key material is zeroized on drop.
#[derive(Debug)]
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
        
        let enc_prekey_iv: Zeroizing<Vec<u8>> =
            Zeroizing::new(dec_prekey_iv.iter().rev().copied().collect());
        let enc_prekey = &enc_prekey_iv[..PREKEY_LEN];
        let enc_iv_bytes = &enc_prekey_iv[PREKEY_LEN..];
        
        for (username, secret) in secrets {
            let mut dec_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
            dec_key_input.extend_from_slice(dec_prekey);
            dec_key_input.extend_from_slice(secret);
            let decrypt_key = sha256(&dec_key_input);
            
            let mut dec_iv_arr = [0u8; IV_LEN];
            dec_iv_arr.copy_from_slice(dec_iv_bytes);
            let decrypt_iv = u128::from_be_bytes(dec_iv_arr);
            
            let mut decryptor = AesCtr::new(&decrypt_key, decrypt_iv);
            let decrypted = Zeroizing::new(decryptor.decrypt(handshake));
            
            let mut tag_bytes = [0u8; 4];
            tag_bytes.copy_from_slice(&decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]);
            
            let proto_tag = match ProtoTag::from_bytes(tag_bytes) {
                Some(tag) => tag,
                None => continue,
            };
            
            let mut dc_idx_bytes = [0u8; 2];
            dc_idx_bytes.copy_from_slice(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]);
            let dc_idx = i16::from_le_bytes(dc_idx_bytes);
            
            let mut enc_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
            enc_key_input.extend_from_slice(enc_prekey);
            enc_key_input.extend_from_slice(secret);
            let encrypt_key = sha256(&enc_key_input);
            let mut enc_iv_arr = [0u8; IV_LEN];
            enc_iv_arr.copy_from_slice(enc_iv_bytes);
            let encrypt_iv = u128::from_be_bytes(enc_iv_arr);
            
            return Some((
                Self {
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

/// Maximum nonce generation attempts; statistically unreachable with a correct CSPRNG.
/// Reaching this limit indicates a broken or adversarial random-bytes source.
pub const MAX_NONCE_ATTEMPTS: usize = 64;

/// Generate a valid random nonce for Telegram handshake.
///
/// Panics if `random_bytes` returns `MAX_NONCE_ATTEMPTS` consecutive invalid nonces,
/// which is a statistical impossibility with a correctly-seeded CSPRNG.
pub fn generate_nonce<R: FnMut(usize) -> Vec<u8>>(mut random_bytes: R) -> [u8; HANDSHAKE_LEN] {
    for _ in 0..MAX_NONCE_ATTEMPTS {
        let nonce_vec = random_bytes(HANDSHAKE_LEN);
        let mut nonce = [0u8; HANDSHAKE_LEN];
        nonce.copy_from_slice(&nonce_vec);
        
        if is_valid_nonce(&nonce) {
            return nonce;
        }
    }
    unreachable!("CSPRNG produced {MAX_NONCE_ATTEMPTS} consecutive invalid nonces — RNG is broken")
}

/// Check if nonce is valid (not matching reserved patterns)
pub fn is_valid_nonce(nonce: &[u8; HANDSHAKE_LEN]) -> bool {
    if RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]) {
        return false;
    }
    
    let first_four = [nonce[0], nonce[1], nonce[2], nonce[3]];
    if RESERVED_NONCE_BEGINNINGS.contains(&first_four) {
        return false;
    }
    
    let continue_four = [nonce[4], nonce[5], nonce[6], nonce[7]];
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
        let Some(key_iv_slice) = key_iv.get(..KEY_LEN + IV_LEN) else {
            return;
        };
        let reversed: Vec<u8> = key_iv_slice.iter().rev().copied().collect();
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
    let mut enc_iv_arr = [0u8; IV_LEN];
    enc_iv_arr.copy_from_slice(&key_iv[..IV_LEN]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);
    
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

    // Every reserved first byte must be rejected, not just 0xef.
    #[test]
    fn test_is_valid_nonce_all_reserved_first_bytes_rejected() {
        for &b in RESERVED_NONCE_FIRST_BYTES {
            let mut nonce = [0x42u8; HANDSHAKE_LEN];
            nonce[0] = b;
            nonce[4..8].copy_from_slice(&[1, 2, 3, 4]); // valid continuation
            assert!(!is_valid_nonce(&nonce), "byte 0x{b:02x} must be reserved");
        }
    }

    // Every reserved 4-byte beginning must be rejected at bytes 0-3.
    #[test]
    fn test_is_valid_nonce_all_reserved_beginnings_rejected() {
        for beginning in RESERVED_NONCE_BEGINNINGS {
            let mut nonce = [0x42u8; HANDSHAKE_LEN];
            nonce[..4].copy_from_slice(beginning);
            nonce[4..8].copy_from_slice(&[1, 2, 3, 4]); // valid continuation
            assert!(
                !is_valid_nonce(&nonce),
                "beginning {:?} must be reserved",
                beginning
            );
        }
    }

    // Every reserved continuation must be rejected at bytes 4-7.
    #[test]
    fn test_is_valid_nonce_all_reserved_continuations_rejected() {
        for cont in RESERVED_NONCE_CONTINUES {
            let mut nonce = [0x42u8; HANDSHAKE_LEN];
            nonce[4..8].copy_from_slice(cont);
            assert!(
                !is_valid_nonce(&nonce),
                "continuation {:?} must be reserved",
                cont
            );
        }
    }

    // 0xee as byte 1 (not byte 0) must not be rejected by the first-byte check.
    #[test]
    fn test_is_valid_nonce_intermediate_tag_at_non_zero_offset_ok() {
        let mut nonce = [0x42u8; HANDSHAKE_LEN];
        nonce[0] = 0x42; // valid first byte
        nonce[1] = 0xee; // not at reserved position
        nonce[4..8].copy_from_slice(&[1, 2, 3, 4]);
        assert!(is_valid_nonce(&nonce));
    }

    // prepare_tg_nonce must correctly embed the proto tag into the nonce.
    #[test]
    fn test_prepare_tg_nonce_embeds_proto_tag() {
        let mut nonce = [0x42u8; HANDSHAKE_LEN];
        prepare_tg_nonce(&mut nonce, ProtoTag::Intermediate, None);
        assert_eq!(
            &nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4],
            &ProtoTag::Intermediate.to_bytes()
        );
    }

    // prepare_tg_nonce with a valid-length enc_key_iv must write reversed bytes.
    #[test]
    fn test_prepare_tg_nonce_with_enc_key_iv_reverses_bytes() {
        let mut nonce = [0u8; HANDSHAKE_LEN];
        let key_iv: Vec<u8> = (0u8..((KEY_LEN + IV_LEN) as u8)).collect();
        prepare_tg_nonce(&mut nonce, ProtoTag::Secure, Some(&key_iv));

        let reversed: Vec<u8> = key_iv[..KEY_LEN + IV_LEN].iter().rev().copied().collect();
        assert_eq!(&nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN], reversed.as_slice());
    }

    #[test]
    fn test_prepare_tg_nonce_short_enc_key_iv_does_not_panic_or_overwrite() {
        let mut nonce = [0x42u8; HANDSHAKE_LEN];
        let short_key_iv = [0u8; 8];

        prepare_tg_nonce(&mut nonce, ProtoTag::Abridged, Some(&short_key_iv));

        assert_eq!(
            &nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4],
            &ProtoTag::Abridged.to_bytes()
        );
        assert_eq!(
            &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN],
            &[0x42u8; KEY_LEN + IV_LEN]
        );
    }

    // from_handshake must return None when no secret matches.
    #[test]
    fn test_from_handshake_no_match_returns_none() {
        let handshake = [0x42u8; HANDSHAKE_LEN];
        let secrets = vec![("user".to_string(), vec![0x01u8; 32])];
        let result = ObfuscationParams::from_handshake(&handshake, &secrets);
        assert!(result.is_none());
    }

    // from_handshake with empty secrets must return None without panic.
    #[test]
    fn test_from_handshake_empty_secrets_returns_none() {
        let handshake = [0u8; HANDSHAKE_LEN];
        let result = ObfuscationParams::from_handshake(&handshake, &[]);
        assert!(result.is_none());
    }

    // generate_nonce must terminate even when the first MAX_NONCE_ATTEMPTS-1 calls
    // return invalid nonces (first byte reserved). The bounded loop must produce
    // a valid nonce on the last attempt rather than looping forever.
    #[test]
    fn test_generate_nonce_bounded_loop_terminates() {
        let mut call_count = 0usize;
        let nonce = generate_nonce(|n| {
            call_count += 1;
            let mut buf = vec![0x42u8; n];
            if call_count < MAX_NONCE_ATTEMPTS {
                // Reserved first byte forces rejection.
                buf[0] = RESERVED_NONCE_FIRST_BYTES[0];
                // Ensure continuation is non-reserved so only first-byte check fires.
                buf[4..8].copy_from_slice(&[1, 2, 3, 4]);
            } else {
                // Final attempt: valid nonce.
                buf[0] = 0x42;
                buf[4..8].copy_from_slice(&[1, 2, 3, 4]);
            }
            buf
        });
        assert!(is_valid_nonce(&nonce), "final nonce must be valid");
        assert_eq!(
            call_count, MAX_NONCE_ATTEMPTS,
            "RNG must be called exactly MAX_NONCE_ATTEMPTS times"
        );
    }

    // Verify that a single valid nonce is returned on the first attempt (common path).
    #[test]
    fn test_generate_nonce_succeeds_on_first_valid_attempt() {
        let mut call_count = 0usize;
        let nonce = generate_nonce(|n| {
            call_count += 1;
            let mut buf = vec![0x42u8; n];
            buf[4..8].copy_from_slice(&[1, 2, 3, 4]);
            buf
        });
        assert!(is_valid_nonce(&nonce));
        assert_eq!(call_count, 1, "valid RNG must not need more than one attempt");
    }

    // ObfuscationParams must NOT implement Clone — key material must not be duplicated.
    // Enforced at compile time: if Clone is ever derived or manually implemented for
    // ObfuscationParams, this assertion will fail to compile.
    static_assertions::assert_not_impl_any!(ObfuscationParams: Clone);
}
