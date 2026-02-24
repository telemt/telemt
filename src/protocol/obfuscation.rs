//! MTProto Obfuscation

#![allow(dead_code)]

use zeroize::Zeroize;
use crate::crypto::{sha256, AesCtr};
use super::constants::*;

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
            
            let dc_idx = i16::from_le_bytes(
                decrypted[DC_IDX_POS..DC_IDX_POS + 2].try_into().unwrap()
            );
            
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
}
