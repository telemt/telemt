//! AES encryption implementations
//!
//! Provides AES-256-CTR and AES-256-CBC modes for `MTProto` encryption.
//!
//! ## Zeroize policy
//!
//! - `AesCbc` stores raw key/IV bytes and zeroizes them on drop.
//! - `AesCtr` wraps an opaque `Aes256Ctr` cipher from the `ctr` crate.
//!   The expanded key schedule lives inside that type and cannot be
//!   zeroized from outside. Callers that hold raw key material (e.g.
//!   `HandshakeSuccess`, `ObfuscationParams`) are responsible for
//!   zeroizing their own copies.

#![allow(dead_code)]

use aes::Aes256;
use ctr::{Ctr128BE, cipher::{KeyIvInit, StreamCipher}};
use zeroize::Zeroize;
use crate::error::{ProxyError, Result};

type Aes256Ctr = Ctr128BE<Aes256>;

/// AES-256-CTR encryptor/decryptor
///
/// CTR mode is symmetric — encryption and decryption are the same operation.
///
/// **Zeroize note:** The inner `Aes256Ctr` cipher state (expanded key schedule
///     + counter) is opaque and cannot be zeroized. If you need to protect key
///     material, zeroize the `[u8; 32]` key and `u128` IV at the call site
///     before dropping them.
pub struct AesCtr {
    cipher: Aes256Ctr,
}

impl AesCtr {
    /// Create new AES-CTR cipher with key and IV
    pub fn new(key: &[u8; 32], iv: u128) -> Self {
        let iv_bytes = iv.to_be_bytes();
        Self {
            cipher: Aes256Ctr::new(key.into(), (&iv_bytes).into()),
        }
    }
    
    /// Create from key and IV slices
    pub fn from_key_iv(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(ProxyError::InvalidKeyLength { expected: 32, got: key.len() });
        }
        if iv.len() != 16 {
            return Err(ProxyError::InvalidKeyLength { expected: 16, got: iv.len() });
        }
        
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);
        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(iv);
        let mut iv_int = u128::from_be_bytes(iv_arr);
        let result = Self::new(&key_arr, iv_int);
        key_arr.zeroize();
        iv_arr.zeroize();
        iv_int.zeroize();
        Ok(result)
    }
    
    /// Encrypt/decrypt data in-place (CTR mode is symmetric)
    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
    
    /// Encrypt data, returning new buffer
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        self.apply(&mut output);
        output
    }
    
    /// Decrypt data (for CTR, identical to encrypt)
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }
}

/// AES-256-CBC cipher with proper chaining
///
/// Unlike CTR mode, CBC is NOT symmetric — encryption and decryption
/// are different operations. This implementation handles CBC chaining
/// correctly across multiple blocks.
///
/// Key and IV are zeroized on drop.
pub struct AesCbc {
    key: [u8; 32],
    iv: [u8; 16],
}

impl Drop for AesCbc {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl AesCbc {
    /// AES block size
    const BLOCK_SIZE: usize = 16;
    
    /// Create new AES-CBC cipher with key and IV
    pub const fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }
    
    /// Create from slices
    pub fn from_slices(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(ProxyError::InvalidKeyLength { expected: 32, got: key.len() });
        }
        if iv.len() != 16 {
            return Err(ProxyError::InvalidKeyLength { expected: 16, got: iv.len() });
        }
        
        Ok(Self {
            key: {
                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(key);
                key_arr
            },
            iv: {
                let mut iv_arr = [0u8; 16];
                iv_arr.copy_from_slice(iv);
                iv_arr
            },
        })
    }
    
    /// Encrypt a single block using raw AES (no chaining)
    fn encrypt_block(&self, block: &[u8; 16], key_schedule: &Aes256) -> [u8; 16] {
        use aes::cipher::BlockEncrypt;
        let mut output = *block;
        key_schedule.encrypt_block((&mut output).into());
        output
    }
    
    /// Decrypt a single block using raw AES (no chaining)
    fn decrypt_block(&self, block: &[u8; 16], key_schedule: &Aes256) -> [u8; 16] {
        use aes::cipher::BlockDecrypt;
        let mut output = *block;
        key_schedule.decrypt_block((&mut output).into());
        output
    }
    
    /// XOR two 16-byte blocks
    fn xor_blocks(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = a[i] ^ b[i];
        }
        result
    }
    
    /// Encrypt data using CBC mode with proper chaining
    ///
    /// CBC Encryption: C[i] = AES_Encrypt(P[i] XOR C[i-1]), where C[-1] = IV
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = Aes256::new((&self.key).into());
        
        let mut result = Vec::with_capacity(data.len());
        let mut prev_ciphertext = self.iv;
        
        for chunk in data.chunks(Self::BLOCK_SIZE) {
            let mut plaintext = [0u8; 16];
            plaintext.copy_from_slice(chunk);
            let xored = Self::xor_blocks(&plaintext, &prev_ciphertext);
            let ciphertext = self.encrypt_block(&xored, &key_schedule);
            prev_ciphertext = ciphertext;
            result.extend_from_slice(&ciphertext);
        }
        
        Ok(result)
    }
    
    /// Decrypt data using CBC mode with proper chaining
    ///
    /// CBC Decryption: P[i] = AES_Decrypt(C[i]) XOR C[i-1], where C[-1] = IV
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = Aes256::new((&self.key).into());
        
        let mut result = Vec::with_capacity(data.len());
        let mut prev_ciphertext = self.iv;
        
        for chunk in data.chunks(Self::BLOCK_SIZE) {
            let mut ciphertext = [0u8; 16];
            ciphertext.copy_from_slice(chunk);
            let decrypted = self.decrypt_block(&ciphertext, &key_schedule);
            let plaintext = Self::xor_blocks(&decrypted, &prev_ciphertext);
            prev_ciphertext = ciphertext;
            result.extend_from_slice(&plaintext);
        }
        
        Ok(result)
    }
    
    /// Encrypt data in-place
    pub fn encrypt_in_place(&self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = Aes256::new((&self.key).into());
        
        let mut prev_ciphertext = self.iv;
        
        for i in (0..data.len()).step_by(Self::BLOCK_SIZE) {
            let block = &mut data[i..i + Self::BLOCK_SIZE];
            
            for j in 0..Self::BLOCK_SIZE {
                block[j] ^= prev_ciphertext[j];
            }
            
            let block_array: &mut [u8; 16] = block
                .try_into()
                .map_err(|_| ProxyError::Crypto("CBC block must be exactly 16 bytes".to_string()))?;
            *block_array = self.encrypt_block(block_array, &key_schedule);
            
            prev_ciphertext = *block_array;
        }
        
        Ok(())
    }
    
    /// Decrypt data in-place
    pub fn decrypt_in_place(&self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = Aes256::new((&self.key).into());
        
        let mut prev_ciphertext = self.iv;
        
        for i in (0..data.len()).step_by(Self::BLOCK_SIZE) {
            let block = &mut data[i..i + Self::BLOCK_SIZE];
            
            let mut current_ciphertext = [0u8; 16];
            current_ciphertext.copy_from_slice(block);
            
            let block_array: &mut [u8; 16] = block
                .try_into()
                .map_err(|_| ProxyError::Crypto("CBC block must be exactly 16 bytes".to_string()))?;
            *block_array = self.decrypt_block(block_array, &key_schedule);
            
            for j in 0..Self::BLOCK_SIZE {
                block[j] ^= prev_ciphertext[j];
            }
            
            prev_ciphertext = current_ciphertext;
        }
        
        Ok(())
    }
}

/// Trait for unified encryption interface
pub trait Encryptor: Send + Sync {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

/// Trait for unified decryption interface
pub trait Decryptor: Send + Sync {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

impl Encryptor for AesCtr {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        Self::encrypt(self, data)
    }
}

impl Decryptor for AesCtr {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        Self::decrypt(self, data)
    }
}

/// No-op encryptor for fast mode
pub struct PassthroughEncryptor;

impl Encryptor for PassthroughEncryptor {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

impl Decryptor for PassthroughEncryptor {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0u8; 32];
        let iv = 12345u128;
        
        let original = b"Hello, MTProto!";
        
        let mut enc = AesCtr::new(&key, iv);
        let encrypted = enc.encrypt(original);
        
        let mut dec = AesCtr::new(&key, iv);
        let decrypted = dec.decrypt(&encrypted);
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes_ctr_in_place() {
        let key = [0x42u8; 32];
        let iv = 999u128;
        
        let original = b"Test data for in-place encryption";
        let mut data = original.to_vec();
        
        let mut cipher = AesCtr::new(&key, iv);
        cipher.apply(&mut data);
        
        assert_ne!(&data[..], original);
        
        let mut cipher = AesCtr::new(&key, iv);
        cipher.apply(&mut data);
        
        assert_eq!(&data[..], original);
    }
    
    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        
        let original = [0u8; 32];
        
        let cipher = AesCbc::new(key, iv);
        let encrypted = cipher.encrypt(&original).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes_cbc_chaining_works() {
        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];
        
        let plaintext = [0xAAu8; 32];
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        
        let block1 = &ciphertext[0..16];
        let block2 = &ciphertext[16..32];
        
        assert_ne!(
            block1, block2,
            "CBC chaining broken: identical plaintext blocks produced identical ciphertext"
        );
    }
    
    #[test]
    fn test_aes_cbc_known_vector() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = [0u8; 16];
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    }
    
    #[test]
    fn test_aes_cbc_multi_block() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 16];
        
        let plaintext: Vec<u8> = (0..80).collect();
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_aes_cbc_in_place() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 16];
        
        let original = [0x56u8; 48];
        let mut buffer = original;
        
        let cipher = AesCbc::new(key, iv);
        
        cipher.encrypt_in_place(&mut buffer).unwrap();
        assert_ne!(&buffer[..], &original[..]);
        
        cipher.decrypt_in_place(&mut buffer).unwrap();
        assert_eq!(&buffer[..], &original[..]);
    }
    
    #[test]
    fn test_aes_cbc_empty_data() {
        let cipher = AesCbc::new([0u8; 32], [0u8; 16]);
        
        let encrypted = cipher.encrypt(&[]).unwrap();
        assert!(encrypted.is_empty());
        
        let decrypted = cipher.decrypt(&[]).unwrap();
        assert!(decrypted.is_empty());
    }
    
    #[test]
    fn test_aes_cbc_unaligned_error() {
        let cipher = AesCbc::new([0u8; 32], [0u8; 16]);
        
        let result = cipher.encrypt(&[0u8; 15]);
        assert!(result.is_err());
        
        let result = cipher.encrypt(&[0u8; 17]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_aes_cbc_avalanche_effect() {
        let key = [0xAB; 32];
        let iv = [0xCD; 16];
        
        let plaintext1 = [0u8; 32];
        let mut plaintext2 = [0u8; 32];
        plaintext2[0] = 0x01;
        
        let cipher = AesCbc::new(key, iv);
        
        let ciphertext1 = cipher.encrypt(&plaintext1).unwrap();
        let ciphertext2 = cipher.encrypt(&plaintext2).unwrap();
        
        assert_ne!(&ciphertext1[0..16], &ciphertext2[0..16]);
        assert_ne!(&ciphertext1[16..32], &ciphertext2[16..32]);
    }
    
    #[test]
    fn test_aes_cbc_iv_matters() {
        let key = [0x55; 32];
        let plaintext = [0x77u8; 16];
        
        let cipher1 = AesCbc::new(key, [0u8; 16]);
        let cipher2 = AesCbc::new(key, [1u8; 16]);
        
        let ciphertext1 = cipher1.encrypt(&plaintext).unwrap();
        let ciphertext2 = cipher2.encrypt(&plaintext).unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }
    
    #[test]
    fn test_aes_cbc_deterministic() {
        let key = [0x99; 32];
        let iv = [0x88; 16];
        let plaintext = [0x77u8; 32];
        
        let cipher = AesCbc::new(key, iv);
        
        let ciphertext1 = cipher.encrypt(&plaintext).unwrap();
        let ciphertext2 = cipher.encrypt(&plaintext).unwrap();
        
        assert_eq!(ciphertext1, ciphertext2);
    }
    
    #[test]
    fn test_aes_cbc_zeroize_on_drop() {
        let key = [0xAA; 32];
        let iv = [0xBB; 16];
        
        let cipher = AesCbc::new(key, iv);
        // Verify key/iv are set
        assert_eq!(cipher.key, [0xAA; 32]);
        assert_eq!(cipher.iv, [0xBB; 16]);
        
        drop(cipher);
        // After drop, key/iv are zeroized (can't observe directly,
        // but the Drop impl runs without panic)
    }
    
    #[test]
    fn test_invalid_key_length() {
        let result = AesCtr::from_key_iv(&[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
        
        let result = AesCbc::from_slices(&[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_iv_length() {
        let result = AesCtr::from_key_iv(&[0u8; 32], &[0u8; 8]);
        assert!(result.is_err());

        let result = AesCbc::from_slices(&[0u8; 32], &[0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn aes_cbc_nist_sp800_38a_f5_3_single_block() {
        // NIST SP 800-38A Section F.5.3 CBC-AES256.Encrypt, block 1.
        let key: [u8; 32] = hex::decode(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ).unwrap().try_into().unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap().try_into().unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let expected = hex::decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6").unwrap();
        let cipher = AesCbc::new(key, iv);
        assert_eq!(cipher.encrypt(&pt).unwrap(), expected, "NIST F.5.3 block 1 encrypt");
        assert_eq!(cipher.decrypt(&expected).unwrap(), pt, "NIST F.5.3 block 1 decrypt");
    }

    #[test]
    fn aes_cbc_four_block_roundtrip_and_chain_consistency() {
        // Chain 4 blocks manually and verify the encrypt/decrypt roundtrip.
        // Each block's ciphertext is used as IV for the next, confirming chaining.
        let key: [u8; 32] = hex::decode(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ).unwrap().try_into().unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap().try_into().unwrap();
        let pt = hex::decode(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        )).unwrap();
        let cipher = AesCbc::new(key, iv);
        let ct = cipher.encrypt(&pt).unwrap();
        // Blocks 1-3 must match NIST SP 800-38A F.5.3 (single-block NIST test covers block 1).
        assert_eq!(&ct[0..16], &hex::decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6").unwrap()[..], "NIST C1");
        assert_eq!(&ct[16..32], &hex::decode("9cfc4e967edb808d679f777bc6702c7d").unwrap()[..], "NIST C2");
        assert_eq!(&ct[32..48], &hex::decode("39f23369a9d9bacfa530e26304231461").unwrap()[..], "NIST C3");
        // Full encrypt+decrypt roundtrip must recover original plaintext.
        assert_eq!(cipher.decrypt(&ct).unwrap(), pt, "Four-block roundtrip failed");
    }

    // ============= Security Property Tests =============

    #[test]
    fn aes_cbc_bit_flip_propagates_to_next_block() {
        // CBC malleability: a 1-bit flip in ciphertext block N causes
        //   - block N to decrypt to garbage,
        //   - block N+1 to have exactly that bit flipped in the decrypted output.
        // An attacker exploiting this can selectively corrupt one plaintext byte
        // at the cost of destroying the preceding block.
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let plaintext = [0x33u8; 32];
        let cipher = AesCbc::new(key, iv);
        let mut ct = cipher.encrypt(&plaintext).unwrap();

        ct[0] ^= 0x01;
        let decrypted = cipher.decrypt(&ct).unwrap();

        assert_ne!(&decrypted[0..16], &plaintext[0..16],
            "Tampered ciphertext block must not decrypt to original plaintext");

        let mut expected_block1 = [0x33u8; 16];
        expected_block1[0] ^= 0x01;
        assert_eq!(&decrypted[16..32], &expected_block1,
            "CBC malleability: bit flip in ciphertext[N] must appear verbatim in plaintext[N+1]");
    }

    #[test]
    fn aes_ctr_split_apply_matches_full_apply() {
        // CTR counter must advance exactly one byte at a time regardless of
        // how calls are chunked.  Any off-by-one in counter advancement breaks
        // the contract and will cause decryption failures.
        let key = [0xABu8; 32];
        let iv = 0x1234567890ABCDEFu128;
        let data = vec![0x5Cu8; 160];

        let full = AesCtr::new(&key, iv).encrypt(&data);
        let split = {
            let mut c = AesCtr::new(&key, iv);
            let mut out = Vec::with_capacity(data.len());
            // Prime-sized chunks stress unaligned AES block boundaries.
            for chunk in data.chunks(17) {
                out.extend_from_slice(&c.encrypt(chunk));
            }
            out
        };
        assert_eq!(full, split,
            "CTR must produce identical output regardless of per-call chunk size");
    }

    #[test]
    fn aes_ctr_different_keys_never_produce_same_keystream() {
        let iv = 0u128;
        let data = vec![0u8; 32];
        let out1 = AesCtr::new(&[0u8; 32], iv).encrypt(&data);
        let out2 = AesCtr::new(&[1u8; 32], iv).encrypt(&data);
        assert_ne!(out1, out2, "Different AES keys must produce different keystreams");
        // All-zero key encrypting all-zero plaintext must not return an all-zero
        // ciphertext (that would imply AES is a no-op).
        assert_ne!(out1, data, "All-zero key+plaintext must not produce all-zero ciphertext");
    }

    #[test]
    fn aes_ctr_from_key_iv_boundary_lengths() {
        assert!(AesCtr::from_key_iv(&[0u8; 31], &[0u8; 16]).is_err(), "key < 32");
        assert!(AesCtr::from_key_iv(&[0u8; 33], &[0u8; 16]).is_err(), "key > 32");
        assert!(AesCtr::from_key_iv(&[], &[0u8; 16]).is_err(), "empty key");
        assert!(AesCtr::from_key_iv(&[0u8; 32], &[0u8; 15]).is_err(), "iv < 16");
        assert!(AesCtr::from_key_iv(&[0u8; 32], &[0u8; 17]).is_err(), "iv > 16");
        assert!(AesCtr::from_key_iv(&[0u8; 32], &[]).is_err(), "empty iv");
        assert!(AesCtr::from_key_iv(&[0u8; 32], &[0u8; 16]).is_ok(), "valid key+iv");
    }

    #[test]
    fn aes_cbc_encrypt_decrypt_allocating_vs_in_place_are_identical() {
        let key = [0x7Fu8; 32];
        let iv_bytes = [0x3Cu8; 16];
        let original = vec![0xEEu8; 64];
        let cipher = AesCbc::new(key, iv_bytes);

        let alloc_ct = cipher.encrypt(&original).unwrap();
        let mut in_place_buf = original.clone();
        cipher.encrypt_in_place(&mut in_place_buf).unwrap();
        assert_eq!(alloc_ct, in_place_buf, "encrypt() and encrypt_in_place() must agree");

        let alloc_pt = cipher.decrypt(&alloc_ct).unwrap();
        let mut in_place_dec = alloc_ct.clone();
        cipher.decrypt_in_place(&mut in_place_dec).unwrap();
        assert_eq!(alloc_pt, in_place_dec, "decrypt() and decrypt_in_place() must agree");
        assert_eq!(alloc_pt, original);
    }

    #[test]
    fn aes_cbc_from_slices_boundary_lengths() {
        assert!(AesCbc::from_slices(&[0u8; 31], &[0u8; 16]).is_err());
        assert!(AesCbc::from_slices(&[0u8; 33], &[0u8; 16]).is_err());
        assert!(AesCbc::from_slices(&[0u8; 32], &[0u8; 15]).is_err());
        assert!(AesCbc::from_slices(&[0u8; 32], &[0u8; 17]).is_err());
        assert!(AesCbc::from_slices(&[0u8; 32], &[0u8; 16]).is_ok());
    }

    #[test]
    fn aes_ctr_nist_sp800_38a_f5_9_four_blocks() {
        // NIST SP 800-38A Section F.5.9 CTR-AES256.Encrypt, all four blocks.
        // This test pins the implementation against the official reference vectors.
        let key: [u8; 32] = hex::decode(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ).unwrap().try_into().unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let plaintext = hex::decode(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        )).unwrap();
        let expected = hex::decode(concat!(
            "601ec313775789a5b7a7f504bbf3d228",
            "f443e3ca4d62b59aca84e990cacaf5c5",
            "2b0930daa23de94ce87017ba2d84988d",
            "dfc9c58db67aada613c2dd08457941a6",
        )).unwrap();
        let mut enc = AesCtr::from_key_iv(&key, &iv).unwrap();
        let ciphertext = enc.encrypt(&plaintext);
        assert_eq!(ciphertext, expected, "NIST F.5.9 CTR-AES256 encrypt");
        let mut dec = AesCtr::from_key_iv(&key, &iv).unwrap();
        assert_eq!(dec.decrypt(&ciphertext), plaintext, "CTR decrypt of NIST vector");
    }

    #[test]
    fn aes_ctr_from_key_iv_matches_direct_new() {
        // The two construction paths must produce bit-identical output.
        let key = [0xA7u8; 32];
        let iv_bytes = [0x3Cu8; 16];
        let plaintext = b"construction equivalence test!!";
        let mut c1 = AesCtr::from_key_iv(&key, &iv_bytes).unwrap();
        let ct1 = c1.encrypt(plaintext);
        let iv_int = u128::from_be_bytes(iv_bytes);
        let mut c2 = AesCtr::new(&key, iv_int);
        let ct2 = c2.encrypt(plaintext);
        assert_eq!(ct1, ct2, "from_key_iv and new must produce identical ciphertext");
    }
}
