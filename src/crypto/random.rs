//! Pseudorandom

#![allow(deprecated)]
#![allow(dead_code)]

use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;
use parking_lot::Mutex;
use zeroize::Zeroize;
use crate::crypto::AesCtr;

/// Cryptographically secure PRNG with AES-CTR
pub struct SecureRandom {
    inner: Mutex<SecureRandomInner>,
}

unsafe impl Send for SecureRandom {}
unsafe impl Sync for SecureRandom {}

struct SecureRandomInner {
    rng: StdRng,
    cipher: AesCtr,
    buffer: Vec<u8>,
}

impl Drop for SecureRandomInner {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl SecureRandom {
    pub fn new() -> Self {
        let mut seed_source = rand::rng();
        let mut rng = StdRng::from_rng(&mut seed_source);
        
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let iv: u128 = rng.random();
        
        let cipher = AesCtr::new(&key, iv);
        
        // Zeroize local key copy — cipher already consumed it
        key.zeroize();
        
        Self {
            inner: Mutex::new(SecureRandomInner {
                rng,
                cipher,
                buffer: Vec::with_capacity(1024),
            }),
        }
    }
    
    /// Fill a caller-provided buffer with random bytes.
    pub fn fill(&self, out: &mut [u8]) {
        let mut inner = self.inner.lock();
        const CHUNK_SIZE: usize = 512;

        let mut written = 0usize;
        while written < out.len() {
            if inner.buffer.is_empty() {
                let mut chunk = vec![0u8; CHUNK_SIZE];
                inner.rng.fill_bytes(&mut chunk);
                inner.cipher.apply(&mut chunk);
                inner.buffer.extend_from_slice(&chunk);
            }

            let take = (out.len() - written).min(inner.buffer.len());
            out[written..written + take].copy_from_slice(&inner.buffer[..take]);
            inner.buffer.drain(..take);
            written += take;
        }
    }

    /// Generate random bytes
    pub fn bytes(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }
    
    /// Generate random number in range [0, max)
    pub fn range(&self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        let mut inner = self.inner.lock();
        inner.rng.gen_range(0..max)
    }
    
    /// Generate random bits
    pub fn bits(&self, k: usize) -> u64 {
        if k == 0 {
            return 0;
        }
        
        let bytes_needed = k.div_ceil(8);
        let bytes = self.bytes(bytes_needed.min(8));
        
        let mut result = 0u64;
        for (i, &b) in bytes.iter().enumerate() {
            if i >= 8 {
                break;
            }
            result |= (b as u64) << (i * 8);
        }
        
        if k < 64 {
            result &= (1u64 << k) - 1;
        }
        
        result
    }
    
    /// Choose random element from slice
    pub fn choose<'a, T>(&self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            Some(&slice[self.range(slice.len())])
        }
    }
    
    /// Shuffle slice in place
    pub fn shuffle<T>(&self, slice: &mut [T]) {
        let mut inner = self.inner.lock();
        for i in (1..slice.len()).rev() {
            let j = inner.rng.gen_range(0..=i);
            slice.swap(i, j);
        }
    }
    
    /// Generate random u32
    pub fn u32(&self) -> u32 {
        let mut inner = self.inner.lock();
        inner.rng.random()
    }
    
    /// Generate random u64
    pub fn u64(&self) -> u64 {
        let mut inner = self.inner.lock();
        inner.rng.random()
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    
    #[test]
    fn test_bytes_uniqueness() {
        let rng = SecureRandom::new();
        let a = rng.bytes(32);
        let b = rng.bytes(32);
        assert_ne!(a, b);
    }
    
    #[test]
    fn test_bytes_length() {
        let rng = SecureRandom::new();
        assert_eq!(rng.bytes(0).len(), 0);
        assert_eq!(rng.bytes(1).len(), 1);
        assert_eq!(rng.bytes(100).len(), 100);
        assert_eq!(rng.bytes(1000).len(), 1000);
    }
    
    #[test]
    fn test_range() {
        let rng = SecureRandom::new();
        
        for _ in 0..1000 {
            let n = rng.range(10);
            assert!(n < 10);
        }
        
        assert_eq!(rng.range(1), 0);
        assert_eq!(rng.range(0), 0);
    }
    
    #[test]
    fn test_bits() {
        let rng = SecureRandom::new();
        
        for _ in 0..100 {
            assert!(rng.bits(1) <= 1);
        }
        
        for _ in 0..100 {
            assert!(rng.bits(8) <= 255);
        }
    }
    
    #[test]
    fn test_choose() {
        let rng = SecureRandom::new();
        let items = vec![1, 2, 3, 4, 5];
        
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            if let Some(&item) = rng.choose(&items) {
                seen.insert(item);
            }
        }
        
        assert_eq!(seen.len(), 5);
        
        let empty: Vec<i32> = vec![];
        assert!(rng.choose(&empty).is_none());
    }
    
    #[test]
    fn test_shuffle() {
        let rng = SecureRandom::new();
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        
        let mut shuffled = original.clone();
        rng.shuffle(&mut shuffled);
        
        let mut sorted = shuffled.clone();
        sorted.sort();
        assert_eq!(sorted, original);
        
        assert_ne!(shuffled, original);
    }
}
