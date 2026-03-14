//! Pseudorandom

#![allow(dead_code)]

// rand 0.9 deprecated Rng::gen_range and Rng::gen in favour of Rng::random_range
// and Rng::random. Those call sites are no longer present in this module;
// the attribute is kept only to silence any residual deprecation noise from
// transitional rand 0.9 APIs used inside macro expansions.
#![allow(deprecated)]

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use parking_lot::Mutex;
use zeroize::Zeroize;
use crate::crypto::AesCtr;

/// Cryptographically secure PRNG with AES-CTR
pub struct SecureRandom {
    inner: Mutex<SecureRandomInner>,
}

struct SecureRandomInner {
    rng: StdRng,
    cipher: AesCtr,
    buffer: Vec<u8>,
    buffer_start: usize,
}

impl Drop for SecureRandomInner {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl SecureRandom {
    pub fn new() -> Self {
        let mut seed_source = rand::rng();
        let rng = StdRng::from_rng(&mut seed_source);
        
        // AES-CTR key and IV are drawn from an independent OS-entropy call, not from
        // the StdRng that produces output bytes.  A dedicated key_rng is seeded
        // directly from the OS (independent entropy source) so that recovering the
        // output `rng`'s state reveals nothing about the AES-CTR whitening key.
        // key_rng is used only during construction and dropped immediately.
        let mut key_rng = StdRng::from_os_rng();
        let mut key = [0u8; 32];
        key_rng.fill_bytes(&mut key);
        let mut iv_bytes = [0u8; 16];
        key_rng.fill_bytes(&mut iv_bytes);
        let iv = u128::from_be_bytes(iv_bytes);
        iv_bytes.zeroize();

        let cipher = AesCtr::new(&key, iv);

        // Zeroize local key copy — cipher already consumed it.
        key.zeroize();
        
        Self {
            inner: Mutex::new(SecureRandomInner {
                rng,
                cipher,
                buffer: Vec::with_capacity(1024),
                buffer_start: 0,
            }),
        }
    }
    
    /// Fill a caller-provided buffer with random bytes.
    pub fn fill(&self, out: &mut [u8]) {
        let mut inner = self.inner.lock();
        const CHUNK_SIZE: usize = 512;

        let mut written = 0usize;
        while written < out.len() {
            if inner.buffer_start >= inner.buffer.len() {
                inner.buffer.clear();
                inner.buffer_start = 0;
            }

            if inner.buffer.is_empty() {
                let mut chunk = vec![0u8; CHUNK_SIZE];
                inner.rng.fill_bytes(&mut chunk);
                inner.cipher.apply(&mut chunk);
                inner.buffer.extend_from_slice(&chunk);
                inner.buffer_start = 0;
                chunk.zeroize();
            }

            let available = inner.buffer.len().saturating_sub(inner.buffer_start);
            let take = (out.len() - written).min(available);
            let start = inner.buffer_start;
            let end = start + take;
            out[written..written + take].copy_from_slice(&inner.buffer[start..end]);
            // Zeroize consumed bytes immediately for forward secrecy.
            inner.buffer[start..end].zeroize();
            inner.buffer_start = end;
            if inner.buffer_start >= inner.buffer.len() {
                inner.buffer.clear();
                inner.buffer_start = 0;
            }
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
        if max <= 1 {
            return 0;
        }
        // Rejection sampling for unbiased [0, max) over the AES-CTR-whitened path.
        // Discards values in the biased tail where 2^64 mod max != 0.
        let max64 = max as u64;
        let threshold = u64::MAX - (u64::MAX % max64);
        loop {
            let mut buf = [0u8; 8];
            self.fill(&mut buf);
            let r = u64::from_le_bytes(buf);
            if r < threshold {
                return (r % max64) as usize;
            }
        }
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
            result |= u64::from(b) << (i * 8);
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
        // Fisher-Yates shuffle using the AES-CTR-whitened range() for index selection.
        for i in (1..slice.len()).rev() {
            let j = self.range(i + 1);
            slice.swap(i, j);
        }
    }
    
    /// Generate random u32
    pub fn u32(&self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Generate random u64
    pub fn u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        u64::from_le_bytes(buf)
    }
}

#[cfg(test)]
impl SecureRandom {
    // Test-only constructor that accepts explicit RNG and AES-CTR components.
    // Used to verify that the AES-CTR key is effective and independent of the
    // StdRng stream: two instances built with the same StdRng seed but different
    // keys must produce different output.
    fn new_with_components(rng: StdRng, key: [u8; 32], iv: u128) -> Self {
        let cipher = AesCtr::new(&key, iv);
        Self {
            inner: Mutex::new(SecureRandomInner {
                rng,
                cipher,
                buffer: Vec::with_capacity(1024),
                buffer_start: 0,
            }),
        }
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

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn test_secure_random_auto_traits() {
        assert_send_sync::<SecureRandom>();
    }
    
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

    #[test]
    fn fill_never_all_zeros_for_large_output() {
        // 512 bytes of CSPRNG output must never be all zeros.
        // Probability is ~1/2^4096 — effectively impossible for a functioning RNG.
        let rng = SecureRandom::new();
        let out = rng.bytes(512);
        assert!(!out.iter().all(|&b| b == 0),
            "CSPRNG must not emit 512 consecutive zero bytes");
    }

    #[test]
    fn fill_large_buffer_exercises_multiple_buffer_refills() {
        // Request 4*CHUNK_SIZE+7 bytes to force at least 4 internal refill cycles.
        // Ensures the refill path and buffer_start bookkeeping are correct under load.
        let rng = SecureRandom::new();
        let out = rng.bytes(512 * 4 + 7);
        assert_eq!(out.len(), 512 * 4 + 7);
        assert!(!out.iter().all(|&b| b == 0),
            "Multi-refill output must not be all-zero");
    }

    #[test]
    fn fill_empty_is_noop() {
        let rng = SecureRandom::new();
        let mut buf: [u8; 0] = [];
        rng.fill(&mut buf); // must not panic or touch memory
    }

    #[test]
    fn bits_boundary_cases() {
        let rng = SecureRandom::new();
        assert_eq!(rng.bits(0), 0, "bits(0) must return 0");
        for _ in 0..100 {
            assert!(rng.bits(1) <= 1, "bits(1) must be 0 or 1");
        }
        for _ in 0..100 {
            assert!(rng.bits(63) < (1u64 << 63), "bits(63) must fit in 63 bits");
        }
        // bits(64) covers the full u64 range; any value is valid, must not panic.
        let _ = rng.bits(64);
    }

    #[test]
    fn shuffle_single_element_unchanged() {
        let rng = SecureRandom::new();
        let mut single = vec![42u64];
        rng.shuffle(&mut single);
        assert_eq!(single, [42u64], "Single-element shuffle must preserve the value");
    }

    #[test]
    fn shuffle_empty_slice_no_panic() {
        let rng = SecureRandom::new();
        let mut empty: Vec<u8> = Vec::new();
        rng.shuffle(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn range_distribution_all_buckets_populated() {
        // 10 000 draws in [0, 10): each bucket must hit at least 500.
        // Expected count per bucket = 1000; threshold 500 catches dead/biased generators
        // while being beyond the range of normal statistical variance.
        let rng = SecureRandom::new();
        let mut counts = [0usize; 10];
        for _ in 0..10_000 {
            let v = rng.range(10);
            assert!(v < 10, "range(10) must return a value strictly less than 10");
            counts[v] += 1;
        }
        for (bucket, &count) in counts.iter().enumerate() {
            assert!(count > 500,
                "Bucket {bucket} has {count}/10000 hits — possible RNG bias or constant output");
        }
    }

    #[test]
    fn concurrent_fill_is_thread_safe() {
        // Eight threads each making 100 fill calls must produce no panics,
        // data races, or incorrect output lengths.
        use std::{sync::Arc, thread};
        let rng = Arc::new(SecureRandom::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let r = Arc::clone(&rng);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let b = r.bytes(64);
                        assert_eq!(b.len(), 64,
                            "fill must return exactly the requested byte count");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("Thread panicked during concurrent fill");
        }
    }

    #[test]
    fn range_uniform_over_non_power_of_two_max() {
        // 7 is neither a power of two nor a factor of 2^64, making it the canonical
        // modulo-bias test. Each bucket must receive at least 1000/7 ≈ 1428 hits.
        // Threshold 1000 is well below the 1/7 expected rate and catches a dead
        // bucket or catastrophic bias without being flaky.
        let rng = SecureRandom::new();
        let mut counts = [0usize; 7];
        for _ in 0..20_000 {
            let v = rng.range(7);
            assert!(v < 7, "range(7) must be in [0, 7)");
            counts[v] += 1;
        }
        for (bucket, &count) in counts.iter().enumerate() {
            assert!(count > 1000,
                "Bucket {bucket} has {count}/20000 hits — rejection-sampling may be biased");
        }
    }

    #[test]
    fn u64_output_is_not_constant() {
        // Two consecutive u64() calls on a functioning CSPRNG must differ.
        // Probability of collision is 2^-64 — impossible in practice.
        let rng = SecureRandom::new();
        let a = rng.u64();
        let b = rng.u64();
        assert_ne!(a, b, "Two consecutive u64() outputs must differ");
    }

    #[test]
    fn u32_output_is_not_constant() {
        let rng = SecureRandom::new();
        let a = rng.u32();
        let b = rng.u32();
        assert_ne!(a, b, "Two consecutive u32() outputs must differ");
    }

    #[test]
    fn range_zero_and_one_are_special_cases() {
        let rng = SecureRandom::new();
        assert_eq!(rng.range(0), 0, "range(0) must return 0");
        assert_eq!(rng.range(1), 0, "range(1) must return 0 — only element is 0");
        for _ in 0..50 {
            assert_eq!(rng.range(1), 0, "range(1) must always return 0");
        }
    }

    #[test]
    fn fill_then_range_do_not_corrupt_each_other() {
        // Fill and range both acquire the same internal lock.  Interleaving them
        // must never corrupt the buffer accounting or produce out-of-bounds values.
        let rng = SecureRandom::new();
        let mut buf = [0u8; 100];
        for _ in 0..200 {
            rng.fill(&mut buf);
            let v = rng.range(256);
            assert!(v < 256, "range(256) must be in [0, 256)");
        }
    }

    // ============= OsRng key-independence regression tests =============

    #[test]
    fn aes_ctr_key_affects_output_independently_of_rng_seed() {
        // Regression test for the forward-secrecy fix.  Identical StdRng seeds
        // combined with *different* AES-CTR keys must yield completely different
        // outputs.  Under the old (broken) design the key was derived from the
        // same StdRng, so identical seeds produced identical keys; this test
        // would have passed trivially and caught no regression.  Under the correct
        // design the key comes from OsRng; injecting identical StdRng seeds with
        // explicitly different keys still produces non-identical output, proving
        // the AES layer is exercised and independent.
        use rand::SeedableRng;
        let seed = [0xABu8; 32];
        let rng1 = StdRng::from_seed(seed);
        let rng2 = StdRng::from_seed(seed);

        let sr1 = SecureRandom::new_with_components(rng1, [0x11u8; 32], 0xDEAD_BEEF_u128);
        let sr2 = SecureRandom::new_with_components(rng2, [0x22u8; 32], 0xDEAD_BEEF_u128);

        assert_ne!(
            sr1.bytes(512),
            sr2.bytes(512),
            "Different AES keys must produce different output even with identical StdRng seeds",
        );
    }

    #[test]
    fn aes_ctr_same_key_same_seed_produces_identical_output() {
        // Determinism check: identical (rng_seed, aes_key, iv) must yield bit-for-bit
        // identical output.  Failure here indicates non-deterministic state in the path.
        use rand::SeedableRng;
        let seed = [0x77u8; 32];
        let key  = [0x55u8; 32];
        let iv   = 0x1234_5678_u128;

        let sr1 = SecureRandom::new_with_components(StdRng::from_seed(seed), key, iv);
        let sr2 = SecureRandom::new_with_components(StdRng::from_seed(seed), key, iv);

        assert_eq!(
            sr1.bytes(512),
            sr2.bytes(512),
            "Identical seed+key+iv must produce identical output (determinism)",
        );
    }

    #[test]
    fn aes_key_change_alters_every_output_block() {
        // A 1-byte difference in the AES key must change every output byte block.
        // If the AES layer were a no-op the output would be identical.
        use rand::SeedableRng;
        let seed = [0xCCu8; 32];
        let mut key_b = [0x11u8; 32];
        key_b[0] ^= 0xFF;

        let sr_a = SecureRandom::new_with_components(StdRng::from_seed(seed), [0x11u8; 32], 0);
        let sr_b = SecureRandom::new_with_components(StdRng::from_seed(seed), key_b, 0);

        let out_a = sr_a.bytes(512);
        let out_b = sr_b.bytes(512);
        assert_ne!(out_a, out_b, "1-byte AES key difference must change output");
    }

    #[test]
    fn aes_iv_change_alters_output() {
        // Changing only the IV while keeping the key and RNG seed identical must
        // produce different output, confirming IV is not ignored.
        use rand::SeedableRng;
        let seed = [0xDDu8; 32];
        let key  = [0xAAu8; 32];

        let sr1 = SecureRandom::new_with_components(StdRng::from_seed(seed), key, 0);
        let sr2 = SecureRandom::new_with_components(StdRng::from_seed(seed), key, 1);

        assert_ne!(
            sr1.bytes(64),
            sr2.bytes(64),
            "Different IV must produce different output",
        );
    }

    // ============= Statistical and structural output tests =============

    #[test]
    fn two_instances_produce_independent_streams() {
        // Two independently-constructed SecureRandom instances must not share an
        // output stream.  Since each uses an OsRng-derived AES key, this holds
        // with probability 1 − 2^−256 per 512-byte comparison.
        let rng1 = SecureRandom::new();
        let rng2 = SecureRandom::new();
        assert_ne!(
            rng1.bytes(512),
            rng2.bytes(512),
            "Two separately-constructed SecureRandom instances must produce independent streams",
        );
    }

    #[test]
    fn fill_chunk_boundary_sizes_return_correct_length() {
        // Sizes straddling the internal CHUNK_SIZE (512) boundary stress the
        // buffer refill bookkeeping.  Each request must return exactly the right
        // number of bytes without panicking or truncating.
        let rng = SecureRandom::new();
        for &size in &[1usize, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096] {
            let out = rng.bytes(size);
            assert_eq!(out.len(), size, "fill({size}) must return exactly {size} bytes");
            if size >= 16 {
                assert!(
                    !out.iter().all(|&b| b == 0),
                    "fill({size}) must not produce all-zero output",
                );
            }
        }
    }

    #[test]
    fn byte_frequency_distribution_is_not_degenerate() {
        // 65 536 bytes / 256 values = 256 expected per bucket.
        // Threshold 64 (25 % of expected) catches any dead byte value or
        // catastrophic bias while tolerating normal statistical variance.
        let rng = SecureRandom::new();
        let out = rng.bytes(65_536);
        let mut freq = [0usize; 256];
        for &b in &out {
            freq[b as usize] += 1;
        }
        for (value, &count) in freq.iter().enumerate() {
            assert!(
                count >= 64,
                "Byte 0x{value:02x} appeared {count}/65536 times; \
                 possible bias or broken cipher",
            );
        }
    }

    #[test]
    fn no_repeating_adjacent_16_byte_blocks_in_large_output() {
        // A degenerate AES-CTR operating in ECB mode, or a broken keystream, would
        // produce repeating 16-byte blocks.  Scan 32 kB for adjacent equal blocks.
        let rng = SecureRandom::new();
        let out = rng.bytes(32 * 1024);
        let blocks: Vec<&[u8]> = out.chunks_exact(16).collect();
        for window in blocks.windows(2) {
            assert_ne!(
                window[0],
                window[1],
                "Consecutive equal 16-byte blocks detected; \
                 possible ECB mode regression or broken cipher",
            );
        }
    }

    #[test]
    fn range_usize_max_terminates_without_panic() {
        // range(usize::MAX) exercises the rejection-sampling edge case where
        // max64 == u64::MAX.  Must terminate and return a value in [0, usize::MAX).
        let rng = SecureRandom::new();
        let v = rng.range(usize::MAX);
        assert!(v < usize::MAX, "range(usize::MAX) must return a value < usize::MAX");
    }

    #[test]
    fn high_concurrency_stress_no_deadlock_or_corruption() {
        // 16 threads × 2 000 fill calls of varying sizes must complete without
        // deadlock, panic, or incorrect output lengths.  Variable sizes hit every
        // buffer-refill boundary inside the lock.
        use std::{sync::Arc, thread};
        let rng = Arc::new(SecureRandom::new());
        let handles: Vec<_> = (0..16u8)
            .map(|i| {
                let r = Arc::clone(&rng);
                thread::spawn(move || {
                    for j in 0..2_000usize {
                        let size = (usize::from(i) * 37 + j * 13 + 1) % 1025;
                        let b = r.bytes(size);
                        assert_eq!(
                            b.len(),
                            size,
                            "concurrent fill must return the exact requested byte count",
                        );
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("Thread panicked during high-concurrency stress");
        }
    }

    #[test]
    fn shuffle_covers_all_120_permutations_of_5_element_slice() {
        // 5! = 120 permutations.  After 10 000 shuffles, every permutation must
        // appear at least once.  A biased or broken shuffle cannot reach all 120;
        // e.g. a shuffle stuck at index 0 would only produce one permutation.
        let rng = SecureRandom::new();
        let base = [1u8, 2, 3, 4, 5];
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let mut s = base;
            rng.shuffle(&mut s);
            seen.insert(s);
        }
        assert_eq!(
            seen.len(),
            120,
            "shuffle must reach all 120 permutations of a 5-element slice; \
             got {} — possible bias or broken Fisher-Yates",
            seen.len(),
        );
    }

    #[test]
    fn choose_is_uniformly_distributed() {
        // 40 000 draws over 4 items: each must appear at least 8 000 times
        // (expected 10 000; threshold 80 % of expected catches dead elements).
        let rng = SecureRandom::new();
        let items = [11u8, 22, 33, 44];
        let mut counts = [0usize; 4];
        for _ in 0..40_000 {
            if let Some(&v) = rng.choose(&items) {
                let idx = items.iter().position(|&x| x == v).unwrap();
                counts[idx] += 1;
            }
        }
        for (i, &c) in counts.iter().enumerate() {
            assert!(
                c > 8_000,
                "choose(): element at index {i} appeared {c}/40000 times; expected ~10000",
            );
        }
    }

    #[test]
    fn sequential_interleaved_api_calls_stay_in_range() {
        // Interleave every public method across 5 000 iterations.  Mixed call
        // patterns must not corrupt buffer accounting or produce out-of-bounds values.
        let rng = SecureRandom::new();
        for i in 0..5_000usize {
            let size = (i % 150) + 1;
            let bytes = rng.bytes(size);
            assert_eq!(bytes.len(), size);

            let r = rng.range(100);
            assert!(r < 100, "range(100) out of bounds: {r}");

            let bit_width = (i % 63) + 1;
            let b = rng.bits(bit_width);
            if bit_width < 64 {
                assert!(
                    b < (1u64 << bit_width),
                    "bits({bit_width}) returned {b}, exceeds mask",
                );
            }

            let _ = rng.u32();
            let _ = rng.u64();
        }
    }
}
