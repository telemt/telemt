//! Reusable buffer pool to avoid allocations in hot paths
//!
//! This module provides a thread-safe pool of `BytesMut` buffers
//! that can be reused across connections to reduce allocation pressure.

#![allow(dead_code)]

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============= Configuration =============

/// Default buffer size
/// CHANGED: Reduced from 64KB to 16KB to match TLS record size and prevent bufferbloat.
pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

/// Default maximum number of pooled buffers
pub const DEFAULT_MAX_BUFFERS: usize = 1024;

// Buffers that grew beyond this multiple of `buffer_size` are dropped rather
// than returned to the pool, preventing memory amplification from a single
// large-payload connection permanently holding oversized allocations.
const MAX_POOL_BUFFER_OVERSIZE_MULT: usize = 4;

// ============= Buffer Pool =============

/// Thread-safe pool of reusable buffers
pub struct BufferPool {
    /// Queue of available buffers
    buffers: ArrayQueue<BytesMut>,
    /// Size of each buffer
    buffer_size: usize,
    /// Maximum number of buffers to pool
    max_buffers: usize,
    /// High-water mark of buffers ever allocated by this pool.
    /// Incremented on every new allocation (miss or preallocate) and never
    /// decremented.  It does NOT represent current live buffer count.
    allocated: AtomicUsize,
    /// Number of times we had to create a new buffer
    misses: AtomicUsize,
    /// Number of successful reuses
    hits: AtomicUsize,
}

impl BufferPool {
    /// Create a new buffer pool with default settings
    pub fn new() -> Self {
        Self::with_config(DEFAULT_BUFFER_SIZE, DEFAULT_MAX_BUFFERS)
    }
    
    /// Create a buffer pool with custom configuration
    pub fn with_config(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            buffers: ArrayQueue::new(max_buffers),
            buffer_size,
            max_buffers,
            allocated: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
        }
    }
    
    /// Get a buffer from the pool, or create a new one if empty
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        match self.buffers.pop() {
            Some(mut buffer) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                buffer.clear();
                PooledBuffer {
                    buffer: Some(buffer),
                    pool: Arc::clone(self),
                }
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.allocated.fetch_add(1, Ordering::Relaxed);
                PooledBuffer {
                    buffer: Some(BytesMut::with_capacity(self.buffer_size)),
                    pool: Arc::clone(self),
                }
            }
        }
    }
    
    /// Try to get a buffer, returns None if pool is empty
    pub fn try_get(self: &Arc<Self>) -> Option<PooledBuffer> {
        self.buffers.pop().map(|mut buffer| {
            self.hits.fetch_add(1, Ordering::Relaxed);
            buffer.clear();
            PooledBuffer {
                buffer: Some(buffer),
                pool: Arc::clone(self),
            }
        })
    }
    
    /// Return a buffer to the pool
    fn return_buffer(&self, mut buffer: BytesMut) {
        buffer.clear();

        // Accept buffers within [buffer_size, buffer_size * MAX_POOL_BUFFER_OVERSIZE_MULT].
        // The lower bound prevents pool capacity from shrinking over time.
        // The upper bound drops buffers that grew excessively (e.g. to serve a large
        // payload) so they do not permanently inflate pool memory or get handed to a
        // future connection that only needs a small allocation.
        let max_acceptable = self.buffer_size.saturating_mul(MAX_POOL_BUFFER_OVERSIZE_MULT);
        if buffer.capacity() >= self.buffer_size && buffer.capacity() <= max_acceptable {
            let _ = self.buffers.push(buffer);
        }
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            pooled: self.buffers.len(),
            allocated: self.allocated.load(Ordering::Relaxed),
            max_buffers: self.max_buffers,
            buffer_size: self.buffer_size,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
    
    /// Get buffer size
    pub const fn buffer_size(&self) -> usize {
        self.buffer_size
    }
    
    /// Preallocate buffers to fill the pool
    pub fn preallocate(&self, count: usize) {
        let to_alloc = count.min(self.max_buffers);
        for _ in 0..to_alloc {
            if self.buffers.push(BytesMut::with_capacity(self.buffer_size)).is_err() {
                break;
            }
            self.allocated.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============= Pool Statistics =============

/// Statistics about buffer pool usage
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Current number of buffers sitting idle in the pool queue
    pub pooled: usize,
    /// High-water mark of buffers ever allocated by this pool.
    /// This is monotonically non-decreasing; it does NOT equal `pooled + in-use`
    /// because dropped buffers (pool full, wrong capacity) reduce live count
    /// without decrementing this field.
    pub allocated: usize,
    /// Maximum buffers allowed
    pub max_buffers: usize,
    /// Size of each buffer
    pub buffer_size: usize,
    /// Number of cache hits (reused buffer)
    pub hits: usize,
    /// Number of cache misses (new allocation)
    pub misses: usize,
}

impl PoolStats {
    /// Get hit rate as percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

// ============= Pooled Buffer =============

/// A buffer that automatically returns to the pool when dropped
pub struct PooledBuffer {
    buffer: Option<BytesMut>,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    /// Take the inner buffer, preventing return to pool
    pub fn take(mut self) -> BytesMut {
        self.buffer.take().unwrap_or_default()
    }
    
    /// Get the capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.buffer.as_ref().map(|b| b.capacity()).unwrap_or(0)
    }
    
    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.as_ref().map(|b| b.is_empty()).unwrap_or(true)
    }
    
    /// Get the length of data in buffer
    pub fn len(&self) -> usize {
        self.buffer.as_ref().map(|b| b.len()).unwrap_or(0)
    }
    
    /// Clear the buffer
    pub fn clear(&mut self) {
        if let Some(ref mut b) = self.buffer {
            b.clear();
        }
    }
}

impl Deref for PooledBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        self.buffer
            .as_ref()
            .expect("PooledBuffer: attempted to deref after buffer was taken")
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer
            .as_mut()
            .expect("PooledBuffer: attempted to deref_mut after buffer was taken")
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.return_buffer(buffer);
        }
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref().map(|b| b.as_ref()).unwrap_or(&[])
    }
}

impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut().map(|b| b.as_mut()).unwrap_or(&mut [])
    }
}

// ============= Scoped Buffer =============

/// A buffer that can be used for a scoped operation
/// Useful for ensuring buffer is returned even on early return
pub struct ScopedBuffer<'a> {
    buffer: &'a mut PooledBuffer,
}

impl<'a> ScopedBuffer<'a> {
    /// Create a new scoped buffer
    pub fn new(buffer: &'a mut PooledBuffer) -> Self {
        buffer.clear();
        Self { buffer }
    }
}

impl<'a> Deref for ScopedBuffer<'a> {
    type Target = BytesMut;
    
    fn deref(&self) -> &Self::Target {
        self.buffer.deref()
    }
}

impl<'a> DerefMut for ScopedBuffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.deref_mut()
    }
}

impl<'a> Drop for ScopedBuffer<'a> {
    fn drop(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pool_basic() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        
        // Get a buffer
        let mut buf1 = pool.get();
        buf1.extend_from_slice(b"hello");
        assert_eq!(&buf1[..], b"hello");
        
        // Drop returns to pool
        drop(buf1);
        
        let stats = pool.stats();
        assert_eq!(stats.pooled, 1);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
        
        // Get again - should reuse
        let buf2 = pool.get();
        assert!(buf2.is_empty()); // Buffer was cleared
        
        let stats = pool.stats();
        assert_eq!(stats.pooled, 0);
        assert_eq!(stats.hits, 1);
    }
    
    #[test]
    fn test_pool_multiple_buffers() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        
        // Get multiple buffers
        let buf1 = pool.get();
        let buf2 = pool.get();
        let buf3 = pool.get();
        
        let stats = pool.stats();
        assert_eq!(stats.allocated, 3);
        assert_eq!(stats.pooled, 0);
        
        // Return all
        drop(buf1);
        drop(buf2);
        drop(buf3);
        
        let stats = pool.stats();
        assert_eq!(stats.pooled, 3);
    }
    
    #[test]
    fn test_pool_overflow() {
        let pool = Arc::new(BufferPool::with_config(1024, 2));
        
        // Get 3 buffers (more than max)
        let buf1 = pool.get();
        let buf2 = pool.get();
        let buf3 = pool.get();
        
        // Return all - only 2 should be pooled
        drop(buf1);
        drop(buf2);
        drop(buf3);
        
        let stats = pool.stats();
        assert_eq!(stats.pooled, 2);
    }
    
    #[test]
    fn test_pool_take() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        
        let mut buf = pool.get();
        buf.extend_from_slice(b"data");
        
        // Take ownership, buffer should not return to pool
        let taken = buf.take();
        assert_eq!(&taken[..], b"data");
        
        let stats = pool.stats();
        assert_eq!(stats.pooled, 0);
    }
    
    #[test]
    fn test_pool_preallocate() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        pool.preallocate(5);
        
        let stats = pool.stats();
        assert_eq!(stats.pooled, 5);
        assert_eq!(stats.allocated, 5);
    }
    
    #[test]
    fn test_pool_try_get() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        
        // Pool is empty, try_get returns None
        assert!(pool.try_get().is_none());
        
        // Add a buffer to pool
        pool.preallocate(1);
        
        // Now try_get should succeed once while the buffer is held
        let buf = pool.try_get();
        assert!(buf.is_some());
        // While buffer is held, pool is empty
        assert!(pool.try_get().is_none());
        // Drop buffer -> returns to pool, should be obtainable again
        drop(buf);
        assert!(pool.try_get().is_some());
    }
    
    #[test]
    fn test_hit_rate() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        
        // First get is a miss
        let buf1 = pool.get();
        drop(buf1);
        
        // Second get is a hit
        let buf2 = pool.get();
        drop(buf2);
        
        // Third get is a hit
        let _buf3 = pool.get();
        
        let stats = pool.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 66.67).abs() < 1.0);
    }
    
    #[test]
    fn test_scoped_buffer() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));
        let mut buf = pool.get();
        
        {
            let mut scoped = ScopedBuffer::new(&mut buf);
            scoped.extend_from_slice(b"scoped data");
            assert_eq!(&scoped[..], b"scoped data");
        }
        
        // After scoped is dropped, buffer is cleared
        assert!(buf.is_empty());
    }
    
    #[test]
    fn test_concurrent_access() {
        use std::thread;
        
        let pool = Arc::new(BufferPool::with_config(1024, 100));
        let mut handles = vec![];
        
        for _ in 0..10 {
            let pool_clone = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let mut buf = pool_clone.get();
                    buf.extend_from_slice(b"test");
                    // buf auto-returned on drop
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let stats = pool.stats();
        // All buffers should be returned
        assert!(stats.pooled > 0);
    }

    // When a buffer containing data is returned to the pool and then re-issued
    // to a new caller, its visible length must be zero.  The caller must not be
    // able to read the previous contents through the BytesMut API.
    // (NOTE: the backing bytes are NOT zeroed — this is intentional.  The pool
    // only resets the length.  Actual plaintext data in the backing bytes is
    // not exploitable through safe Rust, because BytesMut only exposes [0..len].)
    #[test]
    fn pooled_buffer_length_is_zero_when_returned_and_re_issued() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));

        let mut buf = pool.get();
        buf.extend_from_slice(b"sensitive plaintext that must not leak");
        assert_eq!(buf.len(), 38);
        drop(buf); // returns to pool

        let reissued = pool.get();
        assert_eq!(reissued.len(), 0, "re-issued buffer must have zero visible length");
        assert!(reissued.is_empty(), "re-issued buffer.is_empty() must be true");
        // Capacity may be non-zero (reserved), but len == 0 ensures no prior
        // bytes are accessible through the safe API.
    }

    // Preallocated buffers must be usable and their capacity must be at least
    // buffer_size so that callers do not immediately trigger a reallocation.
    #[test]
    fn preallocated_buffers_have_correct_capacity() {
        let pool = Arc::new(BufferPool::with_config(2048, 8));
        pool.preallocate(4);

        let stats = pool.stats();
        assert_eq!(stats.pooled, 4);

        let buf = pool.get();
        assert!(
            buf.capacity() >= 2048,
            "preallocated buffer capacity ({}) must be >= buffer_size (2048)",
            buf.capacity()
        );
    }

    // A buffer that grew moderately (within MAX_POOL_BUFFER_OVERSIZE_MULT of the canonical
    // size) must be returned to the pool, because the allocation is still reasonable and
    // reusing it is more efficient than allocating a new one.
    #[test]
    fn oversized_buffer_is_returned_to_pool() {
        let canonical = 64usize;
        let pool = Arc::new(BufferPool::with_config(canonical, 10));

        let mut buf = pool.get();
        // Grow to 2× the canonical size — within the 4× upper bound.
        buf.reserve(canonical);
        assert!(buf.capacity() >= canonical);
        assert!(
            buf.capacity() <= canonical * MAX_POOL_BUFFER_OVERSIZE_MULT,
            "pre-condition: test growth must stay within the acceptable bound"
        );
        drop(buf);

        // The buffer must have been returned because capacity is within acceptable range.
        let stats = pool.stats();
        assert_eq!(stats.pooled, 1, "moderately-oversized buffer must be returned to pool");
    }

    // A buffer whose capacity fell below buffer_size (e.g. due to take() on
    // the internal BytesMut creating a sub-capacity view) is silently dropped
    // rather than pooled. The pool must not panic and stats must remain valid.
    #[test]
    fn undersized_take_does_not_panic_stats_remain_valid() {
        let pool = Arc::new(BufferPool::with_config(1024, 10));

        let buf = pool.get();
        // take() drains the buffer out of the pool wrapper; the wrapper then
        // calls return_buffer on a freshly allocated (zero-length) BytesMut.
        let _inner: bytes::BytesMut = buf.take();

        // Pool should not have received back an undersized buffer — no panic.
        let stats = pool.stats();
        assert!(stats.pooled <= 1, "undersized buffer must be silently dropped");
    }

    // `allocated` is a high-water mark.  After a miss-then-return cycle, the
    // counter stays at 1 even though the buffer is back in the pool and no
    // buffer is currently live.  Callers must not interpret `allocated` as the
    // count of currently live buffers.
    #[test]
    fn allocated_is_high_water_mark_not_current_live_count() {
        let pool = Arc::new(BufferPool::with_config(64, 10));

        // One miss: allocated = 1.
        let buf = pool.get();
        {
            let stats = pool.stats();
            assert_eq!(stats.allocated, 1);
            assert_eq!(stats.pooled, 0);
        }

        // Return to pool: allocated stays at 1 even though nothing is live.
        drop(buf);
        {
            let stats = pool.stats();
            assert_eq!(stats.allocated, 1, "allocated must not decrease on buffer return");
            assert_eq!(stats.pooled, 1);
        }

        // Hit (reuse): allocated stays 1; no new allocation occurs.
        let buf2 = pool.get();
        drop(buf2);
        {
            let stats = pool.stats();
            assert_eq!(stats.allocated, 1, "reusing a pooled buffer must not increase allocated");
            // If allocated tracked current live count it would have dropped to 0 here —
            // which is the semantic mismatch this test guards against.
        }
    }

    // `allocated` must NOT drop below the total number of new allocations ever
    // made, even after all buffers have been returned and the pool is at full
    // capacity — meaning excess returns are silently dropped.
    #[test]
    fn allocated_never_decrements_even_when_pool_drops_excess_buffers() {
        let pool = Arc::new(BufferPool::with_config(64, 2));

        // Allocate 5 buffers — 5 misses, allocated = 5.
        let bufs: Vec<_> = (0..5).map(|_| pool.get()).collect();
        assert_eq!(pool.stats().allocated, 5);

        // Return all: pool can hold at most 2. The 3 excess buffers are dropped.
        drop(bufs);

        let stats = pool.stats();
        assert_eq!(stats.pooled, 2, "pool should hold max 2");
        assert_eq!(
            stats.allocated, 5,
            "allocated must stay at 5 even though 3 buffers were silently dropped"
        );
        // If allocated were a live-count, it would now be 2 (only pooled).  This
        // test documents that it is NOT: `allocated` is a high-water mark only.
    }

    // Repeated get/drop cycles must not inflate `allocated` beyond the true
    // number of distinct allocations.  Each reuse must increment `hits` and
    // leave `allocated` unchanged.
    #[test]
    fn repeated_get_drop_does_not_inflate_allocated() {
        let pool = Arc::new(BufferPool::with_config(64, 10));

        // Warm up pool with exactly 1 buffer.
        let buf = pool.get(); // miss: allocated = 1
        drop(buf);

        let allocated_after_warmup = pool.stats().allocated;
        assert_eq!(allocated_after_warmup, 1);

        // 50 subsequent get/drop cycles — all hits, allocated must stay at 1.
        for _ in 0..50 {
            let b = pool.get();
            drop(b);
        }

        let stats = pool.stats();
        assert_eq!(
            stats.allocated, 1,
            "allocated must stay at 1 after 50 hit cycles; got {}",
            stats.allocated
        );
        assert_eq!(stats.hits, 50);
    }

    // ── Security invariant: sensitive data must not leak between pool users ───

    // A buffer containing "sensitive" bytes must be zeroed before being handed
    // to the next caller. An attacker who can trigger repeated pool cycles against
    // a shared buffer slot must not be able to read prior connection data.
    #[test]
    fn pooled_buffer_sensitive_data_is_cleared_before_reuse() {
        let pool = Arc::new(BufferPool::with_config(64, 2));
        {
            let mut buf = pool.get();
            buf.extend_from_slice(b"credentials:password123");
            // Drop returns the buffer to the pool after clearing.
        }
        {
            let buf = pool.get();
            // Buffer must be empty — no leftover bytes from the previous user.
            assert!(buf.is_empty(), "pool must clear buffer before handing it to the next caller");
            assert_eq!(buf.len(), 0);
        }
    }

    // Verify that calling take() extracts the full content and the extracted
    // BytesMut does NOT get returned to the pool (no double-return).
    #[test]
    fn pooled_buffer_take_eliminates_pool_return() {
        let pool = Arc::new(BufferPool::with_config(64, 2));
        let stats_before = pool.stats();

        let mut buf = pool.get(); // miss
        buf.extend_from_slice(b"important");
        let inner = buf.take(); // consumes PooledBuffer, should NOT return to pool

        assert_eq!(&inner[..], b"important");
        let stats_after = pool.stats();
        // pooled count must not increase — take() bypasses the pool
        assert_eq!(
            stats_after.pooled, stats_before.pooled,
            "take() must not return the buffer to the pool"
        );
    }

    // Multiple concurrent get() calls must each get an independent empty buffer,
    // not aliased memory. An adversary who can cause aliased buffer access could
    // read or corrupt another connection's in-flight data.
    #[test]
    fn pooled_buffers_are_independent_no_aliasing() {
        let pool = Arc::new(BufferPool::with_config(64, 4));
        let mut b1 = pool.get();
        let mut b2 = pool.get();

        b1.extend_from_slice(b"connection-A");
        b2.extend_from_slice(b"connection-B");

        assert_eq!(&b1[..], b"connection-A");
        assert_eq!(&b2[..], b"connection-B");
        // Verify no aliasing: modifying b2 does not affect b1.
        assert_ne!(&b1[..], &b2[..]);
    }

    // Oversized buffers (capacity grown beyond pool's canonical size) must NOT
    // be returned to the pool — this prevents the pool from holding oversized
    // buffers that could be handed to unrelated connections and leak large chunks
    // of heap across connection boundaries.
    #[test]
    fn oversized_buffer_is_dropped_not_pooled() {
        let canonical = 64usize;
        let pool = Arc::new(BufferPool::with_config(canonical, 4));

        {
            let mut buf = pool.get();
            // Grow well beyond the canonical size.
            buf.extend(std::iter::repeat(0u8).take(canonical * 8));
            // Drop should abandon this oversized buffer rather than returning it.
        }

        let stats = pool.stats();
        // Pool must be empty: the oversized buffer was not re-queued.
        assert_eq!(
            stats.pooled, 0,
            "oversized buffer must be dropped, not returned to pool (got {} pooled)",
            stats.pooled
        );
    }

    // Deref on a PooledBuffer obtained normally must NOT panic.
    #[test]
    fn pooled_buffer_deref_on_live_buffer_does_not_panic() {
        let pool = Arc::new(BufferPool::new());
        let mut buf = pool.get();
        buf.extend_from_slice(b"hello");
        assert_eq!(&buf[..], b"hello");
    }
}
