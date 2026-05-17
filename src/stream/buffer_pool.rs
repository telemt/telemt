//! Reusable buffer pool to avoid allocations in hot paths
//!
//! This module provides a thread-safe pool of BytesMut buffers
//! that can be reused across connections to reduce allocation pressure.
//!
//! On many-core hosts (>16 vCPU) a single global `ArrayQueue` becomes a
//! cross-core cache-line ping-pong source: every `get()` and `return_buffer()`
//! touches the queue head atomics and the per-pool `hits/misses/allocated`
//! counters. `BufferPool` is therefore a thin façade over N internal
//! `BufferPoolShard`s — each shard owns its own queue and counters. Each tokio
//! worker thread stickily binds to one shard via a `thread_local!` hint, so
//! the steady-state hot path touches only that shard's cache lines.
//!
//! Public API (`get`, `try_get`, `stats`, `preallocate`, `trim_to`, `pooled`,
//! `allocated`, `buffer_size`, `max_buffers`) is preserved; statistics are
//! aggregated across shards on demand.

#![allow(dead_code)]

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ============= Configuration =============

/// Default buffer size
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Default maximum number of pooled buffers.
///
/// 4096 sized to cover ~tens of thousands of concurrent connections without
/// re-allocating buffers on every churn. Buffer memory is bounded by
/// `DEFAULT_MAX_BUFFERS * DEFAULT_BUFFER_SIZE` ≈ 256 MiB; the pool only grows
/// to satisfy actual demand. The capacity is split evenly across per-CPU
/// shards (see module docs).
pub const DEFAULT_MAX_BUFFERS: usize = 4096;

/// Minimum number of shards for the pool, even on single-core hosts.
const MIN_SHARDS: usize = 1;
/// Upper bound to avoid runaway memory on hosts with absurd CPU counts.
const MAX_SHARDS: usize = 64;

/// Atomic counter dispensing distinct shard indices to threads on first touch.
static SHARD_DISPENSER: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Cached shard index for the current thread. Set on first access so each
    /// tokio worker thread sticks to one shard and the hot path stays
    /// cache-local.
    static SHARD_HINT: Cell<Option<usize>> = const { Cell::new(None) };
}

fn shard_count_default() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(MIN_SHARDS, MAX_SHARDS)
}

// ============= Buffer Pool Shard =============

/// Single shard of the buffer pool: the original `BufferPool` logic, but only
/// owning a fraction of the global capacity.
struct BufferPoolShard {
    buffers: ArrayQueue<BytesMut>,
    buffer_size: usize,
    max_buffers: usize,
    allocated: AtomicUsize,
    misses: AtomicUsize,
    hits: AtomicUsize,
    replaced_nonstandard: AtomicUsize,
    dropped_pool_full: AtomicUsize,
}

impl BufferPoolShard {
    fn new(buffer_size: usize, max_buffers: usize) -> Self {
        // ArrayQueue requires capacity >= 1.
        let capacity = max_buffers.max(1);
        Self {
            buffers: ArrayQueue::new(capacity),
            buffer_size,
            max_buffers: capacity,
            allocated: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
            replaced_nonstandard: AtomicUsize::new(0),
            dropped_pool_full: AtomicUsize::new(0),
        }
    }

    fn pop_existing(self: &Arc<Self>) -> Option<PooledBuffer> {
        self.buffers.pop().map(|mut buffer| {
            self.hits.fetch_add(1, Ordering::Relaxed);
            buffer.clear();
            PooledBuffer {
                buffer: Some(buffer),
                shard: Arc::clone(self),
            }
        })
    }

    fn alloc_new(self: &Arc<Self>) -> PooledBuffer {
        self.misses.fetch_add(1, Ordering::Relaxed);
        self.allocated.fetch_add(1, Ordering::Relaxed);
        PooledBuffer {
            buffer: Some(BytesMut::with_capacity(self.buffer_size)),
            shard: Arc::clone(self),
        }
    }

    fn return_buffer(&self, mut buffer: BytesMut) {
        const MAX_RETAINED_BUFFER_FACTOR: usize = 2;

        buffer.clear();
        let max_retained_capacity = self
            .buffer_size
            .saturating_mul(MAX_RETAINED_BUFFER_FACTOR)
            .max(self.buffer_size);

        if buffer.capacity() < self.buffer_size || buffer.capacity() > max_retained_capacity {
            self.replaced_nonstandard.fetch_add(1, Ordering::Relaxed);
            buffer = BytesMut::with_capacity(self.buffer_size);
        }

        if self.buffers.push(buffer).is_err() {
            self.dropped_pool_full.fetch_add(1, Ordering::Relaxed);
            self.decrement_allocated();
        }
    }

    fn decrement_allocated(&self) {
        let _ = self
            .allocated
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
    }

    fn trim_to(&self, target_pooled: usize) {
        let target = target_pooled.min(self.max_buffers);
        loop {
            if self.buffers.len() <= target {
                break;
            }
            if self.buffers.pop().is_some() {
                self.decrement_allocated();
            } else {
                break;
            }
        }
    }

    fn preallocate(&self, count: usize) {
        let to_alloc = count.min(self.max_buffers);
        for _ in 0..to_alloc {
            if self
                .buffers
                .push(BytesMut::with_capacity(self.buffer_size))
                .is_err()
            {
                break;
            }
            self.allocated.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ============= Buffer Pool (façade) =============

/// Thread-safe pool of reusable buffers, sharded across CPUs for scalability.
pub struct BufferPool {
    shards: Vec<Arc<BufferPoolShard>>,
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool with default settings.
    pub fn new() -> Self {
        Self::with_config(DEFAULT_BUFFER_SIZE, DEFAULT_MAX_BUFFERS)
    }

    /// Create a buffer pool with custom configuration. `max_buffers` is the
    /// total capacity across all shards.
    pub fn with_config(buffer_size: usize, max_buffers: usize) -> Self {
        Self::with_config_and_shards(buffer_size, max_buffers, shard_count_default())
    }

    /// Build a pool with an explicit shard count. Useful in tests.
    pub fn with_config_and_shards(
        buffer_size: usize,
        max_buffers: usize,
        shard_count: usize,
    ) -> Self {
        let shard_count = shard_count.clamp(MIN_SHARDS, MAX_SHARDS);
        let per_shard = max_buffers.div_ceil(shard_count);
        let shards = (0..shard_count)
            .map(|_| Arc::new(BufferPoolShard::new(buffer_size, per_shard)))
            .collect();
        Self {
            shards,
            buffer_size,
        }
    }

    fn pick_shard_idx(&self) -> usize {
        if self.shards.len() == 1 {
            return 0;
        }
        let n = self.shards.len();
        SHARD_HINT.with(|cell| {
            if let Some(v) = cell.get() {
                v % n
            } else {
                let assigned = SHARD_DISPENSER.fetch_add(1, Ordering::Relaxed);
                cell.set(Some(assigned));
                assigned % n
            }
        })
    }

    /// Get a buffer from the pool, allocating a new one if the local shard is
    /// empty. The buffer is returned to the same shard on drop, preserving
    /// cache locality.
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        let idx = self.pick_shard_idx();
        let shard = &self.shards[idx];
        if let Some(buf) = shard.pop_existing() {
            buf
        } else {
            shard.alloc_new()
        }
    }

    /// Try to get a buffer; returns None if the local shard is empty.
    pub fn try_get(self: &Arc<Self>) -> Option<PooledBuffer> {
        let idx = self.pick_shard_idx();
        self.shards[idx].pop_existing()
    }

    /// Aggregated pool statistics across all shards.
    pub fn stats(&self) -> PoolStats {
        let mut s = PoolStats {
            pooled: 0,
            allocated: 0,
            max_buffers: 0,
            buffer_size: self.buffer_size,
            hits: 0,
            misses: 0,
            replaced_nonstandard: 0,
            dropped_pool_full: 0,
        };
        for shard in &self.shards {
            s.pooled += shard.buffers.len();
            s.allocated += shard.allocated.load(Ordering::Relaxed);
            s.max_buffers += shard.max_buffers;
            s.hits += shard.hits.load(Ordering::Relaxed);
            s.misses += shard.misses.load(Ordering::Relaxed);
            s.replaced_nonstandard += shard.replaced_nonstandard.load(Ordering::Relaxed);
            s.dropped_pool_full += shard.dropped_pool_full.load(Ordering::Relaxed);
        }
        s
    }

    /// Get buffer size (uniform across shards).
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Maximum number of buffers the pool will retain (sum across shards).
    pub fn max_buffers(&self) -> usize {
        self.shards.iter().map(|s| s.max_buffers).sum()
    }

    /// Current number of pooled buffers (sum across shards).
    pub fn pooled(&self) -> usize {
        self.shards.iter().map(|s| s.buffers.len()).sum()
    }

    /// Total buffers allocated (sum across shards).
    pub fn allocated(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.allocated.load(Ordering::Relaxed))
            .sum()
    }

    /// Best-effort number of buffers currently checked out.
    pub fn in_use(&self) -> usize {
        self.allocated().saturating_sub(self.pooled())
    }

    /// Trim pooled buffers down to a target count, divided evenly across shards.
    pub fn trim_to(&self, target_pooled: usize) {
        let n = self.shards.len().max(1);
        let per_shard = target_pooled.div_ceil(n);
        for shard in &self.shards {
            shard.trim_to(per_shard);
        }
    }

    /// Preallocate `count` buffers, divided evenly across shards.
    pub fn preallocate(&self, count: usize) {
        let n = self.shards.len().max(1);
        let per_shard = count.div_ceil(n);
        for shard in &self.shards {
            shard.preallocate(per_shard);
        }
    }

    /// Number of shards in this pool (test/diagnostic helper).
    pub fn shard_count(&self) -> usize {
        self.shards.len()
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
    /// Current number of buffers in pool
    pub pooled: usize,
    /// Total buffers allocated (in-use + pooled)
    pub allocated: usize,
    /// Maximum buffers allowed
    pub max_buffers: usize,
    /// Size of each buffer
    pub buffer_size: usize,
    /// Number of cache hits (reused buffer)
    pub hits: usize,
    /// Number of cache misses (new allocation)
    pub misses: usize,
    /// Number of non-standard buffers replaced during return
    pub replaced_nonstandard: usize,
    /// Number of buffers dropped because the pool queue was full
    pub dropped_pool_full: usize,
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
    shard: Arc<BufferPoolShard>,
}

impl PooledBuffer {
    /// Take the inner buffer, preventing return to pool
    pub fn take(mut self) -> BytesMut {
        self.shard.decrement_allocated();
        self.buffer.take().unwrap()
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
        self.buffer.as_ref().expect("buffer taken")
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().expect("buffer taken")
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.shard.return_buffer(buffer);
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
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));

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
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));

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
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 2, 1));

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
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));

        let mut buf = pool.get();
        buf.extend_from_slice(b"data");

        // Take ownership, buffer should not return to pool
        let taken = buf.take();
        assert_eq!(&taken[..], b"data");

        let stats = pool.stats();
        assert_eq!(stats.pooled, 0);
        assert_eq!(stats.allocated, 0);
    }

    #[test]
    fn test_pool_replaces_oversized_buffers() {
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));

        {
            let mut buf = pool.get();
            buf.reserve(8192);
            assert!(buf.capacity() > 2048);
        }

        let stats = pool.stats();
        assert_eq!(stats.replaced_nonstandard, 1);
        assert_eq!(stats.pooled, 1);

        let buf = pool.get();
        assert!(buf.capacity() <= 2048);
    }

    #[test]
    fn test_pool_preallocate() {
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));
        pool.preallocate(5);

        let stats = pool.stats();
        assert_eq!(stats.pooled, 5);
        assert_eq!(stats.allocated, 5);
    }

    #[test]
    fn test_pool_try_get() {
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));

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
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));

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
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 10, 1));
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
    fn test_pool_sharded_distribution() {
        use std::thread;

        // 4 shards, 20 buffers total -> 5 per shard.
        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 20, 4));
        assert_eq!(pool.shard_count(), 4);

        // Spawn 4 threads, each grabs and drops some buffers. Each thread
        // sticks to its own shard via the thread-local SHARD_HINT.
        let mut handles = vec![];
        for _ in 0..4 {
            let pool_clone = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..5 {
                    held.push(pool_clone.get());
                }
                drop(held);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let stats = pool.stats();
        // All buffers should be back in the pool (5 per shard * 4 shards).
        assert!(stats.pooled > 0);
        assert!(stats.pooled <= 20);
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let pool = Arc::new(BufferPool::with_config_and_shards(1024, 100, 1));
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
}
