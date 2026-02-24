//! Reusable buffer pool to avoid allocations in hot paths
//!
//! This module provides a thread-safe pool of BytesMut buffers
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

// ============= Buffer Pool =============

/// Thread-safe pool of reusable buffers
pub struct BufferPool {
    /// Queue of available buffers
    buffers: ArrayQueue<BytesMut>,
    /// Size of each buffer
    buffer_size: usize,
    /// Maximum number of buffers to pool
    max_buffers: usize,
    /// Total allocated buffers (including in-use)
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
        // Clear the buffer but keep capacity
        buffer.clear();
        
        // Only return if we haven't exceeded max and buffer is right size
        if buffer.capacity() >= self.buffer_size {
            // Try to push to pool, if full just drop
            let _ = self.buffers.push(buffer);
        }
        // If buffer was dropped (pool full), decrement allocated
        // Actually we don't decrement here because the buffer might have been
        // grown beyond our size - we just let it go
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
    pub fn buffer_size(&self) -> usize {
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
}
