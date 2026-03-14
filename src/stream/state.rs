//! State machine foundation types for async streams
//!
//! This module provides core types and traits for implementing
//! stateful async streams with proper partial read/write handling.

#![allow(dead_code)]

use bytes::{Bytes, BytesMut};
use std::io;

// ============= Core Traits =============

/// Trait for stream states
pub trait StreamState: Sized {
    /// Check if this is a terminal state (no more transitions possible)
    fn is_terminal(&self) -> bool;
    
    /// Check if stream is in poisoned/error state
    fn is_poisoned(&self) -> bool;
    
    /// Get human-readable state name for debugging
    fn state_name(&self) -> &'static str;
}

// ============= Transition Types =============

/// Result of a state transition
#[derive(Debug)]
pub enum Transition<S, O> {
    /// Stay in the same state, no output
    Same,
    /// Transition to a new state, no output
    Next(S),
    /// Complete with output, typically transitions to Idle
    Complete(O),
    /// Yield output and transition to new state
    Yield(O, S),
    /// Error occurred, transition to error state
    Error(io::Error),
}

impl<S, O> Transition<S, O> {
    /// Check if transition produces output
    pub const fn has_output(&self) -> bool {
        matches!(self, Self::Complete(_) | Self::Yield(_, _))
    }
    
    /// Map the output value
    pub fn map_output<U, F: FnOnce(O) -> U>(self, f: F) -> Transition<S, U> {
        match self {
            Self::Same => Transition::Same,
            Self::Next(s) => Transition::Next(s),
            Self::Complete(o) => Transition::Complete(f(o)),
            Self::Yield(o, s) => Transition::Yield(f(o), s),
            Self::Error(e) => Transition::Error(e),
        }
    }
    
    /// Map the state value
    pub fn map_state<T, F: FnOnce(S) -> T>(self, f: F) -> Transition<T, O> {
        match self {
            Self::Same => Transition::Same,
            Self::Next(s) => Transition::Next(f(s)),
            Self::Complete(o) => Transition::Complete(o),
            Self::Yield(o, s) => Transition::Yield(o, f(s)),
            Self::Error(e) => Transition::Error(e),
        }
    }
}

// ============= Poll Result Types =============

/// Result of polling for more data
#[derive(Debug)]
pub enum PollResult<T> {
    /// Data is ready
    Ready(T),
    /// Operation would block, need to poll again
    Pending,
    /// Need more input data (minimum bytes required)
    NeedInput(usize),
    /// End of stream reached
    Eof,
    /// Error occurred
    Error(io::Error),
}

impl<T> PollResult<T> {
    /// Check if result is ready
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
    
    /// Check if result indicates EOF
    pub const fn is_eof(&self) -> bool {
        matches!(self, Self::Eof)
    }
    
    /// Convert to Option, discarding non-ready states
    pub fn ok(self) -> Option<T> {
        match self {
            Self::Ready(t) => Some(t),
            _ => None,
        }
    }
    
    /// Map the value
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> PollResult<U> {
        match self {
            Self::Ready(t) => PollResult::Ready(f(t)),
            Self::Pending => PollResult::Pending,
            Self::NeedInput(n) => PollResult::NeedInput(n),
            Self::Eof => PollResult::Eof,
            Self::Error(e) => PollResult::Error(e),
        }
    }
}

impl<T> From<io::Result<T>> for PollResult<T> {
    fn from(result: io::Result<T>) -> Self {
        match result {
            Ok(t) => Self::Ready(t),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Self::Pending,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Self::Eof,
            Err(e) => Self::Error(e),
        }
    }
}

// ============= Buffer State =============

/// State for buffered reading operations
#[derive(Debug)]
pub struct ReadBuffer {
    /// The buffer holding data
    buffer: BytesMut,
    /// Target number of bytes to read (if known)
    target: Option<usize>,
}

impl ReadBuffer {
    /// Create new empty read buffer
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(8192),
            target: None,
        }
    }
    
    /// Create with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
            target: None,
        }
    }
    
    /// Create with target size
    pub fn with_target(target: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(target),
            target: Some(target),
        }
    }
    
    /// Get current buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    
    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
    
    /// Check if target is reached
    pub fn is_complete(&self) -> bool {
        match self.target {
            Some(t) => self.buffer.len() >= t,
            None => false,
        }
    }
    
    /// Get remaining bytes needed
    pub fn remaining(&self) -> usize {
        match self.target {
            Some(t) => t.saturating_sub(self.buffer.len()),
            None => 0,
        }
    }
    
    /// Append data to buffer
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    
    /// Take all data from buffer
    pub fn take(&mut self) -> Bytes {
        self.target = None;
        self.buffer.split().freeze()
    }
    
    /// Take exactly n bytes
    pub fn take_exact(&mut self, n: usize) -> Option<Bytes> {
        if self.buffer.len() >= n {
            Some(self.buffer.split_to(n).freeze())
        } else {
            None
        }
    }
    
    /// Get a slice of the buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
    
    /// Get mutable access to underlying `BytesMut`
    pub const fn as_bytes_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }
    
    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.target = None;
    }
    
    /// Set new target
    pub const fn set_target(&mut self, target: usize) {
        self.target = Some(target);
    }
}

impl Default for ReadBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// State for buffered writing operations
#[derive(Debug)]
pub struct WriteBuffer {
    /// The buffer holding data to write
    buffer: BytesMut,
    /// Position of next byte to write
    position: usize,
    /// Maximum buffer size
    max_size: usize,
}

impl WriteBuffer {
    /// Create new write buffer with default max size (256KB)
    pub fn new() -> Self {
        Self::with_max_size(256 * 1024)
    }
    
    /// Create with specific max size
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(8192),
            position: 0,
            max_size,
        }
    }
    
    /// Get pending bytes count
    pub fn len(&self) -> usize {
        self.buffer.len() - self.position
    }
    
    /// Check if buffer is empty (all written)
    pub fn is_empty(&self) -> bool {
        self.position >= self.buffer.len()
    }
    
    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.max_size
    }
    
    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.max_size.saturating_sub(self.buffer.len())
    }
    
    /// Append data to buffer
    pub fn extend(&mut self, data: &[u8]) -> Result<(), ()> {
        if self.buffer.len() + data.len() > self.max_size {
            return Err(());
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }
    
    /// Get slice of data to write
    pub fn pending(&self) -> &[u8] {
        &self.buffer[self.position..]
    }
    
    /// Advance position by n bytes (after successful write)
    pub fn advance(&mut self, n: usize) {
        self.position = self.position.saturating_add(n).min(self.buffer.len());

        // If all data written, reset buffer
        if self.position >= self.buffer.len() {
            self.buffer.clear();
            self.position = 0;
        }
    }
    
    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }
}

impl Default for WriteBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ============= Fixed-Size Buffer States =============

/// State for reading a fixed-size header
#[derive(Debug, Clone)]
pub struct HeaderBuffer<const N: usize> {
    /// The buffer
    data: [u8; N],
    /// Bytes filled so far
    filled: usize,
}

impl<const N: usize> HeaderBuffer<N> {
    /// Create new empty header buffer
    pub const fn new() -> Self {
        Self {
            data: [0u8; N],
            filled: 0,
        }
    }
    
    /// Get slice for reading into
    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.filled..]
    }
    
    /// Advance filled count
    pub fn advance(&mut self, n: usize) {
        self.filled = (self.filled + n).min(N);
    }
    
    /// Check if completely filled
    pub const fn is_complete(&self) -> bool {
        self.filled >= N
    }
    
    /// Get remaining bytes needed
    pub const fn remaining(&self) -> usize {
        N - self.filled
    }
    
    /// Get filled bytes as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.filled]
    }
    
    /// Get complete buffer (panics if not complete)
    pub fn as_array(&self) -> &[u8; N] {
        assert!(self.is_complete());
        &self.data
    }
    
    /// Take the buffer, resetting state
    pub const fn take(&mut self) -> [u8; N] {
        let data = self.data;
        self.data = [0u8; N];
        self.filled = 0;
        data
    }
    
    /// Reset to empty state
    pub const fn reset(&mut self) {
        self.filled = 0;
    }
}

impl<const N: usize> Default for HeaderBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============= Yield Buffer =============

/// Buffer for yielding data to caller in chunks
#[derive(Debug)]
pub struct YieldBuffer {
    data: Bytes,
    position: usize,
}

impl YieldBuffer {
    /// Create new yield buffer
    pub const fn new(data: Bytes) -> Self {
        Self { data, position: 0 }
    }
    
    /// Check if all data has been yielded
    pub const fn is_empty(&self) -> bool {
        self.position >= self.data.len()
    }
    
    /// Get remaining bytes
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    
    /// Copy data to output slice, return bytes copied
    pub fn copy_to(&mut self, dst: &mut [u8]) -> usize {
        let available = &self.data[self.position..];
        let to_copy = available.len().min(dst.len());
        dst[..to_copy].copy_from_slice(&available[..to_copy]);
        self.position += to_copy;
        to_copy
    }
    
    /// Get remaining data as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.position..]
    }
}

// ============= Macros =============

/// Macro to simplify state transitions in poll methods
#[macro_export]
macro_rules! transition {
    (same) => {
        $crate::stream::state::Transition::Same
    };
    (next $state:expr) => {
        $crate::stream::state::Transition::Next($state)
    };
    (complete $output:expr) => {
        $crate::stream::state::Transition::Complete($output)
    };
    (yield $output:expr, $state:expr) => {
        $crate::stream::state::Transition::Yield($output, $state)
    };
    (error $err:expr) => {
        $crate::stream::state::Transition::Error($err)
    };
}

/// Macro to match poll ready or return pending
#[macro_export]
macro_rules! ready_or_pending {
    ($poll:expr) => {
        match $poll {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_read_buffer_basic() {
        let mut buf = ReadBuffer::with_target(10);
        assert_eq!(buf.remaining(), 10);
        assert!(!buf.is_complete());
        
        buf.extend(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.remaining(), 5);
        assert!(!buf.is_complete());
        
        buf.extend(b"world");
        assert_eq!(buf.len(), 10);
        assert!(buf.is_complete());
    }
    
    #[test]
    fn test_read_buffer_take() {
        let mut buf = ReadBuffer::new();
        buf.extend(b"test data");
        
        let data = buf.take();
        assert_eq!(&data[..], b"test data");
        assert!(buf.is_empty());
    }
    
    #[test]
    fn test_write_buffer_basic() {
        let mut buf = WriteBuffer::with_max_size(100);
        assert!(buf.is_empty());
        
        buf.extend(b"hello").unwrap();
        assert_eq!(buf.len(), 5);
        assert!(!buf.is_empty());
        
        buf.advance(3);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.pending(), b"lo");
    }

    #[test]
    fn write_buffer_advance_beyond_length_does_not_panic() {
        // Advancing past the buffer end must not panic or leave position > buffer.len().
        let mut buf = WriteBuffer::with_max_size(100);
        buf.extend(&[1, 2, 3, 4]).unwrap();
        buf.advance(1000); // far beyond 4-byte content
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        // Buffer should be usable again after the overshoot.
        buf.extend(&[9]).unwrap();
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn write_buffer_advance_exact_length_resets_cleanly() {
        let mut buf = WriteBuffer::with_max_size(64);
        buf.extend(&[0xAA; 16]).unwrap();
        buf.advance(16);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn write_buffer_advance_saturating_on_usize_near_max() {
        // position.saturating_add(very_large_n) must clamp to buffer.len() without overflow.
        let mut buf = WriteBuffer::with_max_size(64);
        buf.extend(&[0xBB; 8]).unwrap();
        buf.advance(usize::MAX);
        assert!(buf.is_empty());
    }
    
    #[test]
    fn test_write_buffer_overflow() {
        let mut buf = WriteBuffer::with_max_size(10);
        assert!(buf.extend(b"short").is_ok());
        assert!(buf.extend(b"toolong").is_err());
    }
    
    #[test]
    fn test_header_buffer() {
        let mut buf = HeaderBuffer::<5>::new();
        assert!(!buf.is_complete());
        assert_eq!(buf.remaining(), 5);
        
        buf.unfilled_mut()[..3].copy_from_slice(b"hel");
        buf.advance(3);
        assert_eq!(buf.remaining(), 2);
        
        buf.unfilled_mut()[..2].copy_from_slice(b"lo");
        buf.advance(2);
        assert!(buf.is_complete());
        assert_eq!(buf.as_array(), b"hello");
    }
    
    #[test]
    fn test_yield_buffer() {
        let mut buf = YieldBuffer::new(Bytes::from_static(b"hello world"));
        
        let mut dst = [0u8; 5];
        assert_eq!(buf.copy_to(&mut dst), 5);
        assert_eq!(&dst, b"hello");
        
        assert_eq!(buf.remaining(), 6);
        
        let mut dst = [0u8; 10];
        assert_eq!(buf.copy_to(&mut dst), 6);
        assert_eq!(&dst[..6], b" world");
        
        assert!(buf.is_empty());
    }
    
    #[test]
    fn test_transition_map() {
        let t: Transition<i32, String> = Transition::Complete("hello".to_string());
        let t = t.map_output(|s| s.len());
        
        match t {
            Transition::Complete(5) => {}
            _ => panic!("Expected Complete(5)"),
        }
    }
    
    #[test]
    fn test_poll_result() {
        let r: PollResult<i32> = PollResult::Ready(42);
        assert!(r.is_ready());
        assert_eq!(r.ok(), Some(42));
        
        let r: PollResult<i32> = PollResult::Eof;
        assert!(r.is_eof());
        assert_eq!(r.ok(), None);
    }

    // WriteBuffer::advance(0) must be a no-op: position unchanged, buffer not reset.
    // A zero-advance could otherwise prematurely reset the buffer and corrupt data
    // that has not yet been written to the upstream.
    #[test]
    fn write_buffer_advance_zero_is_noop() {
        let mut buf = WriteBuffer::with_max_size(64);
        buf.extend(&[0xAA; 8]).unwrap();
        buf.advance(0);
        assert_eq!(buf.len(), 8, "advance(0) must not consume any bytes");
        assert_eq!(buf.pending(), &[0xAA; 8]);
    }

    // WriteBuffer::extend after a partial advance must account for remaining
    // capacity correctly: remaining_capacity() = max_size - buffer.len(), not
    // max_size - position.  A bug here could allow overflow of the internal
    // BytesMut or reject valid writes that should fit.
    #[test]
    fn write_buffer_extend_after_partial_drain_uses_correct_remaining_capacity() {
        let mut buf = WriteBuffer::with_max_size(16);
        buf.extend(&[0x11; 12]).unwrap();
        buf.advance(8); // 8 bytes consumed, 4 still pending
        // remaining_capacity = 16 - 12 (buffer.len) = 4, NOT 16 - 4 (position)
        assert_eq!(buf.remaining_capacity(), 4);
        // Exactly 4 bytes should fit
        assert!(buf.extend(&[0x22; 4]).is_ok());
        // 5 bytes must overflow
        let mut buf2 = WriteBuffer::with_max_size(16);
        buf2.extend(&[0x33; 12]).unwrap();
        buf2.advance(8);
        assert!(buf2.extend(&[0x44; 5]).is_err(), "5 bytes must exceed remaining capacity of 4");
    }

    // ReadBuffer::take_exact with n > len must return None without modifying the buffer.
    #[test]
    fn read_buffer_take_exact_larger_than_available_returns_none() {
        let mut buf = ReadBuffer::new();
        buf.extend(b"AB");
        assert!(buf.take_exact(10).is_none(), "must return None when n > buffer len");
        assert_eq!(buf.len(), 2, "buffer must be unchanged after failed take_exact");
    }

    // HeaderBuffer::advance must clamp at N, never overflow the array.
    // An unclamped advance would advance `filled` past N, causing as_array()
    // to assert-panic on subsequent calls.
    #[test]
    fn header_buffer_advance_clamps_at_capacity() {
        let mut buf = HeaderBuffer::<4>::new();
        buf.advance(100); // far beyond N=4
        assert!(buf.is_complete(), "after overflow advance, buffer must be complete");
        assert_eq!(buf.remaining(), 0);
    }

    // YieldBuffer::copy_to with a zero-length destination must return 0 without
    // advancing position.
    #[test]
    fn yield_buffer_copy_to_empty_dst_is_noop() {
        let mut buf = YieldBuffer::new(bytes::Bytes::from_static(b"hello"));
        let copied = buf.copy_to(&mut []);
        assert_eq!(copied, 0);
        assert_eq!(buf.remaining(), 5, "position must not advance for empty dst");
    }
}
