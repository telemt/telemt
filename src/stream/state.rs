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
    pub fn has_output(&self) -> bool {
        matches!(self, Transition::Complete(_) | Transition::Yield(_, _))
    }

    /// Map the output value
    pub fn map_output<U, F: FnOnce(O) -> U>(self, f: F) -> Transition<S, U> {
        match self {
            Transition::Same => Transition::Same,
            Transition::Next(s) => Transition::Next(s),
            Transition::Complete(o) => Transition::Complete(f(o)),
            Transition::Yield(o, s) => Transition::Yield(f(o), s),
            Transition::Error(e) => Transition::Error(e),
        }
    }

    /// Map the state value
    pub fn map_state<T, F: FnOnce(S) -> T>(self, f: F) -> Transition<T, O> {
        match self {
            Transition::Same => Transition::Same,
            Transition::Next(s) => Transition::Next(f(s)),
            Transition::Complete(o) => Transition::Complete(o),
            Transition::Yield(o, s) => Transition::Yield(o, f(s)),
            Transition::Error(e) => Transition::Error(e),
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
    pub fn is_ready(&self) -> bool {
        matches!(self, PollResult::Ready(_))
    }

    /// Check if result indicates EOF
    pub fn is_eof(&self) -> bool {
        matches!(self, PollResult::Eof)
    }

    /// Convert to Option, discarding non-ready states
    pub fn ok(self) -> Option<T> {
        match self {
            PollResult::Ready(t) => Some(t),
            _ => None,
        }
    }

    /// Map the value
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> PollResult<U> {
        match self {
            PollResult::Ready(t) => PollResult::Ready(f(t)),
            PollResult::Pending => PollResult::Pending,
            PollResult::NeedInput(n) => PollResult::NeedInput(n),
            PollResult::Eof => PollResult::Eof,
            PollResult::Error(e) => PollResult::Error(e),
        }
    }
}

impl<T> From<io::Result<T>> for PollResult<T> {
    fn from(result: io::Result<T>) -> Self {
        match result {
            Ok(t) => PollResult::Ready(t),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => PollResult::Pending,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => PollResult::Eof,
            Err(e) => PollResult::Error(e),
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

    /// Get mutable access to underlying BytesMut
    pub fn as_bytes_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.target = None;
    }

    /// Set new target
    pub fn set_target(&mut self, target: usize) {
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
        self.position += n;

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
    pub fn new() -> Self {
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
    pub fn is_complete(&self) -> bool {
        self.filled >= N
    }

    /// Get remaining bytes needed
    pub fn remaining(&self) -> usize {
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
    pub fn take(&mut self) -> [u8; N] {
        let data = self.data;
        self.data = [0u8; N];
        self.filled = 0;
        data
    }

    /// Reset to empty state
    pub fn reset(&mut self) {
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
    pub fn new(data: Bytes) -> Self {
        Self { data, position: 0 }
    }

    /// Check if all data has been yielded
    pub fn is_empty(&self) -> bool {
        self.position >= self.data.len()
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
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

    // ============= Transition: remaining branches =============

    #[test]
    fn transition_has_output_for_complete_and_yield_only() {
        let t: Transition<i32, &str> = Transition::Same;
        assert!(!t.has_output());
        let t: Transition<i32, &str> = Transition::Next(1);
        assert!(!t.has_output());
        let t: Transition<i32, &str> = Transition::Complete("ok");
        assert!(t.has_output());
        let t: Transition<i32, &str> = Transition::Yield("ok", 1);
        assert!(t.has_output());
        let t: Transition<i32, &str> =
            Transition::Error(io::Error::new(io::ErrorKind::Other, "x"));
        assert!(!t.has_output());
    }

    #[test]
    fn transition_map_output_preserves_non_output_variants() {
        let t: Transition<i32, String> = Transition::Same;
        match t.map_output(|s: String| s.len()) {
            Transition::Same => {}
            _ => panic!("Same should stay Same"),
        }
        let t: Transition<i32, String> = Transition::Next(5);
        match t.map_output(|s: String| s.len()) {
            Transition::Next(5) => {}
            _ => panic!("Next should preserve state"),
        }
        let t: Transition<i32, String> = Transition::Yield("yz".into(), 9);
        match t.map_output(|s: String| s.len()) {
            Transition::Yield(2, 9) => {}
            _ => panic!("Yield output should be mapped"),
        }
        let t: Transition<i32, String> =
            Transition::Error(io::Error::new(io::ErrorKind::Other, "x"));
        match t.map_output(|s: String| s.len()) {
            Transition::Error(_) => {}
            _ => panic!("Error should remain Error"),
        }
    }

    #[test]
    fn transition_map_state_preserves_output_variants() {
        let t: Transition<i32, &str> = Transition::Same;
        match t.map_state(|x| x * 2) {
            Transition::Same => {}
            _ => panic!("Same should stay Same"),
        }
        let t: Transition<i32, &str> = Transition::Next(3);
        match t.map_state(|x| x * 2) {
            Transition::Next(6) => {}
            _ => panic!("Next state should be mapped"),
        }
        let t: Transition<i32, &str> = Transition::Complete("kept");
        match t.map_state(|x| x * 2) {
            Transition::Complete("kept") => {}
            _ => panic!("Complete output should be preserved"),
        }
        let t: Transition<i32, &str> = Transition::Yield("k", 3);
        match t.map_state(|x| x * 2) {
            Transition::Yield("k", 6) => {}
            _ => panic!("Yield state should be mapped, output preserved"),
        }
    }

    // ============= PollResult: remaining branches =============

    #[test]
    fn poll_result_pending_and_need_input_have_no_value() {
        let r: PollResult<i32> = PollResult::Pending;
        assert!(!r.is_ready());
        assert!(!r.is_eof());
        assert_eq!(r.ok(), None);

        let r: PollResult<i32> = PollResult::NeedInput(7);
        assert!(!r.is_ready());
        assert!(!r.is_eof());
        assert_eq!(r.ok(), None);
    }

    #[test]
    fn poll_result_error_has_no_value() {
        let r: PollResult<i32> =
            PollResult::Error(io::Error::new(io::ErrorKind::Other, "boom"));
        assert!(!r.is_ready());
        assert!(!r.is_eof());
        assert_eq!(r.ok(), None);
    }

    #[test]
    fn poll_result_map_only_transforms_ready() {
        let r: PollResult<i32> = PollResult::Ready(7);
        assert!(matches!(r.map(|x| x + 1), PollResult::Ready(8)));

        let r: PollResult<i32> = PollResult::Pending;
        assert!(matches!(r.map(|x| x + 1), PollResult::Pending));

        let r: PollResult<i32> = PollResult::NeedInput(3);
        assert!(matches!(r.map(|x| x + 1), PollResult::NeedInput(3)));

        let r: PollResult<i32> = PollResult::Eof;
        assert!(matches!(r.map(|x| x + 1), PollResult::Eof));

        let r: PollResult<i32> =
            PollResult::Error(io::Error::new(io::ErrorKind::Other, "x"));
        assert!(matches!(r.map(|x| x + 1), PollResult::Error(_)));
    }

    #[test]
    fn poll_result_from_io_result_classifies_error_kinds() {
        let r: PollResult<i32> = Ok::<i32, io::Error>(42).into();
        assert!(matches!(r, PollResult::Ready(42)));

        let r: PollResult<i32> = Err::<i32, io::Error>(io::Error::new(
            io::ErrorKind::WouldBlock,
            "block",
        ))
        .into();
        assert!(matches!(r, PollResult::Pending));

        let r: PollResult<i32> = Err::<i32, io::Error>(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "eof",
        ))
        .into();
        assert!(matches!(r, PollResult::Eof));

        let r: PollResult<i32> = Err::<i32, io::Error>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no",
        ))
        .into();
        assert!(matches!(r, PollResult::Error(_)));
    }

    // ============= ReadBuffer: additional coverage =============

    #[test]
    fn read_buffer_take_exact_splits_only_when_enough() {
        let mut buf = ReadBuffer::new();
        buf.extend(b"abcdef");
        assert!(buf.take_exact(10).is_none());
        let three = buf.take_exact(3).unwrap();
        assert_eq!(&three[..], b"abc");
        assert_eq!(buf.len(), 3);
        let rest = buf.take_exact(3).unwrap();
        assert_eq!(&rest[..], b"def");
        assert!(buf.is_empty());
    }

    #[test]
    fn read_buffer_clear_resets_target_and_data() {
        let mut buf = ReadBuffer::with_target(10);
        buf.extend(b"abc");
        assert_eq!(buf.remaining(), 7);
        buf.clear();
        assert!(buf.is_empty());
        // Target cleared → remaining is 0 for unset target.
        assert_eq!(buf.remaining(), 0);
        assert!(!buf.is_complete());
    }

    #[test]
    fn read_buffer_set_target_changes_remaining() {
        let mut buf = ReadBuffer::new();
        buf.extend(b"abc");
        assert_eq!(buf.remaining(), 0); // no target yet
        buf.set_target(10);
        assert_eq!(buf.remaining(), 7);
        buf.set_target(2);
        // Target shrinks below current length → completes immediately.
        assert!(buf.is_complete());
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn read_buffer_default_capacity_does_not_set_target() {
        let buf = ReadBuffer::with_capacity(1024);
        assert_eq!(buf.remaining(), 0);
        assert!(!buf.is_complete());
    }

    // ============= WriteBuffer: additional coverage =============

    #[test]
    fn write_buffer_remaining_capacity_decreases_as_extended() {
        let mut buf = WriteBuffer::with_max_size(10);
        assert_eq!(buf.remaining_capacity(), 10);
        buf.extend(b"abc").unwrap();
        assert_eq!(buf.remaining_capacity(), 7);
    }

    #[test]
    fn write_buffer_is_full_at_capacity() {
        let mut buf = WriteBuffer::with_max_size(5);
        assert!(!buf.is_full());
        buf.extend(b"hello").unwrap();
        assert!(buf.is_full());
        assert_eq!(buf.remaining_capacity(), 0);
    }

    #[test]
    fn write_buffer_advance_past_end_resets() {
        let mut buf = WriteBuffer::with_max_size(100);
        buf.extend(b"hello").unwrap();
        buf.advance(5);
        // Fully consumed → buffer is reset, empty again with capacity.
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        // Re-use must work after reset.
        buf.extend(b"world").unwrap();
        assert_eq!(buf.pending(), b"world");
    }

    #[test]
    fn write_buffer_clear_resets_position_and_buffer() {
        let mut buf = WriteBuffer::with_max_size(100);
        buf.extend(b"hello").unwrap();
        buf.advance(2);
        assert_eq!(buf.pending(), b"llo");
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.pending(), b"");
    }

    // ============= HeaderBuffer: additional coverage =============

    #[test]
    fn header_buffer_take_returns_data_and_resets() {
        let mut buf = HeaderBuffer::<4>::new();
        buf.unfilled_mut()[..4].copy_from_slice(b"WXYZ");
        buf.advance(4);
        assert!(buf.is_complete());
        let taken = buf.take();
        assert_eq!(&taken, b"WXYZ");
        // After take, buffer is fresh.
        assert!(!buf.is_complete());
        assert_eq!(buf.remaining(), 4);
        assert_eq!(buf.as_slice(), b"");
    }

    #[test]
    fn header_buffer_reset_marks_unfilled() {
        let mut buf = HeaderBuffer::<3>::new();
        buf.unfilled_mut()[..3].copy_from_slice(b"abc");
        buf.advance(3);
        buf.reset();
        assert!(!buf.is_complete());
        assert_eq!(buf.remaining(), 3);
        // reset() does NOT zero the bytes — they will be overwritten on
        // next read. But as_slice() (filled view) must be empty now.
        assert_eq!(buf.as_slice(), b"");
    }

    #[test]
    fn header_buffer_advance_clamps_at_n() {
        let mut buf = HeaderBuffer::<3>::new();
        buf.unfilled_mut()[..3].copy_from_slice(b"abc");
        buf.advance(100); // over-advance must clamp to N
        assert!(buf.is_complete());
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    #[should_panic]
    fn header_buffer_as_array_panics_when_not_complete() {
        let buf = HeaderBuffer::<4>::new();
        let _ = buf.as_array();
    }

    // ============= YieldBuffer: additional coverage =============

    #[test]
    fn yield_buffer_as_slice_reflects_advance() {
        let mut buf = YieldBuffer::new(Bytes::from_static(b"abcdef"));
        assert_eq!(buf.as_slice(), b"abcdef");
        let mut dst = [0u8; 2];
        buf.copy_to(&mut dst);
        assert_eq!(buf.as_slice(), b"cdef");
        assert_eq!(buf.remaining(), 4);
    }

    #[test]
    fn yield_buffer_copy_to_zero_length_dst_is_noop() {
        let mut buf = YieldBuffer::new(Bytes::from_static(b"abc"));
        let mut dst: [u8; 0] = [];
        assert_eq!(buf.copy_to(&mut dst), 0);
        assert_eq!(buf.remaining(), 3);
    }

    // ============= Default trait instances =============

    #[test]
    fn read_buffer_default_is_new() {
        let def = ReadBuffer::default();
        assert!(def.is_empty());
        assert_eq!(def.remaining(), 0);
        assert!(!def.is_complete());
    }

    #[test]
    fn write_buffer_default_is_256k() {
        let def = WriteBuffer::default();
        assert!(def.is_empty());
        assert_eq!(def.remaining_capacity(), 256 * 1024);
    }

    #[test]
    fn header_buffer_default_is_new() {
        let def = HeaderBuffer::<8>::default();
        assert!(!def.is_complete());
        assert_eq!(def.remaining(), 8);
        assert_eq!(def.as_slice(), b"");
    }

    // ============= WriteBuffer: edge cases =============

    #[test]
    fn write_buffer_extend_exactly_at_max_succeeds() {
        let mut buf = WriteBuffer::with_max_size(4);
        assert!(buf.extend(b"abcd").is_ok());
        assert!(buf.is_full());
        assert_eq!(buf.remaining_capacity(), 0);
    }

    #[test]
    fn write_buffer_extend_one_over_max_fails() {
        let mut buf = WriteBuffer::with_max_size(4);
        assert!(buf.extend(b"abc").is_ok());
        assert!(buf.extend(b"de").is_err());
    }

    #[test]
    fn write_buffer_len_tracks_pending_after_partial_advance() {
        let mut buf = WriteBuffer::with_max_size(100);
        buf.extend(b"hello").unwrap();
        assert_eq!(buf.len(), 5);
        buf.advance(3);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.pending(), b"lo");
    }

    // ============= ReadBuffer: accessor coverage =============

    #[test]
    fn read_buffer_as_slice_returns_extented_data() {
        let mut buf = ReadBuffer::new();
        buf.extend(b"hello");
        assert_eq!(buf.as_slice(), b"hello");
    }

    #[test]
    fn read_buffer_as_bytes_mut_allows_direct_write() {
        let mut buf = ReadBuffer::new();
        buf.as_bytes_mut().extend_from_slice(b"abc");
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_slice(), b"abc");
    }

    #[test]
    fn read_buffer_with_target_capacity_equals_target() {
        let buf = ReadBuffer::with_target(256);
        assert_eq!(buf.remaining(), 256);
        assert!(buf.is_empty());
        assert!(!buf.is_complete());
    }

    // ============= YieldBuffer: empty data =============

    #[test]
    fn yield_buffer_empty_data_is_immediately_exhausted() {
        let mut buf = YieldBuffer::new(Bytes::from_static(b""));
        assert!(buf.is_empty());
        assert_eq!(buf.remaining(), 0);
        let mut dst = [0u8; 1];
        assert_eq!(buf.copy_to(&mut dst), 0);
    }

    #[test]
    fn yield_buffer_as_slice_on_empty_is_empty() {
        let buf = YieldBuffer::new(Bytes::from_static(b""));
        assert_eq!(buf.as_slice(), b"");
    }

    // ============= HeaderBuffer: partial fill as_slice =============

    #[test]
    fn header_buffer_as_slice_returns_only_filled_portion() {
        let mut buf = HeaderBuffer::<6>::new();
        buf.unfilled_mut()[..3].copy_from_slice(b"abc");
        buf.advance(3);
        assert_eq!(buf.as_slice(), b"abc");
        assert_eq!(buf.remaining(), 3);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn read_buffer_extend_then_take_preserves_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            let mut buf = ReadBuffer::new();
            buf.extend(&data);
            let taken = buf.take();
            prop_assert_eq!(&taken[..], &data[..]);
        }

        #[test]
        fn read_buffer_take_exact_splits_correctly(
            prefix_len in 1usize..64,
            data in proptest::collection::vec(any::<u8>(), 65..256)
        ) {
            let mut buf = ReadBuffer::new();
            buf.extend(&data);
            let chunk = buf.take_exact(prefix_len);
            prop_assert!(chunk.is_some());
            prop_assert_eq!(&chunk.unwrap()[..], &data[..prefix_len]);
            prop_assert_eq!(buf.len(), data.len() - prefix_len);
        }

        #[test]
        fn write_buffer_extend_then_pending_preserves_order(
            data in proptest::collection::vec(any::<u8>(), 1..256)
        ) {
            let mut buf = WriteBuffer::with_max_size(65536);
            buf.extend(&data).unwrap();
            prop_assert_eq!(buf.pending(), &data[..]);
        }

        #[test]
        fn write_buffer_advance_reduces_pending(
            data in proptest::collection::vec(any::<u8>(), 10..256),
            advance in 1usize..9
        ) {
            // advance < data.len() guaranteed by ranges
            let mut buf = WriteBuffer::with_max_size(65536);
            buf.extend(&data).unwrap();
            buf.advance(advance.min(data.len() - 1));
            prop_assert_eq!(buf.pending(), &data[advance.min(data.len() - 1)..]);
        }

        #[test]
        fn header_buffer_advance_and_remaining_consistent(
            fill in 0usize..128
        ) {
            const N: usize = 128;
            let mut buf = HeaderBuffer::<N>::new();
            buf.advance(fill);
            prop_assert_eq!(buf.remaining(), N - fill);
            if fill >= N {
                prop_assert!(buf.is_complete());
            } else {
                prop_assert!(!buf.is_complete());
            }
        }
    }
}
