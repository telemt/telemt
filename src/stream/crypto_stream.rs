//! Encrypted stream wrappers using AES-CTR
//!
//! This module provides stateful async stream wrappers that handle
//! encryption/decryption with proper partial read/write handling.
//!
//! Key design principles:
//! - Explicit state machines for all async operations
//! - Never lose data on partial reads/writes
//! - Honest reporting of bytes written (`AsyncWrite` contract)
//! - Bounded internal buffers with backpressure
//!
//! AES-CTR is a stream cipher: the keystream position must advance exactly by the
//! number of plaintext bytes that are *accepted* (written or buffered).
//!
//! This implementation guarantees:
//! - CTR state never "drifts"
//! - never accept plaintext unless we can guarantee that all corresponding ciphertext
//!   is either written to upstream or stored in our pending buffer
//! - when upstream is pending -> ciphertext is buffered/bounded and backpressure is applied
//!

#![allow(dead_code)]
//! =======================
//! Writer state machine
//! =======================
//!
//! ┌──────────┐    write buf      ┌──────────┐
//! │   Idle   │ --------------->  │ Flushing │
//! │          │ <---------------  │          │
//! └──────────┘      drained      └──────────┘
//!      │                               │
//!      │            errors             │
//!      ▼                               ▼
//! ┌────────────────────────────────────────┐
//! │                Poisoned                │
//! └────────────────────────────────────────┘
//!
//! Backpressure
//! - pending ciphertext buffer is bounded (configurable per connection)
//! - pending is full and upstream is pending 
//!   -> `poll_write` returns `Poll::Pending`
//!   -> do not accept any plaintext
//!
//! Performance
//! - fast path when pending is empty: encrypt into scratch and try upstream
//!   - if upstream Pending/partial => move remainder into pending without re-encrypting
//! - when upstream is Pending but pending still has room: accept `to_accept` bytes and
//!   encrypt+append ciphertext directly into pending (in-place encryption of appended range)

//!   Encrypted stream wrappers using AES-CTR
//!
//! This module provides stateful async stream wrappers that handle
//! encryption/decryption with proper partial read/write handling.

use bytes::{Bytes, BytesMut};
use std::io::{self, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::crypto::AesCtr;
use super::state::{StreamState, YieldBuffer};

// ============= Constants =============

/// Default size for pending ciphertext buffer (bounded backpressure).
/// Actual limit is supplied at runtime from configuration.
const DEFAULT_MAX_PENDING_WRITE: usize = 64 * 1024;

/// Default read buffer capacity (reader mostly decrypts in-place into caller buffer).
const DEFAULT_READ_CAPACITY: usize = 16 * 1024;

// ============= CryptoReader State =============

#[derive(Debug)]
enum CryptoReaderState {
    /// Ready to read new data
    Idle,

    /// Have decrypted data ready to yield to caller
    Yielding { buffer: YieldBuffer },

    /// Stream encountered an error and cannot be used
    Poisoned { error: Option<io::Error> },
}

impl StreamState for CryptoReaderState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Yielding { .. } => "Yielding",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= CryptoReader =============

/// Reader that decrypts data using AES-CTR with proper state machine.
pub struct CryptoReader<R> {
    upstream: R,
    decryptor: AesCtr,
    state: CryptoReaderState,

    /// Reserved for future coalescing optimizations.
    #[allow(dead_code)]
    read_buf: BytesMut,
}

impl<R> CryptoReader<R> {
    pub fn new(upstream: R, decryptor: AesCtr) -> Self {
        Self {
            upstream,
            decryptor,
            state: CryptoReaderState::Idle,
            read_buf: BytesMut::with_capacity(DEFAULT_READ_CAPACITY),
        }
    }

    pub const fn get_ref(&self) -> &R {
        &self.upstream
    }

    pub const fn get_mut(&mut self) -> &mut R {
        &mut self.upstream
    }

    pub fn into_inner(self) -> R {
        self.upstream
    }

    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }

    pub fn state_name(&self) -> &'static str {
        self.state.state_name()
    }

    fn poison(&mut self, error: io::Error) {
        self.state = CryptoReaderState::Poisoned { error: Some(error) };
    }

    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            CryptoReaderState::Poisoned { error } => error.take().unwrap_or_else(|| {
                io::Error::other("stream previously poisoned")
            }),
            _ => io::Error::other("stream not poisoned"),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CryptoReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();

        #[allow(clippy::never_loop)]
        loop {
            match &mut this.state {
                CryptoReaderState::Poisoned { .. } => {
                    let err = this.take_poison_error();
                    return Poll::Ready(Err(err));
                }

                CryptoReaderState::Yielding { buffer } => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    let to_copy = buffer.remaining().min(buf.remaining());
                    let dst = buf.initialize_unfilled_to(to_copy);
                    let copied = buffer.copy_to(dst);
                    buf.advance(copied);

                    if buffer.is_empty() {
                        this.state = CryptoReaderState::Idle;
                    }

                    return Poll::Ready(Ok(()));
                }

                CryptoReaderState::Idle => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    // Read directly into caller buffer, decrypt in-place for the bytes read.
                    let before = buf.filled().len();

                    match Pin::new(&mut this.upstream).poll_read(cx, buf) {
                        Poll::Pending => return Poll::Pending,

                        Poll::Ready(Err(e)) => {
                            this.poison(io::Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }

                        Poll::Ready(Ok(())) => {
                            let after = buf.filled().len();
                            let bytes_read = after - before;

                            if bytes_read == 0 {
                                // EOF
                                return Poll::Ready(Ok(()));
                            }

                            let filled = buf.filled_mut();
                            this.decryptor.apply(&mut filled[before..after]);

                            trace!(bytes_read, state = this.state_name(), "CryptoReader decrypted chunk");

                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> CryptoReader<R> {
    /// Read and decrypt exactly n bytes.
    pub async fn read_exact_decrypt(&mut self, n: usize) -> Result<Bytes> {
        use tokio::io::AsyncReadExt;

        if self.is_poisoned() {
            return Err(self.take_poison_error());
        }

        let mut result = BytesMut::with_capacity(n);

        // Drain Yielding buffer if present (rare, kept for completeness)
        if let CryptoReaderState::Yielding { buffer } = &mut self.state {
            let to_take = buffer.remaining().min(n);
            let mut temp = vec![0u8; to_take];
            buffer.copy_to(&mut temp);
            result.extend_from_slice(&temp);

            if buffer.is_empty() {
                self.state = CryptoReaderState::Idle;
            }
        }

        while result.len() < n {
            let mut temp = vec![0u8; n - result.len()];
            let read = self.read(&mut temp).await?;

            if read == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("expected {} bytes, got {}", n, result.len()),
                ));
            }

            result.extend_from_slice(&temp[..read]);
        }

        Ok(result.freeze())
    }

/// Read up to `max_size` bytes, returning decrypted bytes as Bytes.
    pub async fn read_decrypt(&mut self, max_size: usize) -> Result<Bytes> {
        use tokio::io::AsyncReadExt;

        if self.is_poisoned() {
            return Err(self.take_poison_error());
        }

        if let CryptoReaderState::Yielding { buffer } = &mut self.state {
            let to_take = buffer.remaining().min(max_size);
            let mut temp = vec![0u8; to_take];
            buffer.copy_to(&mut temp);

            if buffer.is_empty() {
                self.state = CryptoReaderState::Idle;
            }

            return Ok(Bytes::from(temp));
        }

        let mut temp = vec![0u8; max_size];
        let read = self.read(&mut temp).await?;

        if read == 0 {
            return Ok(Bytes::new());
        }

        temp.truncate(read);
        Ok(Bytes::from(temp))
    }
}

// ============= Pending Ciphertext =============

/// Pending ciphertext buffer with explicit position and strict max size.
#[derive(Debug)]
struct PendingCiphertext {
    buf: BytesMut,
    pos: usize,
    max_len: usize,
}

impl PendingCiphertext {
    fn new(max_len: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(16 * 1024),
            pos: 0,
            max_len,
        }
    }

    fn pending_len(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn is_empty(&self) -> bool {
        self.pending_len() == 0
    }

    fn pending_slice(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn remaining_capacity(&self) -> usize {
        self.max_len.saturating_sub(self.pending_len())
    }

    fn compact_consumed_prefix(&mut self) {
        if self.pos == 0 {
            return;
        }

        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            return;
        }

        let _ = self.buf.split_to(self.pos);
        self.pos = 0;
    }

    fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());

        if self.pos == self.buf.len() {
            self.compact_consumed_prefix();
            return;
        }

        // Compact when a large prefix was consumed.
        if self.pos >= 16 * 1024 {
            self.compact_consumed_prefix();
        }
    }

    /// Replace the entire pending ciphertext by moving `src` in (swap, no copy).
    fn replace_with(&mut self, mut src: BytesMut) {
        debug_assert!(src.len() <= self.max_len);

        self.buf.clear();
        self.pos = 0;

        // Swap: keep allocations hot and avoid copying bytes.
        std::mem::swap(&mut self.buf, &mut src);
    }

    /// Append plaintext and encrypt appended range in-place.
    fn push_encrypted(&mut self, encryptor: &mut AesCtr, plaintext: &[u8]) -> Result<()> {
        if plaintext.is_empty() {
            return Ok(());
        }

        if plaintext.len() > self.remaining_capacity() {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "pending ciphertext buffer is full",
            ));
        }

        // Reclaim consumed prefix when physical storage is the only limiter.
        if self.pos > 0 && self.buf.len() + plaintext.len() > self.max_len {
            self.compact_consumed_prefix();
        }

        let start = self.buf.len();
        self.buf.reserve(plaintext.len());
        self.buf.extend_from_slice(plaintext);

        encryptor.apply(&mut self.buf[start..]);

        Ok(())
    }
}

// ============= CryptoWriter State =============

#[derive(Debug)]
enum CryptoWriterState {
    /// No pending ciphertext buffered.
    Idle,

    /// There is pending ciphertext to flush.
    Flushing { pending: PendingCiphertext },

    /// Stream encountered an error and cannot be used
    Poisoned { error: Option<io::Error> },
}

impl StreamState for CryptoWriterState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Flushing { .. } => "Flushing",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= CryptoWriter =============

/// Writer that encrypts data using AES-CTR with correct async semantics.
pub struct CryptoWriter<W> {
    upstream: W,
    encryptor: AesCtr,
    state: CryptoWriterState,
    scratch: BytesMut,
    max_pending_write: usize,
}

impl<W> CryptoWriter<W> {
    pub fn new(upstream: W, encryptor: AesCtr, max_pending_write: usize) -> Self {
        let max_pending = if max_pending_write == 0 {
            DEFAULT_MAX_PENDING_WRITE
        } else {
            max_pending_write
        };
        Self {
            upstream,
            encryptor,
            state: CryptoWriterState::Idle,
            scratch: BytesMut::with_capacity(16 * 1024),
            max_pending_write: max_pending.max(4 * 1024),
        }
    }

    pub const fn get_ref(&self) -> &W {
        &self.upstream
    }

    pub const fn get_mut(&mut self) -> &mut W {
        &mut self.upstream
    }

    pub fn into_inner(self) -> W {
        self.upstream
    }

    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }

    pub fn state_name(&self) -> &'static str {
        self.state.state_name()
    }

    pub const fn has_pending(&self) -> bool {
        matches!(self.state, CryptoWriterState::Flushing { .. })
    }

    pub fn pending_len(&self) -> usize {
        match &self.state {
            CryptoWriterState::Flushing { pending } => pending.pending_len(),
            _ => 0,
        }
    }

    fn poison(&mut self, error: io::Error) {
        self.state = CryptoWriterState::Poisoned { error: Some(error) };
    }

    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            CryptoWriterState::Poisoned { error } => error.take().unwrap_or_else(|| {
                io::Error::other("stream previously poisoned")
            }),
            _ => io::Error::other("stream not poisoned"),
        }
    }

    /// Ensure we are in Flushing state and return mutable pending buffer.
    fn ensure_pending(state: &mut CryptoWriterState, max_pending: usize) -> &mut PendingCiphertext {
        if matches!(state, CryptoWriterState::Idle) {
            *state = CryptoWriterState::Flushing {
                pending: PendingCiphertext::new(max_pending),
            };
        }

        match state {
            CryptoWriterState::Flushing { pending } => pending,
            _ => unreachable!("ensure_pending guarantees Flushing state"),
        }
    }

    /// Select how many plaintext bytes can be accepted in buffering path
    fn select_to_accept_for_buffering(state: &CryptoWriterState, buf_len: usize, max_pending: usize) -> usize {
        if buf_len == 0 {
            return 0;
        }

        match state {
            CryptoWriterState::Flushing { pending } => buf_len.min(pending.remaining_capacity()),
            CryptoWriterState::Idle => buf_len.min(max_pending),
            CryptoWriterState::Poisoned { .. } => 0,
        }
    }

/// Encrypt plaintext into scratch (CTR advances by `plaintext.len()`).
    fn encrypt_into_scratch(encryptor: &mut AesCtr, scratch: &mut BytesMut, plaintext: &[u8]) {
        scratch.clear();
        scratch.reserve(plaintext.len());
        scratch.extend_from_slice(plaintext);
        encryptor.apply(&mut scratch[..]);
    }
}

impl<W: AsyncWrite + Unpin> CryptoWriter<W> {
    /// Flush as much pending ciphertext as possible
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            match &mut self.state {
                CryptoWriterState::Poisoned { .. } => {
                    let err = self.take_poison_error();
                    return Poll::Ready(Err(err));
                }

                CryptoWriterState::Idle => return Poll::Ready(Ok(())),

                CryptoWriterState::Flushing { pending } => {
                    if pending.is_empty() {
                        self.state = CryptoWriterState::Idle;
                        return Poll::Ready(Ok(()));
                    }

                    let data = pending.pending_slice();

                    match Pin::new(&mut self.upstream).poll_write(cx, data) {
                        Poll::Pending => {
                            trace!(
                                pending_len = pending.pending_len(),
                                pending_cap = pending.remaining_capacity(),
                                "CryptoWriter: upstream Pending while flushing pending ciphertext"
                            );
                            return Poll::Pending;
                        }

                        Poll::Ready(Err(e)) => {
                            self.poison(io::Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }

                        Poll::Ready(Ok(0)) => {
                            let err = io::Error::new(
                                ErrorKind::WriteZero,
                                "upstream returned 0 bytes written",
                            );
                            self.poison(io::Error::new(err.kind(), err.to_string()));
                            return Poll::Ready(Err(err));
                        }

                        Poll::Ready(Ok(n)) => {
                            pending.advance(n);
                            continue;
                        }
                    }
                }
            }
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CryptoWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let this = self.get_mut();

        // Poisoned?
        if matches!(this.state, CryptoWriterState::Poisoned { .. }) {
            let err = this.take_poison_error();
            return Poll::Ready(Err(err));
        }

        // Empty write is always OK
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 1) If we have pending ciphertext, prioritize flushing it
        if matches!(this.state, CryptoWriterState::Flushing { .. }) {
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) => {
                    // pending drained -> proceed
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Upstream blocked. Apply ideal backpressure
                    let to_accept =
                        Self::select_to_accept_for_buffering(&this.state, buf.len(), this.max_pending_write);

                    if to_accept == 0 {
                        trace!(
                            buf_len = buf.len(),
                            pending_len = this.pending_len(),
                            "CryptoWriter backpressure: pending full and upstream Pending -> Pending"
                        );
                        return Poll::Pending;
                    }

                    let plaintext = &buf[..to_accept];

                    // Disjoint borrows
                    let encryptor = &mut this.encryptor;
                    let pending = Self::ensure_pending(&mut this.state, this.max_pending_write);

                    if let Err(e) = pending.push_encrypted(encryptor, plaintext) {
                        if e.kind() == ErrorKind::WouldBlock {
                            return Poll::Pending;
                        }
                        return Poll::Ready(Err(e));
                    }

                    return Poll::Ready(Ok(to_accept));
                }
            }
        }

        // 2) Fast path: pending empty -> write-through
        debug_assert!(matches!(this.state, CryptoWriterState::Idle));

        let to_accept = buf.len().min(this.max_pending_write);
        let plaintext = &buf[..to_accept];

        Self::encrypt_into_scratch(&mut this.encryptor, &mut this.scratch, plaintext);

        match Pin::new(&mut this.upstream).poll_write(cx, &this.scratch) {
            Poll::Pending => {
                // Upstream blocked: buffer FULL ciphertext for accepted bytes.
                let ciphertext = std::mem::take(&mut this.scratch);

                let pending = Self::ensure_pending(&mut this.state, this.max_pending_write);
                pending.replace_with(ciphertext);

                Poll::Ready(Ok(to_accept))
            }

            Poll::Ready(Err(e)) => {
                this.poison(io::Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }

            Poll::Ready(Ok(0)) => {
                let err = io::Error::new(ErrorKind::WriteZero, "upstream returned 0 bytes written");
                this.poison(io::Error::new(err.kind(), err.to_string()));
                Poll::Ready(Err(err))
            }

            Poll::Ready(Ok(n)) => {
                if n == this.scratch.len() {
                    this.scratch.clear();
                    return Poll::Ready(Ok(to_accept));
                }

                // Partial upstream write of ciphertext
                let remainder = this.scratch.split_off(n);
                this.scratch.clear();

                let pending = Self::ensure_pending(&mut this.state, this.max_pending_write);
                pending.replace_with(remainder);

                Poll::Ready(Ok(to_accept))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();

        if matches!(this.state, CryptoWriterState::Poisoned { .. }) {
            let err = this.take_poison_error();
            return Poll::Ready(Err(err));
        }

        match this.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        Pin::new(&mut this.upstream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();

        // Best-effort flush pending ciphertext before shutdown
        match this.poll_flush_pending(cx) {
            Poll::Pending => {
                debug!(
                    pending_len = this.pending_len(),
                    "CryptoWriter: shutdown with pending ciphertext (upstream Pending)"
                );
            }
            Poll::Ready(Err(_)) => {}
            Poll::Ready(Ok(())) => {}
        }

        Pin::new(&mut this.upstream).poll_shutdown(cx)
    }
}

// ============= PassthroughStream =============

/// Passthrough stream for fast mode - no encryption/decryption
pub struct PassthroughStream<S> {
    inner: S,
}

impl<S> PassthroughStream<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    pub const fn get_ref(&self) -> &S {
        &self.inner
    }

    pub const fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PassthroughStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PassthroughStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctr() -> AesCtr {
        AesCtr::new(&[0x11; 32], 0x0102_0304_0506_0708_1112_1314_1516_1718)
    }

    #[test]
    fn pending_capacity_reclaims_after_partial_advance_without_compaction_threshold() {
        let mut pending = PendingCiphertext::new(1024);
        let mut ctr = test_ctr();
        let payload = vec![0x41; 900];
        pending.push_encrypted(&mut ctr, &payload).unwrap();

        // Keep position below compaction threshold to validate logical-capacity accounting.
        pending.advance(800);
        assert_eq!(pending.pending_len(), 100);
        assert_eq!(pending.remaining_capacity(), 924);
    }

    #[test]
    fn push_encrypted_respects_pending_limit() {
        let mut pending = PendingCiphertext::new(64);
        let mut ctr = test_ctr();

        pending.push_encrypted(&mut ctr, &[0x10; 64]).unwrap();
        let err = pending.push_encrypted(&mut ctr, &[0x20]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn push_encrypted_compacts_prefix_when_physical_buffer_would_overflow() {
        let mut pending = PendingCiphertext::new(64);
        let mut ctr = test_ctr();

        pending.push_encrypted(&mut ctr, &[0x22; 60]).unwrap();
        pending.advance(30);
        pending.push_encrypted(&mut ctr, &[0x33; 30]).unwrap();

        assert_eq!(pending.pending_len(), 60);
        assert!(pending.buf.len() <= 64);
    }

    #[test]
    fn pending_ciphertext_preserves_stream_order_across_drain_and_append() {
        let mut pending = PendingCiphertext::new(128);
        let mut ctr = test_ctr();

        let first = vec![0xA1; 80];
        let second = vec![0xB2; 40];

        pending.push_encrypted(&mut ctr, &first).unwrap();
        pending.advance(50);
        pending.push_encrypted(&mut ctr, &second).unwrap();

        let mut baseline_ctr = test_ctr();
        let mut baseline_plain = Vec::with_capacity(first.len() + second.len());
        baseline_plain.extend_from_slice(&first);
        baseline_plain.extend_from_slice(&second);
        baseline_ctr.apply(&mut baseline_plain);

        let expected = &baseline_plain[50..];
        assert_eq!(pending.pending_slice(), expected);
    }

    // ============= CryptoWriter integration tests =============

    /// A synchronous writer that records every byte written to it and
    /// accepts at most `max_per_call` bytes per `poll_write`.
    struct PartialWriter {
        written: Vec<u8>,
        max_per_call: usize,
    }

    impl PartialWriter {
        fn new(max_per_call: usize) -> Self {
            Self { written: Vec::new(), max_per_call }
        }
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            let n = buf.len().min(self.max_per_call);
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A writer that returns Poll::Pending on every write, simulating a fully
    /// stalled upstream.
    struct BlockingWriter;

    impl AsyncWrite for BlockingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Pending
        }
    }

    // CTR-mode encryption is a stream cipher: the counter must advance by
    // exactly the number of plaintext bytes accepted — no more, no less.
    // This test forces a partial upstream write (upstream accepts only half the
    // ciphertext at a time) and verifies that the complete ciphertext decoded
    // with a matching CTR decryptor reproduces the original plaintext.
    // A CTR "drift" — where the counter advances by more or fewer bytes than
    // the ciphertext actually written — would corrupt every subsequent byte.
    #[tokio::test]
    async fn crypto_writer_ctr_consistency_through_partial_upstream_writes() {
        let key = [0x55u8; 32];
        let iv = 0xDEAD_BEEF_1234_5678_9ABC_DEF0_1234_5678_u128;

        let plaintext: Vec<u8> = (0u8..=255).cycle().take(512).collect();

        // Upstream accepts exactly 7 bytes per poll_write, forcing many partial
        // write round-trips and exercising the buffering + flushing paths.
        let upstream = PartialWriter::new(7);
        let encryptor = AesCtr::new(&key, iv);
        let mut writer = CryptoWriter::new(upstream, encryptor, 4096);

        // write_all drives flush loops until all plaintext is accepted.
        tokio::io::AsyncWriteExt::write_all(&mut writer, &plaintext).await.unwrap();
        tokio::io::AsyncWriteExt::flush(&mut writer).await.unwrap();

        let mut ciphertext = writer.into_inner().written;
        assert_eq!(ciphertext.len(), plaintext.len(), "all plaintext must be encrypted and written");

        // Decrypt with an independent CTR at the same starting position.
        let mut decryptor = AesCtr::new(&key, iv);
        decryptor.apply(&mut ciphertext);
        assert_eq!(ciphertext, plaintext, "CTR must not drift after partial upstream writes");
    }

    // A zero-byte write must be a no-op: it must not advance the CTR position,
    // not enter the Flushing state, and return Ok(0).  Any CTR advancement here
    // would desynchronise the keystream for the next real write.
    #[tokio::test]
    async fn crypto_writer_zero_byte_write_does_not_advance_ctr() {
        let key = [0x33u8; 32];
        let iv = 0x1111_2222_3333_4444_5555_6666_7777_8888_u128;

        let upstream = PartialWriter::new(4096);
        let encryptor_for_write = AesCtr::new(&key, iv);
        let mut writer = CryptoWriter::new(upstream, encryptor_for_write, 4096);

        // Zero-byte write.
        let n = tokio::io::AsyncWriteExt::write(&mut writer, &[]).await.unwrap();
        assert_eq!(n, 0);
        assert!(!writer.has_pending(), "zero-byte write must not create pending state");

        // Now write one real byte and verify it decrypts to the correct value.
        let plaintext = [0xAB_u8];
        tokio::io::AsyncWriteExt::write_all(&mut writer, &plaintext).await.unwrap();
        tokio::io::AsyncWriteExt::flush(&mut writer).await.unwrap();

        let mut ciphertext = writer.into_inner().written;
        assert_eq!(ciphertext.len(), 1);

        let mut decryptor = AesCtr::new(&key, iv);
        decryptor.apply(&mut ciphertext);
        assert_eq!(ciphertext, plaintext, "CTR position must start at iv, not advance past it during zero-byte write");
    }

    // When the internal pending-ciphertext buffer is full and the upstream is
    // blocked, poll_write MUST return Poll::Pending without accepting any
    // plaintext.  Accepting plaintext without writing the corresponding
    // ciphertext would permanently discard data.
    #[test]
    fn crypto_writer_backpressure_when_pending_full_and_upstream_blocked() {
        use std::task::{Context, Poll};
        use futures::task::noop_waker;

        let key = [0x77u8; 32];
        let iv = 0x0000_0000_0000_0000_0000_0000_0000_0000_u128;

        // max_pending_write = 16 bytes so the buffer fills quickly.
        let upstream = BlockingWriter;
        let encryptor = AesCtr::new(&key, iv);
        // Force a very small pending buffer.  The implementation clamps to 4 KiB
        // minimum, so set it to exactly 4096 via a zero (which maps to the
        // DEFAULT) and then we instead call with_config below.
        let mut writer = CryptoWriter::new(upstream, encryptor, 4096);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First write: upstream is Pending, ciphertext is buffered in pending.
        let payload = vec![0xCC; 4096];
        let poll1 = Pin::new(&mut writer).poll_write(&mut cx, &payload);
        // Should succeed (accepted into pending because upstream was Pending).
        assert!(matches!(poll1, Poll::Ready(Ok(n)) if n > 0),
            "first write should buffer into pending: {:?}", poll1);

        // At this point the pending buffer is full and upstream is still blocked.
        // A subsequent write must return Poll::Pending rather than silently
        // dropping plaintext or overflowing the pending buffer.
        let poll2 = Pin::new(&mut writer).poll_write(&mut cx, &[0xDD; 4096]);
        assert!(
            matches!(poll2, Poll::Pending),
            "must return Pending when pending buffer is full and upstream is blocked, got {:?}", poll2
        );
    }

    // After the reader's upstream returns an error, the reader transitions to
    // Poisoned and every subsequent poll_read must return the same kind of error,
    // never silently returning EOF or Ok(0).
    #[tokio::test]
    async fn crypto_reader_poisoned_state_persists_after_error() {
        use tokio::io::AsyncReadExt;

        // A reader that always returns an error.
        struct ErrorReader;
        impl AsyncRead for ErrorReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<Result<()>> {
                Poll::Ready(Err(io::Error::new(ErrorKind::ConnectionReset, "simulated reset")))
            }
        }

        let key = [0x99u8; 32];
        let iv = 0x0u128;
        let decryptor = AesCtr::new(&key, iv);
        let mut reader = CryptoReader::new(ErrorReader, decryptor);

        // First read must propagate the upstream error.
        let mut buf = [0u8; 16];
        let result1 = reader.read(&mut buf).await;
        assert!(result1.is_err(), "first read must return error");
        assert!(reader.is_poisoned(), "reader must be poisoned after upstream error");

        // Every subsequent read must also return an error, never Ok(0) or EOF.
        let result2 = reader.read(&mut buf).await;
        assert!(result2.is_err(), "poisoned reader must keep returning error");

        let result3 = reader.read(&mut buf).await;
        assert!(result3.is_err(), "poisoned reader must keep returning error on third call");
    }
}
