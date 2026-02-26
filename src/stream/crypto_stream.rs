//! Encrypted stream wrappers using AES-CTR
//!
//! This module provides stateful async stream wrappers that handle
//! encryption/decryption with proper partial read/write handling.
//!
//! Key design principles:
//! - Explicit state machines for all async operations
//! - Never lose data on partial reads/writes
//! - Honest reporting of bytes written (AsyncWrite contract)
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
//!   -> poll_write returns Poll::Pending
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

    pub fn get_ref(&self) -> &R {
        &self.upstream
    }

    pub fn get_mut(&mut self) -> &mut R {
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

    /// Read up to max_size bytes, returning decrypted bytes as Bytes.
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
        self.max_len.saturating_sub(self.buf.len())
    }

    fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());

        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            return;
        }

        // Compact when a large prefix was consumed.
        if self.pos >= 16 * 1024 {
            let _ = self.buf.split_to(self.pos);
            self.pos = 0;
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

    pub fn get_ref(&self) -> &W {
        &self.upstream
    }

    pub fn get_mut(&mut self) -> &mut W {
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

    pub fn has_pending(&self) -> bool {
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

    /// Encrypt plaintext into scratch (CTR advances by plaintext.len()).
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
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
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
