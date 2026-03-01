//! Fake TLS 1.3 stream wrappers
//!
//! This module provides stateful async stream wrappers that handle TLS record
//! framing with proper partial read/write handling.
//!
//! These are "fake" TLS streams:
//! - We wrap raw bytes into syntactically valid TLS 1.3 records (Application Data).
//! - We DO NOT perform real TLS handshake/encryption.
//! - Real crypto for MTProto is handled by the crypto layer underneath.
//!
//! Why do we need this?
//! Telegram MTProto proxy "FakeTLS" mode uses a TLS-looking outer layer for
//! domain fronting / traffic camouflage. iOS Telegram clients are known to
//! produce slightly different TLS record sizing patterns than Android/Desktop,
//! including records that exceed 16384 payload bytes by a small overhead.
//!
//! Key design principles:
//! - Explicit state machines for all async operations
//! - Never lose data on partial reads
//! - Atomic TLS record formation for writes

#![allow(dead_code)]
//! - Proper handling of all TLS record types
//!
//! Important nuance (Telegram FakeTLS):
//! - The TLS spec limits "plaintext fragments" to 2^14 (16384) bytes.
//! - However, the on-the-wire record length can exceed 16384 because TLS 1.3
//!   uses AEAD and can include tag/overhead/padding.
//! - Telegram FakeTLS clients (notably iOS) may send Application Data records
//!   with length up to 16384 + 256 bytes (RFC 8446 §5.2). We accept that as
//!   MAX_TLS_CHUNK_SIZE.
//!
//! If you reject those (e.g. validate length <= 16384), you will see errors like:
//!   "TLS record too large: 16408 bytes"
//! and uploads from iOS will break (media/file sending), while small traffic
//! may still work.

use bytes::{Bytes, BytesMut};
use std::io::{self, Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::protocol::constants::{
    TLS_VERSION,
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER,
    TLS_RECORD_HANDSHAKE, TLS_RECORD_ALERT,
    MAX_TLS_CHUNK_SIZE,
};
use super::state::{StreamState, HeaderBuffer, YieldBuffer, WriteBuffer};

// ============= Constants =============

/// TLS record header size (type + version + length)
const TLS_HEADER_SIZE: usize = 5;

/// Maximum TLS fragment size we emit for Application Data.
/// Real TLS 1.3 allows up to 16384 + 256 bytes of ciphertext (incl. tag).
const MAX_TLS_PAYLOAD: usize = 16384 + 256;

/// Maximum pending write buffer for one record remainder.
/// Note: we never queue unlimited amount of data here; state holds at most one record.
const MAX_PENDING_WRITE: usize = 64 * 1024;

// ============= TLS Record Types =============

/// Parsed TLS record header (5 bytes)
#[derive(Debug, Clone, Copy)]
struct TlsRecordHeader {
    /// Record type (0x17 = Application Data, 0x14 = Change Cipher, etc.)
    record_type: u8,
    /// TLS version bytes
    version: [u8; 2],
    /// Payload length
    length: u16,
}

impl TlsRecordHeader {
    /// Parse header from exactly 5 bytes.
    ///
    /// This currently never returns None, but is kept as Option to allow future
    /// stricter parsing rules without changing callers.
    fn parse(header: &[u8; 5]) -> Option<Self> {
        let record_type = header[0];
        let version = [header[1], header[2]];
        let length = u16::from_be_bytes([header[3], header[4]]);
        Some(Self { record_type, version, length })
    }

    /// Validate the header.
    ///
    /// Nuances:
    /// - We accept TLS 1.0 header version for ClientHello-like records (0x03 0x01),
    ///   and TLS 1.2/1.3 style version bytes for the rest (we use TLS_VERSION = 0x03 0x03).
    /// - For Application Data, Telegram FakeTLS may send payload length up to
    ///   MAX_TLS_CHUNK_SIZE (16384 + 256).
    /// - For other record types we keep stricter bounds to avoid memory abuse.
    fn validate(&self) -> Result<()> {
        // Version: accept TLS 1.0 header (ClientHello quirk) and TLS_VERSION (0x0303).
        if self.version != [0x03, 0x01] && self.version != TLS_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid TLS version: {:02x?}", self.version),
            ));
        }

        let len = self.length as usize;

        // Length checks depend on record type.
        // Telegram FakeTLS: ApplicationData length may be 16384 + 256.
        match self.record_type {
            TLS_RECORD_APPLICATION => {
                if len > MAX_TLS_CHUNK_SIZE {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("TLS record too large: {} bytes (max {})", len, MAX_TLS_CHUNK_SIZE),
                    ));
                }
            }

            // ChangeCipherSpec/Alert/Handshake should never be that large for our usage
            // (post-handshake we don't expect Handshake at all).
            // Keep strict to reduce attack surface.
            _ => {
                if len > MAX_TLS_PAYLOAD {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("TLS control record too large: {} bytes (max {})", len, MAX_TLS_PAYLOAD),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Build header bytes
    fn to_bytes(self) -> [u8; 5] {
        [
            self.record_type,
            self.version[0],
            self.version[1],
            (self.length >> 8) as u8,
            self.length as u8,
        ]
    }
}

// ============= FakeTlsReader State =============

/// State machine states for FakeTlsReader
#[derive(Debug)]
enum TlsReaderState {
    /// Ready to read a new TLS record
    Idle,

    /// Reading the 5-byte TLS record header
    ReadingHeader {
        /// Header buffer (5 bytes)
        header: HeaderBuffer<TLS_HEADER_SIZE>,
    },

    /// Reading the TLS record body (payload)
    ReadingBody {
        record_type: u8,
        length: usize,
        buffer: BytesMut,
    },

    /// Have buffered data ready to yield to caller
    Yielding {
        buffer: YieldBuffer,
    },

    /// Stream encountered an error and cannot be used
    Poisoned {
        error: Option<io::Error>,
    },
}

impl StreamState for TlsReaderState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::ReadingHeader { .. } => "ReadingHeader",
            Self::ReadingBody { .. } => "ReadingBody",
            Self::Yielding { .. } => "Yielding",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= FakeTlsReader =============

/// Reader that unwraps TLS records (FakeTLS).
///
/// This wrapper is responsible ONLY for TLS record framing and skipping
/// non-data records (like CCS). It does not decrypt TLS: payload bytes are passed
/// as-is to upper layers (crypto stream).
///
/// State machine overview:
///
/// ┌──────────┐                    ┌───────────────┐
/// │   Idle   │ -----------------> │ ReadingHeader │
/// └──────────┘                    └───────┬───────┘
///      ▲                                  │
///      │                           header complete
///      │                                  │
///      │                                  ▼
///      │                          ┌───────────────┐
///      │        skip record       │  ReadingBody  │
///      │ <-------- (CCS) -------- │               │
///      │                          └───────┬───────┘
///      │                                  │
///      │                              body complete
///      │                                  ▼
///      │                          ┌───────────────┐
///      │                          │   Yielding    │
///      │                          └───────────────┘
///      │
///      │    errors / w any state
///      ▼
/// ┌───────────────────────────────────────────────┐
/// │                    Poisoned                   │
/// └───────────────────────────────────────────────┘
///
/// NOTE: We must correctly handle partial reads from upstream:
/// - do not assume header arrives in one poll
/// - do not assume body arrives in one poll
/// - never lose already-read bytes
pub struct FakeTlsReader<R> {
    upstream: R,
    state: TlsReaderState,
}

impl<R> FakeTlsReader<R> {
    pub fn new(upstream: R) -> Self {
        Self { upstream, state: TlsReaderState::Idle }
    }

    pub fn get_ref(&self) -> &R { &self.upstream }
    pub fn get_mut(&mut self) -> &mut R { &mut self.upstream }
    pub fn into_inner(self) -> R { self.upstream }

    pub fn is_poisoned(&self) -> bool { self.state.is_poisoned() }
    pub fn state_name(&self) -> &'static str { self.state.state_name() }

    fn poison(&mut self, error: io::Error) {
        self.state = TlsReaderState::Poisoned { error: Some(error) };
    }

    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            TlsReaderState::Poisoned { error } => error.take().unwrap_or_else(|| {
                io::Error::other("stream previously poisoned")
            }),
            _ => io::Error::other("stream not poisoned"),
        }
    }
}

enum HeaderPollResult {
    Pending,
    Eof,
    Complete(TlsRecordHeader),
    Error(io::Error),
}

enum BodyPollResult {
    Pending,
    Complete(Bytes),
    Error(io::Error),
}

impl<R: AsyncRead + Unpin> AsyncRead for FakeTlsReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();

        loop {
            // Take ownership of state to avoid borrow conflicts
            let state = std::mem::replace(&mut this.state, TlsReaderState::Idle);

            match state {
                // Poisoned state: always return the stored error
                TlsReaderState::Poisoned { error } => {
                    this.state = TlsReaderState::Poisoned { error: None };
                    let err = error.unwrap_or_else(|| {
                        io::Error::other("stream previously poisoned")
                    });
                    return Poll::Ready(Err(err));
                }

                // Yield buffered plaintext to caller
                TlsReaderState::Yielding { mut buffer } => {
                    if buf.remaining() == 0 {
                        this.state = TlsReaderState::Yielding { buffer };
                        return Poll::Ready(Ok(()));
                    }

                    let to_copy = buffer.remaining().min(buf.remaining());
                    let dst = buf.initialize_unfilled_to(to_copy);
                    let copied = buffer.copy_to(dst);
                    buf.advance(copied);

                    if buffer.is_empty() {
                        this.state = TlsReaderState::Idle;
                    } else {
                        this.state = TlsReaderState::Yielding { buffer };
                    }

                    return Poll::Ready(Ok(()));
                }

                // Start reading new record
                TlsReaderState::Idle => {
                    if buf.remaining() == 0 {
                        this.state = TlsReaderState::Idle;
                        return Poll::Ready(Ok(()));
                    }

                    this.state = TlsReaderState::ReadingHeader {
                        header: HeaderBuffer::new(),
                    };
                    // loop continues and will handle ReadingHeader
                }

                // Read TLS header (5 bytes)
                TlsReaderState::ReadingHeader { mut header } => {
                    let result = poll_read_header(&mut this.upstream, cx, &mut header);

                    match result {
                        HeaderPollResult::Pending => {
                            this.state = TlsReaderState::ReadingHeader { header };
                            return Poll::Pending;
                        }
                        HeaderPollResult::Eof => {
                            // Clean EOF at record boundary
                            this.state = TlsReaderState::Idle;
                            return Poll::Ready(Ok(()));
                        }
                        HeaderPollResult::Error(e) => {
                            this.poison(Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }
                        HeaderPollResult::Complete(parsed) => {
                            if let Err(e) = parsed.validate() {
                                this.poison(Error::new(e.kind(), e.to_string()));
                                return Poll::Ready(Err(e));
                            }

                            let length = parsed.length as usize;
                            this.state = TlsReaderState::ReadingBody {
                                record_type: parsed.record_type,
                                length,
                                buffer: BytesMut::with_capacity(length),
                            };
                        }
                    }
                }

                // Read TLS payload
                TlsReaderState::ReadingBody { record_type, length, mut buffer } => {
                    let result = poll_read_body(&mut this.upstream, cx, &mut buffer, length);

                    match result {
                        BodyPollResult::Pending => {
                            this.state = TlsReaderState::ReadingBody { record_type, length, buffer };
                            return Poll::Pending;
                        }
                        BodyPollResult::Error(e) => {
                            this.poison(Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }
                        BodyPollResult::Complete(data) => {
                            match record_type {
                                TLS_RECORD_CHANGE_CIPHER => {
                                    // CCS is expected in some clients, ignore it.
                                    this.state = TlsReaderState::Idle;
                                    continue;
                                }

                                TLS_RECORD_APPLICATION => {
                                    // This is what we actually want.
                                    if data.is_empty() {
                                        this.state = TlsReaderState::Idle;
                                        continue;
                                    }

                                    this.state = TlsReaderState::Yielding {
                                        buffer: YieldBuffer::new(data),
                                    };
                                    // loop continues and will yield immediately
                                }

                                TLS_RECORD_ALERT => {
                                    // Treat TLS alert as EOF-like termination.
                                    this.state = TlsReaderState::Idle;
                                    return Poll::Ready(Ok(()));
                                }

                                TLS_RECORD_HANDSHAKE => {
                                    // After FakeTLS handshake is done, we do not expect any Handshake records.
                                    let err = Error::new(ErrorKind::InvalidData, "unexpected TLS handshake record");
                                    this.poison(Error::new(err.kind(), err.to_string()));
                                    return Poll::Ready(Err(err));
                                }

                                _ => {
                                    let err = Error::new(
                                        ErrorKind::InvalidData,
                                        format!("unknown TLS record type: 0x{:02x}", record_type),
                                    );
                                    this.poison(Error::new(err.kind(), err.to_string()));
                                    return Poll::Ready(Err(err));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Poll to read and fill header buffer (standalone function to avoid borrow issues)
fn poll_read_header<R: AsyncRead + Unpin>(
    upstream: &mut R,
    cx: &mut Context<'_>,
    header: &mut HeaderBuffer<TLS_HEADER_SIZE>,
) -> HeaderPollResult {
    while !header.is_complete() {
        let unfilled = header.unfilled_mut();
        let mut read_buf = ReadBuf::new(unfilled);

        match Pin::new(&mut *upstream).poll_read(cx, &mut read_buf) {
            Poll::Pending => return HeaderPollResult::Pending,
            Poll::Ready(Err(e)) => return HeaderPollResult::Error(e),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    // EOF
                    if header.as_slice().is_empty() {
                        return HeaderPollResult::Eof;
                    } else {
                        return HeaderPollResult::Error(Error::new(
                            ErrorKind::UnexpectedEof,
                            format!(
                                "unexpected EOF in TLS header (got {} of 5 bytes)",
                                header.as_slice().len()
                            ),
                        ));
                    }
                }
                header.advance(n);
            }
        }
    }

    let header_bytes = *header.as_array();
    match TlsRecordHeader::parse(&header_bytes) {
        Some(h) => HeaderPollResult::Complete(h),
        None => HeaderPollResult::Error(Error::new(ErrorKind::InvalidData, "failed to parse TLS header")),
    }
}

/// Poll to read record body (standalone function to avoid borrow issues)
fn poll_read_body<R: AsyncRead + Unpin>(
    upstream: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    target_len: usize,
) -> BodyPollResult {
    // NOTE: This implementation uses a temporary Vec to avoid tricky borrow/lifetime
    // issues with BytesMut spare capacity and ReadBuf across polls.
    // It's safe and correct; optimization is possible if needed.
    while buffer.len() < target_len {
        let remaining = target_len - buffer.len();

        let mut temp = vec![0u8; remaining.min(8192)];
        let mut read_buf = ReadBuf::new(&mut temp);

        match Pin::new(&mut *upstream).poll_read(cx, &mut read_buf) {
            Poll::Pending => return BodyPollResult::Pending,
            Poll::Ready(Err(e)) => return BodyPollResult::Error(e),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return BodyPollResult::Error(Error::new(
                        ErrorKind::UnexpectedEof,
                        format!(
                            "unexpected EOF in TLS body (got {} of {} bytes)",
                            buffer.len(),
                            target_len
                        ),
                    ));
                }
                buffer.extend_from_slice(&temp[..n]);
            }
        }
    }

    BodyPollResult::Complete(buffer.split().freeze())
}

impl<R: AsyncRead + Unpin> FakeTlsReader<R> {
    /// Read exactly n bytes through TLS layer.
    ///
    /// This accumulates data across multiple TLS ApplicationData records.
    pub async fn read_exact(&mut self, n: usize) -> Result<Bytes> {
        if self.is_poisoned() {
            return Err(self.take_poison_error());
        }

        let mut result = BytesMut::with_capacity(n);

        while result.len() < n {
            let mut buf = vec![0u8; n - result.len()];
            let read = AsyncReadExt::read(self, &mut buf).await?;

            if read == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("expected {} bytes, got {}", n, result.len()),
                ));
            }

            result.extend_from_slice(&buf[..read]);
        }

        Ok(result.freeze())
    }
}

// ============= FakeTlsWriter State =============

#[derive(Debug)]
enum TlsWriterState {
    /// Ready to accept new data
    Idle,

    /// Writing a complete TLS record (header + body), possibly partially
    WritingRecord {
        record: WriteBuffer,
        payload_size: usize,
    },

    /// Stream encountered an error and cannot be used
    Poisoned {
        error: Option<io::Error>,
    },
}

impl StreamState for TlsWriterState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }

    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::WritingRecord { .. } => "WritingRecord",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= FakeTlsWriter =============

/// Writer that wraps bytes into TLS 1.3 Application Data records.
///
/// We chunk outgoing data into records of <= 16384 payload bytes (MAX_TLS_PAYLOAD).
/// We do not try to mimic AEAD overhead on the wire; Telegram clients accept it.
/// If you want to be more camouflage-accurate later, you could add optional padding
/// to produce records sized closer to MAX_TLS_CHUNK_SIZE.
pub struct FakeTlsWriter<W> {
    upstream: W,
    state: TlsWriterState,
}

impl<W> FakeTlsWriter<W> {
    pub fn new(upstream: W) -> Self {
        Self { upstream, state: TlsWriterState::Idle }
    }

    pub fn get_ref(&self) -> &W { &self.upstream }
    pub fn get_mut(&mut self) -> &mut W { &mut self.upstream }
    pub fn into_inner(self) -> W { self.upstream }

    pub fn is_poisoned(&self) -> bool { self.state.is_poisoned() }
    pub fn state_name(&self) -> &'static str { self.state.state_name() }

    pub fn has_pending(&self) -> bool {
        matches!(&self.state, TlsWriterState::WritingRecord { record, .. } if !record.is_empty())
    }

    fn poison(&mut self, error: io::Error) {
        self.state = TlsWriterState::Poisoned { error: Some(error) };
    }

    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            TlsWriterState::Poisoned { error } => error.take().unwrap_or_else(|| {
                io::Error::other("stream previously poisoned")
            }),
            _ => io::Error::other("stream not poisoned"),
        }
    }

    fn build_record(data: &[u8]) -> BytesMut {
        let header = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: data.len() as u16,
        };

        let mut record = BytesMut::with_capacity(TLS_HEADER_SIZE + data.len());
        record.extend_from_slice(&header.to_bytes());
        record.extend_from_slice(data);
        record
    }
}

enum FlushResult {
    Complete(usize),
    Pending,
    Error(io::Error),
}

impl<W: AsyncWrite + Unpin> FakeTlsWriter<W> {
    fn poll_flush_record_inner(
        upstream: &mut W,
        cx: &mut Context<'_>,
        record: &mut WriteBuffer,
    ) -> FlushResult {
        while !record.is_empty() {
            let data = record.pending();
            match Pin::new(&mut *upstream).poll_write(cx, data) {
                Poll::Pending => return FlushResult::Pending,
                Poll::Ready(Err(e)) => return FlushResult::Error(e),
                Poll::Ready(Ok(0)) => {
                    return FlushResult::Error(Error::new(
                        ErrorKind::WriteZero,
                        "upstream returned 0 bytes written",
                    ));
                }
                Poll::Ready(Ok(n)) => record.advance(n),
            }
        }

        FlushResult::Complete(0)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FakeTlsWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let this = self.get_mut();

        // Take ownership of state to avoid borrow conflicts.
        let state = std::mem::replace(&mut this.state, TlsWriterState::Idle);

        match state {
            TlsWriterState::Poisoned { error } => {
                this.state = TlsWriterState::Poisoned { error: None };
                let err = error.unwrap_or_else(|| {
                    Error::other("stream previously poisoned")
                });
                return Poll::Ready(Err(err));
            }

            TlsWriterState::WritingRecord { mut record, payload_size } => {
                // Finish writing previous record before accepting new bytes.
                match Self::poll_flush_record_inner(&mut this.upstream, cx, &mut record) {
                    FlushResult::Pending => {
                        this.state = TlsWriterState::WritingRecord { record, payload_size };
                        return Poll::Pending;
                    }
                    FlushResult::Error(e) => {
                        this.poison(Error::new(e.kind(), e.to_string()));
                        return Poll::Ready(Err(e));
                    }
                    FlushResult::Complete(_) => {
                        this.state = TlsWriterState::Idle;
                        // continue to accept new buf below
                    }
                }
            }

            TlsWriterState::Idle => {
                this.state = TlsWriterState::Idle;
            }
        }

        // Now in Idle state
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Chunk to maximum TLS payload size
        let chunk_size = buf.len().min(MAX_TLS_PAYLOAD);
        let chunk = &buf[..chunk_size];

        // Build the complete record (header + payload)
        let record_data = Self::build_record(chunk);

        match Pin::new(&mut this.upstream).poll_write(cx, &record_data) {
            Poll::Ready(Ok(n)) if n == record_data.len() => {
                Poll::Ready(Ok(chunk_size))
            }

            Poll::Ready(Ok(n)) => {
                // Partial write of the record: store remainder.
                let mut write_buffer = WriteBuffer::with_max_size(MAX_PENDING_WRITE);
                // record_data length is <= 16389, fits MAX_PENDING_WRITE
                let _ = write_buffer.extend(&record_data[n..]);

                this.state = TlsWriterState::WritingRecord {
                    record: write_buffer,
                    payload_size: chunk_size,
                };

                // We have accepted chunk_size bytes from caller.
                Poll::Ready(Ok(chunk_size))
            }

            Poll::Ready(Err(e)) => {
                this.poison(Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }

            Poll::Pending => {
                // Buffer entire record and report success for this chunk.
                let mut write_buffer = WriteBuffer::with_max_size(MAX_PENDING_WRITE);
                let _ = write_buffer.extend(&record_data);

                this.state = TlsWriterState::WritingRecord {
                    record: write_buffer,
                    payload_size: chunk_size,
                };

                Poll::Ready(Ok(chunk_size))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();

        let state = std::mem::replace(&mut this.state, TlsWriterState::Idle);

        match state {
            TlsWriterState::Poisoned { error } => {
                this.state = TlsWriterState::Poisoned { error: None };
                let err = error.unwrap_or_else(|| {
                    Error::other("stream previously poisoned")
                });
                return Poll::Ready(Err(err));
            }

            TlsWriterState::WritingRecord { mut record, payload_size } => {
                match Self::poll_flush_record_inner(&mut this.upstream, cx, &mut record) {
                    FlushResult::Pending => {
                        this.state = TlsWriterState::WritingRecord { record, payload_size };
                        return Poll::Pending;
                    }
                    FlushResult::Error(e) => {
                        this.poison(Error::new(e.kind(), e.to_string()));
                        return Poll::Ready(Err(e));
                    }
                    FlushResult::Complete(_) => {
                        this.state = TlsWriterState::Idle;
                    }
                }
            }

            TlsWriterState::Idle => {
                this.state = TlsWriterState::Idle;
            }
        }

        Pin::new(&mut this.upstream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();

        let state = std::mem::replace(&mut this.state, TlsWriterState::Idle);

        match state {
            TlsWriterState::WritingRecord { mut record, payload_size: _ } => {
                // Best-effort flush (do not block shutdown forever).
                let _ = Self::poll_flush_record_inner(&mut this.upstream, cx, &mut record);
                this.state = TlsWriterState::Idle;
            }
            _ => {
                this.state = TlsWriterState::Idle;
            }
        }

        Pin::new(&mut this.upstream).poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin> FakeTlsWriter<W> {
    /// Write all data wrapped in TLS records.
    ///
    /// Convenience method that chunks into <= 16384 records.
    pub async fn write_all_tls(&mut self, data: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < data.len() {
            let chunk_size = (data.len() - written).min(MAX_TLS_PAYLOAD);
            let chunk = &data[written..written + chunk_size];

            AsyncWriteExt::write_all(self, chunk).await?;
            written += chunk_size;
        }

        self.flush().await
    }
}

// ============= Tests =============

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    
    // ============= Test Helpers =============
    
    /// Build a valid TLS Application Data record
    fn build_tls_record(data: &[u8]) -> Vec<u8> {
        let mut record = vec![
            TLS_RECORD_APPLICATION,
            TLS_VERSION[0],
            TLS_VERSION[1],
            (data.len() >> 8) as u8,
            data.len() as u8,
        ];
        record.extend_from_slice(data);
        record
    }
    
    /// Build a Change Cipher Spec record
    fn build_ccs_record() -> Vec<u8> {
        vec![
            TLS_RECORD_CHANGE_CIPHER,
            TLS_VERSION[0],
            TLS_VERSION[1],
            0x00, 0x01,  // length = 1
            0x01,        // CCS byte
        ]
    }
    
    /// Mock reader that returns data in chunks
    struct ChunkedReader {
        data: VecDeque<u8>,
        chunk_size: usize,
    }
    
    impl ChunkedReader {
        fn new(data: &[u8], chunk_size: usize) -> Self {
            Self {
                data: data.iter().copied().collect(),
                chunk_size,
            }
        }
    }
    
    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            if self.data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            
            let to_read = self.chunk_size.min(self.data.len()).min(buf.remaining());
            for _ in 0..to_read {
                if let Some(byte) = self.data.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            
            Poll::Ready(Ok(()))
        }
    }
    
    // ============= FakeTlsReader Tests =============
    
    #[tokio::test]
    async fn test_tls_reader_single_record() {
        let payload = b"Hello, TLS!";
        let record = build_tls_record(payload);
        
        let reader = ChunkedReader::new(&record, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let buf = tls_reader.read_exact(payload.len()).await.unwrap();
        assert_eq!(&buf[..], payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_multiple_records() {
        let payload1 = b"First record";
        let payload2 = b"Second record";
        
        let mut data = build_tls_record(payload1);
        data.extend_from_slice(&build_tls_record(payload2));
        
        let reader = ChunkedReader::new(&data, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let buf1 = tls_reader.read_exact(payload1.len()).await.unwrap();
        assert_eq!(&buf1[..], payload1);
        
        let buf2 = tls_reader.read_exact(payload2.len()).await.unwrap();
        assert_eq!(&buf2[..], payload2);
    }
    
    #[tokio::test]
    async fn test_tls_reader_partial_header() {
        // Read header byte by byte
        let payload = b"Test";
        let record = build_tls_record(payload);
        
        let reader = ChunkedReader::new(&record, 1); // 1 byte at a time!
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let buf = tls_reader.read_exact(payload.len()).await.unwrap();
        
        assert_eq!(&buf[..], payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_partial_body() {
        let payload = b"This is a longer payload that will be read in parts";
        let record = build_tls_record(payload);
        
        let reader = ChunkedReader::new(&record, 7); // Awkward chunk size
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let buf = tls_reader.read_exact(payload.len()).await.unwrap();
        
        assert_eq!(&buf[..], payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_skip_ccs() {
        // CCS record followed by application data
        let mut data = build_ccs_record();
        let payload = b"After CCS";
        data.extend_from_slice(&build_tls_record(payload));
        
        let reader = ChunkedReader::new(&data, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let buf = tls_reader.read_exact(payload.len()).await.unwrap();
        
        assert_eq!(&buf[..], payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_multiple_ccs() {
        // Multiple CCS records
        let mut data = build_ccs_record();
        data.extend_from_slice(&build_ccs_record());
        let payload = b"After multiple CCS";
        data.extend_from_slice(&build_tls_record(payload));
        
        let reader = ChunkedReader::new(&data, 3); // Small chunks
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let buf = tls_reader.read_exact(payload.len()).await.unwrap();
        
        assert_eq!(&buf[..], payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_eof() {
        let reader = ChunkedReader::new(&[], 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 10];
        let read = tls_reader.read(&mut buf).await.unwrap();
        
        assert_eq!(read, 0);
    }
    
    #[tokio::test]
    async fn test_tls_reader_state_names() {
        let reader = ChunkedReader::new(&[], 100);
        let tls_reader = FakeTlsReader::new(reader);
        
        assert_eq!(tls_reader.state_name(), "Idle");
        assert!(!tls_reader.is_poisoned());
    }
    
    // ============= FakeTlsWriter Tests =============
    
    #[tokio::test]
    async fn test_tls_writer_single_write() {
        let (client, mut server) = duplex(4096);
        let mut writer = FakeTlsWriter::new(client);
        
        let payload = b"Hello, TLS!";
        writer.write_all(payload).await.unwrap();
        writer.flush().await.unwrap();
        
        // Read the TLS record from server
        let mut header = [0u8; 5];
        server.read_exact(&mut header).await.unwrap();
        
        assert_eq!(header[0], TLS_RECORD_APPLICATION);
        assert_eq!(&header[1..3], &TLS_VERSION);
        
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert_eq!(length, payload.len());
        
        let mut body = vec![0u8; length];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, payload);
    }
    
    #[tokio::test]
    async fn test_tls_writer_large_data_chunking() {
        let (client, mut server) = duplex(65536);
        let mut writer = FakeTlsWriter::new(client);
        
        // Write data larger than MAX_TLS_PAYLOAD
        let payload: Vec<u8> = (0..20000).map(|i| (i % 256) as u8).collect();
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
        
        // Read back - should be multiple records
        let mut received = Vec::new();
        let mut records_count = 0;
        
        while received.len() < payload.len() {
            let mut header = [0u8; 5];
            if server.read_exact(&mut header).await.is_err() {
                break;
            }
            
            assert_eq!(header[0], TLS_RECORD_APPLICATION);
            records_count += 1;
            
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert!(length <= MAX_TLS_PAYLOAD);
            
            let mut body = vec![0u8; length];
            server.read_exact(&mut body).await.unwrap();
            received.extend_from_slice(&body);
        }
        
        assert_eq!(received, payload);
        assert!(records_count >= 2); // Should have multiple records
    }
    
    #[tokio::test]
    async fn test_tls_stream_roundtrip() {
        let (client, server) = duplex(4096);
        
        let mut writer = FakeTlsWriter::new(client);
        let mut reader = FakeTlsReader::new(server);
        
        let original = b"Hello, fake TLS!";
        writer.write_all_tls(original).await.unwrap();
        writer.flush().await.unwrap();
        
        let received = reader.read_exact(original.len()).await.unwrap();
        assert_eq!(&received[..], original);
    }
    
    #[tokio::test]
    async fn test_tls_stream_roundtrip_large() {
        let (client, server) = duplex(4096);
        
        let mut writer = FakeTlsWriter::new(client);
        let mut reader = FakeTlsReader::new(server);
        
        let original: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();
        
        // Write in background
        let write_data = original.clone();
        let write_handle = tokio::spawn(async move {
            writer.write_all_tls(&write_data).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        
        // Read
        let mut received = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        
        write_handle.await.unwrap();
        assert_eq!(received, original);
    }
    
    #[tokio::test]
    async fn test_tls_writer_state_names() {
        let (client, _server) = duplex(4096);
        let writer = FakeTlsWriter::new(client);
        
        assert_eq!(writer.state_name(), "Idle");
        assert!(!writer.is_poisoned());
        assert!(!writer.has_pending());
    }
    
    // ============= Error Handling Tests =============
    
    #[tokio::test]
    async fn test_tls_reader_invalid_version() {
        let invalid_record = vec![
            TLS_RECORD_APPLICATION,
            0x04, 0x00,  // Invalid version
            0x00, 0x05,  // length = 5
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        
        let reader = ChunkedReader::new(&invalid_record, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 5];
        let result = tls_reader.read(&mut buf).await;
        
        assert!(result.is_err());
        assert!(tls_reader.is_poisoned());
    }
    
    #[tokio::test]
    async fn test_tls_reader_unexpected_eof_header() {
        // Partial header
        let partial = vec![TLS_RECORD_APPLICATION, 0x03];
        
        let reader = ChunkedReader::new(&partial, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 10];
        let result = tls_reader.read(&mut buf).await;
        
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_tls_reader_unexpected_eof_body() {
        // Valid header but truncated body
        let mut record = vec![
            TLS_RECORD_APPLICATION,
            TLS_VERSION[0], TLS_VERSION[1],
            0x00, 0x10,  // length = 16
        ];
        record.extend_from_slice(&[0u8; 8]); // Only 8 bytes of body
        
        let reader = ChunkedReader::new(&record, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 16];
        let result = tls_reader.read(&mut buf).await;
        
        assert!(result.is_err());
    }
    
    // ============= Header Parsing Tests =============
    
    #[test]
    fn test_tls_record_header_parse() {
        let header = [0x17, 0x03, 0x03, 0x01, 0x00];
        let parsed = TlsRecordHeader::parse(&header).unwrap();
        
        assert_eq!(parsed.record_type, TLS_RECORD_APPLICATION);
        assert_eq!(parsed.version, TLS_VERSION);
        assert_eq!(parsed.length, 256);
    }
    
    #[test]
    fn test_tls_record_header_validate() {
        let valid = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: 100,
        };
        assert!(valid.validate().is_ok());
        
        let invalid_version = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: [0x04, 0x00],
            length: 100,
        };
        assert!(invalid_version.validate().is_err());
        
        let too_large = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: 20000,
        };
        assert!(too_large.validate().is_err());
    }
    
    #[test]
    fn test_tls_record_header_to_bytes() {
        let header = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: 0x1234,
        };
        
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0x17, 0x03, 0x03, 0x12, 0x34]);
    }
}
