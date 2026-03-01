//! Stream traits and common types

#![allow(dead_code)]

use bytes::Bytes;
use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Extra metadata for frames
#[derive(Debug, Clone, Default)]
pub struct FrameMeta {
    /// Quick ACK requested
    pub quickack: bool,
    /// This is a simple ACK message
    pub simple_ack: bool,
    /// Skip sending this frame
    pub skip_send: bool,
}

impl FrameMeta {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_quickack(mut self) -> Self {
        self.quickack = true;
        self
    }
    
    pub fn with_simple_ack(mut self) -> Self {
        self.simple_ack = true;
        self
    }
}

/// Result of reading a frame
#[derive(Debug)]
pub enum ReadFrameResult {
    /// Frame data with metadata
    Frame(Bytes, FrameMeta),
    /// Connection closed
    Closed,
}

/// Trait for streams that wrap another stream
pub trait LayeredStream<U> {
    /// Get reference to upstream
    fn upstream(&self) -> &U;
    
    /// Get mutable reference to upstream
    fn upstream_mut(&mut self) -> &mut U;
    
    /// Consume self and return upstream
    fn into_upstream(self) -> U;
}

/// A split read half of a stream
pub struct ReadHalf<R> {
    inner: R,
}

impl<R> ReadHalf<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
    
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ReadHalf<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// A split write half of a stream
pub struct WriteHalf<W> {
    inner: W,
}

impl<W> WriteHalf<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
    
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for WriteHalf<W> {
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