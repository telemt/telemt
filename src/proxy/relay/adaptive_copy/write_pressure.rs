use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use super::super::io::SharedCounters;

/// Direct-only writer wrapper that exposes bounded backpressure signals.
pub(super) struct WritePressureIo<W> {
    inner: W,
    counters: Arc<SharedCounters>,
}

impl<W> WritePressureIo<W> {
    /// Wraps the client writer without changing its I/O or error contract.
    pub(super) fn new(inner: W, counters: Arc<SharedCounters>) -> Self {
        Self { inner, counters }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for WritePressureIo<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !buffer.is_empty() {
            this.counters
                .s2c_requested_bytes
                .fetch_add(buffer.len() as u64, Ordering::Relaxed);
        }
        match Pin::new(&mut this.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(written)) => {
                this.counters
                    .s2c_consecutive_pending_writes
                    .store(0, Ordering::Relaxed);
                if written < buffer.len() {
                    this.counters
                        .s2c_partial_writes
                        .fetch_add(1, Ordering::Relaxed);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                this.counters
                    .s2c_consecutive_pending_writes
                    .store(0, Ordering::Relaxed);
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                let _ = this.counters.s2c_consecutive_pending_writes.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| Some(current.saturating_add(1)),
                );
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
