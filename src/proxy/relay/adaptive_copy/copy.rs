use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Poll, ready};

use tokio::io::{AsyncBufRead, AsyncWrite};

/// Copies from the existing reader buffer, flushing accepted bytes when reads stall.
pub(super) async fn copy_with_flush<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncBufRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut copied = 0;
    let mut need_flush = false;
    poll_fn(|cx| {
        loop {
            let buffer = match Pin::new(&mut *reader).poll_fill_buf(cx) {
                Poll::Ready(result) => result?,
                Poll::Pending => {
                    // A writer can accept plaintext while retaining ciphertext. Its
                    // progress must not depend on another source read or eventual EOF.
                    if need_flush {
                        ready!(Pin::new(&mut *writer).poll_flush(cx))?;
                        need_flush = false;
                    }
                    return Poll::Pending;
                }
            };
            if buffer.is_empty() {
                ready!(Pin::new(&mut *writer).poll_flush(cx))?;
                return Poll::Ready(Ok(copied));
            }

            let written = ready!(Pin::new(&mut *writer).poll_write(cx, buffer))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            Pin::new(&mut *reader).consume(written);
            copied += written as u64;
            need_flush = true;
        }
    })
    .await
}
