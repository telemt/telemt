use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::AsyncWrite;

struct NeverWritable;

impl AsyncWrite for NeverWritable {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn shape_padding_returns_before_global_mask_timeout_on_blocked_writer() {
    let mut writer = NeverWritable;
    let started = Instant::now();

    maybe_write_shape_padding(&mut writer, 1, true, 256, 4096, false, 0, false).await;

    assert!(
        started.elapsed() <= MASK_TIMEOUT + std::time::Duration::from_millis(30),
        "shape padding blocked past timeout budget"
    );
}

#[tokio::test]
async fn shape_padding_with_non_http_blur_disabled_at_cap_writes_nothing() {
    let mut output = Vec::new();
    {
        let mut writer = tokio::io::BufWriter::new(&mut output);
        maybe_write_shape_padding(&mut writer, 4096, true, 64, 4096, false, 128, false).await;
        use tokio::io::AsyncWriteExt;
        writer.flush().await.unwrap();
    }

    assert!(output.is_empty());
}
