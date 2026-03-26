use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, ReadBuf};

struct OneByteThenStall {
    sent: bool,
}

impl AsyncRead for OneByteThenStall {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.sent {
            self.sent = true;
            buf.put_slice(&[0x42]);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[tokio::test]
async fn stalling_client_terminates_at_idle_not_relay_timeout() {
    let reader = OneByteThenStall { sent: false };
    let started = Instant::now();

    let result = tokio::time::timeout(
        MASK_RELAY_TIMEOUT,
        consume_client_data(reader, MASK_BUFFER_SIZE * 4),
    )
    .await;

    assert!(
        result.is_ok(),
        "consume_client_data should complete by per-read idle timeout, not hit relay timeout"
    );

    let elapsed = started.elapsed();
    assert!(
        elapsed >= (MASK_RELAY_IDLE_TIMEOUT / 2),
        "consume_client_data returned too quickly for idle-timeout path: {elapsed:?}"
    );
    assert!(
        elapsed < MASK_RELAY_TIMEOUT,
        "consume_client_data waited full relay timeout ({elapsed:?}); \
         per-read idle timeout is missing"
    );
}

#[tokio::test]
async fn fast_reader_drains_to_eof() {
    let data = vec![0xAAu8; 32 * 1024];
    let reader = std::io::Cursor::new(data);

    tokio::time::timeout(MASK_RELAY_TIMEOUT, consume_client_data(reader, usize::MAX))
        .await
        .expect("consume_client_data did not complete for fast EOF reader");
}

#[tokio::test]
async fn io_error_terminates_cleanly() {
    struct ErrReader;

    impl AsyncRead for ErrReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "simulated reset",
            )))
        }
    }

    tokio::time::timeout(
        MASK_RELAY_TIMEOUT,
        consume_client_data(ErrReader, usize::MAX),
    )
    .await
    .expect("consume_client_data did not return on I/O error");
}
