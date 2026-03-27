use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::task::JoinSet;

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
            buf.put_slice(&[0xAA]);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[tokio::test]
async fn consume_stall_stress_finishes_within_idle_budget() {
    let mut set = JoinSet::new();
    let started = Instant::now();

    for _ in 0..64 {
        set.spawn(async {
            tokio::time::timeout(
                MASK_RELAY_TIMEOUT,
                consume_client_data(OneByteThenStall { sent: false }, usize::MAX),
            )
            .await
            .expect("consume_client_data exceeded relay timeout under stall load");
        });
    }

    while let Some(res) = set.join_next().await {
        res.unwrap();
    }

    // Under test constants idle=100ms, relay=200ms. 64 concurrent tasks stalling
    // for 100ms should complete well under a strict 600ms boundary.
    assert!(
        started.elapsed() < MASK_RELAY_TIMEOUT * 3,
        "stall stress batch completed too slowly; possible async executor starvation or head-of-line blocking"
    );
}

#[tokio::test]
async fn consume_zero_cap_returns_immediately() {
    let started = Instant::now();
    consume_client_data(tokio::io::empty(), 0).await;
    assert!(
        started.elapsed() < MASK_RELAY_IDLE_TIMEOUT,
        "zero byte cap must return immediately"
    );
}
