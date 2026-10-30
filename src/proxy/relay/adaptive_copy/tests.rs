use super::*;
use crate::crypto::aes::AesCtr;
use crate::protocol::constants::MAX_TLS_CIPHERTEXT_SIZE;
use crate::stream::{CryptoWriter, FakeTlsWriter};
use std::future::Future;
use std::sync::Mutex;
use std::task::{Wake, Waker};

// Copy-loop error, backpressure, and wakeup invariants share these transport fixtures.
mod flow;

struct BurstReader {
    bytes: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl AsyncRead for BurstReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos == this.bytes.len() && !this.eof {
            return Poll::Pending;
        }
        let n = output.remaining().min(this.bytes.len() - this.pos);
        output.put_slice(&this.bytes[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

struct SinkState {
    bytes: Vec<u8>,
    allowance: usize,
    max_write: usize,
    waker: Option<Waker>,
    flushes: usize,
}

impl SinkState {
    fn new(allowance: usize, max_write: usize) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            bytes: Vec::new(),
            allowance,
            max_write,
            waker: None,
            flushes: 0,
        }))
    }
}

struct Sink(Arc<Mutex<SinkState>>);

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        if state.allowance == 0 {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = bytes.len().min(state.allowance).min(state.max_write);
        state.bytes.extend_from_slice(&bytes[..n]);
        state.allowance -= n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.lock().unwrap().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn plaintext(records: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    let mut offset = 0;
    while offset < records.len() {
        assert!(records.len() - offset >= 5, "incomplete TLS header");
        assert_eq!(&records[offset..offset + 3], &[0x17, 3, 3]);
        let n = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
        assert!(n <= MAX_TLS_CIPHERTEXT_SIZE);
        assert!(records.len() - offset - 5 >= n, "incomplete TLS payload");
        ciphertext.extend_from_slice(&records[offset + 5..offset + 5 + n]);
        offset += 5 + n;
    }
    AesCtr::new(&[7; 32], 9).apply(&mut ciphertext);
    ciphertext
}

#[tokio::test(start_paused = true)]
async fn adaptive_relay_flushes_faketls_tail_without_another_source_event() {
    let payload: Vec<_> = (0..65536).map(|i| (i % 251) as u8).collect();
    let sink = SinkState::new(usize::MAX, usize::MAX);
    let writer = CryptoWriter::new(
        FakeTlsWriter::new(Sink(Arc::clone(&sink))),
        AesCtr::new(&[7; 32], 9),
        65536,
    );
    let stats = Arc::new(Stats::new());
    let user = "adaptive-tail";
    let cancel = CancellationToken::new();
    let mut relay = Box::pin(relay_direct_adaptive(
        tokio::io::empty(),
        writer,
        BurstReader {
            bytes: payload.clone(),
            pos: 0,
            eof: false,
        },
        tokio::io::sink(),
        4096,
        65536,
        1,
        user,
        Arc::clone(&stats),
        stats.current_user_quota_handle(user),
        Some(1024 * 1024),
        None,
        Duration::from_secs(60),
        cancel.clone(),
        DirectBufferBudget::new(1024 * 1024),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(relay.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..3 {
        assert!(relay.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(stats.get_user_total_octets(user), payload.len() as u64);
    let delivered = plaintext(&sink.lock().unwrap().bytes);
    assert_eq!(
        delivered.len(),
        payload.len(),
        "accepted ciphertext must not await another read"
    );
    assert_eq!(delivered, payload);
    assert_eq!(stats.get_user_total_octets(user), payload.len() as u64);
    assert_eq!(stats.get_user_quota_used(user), payload.len() as u64);
    assert_eq!(
        sink.lock().unwrap().flushes,
        1,
        "idle polls must not repeat a completed flush"
    );
    cancel.cancel();
    assert!(matches!(
        relay.as_mut().poll(&mut cx),
        Poll::Ready(Err(ProxyError::UserDisabled { .. }))
    ));
}

#[tokio::test(start_paused = true)]
async fn adaptive_relay_keeps_quota_and_blocked_cancellation_limits() {
    for blocked in [false, true] {
        let payload = vec![29; 65536];
        let sink = SinkState::new(if blocked { 0 } else { usize::MAX }, usize::MAX);
        let writer = CryptoWriter::new(
            FakeTlsWriter::new(Sink(Arc::clone(&sink))),
            AesCtr::new(&[7; 32], 9),
            65536,
        );
        let stats = Arc::new(Stats::new());
        let user = "adaptive-limits";
        let cancel = CancellationToken::new();
        let budget = DirectBufferBudget::new(1024 * 1024);
        let limit = if blocked { 1024 * 1024 } else { 32768 };
        let mut relay = Box::pin(relay_direct_adaptive(
            tokio::io::empty(),
            writer,
            BurstReader {
                bytes: payload.clone(),
                pos: 0,
                eof: false,
            },
            tokio::io::sink(),
            4096,
            65536,
            1,
            user,
            Arc::clone(&stats),
            stats.current_user_quota_handle(user),
            Some(limit),
            None,
            Duration::from_secs(60),
            cancel.clone(),
            Arc::clone(&budget),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        let mut result = relay.as_mut().poll(&mut cx);
        if result.is_pending() {
            tokio::time::advance(Duration::from_millis(1)).await;
            result = relay.as_mut().poll(&mut cx);
        }
        if blocked {
            assert!(result.is_pending());
            assert_eq!(stats.get_user_total_octets(user), payload.len() as u64);
            assert!(sink.lock().unwrap().bytes.is_empty());
            cancel.cancel();
            assert!(matches!(
                relay.as_mut().poll(&mut cx),
                Poll::Ready(Err(ProxyError::UserDisabled { .. }))
            ));
        } else {
            assert!(matches!(
                result,
                Poll::Ready(Err(ProxyError::DataQuotaExceeded { .. }))
            ));
            assert_eq!(stats.get_user_quota_used(user), limit);
            assert_eq!(stats.get_user_total_octets(user), limit);
            assert_eq!(
                plaintext(&sink.lock().unwrap().bytes),
                payload[..limit as usize]
            );
        }
        assert_eq!(budget.snapshot().reserved_bytes, 0);
    }
}
