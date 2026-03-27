use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Duration, Instant, timeout};

const PROD_CAP_BYTES: usize = 5 * 1024 * 1024;

struct FinitePatternReader {
    remaining: usize,
    chunk: usize,
    read_calls: Arc<AtomicUsize>,
}

impl FinitePatternReader {
    fn new(total: usize, chunk: usize, read_calls: Arc<AtomicUsize>) -> Self {
        Self {
            remaining: total,
            chunk,
            read_calls,
        }
    }
}

impl AsyncRead for FinitePatternReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);

        if self.remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let take = self.remaining.min(self.chunk).min(buf.remaining());
        if take == 0 {
            return Poll::Ready(Ok(()));
        }

        let fill = vec![0x5Au8; take];
        buf.put_slice(&fill);
        self.remaining -= take;
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct CountingWriter {
    written: usize,
}

impl AsyncWrite for CountingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written = self.written.saturating_add(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct NeverReadyReader;

impl AsyncRead for NeverReadyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

struct BudgetProbeReader {
    remaining: usize,
    total_read: Arc<AtomicUsize>,
}

impl BudgetProbeReader {
    fn new(total: usize, total_read: Arc<AtomicUsize>) -> Self {
        Self {
            remaining: total,
            total_read,
        }
    }
}

impl AsyncRead for BudgetProbeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let take = self.remaining.min(buf.remaining());
        if take == 0 {
            return Poll::Ready(Ok(()));
        }

        let fill = vec![0xA5u8; take];
        buf.put_slice(&fill);
        self.remaining -= take;
        self.total_read.fetch_add(take, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn positive_copy_with_production_cap_stops_exactly_at_budget() {
    let read_calls = Arc::new(AtomicUsize::new(0));
    let mut reader = FinitePatternReader::new(PROD_CAP_BYTES + (256 * 1024), 4096, read_calls);
    let mut writer = CountingWriter::default();

    let outcome = copy_with_idle_timeout(&mut reader, &mut writer, PROD_CAP_BYTES, true).await;

    assert_eq!(
        outcome.total, PROD_CAP_BYTES,
        "copy path must stop at explicit production cap"
    );
    assert_eq!(writer.written, PROD_CAP_BYTES);
    assert!(
        !outcome.ended_by_eof,
        "byte-cap stop must not be misclassified as EOF"
    );
}

#[tokio::test]
async fn negative_consume_with_zero_cap_performs_no_reads() {
    let read_calls = Arc::new(AtomicUsize::new(0));
    let reader = FinitePatternReader::new(1024, 64, Arc::clone(&read_calls));

    consume_client_data_with_timeout_and_cap(reader, 0).await;

    assert_eq!(
        read_calls.load(Ordering::Relaxed),
        0,
        "zero cap must return before reading attacker-controlled bytes"
    );
}

#[tokio::test]
async fn edge_copy_below_cap_reports_eof_without_overread() {
    let read_calls = Arc::new(AtomicUsize::new(0));
    let payload = 73 * 1024;
    let mut reader = FinitePatternReader::new(payload, 3072, read_calls);
    let mut writer = CountingWriter::default();

    let outcome = copy_with_idle_timeout(&mut reader, &mut writer, PROD_CAP_BYTES, true).await;

    assert_eq!(outcome.total, payload);
    assert_eq!(writer.written, payload);
    assert!(
        outcome.ended_by_eof,
        "finite upstream below cap must terminate via EOF path"
    );
}

#[tokio::test]
async fn adversarial_blackhat_never_ready_reader_is_bounded_by_timeout_guards() {
    let started = Instant::now();

    consume_client_data_with_timeout_and_cap(NeverReadyReader, PROD_CAP_BYTES).await;

    assert!(
        started.elapsed() < Duration::from_millis(350),
        "never-ready reader must be bounded by idle/relay timeout protections"
    );
}

#[tokio::test]
async fn integration_consume_path_honors_production_cap_for_large_payload() {
    let read_calls = Arc::new(AtomicUsize::new(0));
    let reader = FinitePatternReader::new(PROD_CAP_BYTES + (1024 * 1024), 8192, read_calls);

    let bounded = timeout(
        Duration::from_millis(350),
        consume_client_data_with_timeout_and_cap(reader, PROD_CAP_BYTES),
    )
    .await;

    assert!(
        bounded.is_ok(),
        "consume path with production cap must finish within bounded time"
    );
}

#[tokio::test]
async fn adversarial_consume_path_never_reads_beyond_declared_byte_cap() {
    let byte_cap = 5usize;
    let total_read = Arc::new(AtomicUsize::new(0));
    let reader = BudgetProbeReader::new(256 * 1024, Arc::clone(&total_read));

    consume_client_data_with_timeout_and_cap(reader, byte_cap).await;

    assert!(
        total_read.load(Ordering::Relaxed) <= byte_cap,
        "consume path must not read more than configured byte cap"
    );
}

#[tokio::test]
async fn light_fuzz_cap_and_payload_matrix_preserves_min_budget_invariant() {
    let mut seed = 0x1234_5678_9ABC_DEF0u64;

    for _case in 0..96u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let cap = ((seed & 0x3ffff) as usize).saturating_add(1);
        let payload = ((seed.rotate_left(11) & 0x7ffff) as usize).saturating_add(1);
        let chunk = (((seed >> 5) & 0x1fff) as usize).saturating_add(1);

        let read_calls = Arc::new(AtomicUsize::new(0));
        let mut reader = FinitePatternReader::new(payload, chunk, read_calls);
        let mut writer = CountingWriter::default();

        let outcome = copy_with_idle_timeout(&mut reader, &mut writer, cap, true).await;
        let expected = payload.min(cap);

        assert_eq!(
            outcome.total, expected,
            "copy total must match min(payload, cap) under fuzzed inputs"
        );
        assert_eq!(writer.written, expected);
        if payload <= cap {
            assert!(outcome.ended_by_eof);
        } else {
            assert!(!outcome.ended_by_eof);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_copy_tasks_with_production_cap_complete_without_leaks() {
    let workers = 8usize;
    let mut tasks = Vec::with_capacity(workers);

    for idx in 0..workers {
        tasks.push(tokio::spawn(async move {
            let read_calls = Arc::new(AtomicUsize::new(0));
            let mut reader = FinitePatternReader::new(
                PROD_CAP_BYTES + (idx + 1) * 4096,
                4096 + (idx * 257),
                read_calls,
            );
            let mut writer = CountingWriter::default();
            copy_with_idle_timeout(&mut reader, &mut writer, PROD_CAP_BYTES, true).await
        }));
    }

    timeout(Duration::from_secs(3), async {
        for task in tasks {
            let outcome = task.await.expect("stress task must not panic");
            assert_eq!(
                outcome.total, PROD_CAP_BYTES,
                "stress copy task must stay within production cap"
            );
            assert!(
                !outcome.ended_by_eof,
                "stress task should end due to cap, not EOF"
            );
        }
    })
    .await
    .expect("stress suite must complete in bounded time");
}
