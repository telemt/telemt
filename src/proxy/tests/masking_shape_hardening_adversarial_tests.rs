use super::*;
use tokio::io::{AsyncReadExt, AsyncWrite, duplex, empty, sink};

struct CountingWriter {
    written: usize,
}

impl CountingWriter {
    fn new() -> Self {
        Self { written: 0 }
    }
}

impl AsyncWrite for CountingWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.written = self.written.saturating_add(buf.len());
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[test]
fn shape_bucket_clamps_to_cap_when_next_power_of_two_exceeds_cap() {
    let bucket = next_mask_shape_bucket(1200, 1000, 1500);
    assert_eq!(bucket, 1500);
}

#[test]
fn shape_bucket_never_drops_below_total_for_valid_ranges() {
    for total in [1usize, 32, 127, 512, 999, 1000, 1001, 1499, 1500, 1501] {
        let bucket = next_mask_shape_bucket(total, 1000, 1500);
        assert!(
            bucket >= total || total >= 1500,
            "bucket={bucket} total={total}"
        );
    }
}

#[tokio::test]
async fn maybe_write_shape_padding_writes_exact_delta() {
    let mut writer = CountingWriter::new();
    maybe_write_shape_padding(&mut writer, 1200, true, 1000, 1500, false, 0, false).await;
    assert_eq!(writer.written, 300);
}

#[tokio::test]
async fn maybe_write_shape_padding_skips_when_disabled() {
    let mut writer = CountingWriter::new();
    maybe_write_shape_padding(&mut writer, 1200, false, 1000, 1500, false, 0, false).await;
    assert_eq!(writer.written, 0);
}

#[tokio::test]
async fn relay_to_mask_applies_cap_clamped_padding_for_non_power_of_two_cap() {
    let initial = vec![0x16, 0x03, 0x01, 0x04, 0x00];
    let extra = vec![0xAB; 1195];

    let (client_reader, mut client_writer) = duplex(4096);
    let (mut mask_observer, mask_writer) = duplex(4096);

    let relay = tokio::spawn(async move {
        relay_to_mask(
            client_reader,
            sink(),
            empty(),
            mask_writer,
            &initial,
            true,
            1000,
            1500,
            false,
            0,
            false,
            5 * 1024 * 1024,
            MASK_RELAY_IDLE_TIMEOUT,
        )
        .await;
    });

    client_writer.write_all(&extra).await.unwrap();
    client_writer.shutdown().await.unwrap();

    relay.await.unwrap();

    let mut observed = Vec::new();
    mask_observer.read_to_end(&mut observed).await.unwrap();
    assert_eq!(observed.len(), 1500);
    assert_eq!(&observed[..5], &[0x16, 0x03, 0x01, 0x04, 0x00]);
    assert!(observed[5..1200].iter().all(|b| *b == 0xAB));
    assert_eq!(observed[1200..].len(), 300);
}

#[test]
fn shape_bucket_light_fuzz_monotonicity_and_bounds() {
    let floor = 512usize;
    let cap = 4096usize;
    let mut prev = 0usize;

    for step in 1usize..=3000 {
        let total = ((step * 37) ^ (step << 3)) % (cap + 512);
        let bucket = next_mask_shape_bucket(total, floor, cap);

        if total < cap {
            assert!(bucket >= total, "bucket={bucket} total={total}");
            assert!(bucket <= cap, "bucket={bucket} cap={cap}");
        } else {
            assert_eq!(bucket, total, "above-cap totals must remain unchanged");
        }

        if total >= prev {
            // For non-decreasing inputs, bucket class must not regress.
            let prev_bucket = next_mask_shape_bucket(prev, floor, cap);
            assert!(bucket >= prev_bucket || total >= cap);
        }

        prev = total;
    }
}
