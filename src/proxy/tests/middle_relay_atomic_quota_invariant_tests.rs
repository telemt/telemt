use super::*;
use crate::crypto::AesCtr;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

struct CountedWriter {
    write_calls: Arc<AtomicUsize>,
    fail_writes: bool,
}

impl CountedWriter {
    fn new(write_calls: Arc<AtomicUsize>, fail_writes: bool) -> Self {
        Self {
            write_calls,
            fail_writes,
        }
    }
}

impl AsyncWrite for CountedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_calls.fetch_add(1, Ordering::Relaxed);
        if this.fail_writes {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "forced write failure",
            )))
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn make_crypto_writer(inner: CountedWriter) -> CryptoWriter<CountedWriter> {
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(inner, AesCtr::new(&key, iv), 8 * 1024)
}

#[tokio::test]
async fn me_writer_write_fail_keeps_reserved_quota_and_tracks_fail_metrics() {
    let stats = Stats::new();
    let user = "middle-me-writer-no-rollback-user";
    let user_stats = stats.get_or_create_user_stats_handle(user);
    let write_calls = Arc::new(AtomicUsize::new(0));
    let mut writer = make_crypto_writer(CountedWriter::new(write_calls.clone(), true));
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);
    let payload = Bytes::from_static(&[0x11, 0x22, 0x33, 0x44, 0x55]);

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: payload.clone(),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(user_stats.as_ref()),
        Some(64),
        0,
        &bytes_me2c,
        11,
        true,
        false,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(_))),
        "write failure must propagate as I/O error"
    );
    assert!(
        write_calls.load(Ordering::Relaxed) > 0,
        "writer must be attempted after successful quota reservation"
    );
    assert_eq!(
        stats.get_user_quota_used(user),
        payload.len() as u64,
        "reserved quota must not roll back on write failure"
    );
    assert_eq!(
        stats.get_quota_write_fail_bytes_total(),
        payload.len() as u64,
        "write-fail byte metric must include failed payload size"
    );
    assert_eq!(
        stats.get_quota_write_fail_events_total(),
        1,
        "write-fail events metric must increment once"
    );
    assert_eq!(
        stats.get_user_total_octets(user),
        0,
        "telemetry octets_to should not advance when write fails"
    );
    assert_eq!(
        bytes_me2c.load(Ordering::Relaxed),
        0,
        "ME->C committed byte counter must not advance on write failure"
    );
}

#[tokio::test]
async fn me_writer_pre_write_quota_reject_happens_before_writer_poll() {
    let stats = Stats::new();
    let user = "middle-me-writer-precheck-user";
    let limit = 8u64;
    let user_stats = stats.get_or_create_user_stats_handle(user);
    stats.quota_charge_post_write(user_stats.as_ref(), limit);

    let write_calls = Arc::new(AtomicUsize::new(0));
    let mut writer = make_crypto_writer(CountedWriter::new(write_calls.clone(), false));
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[0xAA, 0xBB, 0xCC]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(user_stats.as_ref()),
        Some(limit),
        0,
        &bytes_me2c,
        12,
        true,
        false,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::DataQuotaExceeded { .. })),
        "pre-write quota rejection must return typed quota error"
    );
    assert_eq!(
        write_calls.load(Ordering::Relaxed),
        0,
        "writer must not be polled when pre-write quota reservation fails"
    );
    assert_eq!(
        stats.get_me_d2c_quota_reject_pre_write_total(),
        1,
        "pre-write quota reject metric must increment"
    );
    assert_eq!(
        stats.get_user_quota_used(user),
        limit,
        "failed pre-write reservation must keep previous quota usage unchanged"
    );
    assert_eq!(
        stats.get_quota_write_fail_bytes_total(),
        0,
        "write-fail bytes metric must stay unchanged on pre-write reject"
    );
    assert_eq!(
        stats.get_quota_write_fail_events_total(),
        0,
        "write-fail events metric must stay unchanged on pre-write reject"
    );
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}
