//! Benchmarks for `src/stream/{buffer_pool,state,frame,frame_codec}`.
//!
//! Pins opt.md §2.1 (`BufferPool::get/return` on hot path) and §2.4
//! (`frame_codec` decode/encode + `split_to().freeze()` zero-copy path).
//!
//! `#[path]`-inlines `error`, `crypto`, `protocol`, and the four stream
//! files. No `src/` modifications.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

#[path = "../src/crypto/mod.rs"]
mod crypto;

// Only the constants we need — pulling in `protocol/mod.rs` whole drags
// in test-only `#[cfg(test)] mod security_tests;` includes that reference
// `crate::tls_front`, which doesn't exist in the bench crate.
mod protocol {
    #[path = "../../src/protocol/constants.rs"]
    pub mod constants;
}

mod stream {
    // `#[path]` inside an inline `mod` resolves relative to a virtual
    // `benches/stream/` directory, so we step up one more level.
    #[path = "../../src/stream/buffer_pool.rs"]
    pub mod buffer_pool;

    #[path = "../../src/stream/state.rs"]
    pub mod state;

    #[path = "../../src/stream/frame.rs"]
    pub mod frame;

    #[path = "../../src/stream/frame_codec.rs"]
    pub mod frame_codec;
}

use crate::crypto::SecureRandom;
use crate::protocol::constants::ProtoTag;
use crate::stream::buffer_pool::BufferPool;
use crate::stream::frame::{Frame, create_codec};
use crate::stream::frame_codec::{AbridgedCodec, IntermediateCodec, SecureCodec};
use crate::stream::state::{HeaderBuffer, ReadBuffer, WriteBuffer, YieldBuffer};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn buf_vec(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

const FRAME_SIZES: &[usize] = &[64, 1024, 16_384];

// ============= BufferPool (opt.md §2.1) =============

fn bench_buffer_pool(c: &mut Criterion) {
    let pool = Arc::new(BufferPool::with_config(8192, 64));
    pool.preallocate(32);

    c.bench_function("buffer_pool/get_then_drop_cycle", |b| {
        b.iter(|| {
            let buf = black_box(pool.get());
            drop(black_box(buf));
        });
    });

    c.bench_function("buffer_pool/try_get_hit", |b| {
        b.iter(|| {
            let buf = pool.try_get();
            drop(black_box(buf));
        });
    });

    // Force the pool empty and measure the miss path.
    let empty = Arc::new(BufferPool::with_config(8192, 64));
    c.bench_function("buffer_pool/get_cold", |b| {
        b.iter(|| {
            let buf = black_box(empty.get());
            drop(black_box(buf));
        });
    });
}

// ============= ReadBuffer / WriteBuffer / HeaderBuffer / YieldBuffer =============

fn bench_read_buffer(c: &mut Criterion) {
    let chunk = buf_vec(256);
    c.bench_function("state/read_buffer_extend_take_cycle", |b| {
        let mut rb = ReadBuffer::with_capacity(4096);
        b.iter(|| {
            rb.extend(black_box(&chunk));
            let _ = black_box(rb.take_exact(black_box(256)));
        });
    });
    c.bench_function("state/read_buffer_with_target_extend_complete", |b| {
        b.iter(|| {
            let mut rb = ReadBuffer::with_target(256);
            rb.extend(black_box(&chunk));
            let _ = black_box(rb.is_complete());
            let _ = black_box(rb.take());
        });
    });
}

fn bench_write_buffer(c: &mut Criterion) {
    let chunk = buf_vec(256);
    c.bench_function("state/write_buffer_extend_advance_cycle", |b| {
        let mut wb = WriteBuffer::with_max_size(64 * 1024);
        b.iter(|| {
            wb.extend(black_box(&chunk)).unwrap();
            let pending_len = wb.pending().len();
            wb.advance(black_box(pending_len));
        });
    });
}

fn bench_header_buffer(c: &mut Criterion) {
    let bytes = [0xAAu8; 16];
    c.bench_function("state/header_buffer_fill_take_cycle", |b| {
        let mut hb = HeaderBuffer::<16>::new();
        b.iter(|| {
            hb.unfilled_mut().copy_from_slice(black_box(&bytes));
            hb.advance(black_box(16));
            let _ = black_box(hb.take());
        });
    });
}

fn bench_yield_buffer(c: &mut Criterion) {
    let mut g = c.benchmark_group("state/yield_buffer_copy_to");
    for &n in &[256usize, 4096, 16_384] {
        let data = Bytes::from(buf_vec(n));
        g.throughput(Throughput::Bytes(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &data, |b, d| {
            let mut dst = vec![0u8; n];
            b.iter(|| {
                let mut yb = YieldBuffer::new(d.clone());
                let _ = black_box(yb.copy_to(black_box(&mut dst)));
            });
        });
    }
    g.finish();
}

// ============= frame_codec encode/decode (opt.md §2.4) =============
//
// The free `decode_*`/`encode_*` functions are private to the file, so
// we go through the public `FrameCodec` trait impls instead. Same code
// paths, observable via the trait dispatch.

fn bench_frame_codec_round_trips(c: &mut Criterion) {
    use crate::stream::frame::FrameCodec;
    let rng = Arc::new(SecureRandom::new());
    let abridged = AbridgedCodec::new();
    let intermediate = IntermediateCodec::new();
    let secure = SecureCodec::new(rng);

    let codecs: [(&str, &dyn FrameCodec); 3] = [
        ("abridged", &abridged),
        ("intermediate", &intermediate),
        ("secure", &secure),
    ];
    for (label, codec_ref) in codecs {
        let group_name = format!("frame_codec/{label}");
        let mut g = c.benchmark_group(&group_name);
        for &n in FRAME_SIZES {
            let payload = Bytes::from(buf_vec(n));
            let frame = Frame::new(payload.clone());
            g.throughput(Throughput::Bytes(n as u64));
            g.bench_with_input(BenchmarkId::new("encode", n), &frame, |b, f| {
                b.iter(|| {
                    let mut dst = BytesMut::with_capacity(n + 8);
                    codec_ref.encode(black_box(f), &mut dst).unwrap();
                    let _ = black_box(dst);
                });
            });
            let mut wire = BytesMut::with_capacity(n + 8);
            codec_ref.encode(&frame, &mut wire).unwrap();
            let wire = wire.freeze();
            g.bench_with_input(BenchmarkId::new("decode", n), &wire, |b, w| {
                b.iter(|| {
                    let mut src = BytesMut::from(&w[..]);
                    let _ = black_box(codec_ref.decode(black_box(&mut src)).unwrap());
                });
            });
        }
        g.finish();
    }
}

// ============= Box<dyn FrameCodec> dispatch (opt.md §7.2) =============

fn bench_codec_dispatch(c: &mut Criterion) {
    let rng = Arc::new(SecureRandom::new());
    let abridged = create_codec(ProtoTag::Abridged, rng.clone());
    let intermediate = create_codec(ProtoTag::Intermediate, rng.clone());
    let secure = create_codec(ProtoTag::Secure, rng.clone());

    let payload = Bytes::from(buf_vec(1024));
    let frame = Frame::new(payload);

    c.bench_function("codec_dispatch/encode_abridged_via_box_dyn", |b| {
        b.iter(|| {
            let mut dst = BytesMut::with_capacity(1100);
            abridged.encode(black_box(&frame), &mut dst).unwrap();
            let _ = black_box(dst);
        });
    });
    c.bench_function("codec_dispatch/encode_intermediate_via_box_dyn", |b| {
        b.iter(|| {
            let mut dst = BytesMut::with_capacity(1100);
            intermediate.encode(black_box(&frame), &mut dst).unwrap();
            let _ = black_box(dst);
        });
    });
    c.bench_function("codec_dispatch/encode_secure_via_box_dyn", |b| {
        b.iter(|| {
            let mut dst = BytesMut::with_capacity(1100);
            secure.encode(black_box(&frame), &mut dst).unwrap();
            let _ = black_box(dst);
        });
    });

    // Direct concrete-type encode for comparison.
    let abridged_concrete = AbridgedCodec::new();
    use crate::stream::frame::FrameCodec;
    c.bench_function("codec_dispatch/encode_abridged_concrete", |b| {
        b.iter(|| {
            let mut dst = BytesMut::with_capacity(1100);
            <AbridgedCodec as FrameCodec>::encode(&abridged_concrete, black_box(&frame), &mut dst)
                .unwrap();
            let _ = black_box(dst);
        });
    });
    let intermediate_concrete = IntermediateCodec::new();
    c.bench_function("codec_dispatch/encode_intermediate_concrete", |b| {
        b.iter(|| {
            let mut dst = BytesMut::with_capacity(1100);
            <IntermediateCodec as FrameCodec>::encode(
                &intermediate_concrete,
                black_box(&frame),
                &mut dst,
            )
            .unwrap();
            let _ = black_box(dst);
        });
    });
    let secure_concrete = SecureCodec::new(rng.clone());
    c.bench_function("codec_dispatch/encode_secure_concrete", |b| {
        b.iter(|| {
            let mut dst = BytesMut::with_capacity(1100);
            <SecureCodec as FrameCodec>::encode(&secure_concrete, black_box(&frame), &mut dst)
                .unwrap();
            let _ = black_box(dst);
        });
    });
}

criterion_group! {
    name = pool_and_buffers;
    config = quick();
    targets = bench_buffer_pool, bench_read_buffer, bench_write_buffer,
              bench_header_buffer, bench_yield_buffer
}
criterion_group! {
    name = codec;
    config = quick();
    targets = bench_frame_codec_round_trips, bench_codec_dispatch
}

criterion_main!(pool_and_buffers, codec);
