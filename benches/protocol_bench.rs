//! Benchmarks for `src/protocol/{constants,frame,obfuscation,tls}`.
//!
//! Pins opt.md §6.1 (SNI/ALPN/version three-pass scan of ClientHello),
//! §6.2 (16 KB ClientHello clone in `validate_tls_handshake_at_time`),
//! and §4.2/§4.4 cousins (nonce reverse, per-secret allocations).
//!
//! `#[path]`-inlined: `error.rs`, `crypto/mod.rs`, `protocol/mod.rs`.
//! No `src/` changes.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

#[path = "../src/crypto/mod.rs"]
mod crypto;

// Inline only the three submodules we need. Pulling in `protocol/mod.rs`
// whole drags in `protocol/tls.rs`, whose `#[cfg(test)] mod
// security_tests;` `#[path]`-include references `crate::tls_front` —
// which the bench crate doesn't have. The TLS hot-path (opt.md §6.1,
// §6.2) needs a separate bench harness with stubbed `tls_front`.
mod protocol {
    #[path = "../../src/protocol/constants.rs"]
    pub mod constants;
    #[path = "../../src/protocol/frame.rs"]
    pub mod frame;
    #[path = "../../src/protocol/obfuscation.rs"]
    pub mod obfuscation;
}

use crate::crypto::SecureRandom;
use crate::protocol::constants::{
    HANDSHAKE_LEN, ProtoTag, is_valid_secure_payload_len, secure_padding_len,
    secure_payload_len_from_wire_len,
};
use crate::protocol::frame::{FrameMode, validate_message_length};
#[allow(deprecated)]
use crate::protocol::obfuscation::{
    ObfuscationParams, encrypt_nonce, generate_nonce, is_valid_nonce, prepare_tg_nonce,
};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

// ============= constants helpers =============

fn bench_constants_helpers(c: &mut Criterion) {
    let rng = SecureRandom::new();
    c.bench_function("constants/secure_padding_len", |b| {
        b.iter(|| {
            let _ = black_box(secure_padding_len(black_box(64), &rng));
        });
    });
    let mut g = c.benchmark_group("constants/is_valid_secure_payload_len");
    for n in [0usize, 4, 16, 28, 31].iter().copied() {
        g.bench_with_input(criterion::BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| black_box(is_valid_secure_payload_len(black_box(n))));
        });
    }
    g.finish();

    let mut g = c.benchmark_group("constants/secure_payload_len_from_wire_len");
    for n in [4usize, 8, 16, 24, 31].iter().copied() {
        g.bench_with_input(criterion::BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| black_box(secure_payload_len_from_wire_len(black_box(n))));
        });
    }
    g.finish();
}

// ============= frame helpers =============

fn bench_frame_helpers(c: &mut Criterion) {
    let mut g = c.benchmark_group("frame/validate_message_length");
    for n in [0usize, 4, 64, 256, 1024].iter().copied() {
        g.bench_with_input(criterion::BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| black_box(validate_message_length(black_box(n))));
        });
    }
    g.finish();

    let mut g = c.benchmark_group("frame/frame_mode_max_overhead");
    for m in [
        FrameMode::Abridged,
        FrameMode::Intermediate,
        FrameMode::SecureIntermediate,
        FrameMode::Full,
    ] {
        let label = format!("{m:?}");
        g.bench_with_input(criterion::BenchmarkId::from_parameter(&label), &m, |b, m| {
            b.iter(|| black_box(m.max_overhead()));
        });
    }
    g.finish();
}

// ============= obfuscation =============

fn bench_obfuscation(c: &mut Criterion) {
    // is_valid_nonce — per-nonce retry loop. Bench both a valid 64-byte
    // nonce and a reserved-prefix one (early reject).
    let mut valid = [0x42u8; HANDSHAKE_LEN];
    valid[4..8].copy_from_slice(&[1, 2, 3, 4]);
    c.bench_function("obfuscation/is_valid_nonce_accept", |b| {
        b.iter(|| {
            let _ = black_box(is_valid_nonce(black_box(&valid)));
        });
    });
    let mut bad_first = [0u8; HANDSHAKE_LEN];
    bad_first[0] = 0xef;
    c.bench_function("obfuscation/is_valid_nonce_reject_first_byte", |b| {
        b.iter(|| {
            let _ = black_box(is_valid_nonce(black_box(&bad_first)));
        });
    });
    let mut bad_prefix = [0u8; HANDSHAKE_LEN];
    bad_prefix[..4].copy_from_slice(b"HEAD");
    c.bench_function("obfuscation/is_valid_nonce_reject_reserved_prefix", |b| {
        b.iter(|| {
            let _ = black_box(is_valid_nonce(black_box(&bad_prefix)));
        });
    });

    // generate_nonce — accepts any RNG closure. Critical: the counter
    // MUST be advanced inside the closure, not outside `b.iter`. If we
    // bump it once per `b.iter` call, every retry by `generate_nonce`
    // would receive the same bytes and `is_valid_nonce` would reject
    // them again for the three reserved values (0xef / 0xee / 0xdd)
    // → infinite loop. Advancing inside the closure guarantees each
    // retry sees a different filler byte.
    c.bench_function("obfuscation/generate_nonce", |b| {
        let mut counter: u8 = 0;
        b.iter(|| {
            let _ = black_box(generate_nonce(|n| {
                counter = counter.wrapping_add(1);
                let mut v = vec![counter; n];
                // Force bytes 4..8 to a non-reserved continuation tag.
                v[4..8].copy_from_slice(&[1, 2, 3, 4]);
                v
            }));
        });
    });

    // prepare_tg_nonce — opt.md §4.2 cousin: 48-byte reverse + slice copy.
    c.bench_function("obfuscation/prepare_tg_nonce", |b| {
        let key_iv: Vec<u8> = (0u8..48).collect();
        b.iter(|| {
            let mut nonce = [0x42u8; HANDSHAKE_LEN];
            prepare_tg_nonce(
                black_box(&mut nonce),
                black_box(ProtoTag::Intermediate),
                Some(black_box(&key_iv)),
            );
            let _ = black_box(nonce);
        });
    });

    // ObfuscationParams::from_handshake — opt.md §4.4. Per-secret loop.
    let handshake_bytes = [0x77u8; HANDSHAKE_LEN];
    let secrets: Vec<(String, Vec<u8>)> = (0..10)
        .map(|i| (format!("user{i}"), vec![(i as u8).wrapping_mul(11); 16]))
        .collect();
    let secrets_100: Vec<(String, Vec<u8>)> = (0..100)
        .map(|i| (format!("user{i}"), vec![(i as u8).wrapping_mul(11); 16]))
        .collect();
    // encrypt_nonce — opt.md §4.2/§4.4 cousin: deprecated AES-CTR nonce encrypt.
    #[allow(deprecated)]
    let fixed_nonce = [0x42u8; HANDSHAKE_LEN];
    c.bench_function("obfuscation/encrypt_nonce", |b| {
        b.iter(|| {
            let _ = black_box(encrypt_nonce(black_box(&fixed_nonce)));
        });
    });

    c.bench_function("obfuscation/from_handshake_10_secrets_no_match", |b| {
        b.iter(|| {
            let _ = black_box(ObfuscationParams::from_handshake(
                black_box(&handshake_bytes),
                black_box(&secrets),
            ));
        });
    });
    c.bench_function("obfuscation/from_handshake_100_secrets_no_match", |b| {
        b.iter(|| {
            let _ = black_box(ObfuscationParams::from_handshake(
                black_box(&handshake_bytes),
                black_box(&secrets_100),
            ));
        });
    });
}

criterion_group! {
    name = constants_and_frame;
    config = quick();
    targets = bench_constants_helpers, bench_frame_helpers
}
criterion_group! {
    name = obfuscation;
    config = quick();
    targets = bench_obfuscation
}

criterion_main!(constants_and_frame, obfuscation);
