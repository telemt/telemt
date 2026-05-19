//! Crypto benchmarks for telemt's wrappers.
//!
//! Each benchmark exercises the public API of telemt's `crypto` module
//! (not the underlying crates directly) so that any wrapper overhead —
//! buffer allocation, in-place vs. allocating variants, key-schedule
//! rebuilds per call — shows up in the numbers.
//!
//! **Source layout note.** `telemt` is a binary-only crate (no `lib.rs`),
//! so we cannot do `use telemt::crypto::*` from a bench crate. Instead
//! we `#[path]`-include the relevant source files directly. This means
//! the bench compiles its own private copy of `error` and `crypto` —
//! that's fine for a benchmark (we measure the same code paths) and
//! crucially it keeps `src/` untouched so this whole feature lands as
//! a "no source impact" change.
//!
//! Tuned for short total runtime: three size points (small / mid / large),
//! reduced sample count, sub-second warm-up. A full `cargo bench` should
//! complete in a couple of minutes on a modern CPU, not double-digit ones.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

#[path = "../src/crypto/mod.rs"]
mod crypto;

use crate::crypto::{
    AesCbc, AesCtr, SecureRandom, crc32, crc32c, derive_middleproxy_keys, sha256, sha256_hmac,
};

const SIZES: &[usize] = &[64, 4096, 65_536];
// CBC: include 16 B (single block) — the AES key-schedule cost dominates
// at this size, so it is the point where caching the round-key schedule
// in the cipher struct (an obvious future optimization) would be most
// visible. Keeping the bench point here means a follow-up can prove the
// win with a `--baseline` comparison.
const CBC_SIZES: &[usize] = &[16, 64, 4096, 65_536];

fn quick() -> Criterion {
    // Criterion's defaults (3 s warm-up + 5 s measurement × 100 samples) are
    // overkill for CI-style sanity benches. These knobs cut a single bench
    // from ~8 s to ~1.5 s while staying above criterion's minimums.
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn buf(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xff) as u8).collect()
}

// ============= AES-256-CTR =============

fn bench_aes_ctr_apply_in_place(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes_ctr/apply_in_place");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let key = [0x11u8; 32];
            let iv = 0x4242_4242_4242_4242u128;
            b.iter_batched(
                || {
                    let cipher = AesCtr::new(&key, iv);
                    let data = buf(size);
                    (cipher, data)
                },
                |(mut cipher, mut data)| {
                    cipher.apply(black_box(&mut data));
                    black_box(data)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn bench_aes_ctr_encrypt_alloc(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes_ctr/encrypt_alloc");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let key = [0x11u8; 32];
            let iv = 0x4242_4242_4242_4242u128;
            let data = buf(size);
            b.iter_batched(
                || AesCtr::new(&key, iv),
                |mut cipher| black_box(cipher.encrypt(black_box(&data))),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn bench_aes_ctr_new(c: &mut Criterion) {
    c.bench_function("aes_ctr/new", |b| {
        let key = [0x77u8; 32];
        b.iter(|| {
            let _ = black_box(AesCtr::new(black_box(&key), black_box(0xdead_beefu128)));
        });
    });
}

// ============= AES-256-CBC =============

fn bench_aes_cbc_encrypt_alloc(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes_cbc/encrypt_alloc");
    for &size in CBC_SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let cipher = AesCbc::new([0x33u8; 32], [0x55u8; 16]);
            let data = buf(size);
            b.iter(|| {
                let _ = black_box(cipher.encrypt(black_box(&data)).unwrap());
            });
        });
    }
    g.finish();
}

fn bench_aes_cbc_decrypt_alloc(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes_cbc/decrypt_alloc");
    for &size in CBC_SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let cipher = AesCbc::new([0x33u8; 32], [0x55u8; 16]);
        let ciphertext = cipher.encrypt(&buf(size)).unwrap();
        g.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            let cipher = AesCbc::new([0x33u8; 32], [0x55u8; 16]);
            b.iter(|| {
                let _ = black_box(cipher.decrypt(black_box(ct)).unwrap());
            });
        });
    }
    g.finish();
}

fn bench_aes_cbc_encrypt_in_place(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes_cbc/encrypt_in_place");
    for &size in CBC_SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let cipher = AesCbc::new([0x33u8; 32], [0x55u8; 16]);
            let mut data = buf(size);
            b.iter(|| {
                cipher.encrypt_in_place(black_box(&mut data)).unwrap();
            });
        });
    }
    g.finish();
}

// ============= Hashes =============

fn bench_sha256(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha256");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let data = buf(size);
        g.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = black_box(sha256(black_box(data)));
            });
        });
    }
    g.finish();
}

fn bench_sha256_hmac(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha256_hmac");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let data = buf(size);
        let key = [0xa5u8; 32];
        g.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = black_box(sha256_hmac(black_box(&key), black_box(data)));
            });
        });
    }
    g.finish();
}

fn bench_crc32(c: &mut Criterion) {
    let mut g = c.benchmark_group("crc32");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let data = buf(size);
        g.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = black_box(crc32(black_box(data)));
            });
        });
    }
    g.finish();
}

fn bench_crc32c(c: &mut Criterion) {
    let mut g = c.benchmark_group("crc32c");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let data = buf(size);
        g.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = black_box(crc32c(black_box(data)));
            });
        });
    }
    g.finish();
}

// ============= SecureRandom =============

fn bench_secure_random_fill(c: &mut Criterion) {
    let mut g = c.benchmark_group("secure_random/fill");
    let rng = SecureRandom::new();
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut out = vec![0u8; size];
            b.iter(|| {
                rng.fill(black_box(&mut out));
            });
        });
    }
    g.finish();
}

fn bench_secure_random_bytes_alloc(c: &mut Criterion) {
    let mut g = c.benchmark_group("secure_random/bytes_alloc");
    let rng = SecureRandom::new();
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let _ = black_box(rng.bytes(black_box(size)));
            });
        });
    }
    g.finish();
}

fn bench_secure_random_u64(c: &mut Criterion) {
    let rng = SecureRandom::new();
    c.bench_function("secure_random/u64", |b| {
        b.iter(|| {
            let _ = black_box(rng.u64());
        });
    });
}

// ============= MiddleProxy KDF =============

fn bench_middleproxy_kdf(c: &mut Criterion) {
    c.bench_function("middleproxy/derive_keys", |b| {
        let nonce_srv = [0x11u8; 16];
        let nonce_clt = [0x22u8; 16];
        let clt_ts = 0x44332211u32.to_le_bytes();
        let srv_ip: &[u8] = &[149u8, 154, 175, 50];
        let clt_ip: &[u8] = &[10u8, 0, 0, 1];
        let clt_port = 0x1f90u16.to_le_bytes();
        let srv_port = 0x22b8u16.to_le_bytes();
        let secret = vec![0x55u8; 128];

        b.iter(|| {
            let _ = black_box(derive_middleproxy_keys(
                black_box(&nonce_srv),
                black_box(&nonce_clt),
                black_box(&clt_ts),
                Some(srv_ip),
                black_box(&clt_port),
                black_box(b"CLIENT"),
                Some(clt_ip),
                black_box(&srv_port),
                black_box(&secret),
                None,
                None,
            ));
        });
    });
}

criterion_group! {
    name = aes_ctr;
    config = quick();
    targets = bench_aes_ctr_apply_in_place, bench_aes_ctr_encrypt_alloc, bench_aes_ctr_new
}
criterion_group! {
    name = aes_cbc;
    config = quick();
    targets = bench_aes_cbc_encrypt_alloc, bench_aes_cbc_decrypt_alloc, bench_aes_cbc_encrypt_in_place
}
criterion_group! {
    name = hashes;
    config = quick();
    targets = bench_sha256, bench_sha256_hmac, bench_crc32, bench_crc32c
}
criterion_group! {
    name = secure_random;
    config = quick();
    targets = bench_secure_random_fill, bench_secure_random_bytes_alloc, bench_secure_random_u64
}
criterion_group! {
    name = middleproxy;
    config = quick();
    targets = bench_middleproxy_kdf
}

criterion_main!(aes_ctr, aes_cbc, hashes, secure_random, middleproxy);
