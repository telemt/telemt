//! Benchmarks for `src/proxy/client.rs::wrap_tls_application_record` (opt.md §4.5).
//!
//! The function lives inside a module with heavy tokio/Stats/ProxySharedState
//! dependencies, making `#[path]` inclusion infeasible. The body is copied
//! verbatim below for measurement only — it is never called from production.
//!
//! Source: `src/proxy/client.rs:148-167`.
//! Constants: `TLS_RECORD_APPLICATION` = 0x17, `TLS_VERSION` = [0x03, 0x03]
//! from `src/protocol/constants.rs:200,206`.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

const TLS_RECORD_APPLICATION: u8 = 0x17;
const TLS_VERSION: [u8; 2] = [0x03, 0x03];

// Measurement-only mirror of `src/proxy/client.rs:148-167`.
// Kept in sync manually — do not call from production.
fn wrap_tls_application_record(payload: &[u8]) -> Vec<u8> {
    let chunks = payload.len().div_ceil(u16::MAX as usize).max(1);
    let mut record = Vec::with_capacity(payload.len() + 5 * chunks);

    if payload.is_empty() {
        record.push(TLS_RECORD_APPLICATION);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&0u16.to_be_bytes());
        return record;
    }

    for chunk in payload.chunks(u16::MAX as usize) {
        record.push(TLS_RECORD_APPLICATION);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        record.extend_from_slice(chunk);
    }

    record
}

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_wrap_tls_application_record(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy/wrap_tls_application_record");

    let sizes: &[usize] = &[64, 512, 4_096, 16_384];

    for &size in sizes {
        let payload = vec![0xABu8; size];
        group.bench_function(format!("{size}"), |b| {
            b.iter(|| {
                let _ = black_box(wrap_tls_application_record(black_box(&payload)));
            });
        });
    }

    group.bench_function("empty_payload", |b| {
        b.iter(|| {
            let _ = black_box(wrap_tls_application_record(black_box(&[])));
        });
    });

    group.finish();
}

criterion_group! {
    name = wrap_tls;
    config = quick();
    targets = bench_wrap_tls_application_record
}

criterion_main!(wrap_tls);
