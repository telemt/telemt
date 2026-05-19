//! Benchmarks for hot-path masking classifier helpers from `src/proxy/masking.rs`.
//!
//! NOTE: helper bodies below are a manual copy of the corresponding
//! pure functions in `src/proxy/masking.rs`. Production and bench code
//! diverging from each other is technically possible but would only
//! affect bench accuracy (not runtime behaviour). Keep in sync.

#![allow(dead_code)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

// ── Pure helpers mirrored from src/proxy/masking.rs ──

fn is_http_probe(data: &[u8]) -> bool {
    // RFC 7540 section 3.5: HTTP/2 client preface starts with "PRI ".
    const HTTP_METHODS: [&[u8]; 10] = [
        b"GET ", b"POST", b"HEAD", b"PUT ", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE", b"PATCH",
        b"PRI ",
    ];

    if data.is_empty() {
        return false;
    }

    let window = &data[..data.len().min(16)];
    for method in HTTP_METHODS {
        if data.len() >= method.len() && window.starts_with(method) {
            return true;
        }

        if (2..=3).contains(&window.len()) && method.starts_with(window) {
            return true;
        }
    }

    false
}

fn next_mask_shape_bucket(total: usize, floor: usize, cap: usize) -> usize {
    if total == 0 || floor == 0 || cap < floor {
        return total;
    }

    if total >= cap {
        return total;
    }

    let mut bucket = floor;
    while bucket < total {
        match bucket.checked_mul(2) {
            Some(next) => bucket = next,
            None => return total,
        }
        if bucket > cap {
            return cap;
        }
    }
    bucket
}

fn detect_client_type(data: &[u8]) -> &'static str {
    if is_http_probe(data) {
        return "HTTP";
    }
    if data.len() > 3 && data[0] == 0x16 && data[1] == 0x03 {
        return "TLS-scanner";
    }
    if data.starts_with(b"SSH-") {
        return "SSH";
    }
    if data.len() < 10 {
        return "port-scanner";
    }
    "unknown"
}

// ── Benchmarks ──

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_detect_client_type_tls(c: &mut Criterion) {
    let data: Vec<u8> = {
        let mut v = vec![0x16, 0x03, 0x03, 0x01, 0x00];
        v.extend_from_slice(&[0u8; 256]);
        v
    };
    c.bench_function("masking/detect_client_type/tls_scanner", |b| {
        b.iter(|| detect_client_type(black_box(&data)))
    });
}

fn bench_detect_client_type_http(c: &mut Criterion) {
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    c.bench_function("masking/detect_client_type/http_get", |b| {
        b.iter(|| detect_client_type(black_box(data)))
    });
}

fn bench_detect_client_type_unknown(c: &mut Criterion) {
    let data = [0xAA; 64];
    c.bench_function("masking/detect_client_type/unknown_64b", |b| {
        b.iter(|| detect_client_type(black_box(&data)))
    });
}

fn bench_is_http_probe_short(c: &mut Criterion) {
    let data = b"GE";
    c.bench_function("masking/is_http_probe/partial_2b", |b| {
        b.iter(|| is_http_probe(black_box(data)))
    });
}

fn bench_is_http_probe_miss(c: &mut Criterion) {
    let data = [0xFF; 16];
    c.bench_function("masking/is_http_probe/miss_16b", |b| {
        b.iter(|| is_http_probe(black_box(&data)))
    });
}

fn bench_shape_bucket_mid(c: &mut Criterion) {
    c.bench_function("masking/next_mask_shape_bucket/mid_range", |b| {
        b.iter(|| next_mask_shape_bucket(black_box(1500), 512, 4096))
    });
}

fn bench_shape_bucket_over_cap(c: &mut Criterion) {
    c.bench_function("masking/next_mask_shape_bucket/over_cap", |b| {
        b.iter(|| next_mask_shape_bucket(black_box(8192), 512, 4096))
    });
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_detect_client_type_tls,
        bench_detect_client_type_http,
        bench_detect_client_type_unknown,
        bench_is_http_probe_short,
        bench_is_http_probe_miss,
        bench_shape_bucket_mid,
        bench_shape_bucket_over_cap,
}

criterion_main!(benches);
