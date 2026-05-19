//! Network module benchmarks.
//!
//! `#[path]`-inlines `src/error.rs` and `src/network/dns_overrides.rs` so
//! the bench crate can call pure parser/lookup helpers without `lib.rs`.
//! Same "no source impact" rationale as `benches/crypto_bench.rs`.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

mod network {
    // `#[path]` inside an inline `mod` resolves relative to a virtual
    // `benches/network/` directory — step up one more `..`.
    #[path = "../../src/network/dns_overrides.rs"]
    pub mod dns_overrides;
}

use crate::network::dns_overrides::{
    install_entries, resolve, resolve_socket_addr, split_host_port, validate_entries,
};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

// ============= split_host_port =============

fn bench_split_host_port(c: &mut Criterion) {
    let mut g = c.benchmark_group("dns_overrides/split_host_port");
    let cases: &[(&str, &str)] = &[
        ("ipv4", "example.com:443"),
        ("ipv4_long", "very-long-hostname.subdomain.example.org:8443"),
        ("ipv6", "[2001:db8::1]:443"),
        ("ambiguous", "2001:db8::1:443"),
        ("upper", "EXAMPLE.COM:443"),
    ];
    for (label, input) in cases {
        g.bench_with_input(BenchmarkId::from_parameter(label), input, |b, s| {
            b.iter(|| {
                let _ = black_box(split_host_port(black_box(s)));
            });
        });
    }
    g.finish();
}

// ============= validate_entries =============

fn bench_validate_entries(c: &mut Criterion) {
    let mut g = c.benchmark_group("dns_overrides/validate_entries");
    for n in [1usize, 10, 100] {
        let entries: Vec<String> = (0..n)
            .map(|i| format!("host{i}.example:443:10.0.{}.{}", i / 256, i % 256))
            .collect();
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &entries, |b, e| {
            b.iter(|| {
                let _ = black_box(validate_entries(black_box(e)));
            });
        });
    }
    g.finish();
}

// ============= resolve (RwLock read) =============
//
// `install_entries` writes the global override store; we set it up once
// per benchmark run and measure the read-only path used by every
// outbound connection.
fn bench_resolve(c: &mut Criterion) {
    let entries: Vec<String> = (0..100)
        .map(|i| format!("host{i}.example:443:10.0.{}.{}", i / 256, i % 256))
        .collect();
    // Criterion runs benches sequentially, so global DNS_OVERRIDES state is safe here.
    install_entries(&entries).expect("install bench entries");

    let mut g = c.benchmark_group("dns_overrides/resolve");
    g.bench_function("hit", |b| {
        b.iter(|| {
            let _ = black_box(resolve(black_box("host42.example"), black_box(443)));
        });
    });
    g.bench_function("miss_host", |b| {
        b.iter(|| {
            let _ = black_box(resolve(black_box("nonexistent.example"), black_box(443)));
        });
    });
    g.bench_function("miss_port", |b| {
        b.iter(|| {
            let _ = black_box(resolve(black_box("host42.example"), black_box(80)));
        });
    });
    g.bench_function("socket_addr_hit", |b| {
        b.iter(|| {
            let _ = black_box(resolve_socket_addr(black_box("host42.example"), black_box(443)));
        });
    });
    g.finish();

    // Clean up to avoid leaking state between bench runs (criterion can
    // re-run within the same process).
    install_entries(&[]).expect("clear bench entries");
}

criterion_group! {
    name = dns_overrides;
    config = quick();
    targets = bench_split_host_port, bench_validate_entries, bench_resolve
}

criterion_main!(dns_overrides);
