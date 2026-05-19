//! Benchmarks for `src/proxy/masking.rs` — `choose_interface_snapshot` (opt.md §5.5).
//!
//! The full `masking.rs` module depends on tokio `AsyncMutex`, `tracing`,
//! transport types, etc., making `#[path]` inclusion infeasible. Instead the
//! 4-line pure function is copied verbatim below for measurement only — it is
//! never called from production code.

#![allow(dead_code)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

// Measurement-only mirror of `src/proxy/masking.rs:508-514`.
// Kept in sync manually — do not call from production.
fn choose_interface_snapshot(previous: &[IpAddr], refreshed: Vec<IpAddr>) -> Vec<IpAddr> {
    if refreshed.is_empty() && !previous.is_empty() {
        return previous.to_vec();
    }
    refreshed
}

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_choose_interface_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("masking/choose_snapshot");

    let empty_prev: Vec<IpAddr> = vec![];
    let nonempty_prev: Vec<IpAddr> = (0..4)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .collect();
    let nonempty_refreshed: Vec<IpAddr> = (0..4)
        .map(|i| IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)))
        .collect();
    let large_prev: Vec<IpAddr> = (0..1000)
        .map(|i| IpAddr::V4(Ipv4Addr::new(172, 16, (i >> 8) as u8, i as u8)))
        .collect();

    group.bench_function("empty_refreshed_empty_previous", |b| {
        b.iter(|| {
            let _ = black_box(choose_interface_snapshot(
                black_box(&empty_prev),
                black_box(vec![]),
            ));
        });
    });

    group.bench_function("empty_refreshed_with_previous", |b| {
        b.iter(|| {
            let _ = black_box(choose_interface_snapshot(
                black_box(&nonempty_prev),
                black_box(vec![]),
            ));
        });
    });

    group.bench_function("nonempty_refreshed_empty_previous", |b| {
        b.iter(|| {
            let _ = black_box(choose_interface_snapshot(
                black_box(&empty_prev),
                black_box(nonempty_refreshed.clone()),
            ));
        });
    });

    group.bench_function("nonempty_refreshed_with_previous", |b| {
        b.iter(|| {
            let _ = black_box(choose_interface_snapshot(
                black_box(&nonempty_prev),
                black_box(nonempty_refreshed.clone()),
            ));
        });
    });

    // opt.md §5.5 hot spot: measures the `to_vec` clone cost for 1000 IPs
    // when refreshed is empty and previous is large.
    group.bench_function("large_vec_1000_ips_fallback", |b| {
        b.iter(|| {
            let _ = black_box(choose_interface_snapshot(
                black_box(&large_prev),
                black_box(vec![]),
            ));
        });
    });

    group.finish();
}

criterion_group! {
    name = masking;
    config = quick();
    targets = bench_choose_interface_snapshot
}

criterion_main!(masking);
