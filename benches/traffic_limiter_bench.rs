//! Benchmarks for `src/proxy/traffic_limiter.rs` — token-bucket CAS hot path.
//!
//! Mirrors (approximate positions in `src/proxy/traffic_limiter.rs`):
//!   - `FAIR_EPOCH_MS`                  ~ line 16
//!   - `DirectionBucket::try_consume`   ~ line 126
//!   - `DirectionBucket::refund`        ~ line 159
//!   - `decrement_atomic_saturating`    ~ line 811
//!   - `bytes_per_epoch`                ~ line 835
//!
//! NOTE: helper bodies below are a manual copy of the corresponding
//! pure functions in `src/proxy/traffic_limiter.rs`. Production and bench
//! code diverging from each other is technically possible but would only
//! affect bench accuracy (not runtime behaviour). Keep in sync.
//!
//! `DirectionBucket::try_consume` / `refund` run on every relay byte-chunk.
//! The CAS loop is the critical performance gate. Structures are mirrored
//! verbatim with minimal deps for measurement only.

#![allow(dead_code)]

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

// ── Constants mirrored from traffic_limiter.rs ──

const FAIR_EPOCH_MS: u64 = 20;

// ── Pure math mirrors ──

fn bytes_per_epoch(bps: u64) -> u64 {
    if bps == 0 {
        return 0;
    }
    let numerator = bps.saturating_mul(FAIR_EPOCH_MS);
    let bytes = numerator.saturating_div(8_000);
    bytes.max(1)
}

fn limiter_epoch_start() -> &'static Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now)
}

fn current_epoch() -> u64 {
    let start = limiter_epoch_start();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    elapsed_ms / FAIR_EPOCH_MS
}

fn decrement_atomic_saturating(counter: &AtomicU64, by: u64) {
    if by == 0 {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return;
        }
        let next = current.saturating_sub(by);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

// ── DirectionBucket — mirrored ──

#[derive(Default)]
struct DirectionBucket {
    epoch: AtomicU64,
    used: AtomicU64,
}

impl DirectionBucket {
    fn sync_epoch(&self, epoch: u64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
        }
    }

    fn try_consume(&self, cap_bps: u64, requested: u64) -> u64 {
        if requested == 0 {
            return 0;
        }
        if cap_bps == 0 {
            return requested;
        }

        let epoch = current_epoch();
        self.sync_epoch(epoch);
        let cap_epoch = bytes_per_epoch(cap_bps);

        loop {
            let used = self.used.load(Ordering::Relaxed);
            if used >= cap_epoch {
                return 0;
            }
            let remaining = cap_epoch.saturating_sub(used);
            let grant = requested.min(remaining);
            if grant == 0 {
                return 0;
            }
            let next = used.saturating_add(grant);
            if self
                .used
                .compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return grant;
            }
        }
    }

    fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

// ── Benchmarks ──

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_try_consume_unlimited(c: &mut Criterion) {
    let bucket = DirectionBucket::default();
    c.bench_function("traffic_limiter/try_consume/unlimited_bps_0", |b| {
        b.iter(|| bucket.try_consume(black_box(0), black_box(1024)))
    });
}

fn bench_try_consume_under_cap(c: &mut Criterion) {
    c.bench_function("traffic_limiter/try_consume/under_cap_100Mbps", |b| {
        b.iter_batched(
            || DirectionBucket::default(),
            |bucket| bucket.try_consume(black_box(100_000_000), black_box(1024)),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_try_consume_sequential_no_contention(c: &mut Criterion) {
    c.bench_function(
        "traffic_limiter/try_consume/sequential_no_contention_10Mbps",
        |b| {
            b.iter_batched(
                DirectionBucket::default,
                |bucket| {
                    let mut total = 0u64;
                    for _ in 0..10 {
                        total += bucket.try_consume(black_box(10_000_000), black_box(256));
                    }
                    total
                },
                criterion::BatchSize::SmallInput,
            )
        },
    );
}

fn bench_try_consume_exhausted(c: &mut Criterion) {
    c.bench_function("traffic_limiter/try_consume/exhausted", |b| {
        b.iter_batched(
            || {
                let bucket = DirectionBucket::default();
                bucket.epoch.store(current_epoch(), Ordering::Relaxed);
                bucket.used.store(u64::MAX, Ordering::Relaxed);
                bucket
            },
            |bucket| bucket.try_consume(black_box(10_000_000), black_box(1024)),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_refund(c: &mut Criterion) {
    c.bench_function("traffic_limiter/refund/1KB", |b| {
        b.iter_batched(
            || {
                let bucket = DirectionBucket::default();
                bucket.used.store(10_000, Ordering::Relaxed);
                bucket
            },
            |bucket| bucket.refund(black_box(1024)),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_try_consume_unlimited,
        bench_try_consume_under_cap,
        bench_try_consume_sequential_no_contention,
        bench_try_consume_exhausted,
        bench_refund,
}

criterion_main!(benches);
