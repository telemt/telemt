//! Benchmarks for `src/transport/middle_proxy/fairness/pressure.rs`.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

mod fairness {
    #[path = "../../src/transport/middle_proxy/fairness/model.rs"]
    pub mod model;
    #[path = "../../src/transport/middle_proxy/fairness/pressure.rs"]
    pub mod pressure;
}

use fairness::pressure::{PressureConfig, PressureEvaluator, PressureSignals};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn normal_signals() -> PressureSignals {
    PressureSignals {
        active_flows: 10,
        total_queued_bytes: 100,
        standing_flows: 0,
        backpressured_flows: 0,
    }
}

fn saturated_signals() -> PressureSignals {
    PressureSignals {
        active_flows: 10,
        total_queued_bytes: 950,
        standing_flows: 8,
        backpressured_flows: 9,
    }
}

fn bench_maybe_evaluate_normal(c: &mut Criterion) {
    let mut group = c.benchmark_group("pressure/maybe_evaluate/normal");
    let cfg = PressureConfig::default();
    let now = Instant::now();
    let sig = normal_signals();

    group.bench_function("low", |b| {
        b.iter_batched(
            || PressureEvaluator::new(now),
            |mut ev| black_box(ev.maybe_evaluate(now, &cfg, 1000, sig, true)),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_maybe_evaluate_saturated(c: &mut Criterion) {
    let mut group = c.benchmark_group("pressure/maybe_evaluate/saturated");
    let cfg = PressureConfig::default();
    let now = Instant::now();
    let sig = saturated_signals();

    group.bench_function("high", |b| {
        b.iter_batched(
            || PressureEvaluator::new(now),
            |mut ev| black_box(ev.maybe_evaluate(now, &cfg, 1000, sig, true)),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_note_admission_reject(c: &mut Criterion) {
    let mut group = c.benchmark_group("pressure/note_admission_reject");
    let cfg = PressureConfig::default();
    let now = Instant::now();

    group.bench_function("run", |b| {
        b.iter_batched(
            || PressureEvaluator::new(now),
            |mut ev| ev.note_admission_reject(now, &cfg),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_maybe_evaluate_normal,
        bench_maybe_evaluate_saturated,
        bench_note_admission_reject,
}

criterion_main!(benches);
