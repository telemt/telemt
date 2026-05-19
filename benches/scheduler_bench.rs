//! Benchmarks for `src/transport/middle_proxy/fairness/scheduler.rs`.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

mod protocol {
    pub mod constants {
        pub const RPC_FLAG_QUICKACK: u32 = 0x80000000;
    }
}

mod fairness {
    #[path = "../../src/transport/middle_proxy/fairness/model.rs"]
    pub mod model;
    #[path = "../../src/transport/middle_proxy/fairness/pressure.rs"]
    pub mod pressure;
    #[path = "../../src/transport/middle_proxy/fairness/scheduler.rs"]
    pub mod scheduler;
}

use fairness::scheduler::{WorkerFairnessConfig, WorkerFairnessState};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_enqueue_data_admitted(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/enqueue_data/admitted");
    let data = bytes::Bytes::from(vec![0u8; 1024]);

    group.bench_function("run", |b| {
        b.iter_batched(
            || WorkerFairnessState::new(WorkerFairnessConfig::default(), Instant::now()),
            |mut state| {
                black_box(state.enqueue_data(1, 0, data.clone(), Instant::now()))
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_enqueue_data_rejected_worker_cap(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/enqueue_data/rejected_worker_cap");
    let mut cfg = WorkerFairnessConfig::default();
    cfg.max_total_queued_bytes = 100;
    let data = bytes::Bytes::from(vec![0u8; 1024]);

    group.bench_function("run", |b| {
        b.iter_batched(
            || WorkerFairnessState::new(cfg.clone(), Instant::now()),
            |mut state| black_box(state.enqueue_data(1, 0, data.clone(), Instant::now())),
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_next_decision_two_flows_drr(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/next_decision/two_flows_drr");

    group.bench_function("run", |b| {
        b.iter_batched(
            || {
                let mut cfg = WorkerFairnessConfig::default();
                cfg.base_quantum_bytes = 1024;
                let mut state = WorkerFairnessState::new(cfg, Instant::now());
                let now = Instant::now();
                state.enqueue_data(1, 0, bytes::Bytes::from(vec![0u8; 64]), now);
                state.enqueue_data(2, 0, bytes::Bytes::from(vec![0u8; 64]), now);
                state
            },
            |mut state| {
                black_box(state.next_decision(Instant::now()));
                black_box(state.next_decision(Instant::now()))
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_next_decision_idle(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/next_decision/idle");
    let mut state = WorkerFairnessState::new(WorkerFairnessConfig::default(), Instant::now());

    group.bench_function("run", |b| {
        b.iter(|| black_box(state.next_decision(Instant::now())))
    });
    group.finish();
}

fn bench_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/snapshot");
    let mut state = WorkerFairnessState::new(WorkerFairnessConfig::default(), Instant::now());
    let now = Instant::now();
    state.enqueue_data(1, 0, bytes::Bytes::from(vec![0u8; 1024]), now);
    state.enqueue_data(2, 0, bytes::Bytes::from(vec![0u8; 512]), now);

    group.bench_function("run", |b| b.iter(|| black_box(state.snapshot())));
    group.finish();
}

fn bench_remove_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/remove_flow");

    group.bench_function("run", |b| {
        b.iter_batched(
            || {
                let mut state =
                    WorkerFairnessState::new(WorkerFairnessConfig::default(), Instant::now());
                let now = Instant::now();
                state.enqueue_data(1, 0, bytes::Bytes::from(vec![0u8; 1024]), now);
                state
            },
            |mut state| state.remove_flow(1),
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_enqueue_data_admitted,
        bench_enqueue_data_rejected_worker_cap,
        bench_next_decision_two_flows_drr,
        bench_next_decision_idle,
        bench_snapshot,
        bench_remove_flow,
}

criterion_main!(benches);
