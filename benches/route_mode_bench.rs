#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

mod proxy {
    #[path = "../../src/proxy/route_mode.rs"]
    pub mod route_mode;
}

use proxy::route_mode::{
    RelayRouteMode, RouteCutoverState, RouteRuntimeController,
    cutover_stagger_delay, is_session_affected_by_cutover,
};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_set_mode_transition(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_mode/set_mode/transition");

    group.bench_function("middle_to_direct", |b| {
        b.iter_batched(
            || RouteRuntimeController::new(RelayRouteMode::Middle),
            |ctrl| black_box(ctrl.set_mode(RelayRouteMode::Direct)),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_mode/snapshot");
    let ctrl = RouteRuntimeController::new(RelayRouteMode::Direct);

    group.bench_function("read", |b| {
        b.iter(|| black_box(ctrl.snapshot()));
    });

    group.finish();
}

fn bench_is_session_affected_by_cutover(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_mode/is_session_affected_by_cutover");
    let state = RouteCutoverState {
        mode: RelayRouteMode::Direct,
        generation: 5,
    };

    group.bench_function("affected", |b| {
        b.iter(|| black_box(is_session_affected_by_cutover(state, RelayRouteMode::Middle, 3)));
    });

    group.bench_function("unaffected", |b| {
        b.iter(|| black_box(is_session_affected_by_cutover(state, RelayRouteMode::Direct, 5)));
    });

    group.finish();
}

fn bench_cutover_stagger_delay(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_mode/cutover_stagger_delay");

    group.bench_function("compute", |b| {
        let mut sid = 0u64;
        b.iter(|| {
            sid = sid.wrapping_add(1);
            black_box(cutover_stagger_delay(sid, 7));
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_set_mode_transition,
        bench_snapshot,
        bench_is_session_affected_by_cutover,
        bench_cutover_stagger_delay,
}

criterion_main!(benches);
