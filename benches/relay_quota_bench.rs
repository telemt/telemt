//! Benchmarks for hot-path quota / yield math from `src/proxy/relay.rs`
//! and `src/proxy/middle_relay.rs`. These run per byte-chunk on the relay
//! path, so even sub-ns differences accumulate.
//!
//! NOTE: helper bodies below are a manual copy of the corresponding
//! pure functions in `src/proxy/relay.rs` and `src/proxy/middle_relay.rs`.
//! Production and bench code diverging from each other is technically
//! possible but would only affect bench accuracy (not runtime behaviour).
//! Keep in sync.

#![allow(dead_code)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

// ── Constants mirrored from src/proxy/relay.rs ──

const QUOTA_NEAR_LIMIT_BYTES: u64 = 64 * 1024;
const QUOTA_LARGE_CHARGE_BYTES: u64 = 16 * 1024;
const QUOTA_ADAPTIVE_INTERVAL_MIN_BYTES: u64 = 4 * 1024;
const QUOTA_ADAPTIVE_INTERVAL_MAX_BYTES: u64 = 64 * 1024;

// ── Constants mirrored from src/proxy/middle_relay.rs ──

const C2ME_QUEUED_BYTE_PERMIT_UNIT: usize = 16 * 1024;
const C2ME_QUEUED_PERMITS_PER_SLOT: usize = 4;

// ── Pure helpers mirrored from src/proxy/relay.rs ──

#[inline]
fn quota_adaptive_interval_bytes(remaining_before: u64) -> u64 {
    remaining_before.saturating_div(2).clamp(
        QUOTA_ADAPTIVE_INTERVAL_MIN_BYTES,
        QUOTA_ADAPTIVE_INTERVAL_MAX_BYTES,
    )
}

#[inline]
fn should_immediate_quota_check(remaining_before: u64, charge_bytes: u64) -> bool {
    remaining_before <= QUOTA_NEAR_LIMIT_BYTES || charge_bytes >= QUOTA_LARGE_CHARGE_BYTES
}

// ── Pure helpers mirrored from src/proxy/middle_relay.rs ──

#[inline]
fn c2me_payload_permits(payload_len: usize) -> u32 {
    payload_len
        .max(1)
        .div_ceil(C2ME_QUEUED_BYTE_PERMIT_UNIT)
        .min(u32::MAX as usize) as u32
}

#[inline]
fn c2me_queued_permit_budget(channel_capacity: usize, frame_limit: usize) -> usize {
    channel_capacity
        .saturating_mul(C2ME_QUEUED_PERMITS_PER_SLOT)
        .max(c2me_payload_permits(frame_limit) as usize)
        .max(1)
}

// ── Benchmarks ──

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_quota_adaptive_interval_mid(c: &mut Criterion) {
    c.bench_function("quota/adaptive_interval_bytes/mid", |b| {
        b.iter(|| quota_adaptive_interval_bytes(black_box(40_000)))
    });
}

fn bench_quota_adaptive_interval_saturating(c: &mut Criterion) {
    c.bench_function("quota/adaptive_interval_bytes/saturating", |b| {
        b.iter(|| quota_adaptive_interval_bytes(black_box(u64::MAX)))
    });
}

fn bench_should_immediate_quota_check_far(c: &mut Criterion) {
    c.bench_function("quota/should_immediate_quota_check/far", |b| {
        b.iter(|| should_immediate_quota_check(black_box(10_000_000), black_box(1024)))
    });
}

fn bench_should_immediate_quota_check_near(c: &mut Criterion) {
    c.bench_function("quota/should_immediate_quota_check/near_limit", |b| {
        b.iter(|| should_immediate_quota_check(black_box(32_000), black_box(1024)))
    });
}

fn bench_c2me_payload_permits_small(c: &mut Criterion) {
    c.bench_function("quota/c2me_payload_permits/small_1KB", |b| {
        b.iter(|| c2me_payload_permits(black_box(1024)))
    });
}

fn bench_c2me_payload_permits_huge(c: &mut Criterion) {
    c.bench_function("quota/c2me_payload_permits/huge_1MB", |b| {
        b.iter(|| c2me_payload_permits(black_box(1024 * 1024)))
    });
}

fn bench_c2me_queued_permit_budget(c: &mut Criterion) {
    c.bench_function("quota/c2me_queued_permit_budget/default", |b| {
        b.iter(|| c2me_queued_permit_budget(black_box(1024), black_box(16 * 1024 * 1024)))
    });
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_quota_adaptive_interval_mid,
        bench_quota_adaptive_interval_saturating,
        bench_should_immediate_quota_check_far,
        bench_should_immediate_quota_check_near,
        bench_c2me_payload_permits_small,
        bench_c2me_payload_permits_huge,
        bench_c2me_queued_permit_budget,
}

criterion_main!(benches);
