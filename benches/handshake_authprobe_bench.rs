//! Benchmarks for hot-path handshake helpers from `src/proxy/handshake.rs`.
//!
//! NOTE: helper bodies below are a manual copy of the corresponding
//! pure functions in `src/proxy/handshake.rs`. Production and bench code
//! diverging from each other is technically possible but would only
//! affect bench accuracy (not runtime behaviour). Keep in sync.

#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

// ── Constants mirrored from src/proxy/handshake.rs ──

const OVERLOAD_CANDIDATE_BUDGET_HINTED: usize = 16;
const OVERLOAD_CANDIDATE_BUDGET_UNHINTED: usize = 8;

// ── Pure helpers mirrored from src/proxy/handshake.rs ──

fn sni_hint_hash(sni: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    for byte in sni.bytes() {
        hasher.write_u8(byte.to_ascii_lowercase());
    }
    hasher.finish()
}

fn ip_prefix_hint_key(peer_ip: IpAddr) -> u64 {
    match peer_ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            u64::from_be_bytes([0x04, a, b, c, 0, 0, 0, 0])
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            u64::from_be_bytes([
                0x06, octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
            ])
        }
    }
}

fn mark_candidate_if_new(tried_user_ids: &mut [u32], tried_len: &mut usize, user_id: u32) -> bool {
    if tried_user_ids[..*tried_len].contains(&user_id) {
        return false;
    }
    if *tried_len < tried_user_ids.len() {
        tried_user_ids[*tried_len] = user_id;
        *tried_len += 1;
    }
    true
}

fn budget_for_validation(total_users: usize, overload: bool, has_hint: bool) -> usize {
    if total_users == 0 {
        return 0;
    }
    if !overload {
        return total_users;
    }
    let cap = if has_hint {
        OVERLOAD_CANDIDATE_BUDGET_HINTED
    } else {
        OVERLOAD_CANDIDATE_BUDGET_UNHINTED
    };
    total_users.min(cap.max(1))
}

// ── Benchmarks ──

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn bench_sni_hint_hash_short(c: &mut Criterion) {
    let sni = "example.com";
    c.bench_function("authprobe/sni_hint_hash/short", |b| {
        b.iter(|| sni_hint_hash(black_box(sni)))
    });
}

fn bench_sni_hint_hash_long(c: &mut Criterion) {
    let sni = "very-long-subdomain.intermediate-host.example-multi-label.com";
    c.bench_function("authprobe/sni_hint_hash/long", |b| {
        b.iter(|| sni_hint_hash(black_box(sni)))
    });
}

fn bench_ip_prefix_hint_v4(c: &mut Criterion) {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    c.bench_function("authprobe/ip_prefix_hint_key/v4", |b| {
        b.iter(|| ip_prefix_hint_key(black_box(ip)))
    });
}

fn bench_ip_prefix_hint_v6(c: &mut Criterion) {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0x8a2e, 0x370, 0x7334));
    c.bench_function("authprobe/ip_prefix_hint_key/v6", |b| {
        b.iter(|| ip_prefix_hint_key(black_box(ip)))
    });
}

fn bench_mark_candidate_first_seen(c: &mut Criterion) {
    c.bench_function("authprobe/mark_candidate_if_new/first_seen", |b| {
        b.iter_batched(
            || ([0u32; 32], 0usize),
            |(mut buf, mut len)| black_box(mark_candidate_if_new(&mut buf, &mut len, black_box(42))),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_mark_candidate_duplicate(c: &mut Criterion) {
    // buf reuse across iterations is safe: duplicate hits false-branch without mutation.
    let mut buf = [0u32; 32];
    let mut len = 8usize;
    for i in 0..8u32 {
        buf[i as usize] = i;
    }
    c.bench_function("authprobe/mark_candidate_if_new/duplicate_mid_8", |b| {
        b.iter(|| black_box(mark_candidate_if_new(&mut buf, &mut len.clone(), black_box(4))))
    });
}

fn bench_budget_for_validation_no_overload(c: &mut Criterion) {
    c.bench_function("authprobe/budget_for_validation/no_overload", |b| {
        b.iter(|| budget_for_validation(black_box(1000), false, false))
    });
}

fn bench_budget_for_validation_overload_hinted(c: &mut Criterion) {
    c.bench_function("authprobe/budget_for_validation/overload_hinted", |b| {
        b.iter(|| budget_for_validation(black_box(1000), true, true))
    });
}

criterion_group! {
    name = benches;
    config = quick();
    targets =
        bench_sni_hint_hash_short,
        bench_sni_hint_hash_long,
        bench_ip_prefix_hint_v4,
        bench_ip_prefix_hint_v6,
        bench_mark_candidate_first_seen,
        bench_mark_candidate_duplicate,
        bench_budget_for_validation_no_overload,
        bench_budget_for_validation_overload_hinted,
}

criterion_main!(benches);
