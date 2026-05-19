//! Benchmarks for `transport/middle_proxy/{codec,wire}` — the
//! middle-proxy RPC frame builders/parsers and the proxy-req payload
//! assembler. Locked to opt.md §3.1 (triple-allocation per RPC frame).
//!
//! `#[path]`-inlined: `error.rs`, `crypto/mod.rs`, `protocol/mod.rs`,
//! and the two transport files. Nothing in `src/` is modified.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

#[path = "../src/crypto/mod.rs"]
mod crypto;

// Only the `protocol::constants` submodule — pulling in `protocol/mod.rs`
// whole drags in `#[cfg(test)] mod security_tests;` includes from
// `tls.rs` that reference `crate::tls_front`, which the bench crate
// doesn't have.
mod protocol {
    #[path = "../../src/protocol/constants.rs"]
    pub mod constants;
}

// Bring the two codec files in as a synthetic transport::middle_proxy
// hierarchy so their `crate::transport::middle_proxy::codec` cross-refs
// resolve. The bench crate's `crate::` is this file.
mod transport {
    pub mod middle_proxy {
        // Two levels of inline `mod` nesting → virtual base directory
        // is `benches/transport/middle_proxy/`, so three `..` to reach
        // `src/`.
        #[path = "../../../src/transport/middle_proxy/codec.rs"]
        pub mod codec;

        #[path = "../../../src/transport/middle_proxy/wire.rs"]
        pub mod wire;
    }
}

use crate::protocol::constants::ProtoTag;
use crate::transport::middle_proxy::codec::{
    RpcChecksumMode, build_handshake_payload, build_nonce_payload, build_rpc_frame,
    cbc_decrypt_inplace, cbc_encrypt_padded, parse_handshake_flags, parse_nonce_payload,
    read_rpc_frame_plaintext, rpc_crc,
};
use crate::transport::middle_proxy::wire::{
    build_proxy_req_payload, extract_ip_material, proto_flags_for_tag,
};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn buf(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

const RPC_SIZES: &[usize] = &[64, 1024, 16_384, 65_536];

// ============= build_rpc_frame =============

fn bench_build_rpc_frame(c: &mut Criterion) {
    let mut g = c.benchmark_group("rpc/build_rpc_frame");
    for &n in RPC_SIZES {
        let payload = buf(n);
        g.throughput(Throughput::Bytes(n as u64));
        g.bench_with_input(BenchmarkId::new("crc32", n), &payload, |b, p| {
            b.iter(|| {
                let _ = black_box(build_rpc_frame(black_box(0), black_box(p), RpcChecksumMode::Crc32));
            });
        });
        g.bench_with_input(BenchmarkId::new("crc32c", n), &payload, |b, p| {
            b.iter(|| {
                let _ = black_box(build_rpc_frame(black_box(0), black_box(p), RpcChecksumMode::Crc32c));
            });
        });
    }
    g.finish();
}

// ============= read_rpc_frame_plaintext (Cursor) =============

fn bench_read_rpc_frame(c: &mut Criterion) {
    // block_on overhead is intentionally included — production calls this from async context.
    let runtime = rt();
    let mut g = c.benchmark_group("rpc/read_rpc_frame_plaintext");
    for &n in RPC_SIZES {
        let frame = build_rpc_frame(7, &buf(n), RpcChecksumMode::Crc32);
        g.throughput(Throughput::Bytes(frame.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &frame, |b, f| {
            b.iter(|| {
                let mut cursor = std::io::Cursor::new(f.clone());
                let _ = black_box(runtime.block_on(async {
                    read_rpc_frame_plaintext(&mut cursor).await
                }));
            });
        });
    }
    g.finish();
}

// ============= rpc_crc =============

fn bench_rpc_crc(c: &mut Criterion) {
    let mut g = c.benchmark_group("rpc/rpc_crc");
    for &n in &[64usize, 1024, 16_384] {
        let data = buf(n);
        g.throughput(Throughput::Bytes(n as u64));
        g.bench_with_input(BenchmarkId::new("crc32", n), &data, |b, d| {
            b.iter(|| {
                let _ = black_box(rpc_crc(RpcChecksumMode::Crc32, black_box(d)));
            });
        });
        g.bench_with_input(BenchmarkId::new("crc32c", n), &data, |b, d| {
            b.iter(|| {
                let _ = black_box(rpc_crc(RpcChecksumMode::Crc32c, black_box(d)));
            });
        });
    }
    g.finish();
}

// ============= Nonce / Handshake payloads =============

fn bench_build_parse_nonce(c: &mut Criterion) {
    let nonce = [0xABu8; 16];
    c.bench_function("rpc/build_nonce_payload", |b| {
        b.iter(|| {
            let _ = black_box(build_nonce_payload(
                black_box(0x1234_5678),
                black_box(0x90AB_CDEF),
                black_box(&nonce),
            ));
        });
    });

    let payload = build_nonce_payload(0x1234_5678, 0x90AB_CDEF, &nonce);
    c.bench_function("rpc/parse_nonce_payload", |b| {
        b.iter(|| {
            let _ = black_box(parse_nonce_payload(black_box(&payload)));
        });
    });
}

fn bench_build_parse_handshake(c: &mut Criterion) {
    c.bench_function("rpc/build_handshake_payload", |b| {
        b.iter(|| {
            let _ = black_box(build_handshake_payload(
                black_box([1, 2, 3, 4]),
                black_box(1000),
                black_box([5, 6, 7, 8]),
                black_box(2000),
                black_box(0x800),
            ));
        });
    });

    let payload = build_handshake_payload([1, 2, 3, 4], 1000, [5, 6, 7, 8], 2000, 0x800);
    c.bench_function("rpc/parse_handshake_flags", |b| {
        b.iter(|| {
            let _ = black_box(parse_handshake_flags(black_box(&payload)));
        });
    });
}

// ============= CBC roundtrip =============

fn bench_cbc(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let iv = [0x99u8; 16];

    let mut g = c.benchmark_group("rpc/cbc");
    for &n in &[16usize, 64, 256, 1024, 4096] {
        let plaintext = buf(n);
        g.throughput(Throughput::Bytes(n as u64));
        g.bench_with_input(BenchmarkId::new("encrypt_padded", n), &plaintext, |b, p| {
            b.iter(|| {
                let _ = black_box(cbc_encrypt_padded(&key, &iv, black_box(p)).unwrap());
            });
        });
        let (ct, _) = cbc_encrypt_padded(&key, &iv, &plaintext).unwrap();
        g.bench_with_input(BenchmarkId::new("decrypt_inplace", n), &ct, |b, c| {
            b.iter(|| {
                let mut buf = c.clone();
                let _ = black_box(cbc_decrypt_inplace(&key, &iv, &mut buf).unwrap());
            });
        });
    }
    g.finish();
}

// ============= wire.rs =============

fn bench_extract_ip_material(c: &mut Criterion) {
    let v4: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let mapped: SocketAddr = "[::ffff:1.2.3.4]:80".parse().unwrap();
    c.bench_function("wire/extract_ip_material_v4", |b| {
        b.iter(|| {
            let _ = black_box(extract_ip_material(black_box(v4)));
        });
    });
    c.bench_function("wire/extract_ip_material_v6", |b| {
        b.iter(|| {
            let _ = black_box(extract_ip_material(black_box(v6)));
        });
    });
    c.bench_function("wire/extract_ip_material_mapped", |b| {
        b.iter(|| {
            let _ = black_box(extract_ip_material(black_box(mapped)));
        });
    });
}

fn bench_proto_flags_for_tag(c: &mut Criterion) {
    c.bench_function("wire/proto_flags_for_tag", |b| {
        b.iter(|| {
            for &tag in &[ProtoTag::Abridged, ProtoTag::Intermediate, ProtoTag::Secure] {
                let _ = black_box(proto_flags_for_tag(black_box(tag), black_box(true)));
                let _ = black_box(proto_flags_for_tag(black_box(tag), black_box(false)));
            }
        });
    });
}

fn bench_build_proxy_req_payload(c: &mut Criterion) {
    let client: SocketAddr = "10.1.2.3:1024".parse().unwrap();
    let our: SocketAddr = "10.4.5.6:2048".parse().unwrap();
    let flags = proto_flags_for_tag(ProtoTag::Intermediate, true);
    let tag: &[u8] = b"my-proxy-ad-tag";

    let mut g = c.benchmark_group("wire/build_proxy_req_payload");
    for &n in &[64usize, 1024, 16_384] {
        let data = buf(n);
        g.throughput(Throughput::Bytes(n as u64));
        g.bench_with_input(BenchmarkId::new("with_tag", n), &data, |b, d| {
            b.iter(|| {
                let _ = black_box(build_proxy_req_payload(
                    black_box(7),
                    black_box(client),
                    black_box(our),
                    black_box(d),
                    Some(black_box(tag)),
                    black_box(flags),
                ));
            });
        });
        let flags_no_tag = proto_flags_for_tag(ProtoTag::Intermediate, false);
        g.bench_with_input(BenchmarkId::new("no_tag", n), &data, |b, d| {
            b.iter(|| {
                let _ = black_box(build_proxy_req_payload(
                    black_box(7),
                    black_box(client),
                    black_box(our),
                    black_box(d),
                    None,
                    black_box(flags_no_tag),
                ));
            });
        });
    }
    g.finish();
}

criterion_group! {
    name = rpc_frame;
    config = quick();
    targets = bench_build_rpc_frame, bench_read_rpc_frame, bench_rpc_crc
}
criterion_group! {
    name = rpc_payloads;
    config = quick();
    targets = bench_build_parse_nonce, bench_build_parse_handshake, bench_cbc
}
criterion_group! {
    name = wire;
    config = quick();
    targets = bench_extract_ip_material, bench_proto_flags_for_tag, bench_build_proxy_req_payload
}

criterion_main!(rpc_frame, rpc_payloads, wire);
