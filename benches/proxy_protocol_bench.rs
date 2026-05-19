//! HAProxy PROXY protocol v1/v2 builder + parser benchmarks.
//!
//! `#[path]`-inlines `src/error.rs` and `src/transport/proxy_protocol.rs`.
//! The parser is async over an `AsyncRead`, so we drive it with
//! `std::io::Cursor<Vec<u8>>` wrapped in a tokio runtime — no fake
//! `TcpStream`, no networking.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

#[path = "../src/transport/proxy_protocol.rs"]
mod proxy_protocol;

use crate::proxy_protocol::{
    ProxyProtocolV1Builder, ProxyProtocolV2Builder, parse_proxy_protocol,
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

// ============= Builders =============

fn bench_v1_builder(c: &mut Criterion) {
    let src: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
    c.bench_function("proxy_protocol/v1_builder_tcp4", |b| {
        b.iter(|| {
            let _ = black_box(
                ProxyProtocolV1Builder::new()
                    .tcp4(black_box(src), black_box(dst))
                    .build(),
            );
        });
    });

    let src6: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
    let dst6: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    c.bench_function("proxy_protocol/v1_builder_tcp6", |b| {
        b.iter(|| {
            let _ = black_box(
                ProxyProtocolV1Builder::new()
                    .tcp6(black_box(src6), black_box(dst6))
                    .build(),
            );
        });
    });

    c.bench_function("proxy_protocol/v1_builder_unknown", |b| {
        b.iter(|| {
            let _ = black_box(ProxyProtocolV1Builder::new().build());
        });
    });
}

fn bench_v2_builder(c: &mut Criterion) {
    let src4: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let dst4: SocketAddr = "10.0.0.1:443".parse().unwrap();
    c.bench_function("proxy_protocol/v2_builder_tcp4", |b| {
        b.iter(|| {
            let _ = black_box(
                ProxyProtocolV2Builder::new()
                    .with_addrs(black_box(src4), black_box(dst4))
                    .build(),
            );
        });
    });

    let src6: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
    let dst6: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    c.bench_function("proxy_protocol/v2_builder_tcp6", |b| {
        b.iter(|| {
            let _ = black_box(
                ProxyProtocolV2Builder::new()
                    .with_addrs(black_box(src6), black_box(dst6))
                    .build(),
            );
        });
    });

    c.bench_function("proxy_protocol/v2_builder_local", |b| {
        b.iter(|| {
            let _ = black_box(ProxyProtocolV2Builder::new().build());
        });
    });
}

// ============= Parser (via Cursor) =============

fn bench_parse_v1(c: &mut Criterion) {
    let runtime = rt();
    let header: Vec<u8> = b"PROXY TCP4 192.168.1.1 10.0.0.1 12345 443\r\n".to_vec();
    let default: SocketAddr = "0.0.0.0:0".parse().unwrap();
    c.bench_function("proxy_protocol/parse_v1_tcp4", |b| {
        b.iter(|| {
            let mut cursor = std::io::Cursor::new(header.clone());
            let _ = black_box(runtime.block_on(async {
                parse_proxy_protocol(&mut cursor, default).await
            }));
        });
    });

    let header6: Vec<u8> = b"PROXY TCP6 2001:db8::1 2001:db8::2 1024 443\r\n".to_vec();
    c.bench_function("proxy_protocol/parse_v1_tcp6", |b| {
        b.iter(|| {
            let mut cursor = std::io::Cursor::new(header6.clone());
            let _ = black_box(runtime.block_on(async {
                parse_proxy_protocol(&mut cursor, default).await
            }));
        });
    });
}

fn bench_parse_v2(c: &mut Criterion) {
    let runtime = rt();
    // v2 TCP4 frame: 12-byte signature + 4-byte header + 12-byte addrs.
    let mut frame: Vec<u8> = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    frame.push(0x21); // v2 + PROXY
    frame.push(0x11); // INET + STREAM
    frame.extend_from_slice(&(12u16).to_be_bytes());
    frame.extend_from_slice(&[192, 168, 1, 1, 10, 0, 0, 1, 0x30, 0x39, 0x01, 0xbb]);

    let default: SocketAddr = "0.0.0.0:0".parse().unwrap();
    c.bench_function("proxy_protocol/parse_v2_tcp4", |b| {
        b.iter(|| {
            let mut cursor = std::io::Cursor::new(frame.clone());
            let _ = black_box(runtime.block_on(async {
                parse_proxy_protocol(&mut cursor, default).await
            }));
        });
    });
}

// ============= Round-trip: build → parse =============

fn bench_build_parse_roundtrip_v1(c: &mut Criterion) {
    let runtime = rt();
    let src: SocketAddr = "10.20.30.40:11000".parse().unwrap();
    let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
    let default: SocketAddr = "0.0.0.0:0".parse().unwrap();
    c.bench_function("proxy_protocol/v1_build_then_parse", |b| {
        b.iter(|| {
            let header = ProxyProtocolV1Builder::new()
                .tcp4(black_box(src), black_box(dst))
                .build();
            let mut cursor = std::io::Cursor::new(header);
            let _ = black_box(runtime.block_on(async {
                parse_proxy_protocol(&mut cursor, default).await
            }));
        });
    });
}

criterion_group! {
    name = builders;
    config = quick();
    targets = bench_v1_builder, bench_v2_builder
}
criterion_group! {
    name = parsers;
    config = quick();
    targets = bench_parse_v1, bench_parse_v2, bench_build_parse_roundtrip_v1
}

criterion_main!(builders, parsers);
