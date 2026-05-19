//! TLS hot-path benchmarks for `src/protocol/tls.rs`.
//!
//! Covers opt.md §6.1 (three-pass ClientHello scan: SNI, ALPN, version),
//! §6.2 (16 KB clone in `validate_tls_handshake`), per-handshake
//! `build_server_hello` (RNG-driven, multiple fake_cert_len sizes),
//! `gen_fake_x25519_key` (scalar mult), and cheap per-record parsers
//! `is_tls_handshake` / `parse_tls_record_header`.
//!
//! `#[path]`-inlined: `error.rs`, `crypto/mod.rs`, `protocol/constants.rs`,
//! `protocol/tls.rs`. The `tls.rs` `#[cfg(test)]` guard pulls in
//! `security_tests.rs` which references `crate::tls_front::*`; we provide
//! minimal stubs here so everything compiles without touching `src/`.

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "../src/error.rs"]
mod error;

#[path = "../src/crypto/mod.rs"]
mod crypto;

mod protocol {
    #[path = "../../src/protocol/constants.rs"]
    pub mod constants;
    #[path = "../../src/protocol/tls.rs"]
    pub mod tls;
}

// ---------------------------------------------------------------------------
// Stubs for `crate::tls_front` — required because tls.rs pulls in
// tls_security_tests.rs under #[cfg(test)], which imports:
//   crate::tls_front::emulator::build_emulated_server_hello
//   crate::tls_front::types::{CachedTlsData, ParsedServerHello,
//                             TlsBehaviorProfile, TlsProfileSource}
// These are never called from bench functions; the stubs only need to
// compile.
// ---------------------------------------------------------------------------

pub mod tls_front {
    pub mod emulator {
        use crate::protocol::tls::{ClientHelloTlsVersion, TLS_DIGEST_LEN};
        use crate::crypto::SecureRandom;

        pub fn build_emulated_server_hello(
            _secret: &[u8],
            _client_digest: &[u8; TLS_DIGEST_LEN],
            _session_id: &[u8],
            _cached: &super::types::CachedTlsData,
            _use_full_cert_payload: bool,
            _serverhello_compact: bool,
            _client_tls_version: ClientHelloTlsVersion,
            _rng: &SecureRandom,
            _alpn: Option<Vec<u8>>,
            _new_session_tickets: u8,
        ) -> Vec<u8> {
            Vec::new()
        }
    }

    pub mod types {
        use std::time::SystemTime;

        #[derive(Debug, Clone)]
        pub struct TlsExtension {
            pub ext_type: u16,
            pub data: Vec<u8>,
        }

        #[derive(Debug, Clone)]
        pub struct ParsedServerHello {
            pub version: [u8; 2],
            pub random: [u8; 32],
            pub session_id: Vec<u8>,
            pub cipher_suite: [u8; 2],
            pub compression: u8,
            pub extensions: Vec<TlsExtension>,
        }

        #[derive(Debug, Clone)]
        pub struct ParsedCertificateInfo {
            pub not_after_unix: Option<i64>,
            pub not_before_unix: Option<i64>,
            pub issuer_cn: Option<String>,
            pub subject_cn: Option<String>,
            pub san_names: Vec<String>,
        }

        #[derive(Debug, Clone)]
        pub struct TlsCertPayload {
            pub cert_chain_der: Vec<Vec<u8>>,
            pub certificate_message: Vec<u8>,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub enum TlsProfileSource {
            #[default]
            Default,
            Raw,
            Rustls,
            Merged,
        }

        #[derive(Debug, Clone)]
        pub struct TlsBehaviorProfile {
            pub change_cipher_spec_count: u8,
            pub app_data_record_sizes: Vec<usize>,
            pub ticket_record_sizes: Vec<usize>,
            pub source: TlsProfileSource,
        }

        impl Default for TlsBehaviorProfile {
            fn default() -> Self {
                Self {
                    change_cipher_spec_count: 1,
                    app_data_record_sizes: Vec::new(),
                    ticket_record_sizes: Vec::new(),
                    source: TlsProfileSource::Default,
                }
            }
        }

        #[derive(Debug, Clone)]
        pub struct CachedTlsData {
            pub server_hello_template: ParsedServerHello,
            pub cert_info: Option<ParsedCertificateInfo>,
            pub cert_payload: Option<TlsCertPayload>,
            pub app_data_records_sizes: Vec<usize>,
            pub total_app_data_len: usize,
            pub behavior_profile: TlsBehaviorProfile,
            pub fetched_at: SystemTime,
            pub domain: String,
        }
    }
}

use crate::crypto::{SecureRandom, sha256_hmac};
use crate::protocol::constants::{
    MAX_TLS_CIPHERTEXT_SIZE, TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
    TLS_VERSION,
};
use crate::protocol::tls::{
    build_server_hello, detect_client_hello_tls_version, extract_alpn_from_client_hello,
    extract_sni_from_client_hello, gen_fake_x25519_key, is_tls_handshake,
    parse_tls_record_header, validate_tls_handshake, ClientHelloTlsVersion, TLS_DIGEST_LEN,
    TLS_DIGEST_POS,
};

fn quick() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .sample_size(20)
        .nresamples(10_000)
}

// ============= ClientHello fixtures =============

fn build_client_hello(sni: Option<&str>, alpn: &[&[u8]], supported_versions: &[u16], legacy_version: u16) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    if let Some(host) = sni {
        let mut ext_body = Vec::new();
        let entry_len = 1 + 2 + host.len();
        ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes());
        ext_body.push(0);
        ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(host.as_bytes());
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);
    }

    if !alpn.is_empty() {
        let mut list = Vec::new();
        for proto in alpn {
            list.push(proto.len() as u8);
            list.extend_from_slice(proto);
        }
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(&list);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);
    }

    if !supported_versions.is_empty() {
        let mut list = Vec::new();
        list.push((supported_versions.len() * 2) as u8);
        for &v in supported_versions {
            list.extend_from_slice(&v.to_be_bytes());
        }
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&list);
    }

    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&legacy_version.to_be_bytes());
    hs_body.extend_from_slice(&[0u8; 32]);
    hs_body.push(0);
    hs_body.extend_from_slice(&2u16.to_be_bytes());
    hs_body.extend_from_slice(&[0x13, 0x01]);
    hs_body.push(1);
    hs_body.push(0);
    hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&exts);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let len = hs_body.len() as u32;
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&hs_body);

    let mut record = Vec::new();
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn small_client_hello() -> Vec<u8> {
    build_client_hello(Some("example.com"), &[], &[0x0304], 0x0303)
}

fn large_client_hello() -> Vec<u8> {
    let long_sni: String = "a".repeat(200) + ".example.com";
    build_client_hello(Some(&long_sni), &[b"h2", b"http/1.1"], &[0x0303, 0x0304], 0x0303)
}

fn build_validatable_handshake(secret: &[u8], timestamp: u32, total_len: usize) -> Vec<u8> {
    let mut hs = vec![0u8; total_len];
    if total_len > TLS_DIGEST_POS + TLS_DIGEST_LEN {
        hs[TLS_DIGEST_POS + TLS_DIGEST_LEN] = 0;
    }
    let computed = sha256_hmac(secret, &hs);
    let ts_le = timestamp.to_le_bytes();
    if TLS_DIGEST_POS + 28 + 4 <= hs.len() {
        hs[TLS_DIGEST_POS..TLS_DIGEST_POS + 28].copy_from_slice(&computed[..28]);
        for i in 0..4 {
            hs[TLS_DIGEST_POS + 28 + i] = computed[28 + i] ^ ts_le[i];
        }
    }
    hs
}

// ============= §6.1 Three-pass scan: SNI / ALPN / version =============

fn bench_extract_sni(c: &mut Criterion) {
    let small = small_client_hello();
    let large = large_client_hello();
    let mut g = c.benchmark_group("tls/extract_sni");
    g.bench_function("256B", |b| {
        b.iter(|| {
            let _ = black_box(extract_sni_from_client_hello(black_box(&small)));
        });
    });
    g.bench_function("1500B", |b| {
        b.iter(|| {
            let _ = black_box(extract_sni_from_client_hello(black_box(&large)));
        });
    });
    g.finish();
}

fn bench_extract_alpn(c: &mut Criterion) {
    let small = small_client_hello();
    let large = large_client_hello();
    let mut g = c.benchmark_group("tls/extract_alpn");
    g.bench_function("256B", |b| {
        b.iter(|| {
            let _ = black_box(extract_alpn_from_client_hello(black_box(&small)));
        });
    });
    g.bench_function("1500B", |b| {
        b.iter(|| {
            let _ = black_box(extract_alpn_from_client_hello(black_box(&large)));
        });
    });
    g.finish();
}

fn bench_detect_tls_version(c: &mut Criterion) {
    let small = small_client_hello();
    let large = large_client_hello();
    let mut g = c.benchmark_group("tls/detect_version");
    g.bench_function("256B", |b| {
        b.iter(|| {
            let _ = black_box(detect_client_hello_tls_version(black_box(&small)));
        });
    });
    g.bench_function("1500B", |b| {
        b.iter(|| {
            let _ = black_box(detect_client_hello_tls_version(black_box(&large)));
        });
    });
    g.finish();
}

fn bench_three_passes_combined(c: &mut Criterion) {
    let small = small_client_hello();
    let large = large_client_hello();
    let mut g = c.benchmark_group("tls/three_passes_combined");
    g.bench_function("256B", |b| {
        b.iter(|| {
            let _ = black_box(extract_sni_from_client_hello(black_box(&small)));
            let _ = black_box(extract_alpn_from_client_hello(black_box(&small)));
            let _ = black_box(detect_client_hello_tls_version(black_box(&small)));
        });
    });
    g.bench_function("1500B", |b| {
        b.iter(|| {
            let _ = black_box(extract_sni_from_client_hello(black_box(&large)));
            let _ = black_box(extract_alpn_from_client_hello(black_box(&large)));
            let _ = black_box(detect_client_hello_tls_version(black_box(&large)));
        });
    });
    g.finish();
}

// ============= §6.2 validate_tls_handshake (clone path) =============

fn bench_validate_tls_handshake(c: &mut Criterion) {
    let secret = b"bench-secret-12345";
    let secrets: Vec<(String, Vec<u8>)> = vec![("user".to_string(), secret.to_vec())];
    let sizes: &[usize] = &[256, 1024, 4096, 16384];

    let mut g = c.benchmark_group("tls/validate_handshake");
    for &size in sizes {
        let hs = build_validatable_handshake(secret, 0, size);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &hs, |b, hs| {
            b.iter(|| {
                let _ = black_box(validate_tls_handshake(black_box(hs), black_box(&secrets), true));
            });
        });
    }
    g.finish();
}

// ============= build_server_hello (per-handshake, RNG-driven) =============

fn bench_build_server_hello(c: &mut Criterion) {
    let rng = SecureRandom::new();
    let secret = b"bench-secret-12345";
    let client_digest = [0x42u8; TLS_DIGEST_LEN];
    let cert_sizes: &[usize] = &[64, 512, 4096, 16384];

    let mut g = c.benchmark_group("tls/build_server_hello");
    for &cert_len in cert_sizes {
        g.throughput(Throughput::Elements(1));
        g.bench_with_input(BenchmarkId::from_parameter(cert_len), &cert_len, |b, &cert_len| {
            b.iter(|| {
                let _ = black_box(build_server_hello(
                    black_box(secret),
                    black_box(&client_digest),
                    black_box(&[]),
                    black_box(cert_len),
                    black_box(&rng),
                    black_box(None),
                    black_box(0),
                ));
            });
        });
    }
    g.finish();
}

// ============= gen_fake_x25519_key (per-handshake scalar mult) =============

fn bench_gen_fake_x25519_key(c: &mut Criterion) {
    let rng = SecureRandom::new();
    c.bench_function("tls/gen_fake_x25519_key", |b| {
        b.iter(|| {
            let _ = black_box(gen_fake_x25519_key(black_box(&rng)));
        });
    });
}

// ============= Cheap per-record parsers =============

fn bench_is_tls_handshake(c: &mut Criterion) {
    let valid = [0x16u8, 0x03, 0x01, 0x00, 0x10];
    let invalid = [0x17u8, 0x03, 0x03, 0x00, 0x10];
    let mut g = c.benchmark_group("tls/is_tls_handshake");
    g.bench_function("accept", |b| {
        b.iter(|| {
            let _ = black_box(is_tls_handshake(black_box(&valid)));
        });
    });
    g.bench_function("reject", |b| {
        b.iter(|| {
            let _ = black_box(is_tls_handshake(black_box(&invalid)));
        });
    });
    g.finish();
}

fn bench_parse_tls_record_header(c: &mut Criterion) {
    let valid_tls10 = [0x16u8, 0x03, 0x01, 0x01, 0x00];
    let valid_tls12 = [0x17u8, 0x03, 0x03, 0x00, 0x0a];
    let invalid = [0x16u8, 0x03, 0x02, 0x00, 0x00];
    let mut g = c.benchmark_group("tls/parse_record_header");
    g.bench_function("tls10", |b| {
        b.iter(|| {
            let _ = black_box(parse_tls_record_header(black_box(&valid_tls10)));
        });
    });
    g.bench_function("tls12", |b| {
        b.iter(|| {
            let _ = black_box(parse_tls_record_header(black_box(&valid_tls12)));
        });
    });
    g.bench_function("reject", |b| {
        b.iter(|| {
            let _ = black_box(parse_tls_record_header(black_box(&invalid)));
        });
    });
    g.finish();
}

criterion_group! {
    name = three_pass;
    config = quick();
    targets = bench_extract_sni, bench_extract_alpn, bench_detect_tls_version, bench_three_passes_combined
}
criterion_group! {
    name = validate;
    config = quick();
    targets = bench_validate_tls_handshake
}
criterion_group! {
    name = server_hello;
    config = quick();
    targets = bench_build_server_hello, bench_gen_fake_x25519_key
}
criterion_group! {
    name = cheap_parsers;
    config = quick();
    targets = bench_is_tls_handshake, bench_parse_tls_record_header
}

criterion_main!(three_pass, validate, server_hello, cheap_parsers);
