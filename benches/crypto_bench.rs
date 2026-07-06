use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

#[allow(unused_imports)]
#[path = "../src/crypto/aes.rs"]
mod aes_impl;
#[allow(unused_imports)]
#[path = "../src/error.rs"]
mod error;

use aes_impl::AesCtr;

fn bench_aes_ctr(c: &mut Criterion) {
    c.bench_function("aes_ctr_encrypt_64kb", |b| {
        let data = vec![0u8; 65536];
        b.iter(|| {
            let mut enc = AesCtr::new(&[0u8; 32], 0);
            black_box(enc.encrypt(black_box(data.as_slice())))
        })
    });
}

criterion_group!(benches, bench_aes_ctr);
criterion_main!(benches);
