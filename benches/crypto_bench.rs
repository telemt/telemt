// Cryptobench
use criterion::{Criterion, black_box, criterion_group};

fn bench_aes_ctr(c: &mut Criterion) {
    c.bench_function("aes_ctr_encrypt_64kb", |b| {
        let data = vec![0u8; 65536];
        b.iter(|| {
            let mut enc = AesCtr::new(&[0u8; 32], 0);
            black_box(enc.encrypt(&data))
        })
    });
}
