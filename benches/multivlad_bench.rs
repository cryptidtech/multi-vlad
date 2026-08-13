// SPDX-License-Identifier: Apache-2.0
//! Performance benchmarks for multi-vlad

use criterion::{criterion_group, criterion_main, Criterion};
use multi_key::EncodedMultikey;
use multi_vlad::Builder;
use std::hint::black_box;

fn bench_vlad_encoding(c: &mut Criterion) {
    let signing_key = EncodedMultikey::try_from(
        "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04",
    )
    .unwrap()
    .to_inner();
    let vlad = Builder::default()
        .with_signing_key(&signing_key)
        .with_message(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
        .try_build()
        .unwrap();

    c.bench_function("vlad_to_bytes", |b| {
        b.iter(|| {
            let _bytes: Vec<u8> = black_box(&vlad).clone().into();
        });
    });
}

criterion_group!(benches, bench_vlad_encoding);
criterion_main!(benches);
