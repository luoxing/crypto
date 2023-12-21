use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::hash::*;

fn bench_md2(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_md2", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| md2(&data));
    });
}

fn bench_md4(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_md4", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| md4(&data));
    });
}

fn bench_md5(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_md5", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| md5(&data));
    });
}

fn bench_sm3(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_sm3", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| sm3(&data));
    });
}

fn bench_sha1(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_sha1", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| sha1(&data));
    });
}

fn bench_sha256(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_sha256", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| sha256(&data));
    });
}

fn bench_sha384(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_sha384", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| sha384(&data));
    });
}

fn bench_sha512(c: &mut Criterion) {
    let data = [1u8; 64];
    c.bench_function("bench_sha512", |b| {
        //b.bytes = data.len() as u64;
        b.iter(|| sha512(&data));
    });
}

fn bench_blake2b_256(c: &mut Criterion) {
    let data = black_box([1u8; Blake2b256::BLOCK_LEN]);
    c.bench_function("bench_blake2b_256", |b| {
        //b.bytes = Blake2b256::BLOCK_LEN as u64;
        b.iter(|| blake2b_256(&data));
    });
}

fn bench_blake2s_256(c: &mut Criterion) {
    let data = black_box([1u8; Blake2s256::BLOCK_LEN]);
    c.bench_function("bench_blake2s_256", |b| {
        //b.bytes = Blake2s256::BLOCK_LEN as u64;
        b.iter(|| blake2s_256(&data));
    });
}

criterion_group!(
    benches,
    bench_md2,
    bench_md4,
    bench_md5,
    bench_sm3,
    bench_sha1,
    bench_sha256,
    bench_sha384,
    bench_sha512,
    bench_blake2b_256,
    bench_blake2s_256
);
criterion_main!(benches);
