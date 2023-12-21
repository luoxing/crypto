use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::blockmode::*;

fn bench_aes128_cbc_enc(c: &mut Criterion) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let ivec = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cbc::IV_LEN];
    iv.copy_from_slice(&ivec);

    let mut cipher = Aes128Cbc::new(&key);

    c.bench_function("bench_aes128_cbc_enc", |b| {
        //b.bytes = Aes128Cbc::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([1u8; Aes128Cbc::BLOCK_LEN]);
            cipher.encrypt(&iv, &mut ciphertext);
            ciphertext
        })
    });
}

fn bench_aes128_cfb128_enc(c: &mut Criterion) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let ivec = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb128::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb128::new(&key);

    c.bench_function("bench_aes128_cfb128_enc", |b| {
        //b.bytes = Aes128Cfb128::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([0u8; Aes128Cfb128::BLOCK_LEN]);
            cipher.encrypt_slice(&iv, &mut ciphertext);
            ciphertext
        })
    });
}

fn bench_aes128_ofb_enc(c: &mut Criterion) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let ivec = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Ofb::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Ofb::new(&key);

    c.bench_function("bench_aes128_ofb_enc", |b| {
        //b.bytes = Aes128Ofb::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([0u8; Aes128Ofb::BLOCK_LEN]);
            cipher.encrypt_slice(&iv, &mut ciphertext);
            ciphertext
        })
    });
}

criterion_group!(
    benches,
    bench_aes128_cbc_enc,
    bench_aes128_cfb128_enc,
    bench_aes128_ofb_enc
);
criterion_main!(benches);
