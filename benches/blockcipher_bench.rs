use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::blockcipher::*;
use crypto::encoding::hex;

fn bench_rc2_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Rc2::new(&key);

    c.bench_function("bench_rc2_enc", |b| {
        // NOTE: RC2 的 Block Size 为 8 bytes，改成双倍大小后数据量就会和 AES 这些一样。
        //b.bytes = Rc2::BLOCK_LEN as u64 * 2;
        b.iter(|| {
            let mut ciphertext = black_box([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);
            cipher.decrypt_two_blocks(&mut ciphertext);
            ciphertext
        })
    });
}

fn bench_sm4_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Sm4::new(&key);

    c.bench_function("bench_sm4_enc", |b| {
        //b.bytes = Sm4::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);
            cipher.encrypt(&mut ciphertext);
            ciphertext
        })
    });
}

fn bench_aria128_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Aria128::new(&key);

    c.bench_function("bench_aria128_enc", |b| {
        //b.bytes = Aria128::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);
            cipher.encrypt(&mut ciphertext);
            ciphertext
        })
    });
}

fn bench_aria256_enc(c: &mut Criterion) {
    let key = hex::decode(
        "000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f",
    )
    .unwrap();

    let cipher = Aria256::new(&key);

    c.bench_function("bench_aria256_enc", |b| {
        //b.bytes = Aria256::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);
            cipher.encrypt(&mut ciphertext);
            ciphertext
        })
    });
}

fn bench_camellia128_enc(c: &mut Criterion) {
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let cipher = Camellia128::new(&key);

    c.bench_function("bench_camellia128_enc", |b| {
        //b.bytes = Camellia128::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);
            cipher.encrypt(&mut ciphertext);
            ciphertext
        });
    });
}

fn bench_camellia256_enc(c: &mut Criterion) {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff,
    ];

    let cipher = Camellia256::new(&key);

    c.bench_function("bench_camellia256_enc", |b| {
        //b.bytes = Camellia256::BLOCK_LEN as u64;
        b.iter(|| {
            let mut ciphertext = black_box([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);
            cipher.encrypt(&mut ciphertext);
            ciphertext
        });
    });
}

fn bench_aes128_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut ciphertext = black_box([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);

    let cipher = Aes128::new(&key);

    c.bench_function("bench_aes128_enc", |b| {
        //b.bytes = Aes128::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt(&mut ciphertext);
            ciphertext
        })
    });
}

fn bench_aes256_enc(c: &mut Criterion) {
    let key = hex::decode(
        "000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f",
    )
    .unwrap();
    let mut ciphertext = black_box([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);

    let cipher = Aes256::new(&key);

    c.bench_function("bench_aes256_enc", |b| {
        //b.bytes = Aes256::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt(&mut ciphertext);
            ciphertext
        })
    });
}

criterion_group!(
    benches,
    bench_rc2_enc,
    bench_sm4_enc,
    bench_aria128_enc,
    bench_aria256_enc,
    bench_camellia128_enc,
    bench_camellia256_enc,
    bench_aes128_enc,
    bench_aes256_enc
);
criterion_main!(benches);
