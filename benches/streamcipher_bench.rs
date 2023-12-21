use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::streamcipher::*;

fn bench_rc4(c: &mut Criterion) {
    let key =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let mut ciphertext = black_box([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);

    let mut cipher = Rc4::new(&key);

    c.bench_function("bench_rc4", |b| {
        //b.bytes = 16;
        b.iter(|| {
            cipher.encrypt_slice(&mut ciphertext);
        })
    });
}

fn bench_chacha20(c: &mut Criterion) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut plaintext_and_ciphertext = black_box([1u8; Chacha20::BLOCK_LEN]);

    let chacha20 = Chacha20::new(&key);

    c.bench_function("bench_chacha20", |b| {
        //b.bytes = Chacha20::BLOCK_LEN as u64;
        b.iter(|| {
            chacha20.encrypt_slice(1, &nonce, &mut plaintext_and_ciphertext);
        })
    });
}
criterion_group!(benches, bench_rc4, bench_chacha20);
criterion_main!(benches);
