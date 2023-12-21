use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::aeadcipher::*;

fn bench_aes128_ccm_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = black_box([1u8; Aes128Ccm::BLOCK_LEN + Aes128Ccm::TAG_LEN]);
    let cipher = Aes128Ccm::new(&key);
    c.bench_function("bench_aes128_ccm_enc", |b| {
        //b.bytes = Aes128Ccm::BLOCK_LEN as u64;
        b.iter(|| cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext));
    });
}


fn bench_chacha20_poly1305_enc(c: &mut Criterion) {
    let key = [1u8; Chacha20Poly1305::KEY_LEN];
    let nonce = [2u8; Chacha20Poly1305::NONCE_LEN];
    let aad = [0u8; 0];

    let mut tag_out = black_box([1u8; Chacha20Poly1305::TAG_LEN]);
    let mut ciphertext = black_box([1u8; Chacha20Poly1305::BLOCK_LEN]);

    let cipher = Chacha20Poly1305::new(&key);

    c.bench_function("bench_chacha20_poly1305_enc", |b| {
        //b.bytes = Chacha20Poly1305::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
        })
    });
}


fn bench_aes128_gcm_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = black_box([1u8; Aes128Gcm::BLOCK_LEN + Aes128Gcm::TAG_LEN]);
    let cipher = Aes128Gcm::new(&key);

    c.bench_function("bench_aes128_gcm_enc", |b| {
        //b.bytes = Aes128Gcm::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
        })
    });
}


fn bench_aes128_gcm_siv_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext =
        black_box([1u8; Aes128GcmSiv::BLOCK_LEN + Aes128GcmSiv::TAG_LEN]);
    let cipher = Aes128GcmSiv::new(&key);

    c.bench_function("bench_aes128_gcm_siv_enc", |b| {
        //b.bytes = Aes128GcmSiv::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
        })
    });
}


fn bench_aes128_ocb_tag_128_enc(c: &mut Criterion) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext =
        black_box([1u8; Aes128OcbTag128::BLOCK_LEN + Aes128OcbTag128::TAG_LEN]);
    let cipher = Aes128OcbTag128::new(&key);

    c.bench_function("bench_aes128_ocb_tag_128_enc", |b| {
        //b.bytes = Aes128OcbTag128::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
        })
    });
}


fn bench_aes_siv_cmac_256_enc(c: &mut Criterion) {
    let key = hex::decode(
        "000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f",
    )
    .unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext =
        black_box([1u8; AesSivCmac256::BLOCK_LEN + AesSivCmac256::TAG_LEN]);
    let cipher = AesSivCmac256::new(&key);

    c.bench_function("bench_aes_siv_cmac_256_enc", |b| {
        //b.bytes = AesSivCmac256::BLOCK_LEN as u64;
        b.iter(|| {
            cipher.encrypt_slice(&[&aad], &mut plaintext_and_ciphertext);
        })
    });
}

criterion_group!(benches, 
    bench_aes128_ccm_enc,
    bench_chacha20_poly1305_enc,
    bench_aes128_gcm_enc,
    bench_aes128_gcm_siv_enc,
    bench_aes128_ocb_tag_128_enc,
    bench_aes_siv_cmac_256_enc);
criterion_main!(benches);
