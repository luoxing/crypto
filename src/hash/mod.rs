mod md2;
mod md4;
mod md5;
mod sha1;
mod sha2;
mod sm3;
// TODO: 暂未实现
mod sha3;

mod blake2b;
mod blake2s;
mod blake3;

pub use self::md2::*;
pub use self::md4::*;
pub use self::md5::*;
pub use self::sha1::*;
pub use self::sha2::*;
pub use self::sha3::*;
pub use self::sm3::*;

pub use self::blake2b::*;
pub use self::blake2s::*;
pub use self::blake3::*;

#[test]
fn test_hasher_oneshot() {
    macro_rules! test_oneshot {
        ($name:tt) => {
            {
                let mut m1 = $name::new();
                m1.update(&hex::decode("4b01a2d762fada9ede4d1034a13dc69c").unwrap());
                m1.update(&hex::decode("496d616b65746869735f4c6f6e6750617373506872617365466f725f7361666574795f323031395f30393238405f4021").unwrap());
                let h1 = m1.finalize();

                let h2 = $name::oneshot(&hex::decode("4b01a2d762fada9ede4d1034a13dc69c\
            496d616b65746869735f4c6f6e6750617373506872617365466f725f7361666574795f323031395f30393238405f4021").unwrap());

                assert_eq!(h1, h2);
            }
        }
    }

    test_oneshot!(Md2);
    test_oneshot!(Md4);
    test_oneshot!(Md5);
    test_oneshot!(Sm3);

    // SHA-1
    test_oneshot!(Sha1);

    // SHA-2
    test_oneshot!(Sha224);
    test_oneshot!(Sha256);
    test_oneshot!(Sha384);
    test_oneshot!(Sha512);

    // SHA-3
}