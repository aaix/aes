use std::arch::x86_64::*;

use aes::hw::{HWAesDecoder, HWAesEncoder};
use aes::modes::ecb::ElectronicCodeBook;
use aes::modes::traits::BlockCipherEncoderMode;
use aes::printblock;
use aes::traits::{AESDecoder, AESEncoder, BlockOp};

// https://legacy.cryptool.org/en/cto/aes-step-by-step

fn main() {

    assert!(is_x86_feature_detected!("aes"));

    let key = unsafe {_mm_set_epi32(5222,0,0,1)};

    printblock!("key", key);

    let plaintext = "hello world 😎😎😎 big john machine xd 123 xd";
    println!("plaintext len {}", plaintext.len());

    let mut ciphertext = Vec::new();
    let mut encoder: ElectronicCodeBook<&mut Vec<u8>, __m128i, HWAesEncoder> = ElectronicCodeBook::new(&mut ciphertext, key);

    encoder.write_bytes(plaintext.as_bytes()).unwrap();
    println!("finalising");
    encoder.finalise().unwrap();

    println!("{:02x?}", ciphertext);
    println!("ciphertext len {}", ciphertext.len());

}

