use std::arch::x86_64::*;

use aes::hw::{HWAesDecoder, HWAesEncoder};
use aes::modes::ecb::{ECBDecrypt, ECBEncrypt};
use aes::modes::traits::{BlockCipherDecoderMode, BlockCipherEncoderMode};
use aes::printblock;
use aes::traits::{AESDecoder, AESEncoder, BlockOp};

// https://legacy.cryptool.org/en/cto/aes-step-by-step

fn main() {

    assert!(is_x86_feature_detected!("aes"));

    let key = unsafe {_mm_set_epi32(5222,0,0,1)};

    printblock!("key", key);

    let plaintext = "hello world 😎😎😎 big john machine xd 123 xd";
    println!("as string: '{}'", plaintext);
    println!("plaintext len {}", plaintext.as_bytes().len());
    println!("plaintext is {:02x?}", plaintext.as_bytes());

    let mut ciphertext = Vec::new();
    let mut encoder: ECBEncrypt<&mut Vec<u8>, __m128i, HWAesEncoder> = ECBEncrypt::new(&mut ciphertext, key);

    encoder.write_bytes(plaintext.as_bytes()).unwrap();
    encoder.write_bytes("sentence 2 xdd".as_bytes()).unwrap();
    println!("finalising");
    encoder.finalise().unwrap();

    println!("ciphertext is {:02x?}", ciphertext);
    println!("ciphertext len {}", ciphertext.len());

    let mut decoded = Vec::new();
    let mut decoder: ECBDecrypt<&mut Vec<u8>, __m128i, HWAesDecoder> = ECBDecrypt::new(&mut decoded, key);
    decoder.write_bytes(&ciphertext).unwrap();
    decoder.finalise().unwrap();

    println!("decoded len {}", decoded.len());
    println!("decoded ciphertext to {:02x?}", decoded);
    println!("as string: '{}'", String::from_utf8_lossy(&decoded));

}

