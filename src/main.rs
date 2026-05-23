use std::arch::x86_64::*;

use aes::hw::{HWAesDecoder, HWAesEncoder};
use aes::printblock;
use aes::traits::{AESDecoder, AESEncoder, DisplayBlock};

// https://legacy.cryptool.org/en/cto/aes-step-by-step

fn main() {

    assert!(is_x86_feature_detected!("aes"));

    let key = unsafe {_mm_set_epi32(5222,0,0,1)};

    printblock!("key", key);

    let plaintext = [
        'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', '!', '!', '!', '!', 
    ].map(|c| c as u8);

    let state = unsafe {_mm_loadu_si128(plaintext.as_ptr() as *const __m128i)};

    printblock!("plaintext", plaintext);


    let ciphertext = <HWAesEncoder as AESEncoder<__m128i>>::encrypt(state, key);

    println!("");

    let decoded = <HWAesDecoder as AESDecoder<__m128i>>::decrypt(ciphertext, key);

    printblock!("decoded to", decoded);

}

