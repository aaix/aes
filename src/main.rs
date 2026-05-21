use std::arch::x86_64::*;

use aes::hw::{HWAesDecoder, HWAesEncoder};
use aes::traits::{AESDecoder, AESEncoder};

fn cast(mm: __m128i) -> u128 {
    unsafe {std::mem::transmute(mm) }
}

fn main() {
    let key = unsafe {_mm_set_epi32(5,5,5,5)};

    println!("key is {:x?}", cast(key));

    let plaintext = unsafe {_mm_set_epi32(i32::MIN, i32::MIN, i32::MIN, i32::MIN)};

    println!("plaintext is {:x?}", cast(plaintext));

    let ciphertext = <HWAesEncoder as AESEncoder>::encrypt(plaintext, key);
    println!("ciphertext is {:x?}", cast(ciphertext));



}

