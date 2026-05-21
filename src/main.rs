use std::arch::x86_64::*;

use aes::hw::{HWAesDecoder, HWAesEncoder};
use aes::printblock;
use aes::traits::{AESDecoder, AESEncoder};


fn main() {
    let key = unsafe {_mm_set_epi32(0,0,0,0)};

    printblock!("key", key);


    let plaintext = unsafe {_mm_set_epi32(u32::MAX as i32, u32::MAX as i32, u32::MAX as i32, u32::MAX as i32)};

    printblock!("plaintext", plaintext);


    let ciphertext = <HWAesEncoder as AESEncoder>::encrypt(plaintext, key);


}

