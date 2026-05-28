use std::arch::x86_64::{__m128i, _mm_set_epi32};

use crate::{hw::HWAesDecoder, modes::{cbc::CBCDecrypt, traits::BlockCipherDecoderMode}, padding::pkcs7::PCKCS7Padding, traits::BlockOp};

fn padding_oracle(guess: &[u8], decoded: &mut Vec<u8>, key: __m128i, iv: __m128i) -> bool {
    let mut decoder: CBCDecrypt<16, &mut Vec<u8>, __m128i, HWAesDecoder, PCKCS7Padding<16>> = CBCDecrypt::new(decoded, key, iv);
    decoder.write_bytes(&guess).unwrap();

    decoder.finalise().is_ok()
}

pub fn padding_oracle_attack() {
    let key_idk = unsafe {_mm_set_epi32(5222,15122,-8686,122225)};
    let iv_i_stole = unsafe {_mm_set_epi32(5, -12432, 42314, 111111)};


    // 2 blocks
    // plaintext (hex) is  [68, 69, 20, 31, 32, 33, 20, 78, 64, 20, 31, 32, 34, 35, 36, 37, 38, 39, 31, 32, 33]
    let to_decrypt: [u8; 32] = [0xe4, 0xb8, 0x39, 0xd9, 0x2d, 0x5a, 0x1e, 0x9c, 0x55, 0x5d, 0x81, 0xd7, 0x4a, 0x57, 0x3e, 0x83, 0xdf, 0x35, 0xe5, 0xc7, 0xeb, 0xa7, 0xce, 0x40, 0x3c, 0x01, 0x17, 0x9a, 0x4c, 0xf7, 0xf8, 0x46];
    let mut plaintext:[u8; 32]  = [0; 32];

    let c1: [u8; 16] = to_decrypt[0..16].try_into().unwrap();
    let c2: [u8; 16] = to_decrypt[16..32].try_into().unwrap();

    let oracle = |guess: &[u8]| {
        let mut scratch = Vec::new();
        padding_oracle(guess, &mut scratch, key_idk, iv_i_stole)
    };

    let p2 = do_padding_oracle_attack(c1, c2, oracle);
    let p1 = do_padding_oracle_attack(iv_i_stole.to_slice(), c1, oracle);

    plaintext[0..16].copy_from_slice(&p1);
    plaintext[16..32].copy_from_slice(&p2);

    println!("recovered {:02x?}", plaintext);
    // println!("as string {}", String::from_utf8_lossy(&plaintext))


}


pub fn do_padding_oracle_attack<Oracle>(c1: [u8; 16], c2: [u8; 16], oracle: Oracle) -> [u8; 16]
where Oracle: Fn(&[u8]) -> bool
{

    let mut c1_prime = c1;

    println!("decrypting {:02x?}", c2);

    let mut p2: [u8; 16] = [0u8; 16];

    let mut intermediate: [u8; 16] = [0; 16];

    for index in (0..16).rev() {
        println!("recovering {index}");
        let padding_bytes = (16 - index) as u8;

        for i in (index + 1)..16 {
            // make recovered bytes decrypt to the desired padding value
            c1_prime[i] = intermediate[i] ^ padding_bytes;
        }


        let mut found = false;
        for _ in 0..=255u8 {
            c1_prime[index] = c1_prime[index].wrapping_add(1);
            let mut guess = [0u8; 32];
            guess[0..16].copy_from_slice(&c1_prime);
            guess[16..32].copy_from_slice(&c2);

            let padding_ok = oracle(&guess);
            
            if !padding_ok {continue;}
            intermediate[index] = c1_prime[index] ^ padding_bytes;
            p2[index] = intermediate[index] ^ c1[index];
            found=true;
            break;
        }

        if !found {
            panic!("could find {index}");
        }
        

    }
    println!("c1_prime      {:02x?}", c1_prime);
    println!("p2            {:02x?}", p2);
    
    p2

}