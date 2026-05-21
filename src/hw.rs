use std::arch::{asm, x86_64::{__m128i, *}};

use crate::traits::{AESDecoder, AESEncoder};

pub struct HWAesEncoder {}


impl HWAesEncoder {
    unsafe fn expand_key_128<const RCON: i32>(prev_key: __m128i) -> __m128i {


        let assist = _mm_aeskeygenassist_si128::<RCON>(prev_key);
        let temp_assist = _mm_shuffle_epi32::<0xFF>(assist);
        
        let mut next_key = prev_key;
        let mut temp_shift = _mm_slli_si128::<4>(prev_key);
        next_key = _mm_xor_si128(next_key, temp_shift);
        
        temp_shift = _mm_slli_si128::<4>(temp_shift);
        next_key = _mm_xor_si128(next_key, temp_shift);
        
        temp_shift = _mm_slli_si128::<4>(temp_shift);
        next_key = _mm_xor_si128(next_key, temp_shift);
        
        _mm_xor_si128(next_key, temp_assist)
    }
}

impl AESEncoder for HWAesEncoder {
    
    fn do_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
            "AESENC {state}, [{key}]",
            state = inout(xmm_reg) state,
            key = in(reg) rkey,
        )};

        state
    }
    
    fn do_final_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
            "AESENCLAST {state}, [{key}]",
            state = inout(xmm_reg) state,
            key = in(reg) rkey,
        )};

        state
    }
    
    fn do_first_round(mut state: __m128i, rkey: __m128i) -> __m128i {
        unsafe {asm!(
           "PXOR {state}, {rkey}",
           state = inout(xmm_reg) state,
           rkey = in(xmm_reg) rkey,
        )};
        state
    }

    fn gen_keys(key: __m128i) -> [__m128i; 11] {
        unsafe {
            let mut keys = [_mm_setzero_si128(); 11];
            keys[0] = key;
            
            // Generate keys 1 to 10 using their respective round constants (RCON)
            keys[1]  = Self::expand_key_128::<0x01>(keys[0]);
            keys[2]  = Self::expand_key_128::<0x02>(keys[1]);
            keys[3]  = Self::expand_key_128::<0x04>(keys[2]);
            keys[4]  = Self::expand_key_128::<0x08>(keys[3]);
            keys[5]  = Self::expand_key_128::<0x10>(keys[4]);
            keys[6]  = Self::expand_key_128::<0x20>(keys[5]);
            keys[7]  = Self::expand_key_128::<0x40>(keys[6]);
            keys[8]  = Self::expand_key_128::<0x80>(keys[7]);
            keys[9]  = Self::expand_key_128::<0x1B>(keys[8]);
            keys[10] = Self::expand_key_128::<0x36>(keys[9]);
            
            keys
        }
    }
    
}


pub struct HWAesDecoder {}

impl AESDecoder for HWAesDecoder {
    fn do_round(mut state: __m128i, key: __m128i) -> __m128i {
        unsafe {asm!(
            "AESDEC {state}, {key}",
            state = inout(xmm_reg) state,
            key = in(xmm_reg) key,
        )};

        state
    }
    
    fn do_final_round(mut state: __m128i, key: __m128i) -> __m128i {
        unsafe {asm!(
            "AESDECLAST {state}, {key}",
            state = inout(xmm_reg) state,
            key = in(xmm_reg) key,
        )};

        state
    }
    
}