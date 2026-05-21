use std::arch::{asm, x86_64::{__m128i, _mm_setzero_si128}};

use crate::traits::{AESDecoder, AESEncoder};

pub struct HWAesEncoder {}

impl AESEncoder for HWAesEncoder {
    
    fn do_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
            "AESENC {state}, {key}",
            state = inout(xmm_reg) state,
            key = in(xmm_reg) rkey,
        )};

        state
    }
    
    fn do_final_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
            "AESENCLAST {state}, {key}",
            state = inout(xmm_reg) state,
            key = in(xmm_reg) rkey,
        )};

        state
    }
    
    fn do_first_round(mut state: __m128i, rkey: __m128i) -> __m128i {
        unsafe {asm!(
           "PXOR {state}, {rkey}",
           "AESENC {state}, {rkey}",
           state = inout(xmm_reg) state,
           rkey = in(xmm_reg) rkey,
        )};
        state
    }
    
    fn gen_keys(rounds: usize, key: __m128i) -> Vec<__m128i> {
        let data = vec![unsafe{_mm_setzero_si128()}; rounds];
        unsafe {asm!(
            "AESKEYGENASSIST "
        )};

        data
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