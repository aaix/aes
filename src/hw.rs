use std::arch::{asm, x86_64::*};

use crate::traits::{AESDecoder, AESEncoder, BlockOp};



impl BlockOp for __m128i {
    fn display(&self) -> u128 {
        unsafe {std::mem::transmute::<_, u128>(*self)}.to_be()
    }

    fn from_slice(slice: &[u8; 16]) -> Self {
        unsafe {_mm_loadu_si128(slice.as_ptr() as *const __m128i)}
    }
    
    fn to_slice(self) -> [u8; 16] {
        unsafe {std::mem::transmute(self)}
    }
    
}



pub struct HWAesEncoder {}


fn expand_key_128<const RCON: i32>(prev_key: __m128i) -> __m128i {
    unsafe {
        // _mm_aeskegenassist_si128 doesnt get inlined?
        // let assist =  _mm_aeskeygenassist_si128::<RCON>(prev_key);

        let assist: __m128i;
        asm!(
            "AESKEYGENASSIST {assist}, {prev}, {round}",
            assist = out(xmm_reg) assist,
            prev = in(xmm_reg) prev_key,
            round = const RCON,
        );

        let temp_assist =  _mm_shuffle_epi32::<0xFF>(assist);
        
        let mut next_key = prev_key;
        let mut temp_shift =  _mm_slli_si128::<4>(prev_key);
        next_key =  _mm_xor_si128(next_key, temp_shift) ;
        
        temp_shift =  _mm_slli_si128::<4>(temp_shift) ;
        next_key =  _mm_xor_si128(next_key, temp_shift) ;
        
        temp_shift =  _mm_slli_si128::<4>(temp_shift);
        next_key =  _mm_xor_si128(next_key, temp_shift);
        
        _mm_xor_si128(next_key, temp_assist)
    }

}

impl AESEncoder<__m128i> for HWAesEncoder {
    
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
    
    fn do_first_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
           "PXOR {state}, [{rkey}]",
           state = inout(xmm_reg) state,
           rkey = in(reg) rkey,
        )};
        state
    }

    fn gen_keys(key: __m128i) -> [__m128i; 11] {

        let mut keys = [unsafe {_mm_setzero_si128()}; 11];
        keys[0] = key;
       
        keys[1]  = expand_key_128::<0x01>(keys[0]);
        keys[2]  = expand_key_128::<0x02>(keys[1]);
        keys[3]  = expand_key_128::<0x04>(keys[2]);
        keys[4]  = expand_key_128::<0x08>(keys[3]);
        keys[5]  = expand_key_128::<0x10>(keys[4]);
        keys[6]  = expand_key_128::<0x20>(keys[5]);
        keys[7]  = expand_key_128::<0x40>(keys[6]);
        keys[8]  = expand_key_128::<0x80>(keys[7]);
        keys[9]  = expand_key_128::<0x1B>(keys[8]);
        keys[10] = expand_key_128::<0x36>(keys[9]);
        
        keys
    }
    
}


pub struct HWAesDecoder {}

impl AESDecoder<__m128i> for HWAesDecoder {

    fn do_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
            "AESDEC {state}, [{key}]",
            state = inout(xmm_reg) state,
            key = in(reg) rkey,
        )};

        state
    }
    
    fn do_final_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
            "AESDECLAST {state}, [{key}]",
            state = inout(xmm_reg) state,
            key = in(reg) rkey,
        )};

        state
    }
    
    fn do_first_round(mut state: __m128i, rkey: &__m128i) -> __m128i {
        unsafe {asm!(
           "PXOR {state}, [{rkey}]",
           state = inout(xmm_reg) state,
           rkey = in(reg) rkey,
        )};
        state
    }
    
    fn gen_keys(key: __m128i) -> [__m128i; 11] {

        let mut keys = [unsafe {_mm_setzero_si128()}; 11];
        keys[0] = key;
       
        keys[1]  = expand_key_128::<0x01>(keys[0]);
        keys[2]  = expand_key_128::<0x02>(keys[1]);
        keys[3]  = expand_key_128::<0x04>(keys[2]);
        keys[4]  = expand_key_128::<0x08>(keys[3]);
        keys[5]  = expand_key_128::<0x10>(keys[4]);
        keys[6]  = expand_key_128::<0x20>(keys[5]);
        keys[7]  = expand_key_128::<0x40>(keys[6]);
        keys[8]  = expand_key_128::<0x80>(keys[7]);
        keys[9]  = expand_key_128::<0x1B>(keys[8]);
        keys[10] = expand_key_128::<0x36>(keys[9]);

        let mut dkeys = [unsafe { _mm_setzero_si128() }; 11];

        dkeys[0] = keys[10];
        for i in 1..10 {
            // apply InvMixColumns to the rkeys
            dkeys[i] = unsafe { _mm_aesimc_si128(keys[10 - i]) };
        }
        dkeys[10] = keys[0];

        dkeys
    }
    
}