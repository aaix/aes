use std::arch::x86_64::{__m128i};

use crate::printblock;


pub trait AESEncoder {

    fn do_first_round(plaintext: __m128i, rkey: __m128i) -> __m128i;

    fn do_round(state: __m128i, rkey: &__m128i) -> __m128i;

    fn do_final_round(state: __m128i, rkey: &__m128i) -> __m128i;

    fn gen_keys(key: __m128i) -> [__m128i; 11];

    fn encrypt(plaintext: __m128i, key: __m128i) -> __m128i {

        let mut state: __m128i;
        let keys = Self::gen_keys(key);

        let first_rkey = keys[0];
        state = Self::do_first_round(plaintext, first_rkey);
        printblock!("first round", state);

        for rkey in &keys[1..10] {
            state = Self::do_round(state, rkey);
            printblock!("intermediate round", state);

        };

        let last_rkey = keys[10];
        state = Self::do_final_round(state, &last_rkey);
        printblock!("final round", state);

        state

    }
}

pub trait AESDecoder {
    fn do_round(state: __m128i, key: __m128i) -> __m128i;

    fn do_final_round(state: __m128i, key: __m128i) -> __m128i;
}