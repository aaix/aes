use std::arch::x86_64::{__m128i};


pub trait AESEncoder {

    fn do_first_round(plaintext: __m128i, rkey: __m128i) -> __m128i;

    fn do_round(state: __m128i, rkey: &__m128i) -> __m128i;

    fn do_final_round(state: __m128i, rkey: &__m128i) -> __m128i;

    fn gen_keys(rounds: usize, key: __m128i) -> Vec<__m128i>;

    fn encrypt(plaintext: __m128i, key: __m128i) -> __m128i {

        let rounds = 10;

        let mut state: __m128i;
        let keys = Self::gen_keys(rounds, key);

        let first_rkey = keys[0];
        state = Self::do_first_round(plaintext, first_rkey);


        for rkey in &keys[1..(rounds-2)] {
            state = Self::do_round(state, rkey);
        };

        let last_rkey = keys.last().unwrap();
        Self::do_final_round(state, last_rkey)
    }
}

pub trait AESDecoder {
    fn do_round(state: __m128i, key: __m128i) -> __m128i;

    fn do_final_round(state: __m128i, key: __m128i) -> __m128i;
}