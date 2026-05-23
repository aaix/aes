use std::arch::x86_64::{__m128i};

use crate::printblock;

pub trait DisplayBlock {
    fn display(&self) -> u128;
}


impl DisplayBlock for __m128i {
    fn display(&self) -> u128 {
        unsafe {std::mem::transmute::<_, u128>(*self)}.to_be()
    }
}

impl DisplayBlock for [u8; 16] {
    fn display(&self) -> u128 {
        u128::from_be_bytes(*self)
    }
}


pub trait AESEncoder<Block>
where Block: Copy + Sized + DisplayBlock
{

    fn do_first_round(plaintext: Block, rkey: &Block) -> Block;

    fn do_round(state: Block, rkey: &Block) -> Block;

    fn do_final_round(state: Block, rkey: &Block) -> Block;

    fn gen_keys(key: Block) -> [Block; 11];

    fn encrypt(plaintext: Block, key: Block) -> Block {

        let mut state: Block;
        let keys = Self::gen_keys(key);

        let first_rkey = keys[0];
        state = Self::do_first_round(plaintext, &first_rkey);
        printblock!("first rkey", first_rkey);
        printblock!("first round", state);

        for rkey in &keys[1..10] {
            state = Self::do_round(state, rkey);
            printblock!("intermediate rkey", *rkey);
            printblock!("intermediate round", state);

        };

        let last_rkey = keys[10];
        state = Self::do_final_round(state, &last_rkey);
        printblock!("final rkey", last_rkey);
        printblock!("final round", state);

        state

    }
}

pub trait AESDecoder<Block>
where Block: Copy + Sized + DisplayBlock
{


    fn do_first_round(plaintext: Block, rkey: &Block) -> Block;

    fn do_round(state: Block, rkey: &Block) -> Block;

    fn do_final_round(state: Block, rkey: &Block) -> Block;

    fn gen_keys(key: Block) -> [Block; 11];

    fn decrypt(ciphertext: Block, key: Block) -> Block {

        let mut state: Block;
        let keys = Self::gen_keys(key);

        let first_rkey = keys[0];
        state = Self::do_first_round(ciphertext, &first_rkey);
        printblock!("first rkey", first_rkey);
        printblock!("first round", state);

        for rkey in &keys[1..10] {
            state = Self::do_round(state, rkey);
            printblock!("intermediate rkey", *rkey);
            printblock!("intermediate round", state);

        };

        let last_rkey = keys[10];
        state = Self::do_final_round(state, &last_rkey);
        printblock!("final rkey", last_rkey);
        printblock!("final round", state);

        state

    }
}