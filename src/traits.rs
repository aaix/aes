use crate::printblock;

pub trait BlockOp<const SIZE: usize> {
    fn display(&self) -> String;
    fn from_slice(slice: &[u8; SIZE]) -> Self;
    fn to_slice(self) -> [u8; SIZE];
    fn xor(&self, other: &Self) -> Self;
    fn size() -> usize;
}

impl<const SIZE: usize> BlockOp<SIZE> for [u8; SIZE] {
    fn display(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }
    fn from_slice(slice: &[u8; SIZE]) -> Self {
        *slice
    }
    
    fn to_slice(self) -> [u8; SIZE] {
        self
    }

    fn xor(&self, other: &Self) -> Self {
        std::array::from_fn(|i| self[i] ^ other[i])
    }

    fn size() -> usize {SIZE}
}

pub trait Blockable<const SIZE: usize>: Copy + BlockOp<SIZE> {}
impl<const SIZE: usize, T: Copy + BlockOp<SIZE>> Blockable<SIZE> for T {}



pub trait AESEncoder<Block, const SIZE: usize>
where Block: Blockable<SIZE>
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
        // printblock!("first rkey", first_rkey);
        // printblock!("first round", state);

        for rkey in &keys[1..10] {
            state = Self::do_round(state, rkey);
            // printblock!("intermediate rkey", *rkey);
            // printblock!("intermediate round", state);

        };

        let last_rkey = keys[10];
        state = Self::do_final_round(state, &last_rkey);
        // printblock!("final rkey", last_rkey);
        // printblock!("final round", state);

        state

    }
}

pub trait AESDecoder<Block, const SIZE: usize>
where Block: Copy + Sized + BlockOp<SIZE>
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
        // printblock!("first rkey", first_rkey);
        // printblock!("first round", state);

        for rkey in &keys[1..10] {
            state = Self::do_round(state, rkey);
            // printblock!("intermediate rkey", *rkey);
            // printblock!("intermediate round", state);

        };

        let last_rkey = keys[10];
        state = Self::do_final_round(state, &last_rkey);
        // printblock!("final rkey", last_rkey);
        // printblock!("final round", state);

        state

    }
}