use crate::{padding::traits::Padding, traits::Blockable};

pub struct ZeroPadding<const SIZE: usize> {}

impl<const SIZE: usize, Block: Blockable<SIZE>> Padding<SIZE, Block> for ZeroPadding<SIZE> {
    fn pad_block(plaintext: &[u8]) -> Block {
        let plaintext_len = plaintext.len();

        let mut slice = [0u8; SIZE];
        slice[0..plaintext_len].copy_from_slice(plaintext);
        Block::from_slice(&slice)
    }
}
