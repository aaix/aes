use crate::{padding::traits::Padding, traits::Blockable};

pub struct ZeroPadding {}

impl<Block: Blockable> Padding<Block> for ZeroPadding {
    fn pad_block(plaintext: &[u8]) -> Block {
        let plaintext_len = plaintext.len();

        let mut slice = [0u8; 16];
        slice[0..plaintext_len].copy_from_slice(plaintext);
        Block::from_slice(&slice)
    }
}
