use crate::{padding::traits::Padding, traits::Blockable};

pub struct PCKCS7Padding<const SIZE: usize> {}

impl<const SIZE: usize, Block: Blockable<SIZE>> Padding<SIZE, Block> for PCKCS7Padding<SIZE> {
    fn pad_block(plaintext: &[u8]) -> Block {
        let plaintext_len = plaintext.len();
        let padding_len = Block::size() - plaintext_len;

        let mut slice = [padding_len as u8; SIZE];
        slice[0..plaintext_len].copy_from_slice(plaintext);
        Block::from_slice(&slice)
    }
}
