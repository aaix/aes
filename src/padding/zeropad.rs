use crate::{padding::traits::{Padding, PaddingError}, traits::Blockable};

pub struct ZeroPadding<const SIZE: usize> {}

impl<const SIZE: usize, Block: Blockable<SIZE>> Padding<SIZE, Block> for ZeroPadding<SIZE> {
    fn pad_block(plaintext: &[u8]) -> Block {
        let plaintext_len = plaintext.len();

        let mut slice = [0u8; SIZE];
        slice[0..plaintext_len].copy_from_slice(plaintext);
        Block::from_slice(&slice)
    }
    
    fn remove_padding(last_block: &[u8; SIZE]) -> Result<usize, PaddingError> {
        let mut i = SIZE - 1;
        while last_block[i] == 0 {
            i -= 1;
        }
        Ok(i + 1)
    }
}
