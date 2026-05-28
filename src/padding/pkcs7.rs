use crate::{padding::traits::{Padding, PaddingError}, traits::Blockable};

pub struct PCKCS7Padding<const SIZE: usize> {}

impl<const SIZE: usize, Block: Blockable<SIZE>> Padding<SIZE, Block> for PCKCS7Padding<SIZE> {
    fn pad_block(plaintext: &[u8]) -> Block {
        let plaintext_len = plaintext.len();
        let padding_len = Block::size() - plaintext_len;

        let mut slice = [padding_len as u8; SIZE];
        slice[0..plaintext_len].copy_from_slice(plaintext);
        Block::from_slice(&slice)
    }
    
    fn remove_padding(last_block: &[u8; SIZE]) -> Result<usize, super::traits::PaddingError> {
        let padding_len = last_block[SIZE - 1];

        if padding_len == 0 {
            return Err(PaddingError::InvalidPadding("Zero padding is not allowed"))
        }

        if padding_len as usize > SIZE {
            return Err(PaddingError::InvalidPadding("Padding len greater than block len"))
        }

        let plaintext_len =  SIZE - padding_len as usize;

        // add a padding oracle
        if !last_block[plaintext_len..SIZE].iter().all(|v| *v == padding_len) {
            return Err(PaddingError::InvalidPadding("Padding is not of expected length"))
        }

        Ok(plaintext_len)
    }
    
}
