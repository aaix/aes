use crate::traits::Blockable;

pub trait Padding<const SIZE: usize, Block: Blockable<SIZE>> {
    fn pad_block(partial: &[u8]) -> Block;
}