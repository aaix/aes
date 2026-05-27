use crate::traits::Blockable;

pub trait Padding<Block: Blockable> {
    fn pad_block(partial: &[u8]) -> Block;
}