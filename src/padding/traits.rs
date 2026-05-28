use std::io;

use crate::traits::Blockable;

#[derive(Debug)]
pub enum PaddingError {
    InvalidPadding(&'static str)
}

impl From<PaddingError> for std::io::Error {
    fn from(value: PaddingError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{value:?}"))
    }
}

pub trait Padding<const SIZE: usize, Block: Blockable<SIZE>> {
    fn pad_block(partial: &[u8]) -> Block;
    fn remove_padding(last_block: &[u8; SIZE]) -> Result<usize, PaddingError>;
}