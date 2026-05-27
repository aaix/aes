use std::io;

use crate::{padding::traits::Padding, traits::{AESDecoder, AESEncoder, Blockable}};

pub trait BlockCipherEncoderMode<Encoder, Block, W, PaddingStrategy>
where Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write, PaddingStrategy: Padding<Block>
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}


pub trait BlockCipherDecoderMode<Decoder, Block, W, PaddingStrategy>
where Decoder: AESDecoder<Block>, Block: Blockable, W: io::Write, PaddingStrategy: Padding<Block>
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}
