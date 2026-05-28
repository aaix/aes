use std::io;

use crate::{padding::traits::Padding, traits::{AESDecoder, AESEncoder, Blockable}};

pub trait BlockCipherEncoderMode<const SIZE: usize, Encoder, Block, W, PaddingStrategy>
where Encoder: AESEncoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write, PaddingStrategy: Padding<SIZE, Block>
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}


pub trait BlockCipherDecoderMode<const SIZE: usize, Decoder, Block, W, PaddingStrategy>
where Decoder: AESDecoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write, PaddingStrategy: Padding<SIZE, Block>
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}

pub trait StreamCipherEncoderMode<const SIZE: usize, Encoder, Block, W>
where Encoder: AESEncoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}

pub trait StreamCipherDecoderMode<const SIZE: usize, Decoder, Block, W>
where Decoder: AESDecoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}