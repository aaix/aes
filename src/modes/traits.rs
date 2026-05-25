use std::io;

use crate::traits::{AESDecoder, AESEncoder, Blockable};

pub trait BlockCipherEncoderMode<Encoder, Block, W>
where Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize>;
    fn finalise(self) -> io::Result<usize>;
}
