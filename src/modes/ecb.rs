use std::{io, marker::PhantomData};

use crate::{modes::traits::BlockCipherEncoderMode, traits::{AESEncoder, Blockable}};

pub struct ElectronicCodeBook<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Encoder>,
}

impl<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>> ElectronicCodeBook<W, Block, Encoder> {
    pub fn new(writer: W, key: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData
        }
    }
}

impl<Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write> BlockCipherEncoderMode<Encoder, Block, W> for ElectronicCodeBook<W, Block, Encoder> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {

        // partial + incoming is not a complete block
        if data.len() + self.partial_len < 16 {
            self.partial_block[self.partial_len..self.partial_len + data.len()]
                .copy_from_slice(data);

            return Ok(0);
        }

        // we have a partial block and enough incoming data for atleast 1 block
        let offset = if self.partial_len > 0 {
            let to_take = 16 - self.partial_len;
            println!("taking {to_take}");
            let mut chunk = [0u8; 16];
            chunk[0..self.partial_len].copy_from_slice(&self.partial_block[0..self.partial_len]);
            chunk[self.partial_len..16].copy_from_slice(&data[0..to_take]);
            
            let encoded = Encoder::encrypt(Block::from_slice(&chunk), self.key);

            self.writer.write_all(&encoded.to_slice())?;
            to_take
        } else {
            0
        };

        for chunk in data[offset..data.len()].chunks(16) {
            let len = chunk.len();
            println!("processing chunk len {len}");
            if len != 16 {
                self.partial_block[0..len].copy_from_slice(&chunk);
                self.partial_len = len;
                break;
            }

            let encoded = Encoder::encrypt(Block::from_slice(chunk.try_into().unwrap()), self.key);

            self.writer.write_all(&encoded.to_slice())?;
        }
        
        Ok(data.len() + offset)
    }

    fn finalise(mut self) -> io::Result<usize> {

        if self.partial_len == 0 {
            return Ok(0)
        }

        let mut final_block = self.partial_block;
        // 0 pad
        final_block[self.partial_len..16].iter_mut().for_each(|b| *b = 0);

        let encoded = Encoder::encrypt(Block::from_slice(&final_block), self.key);


        self.writer.write_all(&encoded.to_slice())?;


        Ok(16)
    }
}