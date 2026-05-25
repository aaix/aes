use std::{io, marker::PhantomData};

use crate::{modes::{helpers::PartialBlockHelper, traits::{BlockCipherDecoderMode, BlockCipherEncoderMode}}, traits::{AESDecoder, AESEncoder, Blockable}};

pub struct ECBEncrypt<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Encoder>,
}

impl<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>> ECBEncrypt<W, Block, Encoder> {
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

impl<Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write> BlockCipherEncoderMode<Encoder, Block, W> for ECBEncrypt<W, Block, Encoder> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();
            let encoded = Encoder::encrypt(Block::from_slice(&chunk), self.key);

            self.writer.write_all(&encoded.to_slice())?;
        }

        return Ok(written);
    }

    fn finalise(mut self) -> io::Result<usize> {

        println!("finalising {}", self.partial_len);

        if self.partial_len == 0 {
            return Ok(0)
        }

        let mut final_block = self.partial_block;
        // 0 pad
        final_block[self.partial_len..16].iter_mut().for_each(|b| *b = 0);
        println!("padded final block {:02x?}", final_block);

        let encoded = Encoder::encrypt(Block::from_slice(&final_block), self.key);


        self.writer.write_all(&encoded.to_slice())?;


        Ok(16)
    }
}

pub struct ECBDecrypt<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Decoder>,
}

impl<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>> ECBDecrypt<W, Block, Decoder> {
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

impl<Decoder: AESDecoder<Block>, Block: Blockable, W: io::Write> BlockCipherDecoderMode<Decoder, Block, W> for ECBDecrypt<W, Block, Decoder> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();
            let encoded = Decoder::decrypt(Block::from_slice(&chunk), self.key);

            self.writer.write_all(&encoded.to_slice())?;
        }

        return Ok(written);
    }

    fn finalise(self) -> io::Result<usize> {

        if self.partial_len == 0 {
            return Ok(0)
        }

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected partial remaining block for ECB mode: {} bytes remaining", self.partial_len)
        ));
    }
}