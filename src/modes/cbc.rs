use std::{io, marker::PhantomData};

use crate::{modes::{helpers::PartialBlockHelper, traits::{BlockCipherDecoderMode, BlockCipherEncoderMode}}, traits::{AESDecoder, AESEncoder, BlockOp, Blockable}};

pub struct CBCEncrypt<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Encoder>,

    last_ciphertext: [u8; 16],
}

impl<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>> CBCEncrypt<W, Block, Encoder> {
    pub fn new(writer: W, key: Block, iv: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData,

            last_ciphertext: iv.to_slice(),
        }
    }
}

impl<Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write> BlockCipherEncoderMode<Encoder, Block, W> for CBCEncrypt<W, Block, Encoder> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();
            let block: [u8; 16] = self.last_ciphertext.xor(chunk);

            self.last_ciphertext = Encoder::encrypt(Block::from_slice(&block), self.key).to_slice();

            self.writer.write_all(&self.last_ciphertext)?;
        }

        return Ok(written);
    }

    fn finalise(mut self) -> io::Result<usize> {

        if self.partial_len == 0 {
            return Ok(0)
        }

        let mut final_block = self.partial_block;

        final_block[self.partial_len..16].iter_mut().for_each(|b| *b = 0);
        println!("padded final block {:02x?}", final_block);

        let ciphertext = Encoder::encrypt(Block::from_slice(&final_block.xor(&self.last_ciphertext)), self.key).to_slice();



        self.writer.write_all(&ciphertext.to_slice())?;
        self.writer.flush()?;


        Ok(16)
    }
}

pub struct CBCDecrypt<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Decoder>,

    last_ciphertext: [u8; 16],
}

impl<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>> CBCDecrypt<W, Block, Decoder> {
    pub fn new(writer: W, key: Block, iv: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData,

            last_ciphertext: iv.to_slice(),
        }
    }
}

impl<Decoder: AESDecoder<Block>, Block: Blockable, W: io::Write> BlockCipherDecoderMode<Decoder, Block, W> for CBCDecrypt<W, Block, Decoder> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();

            let plaintext = Decoder::decrypt(Block::from_slice(&chunk), self.key).to_slice();

            let xored: [u8; 16] = self.last_ciphertext.xor(&plaintext);
            self.last_ciphertext.copy_from_slice(chunk);


            self.writer.write_all(&xored)?;
        }

        return Ok(written);
    }

    fn finalise(mut self) -> io::Result<usize> {

        self.writer.flush()?;

        if self.partial_len == 0 {
            return Ok(0)
        }

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected partial remaining block for CBC mode: {} bytes remaining", self.partial_len)
        ));
    }
}