use std::{io, marker::PhantomData};

use crate::{modes::{helpers::PartialBlockHelper, traits::{BlockCipherDecoderMode, BlockCipherEncoderMode}}, padding::traits::Padding, traits::{AESDecoder, AESEncoder, BlockOp, Blockable}};

pub struct CBCEncrypt<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>, PaddingStrategy> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Encoder>,
    padding: PhantomData<PaddingStrategy>,

    last_ciphertext: [u8; 16],
}

impl<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>, PaddingStrategy: Padding<Block>> CBCEncrypt<W, Block, Encoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block, iv: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,

            last_ciphertext: iv.to_slice(),
        }
    }
}

impl<Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write, PaddingStrategy: Padding<Block>> BlockCipherEncoderMode<Encoder, Block, W, PaddingStrategy> for CBCEncrypt<W, Block, Encoder, PaddingStrategy> {

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

        let final_block = PaddingStrategy::pad_block(&self.partial_block[0..self.partial_len]);


        let ciphertext = Encoder::encrypt(final_block.xor(&Block::from_slice(&self.last_ciphertext)), self.key).to_slice();



        self.writer.write_all(&ciphertext.to_slice())?;
        self.writer.flush()?;


        Ok(16)
    }
}

pub struct CBCDecrypt<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>, PaddingStrategy> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Decoder>,
    padding: PhantomData<PaddingStrategy>,

    last_ciphertext: [u8; 16],
}

impl<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>, PaddingStrategy: Padding<Block>> CBCDecrypt<W, Block, Decoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block, iv: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,

            last_ciphertext: iv.to_slice(),
        }
    }
}

impl<Decoder: AESDecoder<Block>, Block: Blockable, W: io::Write, PaddingStrategy: Padding<Block>> BlockCipherDecoderMode<Decoder, Block, W, PaddingStrategy> for CBCDecrypt<W, Block, Decoder, PaddingStrategy> {

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