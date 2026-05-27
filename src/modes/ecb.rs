use std::{io, marker::PhantomData};

use crate::{modes::{helpers::PartialBlockHelper, traits::{BlockCipherDecoderMode, BlockCipherEncoderMode}}, padding::traits::Padding, traits::{AESDecoder, AESEncoder, Blockable}};

pub struct ECBEncrypt<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>, PaddingStrategy: Padding<Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Encoder>,
    padding: PhantomData<PaddingStrategy>,
}

impl<W: io::Write, Block: Blockable, Encoder: AESEncoder<Block>, PaddingStrategy: Padding<Block>> ECBEncrypt<W, Block, Encoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,
        }
    }
}

impl<Encoder: AESEncoder<Block>, Block: Blockable, W: io::Write, PaddingStrategy: Padding<Block>> BlockCipherEncoderMode<Encoder, Block, W, PaddingStrategy> for ECBEncrypt<W, Block, Encoder, PaddingStrategy> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();
            let ciphertext = Encoder::encrypt(Block::from_slice(&chunk), self.key);

            self.writer.write_all(&ciphertext.to_slice())?;
        }

        return Ok(written);
    }

    fn finalise(mut self) -> io::Result<usize> {

        println!("finalising {}", self.partial_len);

        if self.partial_len == 0 {
            return Ok(0)
        }

        let final_block = PaddingStrategy::pad_block(&self.partial_block[0..self.partial_len]);

        let encoded = Encoder::encrypt(final_block, self.key);


        self.writer.write_all(&encoded.to_slice())?;
        self.writer.flush()?;


        Ok(16)
    }
}

pub struct ECBDecrypt<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>, PaddingStrategy> {
    writer: W,
    key: Block,
    partial_block: [u8; 16],
    partial_len: usize,
    encoder: PhantomData<Decoder>,
    padding: PhantomData<PaddingStrategy>,
}

impl<W: io::Write, Block: Blockable, Decoder: AESDecoder<Block>, PaddingStrategy: Padding<Block>> ECBDecrypt<W, Block, Decoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; 16],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,
        }
    }
}

impl<Decoder: AESDecoder<Block>, Block: Blockable, W: io::Write, PaddingStrategy: Padding<Block>> BlockCipherDecoderMode<Decoder, Block, W, PaddingStrategy> for ECBDecrypt<W, Block, Decoder, PaddingStrategy> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();
            let plaintext = Decoder::decrypt(Block::from_slice(&chunk), self.key);

            self.writer.write_all(&plaintext.to_slice())?;
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
            format!("Unexpected partial remaining block for ECB mode: {} bytes remaining", self.partial_len)
        ));
    }
}