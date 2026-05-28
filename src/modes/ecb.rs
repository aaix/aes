use std::{io, marker::PhantomData};

use crate::{modes::{helpers::PartialBlockHelper, traits::{BlockCipherDecoderMode, BlockCipherEncoderMode}}, padding::traits::Padding, traits::{AESDecoder, AESEncoder, Blockable}};

pub struct ECBEncrypt<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Encoder: AESEncoder<Block, SIZE>, PaddingStrategy: Padding<SIZE, Block>> {
    writer: W,
    key: Block,
    partial_block: [u8; SIZE],
    partial_len: usize,
    encoder: PhantomData<Encoder>,
    padding: PhantomData<PaddingStrategy>,
}

impl<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Encoder: AESEncoder<Block, SIZE>, PaddingStrategy: Padding<SIZE, Block>> ECBEncrypt<SIZE, W, Block, Encoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; SIZE],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,
        }
    }
}

impl<const SIZE: usize, Encoder: AESEncoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write, PaddingStrategy: Padding<SIZE, Block>> BlockCipherEncoderMode<SIZE, Encoder, Block, W, PaddingStrategy> for ECBEncrypt<SIZE, W, Block, Encoder, PaddingStrategy> {

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


        Ok(SIZE)
    }
}

pub struct ECBDecrypt<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Decoder: AESDecoder<Block, SIZE>, PaddingStrategy> {
    writer: W,
    key: Block,
    partial_block: [u8; SIZE],
    partial_len: usize,
    encoder: PhantomData<Decoder>,
    padding: PhantomData<PaddingStrategy>,
    last_full_block: Option<[u8; SIZE]>,
}

impl<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Decoder: AESDecoder<Block, SIZE>, PaddingStrategy: Padding<SIZE, Block>> ECBDecrypt<SIZE, W, Block, Decoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; SIZE],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,
            last_full_block: None,
        }
    }
}

impl<const SIZE: usize, Decoder: AESDecoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write, PaddingStrategy: Padding<SIZE, Block>> BlockCipherDecoderMode<SIZE, Decoder, Block, W, PaddingStrategy> for ECBDecrypt<SIZE, W, Block, Decoder, PaddingStrategy> {

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

            if let Some(last_full_block) = self.last_full_block {
                self.writer.write_all(&last_full_block)?;
            }
            self.last_full_block = Some(plaintext.to_slice());
            
        }

        return Ok(written);
    }

    fn finalise(mut self) -> io::Result<usize> {

        self.writer.flush()?;

        if self.partial_len != 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Unexpected partial remaining block for ECB mode: {} bytes remaining", self.partial_len)
            ));
        }


        if let Some(last_full_block) = self.last_full_block {
            let plaintext_len = PaddingStrategy::remove_padding(&last_full_block)?;
            self.writer.write_all(&last_full_block[0..plaintext_len])?;
            self.writer.flush()?;
            return Ok(plaintext_len);
        }

        Ok(0)
    }
}