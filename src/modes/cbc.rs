use std::{io, marker::PhantomData};

use crate::{modes::{helpers::PartialBlockHelper, traits::{BlockCipherDecoderMode, BlockCipherEncoderMode}}, padding::traits::Padding, traits::{AESDecoder, AESEncoder, BlockOp, Blockable}};

pub struct CBCEncrypt<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Encoder: AESEncoder<Block, SIZE>, PaddingStrategy> {
    writer: W,
    key: Block,
    partial_block: [u8; SIZE],
    partial_len: usize,
    encoder: PhantomData<Encoder>,
    padding: PhantomData<PaddingStrategy>,

    last_ciphertext: [u8; SIZE],
}

impl<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Encoder: AESEncoder<Block, SIZE>, PaddingStrategy: Padding<SIZE, Block>> CBCEncrypt<SIZE, W, Block, Encoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block, iv: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; SIZE],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,

            last_ciphertext: iv.to_slice(),
        }
    }
}

impl<const SIZE: usize, Encoder: AESEncoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write, PaddingStrategy: Padding<SIZE, Block>> BlockCipherEncoderMode<SIZE, Encoder, Block, W, PaddingStrategy> for CBCEncrypt<SIZE, W, Block, Encoder, PaddingStrategy> {

    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        let mut helper = PartialBlockHelper::new(
            &mut self.partial_block,
            &mut self.partial_len,
            data
        );

        let mut written = 0;
        while let Some(chunk) = helper.take() {
            written += chunk.len();
            let block: [u8; SIZE] = self.last_ciphertext.xor(chunk);

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


        Ok(SIZE)
    }
}

pub struct CBCDecrypt<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Decoder: AESDecoder<Block, SIZE>, PaddingStrategy> {
    writer: W,
    key: Block,
    partial_block: [u8; SIZE],
    partial_len: usize,
    encoder: PhantomData<Decoder>,
    padding: PhantomData<PaddingStrategy>,

    last_ciphertext: [u8; SIZE],
}

impl<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Decoder: AESDecoder<Block, SIZE>, PaddingStrategy: Padding<SIZE, Block>> CBCDecrypt<SIZE, W, Block, Decoder, PaddingStrategy> {
    pub fn new(writer: W, key: Block, iv: Block) -> Self {
        Self {
            writer,
            key,
            partial_block: [0; SIZE],
            partial_len: 0,
            encoder: PhantomData,
            padding: PhantomData,

            last_ciphertext: iv.to_slice(),
        }
    }
}

impl<const SIZE: usize, Decoder, Block, W, PaddingStrategy>
    BlockCipherDecoderMode<SIZE, Decoder, Block, W, PaddingStrategy>
for CBCDecrypt<SIZE, W, Block, Decoder, PaddingStrategy>
where Decoder: AESDecoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write, PaddingStrategy: Padding<SIZE, Block>
{

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

            let xored: [u8; SIZE] = self.last_ciphertext.xor(&plaintext);
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