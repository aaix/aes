use std::{io, marker::PhantomData};

use crate::{modes::traits::StreamCipherEncoderMode, traits::{AESEncoder, Blockable}};

pub struct CTREncrypt<const SIZE: usize, W: io::Write, Block: Blockable<SIZE>, Encoder: AESEncoder<Block, SIZE>> {
    writer: W,
    key: Block,
    encoder: PhantomData<Encoder>,

    iv_ctr: [u8; SIZE],
    used_bytes: usize,
    key_stream: [u8; SIZE],
}

impl<const SIZE: usize, W, Block, Encoder> CTREncrypt<SIZE, W, Block, Encoder>
where Encoder: AESEncoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write
{
    pub fn new(output: W, key: Block, iv: Block) -> Self {

        assert!(SIZE >= (u64::BITS / 8) as usize);


        let mut encoder = Self {
            writer: output,
            key,
            encoder: PhantomData,

            iv_ctr: iv.to_slice(),
            used_bytes: 0,
            key_stream: [0; SIZE],

        };
        // generate the next (first) block
        // we start the counter from the iv
        // using a u64 counter
        encoder.make_next_block();
        encoder
    }

    fn make_next_block<'a>(&'a mut self) {
        
        self.increment_key();

        self.key_stream = Encoder::encrypt(Block::from_slice(&self.iv_ctr), self.key).to_slice();

    }

    fn increment_key(&mut self) {
        let slice = &mut self.iv_ctr[(SIZE - (u64::BITS as usize / 8))..SIZE];
        
        // aes ctr counter is be
        let mut ctr = u64::from_be_bytes(slice.try_into().unwrap());
        ctr = ctr.wrapping_add(1);

        slice.copy_from_slice(&ctr.to_be_bytes());

    }
}

impl<const SIZE: usize, W, Encoder, Block> StreamCipherEncoderMode<SIZE, Encoder, Block, W> for CTREncrypt<SIZE, W, Block, Encoder>
where Encoder: AESEncoder<Block, SIZE>, Block: Blockable<SIZE>, W: io::Write
{
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {


        for plaintext in data {
            let key_stream_offset = self.used_bytes;

            let ciphertext = plaintext ^ self.key_stream[key_stream_offset];
            self.writer.write_all(&[ciphertext])?;
            self.used_bytes += 1;

            if self.used_bytes == SIZE {
                self.make_next_block();
                self.used_bytes = 0;
            }
        }

        Ok(data.len())
    }

    fn finalise(mut self) -> io::Result<usize> {
        self.writer.flush()?;
        Ok(0)
    }
}

