pub struct PartialBlockHelper<'encoder, 'data, const SIZE: usize> {
    partial_block: &'encoder mut [u8; SIZE],
    partial_len: &'encoder mut usize,
    data: &'data [u8],
    
    combined_chunk: [u8; SIZE],
}

impl<'encoder, 'data, const SIZE: usize, > PartialBlockHelper<'encoder, 'data, SIZE> {

    pub fn new(
        partial_block: &'encoder mut [u8; SIZE],
        partial_len: &'encoder mut usize,
        data: &'data [u8],
    ) -> Self {
        Self { partial_block, partial_len, data, combined_chunk: [0u8; SIZE] }
    }


    pub fn take(&mut self) -> Option<&[u8; SIZE]> {

        if self.data.len() == 0 {
            return None
        }


        // partial + incoming is not a complete block
        if self.data.len() + *self.partial_len < SIZE {
            self.partial_block[*self.partial_len..*self.partial_len + self.data.len()]
                .copy_from_slice(self.data);

            *self.partial_len += self.data.len();
            // println!("wrote {} to partial, new len {}", self.data.len(), self.partial_len);

            return None;
        }

        // we have a partial block and enough incoming data for atleast 1 block
        if *self.partial_len > 0 {
            let to_take = SIZE - *self.partial_len;
            // println!("taking {} from partial and {} from data", *self.partial_len, to_take);
            self.combined_chunk[0..*self.partial_len].copy_from_slice(&self.partial_block[0..*self.partial_len]);
            self.combined_chunk[*self.partial_len..SIZE].copy_from_slice(&self.data[0..to_take]);
            
            *self.partial_len = 0;

            self.data = &self.data[to_take..self.data.len()];
            
            return Some(&self.combined_chunk);
        }

        // just a single block
        if self.data.len() >= SIZE {
            // println!("taking single chunk");
            let chunk = &self.data[0..SIZE];
            self.data = &self.data[SIZE..self.data.len()];
            return Some(chunk.try_into().unwrap());
        }

        // there is not enough block left
        // println!("storing {} in partial", self.data.len());
        self.partial_block[0..self.data.len()].copy_from_slice(&self.data);

        None
    }
}
