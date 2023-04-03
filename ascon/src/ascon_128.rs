use alloc::vec::Vec;

use crate::ascon_core::{pad, State};

#[inline]
fn u64_from_be_bytes(input: &[u8]) -> u64 {
    u64::from_be_bytes(input.try_into().unwrap())
}

#[inline]
fn u64_from_be_bytes_partial(input: &[u8]) -> u64 {
    let mut tmp = [0u8; 8];
    tmp[0..input.len()].copy_from_slice(input);
    u64::from_be_bytes(tmp)
}

#[inline(always)]
const fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}

const RATE: usize = 8;
const IV: u64 = 0x80400c0600000000;

#[derive(Clone, Copy)]
pub struct Key {
    k1: u64,
    k2: u64,
}

impl Key {
    fn get_k1(&self) -> u64 {
        self.k1
    }
    fn get_k2(&self) -> u64 {
        self.k2
    }
}

impl From<&[u8]> for Key {
    fn from(key: &[u8]) -> Self {
        Self {
            k1: u64_from_be_bytes(&key[..8]),
            k2: u64_from_be_bytes(&key[8..]),
        }
    }
}

pub struct Ascon128 {
    state: State,
    key: Key,
}

impl Ascon128 {
    pub fn new(key: Key, nonce: &[u8]) -> Self {
        let mut state = State::new(
            IV,
            key.get_k1(),
            key.get_k2(),
            u64_from_be_bytes(&nonce[..8]),
            u64_from_be_bytes(&nonce[8..]),
        );

        state.permute_12();
        state[3] ^= key.get_k1();
        state[4] ^= key.get_k2();

        Self { state, key }
    }

    fn permute_12_and_apply_key(&mut self) {
        self.state.permute_12();
        self.state[3] ^= self.key.get_k1();
        self.state[4] ^= self.key.get_k2();
    }

    fn permute_state(&mut self) {
        self.state.permute_6();
    }

    fn process_associated_date(&mut self, associated_data: &[u8]) {
        if !associated_data.is_empty() {
            let mut blocks = associated_data.chunks_exact(RATE);
            for block in blocks.by_ref() {
                self.state[0] ^= u64_from_be_bytes(block);
            }
            self.permute_state();

            let last_block = blocks.remainder();
            self.state[0] ^= pad(last_block.len());
            if !last_block.is_empty() {
                self.state[0] ^= u64_from_be_bytes_partial(last_block);
            }

            self.permute_state();
        }

        self.state[4] ^= 1;
    }

    fn process_encrypt_inplace(&mut self, message: &mut [u8]) {
        let mut blocks = message.chunks_exact_mut(RATE);
        for block in blocks.by_ref() {
            self.state[0] ^= u64_from_be_bytes(&block);
            block.copy_from_slice(&u64::to_be_bytes(self.state[0]));
            self.permute_state();
        }

        let last_block = blocks.into_remainder();
        self.state[0] ^= pad(last_block.len());
        if !last_block.is_empty() {
            self.state[0] ^= u64_from_be_bytes_partial(last_block);
            last_block.copy_from_slice(&u64::to_be_bytes(self.state[0])[0..last_block.len()]);
        }
    }

    fn process_decrypt_inplace(&mut self, ciphertext: &mut [u8]) {
        let mut blocks = ciphertext.chunks_exact_mut(RATE);
        for block in blocks.by_ref() {
            let cx = u64_from_be_bytes(&block);
            block.copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            self.permute_state();
        }

        let last_block = blocks.into_remainder();
        self.state[0] ^= pad(last_block.len());
        if !last_block.is_empty() {
            let cx = u64_from_be_bytes_partial(last_block);
            self.state[0] ^= cx;
            last_block.copy_from_slice(&u64::to_be_bytes(self.state[0])[0..last_block.len()]);
            self.state[0] = clear(self.state[0], last_block.len()) ^ cx;
        }
    }

    fn process_final(&mut self) -> [u8; 16] {
        self.state[1] ^= self.key.get_k1();
        self.state[2] ^= self.key.get_k2();

        self.permute_12_and_apply_key();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&self.state[3].to_be_bytes());
        tag[8..].copy_from_slice(&self.state[4].to_be_bytes());
        tag
    }

    pub fn encrypt(&mut self, associated_data: &[u8], plaintext: &mut [u8]) -> Vec<u8> {
        self.process_associated_date(associated_data);
        self.process_encrypt_inplace(plaintext);
        self.process_final().to_vec()
    }

    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        ciphertext: &mut [u8],
        expected_tag: &[u8],
    ) -> Result<(), ()> {
        self.process_associated_date(associated_data);
        self.process_decrypt_inplace(ciphertext);
        let tag = self.process_final();

        if tag == *expected_tag {
            Ok(())
        } else {
            Err(())
        }
    }
}
