use alloc::vec;

use crate::xoodoo::State;

pub const KEYED_ABSORB_RATE: usize = 44;
pub const KEYED_SQUEEZE_RATE: usize = 24;
pub const AUTH_TAG_BYTES: usize = 16;

#[derive(PartialEq)]
enum Phase {
    Up,
    Down,
}

pub struct Xoodyak {
    state: State,
    phase: Phase,
}

impl Xoodyak {
    pub fn new(key: &[u8], nonce: &[u8], counter: Option<&[u8]>) -> Self {
        let mut xoodyak = Self {
            state: State::default(),
            phase: Phase::Up,
        };
        xoodyak.absorb_key_and_nonce(key, nonce, counter);
        xoodyak
    }

    fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }

    #[inline(always)]
    fn up(&mut self, out: Option<&mut [u8]>, cu: u8) {
        self.set_phase(Phase::Up);
        self.state.add_byte(cu, 47);
        self.state.permute();
        if let Some(out) = out {
            self.state.extract_bytes(out);
        }
    }

    #[inline(always)]
    fn down(&mut self, bin: Option<&[u8]>, cd: u8) {
        self.set_phase(Phase::Down);
        if let Some(bin) = bin {
            self.state.add_bytes(bin);
            self.state.add_byte(0x01, bin.len());
        } else {
            self.state.add_byte(0x01, 0);
        }
        self.state.add_byte(cd, 47);
    }

    #[inline]
    fn absorb_any(&mut self, bin: &[u8], rate: usize, cd: u8) {
        let mut chunks_it = bin.chunks(rate);
        if self.phase != Phase::Up {
            self.up(None, 0x00)
        }
        self.down(chunks_it.next(), cd);
        for chunk in chunks_it {
            self.up(None, 0x00);
            self.down(Some(chunk), 0x00);
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        self.absorb_any(data, 16, 0x03);
    }

    #[inline]
    fn squeeze_any(&mut self, out: &mut [u8], cu: u8) {
        let mut chunks_it = out.chunks_mut(KEYED_SQUEEZE_RATE);
        self.up(chunks_it.next(), cu);
        for chunk in chunks_it {
            self.down(None, 0x00);
            self.up(Some(chunk), 0x00);
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.squeeze_any(out, 0x80);
    }

    fn absorb_key_and_nonce(&mut self, key: &[u8], nonce: &[u8], counter: Option<&[u8]>) {
        let key_len = key.len();
        let nonce_len = nonce.len();
        // IV: key || nonce || nonce_len
        let mut iv = vec![0u8; key_len + nonce_len + 1];
        iv[..key_len].copy_from_slice(key);
        iv[key_len..key_len + nonce_len].copy_from_slice(nonce);
        iv[key_len + nonce_len] = nonce_len as u8;
        self.absorb_any(&iv, KEYED_ABSORB_RATE, 0x02);
        if let Some(counter) = counter {
            self.absorb_any(counter, 1, 0x00);
        }
    }

    pub fn encrypt_inplace(&mut self, in_out: &mut [u8]) {
        let mut tmp = [0u8; KEYED_SQUEEZE_RATE];
        let mut cu = 0x80;
        for in_out_chunk in in_out.chunks_mut(KEYED_SQUEEZE_RATE) {
            self.up(Some(&mut tmp), cu);
            cu = 0x00;
            self.down(Some(in_out_chunk), 0x00);
            for (in_out_chunk_byte, tmp_byte) in in_out_chunk.iter_mut().zip(&tmp) {
                *in_out_chunk_byte ^= *tmp_byte;
            }
        }
    }

    pub fn decrypt_inplace(&mut self, in_out: &mut [u8]) {
        let mut tmp = [0u8; KEYED_SQUEEZE_RATE];
        let mut cu = 0x80;
        for in_out_chunk in in_out.chunks_mut(KEYED_SQUEEZE_RATE) {
            self.up(Some(&mut tmp), cu);
            cu = 0x00;
            for (in_out_chunk_byte, tmp_byte) in in_out_chunk.iter_mut().zip(&tmp) {
                *in_out_chunk_byte ^= *tmp_byte;
            }
            self.down(Some(in_out_chunk), 0x00);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let mut data = [0u8; 24];
        let mut xoodyak = Xoodyak::new(&key, &nonce, None);
        xoodyak.encrypt_inplace(&mut data);

        let mut xoodyak = Xoodyak::new(&key, &nonce, None);
        xoodyak.decrypt_inplace(&mut data);

        assert_eq!(data, [0u8; 24]);
    }
}
