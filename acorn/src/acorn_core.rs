use crate::ONES;

#[derive(Clone, Copy, Debug, Default)]
pub struct State {
    s0: u64,
    s61: u64,
    s107: u64,
    s154: u64,
    s193: u64,
    s230: u64,
}

pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
pub fn u32_from_be_bytes(input: &[u8]) -> u32 {
    // Soundness: function is always called with slices of the correct size
    u32::from_be_bytes(input.try_into().unwrap())
}

impl State {
    fn update8(&mut self, m: u32, ca: u32, cb: u32) -> u32 {
        let s244 = (self.s230 >> 14) as u32;
        let s235 = (self.s230 >> 5) as u32;
        let s196 = (self.s193 >> 3) as u32;
        let s160 = (self.s154 >> 6) as u32;
        let s111 = (self.s107 >> 4) as u32;
        let s66 = (self.s61 >> 5) as u32;
        let s23 = (self.s0 >> 23) as u32;
        let s12 = (self.s0 >> 12) as u32;
        let s0 = self.s0 as u32;

        let x289 = (s235 ^ (self.s230 as u32)) & 0xFF;

        let s230 = (self.s230 as u32) ^ s196 ^ (self.s193 as u32) & 0xFF;
        let s193 = (self.s193 as u32) ^ s160 ^ (self.s154 as u32) & 0xFF;
        let s154 = (self.s154 as u32) ^ s111 ^ (self.s107 as u32) & 0xFF;
        let s107 = (self.s107 as u32) ^ s66 ^ (self.s61 as u32) & 0xFF;
        let s61 = (self.s61 as u32) ^ s23 ^ s0 & 0xFF;

        let ks = s12 ^ s154 ^ maj(s235, s61, s193) ^ ch(s230, s111, s66) & 0xFF;
        let f = s0 ^ !s107 ^ maj(s244, s23, s160) ^ (ca & s196) ^ (cb & ks) & 0xFF;

        let s293 = (f ^ m) & 0xFF;

        self.s230 =
            self.s230 >> 8 ^ (x289 as u64) << (289 - 230 - 8) ^ (s293 as u64) << (293 - 230 - 8);
        self.s193 = self.s193 >> 8 ^ (s230 as u64) << (230 - 193 - 8);
        self.s154 = self.s154 >> 8 ^ (s193 as u64) << (193 - 154 - 8);
        self.s107 = self.s107 >> 8 ^ (s154 as u64) << (154 - 107 - 8);
        self.s61 = self.s61 >> 8 ^ (s107 as u64) << (107 - 61 - 8);
        self.s0 = self.s0 >> 8 ^ (s61 as u64) << (61 - 8);

        ks
    }

    fn update32(&mut self, m: u32, ca: u32, cb: u32) -> u32 {
        let s244 = (self.s230 >> 14) as u32;
        let s235 = (self.s230 >> 5) as u32;
        let s196 = (self.s193 >> 3) as u32;
        let s160 = (self.s154 >> 6) as u32;
        let s111 = (self.s107 >> 4) as u32;
        let s66 = (self.s61 >> 5) as u32;
        let s23 = (self.s0 >> 23) as u32;
        let s12 = (self.s0 >> 12) as u32;
        let s0 = self.s0 as u32;

        let x289 = s235 ^ (self.s230 as u32);

        let s230 = (self.s230 as u32) ^ s196 ^ (self.s193 as u32);
        let s193 = (self.s193 as u32) ^ s160 ^ (self.s154 as u32);
        let s154 = (self.s154 as u32) ^ s111 ^ (self.s107 as u32);
        let s107 = (self.s107 as u32) ^ s66 ^ (self.s61 as u32);
        let s61 = (self.s61 as u32) ^ s23 ^ s0;

        let ks = s12 ^ s154 ^ maj(s235, s61, s193) ^ ch(s230, s111, s66);
        let f = s0 ^ !s107 ^ maj(s244, s23, s160) ^ (ca & s196) ^ (cb & ks);

        let s293 = f ^ m;

        self.s230 =
            self.s230 >> 32 ^ (x289 as u64) << (289 - 230 - 32) ^ (s293 as u64) << (293 - 230 - 32);
        self.s193 = self.s193 >> 32 ^ (s230 as u64) << (230 - 193 - 32);
        self.s154 = self.s154 >> 32 ^ (s193 as u64) << (193 - 154 - 32);
        self.s107 = self.s107 >> 32 ^ (s154 as u64) << (154 - 107 - 32);
        self.s61 = self.s61 >> 32 ^ (s107 as u64) << (107 - 61 - 32);
        self.s0 = self.s0 >> 32 ^ (s61 as u64) << (61 - 32);

        ks
    }

    pub fn init(&mut self, key: &[u32; 4], iv: &[u8]) {
        for i in 0..4 {
            self.update32(key[i], ONES, ONES);
        }
        for i in 0..iv.len() {
            self.update8(iv[i] as u32, ONES, ONES);
        }
        self.update32(key[0] ^ 0x01, ONES, ONES);
        for i in (32..15636).step_by(32) {
            self.update32(key[i % 128 / 32], ONES, ONES);
        }
    }

    fn pad(&mut self, cb: u32) {
        self.update32(0x01, ONES, cb);
        for _ in (32..128).step_by(32) {
            self.update32(0x00, ONES, ONES);
        }
        for _ in (128..256).step_by(32) {
            self.update32(0x00, 0, cb);
        }
    }

    pub fn process_associated_data(&mut self, ad: &[u8]) {
        for i in 0..ad.len() {
            self.update8(ad[i] as u32, ONES, ONES);
        }
        self.pad(ONES);
    }

    pub fn crypt(&mut self, message: &mut [u8], mode: u32) {
        let mut chunks = message.chunks_exact_mut(4);
        for blocks in chunks.by_ref() {
            let cx = u32_from_be_bytes(blocks);
            let ks = self.update32(cx, ONES, mode);
            blocks.copy_from_slice(&(cx ^ ks).to_be_bytes());
        }

        let last_block = chunks.into_remainder();
        if !last_block.is_empty() {
            // Iterate over the last block and apply update8
            for i in 0..last_block.len() {
                let cx = last_block[i];
                let ks = self.update8(cx as u32, ONES, mode) as u8;
                last_block[i] = cx ^ ks;
            }
        }
        self.pad(0);
    }

    pub fn finalize(&mut self, tag: &mut [u8; 16]) {
        for _ in (0..640).step_by(32) {
            self.update32(0x00, ONES, ONES);
        }
        for i in 0..tag.len() {
            let ks = self.update8(0x00, ONES, ONES) as u8;
            tag[i] = ks;
        }
    }
}
