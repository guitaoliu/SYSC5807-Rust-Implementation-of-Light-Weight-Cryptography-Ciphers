use acorn_core::u32_from_be_bytes;

mod acorn_core;

const ONES: u32 = 0xffff_ffff;

pub struct AcornHead {
    key: [u32; 4],
}

impl AcornHead {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: [
                u32_from_be_bytes(&key[0..4]),
                u32_from_be_bytes(&key[4..8]),
                u32_from_be_bytes(&key[8..12]),
                u32_from_be_bytes(&key[12..16]),
            ],
        }
    }

    pub fn encrypt(&self, pt: &mut [u8], ad: &[u8], nonce: &[u8]) -> [u8; 16] {
        let mut state = acorn_core::State::default();
        state.init(&self.key, nonce);
        state.process_associated_data(ad);
        state.crypt(pt, 0);

        let mut tag = [0u8; 16];
        state.finalize(&mut tag);

        tag
    }

    pub fn decrypt(
        &self,
        ct: &mut [u8],
        ad: &[u8],
        nonce: &[u8],
        expected_tag: &[u8],
    ) -> Result<(), ()> {
        let mut state = acorn_core::State::default();
        state.init(&self.key, nonce);
        state.process_associated_data(ad);
        state.crypt(ct, ONES);

        let mut tag = [0u8; 16];
        state.finalize(&mut tag);

        if tag == expected_tag {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    const NONCE: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    #[test]
    fn acorn_128() {
        let acorn = AcornHead::new(&KEY);

        let mut pt = [0u8; 16];
        let ad = b"";

        let tag = acorn.encrypt(&mut pt, ad, &NONCE);

        let mut ct = pt;

        assert!(acorn.decrypt(&mut ct, ad, &NONCE, &tag).is_ok());
        assert_eq!([0u8; 16], ct);
    }
}
