#![no_std]
#![forbid(unsafe_code)]

pub mod xoodoo;
pub mod xoodyak;

extern crate alloc;

pub struct XoodyakAead {
    key: [u8; 16],
}

impl XoodyakAead {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key[..16].try_into().unwrap(),
        }
    }

    pub fn encrypt(&mut self, nonce: &[u8], ad: &[u8], plaintext: &mut [u8]) -> [u8; 16] {
        let mut xoodyak = xoodyak::Xoodyak::new(&self.key, nonce, None);
        xoodyak.absorb(ad);
        xoodyak.encrypt_inplace(plaintext);
        let mut tag = [0u8; 16];
        xoodyak.squeeze(&mut tag);
        tag
    }

    pub fn decrypt(
        &mut self,
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &mut [u8],
        expected_tag: &[u8],
    ) -> Result<(), ()> {
        let mut xoodyak = xoodyak::Xoodyak::new(&self.key, nonce, None);
        xoodyak.absorb(ad);
        xoodyak.decrypt_inplace(ciphertext);
        let mut tag = [0u8; 16];
        xoodyak.squeeze(&mut tag);
        if tag == expected_tag {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    const NONCE: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    const TEST_PLAIN_TEXT: &str = "Hello, world!";
    const TEST_LONG_PLAIN_TEXT: &str = "Hello world, this is a test of the emergency broadcast system. This is only a test. If this had been an actual emergency, you would have been instructed to do something else. This concludes this test of the emergency broadcast system.";

    #[test]
    fn ascon128() {
        let mut cipher = XoodyakAead::new(&KEY);

        let mut plaintext = TEST_PLAIN_TEXT.as_bytes().to_vec();
        let tag = cipher.encrypt(NONCE.as_ref(), &[], &mut plaintext);
        let mut ciphertext = plaintext;
        assert!(cipher
            .decrypt(NONCE.as_ref(), &[], &mut ciphertext, &tag)
            .is_ok());

        assert_eq!(TEST_PLAIN_TEXT.as_bytes(), &ciphertext);

        let mut plaintext = TEST_LONG_PLAIN_TEXT.as_bytes().to_vec();
        let tag = cipher.encrypt(NONCE.as_ref(), &[], &mut plaintext);
        let mut ciphertext = plaintext;
        assert!(cipher
            .decrypt(NONCE.as_ref(), &[], &mut ciphertext, &tag)
            .is_ok());

        assert_eq!(TEST_LONG_PLAIN_TEXT.as_bytes(), &ciphertext);
    }
}
