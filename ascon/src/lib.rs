#![no_std]
#![forbid(unsafe_code)]

pub use alloc::vec::Vec;

use ascon_128::Ascon128;
pub use ascon_128::Key;

extern crate alloc;

mod ascon_128;
mod ascon_core;

pub struct AsconHead {
    key: Key,
}

impl AsconHead {
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    pub fn encrypt(&self, nonce: &[u8], associated_data: &[u8], plaintext: &mut [u8]) -> Vec<u8> {
        let mut internal = Ascon128::new(self.key, nonce);
        internal.encrypt(associated_data, plaintext)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &mut [u8],
        expected_tag: &[u8],
    ) -> Result<(), ()> {
        let mut internal = Ascon128::new(self.key, nonce);
        internal.decrypt(associated_data, ciphertext, expected_tag)
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
        let key: Key = Key::from(KEY.as_ref());
        let cipher = AsconHead::new(key);

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
