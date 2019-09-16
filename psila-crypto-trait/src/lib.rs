#![no_std]

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    NotImplemented,
    InvalidKeySize,
    InvalidKey,
    InvalidIvSize,
    InvalidIv,
    InvalidDataSize,
    InvalidNonceSize,
    InvalidNonce,
    InvalidAdditionalDataSize,
    InvalidAdditionalData,
    InvalidIntegrityCodeSize,
    InvalidIntegrityCode,
    Other(u32),
}

pub trait BlockCipher {
    /// Set the key
    fn set_key(&mut self, key: &[u8]) -> Result<(), Error>;
    /// Set the IV
    fn set_iv(&mut self, iv: &[u8]) -> Result<(), Error>;
    /// Process blocks of data
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error>;
    /// Process the last bits and bobs and finish
    fn finish(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error>;
}

pub trait CryptoBackend {
    fn ccmstar_encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        message: &[u8],
        mic_length: usize,
        additional_data: &[u8],
        message_output: &mut [u8],
    ) -> Result<usize, Error>;

    fn ccmstar_decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        message: &[u8],
        mic_length: usize,
        additional_data: &[u8],
        message_output: &mut [u8],
    ) -> Result<usize, Error>;

    fn aes128_ecb_encrypt(&mut self) -> Result<&mut dyn BlockCipher, Error>;
}
