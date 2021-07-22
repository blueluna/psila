#![no_std]

use psila_crypto::{CryptoBackend, Error, BLOCK_SIZE};

use aes::{
    Aes128,
    cipher::{BlockEncrypt, NewBlockCipher}
};
use ccm::{
    aead::{generic_array::GenericArray, AeadInPlace, NewAead},
    consts::{U13, U16, U4, U8},
    Ccm,
};


#[cfg(test)]
mod test;

type AesCcmMic4 = Ccm<Aes128, U4, U13>;
type AesCcmMic8 = Ccm<Aes128, U8, U13>;
type AesCcmMic16 = Ccm<Aes128, U16, U13>;

pub struct RustCryptoBackend {
    cipher: Option<Aes128>,
}

impl Default for RustCryptoBackend {
    fn default() -> Self {
        Self {
            cipher: None,
        }
    }
}

impl CryptoBackend for RustCryptoBackend {
    fn ccmstar_encrypt(
        &mut self,
        // The Key to be used
        key: &[u8],
        // Nonce
        nonce: &[u8],
        // Clear test message
        payload: &[u8],
        // Length of the message integrity code (MIC)
        mic: &mut [u8],
        // Additional data
        additional_data: &[u8],
        // Encrypted message
        message_output: &mut [u8],
    ) -> Result<usize, Error> {
        let key: &GenericArray<u8, U16> = GenericArray::from_slice(key);
        let nonce: &GenericArray<u8, U13> = GenericArray::from_slice(nonce);
        let payload_len = payload.len();
        message_output[..payload_len].copy_from_slice(&payload);
        match mic.len() {
            0 => {
                unimplemented!();
            }
            4 => {
                let cipher = AesCcmMic4::new(key);
                match cipher.encrypt_in_place_detached(nonce, additional_data, &mut message_output[..payload_len]) {
                    Ok(tag) => {
                        mic.copy_from_slice(tag.as_slice());
                        Ok(payload_len)
                    }
                    Err(_e) => Err(Error::BackendError),
                }
            }
            8 => {
                let cipher = AesCcmMic8::new(key);
                match cipher.encrypt_in_place_detached(nonce, additional_data, &mut message_output[..payload_len]) {
                    Ok(tag) => {
                        mic.copy_from_slice(tag.as_slice());
                        Ok(payload_len)
                    }
                    Err(_e) => Err(Error::BackendError),
                }
            }
            16 => {
                let cipher = AesCcmMic16::new(key);
                match cipher.encrypt_in_place_detached(nonce, additional_data, &mut message_output[..payload_len]) {
                    Ok(tag) => {
                        mic.copy_from_slice(tag.as_slice());
                        Ok(payload_len)
                    }
                    Err(_e) => Err(Error::BackendError),
                }
            }
            _ => Err(Error::InvalidIntegrityCodeSize),
        }
    }

    fn ccmstar_decrypt(
        &mut self,
        // The Key to be used
        key: &[u8],
        // Nonce
        nonce: &[u8],
        // Encrypted message with message integrity code (MIC)
        message: &[u8],
        // Length of the message integrity code (MIC)
        mic: &[u8],
        // Additional data
        additional_data: &[u8],
        // Clear text message
        message_output: &mut [u8],
    ) -> Result<usize, Error> {
        let key: &GenericArray<u8, U16> = GenericArray::from_slice(key);
        let nonce: &GenericArray<u8, U13> = GenericArray::from_slice(nonce);
        let payload_len = message.len();
        message_output[..payload_len].copy_from_slice(&message);
        match mic.len() {
            0 => {
                Err(Error::NotImplemented)
            }
            4 => {
                let tag: &GenericArray<u8, U4> = GenericArray::from_slice(mic);
                let cipher = AesCcmMic4::new(key);
                match cipher.decrypt_in_place_detached(nonce, additional_data, &mut message_output[..payload_len], tag) {
                    Ok(_) => Ok(payload_len),
                    Err(_e) => Err(Error::BackendError),
                }
            }
            8 => {
                let tag: &GenericArray<u8, U8> = GenericArray::from_slice(mic);
                let cipher = AesCcmMic8::new(key);
                match cipher.decrypt_in_place_detached(nonce, additional_data, &mut message_output[..payload_len], tag) {
                    Ok(_) => Ok(payload_len),
                    Err(_e) => Err(Error::BackendError),
                }
            }
            16 => {
                let tag: &GenericArray<u8, U16> = GenericArray::from_slice(mic);
                let cipher = AesCcmMic16::new(key);
                match cipher.decrypt_in_place_detached(nonce, additional_data, &mut message_output[..payload_len], tag) {
                    Ok(_) => Ok(payload_len),
                    Err(_e) => Err(Error::BackendError),
                }
            }
            _ => Err(Error::InvalidIntegrityCodeSize),
        }
    }

    fn aes128_ecb_encrypt_set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        match aes::Aes128::new_from_slice(key) {
            Ok(aes) => {
                self.cipher = Some(aes);
                Ok(())
            }
            Err(_) => {
                Err(Error::InvalidKeySize)
            }
        }
    }

    fn aes128_ecb_encrypt_process_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        if input.len() != BLOCK_SIZE || output.len() != BLOCK_SIZE {
            return Err(Error::InvalidDataSize);
        }
        if let Some(cipher) = self.cipher.as_ref() {
            output.copy_from_slice(input);
            let block: &mut GenericArray<u8, U16> = GenericArray::from_mut_slice(output);
            cipher.encrypt_block(block);
        }
        else {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    fn aes128_ecb_encrypt_finish(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.aes128_ecb_encrypt_process_block(input, output)
    }
}

