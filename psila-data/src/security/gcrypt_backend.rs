use std::convert::From;

use byteorder::{BigEndian, ByteOrder};

use crate::common::key::KEY_SIZE;
use crate::error::Error;
use crate::security::{CryptoBackend, BLOCK_SIZE, LENGHT_FIELD_LENGTH};

use gcrypt::{
    self,
    cipher::{Algorithm, Cipher, Mode},
};

impl From<gcrypt::Error> for Error {
    fn from(e: gcrypt::Error) -> Self {
        Error::CryptoError(e.code())
    }
}

pub struct GCryptBackend {
    cipher: Cipher,
}

impl GCryptBackend {
    fn make_flag(a_length: usize, big_m: usize, big_l: usize) -> u8 {
        let mut flag = if a_length > 0 { 0x40 } else { 0 };
        flag = if big_m > 0 {
            flag | ((((big_m - 2) / 2) as u8) & 0x07) << 3
        } else {
            flag
        };
        flag |= 0x07 & ((big_l - 1) as u8);
        flag
    }
}

impl Default for GCryptBackend {
    fn default() -> Self {
        let cipher = Cipher::new(Algorithm::Aes128, Mode::Ecb).unwrap();
        Self { cipher }
    }
}

impl CryptoBackend for GCryptBackend {
    fn aes128_ecb_set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        assert!(key.len() == KEY_SIZE);
        self.cipher.set_key(&key).map_err(|e| e.into())
    }

    fn aes128_ecb_process(&mut self, input: &[u8], mut output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher
            .encrypt(&input, &mut output)
            .map_err(|e| e.into())
    }

    fn ccmstar_decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        message: &[u8],
        mic_length: usize,
        additional_data: &[u8],
        message_output: &mut [u8],
    ) -> Result<usize, Error> {
        assert!(message_output.len() >= (message.len() - mic_length));
        // C.4.1 Decryption Transformation

        if message.len() < mic_length {
            return Err(Error::WrongNumberOfBytes);
        }

        let (encrypted, mic) = message.split_at(message.len() - mic_length);

        let encrypted_blocks = (encrypted.len() + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let encrypted_padding = (encrypted_blocks * BLOCK_SIZE) - encrypted.len();
        let decrypted_size = encrypted.len();

        let additional_data_blocks =
            (additional_data.len() + LENGHT_FIELD_LENGTH + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let additional_data_padding =
            (additional_data_blocks * BLOCK_SIZE) - (additional_data.len() + LENGHT_FIELD_LENGTH);

        let mic_blocks = (mic.len() / BLOCK_SIZE) + 1;
        assert_eq!(mic_blocks, 1);

        let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ctr)?;
        cipher.set_key(key)?;

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (flag, other) = block.split_at_mut(1);
            let (_nonce, _counter) = other.split_at_mut(nonce.len());
            flag[0] = Self::make_flag(0, 0, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
        }

        cipher.set_ctr(block)?;

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (_mic, _padding) = block.split_at_mut(mic.len());
            _mic.copy_from_slice(&mic);
        }

        let mut tag = [0; BLOCK_SIZE];
        cipher.encrypt(&block, &mut tag)?;

        let mut output = [0u8; BLOCK_SIZE];
        for n in 0..encrypted_blocks {
            let mut block = [0u8; BLOCK_SIZE];
            let offset = n * BLOCK_SIZE;
            let length = if n == encrypted_blocks - 1 {
                BLOCK_SIZE - encrypted_padding
            } else {
                BLOCK_SIZE
            };
            {
                let (part, _) = block.split_at_mut(length);
                part.copy_from_slice(&encrypted[offset..offset + length]);
            }
            cipher.encrypt(&block, &mut output)?;
            let (_, part) = message_output.split_at_mut(offset);
            let (part, _) = part.split_at_mut(length);
            part.copy_from_slice(&output[..length]);
        }

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (f, other) = block.split_at_mut(1);
            let (_nonce, mut length) = other.split_at_mut(nonce.len());
            f[0] = Self::make_flag(additional_data.len(), mic_length, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
            BigEndian::write_u16(&mut length, encrypted.len() as u16);
        }

        let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ecb)?;
        cipher.set_key(key)?;

        cipher.encrypt(&block, &mut output)?;

        // Handle additional data longer than the block size
        let mut input = [0; BLOCK_SIZE];
        {
            let length = if additional_data_blocks > 1 {
                BLOCK_SIZE - LENGHT_FIELD_LENGTH
            } else {
                additional_data.len()
            };
            let (mut _l, other) = input.split_at_mut(LENGHT_FIELD_LENGTH);
            let (_a, _padding) = other.split_at_mut(length);
            BigEndian::write_u16(&mut _l, additional_data.len() as u16);
            _a.copy_from_slice(&additional_data[..length]);
        }
        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ input[n];
        }

        cipher.encrypt(&block, &mut output)?;

        if additional_data_blocks > 1 {
            for n in 1..additional_data_blocks {
                let mut input = [0u8; BLOCK_SIZE];
                let offset = (n * BLOCK_SIZE) - LENGHT_FIELD_LENGTH;
                let length = if n == additional_data_blocks - 1 {
                    BLOCK_SIZE - additional_data_padding
                } else {
                    BLOCK_SIZE
                };
                {
                    let (part, _) = input.split_at_mut(length);
                    part.copy_from_slice(&additional_data[offset..offset + length]);
                }
                for m in 0..BLOCK_SIZE {
                    block[m] = output[m] ^ input[m];
                }
                cipher.encrypt(&block, &mut output)?;
            }
        }

        for n in 0..encrypted_blocks {
            let mut input = [0u8; BLOCK_SIZE];
            let offset = n * BLOCK_SIZE;
            let length = if n == encrypted_blocks - 1 {
                BLOCK_SIZE - encrypted_padding
            } else {
                BLOCK_SIZE
            };
            {
                let (part, _) = input.split_at_mut(length);
                part.copy_from_slice(&message_output[offset..offset + length]);
            }
            for n in 0..BLOCK_SIZE {
                block[n] = output[n] ^ input[n];
            }
            cipher.encrypt(&block, &mut output)?;
        }

        let mut valid = true;
        for (a, b) in tag[..mic_length].iter().zip(output[..mic_length].iter()) {
            if a != b {
                valid = false;
                break;
            }
        }

        if valid {
            Ok(decrypted_size)
        } else {
            for b in message_output.iter_mut() {
                *b = 0;
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hash() {
        use crate::security::CryptoProvider;
        use gcrypt;

        gcrypt::init_default();

        let crypt = GCryptBackend::default();
        let mut provider = CryptoProvider::new(crypt);

        // C.6.1 Test Vector Set 1
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        let mut calculated = [0; BLOCK_SIZE];
        provider.hash_key(&key, 0xc0, &mut calculated).unwrap();
        assert_eq!(
            calculated,
            [
                0x45, 0x12, 0x80, 0x7B, 0xF9, 0x4C, 0xB3, 0x40, 0x0F, 0x0E, 0x2C, 0x25, 0xFB, 0x76,
                0xE9, 0x99
            ]
        );
    }

    #[test]
    fn test_decryption_and_authentication_check_2() {
        use gcrypt;

        gcrypt::init_default();

        let mut crypt = GCryptBackend::default();

        let key = [
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
            0xCE, 0xCF,
        ];
        let nonce = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
        ];
        let c = [
            0x1A, 0x55, 0xA3, 0x6A, 0xBB, 0x6C, 0x61, 0x0D, 0x06, 0x6B, 0x33, 0x75, 0x64, 0x9C,
            0xEF, 0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8, 0x0A, 0x89, 0x5C, 0xC1, 0xD8,
            0xFF, 0x94, 0x69,
        ];
        let a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        // M, length of the authentication field in octets 0, 4, 6, 8, 10, 12, 14, 16
        const M: usize = 8;
        let mut _message = vec![0; c.len() - M];
        let mut message = _message.as_mut_slice();

        let used = crypt
            .ccmstar_decrypt(&key, &nonce, &c, M, &a, &mut message)
            .unwrap();

        assert_eq!(used, 23);

        assert_eq!(
            message,
            [
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
            ]
        );
    }

    #[test]
    fn test_handle_secure_payload_1() {
        use crate::security::{CryptoProvider, SecurityLevel, DEFAULT_LINK_KEY};
        use gcrypt;

        gcrypt::init_default();

        let crypt = GCryptBackend::default();
        let mut provider = CryptoProvider::new(crypt);

        let input = [
            0x21, 0x45, 0x30, 0x02, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0xae, 0x5e, 0x9f, 0x46, 0xa6, 0x40, 0xcd, 0xe7, 0x90, 0x2f, 0xd6, 0x0e, 0x43,
            0x23, 0x17, 0x48, 0x4b, 0x4c, 0x5a, 0x9b, 0x4c, 0xde, 0x1c, 0xe7, 0x07, 0x07, 0xb6,
            0xfb, 0x1a, 0x0b, 0xe9, 0x99, 0x7e, 0x0a, 0xf8, 0x0f, 0xdf, 0x5d, 0xcf,
        ];

        let mut _output = vec![0; input.len()];
        let mut output = _output.as_mut_slice();

        let decrypted_size = provider
            .decrypt_payload(
                &DEFAULT_LINK_KEY,
                SecurityLevel::EncryptedIntegrity32,
                &input,
                2,
                &mut output,
            )
            .unwrap();

        assert_eq!(decrypted_size, 35);

        let correct_output = [
            0x05, 0x01, 0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48,
            0x00, 0x40, 0x64, 0x08, 0x00, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x38,
            0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00,
        ];

        assert_eq!(output[..16], correct_output[..16]);
        assert_eq!(output[16..decrypted_size], correct_output[16..]);
    }

    #[test]
    fn test_handle_secure_payload_2() {
        use crate::network;
        use crate::pack::Pack;
        use crate::security::{CryptoProvider, SecurityLevel};
        use gcrypt;

        gcrypt::init_default();

        let crypt = GCryptBackend::default();
        let mut provider = CryptoProvider::new(crypt);

        let key = [
            0x4e, 0x48, 0x3c, 0x5d, 0x6f, 0x68, 0x26, 0x56, 0x70, 0x4e, 0x24, 0x4b, 0x5c, 0x53,
            0x51, 0x44,
        ];
        let input = [
            0x08, 0x02, 0xfd, 0xff, 0x6a, 0x6a, 0x0a, 0x64, 0x28, 0x00, 0x00, 0x00, 0x00, 0xc1,
            0xe9, 0x1f, 0x00, 0x00, 0xff, 0x0f, 0x00, 0x00, 0xea, 0x15, 0x13, 0xe1, 0x36, 0x12,
            0xcc, 0x44, 0x75, 0x64, 0xb0, 0x1d, 0x79, 0x2d, 0xfe, 0xdf, 0xc5, 0x61, 0x74, 0x84,
            0xc3, 0x3a, 0x81, 0x28,
        ];

        let (_nwk, used) = network::NetworkHeader::unpack(&input[..]).unwrap();

        let mut _output = vec![0; input.len()];
        let mut output = _output.as_mut_slice();

        let decrypted_size = provider
            .decrypt_payload(
                &key,
                SecurityLevel::EncryptedIntegrity32,
                &input,
                used,
                &mut output,
            )
            .unwrap();

        assert_eq!(decrypted_size, 20);

        let correct_output = [
            0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x6a, 0x6a, 0xc1, 0xe9, 0x1f,
            0x00, 0x00, 0xff, 0x0f, 0x00, 0x8e,
        ];

        assert_eq!(output[..16], correct_output[..16]);
        assert_eq!(
            output[16..decrypted_size],
            correct_output[16..decrypted_size]
        );
    }

    #[test]
    fn test_handle_secure_payload_3() {
        use crate::network;
        use crate::pack::Pack;
        use crate::security::{CryptoProvider, SecurityLevel};
        use gcrypt;

        gcrypt::init_default();

        let crypt = GCryptBackend::default();
        let mut provider = CryptoProvider::new(crypt);

        let key = [
            0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48, 0x00, 0x40,
            0x64, 0x08,
        ];
        let input = [
            0x08, 0x12, 0xfd, 0xff, 0x7b, 0xc0, 0x1e, 0x04, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f,
            0x0d, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d,
            0x00, 0x00, 0xad, 0x41, 0xd3, 0x7e, 0xf7, 0x5d, 0x6a, 0x67, 0x01, 0x7b, 0x14, 0x62,
            0xee, 0xfa, 0x6a, 0xe1, 0xd1, 0x31, 0x59, 0xb4, 0x7d, 0xd4, 0xf2, 0xb9,
        ];

        let (_nwk, used) = network::NetworkHeader::unpack(&input[..]).unwrap();

        let mut _output = vec![0; input.len()];
        let mut output = _output.as_mut_slice();

        let decrypted_size = provider
            .decrypt_payload(
                &key,
                SecurityLevel::EncryptedIntegrity32,
                &input,
                used,
                &mut output,
            )
            .unwrap();

        assert_eq!(decrypted_size, 20);

        let correct_output = [
            0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x06, 0x81, 0x7b, 0xc0, 0x85, 0xae, 0x21,
            0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x80,
        ];

        assert_eq!(output[..16], correct_output[..16]);
        assert_eq!(output[16..decrypted_size], correct_output[16..]);
    }

    #[test]
    fn test_handle_secure_payload_4() {
        use crate::application_service;
        use crate::pack::Pack;
        use crate::security::{CryptoProvider, SecurityLevel, DEFAULT_LINK_KEY};
        use gcrypt;

        gcrypt::init_default();

        let crypt = GCryptBackend::default();
        let mut provider = CryptoProvider::new(crypt);

        let input = [
            0x21, 0xf2, 0x30, 0x05, 0x00, 0x00, 0x00, 0xb5, 0xb4, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0x63, 0xe2, 0x62, 0xd6, 0xb3, 0x67, 0x4d, 0x0e, 0x34, 0x9f, 0xaa, 0x04, 0x81,
            0xf9, 0x1d, 0xf6, 0xa4, 0x72, 0x7f, 0x36, 0xde, 0x4d, 0xf5, 0xeb, 0xd8, 0xea, 0xc5,
            0x4e, 0x78, 0x1c, 0xd9, 0x36, 0x07, 0xb4, 0x62, 0xc9, 0xf8, 0xb7, 0x77,
        ];

        let (_aps, used) =
            application_service::ApplicationServiceHeader::unpack(&input[..]).unwrap();

        let mut _output = vec![0; input.len()];
        let mut output = _output.as_mut_slice();

        let decrypted_size = provider
            .decrypt_payload(
                &DEFAULT_LINK_KEY,
                SecurityLevel::EncryptedIntegrity32,
                &input,
                used,
                &mut output,
            )
            .unwrap();

        assert_eq!(decrypted_size, 35);
    }
}
