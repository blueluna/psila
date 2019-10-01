use byteorder::{BigEndian, ByteOrder};
use gcrypt::cipher::{Algorithm, Cipher, Mode};

use psila_crypto::{
    BlockCipher, CryptoBackend, Error, BLOCK_SIZE, KEY_SIZE, LENGHT_FIELD_LENGTH,
};

pub struct GCryptCipher {
    cipher: Cipher,
}

impl GCryptCipher {
    pub fn new(algorithm: Algorithm, mode: Mode) -> Result<Self, Error> {
        let cipher = Cipher::new(algorithm, mode).map_err(|e| Error::Other(e.code()))?;
        Ok(Self { cipher })
    }
}

impl BlockCipher for GCryptCipher {
    /// Set the key
    fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        assert!(key.len() == KEY_SIZE);
        self.cipher
            .set_key(&key)
            .map_err(|e| Error::Other(e.code()))
    }
    /// Set the IV
    fn set_iv(&mut self, _iv: &[u8]) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    /// Get the IV
    fn get_iv(&mut self, _iv: &mut [u8]) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    /// Process blocks of data
    fn process_block(&mut self, input: &[u8], mut output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher
            .encrypt(&input, &mut output)
            .map_err(|e| Error::Other(e.code()))
    }
    /// Process the last bits and bobs and finish
    fn finish(&mut self, input: &[u8], mut output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher
            .encrypt(&input, &mut output)
            .map_err(|e| Error::Other(e.code()))
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
        Self {
            cipher: Cipher::new(Algorithm::Aes128, Mode::Ecb).unwrap(),
        }
    }
}

impl CryptoBackend for GCryptBackend {
    fn ccmstar_decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        encrypted: &[u8],
        mic: &[u8],
        additional_data: &[u8],
        message_output: &mut [u8],
    ) -> Result<usize, Error> {
        assert!(message_output.len() >= encrypted.len());

        let encrypted_blocks = (encrypted.len() + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let encrypted_padding = (encrypted_blocks * BLOCK_SIZE) - encrypted.len();
        let decrypted_size = encrypted.len();

        let additional_data_blocks =
            (additional_data.len() + LENGHT_FIELD_LENGTH + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let additional_data_padding =
            (additional_data_blocks * BLOCK_SIZE) - (additional_data.len() + LENGHT_FIELD_LENGTH);

        let mic_blocks = (mic.len() / BLOCK_SIZE) + 1;
        assert_eq!(mic_blocks, 1);

        let mut cipher =
            Cipher::new(Algorithm::Aes128, Mode::Ctr).map_err(|e| Error::Other(e.code()))?;
        cipher.set_key(key).map_err(|e| Error::Other(e.code()))?;

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (flag, other) = block.split_at_mut(1);
            let (_nonce, _counter) = other.split_at_mut(nonce.len());
            flag[0] = Self::make_flag(0, 0, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
        }

        cipher.set_ctr(block).map_err(|e| Error::Other(e.code()))?;

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (_mic, _padding) = block.split_at_mut(mic.len());
            _mic.copy_from_slice(&mic);
        }

        let mut tag = [0; BLOCK_SIZE];
        cipher
            .encrypt(&block, &mut tag)
            .map_err(|e| Error::Other(e.code()))?;

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
            cipher
                .encrypt(&block, &mut output)
                .map_err(|e| Error::Other(e.code()))?;
            let (_, part) = message_output.split_at_mut(offset);
            let (part, _) = part.split_at_mut(length);
            part.copy_from_slice(&output[..length]);
        }

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (f, other) = block.split_at_mut(1);
            let (_nonce, mut length) = other.split_at_mut(nonce.len());
            f[0] = Self::make_flag(additional_data.len(), mic.len(), LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
            BigEndian::write_u16(&mut length, encrypted.len() as u16);
        }

        let mut cipher =
            Cipher::new(Algorithm::Aes128, Mode::Ecb).map_err(|e| Error::Other(e.code()))?;
        cipher.set_key(key).map_err(|e| Error::Other(e.code()))?;

        cipher
            .encrypt(&block, &mut output)
            .map_err(|e| Error::Other(e.code()))?;

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

        cipher
            .encrypt(&block, &mut output)
            .map_err(|e| Error::Other(e.code()))?;

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
                cipher
                    .encrypt(&block, &mut output)
                    .map_err(|e| Error::Other(e.code()))?;
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
            cipher
                .encrypt(&block, &mut output)
                .map_err(|e| Error::Other(e.code()))?;
        }

        let mut valid = true;
        for (a, b) in tag[..mic.len()].iter().zip(output[..mic.len()].iter()) {
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

    fn ccmstar_encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        message: &[u8],
        mic: &mut [u8],
        additional_data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let message_blocks = (message.len() + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let additional_data_blocks =
            (additional_data.len() + LENGHT_FIELD_LENGTH + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let mut work = [0u8; BLOCK_SIZE];
        {
            let mut buffer = [0u8; 256];
            let mut offset = 0;

            buffer[0] = Self::make_flag(additional_data.len(), mic.len(), LENGHT_FIELD_LENGTH);
            offset += 1;
            buffer[offset..offset + nonce.len()].copy_from_slice(nonce);
            offset += nonce.len();
            BigEndian::write_u16(&mut buffer[offset..offset + 2], message.len() as u16);
            offset += std::mem::size_of::<u16>();
            BigEndian::write_u16(
                &mut buffer[offset..offset + 2],
                additional_data.len() as u16,
            );
            offset += std::mem::size_of::<u16>();
            buffer[offset..offset + additional_data.len()].copy_from_slice(additional_data);
            offset += (additional_data_blocks * BLOCK_SIZE) - 2;
            buffer[offset..offset + message.len()].copy_from_slice(message);
            offset += message_blocks * BLOCK_SIZE;

            let mut cipher =
                Cipher::new(Algorithm::Aes128, Mode::Ecb).map_err(|e| Error::Other(e.code()))?;
            cipher.set_key(key).map_err(|e| Error::Other(e.code()))?;

            let mut block = [0u8; BLOCK_SIZE];
            for input in buffer[..offset].chunks(BLOCK_SIZE) {
                for n in 0..BLOCK_SIZE {
                    block[n] = work[n] ^ input[n];
                }

                cipher
                    .encrypt(&block, &mut work)
                    .map_err(|e| Error::Other(e.code()))?;
            }
        }
        {
            let mut buffer = [0u8; 256];
            let mut encrypted = [0u8; 256];
            let mut offset = 0;

            buffer[..message.len()].copy_from_slice(message);
            offset += message_blocks * BLOCK_SIZE;

            let mut block = [0u8; BLOCK_SIZE];
            block[0] = Self::make_flag(0, 0, LENGHT_FIELD_LENGTH);
            block[1..=nonce.len()].copy_from_slice(nonce);

            let mut cipher =
                Cipher::new(Algorithm::Aes128, Mode::Ctr).map_err(|e| Error::Other(e.code()))?;
            cipher.set_key(key).map_err(|e| Error::Other(e.code()))?;
            cipher.set_ctr(block).map_err(|e| Error::Other(e.code()))?;

            let mut block = [0u8; BLOCK_SIZE];
            let mut tag = [0u8; 16];
            block[..mic.len()].copy_from_slice(&work[..mic.len()]);
            cipher
                .encrypt(&block, &mut tag)
                .map_err(|e| Error::Other(e.code()))?;

            for (o, i) in encrypted[..offset]
                .chunks_mut(BLOCK_SIZE)
                .zip(buffer.chunks(BLOCK_SIZE))
            {
                cipher.encrypt(i, o).map_err(|e| Error::Other(e.code()))?;
            }

            output[..message.len()].copy_from_slice(&encrypted[..message.len()]);
            mic.copy_from_slice(&tag[..mic.len()]);
        }

        Ok(message.len())
    }

    /// Set the key
    fn aes128_ecb_encrypt_set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        assert!(key.len() == KEY_SIZE);
        self.cipher
            .set_key(&key)
            .map_err(|e| Error::Other(e.code()))
    }

    /// Set the IV
    fn aes128_ecb_encrypt_set_iv(&mut self, _iv: &[u8]) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    /// Set the IV
    fn aes128_ecb_encrypt_get_iv(&mut self, _iv: &mut [u8]) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    /// Process blocks of data
    fn aes128_ecb_encrypt_process_block(
        &mut self,
        input: &[u8],
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher
            .encrypt(&input, &mut output)
            .map_err(|e| Error::Other(e.code()))
    }
    /// Process the last bits and bobs and finish
    fn aes128_ecb_encrypt_finish(
        &mut self,
        input: &[u8],
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher
            .encrypt(&input, &mut output)
            .map_err(|e| Error::Other(e.code()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decryption_and_authentication_check_1() {
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

        let encrypted = &c[..c.len() - M];
        let mic = &c[c.len() - M..];

        let used = crypt
            .ccmstar_decrypt(&key, &nonce, encrypted, mic, &a, &mut message)
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
    fn test_encryption_and_authentication_check_1() {
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
        let message = [
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        ];
        let encrypted = [
            0x1A, 0x55, 0xA3, 0x6A, 0xBB, 0x6C, 0x61, 0x0D, 0x06, 0x6B, 0x33, 0x75, 0x64, 0x9C,
            0xEF, 0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8
        ];
        let mic = [0x0A, 0x89, 0x5C, 0xC1, 0xD8, 0xFF, 0x94, 0x69];
        let a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        // M, length of the authentication field in octets 0, 4, 6, 8, 10, 12, 14, 16
        const M: usize = 8;
        let mut _output = vec![0; message.len()];
        let mut output = _output.as_mut_slice();

        let mut mic_out = [0u8; M];

        let used = crypt
            .ccmstar_encrypt(&key, &nonce, &message, &mut mic_out, &a, &mut output)
            .unwrap();

        assert_eq!(used, 23);

        assert_eq!(output, encrypted);
        assert_eq!(mic, mic_out);
    }
}
