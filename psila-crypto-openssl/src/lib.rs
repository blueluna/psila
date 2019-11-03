use byteorder::{BigEndian, ByteOrder};
use openssl::symm::{Cipher, Crypter};
use psila_crypto::{BlockCipher, CryptoBackend, Error, BLOCK_SIZE, KEY_SIZE, LENGTH_FIELD_LENGTH};
use std::vec::Vec;

fn clear(slice: &mut [u8]) {
    for v in slice.iter_mut() {
        *v = 0;
    }
}

fn into_error(error: openssl::error::ErrorStack) -> Error {
    let errors = error.errors();
    let code = if errors.is_empty() {
        0
    }
    else {
        errors[0].code() as u32
    };
    Error::Other(code)
}

#[inline]
fn block_xor(a: &[u8], b: &[u8], r: &mut [u8])
{
    for n in 0..BLOCK_SIZE {
        r[n] = a[n] ^ b[n];
    }
}

#[derive(PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub struct OpenSslCipher {
    cipher: Cipher,
    mode: openssl::symm::Mode,
    key: Vec<u8>,
}

impl OpenSslCipher {
    pub fn new_aes_128_ecb(mode: Mode) -> Self {
        let mode = match mode {
            Mode::Encrypt => openssl::symm::Mode::Encrypt,
            Mode::Decrypt => openssl::symm::Mode::Decrypt,
        };
        let cipher = Cipher::aes_128_ecb();
        Self { cipher, mode, key: vec![] }
    }
}

impl BlockCipher for OpenSslCipher {
    /// Set the key
    fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        assert!(key.len() == KEY_SIZE);
        self.key = key.to_vec();
        Ok(())
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
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        let mut temp = [0u8; BLOCK_SIZE * 2];
        let mut crypter = Crypter::new(self.cipher, self.mode, &self.key, None).map_err(|e| into_error(e))?;
        crypter.update(input, &mut temp).map_err(|e| into_error(e))?;
        output.copy_from_slice(&temp[..BLOCK_SIZE]);
        Ok(())
    }
    /// Process the last bits and bobs and finish
    fn finish(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.process_block(input, output)
    }
}

pub struct Aes128Ctr<Cipher> {
    cipher: Cipher,
    counter: [u8; BLOCK_SIZE],
    block: [u8; BLOCK_SIZE],
}

impl<Cipher> Aes128Ctr<Cipher>
where
    Cipher: BlockCipher,
{
    pub fn new(cipher: Cipher, counter: [u8; BLOCK_SIZE]) -> Self {
        Self {
            cipher,
            counter,
            block: [0u8; BLOCK_SIZE],
        }
    }
    /// Set the key
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.cipher.set_key(key)
    }
    /// Process blocks of data
    pub fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher.process_block(&self.counter, &mut self.block)?;
        block_xor(input, &self.block, output);
        // WARNING: Only updating 1/4 of the counter!
        let mut counter = BigEndian::read_u32(&self.counter[12..16]);
        counter = counter.wrapping_add(1);
        BigEndian::write_u32(&mut self.counter[12..16], counter);
        Ok(())
    }
}

pub struct Aes128Cbc<Cipher> {
    cipher: Cipher,
    mode: Mode,
    block: [u8; BLOCK_SIZE],
}

impl<Cipher> Aes128Cbc<Cipher>
where
    Cipher: BlockCipher,
{
    pub fn new(cipher: Cipher, mode: Mode, initialization_vector: [u8; BLOCK_SIZE]) -> Self {
        Self {
            cipher,
            mode,
            block: initialization_vector,
        }
    }
    /// Set the key
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.cipher.set_key(key)
    }
    /// Process blocks of data
    pub fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        match self.mode {
            Mode::Encrypt => {
                for n in 0..BLOCK_SIZE {
                    self.block[n] ^= input[n];
                }
                self.cipher.process_block(&self.block, output)?;
                self.block.copy_from_slice(output);
            }
            Mode::Decrypt => {
                self.cipher.process_block(input, output)?;
                for n in 0..BLOCK_SIZE {
                    output[n] ^= self.block[n];
                }
                self.block.copy_from_slice(input);
            }
        }
        Ok(())
    }
}

pub struct OpenSslBackend {
    cipher: OpenSslCipher,
}

impl OpenSslBackend {
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

impl Default for OpenSslBackend {
    fn default() -> Self {
        Self {
            cipher: OpenSslCipher::new_aes_128_ecb(Mode::Decrypt),
        }
    }
}

impl CryptoBackend for OpenSslBackend {
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
            (additional_data.len() + LENGTH_FIELD_LENGTH + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let additional_data_padding =
            (additional_data_blocks * BLOCK_SIZE) - (additional_data.len() + LENGTH_FIELD_LENGTH);

        let mic_blocks = (mic.len() / BLOCK_SIZE) + 1;
        assert_eq!(mic_blocks, 1);

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (flag, other) = block.split_at_mut(1);
            let (_nonce, _counter) = other.split_at_mut(nonce.len());
            flag[0] = Self::make_flag(0, 0, LENGTH_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
        }

        let mut cipher = Aes128Ctr::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), block);
        cipher.set_key(key)?;

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (_mic, _padding) = block.split_at_mut(mic.len());
            _mic.copy_from_slice(&mic);
        }

        let mut tag = [0; BLOCK_SIZE];
        cipher.process_block(&block, &mut tag)?;

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
            cipher.process_block(&block, &mut output)?;
            let (_, part) = message_output.split_at_mut(offset);
            let (part, _) = part.split_at_mut(length);
            part.copy_from_slice(&output[..length]);
        }

        let mut cipher = Aes128Cbc::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), Mode::Encrypt, [0u8; BLOCK_SIZE]);
        cipher.set_key(key)?;

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (f, other) = block.split_at_mut(1);
            let (_nonce, mut length) = other.split_at_mut(nonce.len());
            f[0] = Self::make_flag(additional_data.len(), mic.len(), LENGTH_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
            BigEndian::write_u16(&mut length, encrypted.len() as u16);
        }

        cipher.process_block(&block, &mut output)?;

        // Handle additional data longer than the block size
        let mut input = [0; BLOCK_SIZE];
        {
            let length = if additional_data_blocks > 1 {
                BLOCK_SIZE - LENGTH_FIELD_LENGTH
            } else {
                additional_data.len()
            };
            let (mut _l, other) = input.split_at_mut(LENGTH_FIELD_LENGTH);
            let (_a, _padding) = other.split_at_mut(length);
            BigEndian::write_u16(&mut _l, additional_data.len() as u16);
            _a.copy_from_slice(&additional_data[..length]);
        }

        cipher.process_block(&input, &mut output)?;

        if additional_data_blocks > 1 {
            for n in 1..additional_data_blocks {
                let mut input = [0u8; BLOCK_SIZE];
                let offset = (n * BLOCK_SIZE) - LENGTH_FIELD_LENGTH;
                let length = if n == additional_data_blocks - 1 {
                    BLOCK_SIZE - additional_data_padding
                } else {
                    BLOCK_SIZE
                };
                {
                    let (part, _) = input.split_at_mut(length);
                    part.copy_from_slice(&additional_data[offset..offset + length]);
                }
                cipher.process_block(&input, &mut output)?;
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
            cipher.process_block(&input, &mut output)?;
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
            (additional_data.len() + LENGTH_FIELD_LENGTH + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
        let mut work = [0u8; BLOCK_SIZE];
        let mut buffer = [0u8; 256];
        {
            let mut offset = 0;

            buffer[0] = Self::make_flag(additional_data.len(), mic.len(), LENGTH_FIELD_LENGTH);
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

            let mut cipher = Aes128Cbc::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), Mode::Encrypt, [0u8; BLOCK_SIZE]);
            cipher.set_key(key)?;

            for input in buffer[..offset].chunks_exact(BLOCK_SIZE) {
                cipher.process_block(input, &mut work)?;
            }
        }
        {
            clear(&mut buffer);
            let mut encrypted = [0u8; 256];
            let mut offset = 0;

            buffer[..message.len()].copy_from_slice(message);
            offset += message_blocks * BLOCK_SIZE;

            let mut block = [0u8; BLOCK_SIZE];
            block[0] = Self::make_flag(0, 0, LENGTH_FIELD_LENGTH);
            block[1..=nonce.len()].copy_from_slice(nonce);

            let mut cipher = Aes128Ctr::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), block);
            cipher.set_key(key)?;

            let mut block = [0u8; BLOCK_SIZE];
            let mut tag = [0u8; 16];
            block[..mic.len()].copy_from_slice(&work[..mic.len()]);
            cipher.process_block(&block, &mut tag)?;

            for (o, i) in encrypted[..offset]
                .chunks_exact_mut(BLOCK_SIZE)
                .zip(buffer.chunks_exact(BLOCK_SIZE))
            {
                cipher.process_block(i, o)?;
            }

            output[..message.len()].copy_from_slice(&encrypted[..message.len()]);
            mic.copy_from_slice(&tag[..mic.len()]);
        }

        Ok(message.len())
    }

    /// Set the key
    fn aes128_ecb_encrypt_set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        assert!(key.len() == KEY_SIZE);
        self.cipher.set_key(&key)
    }

    /// Process blocks of data
    fn aes128_ecb_encrypt_process_block(
        &mut self,
        input: &[u8],
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher.process_block(&input, &mut output)
    }
    /// Process the last bits and bobs and finish
    fn aes128_ecb_encrypt_finish(
        &mut self,
        input: &[u8],
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        assert!(input.len() == BLOCK_SIZE);
        assert!(output.len() == BLOCK_SIZE);
        self.cipher.process_block(&input, &mut output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes_128_ecb_encrypt() {
        // Test vectors taken from NIST Special Publication 800-38A
        // Recommendation for Block Cipher Modes of Operation - Methods and Techniques
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let message = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let result = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
            0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
            0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
        ];
        let mut encrypted = [0u8; 256];
        let mut cipher = OpenSslCipher::new_aes_128_ecb(Mode::Encrypt);
        cipher.set_key(&key).unwrap();
        for (input, output) in message.chunks_exact(BLOCK_SIZE).zip(encrypted.chunks_exact_mut(BLOCK_SIZE)) {
            cipher.process_block(input, output).unwrap();
        }
        for (calculated, correct) in encrypted.chunks_exact(BLOCK_SIZE).zip(result.chunks_exact(BLOCK_SIZE)) {
            assert_eq!(calculated, correct);
        }
    }
    #[test]
    fn test_aes_128_ecb_decrypt() {
        // Test vectors taken from NIST Special Publication 800-38A
        // Recommendation for Block Cipher Modes of Operation - Methods and Techniques
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let message = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
            0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
            0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
        ];
        let result = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let mut decrypted = [0u8; 256];
        let mut cipher = OpenSslCipher::new_aes_128_ecb(Mode::Decrypt);
        cipher.set_key(&key).unwrap();
        for (input, output) in message.chunks_exact(BLOCK_SIZE).zip(decrypted.chunks_exact_mut(BLOCK_SIZE)) {
            cipher.process_block(input, output).unwrap();
        }
        for (calculated, correct) in decrypted.chunks_exact(BLOCK_SIZE).zip(result.chunks_exact(BLOCK_SIZE)) {
            assert_eq!(calculated, correct);
        }
    }
    #[test]
    fn test_aes_128_ctr_encrypt() {
        // Test vectors taken from NIST Special Publication 800-38A
        // Recommendation for Block Cipher Modes of Operation - Methods and Techniques
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
            ];
        let counter = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
            ];
        let message = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
            ];
        let result = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
            0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
            ];
        let mut encrypted = [0u8; 256];
        let mut cipher = Aes128Ctr::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), counter);
        cipher.set_key(&key).unwrap();
        for (input, output) in message.chunks_exact(BLOCK_SIZE).zip(encrypted.chunks_exact_mut(BLOCK_SIZE)) {
            cipher.process_block(input, output).unwrap();
        }
        for (calculated, correct) in encrypted.chunks_exact(BLOCK_SIZE).zip(result.chunks_exact(BLOCK_SIZE)) {
            assert_eq!(calculated, correct);
        }
    }
    #[test]
    fn test_aes_128_ctr_decrypt() {
        // Test vectors taken from NIST Special Publication 800-38A
        // Recommendation for Block Cipher Modes of Operation - Methods and Techniques
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let counter = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
            ];
        let message = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
            0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
        ];
        let result = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let mut decrypted = [0u8; 256];
        let mut cipher = Aes128Ctr::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), counter);
        cipher.set_key(&key).unwrap();
        for (input, output) in message.chunks_exact(BLOCK_SIZE).zip(decrypted.chunks_exact_mut(BLOCK_SIZE)) {
            cipher.process_block(input, output).unwrap();
        }
        for (calculated, correct) in decrypted.chunks_exact(BLOCK_SIZE).zip(result.chunks_exact(BLOCK_SIZE)) {
            assert_eq!(calculated, correct);
        }
    }
    #[test]
    fn test_aes_128_cbc_encrypt() {
        // Test vectors taken from NIST Special Publication 800-38A
        // Recommendation for Block Cipher Modes of Operation - Methods and Techniques
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
            ];
        let initialization_vector = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            ];
        let message = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
            ];
        let result = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
            0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
            0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
            ];
        let mut encrypted = [0u8; 256];
        let mut cipher = Aes128Cbc::new(OpenSslCipher::new_aes_128_ecb(Mode::Encrypt), Mode::Encrypt, initialization_vector);
        cipher.set_key(&key).unwrap();
        for (input, output) in message.chunks_exact(BLOCK_SIZE).zip(encrypted.chunks_exact_mut(BLOCK_SIZE)) {
            cipher.process_block(input, output).unwrap();
        }
        for (calculated, correct) in encrypted.chunks_exact(BLOCK_SIZE).zip(result.chunks_exact(BLOCK_SIZE)) {
            assert_eq!(calculated, correct);
        }
    }
    #[test]
    fn test_aes_128_cbc_decrypt() {
        // Test vectors taken from NIST Special Publication 800-38A
        // Recommendation for Block Cipher Modes of Operation - Methods and Techniques
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let initialization_vector = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            ];
        let message = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
            0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
            0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];
        let result = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let mut decrypted = [0u8; 256];
        let mut cipher = Aes128Cbc::new(OpenSslCipher::new_aes_128_ecb(Mode::Decrypt), Mode::Decrypt, initialization_vector);
        cipher.set_key(&key).unwrap();
        for (input, output) in message.chunks_exact(BLOCK_SIZE).zip(decrypted.chunks_exact_mut(BLOCK_SIZE)) {
            cipher.process_block(input, output).unwrap();
        }
        for (calculated, correct) in decrypted.chunks_exact(BLOCK_SIZE).zip(result.chunks_exact(BLOCK_SIZE)) {
            assert_eq!(calculated, correct);
        }
    }

    #[test]
    fn test_decryption_and_authentication_check_1() {
        let mut crypt = OpenSslBackend::default();

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
        let mut crypt = OpenSslBackend::default();

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
            0xEF, 0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8,
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
