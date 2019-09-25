//! # Security service

use psila_crypto::{self, CryptoBackend};

use crate::error::Error;

mod header;

use crate::common::key::KEY_SIZE;
use crate::pack::{Pack, PackFixed};

pub use header::{KeyIdentifier, SecurityControl, SecurityHeader, SecurityLevel};

pub use psila_crypto::LENGHT_FIELD_LENGTH;
pub use psila_crypto::BLOCK_SIZE;

/// Default link key, "ZigBeeAlliance09"
pub const DEFAULT_LINK_KEY: [u8; KEY_SIZE] = [
    0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39,
];

/// Light link master key
pub const LIGHT_LINK_MASTER_KEY: [u8; KEY_SIZE] = [
    0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57, 0xC8, 0xA4, 0x69, 0xCB, 0xF4, 0x2B, 0xC9, 0x3F, 0xEE, 0x31,
];

/// Light link commisioning link key
pub const LIGHT_LINK_COMMISIONING_LINK_KEY: [u8; KEY_SIZE] = [
    0x81, 0x42, 0x86, 0x86, 0x5D, 0xC1, 0xC8, 0xB2, 0xC8, 0xCB, 0xC5, 0x2E, 0x5D, 0x65, 0xD1, 0xB8,
];

pub struct CryptoProvider<Backend> {
    backend: Backend,
    buffer: [u8; 256],
}

impl<Backend> CryptoProvider<Backend>
where
    Backend: CryptoBackend,
{
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            buffer: [0u8; 256],
        }
    }

    /// Process a block for the Key-hash hash function
    fn hash_key_process_block(
        &mut self,
        input: &[u8],
        mut output: &mut [u8],
        finish: bool,
    ) -> Result<(), Error> {
        self.backend.aes128_ecb_encrypt_set_key(&output)?;
        if finish {
            self.backend
                .aes128_ecb_encrypt_finish(&input, &mut output)?;
        } else {
            self.backend
                .aes128_ecb_encrypt_process_block(&input, &mut output)?;
        }
        // XOR the input into the hash block
        for n in 0..BLOCK_SIZE {
            output[n] ^= input[n];
        }
        Ok(())
    }

    /// Key-hash hash function
    fn hash_key_hash(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        assert!(input.len() < 4096);

        // Clear the first block of output
        for b in output[..BLOCK_SIZE].iter_mut() {
            *b = 0;
        }

        let mut blocks = input.chunks_exact(BLOCK_SIZE);

        // Process input data in cipher block sized chunks
        loop {
            match blocks.next() {
                Some(input_block) => {
                    self.hash_key_process_block(&input_block, &mut output[..BLOCK_SIZE], false)?;
                }
                None => {
                    let mut block = [0u8; BLOCK_SIZE];
                    let remainder = blocks.remainder();
                    assert!(remainder.len() < BLOCK_SIZE - 3);
                    block[..remainder.len()].copy_from_slice(remainder);
                    // Pad the message M by right-concatenating to M the bit ‘1’ followed by the
                    // smallest non-negative number of ‘0’ bits, such that the resulting string has
                    // length 14 (mod 16) octets:
                    block[remainder.len()] = 0x80;
                    let input_len = input.len() as u16 * 8;
                    // Form the padded message M' by right-concatenating to the resulting string the
                    // 16-bit string that is equal to the binary representation of the integer l:
                    block[BLOCK_SIZE - 2] = (input_len >> 8) as u8;
                    block[BLOCK_SIZE - 1] = (input_len & 0xff) as u8;
                    self.hash_key_process_block(&block, &mut output[..BLOCK_SIZE], true)?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// FIPS Pub 198 HMAC
    pub fn hash_key(
        &mut self,
        key: &[u8; KEY_SIZE],
        input: u8,
        result: &mut [u8],
    ) -> Result<(), Error> {
        const HASH_INNER_PAD: u8 = 0x36;
        const HASH_OUTER_PAD: u8 = 0x5c;
        let mut hash_in = [0; BLOCK_SIZE * 2];
        let mut hash_out = [0; BLOCK_SIZE + 1];

        {
            // XOR the key with the outer padding
            for n in 0..KEY_SIZE {
                hash_in[n] = key[n] ^ HASH_OUTER_PAD;
            }
            // XOR the key with the inner padding
            for n in 0..KEY_SIZE {
                hash_out[n] = key[n] ^ HASH_INNER_PAD;
            }
            // Append the input byte
            hash_out[BLOCK_SIZE] = input;
            // Hash hash_out to form (Key XOR opad) || H((Key XOR ipad) || text)
            self.hash_key_hash(&hash_out[..=BLOCK_SIZE], &mut hash_in[BLOCK_SIZE..])?;
            // Hash hash_in to get the result
            self.hash_key_hash(&hash_in, &mut hash_out)?;
        }
        {
            // Take the key
            let (output_key, _) = result.split_at_mut(KEY_SIZE);
            output_key.copy_from_slice(&hash_out[..KEY_SIZE]);
        }

        Ok(())
    }

    pub fn decrypt_payload(
        &mut self,
        key: &[u8; KEY_SIZE],
        security_level: SecurityLevel,
        payload: &[u8],
        secure_header_offset: usize,
        mut output_payload: &mut [u8],
    ) -> Result<usize, Error> {
        let (mut header, used) = SecurityHeader::unpack(&payload[secure_header_offset..])?;
        header.control.set_level(security_level);

        self.buffer[..payload.len()].copy_from_slice(&payload);

        header
            .control
            .pack(&mut self.buffer[secure_header_offset..=secure_header_offset])?;

        let mic_bytes = header.control.level.mic_bytes();

        if payload.len() - used < mic_bytes {
            return Err(Error::WrongNumberOfBytes);
        }

        let mut updated_key = [0; KEY_SIZE];

        match header.control.identifier {
            KeyIdentifier::KeyTransport => {
                self.hash_key(&key, 0x00, &mut updated_key)?;
            }
            KeyIdentifier::KeyLoad => {
                self.hash_key(&key, 0x02, &mut updated_key)?;
            }
            _ => {
                updated_key.copy_from_slice(&key[..]);
            }
        }

        let payload_start = secure_header_offset + used;

        // L -> Message length field, 2
        // Nonce N, 15-L octets
        let mut nonce = [0; 13];
        header.get_nonce(&mut nonce);

        let aad = &self.buffer[..payload_start];
        // Payload == a with length l(a), 0 < l(a) < 2^64
        let payload = &self.buffer[payload_start..payload.len()];

        let used = self.backend.ccmstar_decrypt(
            &updated_key,
            &nonce,
            &payload,
            mic_bytes,
            &aad,
            &mut output_payload,
        )?;

        Ok(used)
    }
}
