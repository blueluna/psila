//! # Security service

use core::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use crate::common::{address::ExtendedAddress, key::KEY_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

use gcrypt::{
    self,
    cipher::{Algorithm, Cipher, Mode},
};

/// L, length of the message length field in octets 2, 3, ... 8. Always 2 for Zigbee
pub const LENGHT_FIELD_LENGTH: usize = 2;
/// Cipher block length
pub const BLOCK_SIZE: usize = 16;

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

/// Security Level, 4.5.1.1.1
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SecurityLevel {
    /// No encryption or message integrity check
    None = 0b000,
    /// No encryption, 32-bit message integrity check
    Integrity32 = 0b001,
    /// No encryption, 64-bit message integrity check
    Integrity64 = 0b010,
    /// No encryption, 128-bit message integrity check
    Integrity128 = 0b011,
    /// Encrypted, No message integrity check
    Encrypted = 0b100,
    /// Encrypted, 32-bit message integrity check
    EncryptedIntegrity32 = 0b101,
    /// Encrypted, 64-bit message integrity check
    EncryptedIntegrity64 = 0b110,
    /// Encrypted, 128-bit message integrity check
    EncryptedIntegrity128 = 0b111,
}

impl TryFrom<u8> for SecurityLevel {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b0000_0111 {
            0b000 => Ok(SecurityLevel::None),
            0b001 => Ok(SecurityLevel::Integrity32),
            0b010 => Ok(SecurityLevel::Integrity64),
            0b011 => Ok(SecurityLevel::Integrity128),
            0b100 => Ok(SecurityLevel::Encrypted),
            0b101 => Ok(SecurityLevel::EncryptedIntegrity32),
            0b110 => Ok(SecurityLevel::EncryptedIntegrity64),
            0b111 => Ok(SecurityLevel::EncryptedIntegrity128),
            _ => Err(Error::UnknownSecurityLevel),
        }
    }
}

impl SecurityLevel {
    /// Number of bytes of message integrity code at the end of the frame
    pub fn mic_bytes(self) -> usize {
        match self {
            SecurityLevel::None | SecurityLevel::Encrypted => 0,
            SecurityLevel::Integrity32 | SecurityLevel::EncryptedIntegrity32 => 4,
            SecurityLevel::Integrity64 | SecurityLevel::EncryptedIntegrity64 => 8,
            SecurityLevel::Integrity128 | SecurityLevel::EncryptedIntegrity128 => 16,
        }
    }
}

/// Key Identifier, 4.5.1.1.2
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyIdentifier {
    /// Data key
    Data = 0b00,
    /// Network key
    Network = 0b01,
    /// Key-transport key
    KeyTransport = 0b10,
    /// Key-load key
    KeyLoad = 0b11,
}

impl TryFrom<u8> for KeyIdentifier {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b0000_0011 {
            0b00 => Ok(KeyIdentifier::Data),
            0b01 => Ok(KeyIdentifier::Network),
            0b10 => Ok(KeyIdentifier::KeyTransport),
            0b11 => Ok(KeyIdentifier::KeyLoad),
            _ => Err(Error::UnknownKeyIdentifier),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SecurityControl {
    pub level: SecurityLevel,
    pub identifier: KeyIdentifier,
    /// The auxilliary header has sender address
    has_source_address: bool,
}

impl SecurityControl {
    pub fn set_level(&mut self, level: SecurityLevel) {
        self.level = level;
    }
}

impl PackFixed<SecurityControl, Error> for SecurityControl {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 1 {
            return Err(Error::NotEnoughSpace);
        }
        let level = self.level as u8;
        let identifier = self.identifier as u8;
        data[0] = level | identifier << 3 | (self.has_source_address as u8) << 5;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        let level = SecurityLevel::try_from(data[0])?;
        let identifier = KeyIdentifier::try_from(data[0] >> 3)?;
        let has_source_address = (data[0] & (0x01 << 5)) == (0x01 << 5);
        Ok(SecurityControl {
            level,
            identifier,
            has_source_address,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SecurityHeader {
    pub control: SecurityControl,
    /// Securit header frame counter
    pub counter: u32,
    ///
    pub source: Option<ExtendedAddress>,
    ///
    pub sequence: Option<u8>,
}

impl SecurityHeader {
    pub fn get_nonce(&self, buf: &mut [u8]) {
        if let Some(source) = self.source {
            source.pack(&mut buf[0..8]).unwrap();
        }
        LittleEndian::write_u32(&mut buf[8..12], self.counter);
        self.control.pack(&mut buf[12..13]).unwrap();
    }
}

impl Pack<SecurityHeader, Error> for SecurityHeader {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 5 {
            return Err(Error::NotEnoughSpace);
        }
        unimplemented!();
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 5 {
            return Err(Error::WrongNumberOfBytes);
        }
        let control = SecurityControl::unpack(&data[..1])?;
        let counter = LittleEndian::read_u32(&data[1..5]);
        let mut offset = 5;
        let source = if control.has_source_address {
            if data.len() < (offset + 8) {
                return Err(Error::WrongNumberOfBytes);
            } else {
                let address = ExtendedAddress::unpack(&data[offset..offset + 8])?;
                offset += 8;
                Some(address)
            }
        } else {
            None
        };
        let sequence = if control.identifier == KeyIdentifier::Network {
            if data.len() < (offset + 1) {
                return Err(Error::WrongNumberOfBytes);
            } else {
                offset += 1;
                Some(data[offset - 1])
            }
        } else {
            None
        };

        Ok((
            SecurityHeader {
                control,
                counter,
                source,
                sequence,
            },
            offset,
        ))
    }
}

/// Process a block for the Key-hash hash function
fn hash_key_process_block(
    cipher: &mut Cipher,
    input: &[u8],
    mut output: &mut [u8],
) -> Result<(), gcrypt::Error> {
    cipher.set_key(&output)?;
    cipher.encrypt(&input, &mut output)?;
    // XOR the input into the hash block
    for n in 0..BLOCK_SIZE {
        output[n] ^= input[n];
    }
    Ok(())
}

/// Key-hash hash function
fn hash_key_hash(input: &[u8], output: &mut [u8]) -> Result<(), gcrypt::Error> {
    assert!(input.len() < 4096);

    // Clear the first block of output
    for b in output[..BLOCK_SIZE].iter_mut() {
        *b = 0;
    }

    let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ecb)?;

    let mut blocks = input.chunks_exact(BLOCK_SIZE);

    // Process input data in cipher block sized chunks
    loop {
        match blocks.next() {
            Some(input_block) => {
                hash_key_process_block(&mut cipher, &input_block, &mut output[..BLOCK_SIZE])?;
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
                hash_key_process_block(&mut cipher, &block, &mut output[..BLOCK_SIZE])?;
                break;
            }
        }
    }
    Ok(())
}

/// FIPS Pub 198 HMAC
pub fn hash_key(key: &[u8; KEY_SIZE], input: u8, result: &mut [u8]) -> Result<(), gcrypt::Error> {
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
        hash_key_hash(&hash_out[..=BLOCK_SIZE], &mut hash_in[BLOCK_SIZE..])?;
        // Hash hash_in to get the result
        hash_key_hash(&hash_in, &mut hash_out)?;
    }
    {
        // Take the key
        let (output_key, _) = result.split_at_mut(KEY_SIZE);
        output_key.copy_from_slice(&hash_out[..KEY_SIZE]);
    }

    Ok(())
}

pub fn make_flag(a_length: usize, big_m: usize, big_l: usize) -> u8 {
    let mut flag = if a_length > 0 { 0x40 } else { 0 };
    flag = if big_m > 0 {
        flag | ((((big_m - 2) / 2) as u8) & 0x07) << 3
    } else {
        flag
    };
    flag |= 0x07 & ((big_l - 1) as u8);
    flag
}

pub fn decryption_and_authentication(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    message: &[u8],
    mic_length: usize,
    additional_data: &[u8],
    message_output: &mut [u8],
) -> Result<bool, gcrypt::Error> {
    assert!(message.len() <= (message_output.len() + mic_length));
    // C.4.1 Decryption Transformation

    if message.len() < mic_length {
        return Err(gcrypt::Error::INV_LENGTH);
    }

    let (encrypted, mic) = message.split_at(message.len() - mic_length);

    let encrypted_blocks = (encrypted.len() + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
    let encrypted_padding = (encrypted_blocks * BLOCK_SIZE) - encrypted.len();

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
        flag[0] = make_flag(0, 0, LENGHT_FIELD_LENGTH);
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
        f[0] = make_flag(additional_data.len(), mic_length, LENGHT_FIELD_LENGTH);
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
        Ok(true)
    } else {
        for b in message_output.iter_mut() {
            *b = 0;
        }
        Ok(false)
    }
}

pub fn handle_secure_payload(
    key: &[u8; KEY_SIZE],
    security_level: SecurityLevel,
    payload: &[u8],
    secure_header_offset: usize,
    mut output_payload: &mut [u8],
) -> Result<usize, gcrypt::Error> {
    let (mut header, used) = match SecurityHeader::unpack(&payload[secure_header_offset..]) {
        Ok((f, used)) => (f, used),
        Err(_) => return Err(gcrypt::Error::INV_PACKET),
    };
    header.control.set_level(security_level);

    let mut _patched_buffer = vec![0u8; payload.len()];
    let patched_buffer = _patched_buffer.as_mut_slice();

    patched_buffer.copy_from_slice(&payload[..]);

    if header
        .control
        .pack(&mut patched_buffer[secure_header_offset..=secure_header_offset])
        .is_err()
    {
        return Err(gcrypt::Error::INV_DATA);
    }

    let mic_bytes = header.control.level.mic_bytes();

    if payload.len() - used < mic_bytes {
        return Err(gcrypt::Error::INV_LENGTH);
    }

    let mut updated_key = [0; KEY_SIZE];

    match header.control.identifier {
        KeyIdentifier::KeyTransport => {
            hash_key(&key, 0x00, &mut updated_key)?;
        }
        KeyIdentifier::KeyLoad => {
            hash_key(&key, 0x02, &mut updated_key)?;
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

    let mut _aad = vec![0; payload_start];
    let aad = _aad.as_mut_slice();
    {
        aad.copy_from_slice(&patched_buffer[..payload_start]);
    }

    // Payload == a with length l(a), 0 < l(a) < 2^64
    let payload = &patched_buffer[payload_start..];

    let valid = decryption_and_authentication(
        &updated_key,
        &nonce,
        &payload,
        mic_bytes,
        &aad,
        &mut output_payload,
    )?;

    let payload_size = if valid { payload.len() - mic_bytes } else { 0 };

    Ok(payload_size)
}

#[allow(dead_code)]
fn print_secure_header(header: &SecurityHeader) {
    print!(
        "SEC Level {:?} Key Identifier {:?}",
        header.control.level, header.control.identifier
    );
    if let Some(src) = header.source {
        print!(" Source {}", src);
    }
    if let Some(seq) = header.sequence {
        print!(" Sequence {}", seq);
    }
    println!(" Counter {}", header.counter);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_security_control() {
        let data = [0x30];
        let sc = SecurityControl::unpack(&data[..1]).unwrap();
        assert_eq!(sc.level, SecurityLevel::None);
        assert_eq!(sc.identifier, KeyIdentifier::KeyTransport);
        assert_eq!(sc.has_source_address, true);
    }

    #[test]
    fn unpack_security_header() {
        let data = [
            0x30, 0x02, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0xae,
            0x5e, 0x9f, 0x46, 0xa6, 0x40, 0xcd, 0xe7, 0x90, 0x2f, 0xd6, 0x0e, 0x43, 0x23, 0x17,
            0x48, 0x4b, 0x4c, 0x5a, 0x9b, 0x4c, 0xde, 0x1c, 0xe7, 0x07, 0x07, 0xb6, 0xfb, 0x1a,
            0x0b, 0xe9, 0x99, 0x7e, 0x0a, 0xf8, 0x0f, 0xdf, 0x5d, 0xcf,
        ];
        let (f, used) = SecurityHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 13);
        assert_eq!(f.control.level, SecurityLevel::None);
        assert_eq!(f.control.identifier, KeyIdentifier::KeyTransport);
        assert_eq!(f.control.has_source_address, true);
        assert_eq!(f.counter, 2);
        assert_eq!(f.source.unwrap(), 0x0021_2eff_ff03_2e38);
        assert_eq!(f.sequence, None);
    }

    #[test]
    fn test_key_hash() {
        use gcrypt;
        gcrypt::init_default();
        // C.6.1 Test Vector Set 1
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        let mut calculated = [0; BLOCK_SIZE];
        hash_key(&key, 0xc0, &mut calculated).unwrap();
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

        let valid = decryption_and_authentication(&key, &nonce, &c, M, &a, &mut message).unwrap();

        assert_eq!(valid, true);

        assert_eq!(
            message,
            [
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
            ]
        );
    }

    #[test]
    fn test_decryption_and_authentication_check() {
        use byteorder::{BigEndian, ByteOrder};
        use gcrypt::{
            self,
            cipher::{Algorithm, Cipher, Mode},
        };

        gcrypt::init_default();

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
        // C.4.1 Decryption Transformation
        let (big_c, big_u) = c.split_at(c.len() - M);

        assert_eq!(
            big_c,
            [
                0x1A, 0x55, 0xA3, 0x6A, 0xBB, 0x6C, 0x61, 0x0D, 0x06, 0x6B, 0x33, 0x75, 0x64, 0x9C,
                0xEF, 0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8
            ]
        );
        assert_eq!(big_u, [0x0A, 0x89, 0x5C, 0xC1, 0xD8, 0xFF, 0x94, 0x69]);

        let ciphertext_data_bytes = ((big_c.len() / 16) + 1) * 16;
        let mut _ciphertext_data = vec![0; ciphertext_data_bytes];
        let ciphertext_data = _ciphertext_data.as_mut_slice();

        {
            let (data, _padding) = ciphertext_data.split_at_mut(big_c.len());
            data.copy_from_slice(&big_c);
        }

        let mut a0 = [0u8; BLOCK_SIZE];
        {
            let (flag, other) = a0.split_at_mut(1);
            let (_nonce, _counter) = other.split_at_mut(nonce.len());
            flag[0] = make_flag(0, 0, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
        }
        assert_eq!(
            a0,
            [
                0x01, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
                0x00, 0x00
            ]
        );

        let mut block = [0u8; BLOCK_SIZE];
        {
            let (_mic, _padding) = block.split_at_mut(big_u.len());
            _mic.copy_from_slice(&big_u);
        }

        let mut output = [0; BLOCK_SIZE];

        let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ctr).unwrap();
        cipher.set_key(key).unwrap();
        cipher.set_ctr(a0).unwrap();
        cipher.encrypt(&block, &mut output).unwrap();

        let mut tag = [0; M];
        tag.copy_from_slice(&output[..M]);

        let mut _decrypted = vec![0; ciphertext_data.len()];
        let mut decrypted = _decrypted.as_mut_slice();
        cipher.encrypt(&ciphertext_data, &mut decrypted).unwrap();

        {
            let (_, _padding) = decrypted.split_at_mut(big_c.len());
            for b in _padding.iter_mut() {
                *b = 0;
            }
        }

        assert_eq!(
            decrypted,
            [
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        assert_eq!(tag, [0xB9, 0xD7, 0x89, 0x67, 0x04, 0xBC, 0xFA, 0x20]);

        {
            let (f, other) = block.split_at_mut(1);
            let (_nonce, mut length) = other.split_at_mut(nonce.len());
            f[0] = make_flag(a.len(), M, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
            BigEndian::write_u16(&mut length, big_c.len() as u16);
        }

        let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ecb).unwrap();
        cipher.set_key(key).unwrap();

        let mut input = [0; BLOCK_SIZE];

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0xF7, 0x74, 0xD1, 0x6E, 0xA7, 0x2D, 0xC0, 0xB3, 0xE4, 0x5E, 0x36, 0xCA, 0x8F, 0x24,
                0x3B, 0x1A
            ]
        );

        {
            let (mut length, other) = input.split_at_mut(2);
            let (_a, _padding) = other.split_at_mut(a.len());
            BigEndian::write_u16(&mut length, a.len() as u16);
            _a.copy_from_slice(&a);
            for b in _padding.iter_mut() {
                *b = 0;
            }
        }

        assert_eq!(
            input,
            [
                0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ]
        );

        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ input[n];
        }

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0x90, 0x2E, 0x72, 0x58, 0xAE, 0x5A, 0x4B, 0x5D, 0x85, 0x7A, 0x25, 0x19, 0xF3, 0xC7,
                0x3A, 0xB3
            ]
        );

        input.copy_from_slice(&decrypted[..BLOCK_SIZE]);

        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ input[n];
        }

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0x5A, 0xB2, 0xC8, 0x6E, 0x3E, 0xDA, 0x23, 0xD2, 0x7C, 0x49, 0x7D, 0xDF, 0x49, 0xBB,
                0xB4, 0x09
            ]
        );

        input.copy_from_slice(&decrypted[BLOCK_SIZE..BLOCK_SIZE * 2]);

        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ input[n];
        }

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0xB9, 0xD7, 0x89, 0x67, 0x04, 0xBC, 0xFA, 0x20, 0xB2, 0x10, 0x36, 0x74, 0x45, 0xF9,
                0x83, 0xD6
            ]
        );

        let mut tag_2 = [0; M];
        tag_2.copy_from_slice(&output[..M]);

        assert_eq!(tag, tag_2);
        assert_eq!(tag_2, [0xB9, 0xD7, 0x89, 0x67, 0x04, 0xBC, 0xFA, 0x20]);
    }

    #[test]
    fn decode_security_header() {
        use gcrypt;

        gcrypt::init_default();

        let data = [
            0x21, 0x45, 0x30, 0x02, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0xae, 0x5e, 0x9f, 0x46, 0xa6, 0x40, 0xcd, 0xe7, 0x90, 0x2f, 0xd6, 0x0e, 0x43,
            0x23, 0x17, 0x48, 0x4b, 0x4c, 0x5a, 0x9b, 0x4c, 0xde, 0x1c, 0xe7, 0x07, 0x07, 0xb6,
            0xfb, 0x1a, 0x0b, 0xe9, 0x99, 0x7e, 0x0a, 0xf8, 0x0f, 0xdf, 0x5d, 0xcf,
        ];

        let (mut f, used) = SecurityHeader::unpack(&data[2..]).unwrap();
        f.control.set_level(SecurityLevel::EncryptedIntegrity32);

        let mut _patched_buffer = vec![0u8; data.len()];
        let patched_buffer = _patched_buffer.as_mut_slice();

        patched_buffer.copy_from_slice(&data[..]);

        f.control.pack(&mut patched_buffer[2..3]).unwrap();

        let mic_bytes = f.control.level.mic_bytes();

        let mut key = [0; KEY_SIZE];

        match f.control.identifier {
            KeyIdentifier::KeyTransport => {
                hash_key(&DEFAULT_LINK_KEY, 0x00, &mut key).unwrap();
            }
            KeyIdentifier::KeyLoad => {
                hash_key(&DEFAULT_LINK_KEY, 0x02, &mut key).unwrap();
            }
            _ => {
                key.copy_from_slice(&DEFAULT_LINK_KEY);
            }
        }

        let payload_start = used + 2;

        // L -> Message length field, 2
        // Nonce N, 15-L octets
        let mut nonce = [0; 13];
        f.get_nonce(&mut nonce);

        let mut _aad = vec![0; payload_start];
        let aad = _aad.as_mut_slice();
        {
            aad.copy_from_slice(&patched_buffer[..payload_start]);
        }

        // Payload == a with length l(a), 0 < l(a) < 2^64
        let payload = &patched_buffer[payload_start..];

        let mut _message = vec![0; payload.len() - mic_bytes];
        let mut message = _message.as_mut_slice();

        let valid =
            decryption_and_authentication(&key, &nonce, &payload, mic_bytes, &aad, &mut message)
                .unwrap();

        assert_eq!(valid, true);

        let correct_message = [
            0x05, 0x01, 0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48,
            0x00, 0x40, 0x64, 0x08, 0x00, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x38,
            0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00,
        ];

        assert_eq!(message[..16], correct_message[..16]);
        assert_eq!(message[16..], correct_message[16..]);
    }

    #[test]
    fn test_handle_secure_payload_1() {
        use gcrypt;

        gcrypt::init_default();

        let input = [
            0x21, 0x45, 0x30, 0x02, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0xae, 0x5e, 0x9f, 0x46, 0xa6, 0x40, 0xcd, 0xe7, 0x90, 0x2f, 0xd6, 0x0e, 0x43,
            0x23, 0x17, 0x48, 0x4b, 0x4c, 0x5a, 0x9b, 0x4c, 0xde, 0x1c, 0xe7, 0x07, 0x07, 0xb6,
            0xfb, 0x1a, 0x0b, 0xe9, 0x99, 0x7e, 0x0a, 0xf8, 0x0f, 0xdf, 0x5d, 0xcf,
        ];

        let mut _output = vec![0; input.len()];
        let mut output = _output.as_mut_slice();

        let decrypted_size = handle_secure_payload(
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
        use gcrypt;

        gcrypt::init_default();

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

        let decrypted_size = handle_secure_payload(
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
        use gcrypt;

        gcrypt::init_default();

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

        let decrypted_size = handle_secure_payload(
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
        use crate::application_service::ApplicationServiceHeader;
        use gcrypt;

        gcrypt::init_default();

        let input = [
            0x21, 0xf2, 0x30, 0x05, 0x00, 0x00, 0x00, 0xb5, 0xb4, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0x63, 0xe2, 0x62, 0xd6, 0xb3, 0x67, 0x4d, 0x0e, 0x34, 0x9f, 0xaa, 0x04, 0x81,
            0xf9, 0x1d, 0xf6, 0xa4, 0x72, 0x7f, 0x36, 0xde, 0x4d, 0xf5, 0xeb, 0xd8, 0xea, 0xc5,
            0x4e, 0x78, 0x1c, 0xd9, 0x36, 0x07, 0xb4, 0x62, 0xc9, 0xf8, 0xb7, 0x77,
        ];

        let (_aps, used) = ApplicationServiceHeader::unpack(&input[..]).unwrap();

        let mut _output = vec![0; input.len()];
        let mut output = _output.as_mut_slice();

        let decrypted_size = handle_secure_payload(
            &DEFAULT_LINK_KEY,
            SecurityLevel::EncryptedIntegrity32,
            &input,
            used,
            &mut output,
        )
        .unwrap();

        assert_eq!(decrypted_size, 35);
    }

    #[test]
    fn test_encryption_and_authentication() {
        use gcrypt;
        gcrypt::init_default();
        use byteorder::{BigEndian, ByteOrder};

        let key = [
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
            0xCE, 0xCF,
        ];
        let nonce = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
        ];
        let m = [
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        ];
        let a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        // M, length of the authentication field in octets 0, 4, 6, 8, 10, 12, 14, 16
        const M: usize = 8;
        // C.3.1 Input Transformation
        let a_blocks = ((a.len() / 16) + 1) * 16;
        let mut _add_auth_data = vec![0; a_blocks];
        let add_auth_data = _add_auth_data.as_mut_slice();
        let m_blocks = ((m.len() / 16) + 1) * 16;
        let mut _plaintext_data = vec![0; m_blocks];
        let plaintext_data = _plaintext_data.as_mut_slice();
        {
            let (mut l, other) = add_auth_data.split_at_mut(2);
            let (_a, _padding) = other.split_at_mut(a.len());
            BigEndian::write_u16(&mut l, a.len() as u16);
            _a.copy_from_slice(&a);
        }
        {
            let (_m, _padding) = plaintext_data.split_at_mut(m.len());
            _m.copy_from_slice(&m);
        }
        let auth_data_len = a_blocks + m_blocks;
        let mut _auth_data = vec![0; auth_data_len];
        let auth_data = _auth_data.as_mut_slice();
        {
            let (_a, _m) = auth_data.split_at_mut(a_blocks);
            _a.copy_from_slice(&add_auth_data);
            _m.copy_from_slice(&plaintext_data);
        }

        let mut block = [0; BLOCK_SIZE];
        // C.3.2 Authentication Transformation
        let flag = make_flag(a.len(), M, LENGHT_FIELD_LENGTH);

        {
            let (f, other) = block.split_at_mut(1);
            let (_nonce, mut length) = other.split_at_mut(nonce.len());
            f[0] = flag;
            _nonce.copy_from_slice(&nonce);
            BigEndian::write_u16(&mut length, m.len() as u16);
        }

        let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ecb).unwrap();
        cipher.set_key(key).unwrap();

        let mut output = [0; BLOCK_SIZE];

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0xF7, 0x74, 0xD1, 0x6E, 0xA7, 0x2D, 0xC0, 0xB3, 0xE4, 0x5E, 0x36, 0xCA, 0x8F, 0x24,
                0x3B, 0x1A
            ]
        );

        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ auth_data[n];
        }

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0x90, 0x2E, 0x72, 0x58, 0xAE, 0x5A, 0x4B, 0x5D, 0x85, 0x7A, 0x25, 0x19, 0xF3, 0xC7,
                0x3A, 0xB3
            ]
        );

        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ auth_data[BLOCK_SIZE + n];
        }

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0x5A, 0xB2, 0xC8, 0x6E, 0x3E, 0xDA, 0x23, 0xD2, 0x7C, 0x49, 0x7D, 0xDF, 0x49, 0xBB,
                0xB4, 0x09
            ]
        );

        for n in 0..BLOCK_SIZE {
            block[n] = output[n] ^ auth_data[(BLOCK_SIZE * 2) + n];
        }

        cipher.encrypt(&block, &mut output).unwrap();

        assert_eq!(
            output,
            [
                0xB9, 0xD7, 0x89, 0x67, 0x04, 0xBC, 0xFA, 0x20, 0xB2, 0x10, 0x36, 0x74, 0x45, 0xF9,
                0x83, 0xD6
            ]
        );

        let mut tag = [0; M];
        tag.copy_from_slice(&output[..M]);

        assert_eq!(tag, [0xB9, 0xD7, 0x89, 0x67, 0x04, 0xBC, 0xFA, 0x20]);

        // C.3.3 Encryption Transformation
        {
            let (flag, other) = block.split_at_mut(1);
            let (_nonce, _counter) = other.split_at_mut(nonce.len());
            flag[0] = make_flag(0, 0, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
            for b in _counter.iter_mut() {
                *b = 0;
            }
        }

        assert_eq!(
            block,
            [
                0x01, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
                0x00, 0x00
            ]
        );

        let mut cipher = Cipher::new(Algorithm::Aes128, Mode::Ctr).unwrap();
        cipher.set_key(key).unwrap();
        cipher.set_ctr(block).unwrap();
        {
            let (flag, other) = block.split_at_mut(1);
            let (_nonce, _counter) = other.split_at_mut(nonce.len());
            flag[0] = make_flag(0, 0, LENGHT_FIELD_LENGTH);
            _nonce.copy_from_slice(&nonce);
            for b in _counter.iter_mut() {
                *b = 0;
            }
        }

        // cipher.encrypt(&block, &mut output).unwrap();

        // assert_eq!(output, [0x12, 0x5C, 0xA9, 0x61, 0xB7, 0x61, 0x6F, 0x02, 0x16, 0x7A, 0x21, 0x66, 0x70, 0x89, 0xF9, 0x07]);
    }
}
