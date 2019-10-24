use core::convert::TryFrom;

use byteorder::{ByteOrder, LittleEndian};

use crate::common::address::{ExtendedAddress, EXTENDED_ADDRESS_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

/// Security Level
///
/// Describes the length of the message integrity check (MIC) and if encryption
/// of message is used.
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
    /// Get the security level from a octet
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

/// Key Identifier
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
    // Get the key identifier from a octet
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
    /// Security level
    pub level: SecurityLevel,
    /// Key identifier
    pub identifier: KeyIdentifier,
    /// The auxilliary header has sender address
    has_source_address: bool,
}

impl SecurityControl {
    // Change the security level to the provided security level
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
    /// Security header flags
    pub control: SecurityControl,
    /// Securit header frame counter
    pub counter: u32,
    /// Source address as extended address
    pub source: Option<ExtendedAddress>,
    /// Sequence number for network keys
    pub sequence: Option<u8>,
}

impl SecurityHeader {
    /// Generate nonce from the header
    pub fn get_nonce(&self, buf: &mut [u8]) -> Result<(), Error> {
        if let Some(source) = self.source {
            source.pack(&mut buf[0..8]).unwrap();
        } else {
            return Err(Error::NoExtendedAddress);
        }
        LittleEndian::write_u32(&mut buf[8..12], self.counter);
        self.control.pack(&mut buf[12..13]).unwrap();
        Ok(())
    }
}

impl Pack<SecurityHeader, Error> for SecurityHeader {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let length = 5
            + if self.source.is_some() { EXTENDED_ADDRESS_SIZE } else { 0 }
            + if self.sequence.is_some() { 1 } else { 0 };
        if data.len() < length {
            return Err(Error::NotEnoughSpace);
        }
        self.control.pack(&mut data[0..=0])?;
        LittleEndian::write_u32(&mut data[1..5], self.counter);
        let mut offset = 5;
        if let Some(source) = self.source {
            source.pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
        }
        if let Some(sequence) = self.sequence {
            data[offset] = sequence;
            offset += 1;
        }
        Ok(offset)
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

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;

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
}
