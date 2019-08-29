use core::convert::TryFrom;
use std::string::String;

use crate::Error;

use byteorder::{ByteOrder, LittleEndian};

extended_enum!(
    /// Attribute data type
    AttributeDataType, u8,
    None => 0x00,
    Data8 => 0x08,
    Data16 => 0x09,
    Data24 => 0x0a,
    Data32 => 0x0b,
    Data40 => 0x0c,
    Data48 => 0x0d,
    Data56 => 0x0e,
    Data64 => 0x0f,
    Boolean => 0x10,
    Bitmap8 => 0x18,
    Bitmap16 => 0x19,
    Bitmap24 => 0x1a,
    Bitmap32 => 0x1b,
    Bitmap40 => 0x1c,
    Bitmap48 => 0x1d,
    Bitmap56 => 0x1e,
    Bitmap64 => 0x1f,
    Unsigned8 => 0x20,
    Unsigned16 => 0x21,
    Unsigned24 => 0x22,
    Unsigned32 => 0x23,
    Unsigned40 => 0x24,
    Unsigned48 => 0x25,
    Unsigned56 => 0x26,
    Unsigned64 => 0x27,
    Signed8 => 0x28,
    Signed16 => 0x29,
    Signed24 => 0x2a,
    Signed32 => 0x2b,
    Signed40 => 0x2c,
    Signed48 => 0x2d,
    Signed56 => 0x2e,
    Signed64 => 0x2f,
    Enumeration8 => 0x30,
    Enumeration16 => 0x31,
    FloatingPoint16 => 0x38,
    FloatingPoint32 => 0x39,
    FloatingPoint64 => 0x3a,
    OctetString => 0x41,
    CharacterString => 0x42,
    LongOctetString => 0x43,
    LongCharacterString => 0x44,
    Array => 0x48,
    Structure => 0x4c,
    Set => 0x50,
    Bag => 0x51,
    TimeOfDay => 0xe0,
    Date => 0xe1,
    UtcTime => 0xe2,
    ClusterIdentifier => 0xe8,
    AttributeIdentifier => 0xe9,
    BuildingAutomationControlNetworkObjectIdentifier => 0xea,
    IeeeAddress => 0xf0,
    Key128 => 0xf1,
    Unknown => 0xff,
);

impl AttributeDataType {
    pub fn num_octets(&self) -> Option<usize> {
        match *self {
            AttributeDataType::None | AttributeDataType::Unknown => Some(0),
            AttributeDataType::Data8
            | AttributeDataType::Boolean
            | AttributeDataType::Bitmap8
            | AttributeDataType::Unsigned8
            | AttributeDataType::Signed8
            | AttributeDataType::Enumeration8 => Some(1),
            AttributeDataType::Data16
            | AttributeDataType::Bitmap16
            | AttributeDataType::Unsigned16
            | AttributeDataType::Signed16
            | AttributeDataType::Enumeration16
            | AttributeDataType::FloatingPoint16
            | AttributeDataType::ClusterIdentifier
            | AttributeDataType::AttributeIdentifier => Some(2),
            AttributeDataType::Data24
            | AttributeDataType::Bitmap24
            | AttributeDataType::Unsigned24
            | AttributeDataType::Signed24 => Some(3),
            AttributeDataType::Data32
            | AttributeDataType::Bitmap32
            | AttributeDataType::Unsigned32
            | AttributeDataType::Signed32
            | AttributeDataType::FloatingPoint32
            | AttributeDataType::TimeOfDay
            | AttributeDataType::Date
            | AttributeDataType::UtcTime
            | AttributeDataType::BuildingAutomationControlNetworkObjectIdentifier => Some(4),
            AttributeDataType::Data40
            | AttributeDataType::Bitmap40
            | AttributeDataType::Unsigned40
            | AttributeDataType::Signed40 => Some(5),
            AttributeDataType::Data48
            | AttributeDataType::Bitmap48
            | AttributeDataType::Unsigned48
            | AttributeDataType::Signed48 => Some(6),
            AttributeDataType::Data56
            | AttributeDataType::Bitmap56
            | AttributeDataType::Unsigned56
            | AttributeDataType::Signed56 => Some(7),
            AttributeDataType::Data64
            | AttributeDataType::Bitmap64
            | AttributeDataType::Unsigned64
            | AttributeDataType::Signed64
            | AttributeDataType::FloatingPoint64
            | AttributeDataType::IeeeAddress => Some(8),
            AttributeDataType::Key128 => Some(16),
            AttributeDataType::OctetString
            | AttributeDataType::CharacterString
            | AttributeDataType::LongOctetString
            | AttributeDataType::LongCharacterString
            | AttributeDataType::Array
            | AttributeDataType::Structure
            | AttributeDataType::Set
            | AttributeDataType::Bag => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum AttributeValue {
    None,
    Data8(u8),
    Data16(u16),
    Data24(u32),
    Data32(u32),
    Data64(u64),
    Boolean(Option<bool>),
    Bitmap8(u8),
    Bitmap16(u16),
    Bitmap24(u32),
    Bitmap32(u32),
    Bitmap64(u64),
    Unsigned8(Option<u8>),
    Unsigned16(Option<u16>),
    Unsigned24(Option<u32>),
    Unsigned32(Option<u32>),
    Unsigned64(Option<u64>),
    Signed8(Option<i8>),
    Signed16(Option<i16>),
    Signed24(Option<i32>),
    Signed32(Option<i32>),
    Signed64(Option<i64>),
    Enumeration8(Option<u8>),
    Enumeration16(Option<u16>),
    FloatingPoint32(f32),
    FloatingPoint64(f64),
    OctetString(Option<Vec<u8>>),
    CharacterString(Option<String>),
    LongOctetString(Option<Vec<u8>>),
    LongCharacterString(Option<String>),
}

impl AttributeValue {
    pub fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
    }

    pub fn unpack(data: &[u8], data_type: AttributeDataType) -> Result<(Self, usize), Error> {
        if let Some(num_octets) = data_type.num_octets() {
            if data.len() < num_octets {
                return Err(Error::WrongNumberOfBytes);
            }
        }
        match data_type {
            AttributeDataType::None => Ok((AttributeValue::None, 0)),
            AttributeDataType::Data8 => Ok((AttributeValue::Data8(data[0]), 1)),
            AttributeDataType::Data16 => {
                let value = LittleEndian::read_u16(&data[0..2]);
                Ok((AttributeValue::Data16(value), 2))
            }
            AttributeDataType::Data24 => {
                let value = LittleEndian::read_u24(&data[0..3]);
                Ok((AttributeValue::Data24(value), 3))
            }
            AttributeDataType::Data32 => {
                let value = LittleEndian::read_u32(&data[0..4]);
                Ok((AttributeValue::Data32(value), 4))
            }
            AttributeDataType::Data64 => {
                let value = LittleEndian::read_u64(&data[0..8]);
                Ok((AttributeValue::Data64(value), 8))
            }
            AttributeDataType::Boolean => {
                let value = match data[0] {
                    0x00 => Some(false),
                    0x01 => Some(true),
                    0xff => None,
                    _ => return Err(Error::InvalidValue),
                };
                Ok((AttributeValue::Boolean(value), 1))
            }
            AttributeDataType::Bitmap8 => Ok((AttributeValue::Bitmap8(data[0]), 1)),
            AttributeDataType::Bitmap16 => {
                let value = LittleEndian::read_u16(&data[0..2]);
                Ok((AttributeValue::Bitmap16(value), 2))
            }
            AttributeDataType::Bitmap24 => {
                let value = LittleEndian::read_u24(&data[0..3]);
                Ok((AttributeValue::Bitmap24(value), 3))
            }
            AttributeDataType::Bitmap32 => {
                let value = LittleEndian::read_u32(&data[0..4]);
                Ok((AttributeValue::Bitmap32(value), 4))
            }
            AttributeDataType::Bitmap64 => {
                let value = LittleEndian::read_u64(&data[0..8]);
                Ok((AttributeValue::Bitmap64(value), 8))
            }
            AttributeDataType::Unsigned8 => {
                let value = match data[0] {
                    0xff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Unsigned8(value), 1))
            }
            AttributeDataType::Unsigned16 => {
                let value = match LittleEndian::read_u16(&data[0..2]) {
                    0xffff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Unsigned16(value), 2))
            }
            AttributeDataType::Unsigned24 => {
                let value = match LittleEndian::read_u24(&data[0..3]) {
                    0x00ff_ffff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Unsigned24(value), 3))
            }
            AttributeDataType::Unsigned32 => {
                let value = match LittleEndian::read_u32(&data[0..4]) {
                    0xffff_ffff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Unsigned32(value), 4))
            }
            AttributeDataType::Unsigned64 => {
                let value = match LittleEndian::read_u64(&data[0..8]) {
                    0xffff_ffff_ffff_ffff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Unsigned64(value), 8))
            }
            AttributeDataType::Signed8 => {
                let value = match data[0] as i8 {
                    -128 => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Signed8(value), 1))
            }
            AttributeDataType::Signed16 => {
                let value = match LittleEndian::read_i16(&data[0..2]) {
                    -32_768 => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Signed16(value), 2))
            }
            AttributeDataType::Signed24 => {
                let value = match LittleEndian::read_i24(&data[0..3]) {
                    0x0080_0000 => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Signed24(value), 3))
            }
            AttributeDataType::Signed32 => {
                let value = match LittleEndian::read_i32(&data[0..4]) {
                    -2_147_483_648 => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Signed32(value), 4))
            }
            AttributeDataType::Signed64 => {
                let value = match LittleEndian::read_i64(&data[0..8]) {
                    -9_223_372_036_854_775_808 => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Signed64(value), 8))
            }
            AttributeDataType::Enumeration8 => {
                let value = match data[0] {
                    0xff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Enumeration8(value), 1))
            }
            AttributeDataType::Enumeration16 => {
                let value = match LittleEndian::read_u16(&data[0..2]) {
                    0xffff => None,
                    v => Some(v),
                };
                Ok((AttributeValue::Enumeration16(value), 2))
            }
            AttributeDataType::FloatingPoint32 => Ok((
                AttributeValue::FloatingPoint32(LittleEndian::read_f32(&data[0..4])),
                4,
            )),
            AttributeDataType::FloatingPoint64 => Ok((
                AttributeValue::FloatingPoint64(LittleEndian::read_f64(&data[0..8])),
                8,
            )),
            AttributeDataType::OctetString => {
                if data.is_empty() {
                    return Err(Error::WrongNumberOfBytes);
                }
                let length = match data[0] {
                    0xff => None,
                    v => Some(v as usize),
                };
                let (value, used) = if let Some(length) = length {
                    if data.len() < length + 1 {
                        return Err(Error::WrongNumberOfBytes);
                    }
                    (Some(data[1..=length].to_vec()), length + 1)
                } else {
                    (None, 1)
                };
                Ok((AttributeValue::OctetString(value), used))
            }
            AttributeDataType::CharacterString => {
                if data.is_empty() {
                    return Err(Error::WrongNumberOfBytes);
                }
                let length = match data[0] {
                    0xff => None,
                    v => Some(v as usize),
                };
                let (value, used) = if let Some(length) = length {
                    if data.len() < length + 1 {
                        return Err(Error::WrongNumberOfBytes);
                    }
                    match String::from_utf8(data[1..=length].to_vec()) {
                        Ok(s) => (Some(s), length + 1),
                        Err(_) => (None, length + 1),
                    }
                } else {
                    (None, 1)
                };
                Ok((AttributeValue::CharacterString(value), used))
            }
            AttributeDataType::LongOctetString => {
                if data.len() < 2 {
                    return Err(Error::WrongNumberOfBytes);
                }
                let length = match LittleEndian::read_u16(&data[0..2]) {
                    0xffff => None,
                    v => Some(v as usize),
                };
                let (value, used) = if let Some(length) = length {
                    if data.len() < length + 2 {
                        return Err(Error::WrongNumberOfBytes);
                    }
                    (Some(data[2..length + 2].to_vec()), length + 2)
                } else {
                    (None, 2)
                };
                Ok((AttributeValue::LongOctetString(value), used))
            }
            AttributeDataType::LongCharacterString => {
                if data.len() < 2 {
                    return Err(Error::WrongNumberOfBytes);
                }
                let length = match LittleEndian::read_u16(&data[0..2]) {
                    0xffff => None,
                    v => Some(v as usize),
                };
                let (value, used) = if let Some(length) = length {
                    if data.len() < length + 1 {
                        return Err(Error::WrongNumberOfBytes);
                    }
                    match String::from_utf8(data[1..=length].to_vec()) {
                        Ok(s) => (Some(s), length + 1),
                        Err(_) => (None, length + 1),
                    }
                } else {
                    (None, 1)
                };
                Ok((AttributeValue::CharacterString(value), used))
            }
            _ => Err(Error::UnsupportedAttributeValue),
        }
    }

    pub fn data_type(&self) -> AttributeDataType {
        match self {
            AttributeValue::None => AttributeDataType::None,
            AttributeValue::Data8(_) => AttributeDataType::Data8,
            AttributeValue::Data16(_) => AttributeDataType::Data16,
            AttributeValue::Data24(_) => AttributeDataType::Data24,
            AttributeValue::Data32(_) => AttributeDataType::Data32,
            AttributeValue::Data64(_) => AttributeDataType::Data64,
            AttributeValue::Boolean(_) => AttributeDataType::Boolean,
            AttributeValue::Bitmap8(_) => AttributeDataType::Bitmap8,
            AttributeValue::Bitmap16(_) => AttributeDataType::Bitmap16,
            AttributeValue::Bitmap24(_) => AttributeDataType::Bitmap24,
            AttributeValue::Bitmap32(_) => AttributeDataType::Bitmap32,
            AttributeValue::Bitmap64(_) => AttributeDataType::Bitmap64,
            AttributeValue::Unsigned8(_) => AttributeDataType::Unsigned8,
            AttributeValue::Unsigned16(_) => AttributeDataType::Unsigned16,
            AttributeValue::Unsigned24(_) => AttributeDataType::Unsigned24,
            AttributeValue::Unsigned32(_) => AttributeDataType::Unsigned32,
            AttributeValue::Unsigned64(_) => AttributeDataType::Unsigned64,
            AttributeValue::Signed8(_) => AttributeDataType::Signed8,
            AttributeValue::Signed16(_) => AttributeDataType::Signed16,
            AttributeValue::Signed24(_) => AttributeDataType::Signed24,
            AttributeValue::Signed32(_) => AttributeDataType::Signed32,
            AttributeValue::Signed64(_) => AttributeDataType::Signed64,
            AttributeValue::Enumeration8(_) => AttributeDataType::Enumeration8,
            AttributeValue::Enumeration16(_) => AttributeDataType::Enumeration16,
            AttributeValue::FloatingPoint32(_) => AttributeDataType::FloatingPoint32,
            AttributeValue::FloatingPoint64(_) => AttributeDataType::FloatingPoint64,
            AttributeValue::OctetString(_) => AttributeDataType::OctetString,
            AttributeValue::CharacterString(_) => AttributeDataType::CharacterString,
            AttributeValue::LongOctetString(_) => AttributeDataType::LongOctetString,
            AttributeValue::LongCharacterString(_) => AttributeDataType::LongCharacterString,
        }
    }
}
