use core::convert::TryFrom;

use crate::pack::Pack;
use crate::Error;

use byteorder::{ByteOrder, LittleEndian};

use crate::common::types::{CharacterString, OctetString};

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
    pub fn num_octets(self) -> Option<usize> {
        match self {
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
    Data40([u8; 5]),
    Data48([u8; 6]),
    Data56([u8; 7]),
    Data64(u64),
    Boolean(u8),
    Bitmap8(u8),
    Bitmap16(u16),
    Bitmap24(u32),
    Bitmap32(u32),
    Bitmap40([u8; 5]),
    Bitmap48([u8; 6]),
    Bitmap56([u8; 7]),
    Bitmap64(u64),
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned24(u32),
    Unsigned32(u32),
    Unsigned40([u8; 5]),
    Unsigned48([u8; 6]),
    Unsigned56([u8; 7]),
    Unsigned64(u64),
    Signed8(i8),
    Signed16(i16),
    Signed24(i32),
    Signed32(i32),
    Signed40([u8; 5]),
    Signed48([u8; 6]),
    Signed56([u8; 7]),
    Signed64(i64),
    Enumeration8(u8),
    Enumeration16(u16),
    FloatingPoint32(f32),
    FloatingPoint64(f64),
    OctetString(Option<OctetString>),
    CharacterString(Option<CharacterString>),
    /*
        LongOctetString(Option<Vec<u8>>),
        LongCharacterString(Option<String>),
    */
    TimeOfDay(u32),
    Date(u32),
    UtcTime(u32),
    ClusterIdentifier(u16),
    AttributeIdentifier(u16),
    IeeeAddress(u64),
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
            AttributeDataType::Data40 => {
                let mut value = [0; 5];
                value.clone_from_slice(&data[0..5]);
                Ok((AttributeValue::Data40(value), 5))
            }
            AttributeDataType::Data48 => {
                let mut value = [0; 6];
                value.clone_from_slice(&data[0..6]);
                Ok((AttributeValue::Data48(value), 6))
            }
            AttributeDataType::Data56 => {
                let mut value = [0; 7];
                value.clone_from_slice(&data[0..7]);
                Ok((AttributeValue::Data56(value), 7))
            }
            AttributeDataType::Data64 => {
                let value = LittleEndian::read_u64(&data[0..8]);
                Ok((AttributeValue::Data64(value), 8))
            }
            AttributeDataType::Boolean => {
                let value = match data[0] {
                    0x00 | 0x01 | 0xff => data[0],
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
            AttributeDataType::Bitmap40 => {
                let mut value = [0; 5];
                value.clone_from_slice(&data[0..5]);
                Ok((AttributeValue::Bitmap40(value), 5))
            }
            AttributeDataType::Bitmap48 => {
                let mut value = [0; 6];
                value.clone_from_slice(&data[0..6]);
                Ok((AttributeValue::Bitmap48(value), 6))
            }
            AttributeDataType::Bitmap56 => {
                let mut value = [0; 7];
                value.clone_from_slice(&data[0..7]);
                Ok((AttributeValue::Bitmap56(value), 7))
            }
            AttributeDataType::Bitmap64 => {
                let value = LittleEndian::read_u64(&data[0..8]);
                Ok((AttributeValue::Bitmap64(value), 8))
            }
            AttributeDataType::Unsigned8 => Ok((AttributeValue::Unsigned8(data[0]), 1)),
            AttributeDataType::Unsigned16 => {
                let value = LittleEndian::read_u16(&data[0..2]);
                Ok((AttributeValue::Unsigned16(value), 2))
            }
            AttributeDataType::Unsigned24 => {
                let value = LittleEndian::read_u24(&data[0..3]);
                Ok((AttributeValue::Unsigned24(value), 3))
            }
            AttributeDataType::Unsigned32 => {
                let value = LittleEndian::read_u32(&data[0..4]);
                Ok((AttributeValue::Unsigned32(value), 4))
            }
            AttributeDataType::Unsigned40 => {
                let mut value = [0; 5];
                value.clone_from_slice(&data[0..5]);
                Ok((AttributeValue::Unsigned40(value), 5))
            }
            AttributeDataType::Unsigned48 => {
                let mut value = [0; 6];
                value.clone_from_slice(&data[0..6]);
                Ok((AttributeValue::Unsigned48(value), 6))
            }
            AttributeDataType::Unsigned56 => {
                let mut value = [0; 7];
                value.clone_from_slice(&data[0..7]);
                Ok((AttributeValue::Unsigned56(value), 7))
            }
            AttributeDataType::Unsigned64 => {
                let value = LittleEndian::read_u64(&data[0..8]);
                Ok((AttributeValue::Unsigned64(value), 8))
            }
            AttributeDataType::Signed8 => Ok((AttributeValue::Signed8(data[0] as i8), 1)),
            AttributeDataType::Signed16 => {
                let value = LittleEndian::read_i16(&data[0..2]);
                Ok((AttributeValue::Signed16(value), 2))
            }
            AttributeDataType::Signed24 => {
                let value = LittleEndian::read_i24(&data[0..3]);
                Ok((AttributeValue::Signed24(value), 3))
            }
            AttributeDataType::Signed32 => {
                let value = LittleEndian::read_i32(&data[0..4]);
                Ok((AttributeValue::Signed32(value), 4))
            }
            AttributeDataType::Signed40 => {
                let mut value = [0; 5];
                value.clone_from_slice(&data[0..5]);
                Ok((AttributeValue::Signed40(value), 5))
            }
            AttributeDataType::Signed48 => {
                let mut value = [0; 6];
                value.clone_from_slice(&data[0..6]);
                Ok((AttributeValue::Signed48(value), 6))
            }
            AttributeDataType::Signed56 => {
                let mut value = [0; 7];
                value.clone_from_slice(&data[0..7]);
                Ok((AttributeValue::Signed56(value), 7))
            }
            AttributeDataType::Signed64 => {
                let value = LittleEndian::read_i64(&data[0..8]);
                Ok((AttributeValue::Signed64(value), 8))
            }
            AttributeDataType::Enumeration8 => Ok((AttributeValue::Enumeration8(data[0]), 1)),
            AttributeDataType::Enumeration16 => {
                let value = LittleEndian::read_u16(&data[0..2]);
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
                let (value, used) = if length.is_some() {
                    let (value, used) = OctetString::unpack(&data)?;
                    (Some(value), used)
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
                let (value, used) = if length.is_some() {
                    let (value, used) = CharacterString::unpack(&data)?;
                    (Some(value), used)
                } else {
                    (None, 1)
                };
                Ok((AttributeValue::CharacterString(value), used))
            }
            /*
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
            */
            AttributeDataType::TimeOfDay => {
                let value = LittleEndian::read_u32(&data[0..4]);
                Ok((AttributeValue::TimeOfDay(value), 4))
            }
            AttributeDataType::Date => {
                let value = LittleEndian::read_u32(&data[0..4]);
                Ok((AttributeValue::Date(value), 4))
            }
            AttributeDataType::UtcTime => {
                let value = LittleEndian::read_u32(&data[0..4]);
                Ok((AttributeValue::UtcTime(value), 4))
            }
            AttributeDataType::ClusterIdentifier => {
                let value = LittleEndian::read_u16(&data[0..2]);
                Ok((AttributeValue::ClusterIdentifier(value), 2))
            }
            AttributeDataType::AttributeIdentifier => {
                let value = LittleEndian::read_u16(&data[0..2]);
                Ok((AttributeValue::ClusterIdentifier(value), 2))
            }
            AttributeDataType::IeeeAddress => {
                let value = LittleEndian::read_u64(&data[0..8]);
                Ok((AttributeValue::IeeeAddress(value), 8))
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
            AttributeValue::Data40(_) => AttributeDataType::Data40,
            AttributeValue::Data48(_) => AttributeDataType::Data48,
            AttributeValue::Data56(_) => AttributeDataType::Data56,
            AttributeValue::Data64(_) => AttributeDataType::Data64,
            AttributeValue::Boolean(_) => AttributeDataType::Boolean,
            AttributeValue::Bitmap8(_) => AttributeDataType::Bitmap8,
            AttributeValue::Bitmap16(_) => AttributeDataType::Bitmap16,
            AttributeValue::Bitmap24(_) => AttributeDataType::Bitmap24,
            AttributeValue::Bitmap32(_) => AttributeDataType::Bitmap32,
            AttributeValue::Bitmap40(_) => AttributeDataType::Bitmap40,
            AttributeValue::Bitmap48(_) => AttributeDataType::Bitmap48,
            AttributeValue::Bitmap56(_) => AttributeDataType::Bitmap56,
            AttributeValue::Bitmap64(_) => AttributeDataType::Bitmap64,
            AttributeValue::Unsigned8(_) => AttributeDataType::Unsigned8,
            AttributeValue::Unsigned16(_) => AttributeDataType::Unsigned16,
            AttributeValue::Unsigned24(_) => AttributeDataType::Unsigned24,
            AttributeValue::Unsigned32(_) => AttributeDataType::Unsigned32,
            AttributeValue::Unsigned40(_) => AttributeDataType::Unsigned40,
            AttributeValue::Unsigned48(_) => AttributeDataType::Unsigned48,
            AttributeValue::Unsigned56(_) => AttributeDataType::Unsigned56,
            AttributeValue::Unsigned64(_) => AttributeDataType::Unsigned64,
            AttributeValue::Signed8(_) => AttributeDataType::Signed8,
            AttributeValue::Signed16(_) => AttributeDataType::Signed16,
            AttributeValue::Signed24(_) => AttributeDataType::Signed24,
            AttributeValue::Signed32(_) => AttributeDataType::Signed32,
            AttributeValue::Signed40(_) => AttributeDataType::Signed40,
            AttributeValue::Signed48(_) => AttributeDataType::Signed48,
            AttributeValue::Signed56(_) => AttributeDataType::Signed56,
            AttributeValue::Signed64(_) => AttributeDataType::Signed64,
            AttributeValue::Enumeration8(_) => AttributeDataType::Enumeration8,
            AttributeValue::Enumeration16(_) => AttributeDataType::Enumeration16,
            AttributeValue::FloatingPoint32(_) => AttributeDataType::FloatingPoint32,
            AttributeValue::FloatingPoint64(_) => AttributeDataType::FloatingPoint64,
            AttributeValue::OctetString(_) => AttributeDataType::OctetString,
            AttributeValue::CharacterString(_) => AttributeDataType::CharacterString,
            /*
                        AttributeValue::LongOctetString(_) => AttributeDataType::LongOctetString,
                        AttributeValue::LongCharacterString(_) => AttributeDataType::LongCharacterString,
            */
            AttributeValue::TimeOfDay(_) => AttributeDataType::TimeOfDay,
            AttributeValue::Date(_) => AttributeDataType::Date,
            AttributeValue::UtcTime(_) => AttributeDataType::UtcTime,
            AttributeValue::ClusterIdentifier(_) => AttributeDataType::ClusterIdentifier,
            AttributeValue::AttributeIdentifier(_) => AttributeDataType::AttributeIdentifier,
            AttributeValue::IeeeAddress(_) => AttributeDataType::IeeeAddress,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            AttributeValue::None
            | AttributeValue::Data8(_)
            | AttributeValue::Data16(_)
            | AttributeValue::Data24(_)
            | AttributeValue::Data32(_)
            | AttributeValue::Data40(_)
            | AttributeValue::Data48(_)
            | AttributeValue::Data56(_)
            | AttributeValue::Data64(_)
            | AttributeValue::Bitmap8(_)
            | AttributeValue::Bitmap16(_)
            | AttributeValue::Bitmap24(_)
            | AttributeValue::Bitmap32(_)
            | AttributeValue::Bitmap40(_)
            | AttributeValue::Bitmap48(_)
            | AttributeValue::Bitmap56(_)
            | AttributeValue::Bitmap64(_) => true,
            AttributeValue::Boolean(v) => *v == 0x00 || *v == 0x01,
            AttributeValue::Unsigned8(v) | AttributeValue::Enumeration8(v) => *v != u8::max_value(),
            AttributeValue::Unsigned16(v)
            | AttributeValue::Enumeration16(v)
            | AttributeValue::ClusterIdentifier(v)
            | AttributeValue::AttributeIdentifier(v) => *v != u16::max_value(),
            AttributeValue::Unsigned24(v) => *v < 0x00ff_ffff,
            AttributeValue::Unsigned32(v)
            | AttributeValue::TimeOfDay(v)
            | AttributeValue::Date(v)
            | AttributeValue::UtcTime(v) => *v != u32::max_value(),
            AttributeValue::Unsigned40(v) => *v != [0xff; 5],
            AttributeValue::Unsigned48(v) => *v != [0xff; 6],
            AttributeValue::Unsigned56(v) => *v != [0xff; 7],
            AttributeValue::Unsigned64(v) | AttributeValue::IeeeAddress(v) => {
                *v != u64::max_value()
            }
            AttributeValue::Signed8(v) => *v != i8::min_value(),
            AttributeValue::Signed16(v) => *v != i16::min_value(),
            AttributeValue::Signed24(v) => *v > -8_388_608 && *v < 8_388_607,
            AttributeValue::Signed32(v) => *v != i32::min_value(),
            AttributeValue::Signed40(v) => *v != [0x80, 0x00, 0x00, 0x00, 0x00],
            AttributeValue::Signed48(v) => *v != [0x80, 0x00, 0x00, 0x00, 0x00, 0x00],
            AttributeValue::Signed56(v) => *v != [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            AttributeValue::Signed64(v) => *v != i64::min_value(),
            AttributeValue::FloatingPoint32(v) => !v.is_normal(),
            AttributeValue::FloatingPoint64(v) => !v.is_normal(),
            AttributeValue::OctetString(v) => v.is_some(),
            AttributeValue::CharacterString(v) => v.is_some(),
            /*
                        AttributeValue::LongOctetString(v) => v.is_some(),
                        AttributeValue::LongCharacterString(v) => v.is_some(),
            */
        }
    }
}

#[cfg(feature = "std")]
const STRING_INVALID: &str = "Invalid";

#[cfg(feature = "std")]
impl std::fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.is_valid() {
            write!(f, "{}", STRING_INVALID)
        } else {
            match self {
                AttributeValue::None => write!(f, "None"),
                AttributeValue::Data8(v) | AttributeValue::Bitmap8(v) => write!(f, "{}", v),
                AttributeValue::Data16(v) | AttributeValue::Bitmap16(v) => write!(f, "{}", v),
                AttributeValue::Data24(v) | AttributeValue::Bitmap24(v) => write!(f, "{}", v),
                AttributeValue::Data32(v) | AttributeValue::Bitmap32(v) => write!(f, "{}", v),
                AttributeValue::Data40(v)
                | AttributeValue::Bitmap40(v)
                | AttributeValue::Unsigned40(v)
                | AttributeValue::Signed40(v) => {
                    let hex: String = v.iter().map(|i| format!("{:02x}", i)).collect();
                    write!(f, "{}", hex)
                }
                AttributeValue::Data48(v)
                | AttributeValue::Bitmap48(v)
                | AttributeValue::Unsigned48(v)
                | AttributeValue::Signed48(v) => {
                    let hex: String = v.iter().map(|i| format!("{:02x}", i)).collect();
                    write!(f, "{}", hex)
                }
                AttributeValue::Data56(v)
                | AttributeValue::Bitmap56(v)
                | AttributeValue::Unsigned56(v)
                | AttributeValue::Signed56(v) => {
                    let hex: String = v.iter().map(|i| format!("{:02x}", i)).collect();
                    write!(f, "{}", hex)
                }
                AttributeValue::Data64(v) | AttributeValue::Bitmap64(v) => write!(f, "{}", v),
                AttributeValue::Boolean(v) => write!(f, "{}", *v == 0x01),
                AttributeValue::Unsigned8(v) | AttributeValue::Enumeration8(v) => {
                    write!(f, "{}", v)
                }
                AttributeValue::Unsigned16(v) | AttributeValue::Enumeration16(v) => {
                    write!(f, "{}", v)
                }
                AttributeValue::Unsigned24(v)
                | AttributeValue::Unsigned32(v)
                | AttributeValue::UtcTime(v) => write!(f, "{}", v),
                AttributeValue::Unsigned64(v) => write!(f, "{}", v),
                AttributeValue::Signed8(v) => write!(f, "{}", v),
                AttributeValue::Signed16(v) => write!(f, "{}", v),
                AttributeValue::Signed24(v) | AttributeValue::Signed32(v) => write!(f, "{}", v),
                AttributeValue::Signed64(v) => write!(f, "{}", v),
                AttributeValue::FloatingPoint32(v) => write!(f, "{}", v),
                AttributeValue::FloatingPoint64(v) => write!(f, "{}", v),
                AttributeValue::OctetString(v) => {
                    if let Some(v) = v {
                        let hex: String = v.iter().map(|i| format!("{:02x}", i)).collect();
                        write!(f, "{}", hex)
                    } else {
                        write!(f, "{}", STRING_INVALID)
                    }
                }
                AttributeValue::CharacterString(v) => {
                    if let Some(v) = v {
                        write!(f, "{}", v)
                    } else {
                        write!(f, "{}", STRING_INVALID)
                    }
                }
                AttributeValue::TimeOfDay(v) => write!(
                    f,
                    "{}:{}:{}.{}",
                    v & 0b0000_0000_0000_1111,
                    (v & 0b0000_0000_1111_0000) >> 8,
                    (v & 0b0000_1111_0000_0000) >> 16,
                    (v & 0b1111_0000_0000_0000) >> 24
                ),
                AttributeValue::Date(v) => write!(
                    f,
                    "{}-{}-{}",
                    (v & 0b0000_0000_0000_1111) + 1900,
                    (v & 0b0000_0000_1111_0000) >> 8,
                    (v & 0b0000_1111_0000_0000) >> 16
                ),
                AttributeValue::ClusterIdentifier(v) | AttributeValue::AttributeIdentifier(v) => {
                    write!(f, "{:04x}", v)
                }
                AttributeValue::IeeeAddress(v) => write!(f, "{:08x}", v),
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn attribute_value_none() {
        let value = AttributeValue::None;
        assert_eq!(value.data_type(), AttributeDataType::None);
        assert_eq!(format!("{}", value), "None");
    }

    #[test]
    fn attribute_value_data8() {
        let value = AttributeValue::Data8(0);
        assert_eq!(value.data_type(), AttributeDataType::Data8);
        assert_eq!(format!("{}", value), "0");
        let value = AttributeValue::Data8(127);
        assert_eq!(format!("{}", value), "127");
        let value = AttributeValue::Data8(255);
        assert_eq!(format!("{}", value), "255");
    }

    #[test]
    fn attribute_value_data16() {
        let value = AttributeValue::Data16(0);
        assert_eq!(value.data_type(), AttributeDataType::Data16);
        assert_eq!(format!("{}", value), "0");
        let value = AttributeValue::Data16(16384);
        assert_eq!(format!("{}", value), "16384");
        let value = AttributeValue::Data16(65535);
        assert_eq!(format!("{}", value), "65535");
    }

    #[test]
    fn attribute_value_unsigned8() {
        for v in u8::min_value()..u8::max_value() {
            let value = AttributeValue::Unsigned8(v);
            assert_eq!(value.data_type(), AttributeDataType::Unsigned8);
            if v == u8::max_value() {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_unsigned16() {
        for v in u16::min_value()..u16::max_value() {
            let value = AttributeValue::Unsigned16(v);
            assert_eq!(value.data_type(), AttributeDataType::Unsigned16);
            if v == u16::max_value() {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_unsigned24() {
        for v in [
            u32::min_value(),
            u32::max_value() / 2,
            0x00ff_ffff,
            u32::max_value(),
        ]
        .iter()
        {
            let value = AttributeValue::Unsigned24(*v);
            assert_eq!(value.data_type(), AttributeDataType::Unsigned24);
            if *v >= 0x00ff_ffff {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_unsigned32() {
        for v in [u32::min_value(), u32::max_value() / 2, u32::max_value()].iter() {
            let value = AttributeValue::Unsigned32(*v);
            assert_eq!(value.data_type(), AttributeDataType::Unsigned32);
            if *v == u32::max_value() {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_signed8() {
        for v in i8::min_value()..i8::max_value() {
            let value = AttributeValue::Signed8(v);
            assert_eq!(value.data_type(), AttributeDataType::Signed8);
            if v == i8::min_value() {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_signed16() {
        for v in i16::min_value()..i16::max_value() {
            let value = AttributeValue::Signed16(v);
            assert_eq!(value.data_type(), AttributeDataType::Signed16);
            if v == i16::min_value() {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_signed24() {
        for v in [
            i32::min_value(),
            i32::max_value() / 2,
            0x00ff_ffff,
            i32::max_value(),
        ]
        .iter()
        {
            let value = AttributeValue::Signed24(*v);
            assert_eq!(value.data_type(), AttributeDataType::Signed24);
            if *v < -8_388_608 || *v > 8_388_607 {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_signed32() {
        for v in [i32::min_value(), i32::max_value() / 2, i32::max_value()].iter() {
            let value = AttributeValue::Signed32(*v);
            assert_eq!(value.data_type(), AttributeDataType::Signed32);
            if *v == i32::min_value() {
                assert_eq!(value.is_valid(), false);
                assert_eq!(format!("{}", value), "Invalid");
            } else {
                assert_eq!(value.is_valid(), true);
                assert_eq!(format!("{}", value), format!("{}", v));
            }
        }
    }

    #[test]
    fn attribute_value_bool() {
        for v in [0u8, 1u8, 2u8, 255u8].iter() {
            let value = AttributeValue::Boolean(*v);
            assert_eq!(value.data_type(), AttributeDataType::Boolean);
            match *v {
                0 => {
                    assert_eq!(value.is_valid(), true);
                    assert_eq!(format!("{}", value), "false");
                }
                1 => {
                    assert_eq!(value.is_valid(), true);
                    assert_eq!(format!("{}", value), "true");
                }
                _ => {
                    assert_eq!(value.is_valid(), false);
                    assert_eq!(format!("{}", value), "Invalid");
                }
            }
        }
    }

}
