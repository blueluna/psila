use core::default::Default;

use crate::pack::PackFixed;
use crate::Error;

use byteorder::{ByteOrder, LittleEndian};

/// Network address size
pub const SHORT_ADDRESS_SIZE: usize = 2;

/// 16-bit short address
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ShortAddress(u16);

impl PackFixed<ShortAddress, Error> for ShortAddress {
    fn pack(&self, mut data: &mut [u8]) -> Result<(), Error> {
        if data.len() == SHORT_ADDRESS_SIZE {
            LittleEndian::write_u16(&mut data, self.0);
            Ok(())
        } else {
            Err(Error::NotEnoughSpace)
        }
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() == SHORT_ADDRESS_SIZE {
            let address = LittleEndian::read_u16(&data);
            Ok(ShortAddress(address))
        } else {
            Err(Error::WrongNumberOfBytes)
        }
    }
}

impl PartialEq<[u8; SHORT_ADDRESS_SIZE]> for ShortAddress {
    fn eq(&self, other: &[u8; SHORT_ADDRESS_SIZE]) -> bool {
        let other = LittleEndian::read_u16(&other[..]);
        self.0 == other
    }
}

impl From<u16> for ShortAddress {
    fn from(value: u16) -> Self {
        ShortAddress(value)
    }
}

impl From<ShortAddress> for u16 {
    fn from(value: ShortAddress) -> Self {
        value.0
    }
}

impl PartialEq<u16> for ShortAddress {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl Default for ShortAddress {
    fn default() -> Self {
        Self(0xffffu16)
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for ShortAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

/// 16-bit network address
pub type NetworkAddress = ShortAddress;
/// 16-bit personal area network (PAN) identifier
pub type PanIdentifier = ShortAddress;
/// 16-bit group identifier
pub type GroupIdentifier = ShortAddress;

/// Extended IEEE address size
pub const EXTENDED_ADDRESS_SIZE: usize = 8;

/// 64-bit extended IEEE address
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ExtendedAddress(u64);

impl PackFixed<ExtendedAddress, Error> for ExtendedAddress {
    fn pack(&self, mut data: &mut [u8]) -> Result<(), Error> {
        if data.len() == EXTENDED_ADDRESS_SIZE {
            LittleEndian::write_u64(&mut data, self.0);
            Ok(())
        } else {
            Err(Error::NotEnoughSpace)
        }
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() == EXTENDED_ADDRESS_SIZE {
            let address = LittleEndian::read_u64(&data);
            Ok(ExtendedAddress(address))
        } else {
            Err(Error::WrongNumberOfBytes)
        }
    }
}

impl PartialEq<[u8; EXTENDED_ADDRESS_SIZE]> for ExtendedAddress {
    fn eq(&self, other: &[u8; EXTENDED_ADDRESS_SIZE]) -> bool {
        let other = LittleEndian::read_u64(&other[..]);
        self.0 == other
    }
}

impl From<u64> for ExtendedAddress {
    fn from(value: u64) -> Self {
        ExtendedAddress(value)
    }
}

impl From<ExtendedAddress> for u64 {
    fn from(value: ExtendedAddress) -> Self {
        value.0
    }
}

impl PartialEq<u64> for ExtendedAddress {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl Default for ExtendedAddress {
    fn default() -> Self {
        Self(0xffff_ffff_ffff_ffffu64)
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for ExtendedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ((self.0 >> 56) & 0xff) as u8,
            ((self.0 >> 48) & 0xff) as u8,
            ((self.0 >> 40) & 0xff) as u8,
            ((self.0 >> 32) & 0xff) as u8,
            ((self.0 >> 24) & 0xff) as u8,
            ((self.0 >> 16) & 0xff) as u8,
            ((self.0 >> 8) & 0xff) as u8,
            ((self.0) & 0xff) as u8,
        )
    }
}

/// 64-bit extended personal area network (PAN) identifier
pub type ExtendedPanIdentifier = ExtendedAddress;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn short_address() {
        let a_zero = ShortAddress(0);
        assert_eq!(a_zero, [0, 0]);
        assert_eq!(format!("{}", a_zero), "0000");
        assert_eq!(a_zero, 0u16);
        let a = ShortAddress::unpack(&[0x81, 0x45]).unwrap();
        assert_eq!(a, [0x81, 0x45]);
        assert_eq!(format!("{}", a), "4581");
        assert_eq!(a, 0x4581);
        let a = ShortAddress(0x4581);
        assert_eq!(a, [0x81, 0x45]);
        assert_eq!(format!("{}", a), "4581");
        assert_eq!(a, 0x4581);
        let mut buf = [0; 2];
        a.pack(&mut buf).unwrap();
        assert_eq!(buf, [0x81, 0x45]);
    }

    #[test]
    fn extended_address() {
        let a = ExtendedAddress::unpack(&[0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22]).unwrap();
        assert_eq!(a, [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22]);
        assert_eq!(format!("{}", a), "22:33:44:55:66:77:88:99");
        assert_eq!(a, 0x2233_4455_6677_8899);
        let mut buf = [0; 8];
        a.pack(&mut buf).unwrap();
        assert_eq!(buf, [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22]);
        let a = ExtendedAddress::from(0x9988_7766_5544_3322);
        a.pack(&mut buf).unwrap();
        assert_eq!(buf, [0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
    }
}
