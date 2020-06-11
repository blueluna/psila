//! # Addresses used in the network

use core::default::Default;

use crate::pack::PackFixed;
use crate::Error;

use byteorder::{ByteOrder, LittleEndian};

/// Short address size
pub const SHORT_ADDRESS_SIZE: usize = 2;
/// Short address, broadcast address
pub const SHORT_ADDRESS_BROADCAST: u16 = 0xffff;
/// Short address, unassigned address
/// The device has associated to a network but has not been assigned a address.
/// The extended address should be used.
pub const SHORT_ADDRESS_UNASSIGNED: u16 = 0xfffe;

/// 16-bit short address
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ShortAddress(u16);

impl ShortAddress {
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    pub fn broadcast() -> Self {
        Self(SHORT_ADDRESS_BROADCAST)
    }

    pub fn is_broadcast(self) -> bool {
        self.0 == SHORT_ADDRESS_BROADCAST
    }

    pub fn is_unassigned(self) -> bool {
        self.0 == SHORT_ADDRESS_UNASSIGNED
    }

    pub fn is_assigned(self) -> bool {
        self.0 < SHORT_ADDRESS_UNASSIGNED
    }
}

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

impl From<ieee802154::mac::frame::ShortAddress> for ShortAddress {
    fn from(value: ieee802154::mac::frame::ShortAddress) -> Self {
        ShortAddress(value.0)
    }
}

impl Into<ieee802154::mac::frame::ShortAddress> for ShortAddress {
    fn into(self) -> ieee802154::mac::frame::ShortAddress {
        ieee802154::mac::frame::ShortAddress(self.0)
    }
}

impl PartialEq<u16> for ShortAddress {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ieee802154::mac::frame::ShortAddress> for ShortAddress {
    fn eq(&self, other: &ieee802154::mac::frame::ShortAddress) -> bool {
        self.0 == other.0
    }
}

impl Default for ShortAddress {
    fn default() -> Self {
        Self(0xffffu16)
    }
}

#[cfg(not(feature = "core"))]
impl std::fmt::Display for ShortAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

#[cfg(feature = "core")]
impl core::fmt::Display for ShortAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

/// 16-bit network address
pub type NetworkAddress = ShortAddress;
/// 16-bit personal area network (PAN) identifier
pub type PanIdentifier = ShortAddress;
/// 16-bit group identifier
pub type GroupIdentifier = ShortAddress;

impl From<ieee802154::mac::frame::PanId> for PanIdentifier {
    fn from(value: ieee802154::mac::frame::PanId) -> Self {
        PanIdentifier::new(value.0)
    }
}

impl Into<ieee802154::mac::frame::PanId> for PanIdentifier {
    fn into(self) -> ieee802154::mac::frame::PanId {
        ieee802154::mac::frame::PanId(self.0)
    }
}

impl PartialEq<ieee802154::mac::frame::PanId> for PanIdentifier {
    fn eq(&self, other: &ieee802154::mac::frame::PanId) -> bool {
        self.0 == other.0
    }
}

/// Extended IEEE address size
pub const EXTENDED_ADDRESS_SIZE: usize = 8;
/// Extended IEEE address, broadcast address
pub const EXTENDED_ADDRESS_BROADCAST: u64 = 0xffff_ffff_ffff_ffffu64;

/// 64-bit extended IEEE address
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ExtendedAddress(u64);

impl ExtendedAddress {
    pub fn new(address: u64) -> Self {
        Self(address)
    }

    pub fn broadcast() -> Self {
        Self(EXTENDED_ADDRESS_BROADCAST)
    }

    pub fn is_broadcast(self) -> bool {
        self.0 == EXTENDED_ADDRESS_BROADCAST
    }
}

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

impl From<ieee802154::mac::frame::ExtendedAddress> for ExtendedAddress {
    fn from(value: ieee802154::mac::frame::ExtendedAddress) -> Self {
        ExtendedAddress(value.0)
    }
}

impl Into<ieee802154::mac::frame::ExtendedAddress> for ExtendedAddress {
    fn into(self) -> ieee802154::mac::frame::ExtendedAddress {
        ieee802154::mac::frame::ExtendedAddress(self.0)
    }
}

impl PartialEq<u64> for ExtendedAddress {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ieee802154::mac::frame::ExtendedAddress> for ExtendedAddress {
    fn eq(&self, other: &ieee802154::mac::frame::ExtendedAddress) -> bool {
        self.0 == other.0
    }
}

impl Default for ExtendedAddress {
    fn default() -> Self {
        Self(0xffff_ffff_ffff_ffffu64)
    }
}

impl core::fmt::Display for ExtendedAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;
    use ieee802154;

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
    fn ieee802154_short_address_interop() {
        let mac_address = ieee802154::mac::frame::ShortAddress(0x3456);
        let address = ShortAddress::from(mac_address);
        assert_eq!(address, ShortAddress(0x3456));
        let address = ShortAddress(0xabcd);
        let mac_address: ieee802154::mac::frame::ShortAddress = address.into();
        assert_eq!(mac_address, ieee802154::mac::frame::ShortAddress(0xabcd));
    }

    #[test]
    fn ieee802154_pan_identifier_interop() {
        let mac_pan_id = ieee802154::mac::frame::PanId(0xa8d5);
        let pan_id = PanIdentifier::from(mac_pan_id);
        assert_eq!(pan_id, PanIdentifier::new(0xa8d5));
        let pan_id = PanIdentifier::new(0x92d7);
        let mac_pan_id: ieee802154::mac::frame::PanId = pan_id.into();
        assert_eq!(mac_pan_id, ieee802154::mac::frame::PanId(0x92d7));
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

    #[test]
    fn ieee802154_extended_address_interop() {
        let mac_address = ieee802154::mac::frame::ExtendedAddress(0x2233_4455_6677_8899);
        let address = ExtendedAddress::from(mac_address);
        assert_eq!(address, ExtendedAddress(0x2233_4455_6677_8899));
        let address = ExtendedAddress(0x8899_aabb_ccdd_eeff);
        let mac_address: ieee802154::mac::frame::ExtendedAddress = address.into();
        assert_eq!(
            mac_address,
            ieee802154::mac::frame::ExtendedAddress(0x8899_aabb_ccdd_eeff)
        );
    }
}
