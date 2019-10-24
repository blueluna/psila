use core::convert::TryFrom;

use crate::common::address::{ExtendedAddress, GroupIdentifier, NetworkAddress, EXTENDED_ADDRESS_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

extended_enum!(
    ManyToOne, u8,
    No => 0x00,
    RouteRequestTableSupport => 0x01,
    NoRouteRequestTableSupport => 0x02,
);

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Options {
    pub many_to_one: ManyToOne,
    pub destination_ieee_address: bool,
    pub multicast: bool,
}

impl PackFixed<Options, Error> for Options {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        let many_to_one = self.many_to_one as u8;
        data[0] = many_to_one << 3
            | (self.destination_ieee_address as u8) << 5
            | (self.multicast as u8) << 6;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        let many_to_one = ManyToOne::try_from((data[0] & 0b0001_1000) >> 3)?;
        let destination_ieee_address = (data[0] & 0b0010_0000) == 0b0010_0000;
        let multicast = (data[0] & 0b0100_0000) == 0b0100_0000;

        Ok(Options {
            many_to_one,
            destination_ieee_address,
            multicast,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressType {
    Singlecast(NetworkAddress),
    Multicast(GroupIdentifier),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RouteRequest {
    pub options: Options,
    pub identifier: u8,
    pub destination_address: AddressType,
    pub path_cost: u8,
    pub destination_ieee_address: Option<ExtendedAddress>,
}

impl Pack<RouteRequest, Error> for RouteRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        assert_eq!(self.destination_ieee_address.is_some(), self.options.destination_ieee_address);
        let length = 5 + if self.destination_ieee_address.is_some() { EXTENDED_ADDRESS_SIZE } else { 0 };
        if data.len() < length {
            return Err(Error::WrongNumberOfBytes);
        }
        self.options.pack(&mut data[0..=0])?;
        data[1] = self.identifier;
        match self.destination_address {
            AddressType::Singlecast(address) => {
                assert!(!self.options.multicast);
                address.pack(&mut data[2..4])?;
            }
            AddressType::Multicast(address) => {
                assert!(self.options.multicast);
                address.pack(&mut data[2..4])?;
            }
        }
        data[4] = self.identifier;
        let mut offset = 5;
        if let Some(address) = self.destination_ieee_address {
            address.pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 5 {
            return Err(Error::WrongNumberOfBytes);
        }
        let options = Options::unpack(&data[0..1])?;
        if options.destination_ieee_address && data.len() < 13 {
            return Err(Error::WrongNumberOfBytes);
        }
        let destination_address = if options.multicast {
            let gi = GroupIdentifier::unpack(&data[2..4])?;
            AddressType::Multicast(gi)
        } else {
            let ad = NetworkAddress::unpack(&data[2..4])?;
            AddressType::Singlecast(ad)
        };
        let destination_ieee_address = if options.destination_ieee_address {
            let addr = ExtendedAddress::unpack(&data[5..13])?;
            Some(addr)
        } else {
            None
        };
        let used = if destination_ieee_address.is_some() {
            13
        } else {
            5
        };

        Ok((
            RouteRequest {
                options,
                identifier: data[1],
                destination_address,
                path_cost: data[4],
                destination_ieee_address,
            },
            used,
        ))
    }
}
