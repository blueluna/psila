use crate::common::address::{ExtendedAddress, NetworkAddress, EXTENDED_ADDRESS_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Options {
    pub orginator_ieee_address: bool,
    pub responder_ieee_address: bool,
    pub multicast: bool,
}

impl PackFixed<Options, Error> for Options {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = (self.orginator_ieee_address as u8) << 4
            | (self.responder_ieee_address as u8) << 5
            | (self.multicast as u8) << 6;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        let orginator_ieee_address = (data[0] & 0b0001_0000) == 0b0001_0000;
        let responder_ieee_address = (data[0] & 0b0010_0000) == 0b0010_0000;
        let multicast = (data[0] & 0b0100_0000) == 0b0100_0000;

        Ok(Options {
            orginator_ieee_address,
            responder_ieee_address,
            multicast,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RouteReply {
    pub options: Options,
    pub identifier: u8,
    pub orginator_address: NetworkAddress,
    pub responder_address: NetworkAddress,
    pub path_cost: u8,
    pub orginator_ieee_address: Option<ExtendedAddress>,
    pub responder_ieee_address: Option<ExtendedAddress>,
}

impl Pack<RouteReply, Error> for RouteReply {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        assert_eq!(self.orginator_ieee_address.is_some(), self.options.orginator_ieee_address);
        assert_eq!(self.responder_ieee_address.is_some(), self.options.responder_ieee_address);
        let length = 7;
        let length = length + if self.orginator_ieee_address.is_some() { EXTENDED_ADDRESS_SIZE } else { 0 };
        let length = length + if self.responder_ieee_address.is_some() { EXTENDED_ADDRESS_SIZE } else { 0 };
        if data.len() < length {
            return Err(Error::WrongNumberOfBytes);
        }
        self.options.pack(&mut data[0..=0])?;
        data[1] = self.identifier;
        self.orginator_address.pack(&mut data[2..4])?;
        self.responder_address.pack(&mut data[4..6])?;
        data[6] = self.path_cost;
        let mut offset = 7;
        if let Some(orginator) = self.orginator_ieee_address {
            orginator.pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
        }
        if let Some(responder) = self.responder_ieee_address {
            responder.pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 7 {
            return Err(Error::WrongNumberOfBytes);
        }
        let options = Options::unpack(&data[0..=0])?;
        let orginator_address = NetworkAddress::unpack(&data[2..4])?;
        let responder_address = NetworkAddress::unpack(&data[4..6])?;
        let mut offset = 7;
        let orginator_ieee_address = if options.orginator_ieee_address {
            if data.len() < (offset + EXTENDED_ADDRESS_SIZE) {
                return Err(Error::WrongNumberOfBytes);
            }
            let address = ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
            Some(address)
        } else {
            None
        };
        let responder_ieee_address = if options.responder_ieee_address {
            if data.len() < (offset + EXTENDED_ADDRESS_SIZE) {
                return Err(Error::WrongNumberOfBytes);
            }
            let address = ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
            Some(address)
        } else {
            None
        };

        Ok((
            RouteReply {
                options,
                identifier: data[1],
                orginator_address,
                responder_address,
                path_cost: data[6],
                orginator_ieee_address,
                responder_ieee_address,
            },
            offset,
        ))
    }
}
