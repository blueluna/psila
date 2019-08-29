use core::convert::TryFrom;

use crate::common::address::{ExtendedAddress, NetworkAddress};
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

extended_enum!(
	RequestType, u8,
	SingleDevice => 0x00,
	Extended => 0x01,
);

// 2.4.3.1.1 NWK_addr_req
/// Network address request
/// Requests the network address for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkAddressRequest {
    pub address: ExtendedAddress,
    pub request_type: RequestType,
    pub start_index: u8,
}

impl Pack<NetworkAddressRequest, Error> for NetworkAddressRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 10 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..8])?;
        data[8] = self.request_type as u8;
        data[9] = self.start_index;
        Ok(10)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 10 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = ExtendedAddress::unpack(&data[0..8])?;
        let request_type = RequestType::try_from(data[8])?;
        Ok((
            Self {
                address,
                request_type,
                start_index: data[9],
            },
            10,
        ))
    }
}

// 2.4.3.1.2 IEEE_addr_req
/// IEEE address request
/// Requests the IEEE address for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct IeeeAddressRequest {
    pub address: NetworkAddress,
    pub request_type: RequestType,
    pub start_index: u8,
}

impl Pack<IeeeAddressRequest, Error> for IeeeAddressRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..2])?;
        data[2] = self.request_type as u8;
        data[3] = self.start_index;
        Ok(4)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        let request_type = RequestType::try_from(data[2])?;
        Ok((
            Self {
                address,
                request_type,
                start_index: data[3],
            },
            4,
        ))
    }
}

/// Network and IEEE address response
///
#[derive(Clone, Debug, PartialEq)]
pub struct AddressResponse {
    pub status: Status,
    pub ieee_address: ExtendedAddress,
    pub network_address: NetworkAddress,
    pub start_index: Option<u8>,
    pub associated_devices: Option<Vec<NetworkAddress>>,
}

impl Pack<AddressResponse, Error> for AddressResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.status.into();
        self.ieee_address.pack(&mut data[1..9])?;
        self.network_address.pack(&mut data[9..11])?;
        let mut offset = 11;
        if let Some(associated_devices) = &self.associated_devices {
            if data.len() < 14 + associated_devices.len() * 2 {
                return Err(Error::WrongNumberOfBytes);
            }
            data[offset] = associated_devices.len() as u8;
            offset += 1;
            data[offset] = if let Some(start_index) = self.start_index {
                start_index
            } else {
                0
            };
            offset += 1;
            for address in associated_devices {
                address.pack(&mut data[offset..offset + 2])?;
                offset += 2;
            }
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let ieee_address = ExtendedAddress::unpack(&data[1..9])?;
        let network_address = NetworkAddress::unpack(&data[9..11])?;
        let mut offset = 11;
        let (num_devices, start_index) = if data.len() >= 13 {
            let num_devices = data[11];
            offset += 1;
            let start_index = data[12];
            offset += 1;
            (num_devices as usize, Some(start_index))
        } else {
            (0, None)
        };
        let associated_devices = if num_devices > 0 {
            if data.len() < offset + num_devices * 2 {
                return Err(Error::WrongNumberOfBytes);
            }
            let mut devices: Vec<NetworkAddress> = Vec::with_capacity(num_devices);
            for _ in 0..num_devices {
                devices.push(NetworkAddress::unpack(&data[offset..offset + 2])?);
                offset += 2;
            }
            Some(devices)
        } else {
            None
        };
        Ok((
            Self {
                status,
                ieee_address,
                network_address,
                start_index,
                associated_devices,
            },
            offset,
        ))
    }
}
