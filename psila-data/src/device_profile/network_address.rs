use core::convert::TryFrom;

use crate::common::address::{ExtendedAddress, NetworkAddress};
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

extended_enum!(
    /// Request type
    RequestType, u8,
    /// Single device request
    SingleDevice => 0x00,
    /// Extended request
    Extended => 0x01,
);

// 2.4.3.1.1 NWK_addr_req
/// Network address request
/// Requests the network address for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkAddressRequest {
    /// Device address
    pub address: ExtendedAddress,
    /// Request type
    pub request_type: RequestType,
    /// Start index
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
/// Extended (IEEE) address request
/// Requests the extended address for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedAddressRequest {
    /// Device address
    pub address: NetworkAddress,
    /// Request type
    pub request_type: RequestType,
    /// Start index
    pub start_index: u8,
}

impl Pack<ExtendedAddressRequest, Error> for ExtendedAddressRequest {
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
    /// Response status
    pub status: Status,
    /// Device extended address
    pub extended_address: ExtendedAddress,
    /// Device network address
    pub network_address: NetworkAddress,
    /// Start index
    pub start_index: u8,
    /// Number of device addresses
    num_devices: Option<u8>,
    /// Device addresses
    devices: [NetworkAddress; 32],
}

impl AddressResponse {
    /// Extended address response
    pub fn is_extended(&self) -> bool {
        self.num_devices.is_some()
    }
    /// No device addresses
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Number of devices
    pub fn len(&self) -> usize {
        if let Some(count) = self.num_devices {
            count as usize
        } else {
            0
        }
    }
    /// Device addresses
    pub fn devices(&self) -> &[NetworkAddress] {
        &self.devices[..self.len()]
    }
    /// Create a single device response
    pub fn single_device_response(
        status: Status,
        extended_address: ExtendedAddress,
        network_address: NetworkAddress,
    ) -> Self {
        Self {
            status,
            extended_address,
            network_address,
            start_index: 0,
            num_devices: None,
            devices: [NetworkAddress::default(); 32],
        }
    }
}

impl Pack<AddressResponse, Error> for AddressResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.status.into();
        self.extended_address.pack(&mut data[1..9])?;
        self.network_address.pack(&mut data[9..11])?;
        let mut offset = 11;
        if let Some(count) = self.num_devices {
            if data.len() < 14 + self.len() * 2 {
                return Err(Error::WrongNumberOfBytes);
            }
            data[offset] = count;
            offset += 1;
            data[offset] = self.start_index;
            offset += 1;
            for address in self.devices().iter() {
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
        let extended_address = ExtendedAddress::unpack(&data[1..9])?;
        let network_address = NetworkAddress::unpack(&data[9..11])?;
        let mut offset = 11;
        let (num_devices, start_index) = if data.len() >= 13 {
            let num_devices = data[11];
            offset += 1;
            let start_index = data[12];
            offset += 1;
            (num_devices as usize, start_index)
        } else {
            (0, 0)
        };
        if data.len() < offset + num_devices * 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut devices = [NetworkAddress::default(); 32];
        for device in devices[..num_devices].iter_mut() {
            *device = NetworkAddress::unpack(&data[offset..offset + 2])?;
            offset += 2;
        }
        let num_devices = if offset == 11 {
            None
        } else {
            Some(num_devices as u8)
        };
        Ok((
            Self {
                status,
                extended_address,
                network_address,
                start_index,
                num_devices,
                devices,
            },
            offset,
        ))
    }
}
