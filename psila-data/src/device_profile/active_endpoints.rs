use core::convert::TryFrom;

use crate::common::address::NetworkAddress;
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

// 2.4.3.1.6 Active_EP_req
/// Active endpoint request
/// Requests the active endpoints for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveEndpointRequest {
    pub address: NetworkAddress,
}

impl Pack<ActiveEndpointRequest, Error> for ActiveEndpointRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..2])?;
        Ok(2)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        Ok((Self { address }, 2))
    }
}

// 2.4.4.2.6 Active_EP_rsp
/// Active endpoint response
/// Response to a active endpoint request
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveEndpointResponse {
    pub status: Status,
    pub address: NetworkAddress,
    pub endpoint_count: u8,
    pub endpoints: [u8; 32],
}

impl ActiveEndpointResponse {
    pub fn success_response(address: NetworkAddress, endpoints: &[u8]) -> Self {
        let mut eps = [0u8; 32];
        let count = if endpoints.len() > 32 {
            32
        } else {
            endpoints.len()
        };
        let ep_count = count as u8;
        eps[..count].copy_from_slice(&endpoints[..count]);
        Self {
            status: Status::Success,
            address,
            endpoint_count: ep_count,
            endpoints: eps,
        }
    }
    pub fn failure_response(status: Status, address: NetworkAddress) -> Self {
        assert!(status != Status::Success);
        let endpoints = [0u8; 32];
        Self {
            status,
            address,
            endpoint_count: 0,
            endpoints,
        }
    }
}

impl Pack<ActiveEndpointResponse, Error> for ActiveEndpointResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let count = if self.status == Status::Success {
            self.endpoint_count as usize
        } else {
            0
        };
        if data.len() < 4 + count {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        self.address.pack(&mut data[1..3])?;
        data[3] = count as u8;
        let end = 4 + count;
        data[4..end].copy_from_slice(&self.endpoints[..count]);
        Ok(end)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let address = NetworkAddress::unpack(&data[1..3])?;
        let endpoint_count = data[3];
        let count = if status == Status::Success {
            endpoint_count as usize
        } else {
            0
        };
        let endpoint_count = count as u8;
        if data.len() < 4 + count {
            return Err(Error::WrongNumberOfBytes);
        }
        if count > 64 {
            return Err(Error::NotEnoughSpace);
        }
        let mut endpoints = [0u8; 32];
        endpoints[..count].copy_from_slice(&data[4..4 + count]);
        Ok((
            Self {
                status,
                address,
                endpoint_count,
                endpoints,
            },
            4 + count,
        ))
    }
}

impl ActiveEndpointResponse {
    pub fn endpoints(&self) -> &[u8] {
        let count = self.endpoint_count as usize;
        &self.endpoints[..count]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_active_endpoint_request() {
        let data = [0x96, 0x1f];
        let (req, used) = ActiveEndpointRequest::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(req.address, 0x1f96);
    }

    #[test]
    fn pack_active_endpoint_request() {
        let request = ActiveEndpointRequest {
            address: NetworkAddress::from(0xabcd),
        };
        let mut data = [0u8; 2];
        let used = request.pack(&mut data[..]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(data, [0xcd, 0xab]);
    }

    #[test]
    fn unpack_active_endpoint_response_success() {
        let data = [0x00, 0x96, 0x1f, 0x01, 0x01];
        let (req, used) = ActiveEndpointResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 5);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x1f96);
        assert_eq!(req.endpoint_count, 1);
        assert_eq!(req.endpoints[..1], [0x01]);

        let data = [0x00, 0x45, 0x78, 0x04, 0x01, 0x10, 0x0f, 0x20];
        let (req, used) = ActiveEndpointResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 8);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x7845);
        assert_eq!(req.endpoint_count, 4);
        assert_eq!(req.endpoints[..4], [0x01, 0x10, 0x0f, 0x20]);
    }

    #[test]
    fn unpack_active_endpoint_response_error() {
        let data = [0x80, 0x54, 0x76, 0x00];
        let (req, used) = ActiveEndpointResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 4);
        assert_eq!(req.status, Status::InvalidRequestType);
        assert_eq!(req.address, 0x7654);
        assert_eq!(req.endpoint_count, 0);
    }

    #[test]
    fn pack_active_endpoint_response_success() {
        let response =
            ActiveEndpointResponse::success_response(NetworkAddress::from(0xcdfe), &[0x01, 0x02]);
        let mut data = [0u8; 6];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 6);
        assert_eq!(data, [0x00, 0xfe, 0xcd, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn pack_active_endpoint_response_error() {
        let response = ActiveEndpointResponse::failure_response(
            Status::InvalidRequestType,
            NetworkAddress::from(0xcdfe),
        );
        let mut data = [0u8; 4];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 4);
        assert_eq!(data, [0x80, 0xfe, 0xcd, 0x00]);
    }
}
