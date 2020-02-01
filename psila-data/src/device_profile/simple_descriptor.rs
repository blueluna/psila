use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryFrom;

use crate::common::address::NetworkAddress;
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

// 2.3.2.5 Simple Descriptor
/// Simple descriptor for a node endpoint
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleDescriptor {
    pub endpoint: u8,
    pub profile: u16,
    pub device: u16,
    pub device_version: u8,
    /// Server clusters implemented by the device
    pub input_cluster_count: u8,
    pub input_clusters: [u16; 32],
    /// Client clusters implemented by the device
    pub output_cluster_count: u8,
    pub output_clusters: [u16; 32],
}

impl SimpleDescriptor {
    pub fn new(
        endpoint: u8,
        profile: u16,
        device: u16,
        device_version: u8,
        input_clusters: &[u16],
        output_clusters: &[u16],
    ) -> Self {
        let icc = if input_clusters.len() > 32 {
            32
        } else {
            input_clusters.len()
        };
        let occ = if output_clusters.len() > 32 {
            32
        } else {
            output_clusters.len()
        };
        let mut ic = [0u16; 32];
        ic[..icc].copy_from_slice(&input_clusters[..icc]);
        let mut oc = [0u16; 32];
        oc[..occ].copy_from_slice(&output_clusters[..occ]);
        Self {
            endpoint,
            profile,
            device,
            device_version,
            input_cluster_count: icc as u8,
            input_clusters: ic,
            output_cluster_count: occ as u8,
            output_clusters: oc,
        }
    }

    pub fn input_clusters(&self) -> &[u16] {
        let count = self.input_cluster_count as usize;
        &self.input_clusters[..count]
    }
    pub fn output_clusters(&self) -> &[u16] {
        let count = self.output_cluster_count as usize;
        &self.output_clusters[..count]
    }
}

impl Pack<SimpleDescriptor, Error> for SimpleDescriptor {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let size =
            8 + (self.input_cluster_count as usize) * 2 + (self.output_cluster_count as usize) * 2;
        if data.len() < size {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.endpoint;
        LittleEndian::write_u16(&mut data[1..3], self.profile);
        LittleEndian::write_u16(&mut data[3..5], self.device);
        data[5] = self.device_version & 0x0f;
        data[6] = self.input_cluster_count;
        let mut offset = 7;
        let count = self.input_cluster_count as usize;
        for n in 0..count {
            LittleEndian::write_u16(&mut data[offset..offset + 2], self.input_clusters[n]);
            offset += 2;
        }
        data[offset] = self.output_cluster_count;
        offset += 1;
        let count = self.output_cluster_count as usize;
        for n in 0..count {
            LittleEndian::write_u16(&mut data[offset..offset + 2], self.output_clusters[n]);
            offset += 2;
        }
        Ok(offset)
    }
    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 8 {
            return Err(Error::WrongNumberOfBytes);
        }
        let endpoint = data[0];
        let profile = LittleEndian::read_u16(&data[1..3]);
        let device = LittleEndian::read_u16(&data[3..5]);
        let device_version = data[5] & 0x0f;
        let input_cluster_count = data[6];
        let count = input_cluster_count as usize;
        let mut offset = 7;
        let mut input_clusters = [0u16; 32];
        for n in 0..count {
            input_clusters[n] = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
        }
        let output_cluster_count = data[offset];
        let count = output_cluster_count as usize;
        offset += 1;
        let mut output_clusters = [0u16; 32];
        for n in 0..count {
            output_clusters[n] = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
        }
        Ok((
            Self {
                endpoint,
                profile,
                device,
                device_version,
                input_cluster_count,
                input_clusters,
                output_cluster_count,
                output_clusters,
            },
            offset,
        ))
    }
}

impl Default for SimpleDescriptor {
    fn default() -> Self {
        Self {
            endpoint: 0,
            profile: 0,
            device: 0,
            device_version: 0,
            input_cluster_count: 0,
            input_clusters: [0; 32],
            output_cluster_count: 0,
            output_clusters: [0; 32],
        }
    }
}

// 2.4.3.1.5 Simple_Desc_req
/// Simple descriptor request
/// Requests the simple descriptor for a remote device endpoint
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleDescriptorRequest {
    pub address: NetworkAddress,
    pub endpoint: u8,
}

impl Pack<SimpleDescriptorRequest, Error> for SimpleDescriptorRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..2])?;
        data[2] = self.endpoint;
        Ok(3)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        let endpoint = data[2];
        Ok((Self { address, endpoint }, 3))
    }
}

// 2.4.4.2.5 Simple_Desc_rsp
/// Simple descriptor response
/// Response to a simple descriptor request
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleDescriptorResponse {
    pub status: Status,
    pub address: NetworkAddress,
    pub descriptor: SimpleDescriptor,
}

impl SimpleDescriptorResponse {
    pub fn success_response(address: NetworkAddress, descriptor: SimpleDescriptor) -> Self {
        Self {
            status: Status::Success,
            address,
            descriptor,
        }
    }
    pub fn failure_response(address: NetworkAddress, status: Status) -> Self {
        Self {
            status,
            address,
            descriptor: SimpleDescriptor::default(),
        }
    }
}

impl Pack<SimpleDescriptorResponse, Error> for SimpleDescriptorResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        self.address.pack(&mut data[1..3])?;
        let size = if self.status == Status::Success {
            let size = self.descriptor.pack(&mut data[4..])?;
            data[3] = size as u8;
            size + 4
        } else {
            data[3] = 0;
            4
        };
        Ok(size)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let address = NetworkAddress::unpack(&data[1..3])?;
        let length = data[3] as usize;
        if data.len() < length + 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let (descriptor, size) = if status == Status::Success {
            let (descriptor, size) = SimpleDescriptor::unpack(&data[4..4 + length])?;
            (descriptor, size + 4)
        } else {
            (SimpleDescriptor::default(), 4)
        };
        Ok((
            Self {
                status,
                address,
                descriptor,
            },
            size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_simple_descriptor() {
        let data = [
            0x01, 0x23, 0x01, 0xdc, 0xfe, 0x0f, 0x03, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04,
            0xff, 0xff, 0x01, 0x80, 0x00, 0x00, 0xf0, 0x0f,
        ];
        let (descriptor, used) = SimpleDescriptor::unpack(&data[..]).unwrap();
        assert_eq!(used, 22);
        assert_eq!(descriptor.endpoint, 0x01);
        assert_eq!(descriptor.profile, 0x0123);
        assert_eq!(descriptor.device, 0xfedc);
        assert_eq!(descriptor.device_version, 0x0f);
        assert_eq!(descriptor.input_cluster_count, 3);
        let clusters = descriptor.input_clusters();
        assert_eq!(clusters.len(), 3);
        assert_eq!(clusters[0], 0x0000);
        assert_eq!(clusters[1], 0x0001);
        assert_eq!(clusters[2], 0x0002);
        assert_eq!(descriptor.output_cluster_count, 4);
        let clusters = descriptor.output_clusters();
        assert_eq!(clusters.len(), 4);
        assert_eq!(clusters[0], 0xffff);
        assert_eq!(clusters[1], 0x8001);
        assert_eq!(clusters[2], 0x0000);
        assert_eq!(clusters[3], 0x0ff0);
    }

    #[test]
    fn unpack_simple_descriptor_request() {
        let data = [0x96, 0x1f, 0x01];
        let (req, used) = SimpleDescriptorRequest::unpack(&data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(req.address, 0x1f96);
        assert_eq!(req.endpoint, 0x01);
    }

    #[test]
    fn pack_simple_descriptor_request() {
        let request = SimpleDescriptorRequest {
            address: NetworkAddress::from(0x8001),
            endpoint: 0x0f,
        };
        let mut data = [0u8; 3];
        let used = request.pack(&mut data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(data, [0x01, 0x80, 0x0f]);
    }

    #[test]
    fn unpack_simple_descriptor_response_sucess() {
        let data = [
            0x00, 0x96, 0x1f, 0x22, 0x01, 0x5e, 0xc0, 0x30, 0x08, 0x02, 0x06, 0x00, 0x00, 0x01,
            0x00, 0x03, 0x00, 0x09, 0x00, 0x05, 0x0b, 0x00, 0x10, 0x07, 0x03, 0x00, 0x04, 0x00,
            0x05, 0x00, 0x06, 0x00, 0x08, 0x00, 0x19, 0x00, 0x00, 0x10,
        ];
        let (req, used) = SimpleDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 38);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x1f96);
        assert_eq!(req.descriptor.endpoint, 0x01);
        assert_eq!(req.descriptor.profile, 0xc05e);
        assert_eq!(req.descriptor.device, 0x0830);
        assert_eq!(req.descriptor.device_version, 0x02);
        assert_eq!(req.descriptor.input_cluster_count, 6);
        let clusters = req.descriptor.input_clusters();
        assert_eq!(clusters.len(), 6);
        assert_eq!(clusters[0], 0x0000);
        assert_eq!(clusters[1], 0x0001);
        assert_eq!(clusters[2], 0x0003);
        assert_eq!(clusters[3], 0x0009);
        assert_eq!(clusters[4], 0x0b05);
        assert_eq!(clusters[5], 0x1000);
        assert_eq!(req.descriptor.output_cluster_count, 7);
        let clusters = req.descriptor.output_clusters();
        assert_eq!(clusters.len(), 7);
        assert_eq!(clusters[0], 0x0003);
        assert_eq!(clusters[1], 0x0004);
        assert_eq!(clusters[2], 0x0005);
        assert_eq!(clusters[3], 0x0006);
        assert_eq!(clusters[4], 0x0008);
        assert_eq!(clusters[5], 0x0019);
        assert_eq!(clusters[6], 0x1000);
    }

    #[test]
    fn unpack_simple_descriptor_response_error() {
        let data = [0x82, 0x65, 0x87, 0x00];
        let (req, used) = SimpleDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 4);
        assert_eq!(req.status, Status::InvalidEndpoint);
        assert_eq!(req.address, 0x8765);
    }

    #[test]
    fn pack_simple_descriptor_response_sucess() {
        let descriptor = SimpleDescriptor::new(
            0x02,
            0x5678,
            0x1234,
            0x0f,
            &[0x0001, 0x0002],
            &[0x0003, 0x0004],
        );
        let response =
            SimpleDescriptorResponse::success_response(NetworkAddress::from(0xfffe), descriptor);

        let mut data = [0u8; 20];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 20);
        assert_eq!(
            data,
            [
                0x00, 0xfe, 0xff, 16, 0x02, 0x78, 0x56, 0x34, 0x12, 0x0f, 2, 0x01, 0x00, 0x02,
                0x00, 2, 0x03, 0x00, 0x04, 0x00
            ]
        );
    }

    #[test]
    fn pack_simple_descriptor_response_error() {
        let response = SimpleDescriptorResponse::failure_response(
            NetworkAddress::from(0xfffe),
            Status::InvalidEndpoint,
        );
        let mut data = [0u8; 4];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 4);
        assert_eq!(data, [0x82, 0xfe, 0xff, 0x00]);
    }
}
