use core::convert::TryFrom;

use crate::common::address::NetworkAddress;
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

use byteorder::{ByteOrder, LittleEndian};

// 2.4.3.1.7 Match_Desc_req
/// Match descriptor request
/// Requests simmple descriptor for devices matching the requested requirements
#[derive(Clone, Debug, PartialEq)]
pub struct MatchDescriptorRequest {
    pub address: NetworkAddress,
    pub profile: u16,
    pub input_clusters: Vec<u16>,
    pub output_clusters: Vec<u16>,
}

impl Pack<MatchDescriptorRequest, Error> for MatchDescriptorRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        assert!(self.input_clusters.len() <= 255);
        assert!(self.output_clusters.len() <= 255);
        let num_clusters = self.input_clusters.len() + self.output_clusters.len();
        if data.len() < 6 + (num_clusters * 2) {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..2])?;
        LittleEndian::write_u16(&mut data[2..4], self.profile);
        data[4] = self.input_clusters.len() as u8;
        let mut offset = 5;
        for cluster in self.input_clusters.iter() {
            LittleEndian::write_u16(&mut data[offset..offset + 2], *cluster);
            offset += 2;
        }
        data[offset] = self.output_clusters.len() as u8;
        offset += 1;
        for cluster in self.output_clusters.iter() {
            LittleEndian::write_u16(&mut data[offset..offset + 2], *cluster);
            offset += 2;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 6 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        let profile = LittleEndian::read_u16(&data[2..4]);
        let num_clusters = data[4] as usize;
        if data.len() < 6 + (num_clusters * 2) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 5;
        let mut input_clusters = vec![];
        for _ in 0..num_clusters {
            input_clusters.push(LittleEndian::read_u16(&data[offset..offset + 2]));
            offset += 2;
        }
        let num_clusters = data[offset] as usize;
        offset += 1;
        if data.len() < offset + (num_clusters * 2) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut output_clusters = vec![];
        for _ in 0..num_clusters {
            output_clusters.push(LittleEndian::read_u16(&data[offset..offset + 2]));
            offset += 2;
        }
        Ok((
            Self {
                address,
                profile,
                input_clusters,
                output_clusters,
            },
            offset,
        ))
    }
}

// 2.4.3.1.7 Match_Desc_req
/// Match descriptor request
/// Requests simmple descriptor for devices matching the requested requirements
#[derive(Clone, Debug, PartialEq)]
pub struct MatchDescriptorResponse {
    pub status: Status,
    pub address: NetworkAddress,
    pub list: Vec<u8>,
}

impl Pack<MatchDescriptorResponse, Error> for MatchDescriptorResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        assert!(self.list.len() <= 255);
        let num_entries = self.list.len();
        if data.len() < 4 + num_entries {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.status as u8;
        self.address.pack(&mut data[1..=2])?;
        data[3] = self.list.len() as u8;
        let mut offset = 4;
        for entry in self.list.iter() {
            data[offset] = *entry;
            offset += 1;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let address = NetworkAddress::unpack(&data[1..=2])?;
        let num_entries = data[3] as usize;
        if data.len() < 4 + num_entries {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 4;
        let mut list = vec![];
        for _ in 0..num_entries {
            list.push(data[offset]);
            offset += 1;
        }
        Ok((
            Self {
                status,
                address,
                list,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_match_descriptor_request() {
        let data = [0xfd, 0xff, 0x04, 0x01, 0x01, 0x19, 0x00, 0x00];
        let (req, used) = MatchDescriptorRequest::unpack(&data[..]).unwrap();
        assert_eq!(used, 8);
        assert_eq!(req.address, 0xfffd);
        assert_eq!(req.profile, 0x0104);
        assert_eq!(req.input_clusters.len(), 1);
        assert_eq!(req.input_clusters[0], 0x0019);
        assert_eq!(req.output_clusters.len(), 0);
    }

    #[test]
    fn unpack_match_descriptor_response() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x01];
        let (req, used) = MatchDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 5);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x0000);
        assert_eq!(req.list.len(), 1);
        assert_eq!(req.list[0], 0x01);
    }
}
