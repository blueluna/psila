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
    /// Device address
    pub address: NetworkAddress,
    /// Profile
    pub profile: u16,
    /// Number of input clusters
    num_input_clusters: u8,
    /// Input clusters
    input_clusters: [u16; 32],
    /// Number of output clusters
    num_output_clusters: u8,
    /// Output clusters
    output_clusters: [u16; 32],
}

impl MatchDescriptorRequest {
    /// Number of input clusters
    pub fn input_clusters_len(&self) -> usize {
        self.num_input_clusters as usize
    }
    /// Input clusters
    pub fn input_clusters_entries(&self) -> &[u16] {
        &self.input_clusters[..self.num_input_clusters as usize]
    }
    /// Number of output clusters
    pub fn output_clusters_len(&self) -> usize {
        self.num_output_clusters as usize
    }
    /// Output clusters
    pub fn output_clusters_entries(&self) -> &[u16] {
        &self.output_clusters[..self.num_output_clusters as usize]
    }
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
        let num_input_clusters = data[4];
        let num_clusters = num_input_clusters as usize;
        if data.len() < 6 + (num_clusters * 2) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 5;
        let mut input_clusters = [0u16; 32];
        for cluster in input_clusters[..num_clusters].iter_mut() {
            *cluster = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
        }
        let num_output_clusters = data[offset];
        let num_clusters = num_output_clusters as usize;
        offset += 1;
        if data.len() < offset + (num_clusters * 2) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut output_clusters = [0u16; 32];
        for cluster in output_clusters[..num_clusters].iter_mut() {
            *cluster = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
        }
        Ok((
            Self {
                address,
                profile,
                input_clusters,
                num_input_clusters,
                output_clusters,
                num_output_clusters,
            },
            offset,
        ))
    }
}

// 2.4.3.1.7 Match_Desc_req
/// Match descriptor request
/// Requests simple descriptor for devices matching the requested requirements
#[derive(Clone, Debug, PartialEq)]
pub struct MatchDescriptorResponse {
    /// Response status
    pub status: Status,
    /// Device address
    pub address: NetworkAddress,
    /// Number of endpoint entries
    num_entries: u8,
    /// Endpoints
    entries: [u8; 32],
}

impl MatchDescriptorResponse {
    /// No endpoints
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }
    /// Number of endpoints
    pub fn len(&self) -> usize {
        self.num_entries as usize
    }
    /// Endpoints
    pub fn entries(&self) -> &[u8] {
        &self.entries[..self.num_entries as usize]
    }
}

impl Pack<MatchDescriptorResponse, Error> for MatchDescriptorResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let num_entries = self.num_entries as usize;
        if data.len() < 4 + num_entries {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.status as u8;
        self.address.pack(&mut data[1..=2])?;
        data[3] = self.num_entries;
        let mut offset = 4;
        data[offset..offset + num_entries].copy_from_slice(&self.entries[..num_entries]);
        offset += num_entries;
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
        let mut entries = [0u8; 32];
        entries[..num_entries].copy_from_slice(&data[4..4 + num_entries]);
        Ok((
            Self {
                status,
                address,
                num_entries: data[3],
                entries,
            },
            4 + num_entries,
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
        assert_eq!(req.input_clusters_len(), 1);
        assert_eq!(req.input_clusters_entries()[0], 0x0019);
        assert_eq!(req.output_clusters_len(), 0);
    }

    #[test]
    fn unpack_match_descriptor_response() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x01];
        let (req, used) = MatchDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 5);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x0000);
        assert_eq!(req.len(), 1);
        assert_eq!(req.entries()[0], 0x01);
    }
}
