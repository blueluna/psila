use core::convert::TryFrom;

use crate::common::address::{ExtendedAddress, NetworkAddress};
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

extended_enum!(
	DeviceType, u8,
	Coordinator => 0x00,
	Router => 0x01,
    EndDevice => 0x02,
    Unknown => 0x03,
);

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::Unknown
    }
}

extended_enum!(
    RxOnWhenIdle, u8,
    Off => 0x00,
    On => 0x01,
    Unknown => 0x02,
);

impl Default for RxOnWhenIdle {
    fn default() -> Self {
        RxOnWhenIdle::Unknown
    }
}

extended_enum!(
    Relationship, u8,
    Parent => 0x00,
    Child => 0x01,
    Sibling => 0x02,
    NoneOfAbove => 0x03,
    PreviousChild => 0x04,
);

impl Default for Relationship {
    fn default() -> Self {
        Relationship::NoneOfAbove
    }
}

extended_enum!(
    PermitJoining, u8,
    Yes => 0x00,
    No => 0x01,
    Unknown => 0x02,
);

impl Default for PermitJoining {
    fn default() -> Self {
        PermitJoining::No
    }
}

// 2.4.3.1.1 NWK_addr_req
/// Network address request
/// Requests the network address for a remote device
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Neighbor {
    pub pan_identifier: ExtendedAddress,
    pub extended_address: ExtendedAddress,
    pub network_address: NetworkAddress,
    pub device_type: DeviceType,
    pub rx_idle: RxOnWhenIdle,
    pub relationship: Relationship,
    pub permit_joining: PermitJoining,
    pub depth: u8,
    pub link_quality: u8,
}

impl Pack<Neighbor, Error> for Neighbor {
    fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 22 {
            return Err(Error::WrongNumberOfBytes);
        }
        let pan_identifier = ExtendedAddress::unpack(&data[0..8])?;
        let extended_address = ExtendedAddress::unpack(&data[8..16])?;
        let network_address = NetworkAddress::unpack(&data[16..18])?;
        let device_type = DeviceType::try_from(data[18] & 0b0000_0011)?;
        let rx_idle = RxOnWhenIdle::try_from((data[18] & 0b0000_1100) >> 2)?;
        let relationship = Relationship::try_from((data[18] & 0b0111_0000) >> 4)?;
        let permit_joining = PermitJoining::try_from((data[19] & 0b1100_0000) >> 6)?;
        Ok((
            Self {
                pan_identifier,
                extended_address,
                network_address,
                device_type,
                rx_idle,
                relationship,
                permit_joining,
                depth: data[20],
                link_quality: data[21],
            },
            22,
        ))
    }
}

impl Default for Neighbor {
    fn default() -> Self {
        Self {
            pan_identifier: ExtendedAddress::default(),
            extended_address: ExtendedAddress::default(),
            network_address: NetworkAddress::default(),
            device_type: DeviceType::default(),
            rx_idle: RxOnWhenIdle::default(),
            relationship: Relationship::default(),
            permit_joining: PermitJoining::default(),
            depth: 0,
            link_quality: 0,
        }
    }
}

/// Network and IEEE address response
///
#[derive(Clone, Debug, PartialEq)]
pub struct ManagementLinkQualityIndicatorResponse {
    pub status: Status,
    pub neighbors_total: u8,
    pub index: u8,
    num_neighbors: u8,
    neighbors: [Neighbor; 16],
}

impl ManagementLinkQualityIndicatorResponse {
    pub fn is_empty(&self) -> bool {
        self.num_neighbors == 0
    }

    pub fn len(&self) -> usize {
        self.num_neighbors as usize
    }

    pub fn neighbors(&self) -> &[Neighbor] {
        &self.neighbors[..self.num_neighbors as usize]
    }
}

impl Pack<ManagementLinkQualityIndicatorResponse, Error>
    for ManagementLinkQualityIndicatorResponse
{
    fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let neighbors_total = data[1];
        let index = data[2];
        let num_entries = data[3] as usize;
        if data.len() < 4 + (num_entries * 22) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 4;
        let mut neighbors = [Neighbor::default(); 16];
        for neighbor in neighbors[..num_entries].iter_mut() {
            let (n, used) = Neighbor::unpack(&data[offset..])?;
            *neighbor = n;
            offset += used;
        }
        Ok((
            Self {
                status,
                neighbors_total,
                index,
                num_neighbors: data[3],
                neighbors,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_link_quality_inicator_response() {
        let data = [
            0x00, 0x02, 0x00, 0x02, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x38, 0x2e,
            0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x93, 0x38, 0x2e,
            0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00,
            0x7b, 0xc0, 0x12, 0x02, 0x02, 0x81,
        ];
        let (rsp, used) = ManagementLinkQualityIndicatorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 48);
        assert_eq!(rsp.status, Status::Success);
    }
}
