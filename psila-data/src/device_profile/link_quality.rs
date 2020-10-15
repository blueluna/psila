//! Link quality message

use core::convert::TryFrom;

use crate::common::address::{ExtendedAddress, ExtendedPanIdentifier, NetworkAddress};
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

extended_enum!(
    /// Node device type
    DeviceType, u8,
    /// The node is a network coordinator
    Coordinator => 0x00,
    /// The node is a router
    Router => 0x01,
    /// The node is a end-device
    EndDevice => 0x02,
    /// The node is of unknown type
    Unknown => 0x03,
);

impl Default for DeviceType {
    /// Initialise the device type as `DeviceType::Unknown`
    fn default() -> Self {
        DeviceType::Unknown
    }
}

extended_enum!(
    /// Whether the node receives when idle or not
    RxOnWhenIdle, u8,
    /// Receiver is disabled when idle
    Off => 0x00,
    /// Receiver is enabled when idle
    On => 0x01,
    /// The status of the reciver is unknown when idle
    Unknown => 0x02,
);

impl Default for RxOnWhenIdle {
    /// Initialise the receive on when idle as `RxOnWhenIdle::Unknown`
    fn default() -> Self {
        RxOnWhenIdle::Unknown
    }
}

extended_enum!(
    /// Relationship between nodes in the network
    Relationship, u8,
    /// The node is parent of the current node
    Parent => 0x00,
    /// The node is a child of the current node
    Child => 0x01,
    /// The node is a sibling of the current node
    Sibling => 0x02,
    /// The node is "none of above"
    NoneOfAbove => 0x03,
    /// The node was once a child of this node, but has left
    PreviousChild => 0x04,
);

impl Default for Relationship {
    /// Initialise the relationship as `Relationship::NoneOfAbove`
    fn default() -> Self {
        Relationship::NoneOfAbove
    }
}

extended_enum!(
    /// Permit join status
    PermitJoining, u8,
    /// Permits joins
    Yes => 0x00,
    /// Rejects joins
    No => 0x01,
    /// Unknown if the node permits joins
    Unknown => 0x02,
);

impl Default for PermitJoining {
    fn default() -> Self {
        PermitJoining::No
    }
}

/// Maximum number of neighbor nodes in `ManagementLinkQualityIndicatorResponse`
const NEIGHBOR_NODE_SIZE: usize = 22;

/// Neighbor information used in link quality indicator response
///
/// Holds various metrics for a node in the network
/// * The extended PAN identifier
/// * The extended address for the node
/// * The network address of the node
/// * The node device type
/// * If the node receives when in idle
/// * The relationship with this node
/// * If the node permits joins
/// * Network depth for the node, how many hops away the node is
/// * The link quanlity indication of the node
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Neighbor {
    /// Extended PAN identifier for which the node
    pub pan_identifier: ExtendedPanIdentifier,
    /// Extended address for the node
    pub extended_address: ExtendedAddress,
    /// Network address for the node
    pub network_address: NetworkAddress,
    /// Node device type
    pub device_type: DeviceType,
    /// Receive when idle configuration
    pub rx_idle: RxOnWhenIdle,
    /// Node relationship
    pub relationship: Relationship,
    /// Permit join configuration for node
    pub permit_joining: PermitJoining,
    /// Network depth for node
    pub depth: u8,
    /// Link quality for node
    pub link_quality: u8,
}

impl Pack<Neighbor, Error> for Neighbor {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < NEIGHBOR_NODE_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        self.pan_identifier.pack(&mut data[0..8])?;
        self.extended_address.pack(&mut data[8..16])?;
        self.network_address.pack(&mut data[16..18])?;
        data[18] =
            self.device_type as u8 | (self.rx_idle as u8) << 2 | (self.relationship as u8) << 4;
        // The order of permit_joining and depth might be different in older
        // versions of the standard
        data[19] = self.permit_joining as u8;
        data[20] = self.depth;
        data[21] = self.link_quality;
        Ok(NEIGHBOR_NODE_SIZE)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < NEIGHBOR_NODE_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let pan_identifier = ExtendedAddress::unpack(&data[0..8])?;
        let extended_address = ExtendedAddress::unpack(&data[8..16])?;
        let network_address = NetworkAddress::unpack(&data[16..18])?;
        let device_type = DeviceType::try_from(data[18] & 0b0000_0011)?;
        let rx_idle = RxOnWhenIdle::try_from((data[18] & 0b0000_1100) >> 2)?;
        let relationship = Relationship::try_from((data[18] & 0b0111_0000) >> 4)?;
        // The order of permit_joining and depth might be different in older
        // versions of the standard
        let permit_joining = PermitJoining::try_from(data[19] & 0b0000_0011)?;
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
            NEIGHBOR_NODE_SIZE,
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

/// Maximum number of neighbor nodes in `ManagementLinkQualityIndicatorResponse`
const NEIGHBOR_MAX_COUNT: usize = 32;
const MGMTLQIRSP_HEADER_SIZE: usize = 4;

/// Link quality indicator response
///
/// Reports status and a neighbor table. The neighbor table is a list of
/// `Neighbor` entries.
#[derive(Clone, Debug, PartialEq)]
pub struct ManagementLinkQualityIndicatorResponse {
    /// Response status
    pub status: Status,
    /// Total numer of neighbors
    pub neighbors_total: u8,
    /// Start index
    pub index: u8,
    /// Number of neighbors in the response
    num_neighbors: u8,
    /// Neighbors
    neighbors: [Neighbor; NEIGHBOR_MAX_COUNT],
}

impl ManagementLinkQualityIndicatorResponse {
    /// Indicates that there are no entries in the neighbor table
    pub fn is_empty(&self) -> bool {
        self.num_neighbors == 0
    }

    /// Number of entries in the neighbor table
    pub fn len(&self) -> usize {
        self.num_neighbors as usize
    }

    /// The neighbor table
    pub fn neighbors(&self) -> &[Neighbor] {
        &self.neighbors[..self.num_neighbors as usize]
    }
}

impl Pack<ManagementLinkQualityIndicatorResponse, Error>
    for ManagementLinkQualityIndicatorResponse
{
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let size = (self.num_neighbors as usize) * NEIGHBOR_NODE_SIZE + MGMTLQIRSP_HEADER_SIZE;
        if data.len() < size {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        data[1] = self.neighbors_total;
        data[2] = self.index;
        data[3] = self.num_neighbors;
        let mut offset = MGMTLQIRSP_HEADER_SIZE;
        for neighbor in self.neighbors.iter() {
            let used = neighbor.pack(&mut data[offset..])?;
            offset += used;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let neighbors_total = data[1];
        let index = data[2];
        let num_entries = data[3] as usize;
        if data.len() < MGMTLQIRSP_HEADER_SIZE + (num_entries * NEIGHBOR_NODE_SIZE) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = MGMTLQIRSP_HEADER_SIZE;
        let mut neighbors = [Neighbor::default(); NEIGHBOR_MAX_COUNT];
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
        assert_eq!(rsp.neighbors_total, 2);
        assert_eq!(rsp.index, 0);
        assert_eq!(rsp.len(), 2);
        assert_eq!(rsp.is_empty(), false);
        assert_eq!(
            rsp.neighbors()[0],
            Neighbor {
                pan_identifier: ExtendedPanIdentifier::new(0x0021_2eff_ff03_2e38),
                extended_address: ExtendedAddress::new(0x0021_2eff_ff03_2e38),
                network_address: NetworkAddress::new(0x0000),
                device_type: DeviceType::Coordinator,
                rx_idle: RxOnWhenIdle::On,
                relationship: Relationship::Parent,
                permit_joining: PermitJoining::Unknown,
                depth: 0,
                link_quality: 0x93,
            }
        );
        assert_eq!(
            rsp.neighbors()[1],
            Neighbor {
                pan_identifier: ExtendedPanIdentifier::new(0x0021_2eff_ff03_2e38),
                extended_address: ExtendedAddress::new(0x000d_6fff_fe21_ae85),
                network_address: NetworkAddress::new(0xc07b),
                device_type: DeviceType::EndDevice,
                rx_idle: RxOnWhenIdle::Off,
                relationship: Relationship::Child,
                permit_joining: PermitJoining::Unknown,
                depth: 2,
                link_quality: 0x81,
            }
        );
    }
}
