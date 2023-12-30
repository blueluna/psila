//! Node descriptor message

use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryFrom;

use crate::common::{address::NetworkAddress, capability_information::CapabilityInformation};
use crate::device_profile::{DeviceType, Status};
use crate::pack::{Pack, PackFixed};
use crate::Error;

bitflags! {
    /// Flags that denotes which bands used
    #[derive(Clone, Debug, PartialEq)]
    pub struct BandFlags: u8 {
        /// 868 MHz band
        const BAND_868MHZ = 0b0000_0001;
        /// 902 to 928 MHz bands
        const BAND_902TO928MHZ = 0b0000_0100;
        /// 2.4 GHz band
        const BAND_2400TO2483MHZ = 0b0000_1000;
    }
}

bitflags! {
    /// Server functionality flags
    #[derive(Clone, Debug, PartialEq)]
    pub struct ServerFlags: u8 {
        /// Primary trust center
        const PRIMARY_TRUST_CENTER      = 0b0000_0001;
        /// Backup trust center
        const BACKUP_TRUST_CENTER       = 0b0000_0010;
        /// Primary binding table
        const PRIMARY_BINDING_TABLE     = 0b0000_0100;
        /// Backup binding table
        const BACKUP_BINDING_TABLE      = 0b0000_1000;
        /// Primary discovery cache
        const PRIMARY_DISCOVERY_CACHE   = 0b0001_0000;
        /// Backup discovery cache
        const BACKUP_DISCOVERY_CACHE    = 0b0010_0000;
        /// Network manager
        const NETWORK_MANAGER           = 0b0100_0000;
    }
}

/// Server mask
#[derive(Clone, Debug, PartialEq)]
pub struct ServerMask {
    /// Server flags
    pub flags: ServerFlags,
    /// Stack complience version
    pub stack_complience_version: u8,
}

impl PackFixed<ServerMask, Error> for ServerMask {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.flags.bits();
        data[1] = (self.stack_complience_version & 0x7f) << 1;
        Ok(())
    }
    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        Ok(Self {
            flags: ServerFlags::from_bits_truncate(data[0]),
            stack_complience_version: (data[1] & 0xfe) >> 1,
        })
    }
}

impl Default for ServerMask {
    fn default() -> Self {
        Self {
            flags: ServerFlags::empty(),
            stack_complience_version: 0,
        }
    }
}

bitflags! {
    /// Descriptor capability
    #[derive(Clone, Debug, PartialEq)]
    pub struct DescriptorCapability: u8 {
        /// Extended active endpoint list available
        const EXTENDED_ACTIVE_END_POINT_LIST_AVAILABLE  = 0b0000_0001;
        /// Extended simple descriptor list available
        const EXTENDED_SIMPLE_DESCRIPTOR_LIST_AVAILABLE = 0b0000_0010;
    }
}

const COMPLEX_DESCRIPTOR: u8 = 0b0000_1000;
const USER_DESCRIPTOR: u8 = 0b0001_0000;

// 2.3.2.3 Node Descriptor
/// Node descriptor
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDescriptor {
    /// Node device type
    pub device_type: DeviceType,
    /// Node has a complex node descriptor
    pub complex_descriptor: bool,
    /// Node has a user descriptor
    pub user_descriptor: bool,
    /// Which frequency bands the node supports
    pub frequency_bands: BandFlags,
    /// The MAC capabilities of the node
    pub mac_capability: CapabilityInformation,
    /// Manufacturer code of the node
    pub manufacturer_code: u16,
    /// Maximum size of a Network package
    pub maximum_buffer_size: u8,
    /// Maximum size of a received application package
    pub maximum_incoming_transfer_size: u16,
    /// Server mask field
    pub server_mask: ServerMask,
    /// Maximum size of a sent application package
    pub maximum_outgoing_transfer_size: u16,
    /// Descriptor capabilities
    pub descriptor_capability: DescriptorCapability,
}

impl PackFixed<NodeDescriptor, Error> for NodeDescriptor {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 13 {
            return Err(Error::WrongNumberOfBytes);
        }
        let _complex_descriptor = if self.complex_descriptor {
            COMPLEX_DESCRIPTOR
        } else {
            0
        };
        let _user_descriptor = if self.user_descriptor {
            USER_DESCRIPTOR
        } else {
            0
        };
        data[0] = (self.device_type as u8) & 0x03 | _complex_descriptor | _user_descriptor;
        data[1] = self.frequency_bands.bits() << 3;
        data[2] = u8::from(self.mac_capability);
        LittleEndian::write_u16(&mut data[3..5], self.manufacturer_code);
        data[5] = self.maximum_buffer_size;
        LittleEndian::write_u16(&mut data[6..8], self.maximum_incoming_transfer_size);
        self.server_mask.pack(&mut data[8..10])?;
        LittleEndian::write_u16(&mut data[10..12], self.maximum_outgoing_transfer_size);
        data[12] = self.descriptor_capability.bits();
        Ok(())
    }
    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 13 {
            return Err(Error::WrongNumberOfBytes);
        }
        let device_type = DeviceType::try_from(data[0] & 0x03)?;
        let complex_descriptor = data[0] & COMPLEX_DESCRIPTOR == COMPLEX_DESCRIPTOR;
        let user_descriptor = data[0] & USER_DESCRIPTOR == USER_DESCRIPTOR;
        let frequency_bands = BandFlags::from_bits_truncate(data[1] >> 3);
        let mac_capability = CapabilityInformation::from(data[2]);
        let manufacturer_code = LittleEndian::read_u16(&data[3..5]);
        let maximum_buffer_size = data[5];
        let maximum_incoming_transfer_size = LittleEndian::read_u16(&data[6..8]);
        let server_mask = ServerMask::unpack(&data[8..10])?;
        let maximum_outgoing_transfer_size = LittleEndian::read_u16(&data[10..12]);
        let descriptor_capability = DescriptorCapability::from_bits_truncate(data[12]);
        Ok(Self {
            device_type,
            complex_descriptor,
            user_descriptor,
            frequency_bands,
            mac_capability,
            manufacturer_code,
            maximum_buffer_size,
            maximum_incoming_transfer_size,
            server_mask,
            maximum_outgoing_transfer_size,
            descriptor_capability,
        })
    }
}

impl Default for NodeDescriptor {
    fn default() -> Self {
        Self {
            device_type: DeviceType::default(),
            complex_descriptor: false,
            user_descriptor: false,
            frequency_bands: BandFlags::empty(),
            mac_capability: CapabilityInformation::default(),
            manufacturer_code: 0,
            maximum_buffer_size: 0,
            maximum_incoming_transfer_size: 0,
            server_mask: ServerMask::default(),
            maximum_outgoing_transfer_size: 0,
            descriptor_capability: DescriptorCapability::empty(),
        }
    }
}

// 2.4.3.1.3 Node_Desc_req
/// Node descriptor request
/// Requests the node descriptor for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDescriptorRequest {
    /// Device address
    pub address: NetworkAddress,
}

impl Pack<NodeDescriptorRequest, Error> for NodeDescriptorRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 2 {
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

// 2.4.4.2.3 Node_Desc_rsp
/// Node descriptor response
/// Respond to a node descriptor request
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDescriptorResponse {
    /// Response status
    pub status: Status,
    /// Device address
    pub address: NetworkAddress,
    /// Node descriptor
    pub descriptor: NodeDescriptor,
}

impl NodeDescriptorResponse {
    /// Create a failure response
    pub fn failure_response(status: Status, address: NetworkAddress) -> Self {
        assert!(status != Status::Success);
        NodeDescriptorResponse {
            status,
            address,
            descriptor: NodeDescriptor::default(),
        }
    }
}

impl Pack<NodeDescriptorResponse, Error> for NodeDescriptorResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let size = if self.status == Status::Success {
            16
        } else {
            3
        };
        if data.len() < size {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        self.address.pack(&mut data[1..3])?;
        if self.status == Status::Success {
            self.descriptor.pack(&mut data[3..16])?;
        }
        Ok(size)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let address = NetworkAddress::unpack(&data[1..3])?;
        let (descriptor, size) = if status == Status::Success {
            if data.len() < 16 {
                return Err(Error::WrongNumberOfBytes);
            }
            (NodeDescriptor::unpack(&data[3..16])?, 16)
        } else {
            (NodeDescriptor::default(), 3)
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
    fn unpack_server_mask() {
        let data = [0x55, 0x42];
        let server_mask = ServerMask::unpack(&data[..]).unwrap();
        assert_eq!(
            server_mask.flags,
            ServerFlags::PRIMARY_TRUST_CENTER
                | ServerFlags::PRIMARY_BINDING_TABLE
                | ServerFlags::PRIMARY_DISCOVERY_CACHE
                | ServerFlags::NETWORK_MANAGER
        );
        assert_eq!(server_mask.stack_complience_version, 0x21);

        let data = [0x2a, 0xf0];
        let server_mask = ServerMask::unpack(&data[..]).unwrap();
        assert_eq!(
            server_mask.flags,
            ServerFlags::BACKUP_TRUST_CENTER
                | ServerFlags::BACKUP_BINDING_TABLE
                | ServerFlags::BACKUP_DISCOVERY_CACHE
        );
        assert_eq!(server_mask.stack_complience_version, 0x78);

        let data = [0x00, 0x00];
        let server_mask = ServerMask::unpack(&data[..]).unwrap();
        assert_eq!(server_mask.flags, ServerFlags::empty());
        assert_eq!(server_mask.stack_complience_version, 0x00);

        let data = [0xff, 0xff];
        let server_mask = ServerMask::unpack(&data[..]).unwrap();
        assert_eq!(server_mask.flags, ServerFlags::all());
        assert_eq!(server_mask.stack_complience_version, 0x7f);

        let data = [0x7f, 0xfe];
        let server_mask = ServerMask::unpack(&data[..]).unwrap();
        assert_eq!(server_mask.flags, ServerFlags::all());
        assert_eq!(server_mask.stack_complience_version, 0x7f);
    }

    #[test]
    fn pack_server_mask() {
        let server_mask = ServerMask {
            flags: ServerFlags::PRIMARY_TRUST_CENTER
                | ServerFlags::PRIMARY_BINDING_TABLE
                | ServerFlags::PRIMARY_DISCOVERY_CACHE
                | ServerFlags::NETWORK_MANAGER,
            stack_complience_version: 0x21,
        };
        let mut data = [0u8; 2];
        server_mask.pack(&mut data[..]).unwrap();
        assert_eq!(data, [0x55, 0x42]);

        let server_mask = ServerMask {
            flags: ServerFlags::BACKUP_TRUST_CENTER
                | ServerFlags::BACKUP_BINDING_TABLE
                | ServerFlags::BACKUP_DISCOVERY_CACHE,
            stack_complience_version: 0x78,
        };
        let mut data = [0u8; 2];
        server_mask.pack(&mut data[..]).unwrap();
        assert_eq!(data, [0x2a, 0xf0]);

        let server_mask = ServerMask {
            flags: ServerFlags::empty(),
            stack_complience_version: 0,
        };
        let mut data = [0u8; 2];
        server_mask.pack(&mut data[..]).unwrap();
        assert_eq!(data, [0, 0]);

        let server_mask = ServerMask {
            flags: ServerFlags::all(),
            stack_complience_version: 0xff,
        };
        let mut data = [0u8; 2];
        server_mask.pack(&mut data[..]).unwrap();
        assert_eq!(data, [0x7f, 0xfe]);
    }

    #[test]
    fn unpack_node_descriptor_request() {
        let data = [0x96, 0x1f];
        let (req, used) = NodeDescriptorRequest::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(req.address, 0x1f96);
    }

    #[test]
    fn pack_node_descriptor_request() {
        let request = NodeDescriptorRequest {
            address: NetworkAddress::from(0x1376),
        };
        let mut data = [0u8; 2];
        let used = request.pack(&mut data[..]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(data, [0x76, 0x13]);
    }

    #[test]
    fn unpack_node_descriptor_response_success() {
        let data = [
            0x00, 0x96, 0x1f, 0x02, 0x40, 0x80, 0x7c, 0x11, 0x52, 0x52, 0x00, 0x00, 0xe6, 0x52,
            0x00, 0x00,
        ];
        let (req, used) = NodeDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 16);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x1f96);
        assert_eq!(req.descriptor.device_type, DeviceType::EndDevice);
        assert_eq!(req.descriptor.complex_descriptor, false);
        assert_eq!(req.descriptor.user_descriptor, false);
        assert_eq!(
            req.descriptor.frequency_bands,
            BandFlags::BAND_2400TO2483MHZ
        );
        assert_eq!(
            req.descriptor.mac_capability.alternate_pan_coordinator,
            false
        );
        assert_eq!(req.descriptor.mac_capability.router_capable, false);
        assert_eq!(req.descriptor.mac_capability.mains_power, false);
        assert_eq!(req.descriptor.mac_capability.idle_receive, false);
        assert_eq!(req.descriptor.mac_capability.frame_protection, false);
        assert_eq!(req.descriptor.mac_capability.allocate_address, true);
        assert_eq!(req.descriptor.manufacturer_code, 0x117c);
        assert_eq!(req.descriptor.maximum_buffer_size, 82);
        assert_eq!(req.descriptor.maximum_incoming_transfer_size, 82);
        assert_eq!(req.descriptor.server_mask.flags.bits(), 0);
        assert_eq!(req.descriptor.server_mask.stack_complience_version, 0x73);
        assert_eq!(req.descriptor.maximum_outgoing_transfer_size, 82);
        assert_eq!(req.descriptor.descriptor_capability.bits(), 0);
    }

    #[test]
    fn unpack_node_descriptor_response_error() {
        let data = [0x80, 0x96, 0x1f];
        let (req, used) = NodeDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(req.status, Status::InvalidRequestType);
        assert_eq!(req.address, 0x1f96);
    }

    #[test]
    fn pack_node_descriptor_response_success() {
        let mac_capability = CapabilityInformation {
            alternate_pan_coordinator: false,
            router_capable: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: true,
        };
        let server_mask = ServerMask {
            flags: ServerFlags::empty(),
            stack_complience_version: 0x21,
        };
        let descriptor = NodeDescriptor {
            device_type: DeviceType::EndDevice,
            complex_descriptor: false,
            user_descriptor: false,
            frequency_bands: BandFlags::BAND_2400TO2483MHZ,
            mac_capability,
            manufacturer_code: 0x1234,
            maximum_buffer_size: 0x20,
            maximum_incoming_transfer_size: 0x20,
            server_mask,
            maximum_outgoing_transfer_size: 0x20,
            descriptor_capability: DescriptorCapability::empty(),
        };
        let response = NodeDescriptorResponse {
            status: Status::Success,
            address: NetworkAddress::from(0x1376),
            descriptor,
        };
        let mut data = [0u8; 16];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 16);
        assert_eq!(
            data,
            [
                0x00, 0x76, 0x13, 0x02, 0x40, 0x80, 0x34, 0x12, 0x20, 0x20, 0x00, 0x00, 0x42, 0x20,
                0x00, 0x00
            ]
        );
    }

    #[test]
    fn pack_node_descriptor_response_error() {
        let response = NodeDescriptorResponse {
            status: Status::InvalidRequestType,
            address: NetworkAddress::from(0x1376),
            descriptor: NodeDescriptor::default(),
        };
        let mut data = [0u8; 3];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(data, [0x80, 0x76, 0x13]);
    }
}
