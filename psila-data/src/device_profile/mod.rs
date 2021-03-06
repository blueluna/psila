//! # Device Profile (ZDP)

mod active_endpoints;
mod device_announce;
pub mod link_quality;
mod match_descriptor;
mod network_address;
pub mod node_descriptor;
pub mod power_descriptor;
mod simple_descriptor;

pub use active_endpoints::{ActiveEndpointRequest, ActiveEndpointResponse};
pub use device_announce::DeviceAnnounce;
pub use link_quality::{DeviceType, ManagementLinkQualityIndicatorResponse};
pub use match_descriptor::{MatchDescriptorRequest, MatchDescriptorResponse};
pub use network_address::{AddressResponse, ExtendedAddressRequest, NetworkAddressRequest};
pub use node_descriptor::{NodeDescriptor, NodeDescriptorRequest, NodeDescriptorResponse};
pub use power_descriptor::{NodePowerDescriptor, PowerDescriptorRequest, PowerDescriptorResponse};
pub use simple_descriptor::{SimpleDescriptor, SimpleDescriptorRequest, SimpleDescriptorResponse};

use core::convert::TryFrom;

use crate::error::Error;
use crate::pack::Pack;

/// Response flag
pub const RESPONSE: u16 = 0x8000;

// 2.4.2 Device Profile Overview
extended_enum!(
    /// Device profile cluster identifiers
    ClusterIdentifier, u16,
    /// Request the network address of another device
    NetworkAddressRequest => 0x0000,
    /// Request the extended (IEEE) address of another device
    ExtendedAddressRequest => 0x0001,
    /// Request the node descriptor of another device
    NodeDescriptorRequest => 0x0002,
    /// Request the power descriptor of another device
    PowerDescriptorRequest => 0x0003,
    /// Request the simple descriptor of another device
    SimpleDescriptorRequest => 0x0004,
    /// Request the active endpoints of another device
    ActiveEndpointRequest => 0x0005,
    /// Find other devices that match the criteria
    MatchDescriptorRequest => 0x0006,
    /// Get the complex descriptor
    ComplexDescriptorRequest => 0x0010,
    /// Get user descriptor
    UserDescriptorRequest => 0x0011,
    /// Discovery cache request
    DiscoveryCacheRequest => 0x0012,
    /// Device announcement notification
    DeviceAnnounce => 0x0013,
    /// Set user descipor
    SetUserDescriptor => 0x0014,
    /// System server discovery request
    SystemServerDiscoveryRequest => 0x0015,
    /// Discovery cache storage request
    DiscoveryCacheStorageRequest => 0x0016,
    /// Node descriptor storage requst
    NodeDescriptorStorageRequest => 0x0017,
    /// Power descriptor storage request
    PowerDescriptorStorageRequest => 0x0018,
    /// Active endpoint storage request
    ActiveEndpointStorageRequest => 0x0019,
    /// Simple descriptor storage request
    SimpleDescriptorStorageRequest => 0x001a,
    /// Remove node cache
    RemoveNodeCache => 0x001b,
    /// Find node cache
    FindNodeCache => 0x001c,
    /// Estended simple descriptor request
    ExtendedSimpleDescriptorRequest => 0x001d,
    /// Extended active endpoint request
    ExtendedActiveEndpointRequest => 0x001e,
    /// Parent announce
    ParentAnnounce => 0x001f,
    /// End-device bind request
    EndDeviceBindRequest => 0x0020,
    /// Bind request
    BindRequest => 0x0021,
    /// Unbind request
    UnbindRequest => 0x0022,
    /// Bind register request
    BindRegisterRequest => 0x0023,
    /// Replace device request
    ReplaceDeviceRequest => 0x0024,
    /// Store backup bind entry request
    StoreBackupBindEntryRequest => 0x0025,
    /// Remove backup bind entry request
    RemoveBackupBindEntryRequest => 0x0026,
    /// Backup bind table request
    BackupBindTableRequest => 0x0027,
    /// Recover bind table request
    RecoverBindTableRequest => 0x0028,
    /// Backup source bind request
    BackupSourceBindRequest => 0x0029,
    /// Recover source bind request
    RecoverSourceBindRequest => 0x002a,
    /// Management network discovery request
    ManagementNetworkDiscoveryRequest => 0x0030,
    /// Management link quality indicator (LQI) request
    ManagementLinkQualityIndicatorRequest => 0x0031,
    /// Management routing table request
    ManagementRoutingTableRequest => 0x0032,
    /// Management binding table request
    ManagementBindingTableRequest => 0x0033,
    /// Management leave request
    ManagementLeaveRequest => 0x0034,
    /// Management direct join request
    ManagementDirectJoinRequest => 0x0035,
    /// Management permit joining request
    ManagementPermitJoiningRequest => 0x0036,
    /// Management cache request
    ManagementCacheRequest => 0x0037,
    /// Management network update request
    ManagementNetworkUpdateRequest => 0x0038,
);

// 2.4.5 ZDP Enumeration Description
extended_enum!(
    /// Response status codes
    Status, u8,
    /// Request succeeded
    Success => 0x00,
    /// The supplied request type was invalid
    InvalidRequestType => 0x80,
    /// The requested device cannot be found
    DeviceNotFound => 0x81,
    /// The provided endpoint is invalid (0x00 or 0xff)
    InvalidEndpoint => 0x82,
    /// Endpoint is not described by a simple descriptor
    NotActive => 0x83,
    /// The requested optional feature is not supported by this device
    NotSupported => 0x84,
    /// The request timed out
    Timeout => 0x85,
    /// Bind request was unsuccessful because the requested cluster was not found
    NoMatch => 0x86,
    /// Failed to unbind because lack of binding entries
    NoEntry => 0x88,
    /// The child descriptor is not available to the parent
    NoDescriptor => 0x89,
    /// The device do not have sufficient storafe to support the request
    InsufficientSpace => 0x8a,
    /// The device could not complete the operation at this time
    NotPermitted => 0x8b,
    /// The device could not complete the operation since the table is full
    TableFull => 0x8c,
    /// The device was not authorised to complete the operation
    NotAuthorised => 0x8d,
    /// The device could not complete the operation because the device binding table is full
    DeviceBindingTableFull => 0x8e,
    /// The requested index was not found
    InvalidIndex => 0x8f,
);

/// Device profile message
#[derive(Clone, Debug, PartialEq)]
pub enum DeviceProfileMessage {
    /// Request the network address of another device
    NetworkAddressRequest(NetworkAddressRequest),
    /// Network address response
    NetworkAddressResponse(AddressResponse),
    /// Request the Extended (IEEE) address of another device
    ExtendedAddressRequest(ExtendedAddressRequest),
    /// Extended (IEEE) address response
    ExtendedAddressResponse(AddressResponse),
    /// Request the node descriptor of another device
    NodeDescriptorRequest(NodeDescriptorRequest),
    /// Response to a node descriptor request
    NodeDescriptorResponse(NodeDescriptorResponse),
    /// Request the power descriptor of another device
    PowerDescriptorRequest(PowerDescriptorRequest),
    /// Response to a power descriptor request
    PowerDescriptorResponse(PowerDescriptorResponse),
    /// Request the endpoint simple desciptor of another device
    SimpleDescriptorRequest(SimpleDescriptorRequest),
    /// Response to a endpoint simple descriptor request
    SimpleDescriptorResponse(SimpleDescriptorResponse),
    /// Request the active endpoints of another device
    ActiveEndpointRequest(ActiveEndpointRequest),
    /// Response to a active endpoints request
    ActiveEndpointResponse(ActiveEndpointResponse),
    /// Find other devices that match the criteria
    MatchDescriptorRequest(MatchDescriptorRequest),
    /// Response to a match descriptor request
    MatchDescriptorResponse(MatchDescriptorResponse),
    /// Device announcement notification
    DeviceAnnounce(DeviceAnnounce),
    /// Management link quality indicator (LQI) request
    /// Message contains the start index as u8
    ManagementLinkQualityIndicatorRequest(u8),
    /// Response to management link quality indicator request
    ManagementLinkQualityIndicatorResponse(ManagementLinkQualityIndicatorResponse),
}

impl DeviceProfileMessage {
    /// Pack device profile message into a byte slice
    pub fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        match *self {
            DeviceProfileMessage::NetworkAddressRequest(ref m) => m.pack(data),
            DeviceProfileMessage::NetworkAddressResponse(ref m) => m.pack(data),
            DeviceProfileMessage::ExtendedAddressRequest(ref m) => m.pack(data),
            DeviceProfileMessage::ExtendedAddressResponse(ref m) => m.pack(data),
            DeviceProfileMessage::NodeDescriptorRequest(ref m) => m.pack(data),
            DeviceProfileMessage::NodeDescriptorResponse(ref m) => m.pack(data),
            DeviceProfileMessage::PowerDescriptorRequest(ref m) => m.pack(data),
            DeviceProfileMessage::PowerDescriptorResponse(ref m) => m.pack(data),
            DeviceProfileMessage::SimpleDescriptorRequest(ref m) => m.pack(data),
            DeviceProfileMessage::SimpleDescriptorResponse(ref m) => m.pack(data),
            DeviceProfileMessage::ActiveEndpointRequest(ref m) => m.pack(data),
            DeviceProfileMessage::ActiveEndpointResponse(ref m) => m.pack(data),
            DeviceProfileMessage::MatchDescriptorRequest(ref m) => m.pack(data),
            DeviceProfileMessage::MatchDescriptorResponse(ref m) => m.pack(data),
            DeviceProfileMessage::DeviceAnnounce(ref m) => m.pack(data),
            DeviceProfileMessage::ManagementLinkQualityIndicatorResponse(ref m) => m.pack(data),
            DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(ref m) => {
                data[0] = *m;
                Ok(1)
            }
        }
    }
    /// Unpack byte slice into a device profile message
    pub fn unpack(data: &[u8], cluster_identifier: u16) -> Result<(Self, usize), Error> {
        let response = (cluster_identifier & RESPONSE) == RESPONSE;
        let cluster_identifier = ClusterIdentifier::try_from(cluster_identifier & 0x7fff)?;
        if response {
            match cluster_identifier {
                ClusterIdentifier::NetworkAddressRequest => {
                    let (rsp, used) = AddressResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::NetworkAddressResponse(rsp), used))
                }
                ClusterIdentifier::ExtendedAddressRequest => {
                    let (rsp, used) = AddressResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::ExtendedAddressResponse(rsp), used))
                }
                ClusterIdentifier::NodeDescriptorRequest => {
                    let (rsp, used) = NodeDescriptorResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::NodeDescriptorResponse(rsp), used))
                }
                ClusterIdentifier::PowerDescriptorRequest => {
                    let (rsp, used) = PowerDescriptorResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::PowerDescriptorResponse(rsp), used))
                }
                ClusterIdentifier::SimpleDescriptorRequest => {
                    let (rsp, used) = SimpleDescriptorResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::SimpleDescriptorResponse(rsp), used))
                }
                ClusterIdentifier::ActiveEndpointRequest => {
                    let (rsp, used) = ActiveEndpointResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::ActiveEndpointResponse(rsp), used))
                }
                ClusterIdentifier::MatchDescriptorRequest => {
                    let (rsp, used) = MatchDescriptorResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::MatchDescriptorResponse(rsp), used))
                }
                ClusterIdentifier::ManagementLinkQualityIndicatorRequest => {
                    let (rsp, used) = ManagementLinkQualityIndicatorResponse::unpack(&data)?;
                    Ok((
                        DeviceProfileMessage::ManagementLinkQualityIndicatorResponse(rsp),
                        used,
                    ))
                }
                ClusterIdentifier::DeviceAnnounce => Err(Error::UnknownClusterIdentifier),
                _ => Err(Error::NotImplemented),
            }
        } else {
            match cluster_identifier {
                ClusterIdentifier::NetworkAddressRequest => {
                    let (req, used) = NetworkAddressRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::NetworkAddressRequest(req), used))
                }
                ClusterIdentifier::ExtendedAddressRequest => {
                    let (req, used) = ExtendedAddressRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::ExtendedAddressRequest(req), used))
                }
                ClusterIdentifier::NodeDescriptorRequest => {
                    let (req, used) = NodeDescriptorRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::NodeDescriptorRequest(req), used))
                }
                ClusterIdentifier::PowerDescriptorRequest => {
                    let (req, used) = PowerDescriptorRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::PowerDescriptorRequest(req), used))
                }
                ClusterIdentifier::SimpleDescriptorRequest => {
                    let (req, used) = SimpleDescriptorRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::SimpleDescriptorRequest(req), used))
                }
                ClusterIdentifier::ActiveEndpointRequest => {
                    let (req, used) = ActiveEndpointRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::ActiveEndpointRequest(req), used))
                }
                ClusterIdentifier::MatchDescriptorRequest => {
                    let (req, used) = MatchDescriptorRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::MatchDescriptorRequest(req), used))
                }
                ClusterIdentifier::DeviceAnnounce => {
                    let (req, used) = DeviceAnnounce::unpack(&data)?;
                    Ok((DeviceProfileMessage::DeviceAnnounce(req), used))
                }
                ClusterIdentifier::ManagementLinkQualityIndicatorRequest => {
                    if data.is_empty() {
                        return Err(Error::WrongNumberOfBytes);
                    }
                    Ok((
                        DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(data[0]),
                        1,
                    ))
                }
                _ => Err(Error::NotImplemented),
            }
        }
    }
}

/// Device profile frame
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceProfileFrame {
    /// Transaction sequence
    pub transaction_sequence: u8,
    /// Device profile message
    pub message: DeviceProfileMessage,
}

impl DeviceProfileFrame {
    /// Pack device profile frame into byte slice
    pub fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.transaction_sequence;
        let used = self.message.pack(&mut data[1..])?;
        Ok(1 + used)
    }
    /// Unpack byte slice into device profile frame
    pub fn unpack(data: &[u8], cluster_identifier: u16) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let transaction_sequence = data[0];
        let (message, used) = DeviceProfileMessage::unpack(&data[1..], cluster_identifier)?;
        Ok((
            Self {
                transaction_sequence,
                message,
            },
            1 + used,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_device_announce() {
        let cluster_identifier = 0x0013;
        let data = [
            0x81, 0x6a, 0x6a, 0xc1, 0xe9, 0x1f, 0x00, 0x00, 0xff, 0x0f, 0x00, 0x8e,
        ];
        let (zdp, used) = DeviceProfileFrame::unpack(&data[..], cluster_identifier).unwrap();
        assert_eq!(used, 12);
        assert_eq!(zdp.transaction_sequence, 0x81);
        match zdp.message {
            DeviceProfileMessage::DeviceAnnounce(ref da) => {
                assert_eq!(da.network_address, [0x6a, 0x6a]);
                assert_eq!(
                    da.extended_address,
                    [0xc1, 0xe9, 0x1f, 0x00, 0x00, 0xff, 0x0f, 0x00]
                );
                assert_eq!(da.capability.alternate_pan_coordinator, false);
                assert_eq!(da.capability.router_capable, true);
                assert_eq!(da.capability.mains_power, true);
                assert_eq!(da.capability.idle_receive, true);
                assert_eq!(da.capability.frame_protection, false);
                assert_eq!(da.capability.allocate_address, true);
            }
            _ => {
                unreachable!();
            }
        }
    }

    #[test]
    fn unpack_link_quality_indicator_request() {
        let cluster_identifier = 0x0031;
        let data = [0x2a, 0x00];
        let (zdp, used) = DeviceProfileFrame::unpack(&data[..], cluster_identifier).unwrap();
        assert_eq!(used, 2);
        assert_eq!(zdp.transaction_sequence, 0x2a);
        match zdp.message {
            DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(ref index) => {
                assert_eq!(*index, 0x00);
            }
            _ => {
                unreachable!();
            }
        }
    }

    #[test]
    fn pack_device_announce() {
        use crate::{CapabilityInformation, ExtendedAddress, NetworkAddress};

        let device_announce = DeviceAnnounce {
            network_address: NetworkAddress::new(0x3289),
            extended_address: ExtendedAddress::new(0x0123_4567_89ab_cdef),
            capability: CapabilityInformation {
                alternate_pan_coordinator: false,
                router_capable: false,
                mains_power: true,
                idle_receive: true,
                frame_protection: false,
                allocate_address: true,
            },
        };
        let message = DeviceProfileMessage::DeviceAnnounce(device_announce);
        let frame = DeviceProfileFrame {
            transaction_sequence: 0x52,
            message,
        };

        let mut buffer = [0u8; 128];
        let size = frame.pack(&mut buffer).unwrap();

        assert_eq!(size, 12);
        assert_eq!(buffer[0], 0x52);
        assert_eq!(buffer[1..=2], [0x89, 0x32]);
        assert_eq!(
            buffer[3..=10],
            [0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(buffer[11], 0x8c);
    }

    #[test]
    fn pack_link_quality_indicator_request() {
        let message = DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(0x07);
        let frame = DeviceProfileFrame {
            transaction_sequence: 0xcc,
            message,
        };

        let mut buffer = [0u8; 128];
        let size = frame.pack(&mut buffer).unwrap();

        assert_eq!(size, 2);
        assert_eq!(buffer[0], 0xcc); // transaction sequence
        assert_eq!(buffer[1], 0x07); // index
    }
}
