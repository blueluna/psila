mod device_announce;
mod link_quality;
mod match_descriptor;
mod network_address;
mod node_descriptor;

pub use device_announce::DeviceAnnounce;
pub use link_quality::ManagementLinkQualityIndicatorResponse;
pub use match_descriptor::{MatchDescriptorRequest, MatchDescriptorResponse};
pub use network_address::{AddressResponse, IeeeAddressRequest, NetworkAddressRequest};
pub use node_descriptor::NodeDescriptorRequest;

use core::convert::TryFrom;

use crate::error::Error;
use crate::pack::Pack;

const RESPONSE: u16 = 0x8000;

// 2.4.2 Device Profile Overview
extended_enum!(
	/// Device profile cluster identifiers
	ClusterIdentifier, u16,
	NetworkAddressRequest => 0x0000,
	IeeeAddressRequest => 0x0001,
	NodeDescriptorRequest => 0x0002,
	PowerDescriptorRequest => 0x0003,
	SimpleDescriptorRequest => 0x0004,
	ActiveEndpointRequest => 0x0005,
	MatchDescriptorRequest => 0x0006,
	ComplexDescriptorRequest => 0x0010,
	UserDescriptorRequest => 0x0011,
	DiscoveryCacheRequest => 0x0012,
	// No response
	DeviceAnnounce => 0x0013,
	SetUserDescriptor => 0x0014,
	SystemServerDiscoveryRequest => 0x0015,
	DiscoveryCacheStorageRequest => 0x0016,
	NodeDescriptorStorageRequest => 0x0017,
	PowerDescriptorStorageRequest => 0x0018,
	ActiveEndpointStorageRequest => 0x0019,
	SimpleDescriptorStorageRequest => 0x001a,
	RemoveNodeCache => 0x001b,
	FindNodeCache => 0x001c,
	ExtendedSimpleDescriptorRequest => 0x001d,
	ExtendedActiveEndpointRequest => 0x001e,
	ParentAnnounce => 0x001f,
	EndDeviceBindRequest => 0x0020,
	BindRequest => 0x0021,
	UnbindRequest => 0x0022,
	BindRegisterRequest => 0x0023,
	ReplaceDeviceRequest => 0x0024,
	StoreBackupBindEntryRequest => 0x0025,
	RemoveBackupBindEntryRequest => 0x0026,
	BackupBindTableRequest => 0x0027,
	RecoverBindTableRequest => 0x0028,
	BackupSourceBindRequest => 0x0029,
	RecoverSourceBindRequest => 0x002a,
	ManagementNetworkDiscoveryRequest => 0x0030,
	ManagementLinkQualityIndicatorRequest => 0x0031,
	ManagementRoutingTableRequest => 0x0032,
	ManagementBindingTableRequest => 0x0033,
	ManagementLeaveRequest => 0x0034,
	ManagementDirectJoinRequest => 0x0035,
	ManagementPermitJoiningRequest => 0x0036,
	ManagementCacheRequest => 0x0037,
	ManagementNetworkUpdateRequest => 0x0038,
);

// 2.4.5 ZDP Enumeration Description
extended_enum!(
    /// Response status codes
	Status, u8,
    /// Request succeded
	Success => 0x00,
    /// 
	InvalidRequestType => 0x80,
	DeviceNotFound => 0x81,
	InvalidEndpoint => 0x82,
	NotActive => 0x83,
	NotSupported => 0x84,
	Timeout => 0x85,
	NoMatch => 0x86,
	NoEntry => 0x88,
	NoDescriptor => 0x89,
	InsufficientSpace => 0x8a,
	NotPermitted => 0x8b,
	TableFull => 0x8c,
	NotAuthorized => 0x8d,
	DeviceBindingTableFull => 0x8e,
	InvalidIndex => 0x8f,
);

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceProfileMessage {
    NetworkAddressRequest(NetworkAddressRequest),
    NetworkAddressResponse(AddressResponse),
    IeeeAddressRequest(IeeeAddressRequest),
    IeeeAddressResponse(AddressResponse),
    NodeDescriptorRequest(NodeDescriptorRequest),
    MatchDescriptorRequest(MatchDescriptorRequest),
    MatchDescriptorResponse(MatchDescriptorResponse),
    DeviceAnnounce(DeviceAnnounce),
    /// Management link quality indicator (LQI) request
    /// Message contains the start index as u8
    ManagementLinkQualityIndicatorRequest(u8),
    ManagementLinkQualityIndicatorResponse(ManagementLinkQualityIndicatorResponse),
}

impl DeviceProfileMessage {
    pub fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        match *self {
            DeviceProfileMessage::NetworkAddressRequest(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::NetworkAddressResponse(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::IeeeAddressRequest(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::IeeeAddressResponse(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::NodeDescriptorRequest(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::MatchDescriptorRequest(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::MatchDescriptorResponse(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::DeviceAnnounce(ref m) => m.pack(&mut data[..]),
            DeviceProfileMessage::ManagementLinkQualityIndicatorResponse(ref m) => {
                m.pack(&mut data[..])
            }
            DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(ref m) => {
                data[0] = *m;
                Ok(1)
            }
        }
    }

    pub fn unpack(data: &[u8], cluster_identifier: u16) -> Result<(Self, usize), Error> {
        let response = (cluster_identifier & RESPONSE) == RESPONSE;
        let cluster_identifier = ClusterIdentifier::try_from(cluster_identifier & 0x7fff)?;
        if response {
            match cluster_identifier {
                ClusterIdentifier::NetworkAddressRequest => {
                    let (rsp, used) = AddressResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::NetworkAddressResponse(rsp), used))
                }
                ClusterIdentifier::IeeeAddressRequest => {
                    let (rsp, used) = AddressResponse::unpack(&data)?;
                    Ok((DeviceProfileMessage::IeeeAddressResponse(rsp), used))
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
                ClusterIdentifier::IeeeAddressRequest => {
                    let (req, used) = IeeeAddressRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::IeeeAddressRequest(req), used))
                }
                ClusterIdentifier::NodeDescriptorRequest => {
                    let (req, used) = NodeDescriptorRequest::unpack(&data)?;
                    Ok((DeviceProfileMessage::NodeDescriptorRequest(req), used))
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

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceProfileFrame {
    pub transaction_sequence: u8,
    pub message: DeviceProfileMessage,
}

impl DeviceProfileFrame {
    pub fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.transaction_sequence;
        let used = self.message.pack(&mut data[1..])?;
        Ok(1 + used)
    }

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
                    da.ieee_address,
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
}
