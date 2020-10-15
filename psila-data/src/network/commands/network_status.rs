use core::convert::TryFrom;

use crate::common::address::NetworkAddress;
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

extended_enum!(
    /// Status identifier
    Status, u8,
    /// No route available
    NoRouteAvailable => 0x00,
    /// Tree link failure
    TreeLinkFailure => 0x01,
    /// Non-tree link failure
    NonTreeLinkFailure => 0x02,
    /// Low battery level
    LowBatteryLevel => 0x03,
    /// No routing capacity
    NoRoutingCapacity => 0x04,
    /// No indirect capacity
    NoIndirectCapacity => 0x05,
    /// Indirect transaction expired
    IndirectTransactionExpiry => 0x06,
    /// Target device unavailable
    TargetDeviceUnavailable => 0x07,
    /// Target address unallocated
    TargetAddressUnallocated => 0x08,
    /// Parent link failure
    ParentLinkFailure => 0x09,
    /// Validate route
    ValidateRoute => 0x0a,
    /// Source route failure
    SourceRouteFailure => 0x0b,
    /// Many-to-one route failure
    ManyToOneRouteFailure => 0x0c,
    /// Address conflict
    AddressConflict => 0x0d,
    /// Verify addresses
    VerifyAddresses => 0x0e,
    /// PAN identifier update
    PANIdentifierUpdate => 0x0f,
    /// Short address update
    ShortAddressUpdate => 0x10,
    /// Bad frame counter
    BadFrameCounter => 0x11,
    /// Bad key sequence number
    BadKeySequenceNumber => 0x12,
);

/// Network status message
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkStatus {
    /// Network status
    pub status: Status,
    /// Destination address
    pub destination: NetworkAddress,
}

impl Pack<NetworkStatus, Error> for NetworkStatus {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        self.destination.pack(&mut data[1..3])?;
        Ok(3)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let destination = NetworkAddress::unpack(&data[1..3])?;
        Ok((
            NetworkStatus {
                status,
                destination,
            },
            3,
        ))
    }
}
