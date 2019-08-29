use core::convert::TryFrom;

use crate::common::address::NetworkAddress;
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

extended_enum!(
    Status, u8,
    NoRouteAvailable => 0x00,
    TreeLinkFailure => 0x01,
    NonTreeLinkFailure => 0x02,
    LowBatteryLevel => 0x03,
    NoRoutingCapacity => 0x04,
    NoIndirectCapacity => 0x05,
    IndirectTransactionExpiry => 0x06,
    TargetDeviceUnavailable => 0x07,
    TargetAddressUnallocated => 0x08,
    ParentLinkFailure => 0x09,
    ValidateRoute => 0x0a,
    SourceRouteFailure => 0x0b,
    ManyToOneRouteFailure => 0x0c,
    AddressConflict => 0x0d,
    VerifyAddresses => 0x0e,
    PANIdentifierUpdate => 0x0f,
    ShortAddressUpdate => 0x10,
    BadFrameCounter => 0x11,
    BadKeySequenceNumber => 0x12,
);

#[derive(Clone, Debug, PartialEq)]
pub struct NetworkStatus {
    pub status: Status,
    pub destination: NetworkAddress,
}

impl Pack<NetworkStatus, Error> for NetworkStatus {
    fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
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
