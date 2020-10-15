use core::convert::TryFrom;

use crate::common::address::{NetworkAddress, SHORT_ADDRESS_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};
use crate::CapabilityInformation;

extended_enum!(
    /// Association Status
    AssociationStatus, u8,
    /// Successful
    Successful => 0x00,
    /// Network (PAN) at capacity
    NetworkAtCapacity => 0x01,
    /// Access to PAN denied
    AccessDenied => 0x02,
    /// Duplicate hopping sequence offset
    HoppingSequenceOffsetDuplication => 0x03,
    /// Fast association was successful
    FastAssociationSuccesful => 0x80,
);

/// Rejoin request
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RejoinRequest {
    /// Device capability information
    pub capability: CapabilityInformation,
}

impl Pack<RejoinRequest, Error> for RejoinRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.capability);
        Ok(1)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let capability = CapabilityInformation::from(data[0]);
        Ok((RejoinRequest { capability }, 1))
    }
}

/// Rejoin response
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RejoinResponse {
    /// Device address
    pub address: NetworkAddress,
    /// Association status
    pub status: AssociationStatus,
}

impl Pack<RejoinResponse, Error> for RejoinResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < (SHORT_ADDRESS_SIZE + 1) {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..SHORT_ADDRESS_SIZE])?;
        data[SHORT_ADDRESS_SIZE] = u8::from(self.status);
        Ok(SHORT_ADDRESS_SIZE + 1)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < (SHORT_ADDRESS_SIZE + 1) {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..SHORT_ADDRESS_SIZE])?;
        let status = AssociationStatus::try_from(data[2])?;
        Ok((RejoinResponse { address, status }, SHORT_ADDRESS_SIZE + 1))
    }
}
