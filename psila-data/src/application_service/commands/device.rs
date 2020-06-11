use core::convert::TryFrom;

use crate::common::address::{
    ExtendedAddress, ShortAddress, EXTENDED_ADDRESS_SIZE, SHORT_ADDRESS_SIZE,
};
use crate::pack::{Pack, PackFixed};
use crate::Error;

extended_enum!(
Status, u8,
SecuredRejoin => 0x00,
UnsecuredJoin => 0x01,
Left => 0x02,
TrustCenterRejoin => 0x03,
);

/// Update device command
///
/// These are notification sent when device status changes
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateDevice {
    /// Extended address of the device
    pub address: ExtendedAddress,
    /// Short address of the device
    pub short_address: ShortAddress,
    /// Device status
    pub status: Status,
}

impl Pack<UpdateDevice, Error> for UpdateDevice {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 0;
        self.address
            .pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        self.short_address
            .pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += SHORT_ADDRESS_SIZE;
        data[offset] = u8::from(self.status);
        offset += 1;
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 0;
        let address = ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        let short_address = ShortAddress::unpack(&data[offset..offset + SHORT_ADDRESS_SIZE])?;
        offset += SHORT_ADDRESS_SIZE;
        let status = Status::try_from(data[offset])?;
        Ok((
            Self {
                address,
                short_address,
                status,
            },
            offset,
        ))
    }
}

/// Remove device command
///
/// These are notification sent when a device is removed
#[derive(Clone, Debug, PartialEq)]
pub struct RemoveDevice {
    /// Extended address of the device
    pub address: ExtendedAddress,
}

impl Pack<RemoveDevice, Error> for RemoveDevice {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < EXTENDED_ADDRESS_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[..EXTENDED_ADDRESS_SIZE])?;
        Ok(EXTENDED_ADDRESS_SIZE)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < EXTENDED_ADDRESS_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = ExtendedAddress::unpack(&data[..EXTENDED_ADDRESS_SIZE])?;
        Ok((Self { address }, EXTENDED_ADDRESS_SIZE))
    }
}
