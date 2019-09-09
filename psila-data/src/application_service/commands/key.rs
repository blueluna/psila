use core::convert::TryFrom;

use crate::application_service::ApplicationServiceStatus;
use crate::common::{
    address::{ExtendedAddress, EXTENDED_ADDRESS_SIZE},
    key::KeyType,
};
use crate::pack::{Pack, PackFixed};
use crate::security::BLOCK_SIZE;
use crate::Error;

extended_enum!(
    /// Key type used in key requests
    RequestKeyType, u8,
    /// Application link key
    ApplicationLinkKey => 0x02,
    /// Trust-center link key
    TrustCenterLinkKey => 0x04,
    );

/// Request key command
///
/// Device request for a key
#[derive(Clone, Debug, PartialEq)]
pub struct RequestKey {
    /// Key type which is requested
    pub key_type: RequestKeyType,
    /// Optional partner address, used for application link keys
    pub partner_address: Option<ExtendedAddress>,
}

impl Pack<RequestKey, Error> for RequestKey {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        match self.key_type {
            RequestKeyType::ApplicationLinkKey => assert!(self.partner_address.is_some()),
            RequestKeyType::TrustCenterLinkKey => assert!(self.partner_address.is_none()),
        }
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.key_type);
        let mut offset = 1;
        if let Some(address) = self.partner_address {
            if data.len() < 9 {
                return Err(Error::WrongNumberOfBytes);
            }
            address.pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let key_type = RequestKeyType::try_from(data[0])?;
        let mut offset = 1;
        let partner_address = match key_type {
            RequestKeyType::ApplicationLinkKey => {
                if data.len() < 9 {
                    return Err(Error::WrongNumberOfBytes);
                }
                offset += EXTENDED_ADDRESS_SIZE;
                Some(ExtendedAddress::unpack(
                    &data[offset..offset + EXTENDED_ADDRESS_SIZE],
                )?)
            }
            RequestKeyType::TrustCenterLinkKey => None,
        };
        Ok((
            Self {
                key_type,
                partner_address,
            },
            offset,
        ))
    }
}

/// Switch key command
///
///
#[derive(Clone, Debug, PartialEq)]
pub struct SwitchKey {
    /// Sequence number
    pub sequence: u8,
}

impl Pack<SwitchKey, Error> for SwitchKey {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.sequence;
        Ok(1)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        Ok((Self { sequence: data[0] }, 1))
    }
}

/// Verify key command
///
///
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyKey {
    /// Key type which shall be verified
    pub key_type: KeyType,
    /// 64-bit extended address of the source
    pub source: ExtendedAddress,
    /// Hash value
    pub value: [u8; BLOCK_SIZE],
}

impl Pack<VerifyKey, Error> for VerifyKey {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 1 + EXTENDED_ADDRESS_SIZE + BLOCK_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.key_type);
        let mut offset = 1;
        self.source
            .pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        data[offset..offset + BLOCK_SIZE].copy_from_slice(&self.value);
        offset += BLOCK_SIZE;
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 1 + EXTENDED_ADDRESS_SIZE + BLOCK_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let key_type = KeyType::try_from(data[0])?;
        let mut offset = 1;
        let source = ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        let mut value = [0u8; BLOCK_SIZE];
        value.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
        offset += BLOCK_SIZE;
        Ok((
            Self {
                key_type,
                source,
                value,
            },
            offset,
        ))
    }
}

/// Confirm key command
///
///
#[derive(Clone, Debug, PartialEq)]
pub struct ConfirmKey {
    /// Status code
    pub status: ApplicationServiceStatus,
    /// Key type which shall be verified
    pub key_type: KeyType,
    /// 64-bit extended address of the destination
    pub destination: ExtendedAddress,
}

impl Pack<ConfirmKey, Error> for ConfirmKey {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 2 + EXTENDED_ADDRESS_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        data[1] = u8::from(self.key_type);
        let mut offset = 2;
        self.destination
            .pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 + EXTENDED_ADDRESS_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = ApplicationServiceStatus::try_from(data[0])?;
        let key_type = KeyType::try_from(data[1])?;
        let mut offset = 2;
        let destination = ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        Ok((
            Self {
                status,
                key_type,
                destination,
            },
            offset,
        ))
    }
}
