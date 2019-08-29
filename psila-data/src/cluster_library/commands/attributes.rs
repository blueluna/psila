use core::convert::TryFrom;

use crate::cluster_library::{AttributeDataType, AttributeValue, ClusterLibraryStatus};
use crate::common::address::ShortAddress;
use crate::pack::{Pack, PackFixed};
use crate::Error;

/// 16-bit attribute identifier
pub type AttributeIdentifier = ShortAddress;

#[derive(Clone, Debug, PartialEq)]
pub struct ReadAttributes {
    pub attributes: Vec<AttributeIdentifier>,
}

impl Pack<ReadAttributes, Error> for ReadAttributes {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < self.attributes.len() * 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 0;
        for attribute_id in self.attributes.iter() {
            attribute_id.pack(&mut data[offset..offset + 2])?;
            offset += 2;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() % 2 != 0 {
            return Err(Error::WrongNumberOfBytes);
        }
        let num_attributes = data.len() / 2;
        let mut attributes: Vec<AttributeIdentifier> = Vec::with_capacity(num_attributes);
        let mut offset = 0;
        for _ in 0..num_attributes {
            let attribute_id = AttributeIdentifier::unpack(&data[offset..offset + 2])?;
            attributes.push(attribute_id);
            offset += 2;
        }
        Ok((Self { attributes }, offset))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AttributeStatus {
    pub identifier: AttributeIdentifier,
    pub status: ClusterLibraryStatus,
    pub value: Option<AttributeValue>,
}

impl Pack<AttributeStatus, Error> for AttributeStatus {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.identifier.pack(&mut data[0..2])?;
        data[2] = u8::from(self.status);
        let used = if let Some(value) = &self.value {
            if data.len() < 4 {
                return Err(Error::WrongNumberOfBytes);
            }
            data[3] = u8::from(value.data_type());
            value.pack(&mut data[4..])? + 4
        } else {
            3
        };
        Ok(used)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let identifier = AttributeIdentifier::unpack(&data[0..2])?;
        let status = ClusterLibraryStatus::try_from(data[2])?;
        if status != ClusterLibraryStatus::Success {
            return Ok((
                Self {
                    identifier,
                    status,
                    value: None,
                },
                3,
            ));
        }
        if data.len() < 4 {
            return Err(Error::WrongNumberOfBytes);
        }
        let data_type = AttributeDataType::try_from(data[3])?;
        let (value, used) = AttributeValue::unpack(&data[4..], data_type)?;
        Ok((
            Self {
                identifier,
                status,
                value: Some(value),
            },
            used + 4,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReadAttributesResponse {
    pub attributes: Vec<AttributeStatus>,
}

impl Pack<ReadAttributesResponse, Error> for ReadAttributesResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;
        for attribute in self.attributes.iter() {
            offset += attribute.pack(&mut data[offset..])?;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let mut attributes: Vec<AttributeStatus> = Vec::new();
        loop {
            if offset == data.len() {
                break;
            }
            let (attribute_status, used) = AttributeStatus::unpack(&data[offset..])?;
            attributes.push(attribute_status);
            offset += used;
        }
        Ok((Self { attributes }, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_read_attributes() {
        let data = [0x0b, 0x05];
        let (cmd, used) = ReadAttributes::unpack(&data).unwrap();
        assert_eq!(used, 2);
        assert_eq!(cmd.attributes[0], 0x050b);
    }
}
