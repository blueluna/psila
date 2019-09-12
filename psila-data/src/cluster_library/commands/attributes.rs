use core::convert::TryFrom;

use crate::cluster_library::{
    AttributeDataType, AttributeIdentifier, AttributeValue, ClusterLibraryStatus,
};
use crate::pack::{Pack, PackFixed};
use crate::Error;

#[cfg(feature = "std")]
pub type AttributeIdentifierVec = std::vec::Vec<AttributeIdentifier>;

#[cfg(feature = "core")]
pub type AttributeIdentifierVec = heapless::Vec<AttributeIdentifier, heapless::consts::U32>;

#[derive(Clone, Debug, PartialEq)]
pub struct ReadAttributes {
    pub attributes: AttributeIdentifierVec,
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
        let mut attributes = AttributeIdentifierVec::new();
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

#[cfg(feature = "std")]
pub type AttributeStatusVec = std::vec::Vec<AttributeStatus>;

#[cfg(feature = "core")]
pub type AttributeStatusVec = heapless::Vec<AttributeStatus, heapless::consts::U32>;

#[derive(Clone, Debug, PartialEq)]
pub struct ReadAttributesResponse {
    pub attributes: AttributeStatusVec,
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
        let mut attributes = AttributeStatusVec::new();
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

#[derive(Clone, Debug, PartialEq)]
pub struct WriteAttributeRecord {
    pub identifier: AttributeIdentifier,
    pub value: AttributeValue,
}

impl Pack<WriteAttributeRecord, Error> for WriteAttributeRecord {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.identifier.pack(&mut data[0..2])?;
        data[2] = u8::from(self.value.data_type());
        let used = self.value.pack(&mut data[3..])?;
        Ok(used + 3)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let identifier = AttributeIdentifier::unpack(&data[0..2])?;
        let data_type = AttributeDataType::try_from(data[2])?;
        let (value, used) = AttributeValue::unpack(&data[3..], data_type)?;
        Ok((Self { identifier, value }, used + 3))
    }
}

#[cfg(feature = "std")]
pub type WriteAttributeRecordVec = std::vec::Vec<WriteAttributeRecord>;

#[cfg(feature = "core")]
pub type WriteAttributeRecordVec = heapless::Vec<WriteAttributeRecord, heapless::consts::U16>;

#[derive(Clone, Debug, PartialEq)]
pub struct WriteAttributes {
    pub attributes: WriteAttributeRecordVec,
}

impl Pack<WriteAttributes, Error> for WriteAttributes {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;
        for attribute in self.attributes.iter() {
            offset += attribute.pack(&mut data[offset..])?;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let mut attributes = WriteAttributeRecordVec::new();
        loop {
            if offset == data.len() {
                break;
            }
            let (record, used) = WriteAttributeRecord::unpack(&data[offset..])?;
            attributes.push(record);
            offset += used;
        }
        Ok((Self { attributes }, offset))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WriteAttributeStatus {
    pub status: ClusterLibraryStatus,
    pub identifier: AttributeIdentifier,
}

impl Pack<WriteAttributeStatus, Error> for WriteAttributeStatus {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        self.identifier.pack(&mut data[1..=2])?;
        Ok(3)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = ClusterLibraryStatus::try_from(data[0])?;
        let identifier = AttributeIdentifier::unpack(&data[1..=2])?;
        Ok((Self { status, identifier }, 3))
    }
}

#[cfg(feature = "std")]
pub type WriteAttributeStatusVec = std::vec::Vec<WriteAttributeStatus>;

#[cfg(feature = "core")]
pub type WriteAttributeStatusVec = heapless::Vec<WriteAttributeStatus, heapless::consts::U16>;

#[derive(Clone, Debug, PartialEq)]
pub struct WriteAttributesResponse {
    pub attributes: WriteAttributeStatusVec,
}

impl Pack<WriteAttributesResponse, Error> for WriteAttributesResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;
        for attribute in self.attributes.iter() {
            offset += attribute.pack(&mut data[offset..])?;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let mut attributes = WriteAttributeStatusVec::new();
        loop {
            if offset == data.len() {
                break;
            }
            let (attribute_status, used) = WriteAttributeStatus::unpack(&data[offset..])?;
            attributes.push(attribute_status);
            offset += used;
        }
        Ok((Self { attributes }, offset))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReportAttributes {
    pub attributes: WriteAttributeRecordVec,
}

impl Pack<ReportAttributes, Error> for ReportAttributes {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;
        for attribute in self.attributes.iter() {
            offset += attribute.pack(&mut data[offset..])?;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut offset = 0;
        let mut attributes = WriteAttributeRecordVec::new();
        loop {
            if offset == data.len() {
                break;
            }
            let (record, used) = WriteAttributeRecord::unpack(&data[offset..])?;
            attributes.push(record);
            offset += used;
        }
        Ok((Self { attributes }, offset))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn unpack_read_attributes() {
        let data = [0x0b, 0x05];
        let (cmd, used) = ReadAttributes::unpack(&data).unwrap();
        assert_eq!(used, 2);
        assert_eq!(cmd.attributes[0], 0x050b);
    }

    #[test]
    fn unpack_read_attributes_response() {
        use crate::cluster_library::AttributeValue;

        let data = [
            0x04, 0x00, 0x00, 0x42, 0x0e, 0x49, 0x4b, 0x45, 0x41, 0x20, 0x6f, 0x66, 0x20, 0x53,
            0x77, 0x65, 0x64, 0x65, 0x6e,
        ];
        let (cmd, used) = ReadAttributesResponse::unpack(&data).unwrap();
        assert_eq!(used, 19);
        assert_eq!(cmd.attributes[0].identifier, 0x0004);
        assert_eq!(cmd.attributes[0].status, ClusterLibraryStatus::Success);
        assert_eq!(
            cmd.attributes[0].value,
            Some(AttributeValue::CharacterString(Some(
                "IKEA of Sweden".to_string()
            )))
        );
        assert_eq!(
            format!("{}", cmd.attributes[0].value.as_ref().unwrap()),
            "IKEA of Sweden".to_string()
        );
    }

    #[test]
    fn unpack_report_attributes() {
        use crate::cluster_library::AttributeValue;

        let data = [
            0x03, 0x00, 0x21, 0xba, 0x75, 0x04, 0x00, 0x21, 0x1d, 0x69, 0x07, 0x00, 0x21, 0xc6,
            0x01,
        ];
        let (cmd, used) = ReportAttributes::unpack(&data).unwrap();
        assert_eq!(used, 15);
        assert_eq!(cmd.attributes[0].identifier, 0x0003);
        assert_eq!(cmd.attributes[0].value, AttributeValue::Unsigned16(0x75ba));
        assert_eq!(cmd.attributes[1].identifier, 0x0004);
        assert_eq!(cmd.attributes[1].value, AttributeValue::Unsigned16(0x691d));
        assert_eq!(cmd.attributes[2].identifier, 0x0007);
        assert_eq!(cmd.attributes[2].value, AttributeValue::Unsigned16(0x01c6));
    }
}
