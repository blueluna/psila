use core::convert::TryFrom;

use crate::cluster_library::{
    AttributeDataType, AttributeIdentifier, AttributeValue, ClusterLibraryStatus,
};
use crate::pack::{Pack, PackFixed};
use crate::Error;

#[cfg(not(feature = "core"))]
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
            let (used, data_type) = value.pack(&mut data[4..])?;
            data[3] = u8::from(data_type);
            4 + used
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

#[cfg(not(feature = "core"))]
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
        let (used, data_type) = self.value.pack(&mut data[3..])?;
        data[2] = u8::from(data_type);
        Ok(3 + used)
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

#[cfg(not(feature = "core"))]
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

#[cfg(not(feature = "core"))]
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

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoverAttributes {
    pub start: AttributeIdentifier,
    pub count: u8,
}

impl Pack<DiscoverAttributes, Error> for DiscoverAttributes {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.start.pack(&mut data[0..2])?;
        data[2] = self.count;
        Ok(3)
    }
    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let start = AttributeIdentifier::unpack(&data[0..2])?;
        let count = data[2];
        Ok((Self { start, count }, 3))
    }
}

#[cfg(not(feature = "core"))]
pub type DiscoverAttributeVec = std::vec::Vec<(AttributeIdentifier, AttributeDataType)>;

#[cfg(feature = "core")]
pub type DiscoverAttributeVec =
    heapless::Vec<(AttributeIdentifier, AttributeDataType), heapless::consts::U16>;

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoverAttributesResponse {
    pub complete: bool,
    pub attributes: DiscoverAttributeVec,
}

impl Pack<DiscoverAttributesResponse, Error> for DiscoverAttributesResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < (self.attributes.len() * 3) + 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.complete);
        let mut offset = 1;
        for attribute in self.attributes.iter() {
            attribute.0.pack(&mut data[offset..offset + 2])?;
            data[offset + 2] = u8::from(attribute.1);
            offset += 3;
        }
        Ok(offset)
    }
    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let complete = data[0] != 0;
        let mut offset = 1;
        let mut attributes = DiscoverAttributeVec::new();
        while (offset + 3) <= data.len() {
            let id = AttributeIdentifier::unpack(&data[offset..offset + 2])?;
            let dt = AttributeDataType::try_from(data[offset + 2])?;
            attributes.push((id, dt));
            offset += 3;
        }
        Ok((
            Self {
                complete,
                attributes,
            },
            offset,
        ))
    }
}

#[cfg(all(test, not(feature = "core")))]
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
    fn unpack_read_attributes_response_1() {
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
    fn unpack_read_attributes_response_2() {
        use crate::cluster_library::AttributeValue;

        let data = [
            0x05, 0x00, 0x00, 0x42, 0x06, 0x53, 0x50, 0x20, 0x31, 0x32, 0x30, 0x06, 0x00, 0x00,
            0x42, 0x0c, 0x32, 0x30, 0x31, 0x37, 0x31, 0x30, 0x32, 0x37, 0x2d, 0x31, 0x30, 0x30,
            0x07, 0x00, 0x00, 0x30, 0x01, 0x0a, 0x00, 0x00, 0x41, 0x09, 0x30, 0x31, 0x30, 0x34,
            0x30, 0x30, 0x30, 0x38, 0x32, 0x00, 0x40, 0x00, 0x42, 0x03, 0x32, 0x2e, 0x30,
        ];
        let (cmd, used) = ReadAttributesResponse::unpack(&data).unwrap();
        assert_eq!(used, 55);
        assert_eq!(cmd.attributes[0].identifier, 0x0005);
        assert_eq!(cmd.attributes[0].status, ClusterLibraryStatus::Success);
        assert_eq!(
            cmd.attributes[0].value,
            Some(AttributeValue::CharacterString(Some("SP 120".to_string())))
        );
        assert_eq!(cmd.attributes[1].identifier, 0x0006);
        assert_eq!(cmd.attributes[1].status, ClusterLibraryStatus::Success);
        assert_eq!(
            cmd.attributes[1].value,
            Some(AttributeValue::CharacterString(Some(
                "20171027-100".to_string()
            )))
        );
        assert_eq!(cmd.attributes[2].identifier, 0x0007);
        assert_eq!(cmd.attributes[2].status, ClusterLibraryStatus::Success);
        assert_eq!(
            cmd.attributes[2].value,
            Some(AttributeValue::Enumeration8(1))
        );
        assert_eq!(cmd.attributes[3].identifier, 0x000a);
        assert_eq!(cmd.attributes[3].status, ClusterLibraryStatus::Success);
        assert_eq!(
            cmd.attributes[3].value,
            Some(AttributeValue::OctetString(Some(vec![
                0x30, 0x31, 0x30, 0x34, 0x30, 0x30, 0x30, 0x38, 0x32
            ])))
        );
        assert_eq!(cmd.attributes[4].identifier, 0x4000);
        assert_eq!(cmd.attributes[4].status, ClusterLibraryStatus::Success);
        assert_eq!(
            cmd.attributes[4].value,
            Some(AttributeValue::CharacterString(Some("2.0".to_string())))
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

    #[test]
    fn unpack_discover_attributes() {
        let data = [0x00, 0x00, 0xf0];
        let (cmd, used) = DiscoverAttributes::unpack(&data).unwrap();
        assert_eq!(used, 3);
        assert_eq!(cmd.start, AttributeIdentifier::from(0));
        assert_eq!(cmd.count, 240);
    }

    #[test]
    fn pack_discover_attributes() {
        let cmd = DiscoverAttributes {
            start: AttributeIdentifier::from(0x1234),
            count: 12,
        };
        let mut data = [0u8; 3];
        let used = cmd.pack(&mut data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(data, [0x34, 0x12, 0x0c]);
    }

    #[test]
    fn unpack_discover_attributes_response() {
        let data = [
            0x00, 0x00, 0x00, 0x10, 0x00, 0x40, 0x10, 0x01, 0x40, 0x21, 0x02, 0x40, 0x21, 0x03,
            0x40, 0x30,
        ];
        let (cmd, used) = DiscoverAttributesResponse::unpack(&data).unwrap();
        assert_eq!(used, 16);
        assert_eq!(cmd.complete, false);
        assert_eq!(cmd.attributes.len(), 5);
        assert_eq!(cmd.attributes[0].0, AttributeIdentifier::from(0x0000));
        assert_eq!(cmd.attributes[0].1, AttributeDataType::Boolean);
        assert_eq!(cmd.attributes[1].0, AttributeIdentifier::from(0x4000));
        assert_eq!(cmd.attributes[1].1, AttributeDataType::Boolean);
        assert_eq!(cmd.attributes[2].0, AttributeIdentifier::from(0x4001));
        assert_eq!(cmd.attributes[2].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[3].0, AttributeIdentifier::from(0x4002));
        assert_eq!(cmd.attributes[3].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[4].0, AttributeIdentifier::from(0x4003));
        assert_eq!(cmd.attributes[4].1, AttributeDataType::Enumeration8);

        let data = [
            0x01, 0x00, 0x00, 0x10, 0x00, 0x40, 0x10, 0x01, 0x40, 0x21, 0x02, 0x40, 0x21, 0x03,
            0x40, 0x30, 0xfd, 0xff, 0x21,
        ];
        let (cmd, used) = DiscoverAttributesResponse::unpack(&data).unwrap();
        assert_eq!(used, 19);
        assert_eq!(cmd.complete, true);
        assert_eq!(cmd.attributes.len(), 6);
        assert_eq!(cmd.attributes[0].0, AttributeIdentifier::from(0x0000));
        assert_eq!(cmd.attributes[0].1, AttributeDataType::Boolean);
        assert_eq!(cmd.attributes[1].0, AttributeIdentifier::from(0x4000));
        assert_eq!(cmd.attributes[1].1, AttributeDataType::Boolean);
        assert_eq!(cmd.attributes[2].0, AttributeIdentifier::from(0x4001));
        assert_eq!(cmd.attributes[2].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[3].0, AttributeIdentifier::from(0x4002));
        assert_eq!(cmd.attributes[3].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[4].0, AttributeIdentifier::from(0x4003));
        assert_eq!(cmd.attributes[4].1, AttributeDataType::Enumeration8);
        assert_eq!(cmd.attributes[5].0, AttributeIdentifier::from(0xfffd));
        assert_eq!(cmd.attributes[5].1, AttributeDataType::Unsigned16);

        let data = [
            0x01, 0x02, 0x00, 0x21, 0x03, 0x00, 0x21, 0x04, 0x00, 0x21, 0x07, 0x00, 0x21, 0x08,
            0x00, 0x30, 0x0f, 0x00, 0x18, 0x10, 0x00, 0x20, 0x01, 0x40, 0x30, 0x0a, 0x40, 0x19,
            0x0b, 0x40, 0x21, 0x0c, 0x40, 0x21, 0x0d, 0x40, 0x21, 0x10, 0x40, 0x21, 0xfd, 0xff,
            0x21,
        ];
        let (cmd, used) = DiscoverAttributesResponse::unpack(&data).unwrap();
        assert_eq!(used, 43);
        assert_eq!(cmd.complete, true);
        assert_eq!(cmd.attributes.len(), 14);
        assert_eq!(cmd.attributes[0].0, AttributeIdentifier::from(0x0002));
        assert_eq!(cmd.attributes[0].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[1].0, AttributeIdentifier::from(0x0003));
        assert_eq!(cmd.attributes[1].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[2].0, AttributeIdentifier::from(0x0004));
        assert_eq!(cmd.attributes[2].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[3].0, AttributeIdentifier::from(0x0007));
        assert_eq!(cmd.attributes[3].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[4].0, AttributeIdentifier::from(0x0008));
        assert_eq!(cmd.attributes[4].1, AttributeDataType::Enumeration8);
        assert_eq!(cmd.attributes[5].0, AttributeIdentifier::from(0x000f));
        assert_eq!(cmd.attributes[5].1, AttributeDataType::Bitmap8);
        assert_eq!(cmd.attributes[6].0, AttributeIdentifier::from(0x0010));
        assert_eq!(cmd.attributes[6].1, AttributeDataType::Unsigned8);
        assert_eq!(cmd.attributes[7].0, AttributeIdentifier::from(0x4001));
        assert_eq!(cmd.attributes[7].1, AttributeDataType::Enumeration8);
        assert_eq!(cmd.attributes[8].0, AttributeIdentifier::from(0x400a));
        assert_eq!(cmd.attributes[8].1, AttributeDataType::Bitmap16);
        assert_eq!(cmd.attributes[9].0, AttributeIdentifier::from(0x400b));
        assert_eq!(cmd.attributes[9].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[10].0, AttributeIdentifier::from(0x400c));
        assert_eq!(cmd.attributes[10].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[11].0, AttributeIdentifier::from(0x400d));
        assert_eq!(cmd.attributes[11].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[12].0, AttributeIdentifier::from(0x4010));
        assert_eq!(cmd.attributes[12].1, AttributeDataType::Unsigned16);
        assert_eq!(cmd.attributes[13].0, AttributeIdentifier::from(0xfffd));
        assert_eq!(cmd.attributes[13].1, AttributeDataType::Unsigned16);
    }

    #[test]
    fn pack_discover_attributes_response() {
        let mut attributes = DiscoverAttributeVec::new();
        attributes.push((
            AttributeIdentifier::from(0x0000),
            AttributeDataType::Unsigned8,
        ));
        attributes.push((
            AttributeIdentifier::from(0x0001),
            AttributeDataType::Unsigned16,
        ));
        attributes.push((
            AttributeIdentifier::from(0x0002),
            AttributeDataType::Unsigned32,
        ));
        let cmd = DiscoverAttributesResponse {
            complete: false,
            attributes,
        };
        let mut data = [0u8; 10];
        let used = cmd.pack(&mut data[..]).unwrap();
        assert_eq!(used, 10);
        assert_eq!(
            data,
            [0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x21, 0x02, 0x00, 0x23]
        );

        let mut attributes = DiscoverAttributeVec::new();
        attributes.push((AttributeIdentifier::from(0x8765), AttributeDataType::Data32));
        attributes.push((
            AttributeIdentifier::from(0xfffd),
            AttributeDataType::OctetString,
        ));
        attributes.push((
            AttributeIdentifier::from(0x0123),
            AttributeDataType::UtcTime,
        ));
        attributes.push((
            AttributeIdentifier::from(0x0000),
            AttributeDataType::Unsigned8,
        ));
        attributes.push((
            AttributeIdentifier::from(0x5678),
            AttributeDataType::FloatingPoint64,
        ));
        attributes.push((
            AttributeIdentifier::from(0x0101),
            AttributeDataType::IeeeAddress,
        ));
        let cmd = DiscoverAttributesResponse {
            complete: true,
            attributes,
        };
        let mut data = [0u8; 19];
        let used = cmd.pack(&mut data[..]).unwrap();
        assert_eq!(used, 19);
        assert_eq!(
            data,
            [
                0x01, 0x65, 0x87, 0x0b, 0xfd, 0xff, 0x41, 0x23, 0x01, 0xe2, 0x00, 0x00, 0x20, 0x78,
                0x56, 0x3a, 0x01, 0x01, 0xf0
            ]
        );
    }
}
