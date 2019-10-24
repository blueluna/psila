use core::convert::TryFrom;

use crate::error::Error;
use crate::pack::{Pack, PackFixed};

use byteorder::{ByteOrder, LittleEndian};

// ZCL, 2.4.1.1.1 Frame Type Sub-field
/// Frame type field
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FrameType {
    /// The command is global for all clusters
    Global = 0b00,
    /// Command is specific or local to a cluster
    Local = 0b01,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;
    /// Get `FrameType` from a `u8`
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b11 {
            0b00 => Ok(FrameType::Global),
            0b01 => Ok(FrameType::Local),
            _ => Err(Error::UnknownFrameType),
        }
    }
}

/// Direction of the command
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Direction {
    /// Sent from the server side to the client side
    ToServer = 0,
    /// Sent from the client side to the server side
    ToClient = 1,
}

impl TryFrom<u8> for Direction {
    type Error = Error;
    /// Get `Direction`from `u8`
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b0000_1000 {
            0b0000_0000 => Ok(Direction::ToServer),
            0b0000_1000 => Ok(Direction::ToClient),
            _ => Err(Error::InvalidValue),
        }
    }
}

impl From<Direction> for u8 {
    /// Get `u8` from `Direction`
    fn from(value: Direction) -> u8 {
        match value {
            Direction::ToServer => 0b0000_0000,
            Direction::ToClient => 0b0000_1000,
        }
    }
}

// ZCL, 2.4.1.1 Frame Control Field
/// Cluster library frame control field
#[derive(Copy, Clone, Debug)]
pub struct FrameControl {
    /// Frame type, see `FrameType`
    pub frame_type: FrameType,
    /// Manufacturer specific command
    pub manufacturer_specific: bool,
    /// Command direction, see `Direction`
    pub direction: Direction,
    /// Disable default response mechanism
    pub disable_default_response: bool,
}

impl PackFixed<FrameControl, Error> for FrameControl {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 1 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let frame_type = self.frame_type as u8;
            data[0] = frame_type
                | ((self.manufacturer_specific as u8) << 2)
                | u8::from(self.direction)
                | ((self.disable_default_response as u8) << 4);
            Ok(())
        }
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 1 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let frame_type = FrameType::try_from(data[0])?;
            let manufacturer_specific = (data[0] & 0b0000_0100) == 0b0000_0100;
            let direction = Direction::try_from(data[0])?;
            let disable_default_response = (data[0] & 0b0001_0000) == 0b0001_0000;
            Ok(Self {
                frame_type,
                manufacturer_specific,
                direction,
                disable_default_response,
            })
        }
    }
}

// ZCL, 2.4.1 General ZCL Frame Format
/// Cluster library frame header
#[derive(Copy, Clone, Debug)]
pub struct ClusterLibraryHeader {
    /// Frame control, see `FrameControl`
    pub control: FrameControl,
    /// Optional manufacturer code for manufacturer specific clusters
    pub manufacturer: Option<u16>,
    /// Transaction sequence code
    pub transaction_sequence: u8,
    /// Command identifier
    pub command: u8,
}

impl Pack<ClusterLibraryHeader, Error> for ClusterLibraryHeader {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let length = if self.manufacturer.is_some() { 5 } else { 3 };
        if data.len() < length {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut control = self.control;
        control.manufacturer_specific = self.manufacturer.is_some();
        control.pack(&mut data[0..1])?;
        let mut offset = 1;
        if let Some(manufacturer) = self.manufacturer {
            LittleEndian::write_u16(&mut data[offset..offset + 2], manufacturer);
            offset += 2;
        }
        data[offset] = self.transaction_sequence;
        offset += 1;
        data[offset] = self.command;
        offset += 1;
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let control = FrameControl::unpack(&data[0..1])?;
        let mut offset = 1;
        let manufacturer = if control.manufacturer_specific {
            if data.len() < 5 {
                return Err(Error::WrongNumberOfBytes);
            }
            let manufacturer = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
            Some(manufacturer)
        } else {
            None
        };

        let transaction_sequence = data[offset];
        offset += 1;
        let command = data[offset];
        offset += 1;

        Ok((
            Self {
                control,
                manufacturer,
                transaction_sequence,
                command,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_frame_control() {
        let data = [0x11];

        let control = FrameControl::unpack(&data[0..1]).unwrap();

        assert_eq!(control.frame_type, FrameType::Local);
        assert_eq!(control.manufacturer_specific, false);
        assert_eq!(control.direction, Direction::ToServer);
        assert_eq!(control.disable_default_response, true);
    }

    #[test]
    fn pack_frame_control() {
        let mut data = [0u8; 1];

        let control = FrameControl {
            frame_type: FrameType::Local,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        };

        control.pack(&mut data).unwrap();
        assert_eq!(data[0], 0x01);

        let control = FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: true,
            direction: Direction::ToServer,
            disable_default_response: false,
        };

        control.pack(&mut data).unwrap();
        assert_eq!(data[0], 0x04);

        let control = FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToClient,
            disable_default_response: false,
        };

        control.pack(&mut data).unwrap();
        assert_eq!(data[0], 0x08);

        let control = FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: true,
        };

        control.pack(&mut data).unwrap();
        assert_eq!(data[0], 0x10);
    }

    #[test]
    fn unpack_header() {
        let data = [0x11, 0x80, 0x00, 0x16, 0x1f, 0xb4, 0x5b, 0x02, 0x12];

        let (zcl, used) = ClusterLibraryHeader::unpack(&data[..]).unwrap();

        assert_eq!(used, 3);
        assert_eq!(zcl.control.frame_type, FrameType::Local);
        assert_eq!(zcl.control.manufacturer_specific, false);
        assert_eq!(zcl.control.direction, Direction::ToServer);
        assert_eq!(zcl.control.disable_default_response, true);
        assert_eq!(zcl.manufacturer, None);
        assert_eq!(zcl.transaction_sequence, 0x80);
        assert_eq!(zcl.command, 0x00);

        let data = [0x11, 0x98, 0x00, 0xea, 0x78, 0x53, 0xb9, 0x02, 0x12];

        let (zcl, used) = ClusterLibraryHeader::unpack(&data[..]).unwrap();

        assert_eq!(used, 3);
        assert_eq!(zcl.control.frame_type, FrameType::Local);
        assert_eq!(zcl.control.manufacturer_specific, false);
        assert_eq!(zcl.control.direction, Direction::ToServer);
        assert_eq!(zcl.control.disable_default_response, true);
        assert_eq!(zcl.manufacturer, None);
        assert_eq!(zcl.transaction_sequence, 0x98);
        assert_eq!(zcl.command, 0x00);
    }

    #[test]
    fn unpack_header_2() {
        let data = [0x18, 0x05, 0x01, 0x0b, 0x05, 0x00, 0x29, 0x00, 0x00];

        let (zcl, used) = ClusterLibraryHeader::unpack(&data[..]).unwrap();

        assert_eq!(used, 3);
        assert_eq!(zcl.control.frame_type, FrameType::Global);
        assert_eq!(zcl.control.manufacturer_specific, false);
        assert_eq!(zcl.control.direction, Direction::ToClient);
        assert_eq!(zcl.control.disable_default_response, true);
        assert_eq!(zcl.manufacturer, None);
        assert_eq!(zcl.transaction_sequence, 0x05);
        assert_eq!(zcl.command, 0x01);

        let data = [0x00, 0x04, 0x00, 0x0b, 0x05];

        let (zcl, used) = ClusterLibraryHeader::unpack(&data[..]).unwrap();

        assert_eq!(used, 3);
        assert_eq!(zcl.control.frame_type, FrameType::Global);
        assert_eq!(zcl.control.manufacturer_specific, false);
        assert_eq!(zcl.control.direction, Direction::ToServer);
        assert_eq!(zcl.control.disable_default_response, false);
        assert_eq!(zcl.manufacturer, None);
        assert_eq!(zcl.transaction_sequence, 0x04);
        assert_eq!(zcl.command, 0x00);
    }

    #[test]
    fn pack_header() {
        let mut buffer = [0u8; 32];

        let header = ClusterLibraryHeader {
            control: FrameControl {
                frame_type: FrameType::Local,
                manufacturer_specific: false,
                direction: Direction::ToClient,
                disable_default_response: false,
            },
            manufacturer: None,
            transaction_sequence: 0x34,
            command: 0x18,
        };
        let used = header.pack(&mut buffer).unwrap();

        assert_eq!(used, 3);
        assert_eq!(buffer[0], 0x09); // control
        assert_eq!(buffer[1], 0x34); // transaction sequence
        assert_eq!(buffer[2], 0x18); // command

        let header = ClusterLibraryHeader {
            control: FrameControl {
                frame_type: FrameType::Local,
                manufacturer_specific: false,
                direction: Direction::ToClient,
                disable_default_response: false,
            },
            manufacturer: Some(0x7654),
            transaction_sequence: 0x01,
            command: 0xee,
        };
        let used = header.pack(&mut buffer).unwrap();

        assert_eq!(used, 5);
        assert_eq!(buffer[0], 0x0d); // control
        assert_eq!(buffer[1..=2], [0x54, 0x76]); // manufacturer
        assert_eq!(buffer[3], 0x01); // transaction sequence
        assert_eq!(buffer[4], 0xee); // command

        let header = ClusterLibraryHeader {
            control: FrameControl {
                frame_type: FrameType::Global,
                manufacturer_specific: true,
                direction: Direction::ToClient,
                disable_default_response: false,
            },
            manufacturer: None,
            transaction_sequence: 0xf1,
            command: 0xaa,
        };
        let used = header.pack(&mut buffer).unwrap();

        assert_eq!(used, 3);
        assert_eq!(buffer[0], 0x08); // control
        assert_eq!(buffer[1], 0xf1); // transaction sequence
        assert_eq!(buffer[2], 0xaa); // command
    }
}
