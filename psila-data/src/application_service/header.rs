use core::convert::TryFrom;

use crate::error::Error;
use crate::pack::{Pack, PackFixed};

use byteorder::{ByteOrder, LittleEndian};

/// 2.2.5.1.1.1 Frame Type Sub-Field
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FrameType {
    Data = 0b00,
    Command = 0b01,
    Acknowledgement = 0b10,
    InterPan = 0b11,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b11 {
            0b00 => Ok(FrameType::Data),
            0b01 => Ok(FrameType::Command),
            0b10 => Ok(FrameType::Acknowledgement),
            0b11 => Ok(FrameType::InterPan),
            _ => Err(Error::UnknownFrameType),
        }
    }
}

/// 2.2.5.1.1.2 Delivery Mode Sub-Field
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DeliveryMode {
    Unicast = 0b0000,
    Indirect = 0b0100,
    Broadcast = 0b1000,
    GroupAdressing = 0b1100,
}

impl TryFrom<u8> for DeliveryMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b1100 {
            0b0000 => Ok(DeliveryMode::Unicast),
            0b0100 => Ok(DeliveryMode::Indirect),
            0b1000 => Ok(DeliveryMode::Broadcast),
            0b1100 => Ok(DeliveryMode::GroupAdressing),
            _ => Err(Error::UnknownDeliveryMode),
        }
    }
}

/// 2.2.5.1.1 Frame Control Field
#[derive(Copy, Clone, Debug)]
pub struct FrameControl {
    pub frame_type: FrameType,
    pub delivery_mode: DeliveryMode,
    pub acknowledge_format: bool,
    pub security: bool,
    pub acknowledge_request: bool,
    pub extended_header: bool,
}

impl PackFixed<FrameControl, Error> for FrameControl {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 1 {
            return Err(Error::NotEnoughSpace);
        }
        let frame_type = self.frame_type as u8;
        let delivery_mode = self.delivery_mode as u8;
        data[0] = frame_type
            | delivery_mode
            | (self.acknowledge_format as u8) << 4
            | (self.security as u8) << 5
            | (self.acknowledge_request as u8) << 6
            | (self.extended_header as u8) << 7;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 1 {
            return Err(Error::WrongNumberOfBytes);
        }
        let frame_type = FrameType::try_from(data[0])?;
        let delivery_mode = DeliveryMode::try_from(data[0])?;
        let acknowledge_format = (data[0] & 0x10) == 0x10;
        let security = (data[0] & 0x20) == 0x20;
        let acknowledge_request = (data[0] & 0x40) == 0x40;
        let extended_header = (data[0] & 0x80) == 0x80;
        Ok(FrameControl {
            frame_type,
            delivery_mode,
            acknowledge_format,
            security,
            acknowledge_request,
            extended_header,
        })
    }
}

/// 2.2.5 Frame Formats
#[derive(Copy, Clone, Debug)]
pub struct ApplicationServiceHeader {
    pub control: FrameControl,
    pub destination: Option<u8>,
    pub group: Option<u16>,
    pub cluster: Option<u16>,
    pub profile: Option<u16>,
    pub source: Option<u8>,
    pub counter: u8,
}

impl ApplicationServiceHeader {
    pub fn new_data_header(
        destination: u8,
        cluster: u16,
        profile: u16,
        source: u8,
        counter: u8,
        acknowledge_request: bool,
        secure: bool,
    ) -> Self {
        ApplicationServiceHeader {
            control: FrameControl {
                frame_type: FrameType::Data,
                delivery_mode: DeliveryMode::Unicast,
                acknowledge_format: false,
                security: secure,
                acknowledge_request,
                extended_header: false,
            },
            destination: Some(destination),
            group: None,
            cluster: Some(cluster),
            profile: Some(profile),
            source: Some(source),
            counter,
        }
    }

    pub fn new_acknowledge_header(source: &ApplicationServiceHeader) -> Self {
        if source.control.acknowledge_format {
            ApplicationServiceHeader {
                control: FrameControl {
                    frame_type: FrameType::Acknowledgement,
                    delivery_mode: DeliveryMode::Unicast,
                    acknowledge_format: true,
                    security: source.control.security,
                    acknowledge_request: false,
                    extended_header: false,
                },
                destination: None,
                group: None,
                cluster: None,
                profile: None,
                source: None,
                counter: source.counter,
            }
        } else {
            ApplicationServiceHeader {
                control: FrameControl {
                    frame_type: FrameType::Acknowledgement,
                    delivery_mode: DeliveryMode::Unicast,
                    acknowledge_format: false,
                    security: source.control.security,
                    acknowledge_request: false,
                    extended_header: false,
                },
                destination: source.destination,
                group: None,
                cluster: source.cluster,
                profile: source.profile,
                source: source.source,
                counter: source.counter,
            }
        }
    }

    fn which_fields(control: FrameControl) -> (bool, bool, bool, bool, usize) {
        let (has_destination, has_group, has_cluster_profile, has_source) = match control.frame_type
        {
            FrameType::Data => {
                let (has_destination, has_group) = match control.delivery_mode {
                    DeliveryMode::Unicast | DeliveryMode::Broadcast => (true, false),
                    DeliveryMode::GroupAdressing => (false, true),
                    DeliveryMode::Indirect => (false, false),
                };
                (has_destination, has_group, true, true)
            }
            FrameType::Command => (false, false, false, false),
            FrameType::Acknowledgement => {
                let has_address = !control.acknowledge_format;
                (has_address, false, has_address, has_address)
            }
            FrameType::InterPan => (false, false, true, false),
        };
        let length = 2; // control and counter
        let length = length + if has_destination { 1 } else { 0 };
        let length = length + if has_group { 2 } else { 0 };
        let length = length + if has_cluster_profile { 4 } else { 0 };
        let length = length + if has_source { 1 } else { 0 };
        (
            has_destination,
            has_group,
            has_cluster_profile,
            has_source,
            length,
        )
    }
}

impl Pack<ApplicationServiceHeader, Error> for ApplicationServiceHeader {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let (has_destination, has_group, has_cluster_profile, has_source, length) =
            Self::which_fields(self.control);
        assert_eq!(self.destination.is_some(), has_destination);
        assert_eq!(self.group.is_some(), has_group);
        assert_eq!(self.cluster.is_some(), has_cluster_profile);
        assert_eq!(self.profile.is_some(), has_cluster_profile);
        assert_eq!(self.source.is_some(), has_source);
        if data.len() < length {
            return Err(Error::NotEnoughSpace);
        }
        self.control.pack(&mut data[..1])?;
        let mut offset = 1;
        if let Some(destination) = self.destination {
            data[offset] = destination;
            offset += 1;
        }
        if let Some(group) = self.group {
            LittleEndian::write_u16(&mut data[offset..offset + 2], group);
            offset += 2;
        }
        if let Some(cluster) = self.cluster {
            LittleEndian::write_u16(&mut data[offset..offset + 2], cluster);
            offset += 2;
        }
        if let Some(profile) = self.profile {
            LittleEndian::write_u16(&mut data[offset..offset + 2], profile);
            offset += 2;
        }
        if let Some(source) = self.source {
            data[offset] = source;
            offset += 1;
        }
        data[offset] = self.counter;
        offset += 1;
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        let control = FrameControl::unpack(&data[..1])?;
        let mut offset = 1;
        let (has_destination, has_group, has_cluster_profile, has_source, length) =
            Self::which_fields(control);
        if data.len() < length {
            return Err(Error::NotEnoughSpace);
        }
        let destination = if has_destination {
            offset += 1;
            Some(data[offset - 1])
        } else {
            None
        };
        let group = if has_group {
            let word = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
            Some(word)
        } else {
            None
        };
        let cluster = if has_cluster_profile {
            let word = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
            Some(word)
        } else {
            None
        };
        let profile = if has_cluster_profile {
            let word = LittleEndian::read_u16(&data[offset..offset + 2]);
            offset += 2;
            Some(word)
        } else {
            None
        };
        let source = if has_source {
            offset += 1;
            Some(data[offset - 1])
        } else {
            None
        };
        let counter = if control.frame_type == FrameType::InterPan {
            0
        } else {
            offset += 1;
            data[offset - 1]
        };

        Ok((
            ApplicationServiceHeader {
                control,
                destination,
                group,
                cluster,
                profile,
                source,
                counter,
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
        let data = [0x21];
        let fc = FrameControl::unpack(&data[..1]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Command);
        assert_eq!(fc.delivery_mode, DeliveryMode::Unicast);
        assert_eq!(fc.acknowledge_format, false);
        assert_eq!(fc.security, true);
        assert_eq!(fc.acknowledge_request, false);
        assert_eq!(fc.extended_header, false);
    }

    #[test]
    fn pack_frame_control() {
        let mut data = [0xff];

        let control = FrameControl {
            frame_type: FrameType::Data,
            delivery_mode: DeliveryMode::Unicast,
            acknowledge_format: false,
            security: false,
            acknowledge_request: false,
            extended_header: false,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x00);

        let control = FrameControl {
            frame_type: FrameType::Command,
            delivery_mode: DeliveryMode::Unicast,
            acknowledge_format: false,
            security: false,
            acknowledge_request: false,
            extended_header: false,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x01);

        let control = FrameControl {
            frame_type: FrameType::Acknowledgement,
            delivery_mode: DeliveryMode::Unicast,
            acknowledge_format: false,
            security: false,
            acknowledge_request: false,
            extended_header: false,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x02);

        let control = FrameControl {
            frame_type: FrameType::InterPan,
            delivery_mode: DeliveryMode::Unicast,
            acknowledge_format: false,
            security: false,
            acknowledge_request: false,
            extended_header: true,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x83);

        let control = FrameControl {
            frame_type: FrameType::Acknowledgement,
            delivery_mode: DeliveryMode::Broadcast,
            acknowledge_format: false,
            security: false,
            acknowledge_request: true,
            extended_header: false,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x4a);

        let control = FrameControl {
            frame_type: FrameType::Command,
            delivery_mode: DeliveryMode::GroupAdressing,
            acknowledge_format: false,
            security: true,
            acknowledge_request: false,
            extended_header: false,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x2d);

        let control = FrameControl {
            frame_type: FrameType::Acknowledgement,
            delivery_mode: DeliveryMode::Unicast,
            acknowledge_format: true,
            security: false,
            acknowledge_request: false,
            extended_header: false,
        };
        let _ = control.pack(&mut data);
        assert_eq!(data[0], 0x12);
    }

    #[cfg(not(feature = "core"))]
    fn print_frame(frame: &ApplicationServiceHeader) {
        print!(
            "APS {:?} {:?}",
            frame.control.frame_type, frame.control.delivery_mode,
        );
        if frame.control.security {
            print!(" Secure");
        }
        if frame.control.acknowledge_request {
            print!(" AckReq");
        }
        if frame.control.extended_header {
            print!(" ExtHdr");
        }
        if let Some(addr) = frame.destination {
            print!(" Dst {:02x}", addr);
        }
        if let Some(group) = frame.group {
            print!(" Group {:04x}", group);
        }
        if let Some(cluster) = frame.cluster {
            print!(" Cluster {:04x}", cluster);
        }
        if let Some(profile) = frame.profile {
            print!(" Profile {:04x}", profile);
        }
        if let Some(addr) = frame.source {
            print!(" Src {:02x}", addr);
        }
        println!(" Counter {:02x}", frame.counter);
    }

    #[cfg(feature = "core")]
    fn print_frame(_frame: &ApplicationServiceHeader) {}

    #[test]
    fn unpack_frame() {
        let data = [
            0x28, 0x72, 0x30, 0x00, 0x00, 0x63, 0x7d, 0x61, 0x03, 0x00, 0x8d, 0x15, 0x00, 0x00,
            0xc2, 0x57, 0xc5, 0x9b, 0x87, 0xa2,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 8);
        print_frame(&aps);
        let data = [
            0x21, 0xd3, 0x30, 0x06, 0x00, 0x00, 0x00, 0xb5, 0x41, 0x24, 0x74, 0x03, 0x00, 0xb5,
            0xb4, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x00, 0xea, 0x6a, 0x2a, 0x9b, 0x69, 0x62,
            0x51, 0x29, 0x71, 0x41, 0xa5, 0x8c, 0x33, 0x78, 0xc5, 0x9b, 0xf8, 0xc2, 0x11, 0x17,
            0x10, 0xe4, 0x00, 0x8e, 0xbc, 0xbc, 0xf5, 0x76, 0x15, 0x3e, 0x2a, 0x2e,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        print_frame(&aps);
        let data = [
            0x21, 0x99, 0x30, 0x01, 0x00, 0x00, 0x00, 0xb5, 0xb4, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0xe7, 0xdf, 0x99, 0xc9, 0x81, 0x22, 0x3d, 0x67, 0x29, 0x31, 0x45, 0xb3, 0x2b,
            0xa2, 0x11, 0x74, 0xcb, 0xcc, 0xbd, 0xe5, 0xe4, 0x76, 0xb0, 0x6e, 0x05, 0xee, 0x35,
            0xfd, 0x5f, 0xd1, 0xd8, 0x08, 0x8e, 0x4d, 0xc1, 0x70, 0xa1, 0x52, 0xa9,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        print_frame(&aps);
        let data = [
            0x21, 0xa7, 0x30, 0x03, 0x00, 0x00, 0x00, 0xb5, 0xb4, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0x62, 0xd3, 0x3d, 0xca, 0x7f, 0x86, 0xaa, 0x15, 0x8f, 0x4c, 0x7b, 0xee, 0xa7,
            0xf0, 0x3b, 0x1d, 0x89, 0xe8, 0x7c, 0x20, 0x3d, 0xc2, 0x63, 0xb9, 0x7f, 0x7e, 0xeb,
            0x6d, 0x39, 0x13, 0x6b, 0x7f, 0x36, 0x73, 0x83, 0x66, 0x8d, 0xc1, 0x93,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        print_frame(&aps);
        let data = [
            0x21, 0x41, 0x30, 0x01, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x03, 0xff, 0xc8, 0x53, 0x5f,
            0x02, 0x13, 0x2b, 0xff, 0x2e, 0x21, 0x00, 0x00, 0x61, 0x00, 0x75, 0x27, 0xe5, 0x94,
            0x3e, 0x3f, 0xd9, 0x47, 0x3c, 0x81, 0xfa, 0x7a, 0xda, 0x82, 0x34, 0x51, 0x81, 0x3f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        print_frame(&aps);
        let data = [
            0x21, 0x45, 0x30, 0x02, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21,
            0x00, 0xae, 0x5e, 0x9f, 0x46, 0xa6, 0x40, 0xcd, 0xe7, 0x90, 0x2f, 0xd6, 0x0e, 0x43,
            0x23, 0x17, 0x48, 0x4b, 0x4c, 0x5a, 0x9b, 0x4c, 0xde, 0x1c, 0xe7, 0x07, 0x07, 0xb6,
            0xfb, 0x1a, 0x0b, 0xe9, 0x99, 0x7e, 0x0a, 0xf8, 0x0f, 0xdf, 0x5d, 0xcf,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        print_frame(&aps);
        let data = [
            0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x06, 0x81, 0x7b, 0xc0, 0x85, 0xae, 0x21,
            0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x80,
        ];
        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        assert_eq!(used, 8);
        print_frame(&aps);
    }

    #[test]
    fn unpack_inter_pan_frame() {
        let data = [
            0x0b, 0x00, 0x10, 0x5e, 0xc0, 0x11, 0x80, 0x00, 0x16, 0x1f, 0xb4, 0x5b, 0x02, 0x12,
        ];

        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        print_frame(&aps);

        // Touchlink has cluster 1000 and profile c05e

        assert_eq!(used, 5);

        let data = [
            0x0b, 0x00, 0x10, 0x5e, 0xc0, 0x11, 0x98, 0x00, 0xea, 0x78, 0x53, 0xb9, 0x02, 0x12,
        ];

        let (aps, used) = ApplicationServiceHeader::unpack(&data[..]).unwrap();
        print_frame(&aps);

        assert_eq!(used, 5);
    }

    #[test]
    fn pack_frame() {
        let header = ApplicationServiceHeader::new_data_header(
            0x01, 0x7654, 0x1234, 0x00, 0xaa, false, true,
        );
        let mut buffer = [0u8; 32];
        let size = header.pack(&mut buffer).unwrap();
        assert_eq!(size, 8);
        assert_eq!(buffer[0], 0x20);
        assert_eq!(buffer[1], 0x01);
        assert_eq!(buffer[2..=3], [0x54, 0x76]);
        assert_eq!(buffer[4..=5], [0x34, 0x12]);
        assert_eq!(buffer[6], 0x00);
        assert_eq!(buffer[7], 0xaa);
    }
}
