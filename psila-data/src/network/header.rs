//! Network header

use core::convert::TryFrom;

use crate::common::address::{EXTENDED_ADDRESS_SIZE, SHORT_ADDRESS_SIZE};
use crate::pack::{Pack, PackFixed};
use crate::{Error, ExtendedAddress, NetworkAddress};

/// Frame type sub-field
///
/// Indicates if this frame is a Data, Command or Inter-PAN frame.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FrameType {
    /// Data frame
    Data = 0b0000_0000,
    /// Command frame
    Command = 0b0000_0001,
    /// Inter-PAN frame
    InterPan = 0b0000_0011,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b0000_0011 {
            0b00 => Ok(FrameType::Data),
            0b01 => Ok(FrameType::Command),
            0b11 => Ok(FrameType::InterPan),
            _ => Err(Error::UnknownFrameType),
        }
    }
}

/// Discover route sub-field
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DiscoverRoute {
    /// Supress route discovery
    SurpressDiscovery = 0b0000_0000,
    /// Enable route discovery
    EnableDiscovery = 0b0100_0000,
}

impl TryFrom<u8> for DiscoverRoute {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b1100_0000 {
            0b0000_0000 => Ok(DiscoverRoute::SurpressDiscovery),
            0b0100_0000 => Ok(DiscoverRoute::EnableDiscovery),
            _ => Err(Error::UnknownDiscoverRoute),
        }
    }
}

/// Frame Control Field
#[derive(Copy, Clone, Debug)]
pub struct FrameControl {
    /// Frame Type Sub-Field
    pub frame_type: FrameType,
    /// Protocol Version Sub-Field
    pub protocol_version: u8,
    /// Discover Route Sub-Field
    pub discover_route: DiscoverRoute,
    /// Multicast Flag Sub-Field
    multicast: bool,
    /// Security Sub-Field
    pub security: bool,
    /// Source Route Sub-Field
    contains_source_route_frame: bool,
    /// Destination IEEE Address Sub-Field
    contains_destination_ieee_address: bool,
    /// Source IEEE Address Sub-Field
    contains_source_ieee_address: bool,
}

impl PackFixed<FrameControl, Error> for FrameControl {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 2 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let frame_type = self.frame_type as u8;
            let discover_route = self.discover_route as u8;

            data[0] = frame_type | (self.protocol_version << 2) | discover_route;
            data[1] = self.multicast as u8
                | ((self.security as u8) << 1)
                | ((self.contains_source_route_frame as u8) << 2)
                | ((self.contains_destination_ieee_address as u8) << 3)
                | ((self.contains_source_ieee_address as u8) << 4);
            Ok(())
        }
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 2 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let frame_type = FrameType::try_from(data[0])?;
            let discover_route = DiscoverRoute::try_from(data[0])?;
            Ok(Self {
                frame_type,
                protocol_version: (data[0] >> 2) & 0b1111,
                discover_route,
                multicast: (data[1]) & 0b1 == 1,
                security: (data[1] >> 1) & 0b1 == 1,
                contains_source_route_frame: (data[1] >> 2) & 0b1 == 1,
                contains_destination_ieee_address: (data[1] >> 3) & 0b1 == 1,
                contains_source_ieee_address: (data[1] >> 4) & 0b1 == 1,
            })
        }
    }
}

// 3.3.1.8.1 Multicast Mode Sub-Field
/// Multi-cast member mode
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MulticastMode {
    /// Sent from a device which is not member of the group
    NonmemberMode = 0b0000_0000,
    /// Sent from a device which is member of the group
    MemberMode = 0b0000_0001,
}

impl TryFrom<u8> for MulticastMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b0000_0011 {
            0b0000_0000 => Ok(MulticastMode::NonmemberMode),
            0b0000_0001 => Ok(MulticastMode::MemberMode),
            _ => Err(Error::UnknownDiscoverRoute),
        }
    }
}

// 3.3.1.8 Multicast Control Field
/// Multi-cast control field
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct MulticastControl {
    /// Multi-cast member mode
    pub mode: MulticastMode,
    /// Non-member radius
    /// Decremeted for each hop, discard if the radius is zero. The value 7 has
    /// a special meaning, infinite. Then the value shall not decremented.
    pub radius: u8,
    /// Maximum radius
    pub max_radius: u8,
}

impl PackFixed<MulticastControl, Error> for MulticastControl {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 1 {
            Err(Error::WrongNumberOfBytes)
        } else {
            data[0] = self.mode as u8 & (self.radius << 2) & (self.max_radius << 5);
            Ok(())
        }
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 1 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let mode = MulticastMode::try_from(data[0])?;
            Ok(Self {
                mode,
                radius: (data[0] >> 2) & 0b111,
                max_radius: (data[0] >> 5) & 0b111,
            })
        }
    }
}

/// Source route frame message
#[derive(Clone, Debug, PartialEq)]
pub struct SourceRouteFrame {
    /// Index
    pub index: u8,
    /// Number of entries
    num_entries: u8,
    /// Entries
    entries: [NetworkAddress; 32],
}

impl SourceRouteFrame {
    /// Create a source route frame from relay list
    pub fn new(relay_list: &[NetworkAddress]) -> Self {
        if relay_list.is_empty() {
            panic!("Relay list cannot be of length 0.");
        }
        let mut entries = [NetworkAddress::default(); 32];
        entries[..relay_list.len()].copy_from_slice(relay_list);
        Self {
            index: relay_list.len() as u8 - 1,
            num_entries: relay_list.len() as u8,
            entries,
        }
    }
    /// No route entries
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }
    /// Number of route entries
    pub fn len(&self) -> usize {
        self.num_entries as usize
    }
    /// Get index
    pub fn get_index(&self) -> u8 {
        self.index
    }
    /// Decrement index
    pub fn decrement_index(&mut self) {
        self.index -= 1;
    }
    /// Route entries
    pub fn entries(&self) -> &[NetworkAddress] {
        &self.entries[..self.num_entries as usize]
    }
}

impl Pack<SourceRouteFrame, Error> for SourceRouteFrame {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 2 + self.len() * 2 {
            Err(Error::WrongNumberOfBytes)
        } else {
            data[0] = self.num_entries;
            data[1] = self.index;
            let mut offset = 2;
            for address in &self.entries[..self.len()] {
                address.pack(&mut data[offset..offset + SHORT_ADDRESS_SIZE])?;
                offset += SHORT_ADDRESS_SIZE;
            }
            Ok(offset)
        }
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let count = data[0] as usize;
        let index = data[1];
        if data.len() < (count * SHORT_ADDRESS_SIZE) + 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        if count == 0 || index as usize >= count {
            return Err(Error::BrokenRelayList);
        }
        let end = 2 + (count * SHORT_ADDRESS_SIZE);
        let mut entries = [NetworkAddress::default(); 32];
        for (n, chunk) in data[2..end].chunks(SHORT_ADDRESS_SIZE).enumerate() {
            entries[n] = NetworkAddress::unpack(chunk)?;
        }
        Ok((
            Self {
                index,
                num_entries: data[0],
                entries,
            },
            (count * SHORT_ADDRESS_SIZE) + 2,
        ))
    }
}

const MIN_NUM_BYTES: usize = 8;

/// Network frame header
///
#[derive(Clone, Debug)]
pub struct NetworkHeader {
    /// Frame control field
    pub control: FrameControl,
    /// Network destination address
    pub destination_address: NetworkAddress,
    /// Network source address
    pub source_address: NetworkAddress,
    /// Radius
    pub radius: u8,
    /// Frame sequence number
    pub sequence_number: u8,
    /// Optional extended (IEEE) destination address
    pub destination_ieee_address: Option<ExtendedAddress>,
    /// Optional extended (IEEE) source address
    pub source_ieee_address: Option<ExtendedAddress>,
    /// Optional multicast control field
    pub multicast_control: Option<MulticastControl>,
    /// Optional source route frame field
    pub source_route_frame: Option<SourceRouteFrame>,
}

impl NetworkHeader {
    /// Create a new data header with the given information
    pub fn new_data_header(
        protocol_version: u8,
        discover_route: DiscoverRoute,
        security: bool,
        destination_address: NetworkAddress,
        source_address: NetworkAddress,
        radius: u8,
        sequence_number: u8,
        source_route_frame: Option<SourceRouteFrame>,
    ) -> Self {
        Self {
            control: FrameControl {
                frame_type: FrameType::Data,
                protocol_version,
                discover_route,
                multicast: false,
                security,
                contains_source_route_frame: source_route_frame.is_some(),
                contains_destination_ieee_address: false,
                contains_source_ieee_address: false,
            },
            destination_address,
            source_address,
            radius,
            sequence_number,
            destination_ieee_address: None,
            source_ieee_address: None,
            multicast_control: None,
            source_route_frame,
        }
    }
    /// Create a new command header with the given information
    pub fn new_command_header(
        protocol_version: u8,
        discover_route: DiscoverRoute,
        security: bool,
        destination_address: NetworkAddress,
        source_address: NetworkAddress,
        radius: u8,
        sequence_number: u8,
        source_route_frame: Option<SourceRouteFrame>,
    ) -> Self {
        Self {
            control: FrameControl {
                frame_type: FrameType::Command,
                protocol_version,
                discover_route,
                multicast: false,
                security,
                contains_source_route_frame: source_route_frame.is_some(),
                contains_destination_ieee_address: false,
                contains_source_ieee_address: false,
            },
            destination_address,
            source_address,
            radius,
            sequence_number,
            destination_ieee_address: None,
            source_ieee_address: None,
            multicast_control: None,
            source_route_frame,
        }
    }
}

impl Pack<NetworkHeader, Error> for NetworkHeader {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let mut control = self.control;
        if control.frame_type == FrameType::InterPan {
            control.pack(&mut data[0..2])?;
            return Ok(2);
        }
        let mut total_length = MIN_NUM_BYTES;

        self.destination_address.pack(&mut data[2..=3])?;
        self.source_address.pack(&mut data[4..=5])?;
        data[6] = self.radius;
        data[7] = self.sequence_number;

        control.contains_destination_ieee_address = if let Some(v) = self.destination_ieee_address {
            if data.len() > total_length + 8 {
                v.pack(&mut data[total_length..total_length + 8])?;
                total_length += 8;
                true
            } else {
                return Err(Error::NotEnoughSpace);
            }
        } else {
            false
        };

        control.contains_source_ieee_address = if let Some(v) = self.source_ieee_address {
            if data.len() > total_length + 8 {
                v.pack(&mut data[total_length..total_length + 8])?;
                total_length += 8;
                true
            } else {
                return Err(Error::NotEnoughSpace);
            }
        } else {
            false
        };

        control.multicast = if let Some(v) = self.multicast_control {
            if data.len() > total_length + 8 {
                v.pack(&mut data[total_length..=total_length])?;
                total_length += 1;
                true
            } else {
                return Err(Error::NotEnoughSpace);
            }
        } else {
            false
        };

        control.contains_source_route_frame = if let Some(v) = &self.source_route_frame {
            if data.len() > total_length + 8 {
                let length = v.pack(&mut data[total_length..total_length + 8])?;
                total_length += length as usize;
                true
            } else {
                return Err(Error::NotEnoughSpace);
            }
        } else {
            false
        };

        control.pack(&mut data[0..2])?;

        Ok(total_length)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let frame_control = FrameControl::unpack(&data[0..2])?;
        if frame_control.frame_type == FrameType::InterPan {
            return Ok((
                NetworkHeader {
                    control: frame_control,
                    destination_address: NetworkAddress::from(0),
                    source_address: NetworkAddress::from(0),
                    radius: 0,
                    sequence_number: 0,
                    destination_ieee_address: None,
                    source_ieee_address: None,
                    multicast_control: None,
                    source_route_frame: None,
                },
                2,
            ));
        }
        if data.len() < MIN_NUM_BYTES {
            return Err(Error::WrongNumberOfBytes);
        }
        let destination_address = NetworkAddress::unpack(&data[2..4])?;
        let source_address = NetworkAddress::unpack(&data[4..6])?;

        let frame_control = FrameControl::unpack(&data[0..2])?;

        let mut total_length = MIN_NUM_BYTES;

        if frame_control.contains_destination_ieee_address {
            total_length += EXTENDED_ADDRESS_SIZE;
        }
        if frame_control.contains_source_ieee_address {
            total_length += EXTENDED_ADDRESS_SIZE;
        }
        if frame_control.multicast {
            total_length += 1;
        }
        if data.len() < total_length {
            return Err(Error::WrongNumberOfBytes);
        }

        let mut offset = MIN_NUM_BYTES;

        let destination_ieee_address = if frame_control.contains_destination_ieee_address {
            let destination_ieee_address =
                ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
            Some(destination_ieee_address)
        } else {
            None
        };

        let source_ieee_address = if frame_control.contains_source_ieee_address {
            let source_ieee_address =
                ExtendedAddress::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
            offset += EXTENDED_ADDRESS_SIZE;
            Some(source_ieee_address)
        } else {
            None
        };

        let multicast_control = if frame_control.multicast {
            let multicast_control = Some(MulticastControl::unpack(&data[offset..=offset])?);
            offset += 1;
            multicast_control
        } else {
            None
        };

        let source_route_frame = if frame_control.contains_source_route_frame {
            let (source_route_frame, used) = SourceRouteFrame::unpack(&data[offset..])?;
            offset += used;
            Some(source_route_frame)
        } else {
            None
        };

        Ok((
            NetworkHeader {
                control: frame_control,
                destination_address,
                source_address,
                radius: data[6],
                sequence_number: data[7],
                destination_ieee_address,
                source_ieee_address,
                multicast_control,
                source_route_frame,
            },
            offset,
        ))
    }
}

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;

    #[allow(clippy::cognitive_complexity)]
    #[test]
    fn unpack_frame_control_1() {
        let data = [0x00, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x01, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Command);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x03, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::InterPan);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x04, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 1);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x3c, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 15);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x40, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::EnableDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);
    }

    #[allow(clippy::cognitive_complexity)]
    #[test]
    fn unpack_frame_control_2() {
        let data = [0x00, 0x01];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, true);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x00, 0x02];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, true);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x00, 0x04];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, true);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x00, 0x08];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, true);
        assert_eq!(fc.contains_source_ieee_address, false);

        let data = [0x00, 0x10];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, true);

        let data = [0x00, 0xe0];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::Data);
        assert_eq!(fc.protocol_version, 0);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);
    }

    #[test]
    fn unpack_frame_control_3() {
        let data = [0x0b, 0x00];
        let fc = FrameControl::unpack(&data[..2]).unwrap();
        assert_eq!(fc.frame_type, FrameType::InterPan);
        assert_eq!(fc.protocol_version, 2);
        assert_eq!(fc.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(fc.multicast, false);
        assert_eq!(fc.security, false);
        assert_eq!(fc.contains_source_route_frame, false);
        assert_eq!(fc.contains_destination_ieee_address, false);
        assert_eq!(fc.contains_source_ieee_address, false);
    }

    #[test]
    fn unpack_frame_control_error() {
        let data = [0x02, 0x00];
        match FrameControl::unpack(&data[..2]) {
            Ok(_) => {
                unreachable!();
            }
            Err(e) => match e {
                Error::UnknownFrameType => {}
                _ => {
                    unreachable!();
                }
            },
        }

        let data = [0x80, 0x00];
        match FrameControl::unpack(&data[..2]) {
            Ok(_) => {
                unreachable!();
            }
            Err(e) => match e {
                Error::UnknownDiscoverRoute => {}
                _ => {
                    unreachable!();
                }
            },
        }

        let data = [0xc0, 0x00];
        match FrameControl::unpack(&data[..2]) {
            Ok(_) => {
                unreachable!();
            }
            Err(e) => match e {
                Error::UnknownDiscoverRoute => {}
                _ => {
                    unreachable!();
                }
            },
        }
    }

    #[test]
    fn pack_frame_control_1() {
        let control = FrameControl {
            frame_type: FrameType::Data,
            protocol_version: 2,
            discover_route: DiscoverRoute::SurpressDiscovery,
            multicast: false,
            security: true,
            contains_source_route_frame: false,
            contains_destination_ieee_address: false,
            contains_source_ieee_address: false,
        };
        let correct_data = [0x08, 0x02];
        let mut data = [0x00; 2];
        control.pack(&mut data).unwrap();
        assert_eq!(data, correct_data);

        let control = FrameControl {
            frame_type: FrameType::Command,
            protocol_version: 1,
            discover_route: DiscoverRoute::EnableDiscovery,
            multicast: false,
            security: false,
            contains_source_route_frame: false,
            contains_destination_ieee_address: false,
            contains_source_ieee_address: false,
        };
        let correct_data = [0x45, 0x00];
        control.pack(&mut data).unwrap();
        assert_eq!(data, correct_data);

        let control = FrameControl {
            frame_type: FrameType::Data,
            protocol_version: 2,
            discover_route: DiscoverRoute::SurpressDiscovery,
            multicast: true,
            security: false,
            contains_source_route_frame: false,
            contains_destination_ieee_address: false,
            contains_source_ieee_address: false,
        };
        let correct_data = [0x08, 0x01];
        let mut data = [0x00; 2];
        control.pack(&mut data).unwrap();
        assert_eq!(data, correct_data);

        let control = FrameControl {
            frame_type: FrameType::Data,
            protocol_version: 2,
            discover_route: DiscoverRoute::SurpressDiscovery,
            multicast: false,
            security: false,
            contains_source_route_frame: true,
            contains_destination_ieee_address: false,
            contains_source_ieee_address: false,
        };
        let correct_data = [0x08, 0x04];
        let mut data = [0x00; 2];
        control.pack(&mut data).unwrap();
        assert_eq!(data, correct_data);

        let control = FrameControl {
            frame_type: FrameType::Data,
            protocol_version: 2,
            discover_route: DiscoverRoute::SurpressDiscovery,
            multicast: false,
            security: false,
            contains_source_route_frame: false,
            contains_destination_ieee_address: true,
            contains_source_ieee_address: false,
        };
        let correct_data = [0x08, 0x08];
        let mut data = [0x00; 2];
        control.pack(&mut data).unwrap();
        assert_eq!(data, correct_data);

        let control = FrameControl {
            frame_type: FrameType::Data,
            protocol_version: 2,
            discover_route: DiscoverRoute::SurpressDiscovery,
            multicast: false,
            security: false,
            contains_source_route_frame: false,
            contains_destination_ieee_address: false,
            contains_source_ieee_address: true,
        };
        let correct_data = [0x08, 0x10];
        let mut data = [0x00; 2];
        control.pack(&mut data).unwrap();
        assert_eq!(data, correct_data);
    }

    fn print_frame(frame: &NetworkHeader) {
        print!("NWK Type {:?} ", frame.control.frame_type);
        print!("Version {} ", frame.control.protocol_version);
        print!("{:?} ", frame.control.discover_route);
        print!("DST {} ", frame.destination_address);
        print!("SRC {} ", frame.source_address);
        print!("RAD {} ", frame.radius);
        print!("SEQ {:02x} ", frame.sequence_number);
        if let Some(dst) = frame.destination_ieee_address {
            print!("DST {} ", dst);
        }
        if let Some(src) = frame.source_ieee_address {
            print!("SRC {} ", src);
        }
        if let Some(mc) = &frame.multicast_control {
            print!("Multi-Cast {:?} ", mc);
        }
        if let Some(srf) = &frame.source_route_frame {
            print!("Secure {:?} ", srf);
        }
    }

    #[test]
    fn unpack_data_header() {
        let data = [0x08, 0x00, 0x3e, 0xed, 0x00, 0x00, 0x01, 0x87];
        let (nwk, used) = NetworkHeader::unpack(&data[..]).unwrap();
        print_frame(&nwk);
        assert_eq!(used, 8);
        assert_eq!(nwk.control.frame_type, FrameType::Data);
        assert_eq!(nwk.control.protocol_version, 2);
        assert_eq!(nwk.control.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(nwk.control.multicast, false);
        assert_eq!(nwk.control.security, false);
        assert_eq!(nwk.control.contains_source_route_frame, false);
        assert_eq!(nwk.control.contains_destination_ieee_address, false);
        assert_eq!(nwk.control.contains_source_ieee_address, false);
        assert_eq!(nwk.destination_address, [0x3e, 0xed]);
        assert_eq!(nwk.source_address, [0x00, 0x00]);
        assert_eq!(nwk.radius, 1);
        assert_eq!(nwk.sequence_number, 135);
        assert_eq!(nwk.destination_ieee_address, None);
        assert_eq!(nwk.source_ieee_address, None);
        assert_eq!(nwk.multicast_control, None);
        assert_eq!(nwk.source_route_frame, None);
    }

    #[test]
    fn unpack_inter_pan_header() {
        let data = [0x0b, 0x00];
        let (nwk, used) = NetworkHeader::unpack(&data[..]).unwrap();
        print_frame(&nwk);
        assert_eq!(used, 2);
        assert_eq!(nwk.control.frame_type, FrameType::InterPan);
        assert_eq!(nwk.control.protocol_version, 2);
        assert_eq!(nwk.control.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(nwk.control.multicast, false);
        assert_eq!(nwk.control.security, false);
        assert_eq!(nwk.control.contains_source_route_frame, false);
        assert_eq!(nwk.control.contains_destination_ieee_address, false);
        assert_eq!(nwk.control.contains_source_ieee_address, false);
        assert_eq!(nwk.destination_address, [0, 0]);
        assert_eq!(nwk.source_address, [0, 0]);
        assert_eq!(nwk.radius, 0);
        assert_eq!(nwk.sequence_number, 0);
        assert_eq!(nwk.destination_ieee_address, None);
        assert_eq!(nwk.source_ieee_address, None);
        assert_eq!(nwk.multicast_control, None);
        assert_eq!(nwk.source_route_frame, None);
    }

    #[test]
    fn unpack_header() {
        let data = [
            0x08, 0x06, 0xa4, 0x31, 0x00, 0x00, 0x0a, 0x3b, 0x01, 0x00, 0xf9, 0xa7, 0x28, 0xa4,
            0xde, 0x0a, 0x00, 0xb5, 0xb4, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x00, 0xb3, 0x5d,
            0x06, 0xca, 0xec, 0x2c, 0xb3, 0xf3, 0x8a, 0x20, 0x4a, 0xb9,
        ];
        let (nwk, used) = NetworkHeader::unpack(&data[..]).unwrap();
        print_frame(&nwk);
        assert_eq!(used, 12);
        assert_eq!(nwk.control.frame_type, FrameType::Data);
        assert_eq!(nwk.control.protocol_version, 2);
        assert_eq!(nwk.control.discover_route, DiscoverRoute::SurpressDiscovery);
        assert_eq!(nwk.control.multicast, false);
        assert_eq!(nwk.control.security, true);
        assert_eq!(nwk.control.contains_source_route_frame, true);
        assert_eq!(nwk.control.contains_destination_ieee_address, false);
        assert_eq!(nwk.control.contains_source_ieee_address, false);
        assert_eq!(nwk.destination_address, [0xa4, 0x31]);
        assert_eq!(nwk.source_address, [0, 0]);
        assert_eq!(nwk.radius, 10);
        assert_eq!(nwk.sequence_number, 59);
        assert_eq!(nwk.destination_ieee_address, None);
        assert_eq!(nwk.source_ieee_address, None);
        assert_eq!(nwk.multicast_control, None);
        assert!(nwk.source_route_frame.is_some());
    }

    #[test]
    fn pack_header() {
        let control = FrameControl {
            frame_type: FrameType::Data,
            protocol_version: 2,
            discover_route: DiscoverRoute::SurpressDiscovery,
            multicast: false,
            security: true,
            contains_source_route_frame: false,
            contains_destination_ieee_address: false,
            contains_source_ieee_address: false,
        };
        let header = NetworkHeader {
            control,
            destination_address: NetworkAddress::new(0x31a4),
            source_address: NetworkAddress::new(0x0000),
            radius: 10,
            sequence_number: 59,
            destination_ieee_address: None,
            source_ieee_address: None,
            multicast_control: None,
            source_route_frame: None,
        };
        let correct_data = [0x08, 0x02, 0xa4, 0x31, 0x00, 0x00, 0x0a, 0x3b];
        let mut data = [0; 8];
        let used = header.pack(&mut data).unwrap();
        assert_eq!(used, 8);
        assert_eq!(data, correct_data);
    }
}
