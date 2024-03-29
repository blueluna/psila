use byte::BytesExt;
use core::cell::Cell;

use ieee802154::mac::security::SecurityContext;
pub use ieee802154::mac::{
    command::{AssociationStatus, CapabilityInformation, Command},
    Address, AddressMode, ExtendedAddress, Frame, FrameContent, FrameType, FrameVersion, Header,
    ShortAddress,
};
use ieee802154::mac::{FooterMode, FrameSerDesContext};
use psila_data::PanIdentifier;

use crate::identity::Identity;
use crate::Error;

pub(crate) fn unpack_header(data: &[u8]) -> Result<Header, Error> {
    match data.read::<Header>(&mut 0) {
        Ok(header) => Ok(header),
        Err(error) => {
            match error {
                byte::Error::Incomplete => {
                    #[cfg(feature = "defmt")]
                    defmt::error!("Failed to unpack header, Incomplete, {}", data.len());
                }
                byte::Error::BadOffset(_offset) => {
                    #[cfg(feature = "defmt")]
                    defmt::error!("Failed to unpack header, Bad offset {}", _offset);
                }
                byte::Error::BadInput { err: _message } => {
                    #[cfg(feature = "defmt")]
                    defmt::error!("Failed to unpack header, Bad input {}", _message);
                }
            }
            Err(error.into())
        }
    }
}

pub(crate) fn pack_header(header: &Header, data: &mut [u8]) -> Result<usize, Error> {
    let mut len = 0usize;
    data.write_with(
        &mut len,
        *header,
        &Some(&mut SecurityContext::no_security()),
    )?;
    Ok(len)
}

pub(crate) fn unpack_frame(data: &[u8]) -> Result<Frame, Error> {
    match data.read_with::<Frame>(&mut 0, FooterMode::None) {
        Ok(frame) => Ok(frame),
        Err(error) => {
            match error {
                byte::Error::Incomplete => {
                    #[cfg(feature = "defmt")]
                    {
                        if let Ok(header) = unpack_header(data) {
                            defmt::error!(
                                "Failed to unpack frame, Incomplete, {} {=[u8]:02x} {=?}",
                                data.len(),
                                data,
                                header
                            );
                        } else {
                            defmt::error!(
                                "Failed to unpack frame, Incomplete, {} {=[u8]:02x}",
                                data.len(),
                                data
                            );
                        }
                    }
                }
                byte::Error::BadOffset(_offset) => {
                    #[cfg(feature = "defmt")]
                    defmt::error!("Failed to unpack frame, Bad offset {}", _offset);
                }
                byte::Error::BadInput { err: _message } => {
                    #[cfg(feature = "defmt")]
                    defmt::error!("Failed to unpack frame, Bad input {}", _message);
                }
            }
            Err(error.into())
        }
    }
}

pub(crate) fn pack_frame(frame: &Frame, data: &mut [u8]) -> Result<usize, Error> {
    let mut len = 0usize;
    data.write_with(
        &mut len,
        *frame,
        &mut FrameSerDesContext::no_security(FooterMode::None),
    )?;
    // defmt::info!("pack_frame seq {=u8}, {=[u8]:02x}", frame.header.seq, data[..len]);
    Ok(len)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Orphan,
    Scan,
    Associate,
    QueryAssociationStatus,
    Associated,
}

/// MAC-layer service
pub struct MacService {
    state: State,
    version: FrameVersion,
    sequence: Cell<u8>,
    pan_identifier: PanIdentifier,
    identity: Identity,
    capabilities: CapabilityInformation,
    coordinator: Identity,
    next_event_timestamp: u32,
}

impl MacService {
    /// Create a new `MacService`
    ///
    /// Will use the 802.15.4-2003 version without security
    pub fn new(
        address: psila_data::ExtendedAddress,
        capabilities: psila_data::CapabilityInformation,
    ) -> Self {
        let capabilities = CapabilityInformation {
            full_function_device: capabilities.router_capable,
            mains_power: capabilities.mains_power,
            idle_receive: capabilities.idle_receive,
            frame_protection: capabilities.frame_protection,
            allocate_address: capabilities.allocate_address,
        };
        MacService {
            state: State::Orphan,
            version: FrameVersion::Ieee802154_2003,
            sequence: Cell::new(0),
            pan_identifier: PanIdentifier::broadcast(),
            identity: Identity::from_extended(address),
            capabilities,
            coordinator: Identity::default(),
            next_event_timestamp: 0,
        }
    }

    pub fn set_network(
        &mut self,
        pan_identifier: PanIdentifier,
        short_address: psila_data::ShortAddress,
        coordinator: Identity,
    ) -> Result<(), Error> {
        self.pan_identifier = pan_identifier;
        self.identity.short = short_address;
        self.coordinator = coordinator;
        self.state = State::Associated;
        Ok(())
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn pan_identifier(&self) -> PanIdentifier {
        self.pan_identifier
    }

    pub fn coordinator_identity(&self) -> Identity {
        self.coordinator
    }

    /// Get the next sequence number
    fn sequence_next(&self) -> u8 {
        let sequence = (*self).sequence.get();
        let sequence = sequence.wrapping_add(1);
        (*self).sequence.set(sequence);
        sequence
    }

    /// Create a header using the provided arguments
    fn create_header(
        &self,
        frame_type: FrameType,
        pending: bool,
        acknowledge: bool,
        destination: Option<Address>,
        source: Option<Address>,
    ) -> Header {
        let sequence = if frame_type == FrameType::Acknowledgement {
            0
        } else {
            self.sequence_next()
        };
        let compression = if let (Some(dst), Some(src)) = (destination, source) {
            dst.pan_id() == src.pan_id()
        } else {
            false
        };
        Header {
            seq: sequence,
            frame_type,
            auxiliary_security_header: None,
            frame_pending: pending,
            ack_request: acknowledge,
            pan_id_compress: compression,
            version: self.version,
            ie_present: false,
            seq_no_suppress: false,
            destination,
            source,
        }
    }

    /// Create a header using the provided arguments
    fn create_header_self_source(
        &self,
        frame_type: FrameType,
        pending: bool,
        acknowledge: bool,
        destination: Option<Address>,
    ) -> Header {
        let source = if self.identity.assigned_short() {
            Address::Short(self.pan_identifier.into(), self.identity.short.into())
        } else {
            Address::Extended(self.pan_identifier.into(), self.identity.extended.into())
        };
        self.create_header(frame_type, pending, acknowledge, destination, Some(source))
    }

    /// Build a Imm-Ack frame
    ///
    /// IEEE 802.15.4-2015 chapter 7.3.3
    ///
    /// ```notrust
    /// +-------------+--------+---------+-------------+----------+----------+
    /// | Destination | Source | Pending | Acknowledge | Compress | Security |
    /// +-------------+--------+---------+-------------+----------+----------+
    /// | None        | None   | 1       | false       | false    | false    |
    /// +-------------+--------+---------+-------------+----------+----------+
    /// ```
    ///
    /// 1. If this is a response to a data request frame, this is set to true
    ///    if there is data pending, otherwise false.
    ///
    /// No payload
    ///
    pub fn build_acknowledge(
        &self,
        sequence: u8,
        pending: bool,
        data: &mut [u8],
    ) -> Result<usize, Error> {
        let mut header = self.create_header(FrameType::Acknowledgement, pending, false, None, None);
        header.seq = sequence;
        let frame = Frame {
            header,
            content: FrameContent::Acknowledgement,
            payload: &[],
            footer: [0u8; 2],
        };
        pack_frame(&frame, data)
    }

    /// Build a beacon request frame
    ///
    /// IEEE 802.15.4-2015 chapter 7.5.8
    ///
    /// ```notrust
    /// +-------------+--------+---------+-------------+----------+----------+
    /// | Destination | Source | Pending | Acknowledge | Compress | Security |
    /// +-------------+--------+---------+-------------+----------+----------+
    /// | Short       | None   | false   | false       | false    | false    |
    /// +-------------+--------+---------+-------------+----------+----------+
    /// ```
    ///
    /// ```notrust
    /// +------------+------------+-------------+-----------+
    /// | Dst PAN Id | Src PAN Id | Destination | Source    |
    /// +------------+------------+-------------+-----------+
    /// | Broadcast  | None       | Broadcast   | None      |
    /// +------------+------------+-------------+-----------+
    /// ```
    ///
    /// No payload
    ///
    pub fn build_beacon_request(&self, data: &mut [u8]) -> Result<(usize, u32), Error> {
        let header = self.create_header(
            FrameType::MacCommand,
            false,
            false,
            Address::broadcast(&AddressMode::Short),
            None,
        );
        let frame = Frame {
            header,
            content: FrameContent::Command(Command::BeaconRequest),
            payload: &[],
            footer: [0u8; 2],
        };
        let length = pack_frame(&frame, data)?;
        Ok((length, 2_000_000))
    }

    pub fn build_association_request(
        &self,
        pan_id: PanIdentifier,
        destination: psila_data::ShortAddress,
        data: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        let source = Address::Extended(
            PanIdentifier::broadcast().into(),
            self.identity.extended.into(),
        );
        let destination = Address::Short(pan_id.into(), destination.into());
        let header = self.create_header(
            FrameType::MacCommand,
            false,
            true,
            Some(destination),
            Some(source),
        );
        let frame = Frame {
            header,
            content: FrameContent::Command(Command::AssociationRequest(self.capabilities)),
            payload: &[],
            footer: [0u8; 2],
        };
        let length = pack_frame(&frame, data)?;
        Ok((length, 5_000_000))
    }

    pub fn build_data_request(
        &self,
        destination: psila_data::ShortAddress,
        data: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        let header = self.create_header_self_source(
            FrameType::MacCommand,
            false,
            true,
            Some(Address::Short(
                self.pan_identifier.into(),
                destination.into(),
            )),
        );
        let frame = Frame {
            header,
            content: FrameContent::Command(Command::DataRequest),
            payload: &[0u8; 0],
            footer: [0u8; 2],
        };
        let length = pack_frame(&frame, data)?;
        Ok((length, 0))
    }

    pub fn build_data_header(
        &self,
        destination: psila_data::ShortAddress,
        acknowledge: bool,
    ) -> Header {
        self.create_header_self_source(
            FrameType::Data,
            false, // Pending data
            acknowledge,
            Some(Address::Short(
                self.pan_identifier.into(),
                destination.into(),
            )),
        )
    }

    pub fn requests_acknowledge(&self, frame: &Frame) -> bool {
        if frame.header.ack_request {
            self.identity.addressed_to(&frame.header.destination)
        } else {
            false
        }
    }

    fn handle_beacon(&mut self, frame: &Frame) -> Result<(usize, u32), Error> {
        let (src_id, src_short) = if let Some(Address::Short(id, short)) = frame.header.source {
            (id.into(), short.into())
        } else {
            return Err(Error::InvalidAddress);
        };
        if let FrameContent::Beacon(beacon) = &frame.content {
            if beacon.superframe_spec.pan_coordinator && beacon.superframe_spec.association_permit {
                if let State::Scan = self.state {
                    #[cfg(feature = "defmt")]
                    defmt::info!(
                        "mac: Beacon {=u16:04x}:{=u16:04x} permit join",
                        u16::from(src_id),
                        u16::from(src_short)
                    );
                    self.pan_identifier = src_id;
                    self.coordinator.short = src_short;
                    self.state = State::Associate;
                }
            } else {
                #[cfg(feature = "defmt")]
                defmt::info!(
                    "mac: Beacon {=u16:04x}:{=u16:04x}",
                    u16::from(src_id),
                    u16::from(src_short)
                );
            }
        } else {
            // Failed to parse beacon
        }
        Ok((0, 0))
    }

    fn handle_association_response(
        &mut self,
        header: &Header,
        address: ShortAddress,
        status: AssociationStatus,
    ) -> Result<(usize, u32), Error> {
        let pan_id = if let Some(src) = header.source {
            src.pan_id().into()
        } else {
            #[cfg(feature = "defmt")]
            defmt::warn!("Invalid PAN indetifier");
            return Err(Error::InvalidPanIdentifier);
        };
        if pan_id != self.pan_identifier {
            #[cfg(feature = "defmt")]
            defmt::warn!(
                "Invalid PAN indetifier {=u16} != {=u16}",
                u16::from(pan_id),
                u16::from(self.pan_identifier)
            );
            return Err(Error::InvalidPanIdentifier);
        }
        match (self.state, status) {
            (State::QueryAssociationStatus, AssociationStatus::Successful) => {
                #[cfg(feature = "defmt")]
                defmt::info!(
                    "MAC: Association Response, Success, {=u16}:{=u16}",
                    u16::from(pan_id),
                    address.0
                );
                self.pan_identifier = pan_id;
                self.identity.short = address.into();
                self.state = State::Associated;
            }
            (State::QueryAssociationStatus, _) => {
                #[cfg(feature = "defmt")]
                defmt::info!(
                    "MAC: Association Response {=u16} {=u8}",
                    u16::from(pan_id),
                    u8::from(status)
                );
                self.pan_identifier = PanIdentifier::broadcast();
                self.identity.short = psila_data::ShortAddress::broadcast();
                self.state = State::Orphan;
            }
            (_, AssociationStatus::Successful) => {
                #[cfg(feature = "defmt")]
                defmt::info!(
                    "MAC: Association Response, Success, {=u16}:{=u16}, Bad state",
                    u16::from(pan_id),
                    address.0
                );
            }
            (_, _) => {}
        }
        Ok((0, 0))
    }

    fn handle_command(&mut self, frame: &Frame) -> Result<(usize, u32), Error> {
        if let FrameContent::Command(command) = &frame.content {
            match command {
                Command::AssociationResponse(address, status) => {
                    self.handle_association_response(&frame.header, *address, *status)
                }
                _ => Ok((0, 0)),
            }
        } else {
            Err(Error::MalformedPacket)
        }
    }

    fn handle_acknowledge(
        &mut self,
        frame: &Frame,
        buffer: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        if frame.header.seq == self.sequence.get() {
            if let State::Associate = self.state {
                self.state = State::QueryAssociationStatus;
                #[cfg(feature = "defmt")]
                defmt::info!("MAC: Send data request");
                return self.build_data_request(self.coordinator.short, buffer);
            }
        } else {
            if self.destination_me(frame) {
                #[cfg(feature = "defmt")]
                defmt::warn!("MAC: Acknowledge, unknown sequence {=u8}", frame.header.seq);
            }
        }
        Ok((0, 0))
    }

    pub fn handle_frame(
        &mut self,
        timestamp: u32,
        frame: &Frame,
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        let (used, timeout) = match frame.header.frame_type {
            FrameType::Acknowledgement => self.handle_acknowledge(&frame, buffer),
            FrameType::Beacon => self.handle_beacon(&frame),
            FrameType::MacCommand => self.handle_command(&frame),
            FrameType::Data
            | FrameType::Multipurpose
            | FrameType::FragOrFragAck
            | FrameType::Extended => Ok((0, 0)),
        }?;
        if timeout > 0 {
            self.next_event_timestamp = timestamp.wrapping_add(timeout);
        }
        Ok(used)
    }

    pub fn update(&mut self, timestamp: u32, buffer: &mut [u8]) -> Result<usize, Error> {
        if timestamp < self.next_event_timestamp {
            return Ok(0);
        }
        let (used, timeout) = match self.state {
            State::Orphan => {
                self.state = State::Scan;
                #[cfg(feature = "defmt")]
                defmt::info!("MAC: Send beacon request");
                self.build_beacon_request(buffer)
            }
            State::Scan | State::QueryAssociationStatus => {
                #[cfg(feature = "defmt")]
                defmt::info!("MAC: Association failed, retry");
                self.state = State::Orphan;
                Ok((0, 28_000_000))
            }
            State::Associate => {
                // Send a association request
                #[cfg(feature = "defmt")]
                defmt::info!("MAC: Send association request");
                self.build_association_request(self.pan_identifier, self.coordinator.short, buffer)
            }
            State::Associated => Ok((0, 0)),
        }?;
        if timeout > 0 {
            self.next_event_timestamp = timestamp.wrapping_add(timeout);
        }
        Ok(used)
    }

    fn match_short_address<T: Into<ShortAddress>>(&self, address: T) -> bool {
        if self.identity.short.is_assigned() {
            self.identity.short == address.into()
        } else {
            false
        }
    }

    fn match_extended_address<T: Into<ExtendedAddress>>(&self, address: T) -> bool {
        if !self.identity.extended.is_broadcast() {
            self.identity.extended == address.into()
        } else {
            false
        }
    }

    fn match_associated_pan<T: Into<PanIdentifier>>(&self, pan_identifier: T) -> bool {
        if self.pan_identifier.is_assigned() {
            self.pan_identifier == pan_identifier.into()
        } else {
            false
        }
    }

    fn match_associated_pan_or_broadcast<T: Into<PanIdentifier>>(&self, pan_identifier: T) -> bool {
        if self.pan_identifier.is_assigned() {
            let pan_id = pan_identifier.into();
            self.pan_identifier == pan_id || pan_id.is_broadcast()
        } else {
            false
        }
    }

    fn destination_me(&self, frame: &Frame) -> bool {
        match frame.header.destination {
            None => false,
            Some(Address::Short(pan_id, address)) => {
                self.match_associated_pan(pan_id) && self.match_short_address(address)
            }
            Some(Address::Extended(pan_id, address)) => {
                self.match_associated_pan(pan_id) && self.match_extended_address(address)
            }
        }
    }

    fn broadcast_destination(&self, frame: &Frame) -> bool {
        match frame.header.destination {
            None => true,
            Some(Address::Short(pan_id, address)) => {
                if address == ieee802154::mac::ShortAddress::broadcast() {
                    self.match_associated_pan_or_broadcast(pan_id)
                } else {
                    false
                }
            }
            Some(Address::Extended(pan_id, address)) => {
                if address == ieee802154::mac::ExtendedAddress::broadcast() {
                    self.match_associated_pan_or_broadcast(pan_id)
                } else {
                    false
                }
            }
        }
    }

    pub fn destination_me_or_broadcast(&self, frame: &Frame) -> bool {
        self.destination_me(frame) || self.broadcast_destination(frame)
    }
}

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;

    #[test]
    fn unpack_acknowledge() {
        unpack_frame(&[2u8, 0u8, 4u8]).unwrap();
    }

    #[test]
    fn build_acknowledge() {
        let address = psila_data::ExtendedAddress::new(0x8899_aabb_ccdd_eeff);
        let capabilities = psila_data::CapabilityInformation {
            alternate_pan_coordinator: false,
            router_capable: false,
            mains_power: true,
            idle_receive: true,
            frame_protection: false,
            allocate_address: true,
        };
        let service = MacService::new(address, capabilities);

        let mut data = [0u8; 256];
        let size = service.build_acknowledge(0xaa, false, &mut data).unwrap();

        assert_eq!(size, 3);
        assert_eq!(data[..size], [0x02, 0x00, 0xaa]);
    }

    #[test]
    fn build_beacon_request() {
        let address = psila_data::ExtendedAddress::new(0x8899_aabb_ccdd_eeff);
        let capabilities = psila_data::CapabilityInformation {
            alternate_pan_coordinator: false,
            router_capable: false,
            mains_power: true,
            idle_receive: true,
            frame_protection: false,
            allocate_address: true,
        };
        let service = MacService::new(address, capabilities);

        let mut data = [0u8; 256];
        let (size, timeout) = service.build_beacon_request(&mut data).unwrap();

        assert_eq!(size, 8);
        assert_eq!(timeout, 2_000_000);
        assert_eq!(
            data[..size],
            [0x03, 0x08, 0x01, 0xff, 0xff, 0xff, 0xff, 0x07]
        );
    }

    #[test]
    fn build_association_request() {
        let address = psila_data::ExtendedAddress::new(0x8899_aabb_ccdd_eeff);
        let capabilities = psila_data::CapabilityInformation {
            alternate_pan_coordinator: false,
            router_capable: false,
            mains_power: true,
            idle_receive: true,
            frame_protection: false,
            allocate_address: true,
        };
        let service = MacService::new(address, capabilities);
        let network_id = psila_data::PanIdentifier::new(0x6745);
        let coordinator_address = psila_data::ShortAddress::new(0xa987);

        let mut data = [0u8; 256];
        let (size, timeout) = service
            .build_association_request(network_id, coordinator_address, &mut data)
            .unwrap();

        assert_eq!(size, 19);
        assert_eq!(timeout, 5_000_000);
        assert_eq!(
            data[..size],
            [
                0x23, 0xc8, 0x01, 0x45, 0x67, 0x87, 0xa9, 0xff, 0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb,
                0xaa, 0x99, 0x88, 0x01, 0x8c
            ]
        );
    }

    #[test]
    fn build_data_request() {
        let address = psila_data::ExtendedAddress::new(0x8899_aabb_ccdd_eeff);
        let capabilities = psila_data::CapabilityInformation {
            alternate_pan_coordinator: false,
            router_capable: false,
            mains_power: true,
            idle_receive: true,
            frame_protection: false,
            allocate_address: true,
        };
        let mut service = MacService::new(address, capabilities);
        let destination = psila_data::ShortAddress::new(0xa987);
        let network_id = psila_data::PanIdentifier::new(0x6745);
        service.pan_identifier = network_id;

        let mut data = [0u8; 256];
        let (size, timeout) = service.build_data_request(destination, &mut data).unwrap();

        assert_eq!(size, 16);
        assert_eq!(timeout, 0);
        assert_eq!(
            data[..size],
            [
                0x63, 0xc8, 0x01, 0x45, 0x67, 0x87, 0xa9, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                0x88, 0x04
            ]
        );
    }
}
