use core::cell::Cell;

pub use ieee802154::mac::{
    command::{AssociationStatus, CapabilityInformation, Command},
    Address, AddressMode, ExtendedAddress, Frame, FrameContent, FrameType, FrameVersion, Header,
    Security, ShortAddress, WriteFooter,
};

use psila_data::PanIdentifier;

use crate::indentity::Identity;
use crate::Error;

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
            coordinator: Identity::new(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn identity(&self) -> Identity {
        self.identity
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
        destination: Address,
        source: Address,
    ) -> Header {
        let sequence = if frame_type == FrameType::Acknowledgement {
            0
        } else {
            self.sequence_next()
        };
        let compression = if let (Some(dst), Some(src)) = (destination.pan_id(), source.pan_id()) {
            dst == src
        } else {
            false
        };
        Header {
            seq: sequence,
            frame_type,
            security: Security::None,
            frame_pending: pending,
            ack_request: acknowledge,
            pan_id_compress: compression,
            version: self.version,
            destination,
            source,
        }
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
    /// 1. If this is a response to a data reuqest frame, this is set to true
    ///    if there is data pending, otherwise false.
    ///
    /// No payload
    ///
    pub fn build_acknowledge(&self, sequence: u8, pending: bool, mut data: &mut [u8]) -> usize {
        let mut header = self.create_header(
            FrameType::Acknowledgement,
            pending,
            false,
            Address::None,
            Address::None,
        );
        header.seq = sequence;
        let frame = Frame {
            header,
            content: FrameContent::Acknowledgement,
            payload: &[],
            footer: [0u8; 2],
        };
        frame.encode(&mut data, WriteFooter::No)
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
            Address::None,
        );
        let frame = Frame {
            header,
            content: FrameContent::Command(Command::BeaconRequest),
            payload: &[],
            footer: [0u8; 2],
        };
        Ok((frame.encode(data, WriteFooter::No), 2_000_000))
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
        let header = self.create_header(FrameType::MacCommand, false, true, destination, source);
        let frame = Frame {
            header,
            content: FrameContent::Command(Command::AssociationRequest(self.capabilities)),
            payload: &[],
            footer: [0u8; 2],
        };
        Ok((frame.encode(data, WriteFooter::No), 0))
    }

    pub fn build_data_request(
        &self,
        destination: psila_data::ShortAddress,
        data: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        let source = if self.identity.assigned_short() {
            Address::Short(self.pan_identifier.into(), self.identity.short.into())
        } else {
            Address::Extended(self.pan_identifier.into(), self.identity.extended.into())
        };
        let header = self.create_header(
            FrameType::MacCommand,
            false,
            true,
            Address::Short(self.pan_identifier.into(), destination.into()),
            source,
        );
        let frame = Frame {
            header,
            content: FrameContent::Command(Command::DataRequest),
            payload: &[0u8; 0],
            footer: [0u8; 2],
        };
        Ok((frame.encode(data, WriteFooter::No), 0))
    }

    pub fn requests_acknowledge(&self, frame: &Frame) -> bool {
        if frame.header.ack_request {
            self.identity.addressed_to(&frame.header.destination)
        } else {
            false
        }
    }

    fn handle_beacon(&mut self, frame: &Frame, buffer: &mut [u8]) -> Result<(usize, u32), Error> {
        let (src_id, src_short) = if let Address::Short(id, short) = frame.header.source {
            (id.into(), short.into())
        } else {
            return Err(Error::InvalidAddress);
        };
        if let FrameContent::Beacon(beacon) = &frame.content {
            if beacon.superframe_spec.pan_coordinator && beacon.superframe_spec.association_permit {
                if let State::Scan = self.state {
                    self.pan_identifier = src_id;
                    self.coordinator.short = src_short;
                    self.state = State::Associate;
                    // Send a association request
                    return self.build_association_request(src_id, src_short, buffer);
                }
            }
        }
        Ok((0, 0))
    }

    fn handle_association_response(
        &mut self,
        header: &Header,
        address: ShortAddress,
        status: AssociationStatus,
        _buffer: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        let pan_id = if let Some(pan_id) = header.source.pan_id() {
            pan_id.into()
        } else {
            return Err(Error::InvalidPanIdentifier);
        };
        if pan_id != self.pan_identifier {
            return Err(Error::InvalidPanIdentifier);
        }
        match (self.state, status) {
            (State::QueryAssociationStatus, AssociationStatus::Successful) => {
                self.pan_identifier = pan_id;
                self.identity.short = address.into();
                self.state = State::Associated;
            }
            (State::QueryAssociationStatus, _) => {
                self.pan_identifier = PanIdentifier::broadcast();
                self.identity.short = psila_data::ShortAddress::broadcast();
                self.state = State::Orphan;
            }
            (_, _) => {}
        }
        Ok((0, 0))
    }

    fn handle_command(&mut self, frame: &Frame, buffer: &mut [u8]) -> Result<(usize, u32), Error> {
        if let FrameContent::Command(command) = &frame.content {
            match command {
                Command::AssociationResponse(address, status) => {
                    self.handle_association_response(&frame.header, *address, *status, buffer)
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
                return self.build_data_request(self.coordinator.short, buffer);
            }
        }
        Ok((0, 0))
    }

    pub fn handle_frame(
        &mut self,
        frame: &Frame,
        buffer: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        match frame.header.frame_type {
            FrameType::Acknowledgement => self.handle_acknowledge(&frame, buffer),
            FrameType::Beacon => self.handle_beacon(&frame, buffer),
            FrameType::Data => Ok((0, 0)),
            FrameType::MacCommand => self.handle_command(&frame, buffer),
        }
    }

    pub fn timeout(&mut self, buffer: &mut [u8]) -> Result<(usize, u32), Error> {
        match self.state {
            State::Orphan => {
                self.state = State::Scan;
                self.build_beacon_request(buffer)
            }
            State::Scan | State::Associate | State::QueryAssociationStatus => {
                self.state = State::Orphan;
                Ok((0, 27_000_000))
            }
            State::Associated => Ok((0, 0)),
        }
    }
}

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;

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
        let size = service.build_acknowledge(0xaa, false, &mut data);

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
        assert_eq!(timeout, 0);
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
