//! # Psila Service

#![no_std]

use core::convert::From;
use core::convert::TryFrom;

use bbqueue::{Producer};

use heapless::Vec;

use psila_data::{
    self,
    cluster_library::{
        AttributeDataType, AttributeIdentifier, ClusterLibraryStatus, GeneralCommandIdentifier,
    },
    pack::Pack,
    CapabilityInformation, ExtendedAddress, Key, NetworkAddress, PanIdentifier,
};

use psila_crypto::CryptoBackend;

mod application_service;
mod cluster_library;
mod error;
mod identity;
pub mod mac;
mod security;

pub use cluster_library::ClusterLibraryHandler;
pub use error::Error;
pub use identity::Identity;

use application_service::ApplicationServiceContext;
use mac::MacService;

/// Max buffer size
pub const PACKET_BUFFER_MAX: usize = 128;

/// Link status reporting interval in microseconds
pub const LINK_STATUS_INTERVAL: u32 = 60_000_000;

use psila_data::pack::PackFixed;

/// Association state for this device in the network
#[derive(Clone, Copy, PartialEq)]
pub enum NetworkState {
    Orphan,
    Associated,
    Secure,
}

/// Information for a device on the network
// Also see 3.6.1.5 in the Zigbee specification
pub struct NetworkDevice {
    /// Device network address
    network_address: NetworkAddress,
    /// Device extended (IEEE) address
    extended_address: ExtendedAddress,
    /// Device last seen in milliseconds
    last_seen: u32,
    /// Type of device
    device_type: psila_data::device_profile::link_quality::DeviceType,
    /// Device relationship
    relationship: psila_data::device_profile::link_quality::Relationship,
    /// Link quality to the device
    link_quality: u8,
    /// Outgoing path cost to the device
    outgoing_cost: u8,
}

impl Default for NetworkDevice {
    fn default() -> Self {
        Self {
            network_address: NetworkAddress::default(),
            extended_address: ExtendedAddress::default(),
            last_seen: 0,
            device_type: psila_data::device_profile::link_quality::DeviceType::Unknown,
            relationship: psila_data::device_profile::link_quality::Relationship::NoneOfAbove,
            link_quality: 0xff,
            outgoing_cost: 0xff,
        }
    }
}

pub struct PsilaService<'a, CB, CLH, const N: usize> {
    mac: MacService,
    application_service: ApplicationServiceContext,
    security_manager: security::SecurityManager<CB>,
    capability: CapabilityInformation,
    tx_queue: Producer<'a, N>,
    state: NetworkState,
    identity: Identity,
    buffer: core::cell::RefCell<[u8; PACKET_BUFFER_MAX]>,
    scratch: core::cell::RefCell<[u8; PACKET_BUFFER_MAX]>,
    timestamp: u32,
    next_link_status: u32,
    known_devices: Vec<NetworkDevice, 16>,
    cluser_library_handler: CLH,
}

impl<'a, CB, CLH, const N: usize> PsilaService<'a, CB, CLH, N>
where
    CB: CryptoBackend,
    CLH: ClusterLibraryHandler,
{
    pub fn new(
        crypto: CB,
        tx_queue: Producer<'a, N>,
        address: ExtendedAddress,
        default_link_key: Key,
        cluser_library_handler: CLH,
    ) -> Self {
        let capability = CapabilityInformation {
            alternate_pan_coordinator: false,
            router_capable: false,
            mains_power: true,
            idle_receive: true,
            frame_protection: false,
            allocate_address: true,
        };
        Self {
            mac: MacService::new(address, capability),
            application_service: ApplicationServiceContext::default(),
            security_manager: security::SecurityManager::new(crypto, default_link_key),
            capability,
            tx_queue,
            state: NetworkState::Orphan,
            identity: Identity::default(),
            buffer: core::cell::RefCell::new([0u8; 128]),
            scratch: core::cell::RefCell::new([0u8; 128]),
            timestamp: 0,
            next_link_status: 0,
            known_devices: Vec::new(),
            cluser_library_handler,
        }
    }

    pub fn get_state(&self) -> NetworkState {
        self.state
    }

    fn set_state(&mut self, state: NetworkState) {
        match (self.state, state) {
            (NetworkState::Orphan, NetworkState::Secure) => {
                self.next_link_status = self.timestamp.wrapping_add(LINK_STATUS_INTERVAL);
            }
            (_, _) => {}
        }
        self.state = state;
    }

    pub fn set_network(
        &mut self,
        pan_identifier: PanIdentifier,
        network_address: NetworkAddress,
        coordinator_identity: Identity,
    ) -> Result<(), Error> {
        if self.get_state() == NetworkState::Orphan {
            self.mac
                .set_network(pan_identifier, network_address, coordinator_identity)?;
            self.set_state(NetworkState::Associated);
        }
        Ok(())
    }

    pub fn set_network_key(&mut self, key: Key, key_sequence: u8) -> Result<(), Error> {
        use psila_data::application_service::commands::transport_key::NetworkKey;
        if self.get_state() == NetworkState::Associated {
            let key = NetworkKey {
                key,
                sequence: key_sequence,
                destination: self.identity.extended,
                source: ExtendedAddress::broadcast(),
            };
            self.security_manager.set_network_key(key);
            self.set_state(NetworkState::Secure);
        }
        Ok(())
    }

    /// Push a packet onto the queue
    fn queue_packet_from_buffer(&mut self, length: usize) -> Result<(), Error> {
        assert!(length < PACKET_BUFFER_MAX);
        let grant_size = length + 1;
        match self.tx_queue.grant_exact(grant_size) {
            Ok(mut grant) => {
                grant[0] = length as u8;
                grant[1..].copy_from_slice(&self.buffer.borrow()[..length]);
                grant.commit(grant_size);
                Ok(())
            }
            Err(_) => Err(Error::NotEnoughSpace),
        }
    }

    /// Receive, call this method when new data has been received by the radio
    /// ### Return
    /// true if the message was addressed to this device
    pub fn handle_acknowledge(&mut self, data: &[u8]) -> Result<bool, Error> {
        match mac::Frame::decode(data, false) {
            Ok(frame) => {
                if !self.mac.destination_me_or_broadcast(&frame) {
                    return Ok(false);
                }
                if self.mac.requests_acknowledge(&frame) {
                    // If the frame is a data request frame, send an acknowledge with pending set
                    // Use the frame sequence number from the received frame in the acknowledge
                    let packet_length = self.mac.build_acknowledge(
                        frame.header.seq,
                        false,
                        &mut self.buffer.borrow_mut()[..],
                    );
                    self.queue_packet_from_buffer(packet_length)?;
                }
                Ok(true)
            }
            Err(_) => Err(Error::MalformedPacket),
        }
    }

    /// Receive, call this method when new data has been received by the radio
    /// ### Return
    /// A new timeout value that the timer shall be configured with, a timeout
    /// value of zero (0) shall be ignored
    pub fn receive(&mut self, timestamp: u32, data: &[u8]) -> Result<(), Error> {
        self.timestamp = timestamp;
        match mac::Frame::decode(data, false) {
            Ok(frame) => {
                if !self.mac.destination_me_or_broadcast(&frame) {
                    return Ok(());
                }
                let packet_length =
                    self.mac
                        .handle_frame(timestamp, &frame, &mut self.buffer.borrow_mut()[..])?;
                if packet_length > 0 {
                    self.queue_packet_from_buffer(packet_length)?;
                }
                if let mac::State::Associated = self.mac.state() {
                    if let NetworkState::Orphan = self.get_state() {
                        self.identity = *self.mac.identity();
                        self.set_state(NetworkState::Associated);
                    }
                    self.handle_mac_frame(&frame)?;
                }
                Ok(())
            }
            Err(_) => Err(Error::MalformedPacket),
        }
    }

    /// Update, call this method at ragular intervals
    pub fn update(&mut self, timestamp: u32) -> Result<(), Error> {
        self.timestamp = timestamp;
        let packet_length = self
            .mac
            .update(timestamp, &mut self.buffer.borrow_mut()[..])?;
        if packet_length > 0 {
            self.queue_packet_from_buffer(packet_length)?;
        }
        if self.get_state() != NetworkState::Secure {
            return Ok(());
        }
        if timestamp > self.next_link_status {
            let _ = self.queue_network_link_status();
            self.next_link_status = self.timestamp.wrapping_add(LINK_STATUS_INTERVAL);
        }
        Ok(())
    }

    fn handle_mac_frame(&mut self, frame: &mac::Frame) -> Result<(), Error> {
        use psila_data::network::{BeaconInformation, NetworkHeader};

        match frame.header.frame_type {
            mac::FrameType::Data => {
                let (header, used) = NetworkHeader::unpack(frame.payload)?;
                let mut payload = [0u8; PACKET_BUFFER_MAX];
                let payload_size = if header.control.security {
                    self.security_manager
                        .decrypt_payload(frame.payload, used, &mut payload)?
                } else {
                    let payload_size = frame.payload.len() - used;
                    payload[..payload_size].copy_from_slice(&frame.payload[used..]);
                    payload_size
                };
                // TODO: Look up source extended address
                if payload_size > 0 {
                    self.handle_network_frame(&header, &payload[..payload_size])?;
                }
            }
            mac::FrameType::Beacon => {
                defmt::info!("Handle network beacon");
                let _ = BeaconInformation::unpack(frame.payload)?;
            }
            _ => (),
        }
        Ok(())
    }

    /// Handle a network (NWK) frame
    fn handle_network_frame(
        &mut self,
        header: &psila_data::network::NetworkHeader,
        nwk_payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::application_service::ApplicationServiceHeader;
        use psila_data::network::header::FrameType;

        let nwk_header = header;

        match header.control.frame_type {
            FrameType::Data => {
                let mut aps_payload = [0u8; PACKET_BUFFER_MAX];
                let (aps_header, used) = ApplicationServiceHeader::unpack(nwk_payload)?;
                let aps_payload_length = if aps_header.control.security {
                    self.security_manager
                        .decrypt_payload(nwk_payload, used, &mut aps_payload)?
                } else {
                    let payload_length = nwk_payload.len() - used;
                    aps_payload[..payload_length].copy_from_slice(&nwk_payload[used..]);
                    payload_length
                };
                if aps_payload_length > 0 {
                    self.handle_application_service_frame(
                        &nwk_header,
                        &aps_header,
                        &aps_payload[..aps_payload_length],
                    )?;
                }
            }
            FrameType::Command => {
                // handle command
                self.handle_network_command(header, nwk_payload)?;
            }
            FrameType::InterPan => {
                // Not supported yet
                defmt::info!("Handle inter-PAN");
            }
        }
        Ok(())
    }

    /// Handle network (NWK) command
    fn handle_network_command(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::network::commands;

        let command_identifier = commands::CommandIdentifier::try_from(payload[0])?;

        match command_identifier {
            commands::CommandIdentifier::RouteRequest => {
                defmt::info!("> Network Route request");
                let (req, _) = commands::RouteRequest::unpack(&payload[1..])?;
                let nwk_match = match req.destination_address {
                    commands::AddressType::Singlecast(address) => {
                        // defmt::info!("> Short address {:}", address);
                        address == self.identity.short
                    }
                    commands::AddressType::Multicast(_) => false,
                };
                let extended_match = match req.destination_ieee_address {
                    Some(address) => address == self.identity.extended,
                    None => false,
                };
                if nwk_match {
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let reply = commands::RouteReply {
                        options: commands::route_reply::Options {
                            orginator_ieee_address: false,
                            multicast: false,
                            responder_ieee_address: false,
                        },
                        identifier: req.identifier,
                        orginator_address: nwk_header.source_address,
                        responder_address: self.identity.short,
                        path_cost: 1,
                        orginator_ieee_address: None,
                        responder_ieee_address: None,
                    };
                    let reply = commands::Command::RouteReply(reply);
                    let nwk_frame_size = self.application_service.build_network_command(
                        &self.identity,
                        nwk_header.source_address,
                        &reply,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    let frame_size = mac_header_len + nwk_frame_size;
                    match self.queue_packet_from_buffer(frame_size) {
                        Ok(()) => {
                            defmt::info!("< Queued route response {=usize}", frame_size);
                        }
                        Err(err) => {
                            defmt::error!("< Failed to queue route response");
                            return Err(err);
                        }
                    }
                } else if extended_match {
                    defmt::info!("Extended match");
                }
            }
            commands::CommandIdentifier::RouteReply => {
                defmt::info!("> Network Route reply");
            }
            commands::CommandIdentifier::NetworkStatus => {
                defmt::info!("> Network Network status");
            }
            commands::CommandIdentifier::Leave => {
                defmt::info!("> Network Leave");
            }
            commands::CommandIdentifier::RouteRecord => {
                defmt::info!("> Network Route record");
            }
            commands::CommandIdentifier::RejoinRequest => {
                defmt::info!("> Network Rejoin request");
            }
            commands::CommandIdentifier::RejoinResponse => {
                defmt::info!("> Network Rejoin response");
            }
            commands::CommandIdentifier::LinkStatus => {
                let mut cost = 0xff;
                match commands::LinkStatus::unpack(&payload[1..]) {
                    Ok((req, _)) => {
                        for entry in req.entries() {
                            if entry.address == self.identity.short {
                                cost = entry.incoming_cost;
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        defmt::info!("> Invalid Link Status");
                    }
                }
                if cost < 0xff {
                    for device in &mut self.known_devices {
                        if nwk_header.source_address == device.network_address {
                            device.outgoing_cost = cost;
                        }
                    }
                }
            }
            commands::CommandIdentifier::NetworkReport => {
                defmt::info!("> Network Network report");
            }
            commands::CommandIdentifier::NetworkUpdate => {
                defmt::info!("> Network Network update");
            }
            commands::CommandIdentifier::EndDeviceTimeoutRequest => {
                defmt::info!("> Network End-device timeout request");
            }
            commands::CommandIdentifier::EndDeviceTimeoutResponse => {
                defmt::info!("> Network End-device timeout response");
            }
        }
        Ok(())
    }

    fn handle_application_service_frame(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        aps_header: &psila_data::application_service::ApplicationServiceHeader,
        aps_payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::application_service::header::FrameType;

        self.handle_application_service_acknowledge(nwk_header, aps_header)?;

        match aps_header.control.frame_type {
            FrameType::Data => {
                if let (Some(cluster), Some(profile), Some(ep_src), Some(ep_dst)) = (
                    aps_header.cluster,
                    aps_header.profile,
                    aps_header.source,
                    aps_header.destination,
                ) {
                    if profile == 0x0000 {
                        self.handle_device_profile(nwk_header, cluster, aps_payload)?;
                    } else {
                        self.handle_cluster_library(
                            nwk_header,
                            profile,
                            cluster,
                            ep_src,
                            ep_dst,
                            aps_payload,
                        )?;
                    }
                } else {
                    defmt::info!("Application service data");
                }
            }
            FrameType::Command => {
                // handle command
                self.handle_application_service_command(aps_payload)?;
            }
            FrameType::InterPan => {
                defmt::info!("> APS inter-PAN");
                // Not supported yet
            }
            FrameType::Acknowledgement => {
                defmt::info!("> APS acknowledge");
                // ...
            }
        }
        Ok(())
    }

    fn handle_application_service_command(&mut self, aps_payload: &[u8]) -> Result<(), Error> {
        use psila_data::{
            application_service::commands::{transport_key::NetworkKey, CommandIdentifier},
            common::key::KeyType,
        };
        // handle command
        let command_identifier = CommandIdentifier::try_from(aps_payload[0])?;
        if command_identifier == CommandIdentifier::TransportKey {
            let key_type = KeyType::try_from(aps_payload[1])?;
            if key_type == KeyType::StandardNetworkKey {
                let key = NetworkKey::unpack(&aps_payload[2..])?;
                defmt::info!("> APS Set network key");
                self.set_state(NetworkState::Secure);
                self.security_manager.set_network_key(key);
                self.queue_device_announce()?;
            }
        } else {
            defmt::info!("> APS command, {=u8}", u8::from(command_identifier));
        }
        Ok(())
    }

    fn handle_application_service_acknowledge(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        aps_header: &psila_data::application_service::ApplicationServiceHeader,
    ) -> Result<(), Error> {
        if aps_header.control.acknowledge_request {
            if aps_header.control.acknowledge_format {
                defmt::info!("APS acknowledge request, compact");
            } else {
                defmt::info!("APS acknowledge request, extended");
            }
            let mac_header = self.mac.build_data_header(
                nwk_header.source_address, // destination address
                false,                     // request acknowledge
            );
            let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
            let nwk_frame_size = self.application_service.build_acknowledge(
                &self.identity,
                nwk_header.source_address,
                &aps_header,
                &mut self.buffer.borrow_mut()[mac_header_len..],
                &mut self.security_manager,
            )?;
            let frame_size = mac_header_len + nwk_frame_size;
            match self.queue_packet_from_buffer(frame_size) {
                Ok(()) => {
                    defmt::info!("< Queued acknowledge {=usize}", frame_size);
                }
                Err(err) => {
                    defmt::error!("< Failed to queue acknowledge");
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    fn handle_device_profile(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        cluster: u16,
        aps_payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::device_profile;
        let sequence = aps_payload[0];
        let payload = &aps_payload[1..];
        let response = cluster & device_profile::RESPONSE == device_profile::RESPONSE;
        if response {
            match device_profile::ClusterIdentifier::try_from(cluster & !device_profile::RESPONSE) {
                Ok(device_profile::ClusterIdentifier::NetworkAddressRequest) => {
                    defmt::info!("> DP Network address response");
                }
                Ok(device_profile::ClusterIdentifier::ExtendedAddressRequest) => {
                    defmt::info!("> DP Extended address response");
                }
                Ok(device_profile::ClusterIdentifier::NodeDescriptorRequest) => {
                    defmt::info!("> DP Node descriptor response");
                }
                Ok(device_profile::ClusterIdentifier::PowerDescriptorRequest) => {
                    defmt::info!("> DP Power descriptor response");
                }
                Ok(device_profile::ClusterIdentifier::SimpleDescriptorRequest) => {
                    defmt::info!("> DP Simple descriptor response");
                }
                Ok(device_profile::ClusterIdentifier::ActiveEndpointRequest) => {
                    defmt::info!("> DP Active endpoint response");
                }
                Ok(device_profile::ClusterIdentifier::MatchDescriptorRequest) => {
                    defmt::info!("> DP Match descriptor response");
                }
                Ok(device_profile::ClusterIdentifier::DeviceAnnounce) => {
                    defmt::info!("> DP Device announce (response)");
                }
                Ok(device_profile::ClusterIdentifier::ManagementLinkQualityIndicatorRequest) => {
                    defmt::info!("> DP Link quality indicator response");
                }
                Ok(_) => {}
                Err(_) => {
                    defmt::info!("> DP Invalid cluster {=u16}", cluster);
                }
            }
        } else {
            match device_profile::ClusterIdentifier::try_from(cluster & !device_profile::RESPONSE) {
                Ok(device_profile::ClusterIdentifier::NetworkAddressRequest) => {
                    let (req, _used) = device_profile::NetworkAddressRequest::unpack(payload)?;
                    let status = if req.address == self.identity.extended {
                        device_profile::Status::Success
                    } else {
                        device_profile::Status::DeviceNotFound
                    };
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size = self.application_service.build_network_address_response(
                        &self.identity,
                        nwk_header.source_address,
                        sequence,
                        status,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
                Ok(device_profile::ClusterIdentifier::ExtendedAddressRequest) => {
                    let (req, _used) = device_profile::ExtendedAddressRequest::unpack(payload)?;
                    let status = if req.address == self.identity.short {
                        device_profile::Status::Success
                    } else {
                        device_profile::Status::DeviceNotFound
                    };
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size = self.application_service.build_extended_address_response(
                        &self.identity,
                        nwk_header.source_address,
                        sequence,
                        status,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
                Ok(device_profile::ClusterIdentifier::NodeDescriptorRequest) => {
                    let (req, _used) = device_profile::NodeDescriptorRequest::unpack(payload)?;
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size = self.application_service.build_node_descriptor_response(
                        &self.identity,
                        nwk_header.source_address,
                        &req,
                        self.capability,
                        sequence,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
                Ok(device_profile::ClusterIdentifier::PowerDescriptorRequest) => {
                    let (req, _used) = device_profile::PowerDescriptorRequest::unpack(payload)?;
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size = self.application_service.build_power_descriptor_response(
                        &self.identity,
                        nwk_header.source_address,
                        &req,
                        sequence,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
                Ok(device_profile::ClusterIdentifier::SimpleDescriptorRequest) => {
                    let (req, _used) = device_profile::SimpleDescriptorRequest::unpack(payload)?;
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let descriptor = self
                        .cluser_library_handler
                        .get_simple_desciptor(req.endpoint);
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size =
                        self.application_service.build_simple_descriptor_response(
                            &self.identity,
                            nwk_header.source_address,
                            &req,
                            descriptor,
                            sequence,
                            &mut self.buffer.borrow_mut()[mac_header_len..],
                            &mut self.security_manager,
                        )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
                Ok(device_profile::ClusterIdentifier::ActiveEndpointRequest) => {
                    let (req, _used) = device_profile::ActiveEndpointRequest::unpack(payload)?;
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let endpoints = self.cluser_library_handler.active_endpoints();
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size = self.application_service.build_active_endpoint_response(
                        &self.identity,
                        nwk_header.source_address,
                        &req,
                        &endpoints,
                        sequence,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
                Ok(device_profile::ClusterIdentifier::MatchDescriptorRequest) => {
                    defmt::info!("> DP Match descriptor request");
                }
                Ok(device_profile::ClusterIdentifier::DeviceAnnounce) => {
                    defmt::info!("> DP Device announce");
                }
                Ok(device_profile::ClusterIdentifier::ManagementLinkQualityIndicatorRequest) => {
                    defmt::info!("> DP Link quality indicator request");
                }
                Ok(_) => {}
                Err(_) => {
                    defmt::warn!("> DP Invalid cluster {=u16}", cluster);
                }
            }
        }
        Ok(())
    }

    fn handle_cluster_library(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        profile: u16,
        cluster: u16,
        ep_src: u8,
        ep_dst: u8,
        payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::cluster_library::{self, commands, ClusterLibraryHeader, FrameType};

        match ClusterLibraryHeader::unpack(payload) {
            Ok((header, used)) => {
                let (response_command, response_size) =
                    if header.control.frame_type == FrameType::Global {
                        if let Ok(command) =
                            cluster_library::GeneralCommandIdentifier::try_from(header.command)
                        {
                            self.handle_general_cluster_command(
                                profile,
                                cluster,
                                ep_dst,
                                command,
                                &payload[used..],
                            )?
                        } else {
                            defmt::error!(
                            "Unknown general command. Profile {=u16} Cluster {=u16} Command {=u8}",
                            profile,
                            cluster,
                            header.command
                        );
                            (GeneralCommandIdentifier::DefaultResponse, 0)
                        }
                    } else {
                        let status = match self.cluser_library_handler.run(
                            profile,
                            cluster,
                            ep_dst,
                            header.command,
                            &payload[used..],
                        ) {
                            Ok(_) => psila_data::cluster_library::ClusterLibraryStatus::Success,
                            Err(status) => status,
                        };
                        if header.control.disable_default_response {
                            (GeneralCommandIdentifier::DefaultResponse, 0)
                        } else {
                            let command = commands::DefaultResponse {
                                command: header.command,
                                status,
                            };
                            let used = command.pack(&mut self.scratch.borrow_mut()[..])?;
                            (GeneralCommandIdentifier::DefaultResponse, used)
                        }
                    };
                if response_size > 0 {
                    let zcl_header =
                        psila_data::cluster_library::ClusterLibraryHeader::new_response(
                            &header,
                            response_command,
                        );
                    let mac_header = self.mac.build_data_header(
                        nwk_header.source_address, // destination address
                        false,                     // request acknowledge
                    );
                    let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                    let nwk_frame_size = self.application_service.build_cluster_library_response(
                        &self.identity,
                        nwk_header.source_address,
                        profile,
                        cluster,
                        ep_src,
                        ep_dst,
                        &zcl_header,
                        &self.scratch.borrow()[..response_size],
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
            }
            Err(_) => {
                defmt::error!("Failed to parse ZCL {=u16} {=u16}", profile, cluster);
            }
        }
        Ok(())
    }

    fn handle_general_cluster_command(
        &mut self,
        profile: u16,
        cluster: u16,
        endpoint: u8,
        command_identifier: GeneralCommandIdentifier,
        payload: &[u8],
    ) -> Result<(GeneralCommandIdentifier, usize), Error> {
        let response_data = &mut self.scratch.borrow_mut()[..];

        let (command, used) = match command_identifier {
            GeneralCommandIdentifier::ReadAttributes => {
                let mut offset = 0;
                for ref chunk in payload.chunks_exact(2) {
                    let identifier = AttributeIdentifier::unpack(chunk)?;
                    let _ = identifier.pack(&mut response_data[offset..offset + 2])?;
                    offset += 2;
                    let used = match self.cluser_library_handler.read_attribute(
                        profile,
                        cluster,
                        endpoint,
                        identifier.into(),
                        &mut response_data[offset + 2..],
                    ) {
                        Ok((attribut_type, used)) => {
                            response_data[offset] = ClusterLibraryStatus::Success.into();
                            response_data[offset + 1] = attribut_type.into();
                            used + 2
                        }
                        Err(status) => {
                            response_data[offset] = status.into();
                            1
                        }
                    };
                    offset += used;
                }
                (GeneralCommandIdentifier::ReadAttributesResponse, offset)
            }
            GeneralCommandIdentifier::WriteAttributes => {
                let mut in_offset = 0;
                let mut out_offset = 0;
                while in_offset < payload.len() {
                    let identifier =
                        AttributeIdentifier::unpack(&payload[in_offset..in_offset + 2])?;
                    let data_type = AttributeDataType::try_from(payload[in_offset + 2])?;
                    in_offset += 3;
                    let (data_size, used) = data_type.get_size(&payload[in_offset..]);
                    if let Some(data_size) = data_size {
                        in_offset += used;
                        let status = match self.cluser_library_handler.write_attribute(
                            profile,
                            cluster,
                            endpoint,
                            identifier.into(),
                            data_type,
                            &payload[in_offset..in_offset + data_size],
                        ) {
                            Ok(_) => psila_data::cluster_library::ClusterLibraryStatus::Success,
                            Err(status) => status,
                        };
                        in_offset += data_size;
                        let _ = identifier.pack(&mut response_data[out_offset..out_offset + 2])?;
                        response_data[out_offset + 2] = status.into();
                        out_offset += 3;
                    } else {
                        defmt::warn!("Unsupported data type {=u8}", u8::from(data_type));
                        break;
                    }
                }
                (
                    GeneralCommandIdentifier::WriteAttributesResponse,
                    out_offset,
                )
            }
            _ => {
                defmt::warn!(
                    "Ignored general command {=u8}",
                    u8::from(command_identifier)
                );
                (GeneralCommandIdentifier::DefaultResponse, 0)
            }
        };
        Ok((command, used))
    }

    fn queue_device_announce(&mut self) -> Result<(), Error> {
        let mac_header = self
            .mac
            .build_data_header(NetworkAddress::broadcast(), false);
        let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
        let nwk_frame_size = self.application_service.build_device_announce(
            &self.identity,
            self.capability,
            &mut self.buffer.borrow_mut()[mac_header_len..],
            &mut self.security_manager,
        )?;
        self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)
    }

    fn queue_network_link_status(&mut self) -> Result<(), Error> {
        use psila_data::network::commands::{Command, LinkStatus, LinkStatusEntry};
        let mac_header = self.mac.build_data_header(
            NetworkAddress::broadcast(), // destination address
            false,                       // request acknowledge
        );
        let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
        let mut entries = [LinkStatusEntry::default(); 32];
        let mut num_entries = 0;
        for device in self.known_devices.iter() {
            if device.network_address.is_assigned()
                && device.outgoing_cost < 0xff
                && device.link_quality < 0xff
            {
                entries[num_entries].address = device.network_address;
                entries[num_entries].incoming_cost =
                    psila_data::link_quality_to_cost(device.link_quality);
                entries[num_entries].outgoing_cost = device.outgoing_cost;
                num_entries = num_entries + 1;
            }
            if num_entries >= 32 {
                break;
            }
        }
        let reply = LinkStatus::new(&entries[..num_entries]);
        let reply = Command::LinkStatus(reply);
        let nwk_frame_size = self.application_service.build_network_command(
            &self.identity,
            NetworkAddress::broadcast(),
            &reply,
            &mut self.buffer.borrow_mut()[mac_header_len..],
            &mut self.security_manager,
        )?;
        let frame_size = mac_header_len + nwk_frame_size;
        match self.queue_packet_from_buffer(frame_size) {
            Ok(()) => {
                defmt::info!("< Queued network link status {=usize}", frame_size);
            }
            Err(err) => {
                defmt::error!("< Failed to queue network link status");
                return Err(err);
            }
        }
        Ok(())
    }
}
