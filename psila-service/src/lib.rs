//! # Psila Service

#![no_std]

use core::convert::TryFrom;

use bbqueue::{ArrayLength, Producer};

use heapless::{consts::U16, Vec};

use psila_data::{self, pack::Pack, CapabilityInformation, ExtendedAddress, Key, NetworkAddress};

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

#[derive(Clone, Copy, PartialEq)]
pub enum NetworkState {
    Orphan,
    Associated,
    Secure,
}

// Also see 3.6.1.5 in the Zigbee specification
pub struct NetworkDevice {
    network_address: NetworkAddress,
    extended_address: ExtendedAddress,
    last_seen: u32,
    device_type: psila_data::device_profile::link_quality::DeviceType,
    relationship: psila_data::device_profile::link_quality::Relationship,
    link_quality: u8,
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

pub struct PsilaService<'a, N: ArrayLength<u8>, CB, CLH> {
    mac: MacService,
    application_service: ApplicationServiceContext,
    security_manager: security::SecurityManager<CB>,
    capability: CapabilityInformation,
    tx_queue: Producer<'a, N>,
    state: NetworkState,
    identity: Identity,
    buffer: core::cell::RefCell<[u8; 128]>,
    timestamp: u32,
    next_link_status: u32,
    known_devices: Vec<NetworkDevice, U16>,
    cluser_library_handler: CLH,
}

impl<'a, N: ArrayLength<u8>, CB, CLH> PsilaService<'a, N, CB, CLH>
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
    pub fn receive(&mut self, data: &[u8], timestamp: u32) -> Result<u32, Error> {
        self.timestamp = timestamp;
        match mac::Frame::decode(data, false) {
            Ok(frame) => {
                if !self.mac.destination_me_or_broadcast(&frame) {
                    return Ok(0);
                }
                let (packet_length, timeout) = self
                    .mac
                    .handle_frame(&frame, &mut self.buffer.borrow_mut()[..])?;
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
                Ok(timeout)
            }
            Err(_) => Err(Error::MalformedPacket),
        }
    }

    /// Timeout, call this method when the timer has triggered a time-out
    /// ### Return
    /// A new timeout value that the timer shall be configured with, a timeout
    /// value of zero (0) shall be ignored
    pub fn timeout(&mut self) -> Result<u32, Error> {
        let (packet_length, timeout) = self.mac.timeout(&mut self.buffer.borrow_mut()[..])?;
        if packet_length > 0 {
            self.queue_packet_from_buffer(packet_length)?;
        }
        Ok(timeout)
    }

    /// Update, call this method at ragular intervals
    pub fn update(&mut self, timestamp: u32) -> Result<(), Error> {
        self.timestamp = timestamp;
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
                log::info!("Handle network beacon");
                let _ = BeaconInformation::unpack(frame.payload)?;
            }
            _ => (),
        }
        Ok(())
    }

    /// Handle a network frame
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
                log::info!("Handle inter-PAN");
                // Not supported yet
            }
        }
        Ok(())
    }

    fn handle_network_command(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::network::commands::Command;

        match Command::unpack(payload) {
            Ok((cmd, _used)) => match cmd {
                Command::RouteRequest(req) => {
                    use psila_data::network::commands::AddressType;
                    log::info!("> Network Route request");
                    let nwk_match = match req.destination_address {
                        AddressType::Singlecast(address) => address == self.identity.short,
                        AddressType::Multicast(_) => false,
                    };
                    let extended_match = match req.destination_ieee_address {
                        Some(address) => address == self.identity.extended,
                        None => false,
                    };
                    if nwk_match {
                        log::info!("Match");
                        let mac_header = self.mac.build_data_header(
                            nwk_header.source_address, // destination address
                            false,                     // request acknowledge
                        );
                        let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                        use psila_data::network::commands;
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
                        let reply = Command::RouteReply(reply);
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
                                log::info!("< Queued route response {}", frame_size);
                            }
                            Err(err) => {
                                log::error!("< Failed to queue route response, {:?}", err);
                                return Err(err);
                            }
                        }
                    } else if extended_match {
                        log::info!("Extended match");
                    }
                }
                Command::RouteReply(_) => {
                    log::info!("> Network Route reply");
                }
                Command::NetworkStatus(_) => {
                    log::info!("> Network Network status");
                }
                Command::Leave(_) => {
                    log::info!("> Network Leave");
                }
                Command::RouteRecord(_) => {
                    log::info!("> Network Route record");
                }
                Command::RejoinRequest(_) => {
                    log::info!("> Network Rejoin request");
                }
                Command::RejoinResponse(_) => {
                    log::info!("> Network Rejoin response");
                }
                Command::LinkStatus(_) => {
                    log::info!("> Network Link Status");
                }
                Command::NetworkReport(_) => {
                    log::info!("> Network Network report");
                }
                Command::NetworkUpdate(_) => {
                    log::info!("> Network Network update");
                }
                Command::EndDeviceTimeoutRequest(_) => {
                    log::info!("> Network End-device timeout request");
                }
                Command::EndDeviceTimeoutResponse(_) => {
                    log::info!("> Network End-device timeout response");
                }
            },
            Err(_) => {
                log::warn!("Failed to decode network command");
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
        use psila_data::application_service::{
            commands::{Command, TransportKey},
            header::FrameType,
        };

        if aps_header.control.acknowledge_request {
            if aps_header.control.acknowledge_format {
                log::info!("APS acknowledge request, compact ");
            } else {
                log::info!("APS acknowledge request, extended ");
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
                    log::info!("< Queued acknowledge {}", frame_size);
                }
                Err(err) => {
                    log::error!("< Failed to queue acknowledge, {:?}", err);
                    return Err(err);
                }
            }
        }

        match aps_header.control.frame_type {
            FrameType::Data => {
                if let (Some(cluster), Some(profile), Some(ep_src), Some(ep_dst)) = (
                    aps_header.cluster,
                    aps_header.profile,
                    aps_header.source,
                    aps_header.destination,
                ) {
                    if profile == 0x0000 {
                        use psila_data::device_profile::DeviceProfileFrame;
                        match DeviceProfileFrame::unpack(aps_payload, cluster) {
                            Ok((frame, _)) => {
                                self.handle_device_profile(nwk_header, aps_header, frame)?;
                            }
                            Err(err) => {
                                log::error!(
                                    "Failed to parse device profile message, {:04x}, {:?}",
                                    cluster,
                                    err
                                );
                            }
                        }
                    } else {
                        self.handle_cluster_library(
                            nwk_header,
                            aps_header,
                            profile,
                            cluster,
                            ep_src,
                            ep_dst,
                            aps_payload,
                        )?;
                    }
                } else {
                    log::info!("Application service data");
                }
            }
            FrameType::Command => {
                // handle command
                let (command, _used) = Command::unpack(aps_payload)?;
                if let Command::TransportKey(cmd) = command {
                    if let TransportKey::StandardNetworkKey(key) = cmd {
                        log::info!("> APS Set network key");
                        self.set_state(NetworkState::Secure);
                        self.security_manager.set_network_key(key);
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
                        self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                    } else {
                        log::info!("> APS command, {:?}", command.identifier());
                    }
                } else {
                    log::info!("> APS command, {:?}", command.identifier());
                }
            }
            FrameType::InterPan => {
                log::info!("> APS inter-PAN");
                // Not supported yet
            }
            FrameType::Acknowledgement => {
                log::info!("> APS acknowledge");
                // ...
            }
        }
        Ok(())
    }

    fn handle_device_profile(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        _aps_header: &psila_data::application_service::ApplicationServiceHeader,
        frame: psila_data::device_profile::DeviceProfileFrame,
    ) -> Result<(), Error> {
        use psila_data::device_profile::DeviceProfileMessage;

        match frame.message {
            DeviceProfileMessage::NetworkAddressRequest(req) => {
                log::info!("> DP Network address request");
                let mac_header = self.mac.build_data_header(
                    nwk_header.source_address, // destination address
                    false,                     // request acknowledge
                );
                let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                let nwk_frame_size = self.application_service.build_network_address_response(
                    &self.identity,
                    nwk_header.source_address,
                    &req,
                    &mut self.buffer.borrow_mut()[mac_header_len..],
                    &mut self.security_manager,
                )?;
                self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
            }
            DeviceProfileMessage::ExtendedAddressRequest(req) => {
                log::info!("> DP Extended address request");
                let mac_header = self.mac.build_data_header(
                    nwk_header.source_address, // destination address
                    false,                     // request acknowledge
                );
                let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                let nwk_frame_size = self.application_service.build_extended_address_response(
                    &self.identity,
                    nwk_header.source_address,
                    &req,
                    &mut self.buffer.borrow_mut()[mac_header_len..],
                    &mut self.security_manager,
                )?;
                self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
            }
            DeviceProfileMessage::NodeDescriptorRequest(req) => {
                log::info!("> DP Node descriptor request, {}", req.address);
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
                    &mut self.buffer.borrow_mut()[mac_header_len..],
                    &mut self.security_manager,
                )?;
                log::info!("< Queue response");
                match self.queue_packet_from_buffer(mac_header_len + nwk_frame_size) {
                    Ok(()) => {
                        log::info!("< Queued response");
                    }
                    Err(err) => {
                        log::error!("< Failed to queue response, {:?}", err);
                        return Err(err);
                    }
                }
            }
            DeviceProfileMessage::PowerDescriptorRequest(req) => {
                log::info!("> DP Power descriptor request");
                let mac_header = self.mac.build_data_header(
                    nwk_header.source_address, // destination address
                    false,                     // request acknowledge
                );
                let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                let nwk_frame_size = self.application_service.build_power_descriptor_response(
                    &self.identity,
                    nwk_header.source_address,
                    &req,
                    &mut self.buffer.borrow_mut()[mac_header_len..],
                    &mut self.security_manager,
                )?;
                self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
            }
            DeviceProfileMessage::SimpleDescriptorRequest(req) => {
                log::info!("> DP Simple descriptor request {:02x}", req.endpoint);
                let mac_header = self.mac.build_data_header(
                    nwk_header.source_address, // destination address
                    false,                     // request acknowledge
                );
                use psila_data::device_profile::SimpleDescriptor;
                let descriptor = match req.endpoint {
                    0x01 => {
                        Some(SimpleDescriptor::new(
                            req.endpoint,                                                     // endpoint
                            u16::from(psila_data::common::ProfileIdentifier::HomeAutomation), // profile
                            0x0100, // device, HA On-off light
                            0,      // device version
                            &[0x0000, 0x0006],
                            &[],
                        ))
                    }
                    _ => None,
                };
                let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                let nwk_frame_size = self.application_service.build_simple_descriptor_response(
                    &self.identity,
                    nwk_header.source_address,
                    &req,
                    descriptor,
                    &mut self.buffer.borrow_mut()[mac_header_len..],
                    &mut self.security_manager,
                )?;
                self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
            }
            DeviceProfileMessage::ActiveEndpointRequest(req) => {
                log::info!("> DP Active endpoint request, {}", req.address);
                let mac_header = self.mac.build_data_header(
                    nwk_header.source_address, // destination address
                    false,                     // request acknowledge
                );
                let endpoints = [0x01];
                let mac_header_len = mac_header.encode(&mut self.buffer.borrow_mut()[..]);
                let nwk_frame_size = self.application_service.build_active_endpoint_response(
                    &self.identity,
                    nwk_header.source_address,
                    &req,
                    &endpoints,
                    &mut self.buffer.borrow_mut()[mac_header_len..],
                    &mut self.security_manager,
                )?;
                self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
            }
            DeviceProfileMessage::MatchDescriptorRequest(_req) => {
                log::info!("> DP Match descriptor request");
            }
            DeviceProfileMessage::DeviceAnnounce(_req) => {
                log::info!("> DP Device announce");
            }
            DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(_req) => {
                log::info!("> DP Link quality indicator request");
            }
            DeviceProfileMessage::NetworkAddressResponse(_rsp) => {
                log::info!("> DP Network address response");
            }
            DeviceProfileMessage::ExtendedAddressResponse(_rsp) => {
                log::info!("> DP Extended address response");
            }
            DeviceProfileMessage::NodeDescriptorResponse(_rsp) => {
                log::info!("> DP Node descriptor response");
            }
            DeviceProfileMessage::PowerDescriptorResponse(_rsp) => {
                log::info!("> DP Power descriptor response");
            }
            DeviceProfileMessage::SimpleDescriptorResponse(_rsp) => {
                log::info!("> DP Simple descriptor response");
            }
            DeviceProfileMessage::ActiveEndpointResponse(_rsp) => {
                log::info!("> DP Active endpoint response");
            }
            DeviceProfileMessage::MatchDescriptorResponse(_rsp) => {
                log::info!("> DP Match desriptor response");
            }
            DeviceProfileMessage::ManagementLinkQualityIndicatorResponse(_rsp) => {
                log::info!("> DP Link quality indicator response");
            }
        }
        Ok(())
    }

    fn handle_cluster_library(
        &mut self,
        nwk_header: &psila_data::network::NetworkHeader,
        aps_header: &psila_data::application_service::ApplicationServiceHeader,
        profile: u16,
        cluster: u16,
        ep_src: u8,
        ep_dst: u8,
        payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::cluster_library::{
            self, commands, ClusterLibraryHeader, Command, FrameType,
        };

        match ClusterLibraryHeader::unpack(payload) {
            Ok((header, used)) => {
                let response = if header.control.frame_type == FrameType::Global {
                    if let Ok(command) =
                        cluster_library::GeneralCommandIdentifier::try_from(header.command)
                    {
                        self.handle_general_cluster_command(
                            profile,
                            cluster,
                            command,
                            &payload[used..],
                        )?
                    } else {
                        log::error!(
                            "Unknown general command. Profile {:04x} Cluster {:04x} Command {:04x}",
                            profile,
                            cluster,
                            header.command
                        );
                        None
                    }
                } else {
                    let status =
                        match self
                            .cluser_library_handler
                            .run(profile, cluster, header.command)
                        {
                            Ok(_) => psila_data::cluster_library::ClusterLibraryStatus::Success,
                            Err(status) => status,
                        };
                    if header.control.disable_default_response {
                        None
                    } else {
                        Some(Command::DefaultResponse(commands::DefaultResponse {
                            command: header.command,
                            status,
                        }))
                    }
                };
                if let Some(response) = response {
                    log::info!("> ZCL response");
                    let zcl_header =
                        psila_data::cluster_library::ClusterLibraryHeader::new_response(
                            &header,
                            response.command_identifier(),
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
                        &response,
                        &mut self.buffer.borrow_mut()[mac_header_len..],
                        &mut self.security_manager,
                    )?;
                    self.queue_packet_from_buffer(mac_header_len + nwk_frame_size)?;
                }
            }
            Err(_) => {
                log::error!("Failed to parse ZCL {:04x} {:04x}", profile, cluster);
            }
        }
        Ok(())
    }

    fn handle_general_cluster_command(
        &mut self,
        profile: u16,
        cluster: u16,
        command_identifier: psila_data::cluster_library::GeneralCommandIdentifier,
        payload: &[u8],
    ) -> Result<Option<psila_data::cluster_library::Command>, Error> {
        use psila_data::cluster_library::{commands, Command};
        if let Ok((command, _used)) = Command::unpack(payload, command_identifier) {
            let response = match command {
                Command::ReadAttributes(command) => {
                    let mut response = commands::ReadAttributesResponse::new();
                    for attribute in command.attributes {
                        let attribute_status = match self.cluser_library_handler.read_attribute(
                            profile,
                            cluster,
                            attribute.into(),
                        ) {
                            Ok(value) => commands::AttributeStatus::from_value(attribute, value),
                            Err(status) => {
                                commands::AttributeStatus::from_status(attribute, status)
                            }
                        };
                        response.attributes.push(attribute_status);
                    }
                    Some(Command::ReadAttributesResponse(response))
                }
                Command::WriteAttributes(command) | Command::WriteAttributesUndivided(command) => {
                    let mut response = commands::WriteAttributesResponse::new();
                    for attribute in command.attributes {
                        let status = match self.cluser_library_handler.write_attribute(
                            profile,
                            cluster,
                            attribute.identifier.into(),
                            attribute.value,
                        ) {
                            Ok(_) => psila_data::cluster_library::ClusterLibraryStatus::Success,
                            Err(status) => status,
                        };
                        let status = commands::WriteAttributeStatus {
                            status,
                            identifier: attribute.identifier,
                        };
                        response.attributes.push(status);
                    }
                    Some(Command::WriteAttributesResponse(response))
                }
                Command::WriteAttributesNoResponse(command) => {
                    for attribute in command.attributes {
                        let _ = self.cluser_library_handler.write_attribute(
                            profile,
                            cluster,
                            attribute.identifier.into(),
                            attribute.value,
                        );
                    }
                    None
                }
                _ => {
                    log::warn!(
                        "Ignored general command {:02x}",
                        u8::from(command_identifier)
                    );
                    None
                }
            };
            return Ok(response);
        }
        Ok(None)
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
                log::info!("< Queued network link status {}", frame_size);
            }
            Err(err) => {
                log::error!("< Failed to queue network link status, {:?}", err);
                return Err(err);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;
    use bbqueue::{consts::U512, BBBuffer};
    use psila_crypto_openssl::OpenSslBackend;
    use psila_data::cluster_library::{AttributeValue, ClusterLibraryStatus};

    struct BasicClusterLibraryHandler {}

    impl ClusterLibraryHandler for BasicClusterLibraryHandler {
        fn read_attribute(
            &self,
            _profile: u16,
            _cluster: u16,
            _attribute: u16,
        ) -> Result<AttributeValue, ClusterLibraryStatus> {
            Err(ClusterLibraryStatus::UnsupportedAttribute)
        }
        fn write_attribute(
            &mut self,
            _profile: u16,
            _cluster: u16,
            _attribute: u16,
            _value: AttributeValue,
        ) -> Result<(), ClusterLibraryStatus> {
            Err(ClusterLibraryStatus::UnsupportedAttribute)
        }
        fn run(
            &mut self,
            _profile: u16,
            _cluster: u16,
            _command: u8,
        ) -> Result<(), ClusterLibraryStatus> {
            Err(ClusterLibraryStatus::UnsupportedClusterCommand)
        }
    }

    #[test]
    fn build_beacon_request() {
        const DEFAULT_LINK_KEY: [u8; 16] = [
            0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
            0x30, 0x39,
        ];
        let crypto_backend = OpenSslBackend::default();
        let address = psila_data::ExtendedAddress::new(0x8899_aabb_ccdd_eeff);
        let tx_queue: BBBuffer<U512> = BBBuffer::new();
        let (tx_producer, mut tx_consumer) = tx_queue.try_split().unwrap();
        let cluser_library_handler = BasicClusterLibraryHandler {};

        let mut service = PsilaService::new(
            crypto_backend,
            tx_producer,
            address,
            DEFAULT_LINK_KEY.into(),
            cluser_library_handler,
        );

        let timeout = service.timeout().unwrap();

        assert_eq!(timeout, 2_000_000);

        let grant = tx_consumer.read().unwrap();
        let packet_length = grant[0] as usize;
        let packet = &grant[1..=packet_length];

        assert_eq!(packet_length, 8);

        assert_eq!(packet, [0x03, 0x08, 0x01, 0xff, 0xff, 0xff, 0xff, 0x07]);
        grant.release(packet_length + 1);

        assert!(tx_consumer.read().is_err());
    }
}
