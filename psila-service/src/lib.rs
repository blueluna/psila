//! # Psila Service

#![no_std]

use core::cell::Cell;

use log;

use bbqueue;

use psila_data::{pack::Pack, CapabilityInformation, ExtendedAddress, Key};

use psila_crypto::CryptoBackend;

mod application_service;
mod error;
mod identity;
pub mod mac;
mod security;

pub use error::Error;
pub use identity::Identity;

use application_service::ApplicationServiceContext;
use mac::MacService;

/// Max buffer size
pub const PACKET_BUFFER_MAX: usize = 128;

#[derive(Clone, Copy)]
pub enum NetworkState {
    Orphan,
    Associated,
    Secure,
}

pub struct PsilaService<CB> {
    mac: MacService,
    application_service: ApplicationServiceContext,
    security_manager: security::SecurityManager<CB>,
    capability: CapabilityInformation,
    tx_queue: bbqueue::Producer,
    state: Cell<NetworkState>,
}

impl<CB> PsilaService<CB>
where
    CB: CryptoBackend,
{
    pub fn new(
        crypto: CB,
        tx_queue: bbqueue::Producer,
        address: ExtendedAddress,
        default_link_key: Key,
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
            state: Cell::new(NetworkState::Orphan),
        }
    }

    pub fn get_state(&self) -> NetworkState {
        self.state.get()
    }

    fn set_state(&self, state: NetworkState) {
        (*self).state.set(state);
    }

    /// Push a packet onto the queue
    fn queue_packet(&mut self, data: &[u8]) -> Result<(), Error> {
        assert!(data.len() < (u8::max_value() as usize));
        let length = data.len() + 1;
        match self.tx_queue.grant(length) {
            Ok(mut grant) => {
                grant[0] = data.len() as u8;
                grant[1..].copy_from_slice(&data);
                self.tx_queue.commit(length, grant);
                Ok(())
            }
            Err(_) => Err(Error::NotEnoughSpace),
        }
    }

    /// Receive, call this method when new data has been received by the radio
    /// ### Return
    /// true if the message was addressed to this device
    pub fn handle_acknowledge(&mut self, data: &[u8]) -> Result<bool, Error> {
        let mut buffer = [0u8; PACKET_BUFFER_MAX];
        match mac::Frame::decode(data, false) {
            Ok(frame) => {
                if !self.mac.destination_me_or_broadcast(&frame) {
                    return Ok(false);
                }
                if self.mac.requests_acknowledge(&frame) {
                    // If the frame is a data request frame, send an acknowledge with pending set
                    // Use the frame sequence number from the received frame in the acknowledge
                    let packet_length =
                        self.mac
                            .build_acknowledge(frame.header.seq, false, &mut buffer);
                    self.queue_packet(&buffer[..packet_length])?;
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
    pub fn receive(&mut self, data: &[u8]) -> Result<u32, Error> {
        let mut buffer = [0u8; PACKET_BUFFER_MAX];
        match mac::Frame::decode(data, false) {
            Ok(frame) => {
                if !self.mac.destination_me_or_broadcast(&frame) {
                    return Ok(0);
                }
                let (packet_length, timeout) = self.mac.handle_frame(&frame, &mut buffer)?;
                if packet_length > 0 {
                    self.queue_packet(&buffer[..packet_length])?;
                }
                if let mac::State::Associated = self.mac.state() {
                    if let NetworkState::Orphan = self.get_state() {
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
        let mut buffer = [0u8; PACKET_BUFFER_MAX];
        let (packet_length, timeout) = self.mac.timeout(&mut buffer)?;
        if packet_length > 0 {
            self.queue_packet(&buffer[..packet_length])?;
        }
        Ok(timeout)
    }

    fn handle_mac_frame(&mut self, frame: &mac::Frame) -> Result<(), Error> {
        use psila_data::network::{BeaconInformation, NetworkHeader};

        match frame.header.frame_type {
            mac::FrameType::Data => {
                let (header, used) = NetworkHeader::unpack(frame.payload)?;
                let mut payload = [0u8; PACKET_BUFFER_MAX];
                let payload_size = if header.control.security {
                    log::info!("Decrypt network data");
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

        match header.control.frame_type {
            FrameType::Data => {
                let mut aps_payload = [0u8; PACKET_BUFFER_MAX];
                log::info!("Unpack application service header");
                let (header, used) = ApplicationServiceHeader::unpack(nwk_payload)?;
                log::info!("...done");
                let aps_payload_length = if header.control.security {
                    log::info!("Decrypt application service data");
                    self.security_manager
                        .decrypt_payload(nwk_payload, used, &mut aps_payload)?
                } else {
                    let payload_length = nwk_payload.len() - used;
                    aps_payload[..payload_length].copy_from_slice(&nwk_payload[used..]);
                    payload_length
                };
                if aps_payload_length > 0 {
                    self.handle_application_service_frame(
                        &header,
                        &aps_payload[..aps_payload_length],
                    )?;
                }
            }
            FrameType::Command => {
                // handle command
                self.handle_network_command(nwk_payload)?;
            }
            FrameType::InterPan => {
                log::info!("Handle inter-PAN");
                // Not supported yet
            }
        }
        Ok(())
    }

    fn handle_network_command(&self, payload: &[u8]) -> Result<(), Error> {
        use psila_data::network::commands::Command;
        log::info!("Unpack network command");
        match Command::unpack(payload) {
            Ok((cmd, _used)) => match cmd {
                Command::RouteRequest(_) => {
                    log::info!("Route request");
                }
                Command::RouteReply(_) => {
                    log::info!("Route reply");
                }
                Command::NetworkStatus(_) => {
                    log::info!("Network status");
                }
                Command::Leave(_) => {
                    log::info!("Leave");
                }
                Command::RouteRecord(_) => {
                    log::info!("Route record");
                }
                Command::RejoinRequest(_) => {
                    log::info!("Rejoin request");
                }
                Command::RejoinResponse(_) => {
                    log::info!("Rejoin response");
                }
                Command::LinkStatus(_) => {
                    log::info!("Link Status");
                }
                Command::NetworkReport(_) => {
                    log::info!("Network report");
                }
                Command::NetworkUpdate(_) => {
                    log::info!("Network update");
                }
                Command::EndDeviceTimeoutRequest(_) => {
                    log::info!("End-device timeout request");
                }
                Command::EndDeviceTimeoutResponse(_) => {
                    log::info!("End-device timeout response");
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
        header: &psila_data::application_service::ApplicationServiceHeader,
        aps_payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::application_service::{
            commands::{Command, TransportKey},
            header::FrameType,
        };
        let mut buffer = [0u8; PACKET_BUFFER_MAX];
        match header.control.frame_type {
            FrameType::Data => {
                log::info!("Handle application service data");
                // ...
            }
            FrameType::Command => {
                log::info!("Handle application service command");
                // handle command
                log::info!("Unpack application service command");
                let (command, _used) = Command::unpack(aps_payload)?;
                log::info!("...done");
                if let Command::TransportKey(cmd) = command {
                    if let TransportKey::StandardNetworkKey(key) = cmd {
                        log::info!("Set network key");
                        self.set_state(NetworkState::Secure);
                        self.security_manager.set_network_key(key);
                        log::info!("Queue device announce");
                        let mac_header = self
                            .mac
                            .build_data_header(psila_data::NetworkAddress::broadcast(), false);
                        let mac_header_len = mac_header.encode(&mut buffer);
                        let mwk_frame_size = self.application_service.build_device_announce(
                            &self.mac.identity(),
                            self.capability,
                            &mut buffer[mac_header_len..],
                            &mut self.security_manager,
                        )?;
                        self.queue_packet(&buffer[..(mac_header_len + mwk_frame_size)])?;
                    }
                }
            }
            FrameType::InterPan => {
                log::info!("Handle application service inter-PAN");
                // Not supported yet
            }
            FrameType::Acknowledgement => {
                log::info!("Handle application service acknowledge");
                // ...
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use super::*;
    use bbqueue::{self, bbq, BBQueue};
    use psila_crypto_openssl::OpenSslBackend;

    #[test]
    fn build_beacon_request() {
        const DEFAULT_LINK_KEY: [u8; 16] = [
            0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
            0x30, 0x39,
        ];
        let crypto_backend = OpenSslBackend::default();
        let address = psila_data::ExtendedAddress::new(0x8899_aabb_ccdd_eeff);
        let tx_queue = bbq![256 * 2].unwrap();
        let (tx_producer, mut tx_consumer) = tx_queue.split();

        let mut service = PsilaService::new(
            crypto_backend,
            tx_producer,
            address,
            DEFAULT_LINK_KEY.into(),
        );

        let timeout = service.timeout().unwrap();

        assert_eq!(timeout, 1_000_000);

        let grant = tx_consumer.read().unwrap();
        let packet_length = grant[0] as usize;
        let packet = &grant[1..=packet_length];

        assert_eq!(packet_length, 8);

        assert_eq!(packet, [0x03, 0x08, 0x01, 0xff, 0xff, 0xff, 0xff, 0x07]);
        tx_consumer.release(packet_length + 1, grant);

        assert!(tx_consumer.read().is_err());
    }
}
