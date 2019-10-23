//! # Psila Service

#![no_std]

use log;

use bbqueue;

use psila_data::{pack::Pack, CapabilityInformation, ExtendedAddress, Key};

use psila_crypto::CryptoBackend;

mod error;
mod indentity;
pub mod mac;
mod security;

pub use error::Error;
pub use indentity::Identity;

use mac::MacService;

/// Short address size
pub const PACKET_BUFFER_MAX: usize = 128;

pub struct PsilaService<CB> {
    mac: MacService,
    security_manager: security::SecurityManager<CB>,
    capability: CapabilityInformation,
    tx_queue: bbqueue::Producer,
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
            security_manager: security::SecurityManager::new(crypto, default_link_key),
            capability,
            tx_queue,
        }
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
    /// A new timeout value that the timer shall be configured with, a timeout
    /// value of zero (0) shall be ignored
    pub fn receive(&mut self, data: &[u8]) -> Result<u32, Error> {
        let mut buffer = [0u8; PACKET_BUFFER_MAX];
        match mac::Frame::decode(data, false) {
            Ok(frame) => {
                if !self.mac.destination_me_or_broadcast(&frame) {
                    return Ok(0);
                }
                if self.mac.requests_acknowledge(&frame) {
                    // If the frame is a data request frame, send an acknowledge with pending set
                    // Use the frame sequence number from the received frame in the acknowledge
                    let packet_length =
                        self.mac
                            .build_acknowledge(frame.header.seq, false, &mut buffer);
                    self.queue_packet(&buffer[..packet_length])?;
                }
                let (packet_length, timeout) = self.mac.handle_frame(&frame, &mut buffer)?;
                if packet_length > 0 {
                    self.queue_packet(&buffer[..packet_length])?;
                }
                if self.mac.state() == mac::State::Associated {
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
                log::info!("Handle network data");
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
                self.handle_network_frame(&header, &payload[..payload_size])?;
            }
            mac::FrameType::Beacon => {
                log::info!("Handle network beacon");
                let _ = BeaconInformation::unpack(frame.payload)?;
            }
            _ => (),
        }
        Ok(())
    }

    fn handle_network_frame(
        &mut self,
        header: &psila_data::network::NetworkHeader,
        nwk_payload: &[u8],
    ) -> Result<(), Error> {
        use psila_data::application_service::ApplicationServiceHeader;
        use psila_data::network::{commands::Command, header::FrameType};

        match header.control.frame_type {
            FrameType::Data => {
                log::info!("Handle network data");
                let mut aps_payload = [0u8; PACKET_BUFFER_MAX];
                let (header, used) = ApplicationServiceHeader::unpack(nwk_payload)?;
                let aps_payload_length = if header.control.security {
                    log::info!("Decrypt application service data");
                    self.security_manager
                        .decrypt_payload(nwk_payload, used, &mut aps_payload)?
                } else {
                    let payload_length = nwk_payload.len() - used;
                    aps_payload[..payload_length].copy_from_slice(&nwk_payload[used..]);
                    payload_length
                };
                self.handle_application_service_frame(&header, &aps_payload[..aps_payload_length])?;
            }
            FrameType::Command => {
                log::info!("Handle network command");
                let _command = Command::unpack(nwk_payload)?;
                // handle command
            }
            FrameType::InterPan => {
                log::info!("Handle inter-PAN");
                // Not supported yet
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
        match header.control.frame_type {
            FrameType::Data => {
                log::info!("Handle application service data");
                // ...
            }
            FrameType::Command => {
                log::info!("Handle application service command");
                // handle command
                let (command, _used) = Command::unpack(aps_payload)?;
                if let Command::TransportKey(cmd) = command {
                    if let TransportKey::StandardNetworkKey(key) = cmd {
                        self.security_manager.set_network_key(key.key);
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
    use psila_crypto_gcrypt::GCryptBackend;

    #[test]
    fn build_beacon_request() {
        use gcrypt;
        gcrypt::init_default();

        const DEFAULT_LINK_KEY: [u8; 16] = [
            0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
            0x30, 0x39,
        ];
        let crypto_backend = GCryptBackend::default();
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
