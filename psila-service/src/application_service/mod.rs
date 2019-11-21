use core::cell::Cell;

use crate::security::SecurityManager;
use crate::{Error, Identity};
use psila_crypto::CryptoBackend;
use psila_data::{
    application_service::ApplicationServiceHeader,
    device_profile::{DeviceAnnounce, DeviceProfileFrame, DeviceProfileMessage},
    network::{header::DiscoverRoute, NetworkHeader},
    pack::Pack,
    CapabilityInformation, NetworkAddress,
};

pub struct ApplicationServiceContext {
    aps_sequence: Cell<u8>,
    dp_sequence: Cell<u8>,
    nwk_sequence: Cell<u8>,
}

impl Default for ApplicationServiceContext {
    fn default() -> Self {
        Self {
            aps_sequence: Cell::new(0),
            dp_sequence: Cell::new(0),
            nwk_sequence: Cell::new(0),
        }
    }
}

impl ApplicationServiceContext {
    /// Get the next sequence number
    fn aps_sequence_next(&self) -> u8 {
        let sequence = (*self).aps_sequence.get();
        let sequence = sequence.wrapping_add(1);
        (*self).aps_sequence.set(sequence);
        sequence
    }
    /// Get the next sequence number
    fn dp_sequence_next(&self) -> u8 {
        let sequence = (*self).dp_sequence.get();
        let sequence = sequence.wrapping_add(1);
        (*self).dp_sequence.set(sequence);
        sequence
    }
    /// Get the next sequence number
    fn nwk_sequence_next(&self) -> u8 {
        let sequence = (*self).nwk_sequence.get();
        let sequence = sequence.wrapping_add(1);
        (*self).nwk_sequence.set(sequence);
        sequence
    }

    pub fn build_device_announce<CB: CryptoBackend>(
        &self,
        identity: &Identity,
        capability: CapabilityInformation,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let device_announce = DeviceAnnounce {
            network_address: identity.short,
            ieee_address: identity.extended,
            capability,
        };
        let message = DeviceProfileMessage::DeviceAnnounce(device_announce);
        let device_profile_frame = DeviceProfileFrame {
            transaction_sequence: self.dp_sequence_next(),
            message,
        };
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                        // destination
            0x0013,                   // cluster
            0,                        // profile
            0,                        // source
            self.aps_sequence_next(), // counter
            false,                    // acknowledge request
            false,                    // security
        );
        let network_header = NetworkHeader::new_data_header(
            2,                              // protocol version
            DiscoverRoute::EnableDiscovery, // discovery route
            true,                           // security
            NetworkAddress::new(0xfffd),    // destination address
            identity.short,                 // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut nwk_buffer = [0u8; 128];
        let mut offset = 0;
        let used = aps_header.pack(&mut nwk_buffer[offset..])?;
        offset += used;
        let used = device_profile_frame.pack(&mut nwk_buffer[offset..])?;
        offset += used;
        let used = security.encrypt_network_payload(
            identity.extended,
            network_header,
            &nwk_buffer[..offset],
            buffer,
        )?;
        Ok(used)
    }
}
