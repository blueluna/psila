use core::cell::{Cell, RefCell};

use crate::security::SecurityManager;
use crate::{Error, Identity};
use psila_crypto::CryptoBackend;
use psila_data::{
    application_service::ApplicationServiceHeader,
    cluster_library,
    device_profile::{self, ClusterIdentifier, DeviceAnnounce},
    network::{self, header::DiscoverRoute, NetworkHeader},
    pack::Pack,
    CapabilityInformation, NetworkAddress,
};

pub struct ApplicationServiceContext {
    aps_sequence: Cell<u8>,
    dp_sequence: Cell<u8>,
    nwk_sequence: Cell<u8>,
    buffer: RefCell<[u8; 128]>,
}

impl Default for ApplicationServiceContext {
    fn default() -> Self {
        Self {
            aps_sequence: Cell::new(0),
            dp_sequence: Cell::new(0),
            nwk_sequence: Cell::new(0),
            buffer: RefCell::new([0u8; 128]),
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

    pub fn build_acknowledge<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        source_header: &ApplicationServiceHeader,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let aps_header = ApplicationServiceHeader::new_acknowledge_header(source_header, 1);
        let network_header = NetworkHeader::new_data_header(
            2,                              // protocol version
            DiscoverRoute::EnableDiscovery, // discovery route
            true,                           // security
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let used = aps_header.pack(&mut self.buffer.borrow_mut()[..])?;
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..used],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_network_command<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        network_command: &network::Command,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let network_header = NetworkHeader::new_command_header(
            2,                              // protocol version
            DiscoverRoute::EnableDiscovery, // discovery route
            true,                           // security
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let used = network_command.pack(&mut self.buffer.borrow_mut()[..])?;
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..used],
            buffer,
        )?;
        Ok(used)
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
            extended_address: identity.extended,
            capability,
        };
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                                        // destination
            ClusterIdentifier::DeviceAnnounce.into(), // cluster
            0,                                        // profile
            0,                                        // source
            self.aps_sequence_next(),                 // counter
            false,                                    // acknowledge request
            false,                                    // security
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
        let mut offset = 0;
        {
            let work_buffer = &mut self.buffer.borrow_mut()[offset..];
            let used = aps_header.pack(&mut work_buffer[offset..])?;
            offset += used;
            work_buffer[offset] = self.dp_sequence_next();
            offset += 1;
            let used = device_announce.pack(&mut work_buffer[offset..])?;
            offset += used;
        }
        let used = security.encrypt_network_payload(
            identity.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_address_response<CB: CryptoBackend>(
        &self,
        status: device_profile::Status,
        dp_sequence: u8,
        cluster: ClusterIdentifier,
        source: &Identity,
        destination: NetworkAddress,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let rsp = device_profile::AddressResponse::single_device_response(
            status,
            source.extended,
            source.short,
        );
        let cluster = device_profile::RESPONSE | u16::from(cluster);
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                        // destination
            cluster,                  // cluster
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
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut offset = 0;
        {
            let work_buffer = &mut self.buffer.borrow_mut()[offset..];
            let used = aps_header.pack(&mut work_buffer[offset..])?;
            offset += used;
            work_buffer[offset] = dp_sequence;
            offset += 1;
            let used = rsp.pack(&mut work_buffer[offset..])?;
            offset += used;
        }
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_network_address_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        dp_sequence: u8,
        status: device_profile::Status,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        self.build_address_response(
            status,
            dp_sequence,
            ClusterIdentifier::NetworkAddressRequest,
            source,
            destination,
            buffer,
            security,
        )
    }

    pub fn build_extended_address_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        dp_sequence: u8,
        status: device_profile::Status,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        self.build_address_response(
            status,
            dp_sequence,
            ClusterIdentifier::ExtendedAddressRequest,
            source,
            destination,
            buffer,
            security,
        )
    }

    pub fn build_node_descriptor_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        request: &device_profile::NodeDescriptorRequest,
        capability: CapabilityInformation,
        dp_sequence: u8,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let ndr = if request.address == source.short {
            let descriptor = device_profile::NodeDescriptor {
                device_type: device_profile::DeviceType::EndDevice,
                complex_descriptor: false,
                user_descriptor: false,
                frequency_bands: device_profile::node_descriptor::BandFlags::BAND_2400TO2483MHZ,
                mac_capability: capability,
                manufacturer_code: 0x1272, // Smartplus Inc.
                maximum_buffer_size: 82,
                maximum_incoming_transfer_size: 82,
                server_mask: device_profile::node_descriptor::ServerMask::default(),
                maximum_outgoing_transfer_size: 82,
                descriptor_capability: device_profile::node_descriptor::DescriptorCapability::empty(
                ),
            };
            device_profile::NodeDescriptorResponse {
                status: device_profile::Status::Success,
                address: source.short,
                descriptor,
            }
        } else {
            device_profile::NodeDescriptorResponse::failure_response(
                device_profile::Status::InvalidRequestType,
                source.short,
            )
        };
        let cluster =
            device_profile::RESPONSE | u16::from(ClusterIdentifier::NodeDescriptorRequest);
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                        // destination
            cluster,                  // cluster
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
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut offset = 0;
        {
            let work_buffer = &mut self.buffer.borrow_mut();
            let used = aps_header.pack(&mut work_buffer[offset..])?;
            offset += used;
            work_buffer[offset] = dp_sequence;
            offset += 1;
            let used = ndr.pack(&mut work_buffer[offset..])?;
            offset += used;
        }
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_active_endpoint_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        request: &device_profile::ActiveEndpointRequest,
        endpoints: &[u8],
        dp_sequence: u8,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let aer = if request.address == source.short {
            device_profile::ActiveEndpointResponse::success_response(source.short, endpoints)
        } else {
            device_profile::ActiveEndpointResponse::failure_response(
                device_profile::Status::InvalidRequestType,
                source.short,
            )
        };
        let cluster =
            device_profile::RESPONSE | u16::from(ClusterIdentifier::ActiveEndpointRequest);
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                        // destination
            cluster,                  // cluster
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
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut offset = 0;
        {
            let work_buffer = &mut self.buffer.borrow_mut();
            let used = aps_header.pack(&mut work_buffer[offset..])?;
            offset += used;
            work_buffer[offset] = dp_sequence;
            offset += 1;
            let used = aer.pack(&mut work_buffer[offset..])?;
            offset += used;
        }
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_power_descriptor_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        request: &device_profile::PowerDescriptorRequest,
        dp_sequence: u8,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let pdr = if request.address == source.short {
            let descriptor = device_profile::NodePowerDescriptor::default();
            device_profile::PowerDescriptorResponse {
                status: device_profile::Status::Success,
                address: destination,
                descriptor,
            }
        } else {
            device_profile::PowerDescriptorResponse::failure_response(
                device_profile::Status::InvalidRequestType,
                source.short,
            )
        };
        let cluster =
            device_profile::RESPONSE | u16::from(ClusterIdentifier::PowerDescriptorRequest);
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                        // destination
            cluster,                  // cluster
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
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut offset = 0;
        {
            let work_buffer = &mut self.buffer.borrow_mut();
            let used = aps_header.pack(&mut work_buffer[offset..])?;
            offset += used;
            work_buffer[offset] = dp_sequence;
            offset += 1;
            let used = pdr.pack(&mut work_buffer[offset..])?;
            offset += used;
        }
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_simple_descriptor_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        request: &device_profile::SimpleDescriptorRequest,
        descriptor: Option<device_profile::SimpleDescriptor>,
        dp_sequence: u8,
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let sdr = if request.address == source.short {
            if let Some(descriptor) = descriptor {
                device_profile::SimpleDescriptorResponse::success_response(
                    request.address,
                    descriptor,
                )
            } else {
                device_profile::SimpleDescriptorResponse::failure_response(
                    device_profile::Status::NotActive,
                    source.short,
                )
            }
        } else {
            device_profile::SimpleDescriptorResponse::failure_response(
                device_profile::Status::InvalidRequestType,
                source.short,
            )
        };
        let cluster =
            device_profile::RESPONSE | u16::from(ClusterIdentifier::SimpleDescriptorRequest);
        let aps_header = ApplicationServiceHeader::new_data_header(
            0,                        // destination
            cluster,                  // cluster
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
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut offset = 0;
        {
            let work_buffer = &mut self.buffer.borrow_mut();
            let used = aps_header.pack(&mut work_buffer[offset..])?;
            offset += used;
            work_buffer[offset] = dp_sequence;
            offset += 1;
            let used = sdr.pack(&mut work_buffer[offset..])?;
            offset += used;
        }
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }

    pub fn build_cluster_library_response<CB: CryptoBackend>(
        &self,
        source: &Identity,
        destination: NetworkAddress,
        profile: u16,
        cluster: u16,
        ep_src: u8,
        ep_dst: u8,
        zcl_header: &cluster_library::ClusterLibraryHeader,
        zcl_data: &[u8],
        buffer: &mut [u8],
        security: &mut SecurityManager<CB>,
    ) -> Result<usize, Error> {
        let aps_header = ApplicationServiceHeader::new_data_header(
            ep_src,                   // destination
            cluster,                  // cluster
            profile,                  // profile
            ep_dst,                   // source
            self.aps_sequence_next(), // counter
            false,                    // acknowledge request
            false,                    // security
        );
        let network_header = NetworkHeader::new_data_header(
            2,                              // protocol version
            DiscoverRoute::EnableDiscovery, // discovery route
            true,                           // security
            destination,                    // destination address
            source.short,                   // source address
            16,                             // radius
            self.nwk_sequence_next(),       // network sequence number
            None,                           // source route frame
        );
        let mut offset = 0;
        let used = aps_header.pack(&mut self.buffer.borrow_mut()[offset..])?;
        offset += used;
        let used = zcl_header.pack(&mut self.buffer.borrow_mut()[offset..])?;
        offset += used;
        self.buffer.borrow_mut()[offset..offset + zcl_data.len()].copy_from_slice(zcl_data);
        offset += zcl_data.len();
        let used = security.encrypt_network_payload(
            source.extended,
            network_header,
            &self.buffer.borrow()[..offset],
            buffer,
        )?;
        Ok(used)
    }
}
