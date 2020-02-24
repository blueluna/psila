#![allow(clippy::cognitive_complexity)]

use std::convert::TryFrom;

use crate::security::SecurityService;

use ieee802154::mac::{self, beacon::BeaconOrder};
use psila_data::{
    self,
    application_service::{self, ApplicationServiceHeader},
    cluster_library,
    common::profile_identifier::ProfileIdentifier,
    device_profile::DeviceProfileFrame,
    network::{self, beacon::BeaconInformation, header::DiscoverRoute, NetworkHeader},
    pack::Pack,
};

pub struct Parser {
    pub security: SecurityService,
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            security: SecurityService::new(),
        }
    }

    fn handle_cluster_library_command(
        &self,
        payload: &[u8],
        command: cluster_library::GeneralCommandIdentifier,
    ) {
        match cluster_library::Command::unpack(&payload, command) {
            Ok((cmd, _used)) => {
                print!("ZCL CMD ");
                match cmd {
                    cluster_library::Command::ReadAttributes(cmd) => {
                        print!("Read attributes ");
                        for attr in cmd.attributes.iter() {
                            print!("{} ", attr);
                        }
                        println!();
                    }
                    cluster_library::Command::ReadAttributesResponse(cmd) => {
                        print!("Read attributes response ");
                        for attr in cmd.attributes.iter() {
                            print!("{} ", attr.identifier);
                            match attr.status {
                                cluster_library::ClusterLibraryStatus::Success => {
                                    if let Some(value) = &attr.value {
                                        print!("{} ", value);
                                    } else {
                                        print!("None ");
                                    }
                                }
                                _ => {
                                    print!("{:?} ", attr.status);
                                }
                            }
                        }
                        println!();
                    }
                    cluster_library::Command::WriteAttributes(cmd)
                    | cluster_library::Command::WriteAttributesUndivided(cmd)
                    | cluster_library::Command::WriteAttributesNoResponse(cmd) => {
                        print!("Write attributes ");
                        for attr in cmd.attributes.iter() {
                            print!("{} {} ", attr.identifier, attr.value);
                        }
                        println!();
                    }
                    cluster_library::Command::WriteAttributesResponse(cmd) => {
                        print!("Write attributes response");
                        for attr in cmd.attributes.iter() {
                            print!(" {} {:?}", attr.identifier, attr.status);
                        }
                        println!();
                    }
                    cluster_library::Command::ReportAttributes(cmd) => {
                        print!("Report attributes ");
                        for attr in cmd.attributes.iter() {
                            print!("{} {} ", attr.identifier, attr.value);
                        }
                        println!();
                    }
                    cluster_library::Command::DefaultResponse(cmd) => {
                        println!("Default response {:02x} {:?}", cmd.command, cmd.status);
                    }
                    cluster_library::Command::DiscoverAttributes(cmd) => {
                        println!("Discovery attributes {} {}", cmd.start, cmd.count);
                    }
                    cluster_library::Command::DiscoverAttributesResponse(cmd) => {
                        print!("Discovery attributes response {}", cmd.complete);
                        for attribute in cmd.attributes.iter() {
                            print!(" {} {:?}", attribute.0, attribute.1);
                        }
                        println!();
                    }
                    _ => {
                        print!("{:?} Payload: ", cmd);
                        for b in payload.iter() {
                            print!("{:02x}", b);
                        }
                        println!();
                    }
                }
            }
            Err(e) => {
                print!("Failed to parse ZCL command, {:?}", e);
                print!(" Payload: ");
                for b in payload.iter() {
                    print!("{:02x}", b);
                }
                println!();
            }
        }
    }

    fn handle_cluster_library(&self, payload: &[u8], profile: ProfileIdentifier, cluster: u16) {
        use psila_data::cluster_library::{ClusterLibraryHeader, FrameType};

        print!("ZCL {:?} {:04x} ", profile, cluster);
        match ClusterLibraryHeader::unpack(payload) {
            Ok((header, used)) => {
                print!(
                    "{:?} {:?} ",
                    header.control.frame_type, header.control.direction
                );
                if !header.control.disable_default_response {
                    print!("RSP ");
                }
                if let Some(manufacturer) = header.manufacturer {
                    print!("MNF {:04x} ", manufacturer);
                }
                print!("SEQ {} ", header.transaction_sequence);
                if header.control.frame_type == FrameType::Global {
                    if let Ok(cmd) =
                        cluster_library::GeneralCommandIdentifier::try_from(header.command)
                    {
                        println!("CMD {:?} ", cmd);
                        self.handle_cluster_library_command(&payload[used..], cmd);
                    } else {
                        print!("Unknown command {:02x} Payload: ", header.command);
                        for b in payload[used..].iter() {
                            print!("{:02x}", b);
                        }
                        println!();
                    }
                } else {
                    print!("CMD {:02x} Payload: ", header.command);
                    for b in payload[used..].iter() {
                        print!("{:02x}", b);
                    }
                    println!();
                }
            }
            Err(e) => {
                print!("Failed to parse ZCL frame, {:?}", e);
                print!(" Payload: ");
                for b in payload.iter() {
                    print!("{:02x}", b);
                }
                println!();
            }
        }
    }

    fn handle_device_profile(&self, payload: &[u8], cluster: u16) {
        use psila_data::device_profile::DeviceProfileMessage;

        print!("ZDP ");
        match DeviceProfileFrame::unpack(payload, cluster) {
            Ok((frame, _)) => {
                print!("SEQ {} ", frame.transaction_sequence,);
                match frame.message {
                    DeviceProfileMessage::NetworkAddressRequest(req) => {
                        print!(
                            "Network Address Request {} {:?} Start {}",
                            req.address, req.request_type, req.start_index
                        );
                    }
                    DeviceProfileMessage::NetworkAddressResponse(rsp) => {
                        print!(
                            "Network Address Response {:?} {} {}",
                            rsp.status, rsp.network_address, rsp.ieee_address
                        );
                        if !rsp.is_empty() {
                            print!(" Start {}", rsp.start_index);
                            print!(" Associated Devices");
                            for address in rsp.devices() {
                                print!(" {}", address);
                            }
                        }
                    }
                    DeviceProfileMessage::IeeeAddressRequest(req) => {
                        print!(
                            "Network Address Request {} {:?} Start {}",
                            req.address, req.request_type, req.start_index
                        );
                    }
                    DeviceProfileMessage::IeeeAddressResponse(rsp) => {
                        print!(
                            "Network Address Response {:?} {} {}",
                            rsp.status, rsp.network_address, rsp.ieee_address
                        );
                        if !rsp.is_empty() {
                            print!(" Start {}", rsp.start_index);
                            print!(" Associated Devices");
                            for address in rsp.devices() {
                                print!(" {}", address);
                            }
                        }
                    }
                    DeviceProfileMessage::NodeDescriptorRequest(req) => {
                        print!("Node Descriptor Request {}", req.address);
                    }
                    DeviceProfileMessage::NodeDescriptorResponse(rsp) => {
                        print!(
                            "Node Descriptor Response {} {:?} {:?}",
                            rsp.address, rsp.status, rsp.descriptor.device_type,
                        );
                        if rsp.descriptor.complex_descriptor {
                            print!(" CPX");
                        }
                        if rsp.descriptor.user_descriptor {
                            print!(" USR");
                        }
                        use psila_data::device_profile::node_descriptor;
                        if rsp
                            .descriptor
                            .frequency_bands
                            .contains(node_descriptor::BandFlags::BAND_868MHZ)
                        {
                            print!(" 868MHz");
                        }
                        if rsp
                            .descriptor
                            .frequency_bands
                            .contains(node_descriptor::BandFlags::BAND_902TO928MHZ)
                        {
                            print!(" 9XXMHz");
                        }
                        if rsp
                            .descriptor
                            .frequency_bands
                            .contains(node_descriptor::BandFlags::BAND_2400TO2483MHZ)
                        {
                            print!(" 24XXMHz");
                        }
                        print!(
                            " {} {:04x} {} {} {}",
                            rsp.descriptor.mac_capability,
                            rsp.descriptor.manufacturer_code,
                            rsp.descriptor.maximum_buffer_size,
                            rsp.descriptor.maximum_incoming_transfer_size,
                            rsp.descriptor.maximum_outgoing_transfer_size
                        );
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::PRIMARY_TRUST_CENTER)
                        {
                            print!(" TC");
                        }
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::BACKUP_TRUST_CENTER)
                        {
                            print!(" BTC");
                        }
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::PRIMARY_BINDING_TABLE)
                        {
                            print!(" BT");
                        }
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::BACKUP_BINDING_TABLE)
                        {
                            print!(" BBT");
                        }
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::PRIMARY_DISCOVERY_CACHE)
                        {
                            print!(" DC");
                        }
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::BACKUP_DISCOVERY_CACHE)
                        {
                            print!(" BDC");
                        }
                        if rsp
                            .descriptor
                            .server_mask
                            .flags
                            .contains(node_descriptor::ServerFlags::NETWORK_MANAGER)
                        {
                            print!(" NM");
                        }
                        print!(
                            " {:02}",
                            rsp.descriptor.server_mask.stack_complience_version
                        );
                        if rsp.descriptor.descriptor_capability.contains(node_descriptor::DescriptorCapability::EXTENDED_ACTIVE_END_POINT_LIST_AVAILABLE) {
                            print!(" EEL");
                        }
                        if rsp.descriptor.descriptor_capability.contains(node_descriptor::DescriptorCapability::EXTENDED_SIMPLE_DESCRIPTOR_LIST_AVAILABLE) {
                            print!(" ESD");
                        }
                    }
                    DeviceProfileMessage::PowerDescriptorRequest(req) => {
                        print!("Power Descriptor Request {}", req.address);
                    }
                    DeviceProfileMessage::PowerDescriptorResponse(rsp) => {
                        print!(
                            "Power Descriptor Response {} {:?} {:?} {:?} {:?} {:?}",
                            rsp.address,
                            rsp.status,
                            rsp.descriptor.mode,
                            rsp.descriptor.available_sources,
                            rsp.descriptor.current_sources,
                            rsp.descriptor.level
                        );
                    }
                    DeviceProfileMessage::SimpleDescriptorRequest(req) => {
                        print!(
                            "Simple Descriptor Request {} Endpoint {:02x}",
                            req.address, req.endpoint
                        );
                    }
                    DeviceProfileMessage::SimpleDescriptorResponse(rsp) => {
                        print!(
                            "Simple Descriptor Response {} {:?} {:02x} {:04x} {:04x} {:02x}",
                            rsp.address,
                            rsp.status,
                            rsp.descriptor.endpoint,
                            rsp.descriptor.profile,
                            rsp.descriptor.device,
                            rsp.descriptor.device_version,
                        );
                        let clusters = rsp.descriptor.input_clusters();
                        print!(" IN {}", clusters.len());
                        for cluster in clusters {
                            print!(" {:04x}", cluster);
                        }
                        let clusters = rsp.descriptor.output_clusters();
                        print!(" OUT {}", clusters.len());
                        for cluster in clusters {
                            print!(" {:04x}", cluster);
                        }
                    }
                    DeviceProfileMessage::ActiveEndpointRequest(req) => {
                        print!("Active Endpoint Request {}", req.address);
                    }
                    DeviceProfileMessage::ActiveEndpointResponse(rsp) => {
                        print!("Active Endpoint Response {} {:?}", rsp.address, rsp.status);
                        for endpoint in rsp.endpoints() {
                            print!(" {:02x}", endpoint);
                        }
                    }
                    DeviceProfileMessage::MatchDescriptorRequest(req) => {
                        print!(
                            "Match Descriptor Request: Address {} Profile {:04x} Input",
                            req.address, req.profile
                        );
                        for cluster in req.input_clusters_entries() {
                            print!(" {:04x}", cluster);
                        }
                        print!(" Output");
                        for cluster in req.output_clusters_entries() {
                            print!(" {:04x}", cluster);
                        }
                    }
                    DeviceProfileMessage::MatchDescriptorResponse(rsp) => {
                        print!(
                            "Match Descriptor Response: {:?} Address {} Nodes",
                            rsp.status, rsp.address
                        );
                        for node in rsp.entries() {
                            print!(" {:02x}", node);
                        }
                    }
                    DeviceProfileMessage::DeviceAnnounce(da) => {
                        print!(
                            "Device Announce {} {} {}",
                            da.network_address, da.ieee_address, da.capability
                        );
                    }
                    DeviceProfileMessage::ManagementLinkQualityIndicatorRequest(start_index) => {
                        print!("LQI Request {} ", start_index);
                    }
                    DeviceProfileMessage::ManagementLinkQualityIndicatorResponse(rsp) => {
                        print!("LQI Response: {:?} ", rsp.status);
                        if rsp.len() != rsp.neighbors_total as usize {
                            print!("Index {} Total {} ", rsp.neighbors_total, rsp.index);
                        }
                        for neighbor in rsp.neighbors() {
                            print!(
                                "{} {:?} RX on idle {:?} {:?} LQI {} ",
                                neighbor.extended_address,
                                neighbor.device_type,
                                neighbor.rx_idle,
                                neighbor.relationship,
                                neighbor.link_quality
                            );
                        }
                    }
                }
            }
            Err(e) => {
                print!("Failed to parse ZDP frame, {:?}", e);
                print!(" Payload: ");
                for b in payload.iter() {
                    print!("{:02x}", b);
                }
            }
        }
        println!();
    }

    fn handle_application_service_command(&mut self, payload: &[u8]) {
        use application_service::Command;
        print!("APS Command ");
        match Command::unpack(payload) {
            Ok((cmd, _used)) => {
                match cmd {
                    Command::SymmetricKeyKeyEstablishment1(cmd) => {
                        print!(
                            "SKKE1 Initator {} Responder {} ",
                            cmd.initiator, cmd.responder
                        );
                        for b in cmd.data.iter() {
                            print!("{:02x}", b);
                        }
                    }
                    Command::SymmetricKeyKeyEstablishment2(cmd) => {
                        print!(
                            "SKKE2 Initator {} Responder {} ",
                            cmd.initiator, cmd.responder
                        );
                        for b in cmd.data.iter() {
                            print!("{:02x}", b);
                        }
                    }
                    Command::SymmetricKeyKeyEstablishment3(cmd) => {
                        print!(
                            "SKKE3 Initator {} Responder {} ",
                            cmd.initiator, cmd.responder
                        );
                        for b in cmd.data.iter() {
                            print!("{:02x}", b);
                        }
                    }
                    Command::SymmetricKeyKeyEstablishment4(cmd) => {
                        print!(
                            "SKKE4 Initator {} Responder {} ",
                            cmd.initiator, cmd.responder
                        );
                        for b in cmd.data.iter() {
                            print!("{:02x}", b);
                        }
                    }
                    Command::TransportKey(cmd) => {
                        use application_service::commands::TransportKey;
                        print!("Transport Key ");
                        match cmd {
                            TransportKey::TrustCenterMasterKey(key) => {
                                print!(
                                    "Trust Center Master Key, DST {} SRC {} KEY {}",
                                    key.destination, key.source, key.key
                                );
                            }
                            TransportKey::StandardNetworkKey(key) => {
                                print!(
                                    "Standard Network Key, DST {} SRC {} SEQ {} KEY {}",
                                    key.destination, key.source, key.sequence, key.key
                                );
                                self.security.add_transport_key(&key);
                            }
                            TransportKey::ApplicationMasterKey(key) => {
                                print!(
                                    "Application Master Key, Partner {} {} KEY {}",
                                    key.partner,
                                    if key.initiator { "Initiator" } else { "" },
                                    key.key
                                );
                            }
                            TransportKey::ApplicationLinkKey(key) => {
                                print!(
                                    "Application Link Key, Partner {} {} KEY {}",
                                    key.partner,
                                    if key.initiator { "Initiator" } else { "" },
                                    key.key
                                );
                            }
                            TransportKey::UniqueTrustCenterLinkKey(key) => {
                                print!(
                                    "Unique Trust Center Link Key, DST {} SRC {} KEY {}",
                                    key.destination, key.source, key.key
                                );
                            }
                            TransportKey::HighSecurityNetworkKey(key) => {
                                print!(
                                    "High Security Network Key, DST {} SRC {} SEQ {} KEY {}",
                                    key.destination, key.source, key.sequence, key.key
                                );
                            }
                        }
                    }
                    Command::UpdateDevice(cmd) => {
                        print!(
                            "Update Device, {} {} {:?}",
                            cmd.address, cmd.short_address, cmd.status
                        );
                    }
                    Command::RemoveDevice(cmd) => {
                        print!("Remove Device, {}", cmd.address);
                    }
                    Command::RequestKey(cmd) => {
                        print!("Request Key, {:?}", cmd.key_type);
                        if let Some(partner) = cmd.partner_address {
                            print!(" Partner {}", partner);
                        }
                    }
                    Command::SwitchKey(cmd) => {
                        print!("Switch Key, Sequence {}", cmd.sequence);
                    }
                    Command::EntityAuthenticationInitiatorChallenge => {
                        print!("EAC Initiator");
                    }
                    Command::EntityAuthenticationResponderChallenge => {
                        print!("EAC Responder");
                    }
                    Command::EntityAuthenticationInitiatorMacAndData => {
                        print!("EAMD Initiator");
                    }
                    Command::EntityAuthenticationResponderMacAndData => {
                        print!("EAMD Responder");
                    }
                    Command::Tunnel(cmd) => {
                        print!("Tunnel {}", cmd.destination);
                    }
                    Command::VerifyKey(cmd) => {
                        print!("Verify Key, Source {} Type {:?} ", cmd.source, cmd.key_type);
                        for b in cmd.value.iter() {
                            print!("{:02x}", b);
                        }
                    }
                    Command::ConfirmKey(cmd) => {
                        print!(
                            "Confirm Key, Source {} Type {:?} Status {:?}",
                            cmd.destination, cmd.key_type, cmd.status
                        );
                    }
                }
                println!();
            }
            Err(e) => {
                println!("Failed to parse APS command, {:?}", e);
            }
        }
    }

    fn parse_application_service_frame(&mut self, payload: &[u8]) {
        print!("APS ");
        match ApplicationServiceHeader::unpack(payload) {
            Ok((header, used)) => {
                print!(
                    "{:?} {:?} ",
                    header.control.frame_type, header.control.delivery_mode,
                );
                if header.control.security {
                    print!("Secure ");
                }
                if header.control.acknowledge_request {
                    print!("AckReq ");
                }
                if header.control.extended_header {
                    print!("ExtHdr ");
                }
                if let Some(addr) = header.destination {
                    print!("Dst {:02x} ", addr);
                }
                if let Some(group) = header.group {
                    print!("Group {:04x} ", group);
                }
                if let Some(cluster) = header.cluster {
                    print!("Cluster {:04x} ", cluster);
                }
                if let Some(profile) = header.profile {
                    print!("Profile {:04x} ", profile);
                }
                if let Some(addr) = header.source {
                    print!("Src {:02x} ", addr);
                }
                println!("Counter {:02x}", header.counter);
                let mut processed_payload = [0u8; 256];
                let length = if header.control.security {
                    self.security
                        .decrypt(&payload, used, &mut processed_payload)
                } else {
                    let length = payload.len() - used;
                    processed_payload[..length].copy_from_slice(&payload[used..]);
                    length
                };
                match header.control.frame_type {
                    application_service::header::FrameType::Data => {
                        if let (Some(cluster), Some(profile)) = (header.cluster, header.profile) {
                            match ProfileIdentifier::try_from(profile) {
                                Ok(profile) => match profile {
                                    ProfileIdentifier::DeviceProfile => {
                                        self.handle_device_profile(
                                            &processed_payload[..length],
                                            cluster,
                                        );
                                    }
                                    _ => {
                                        self.handle_cluster_library(
                                            &processed_payload[..length],
                                            profile,
                                            cluster,
                                        );
                                    }
                                },
                                Err(_) => {
                                    print!("Payload: ");
                                    for b in payload[used..].iter() {
                                        print!("{:02x}", b);
                                    }
                                    println!();
                                }
                            }
                        } else {
                            print!("Payload: ");
                            for b in payload[used..].iter() {
                                print!("{:02x}", b);
                            }
                            println!();
                        }
                    }
                    application_service::header::FrameType::Command => {
                        self.handle_application_service_command(&processed_payload[..length]);
                    }
                    application_service::header::FrameType::Acknowledgement => {
                        if !payload[used..].is_empty() {
                            print!("APS Acknowledgement Payload: ");
                            for b in payload[used..].iter() {
                                print!("{:02x}", b);
                            }
                            println!();
                        }
                    }
                    application_service::header::FrameType::InterPan => {
                        print!("APS Inter-PAN Payload: ");
                        for b in payload[used..].iter() {
                            print!("{:02x}", b);
                        }
                        println!();
                    }
                }
            }
            Err(e) => {
                println!("Failed to parse APS header, {:?}", e);
            }
        }
    }

    fn parse_network_command(&self, payload: &[u8]) {
        use network::commands::Command;
        print!("NWK CMD ");
        match Command::unpack(payload) {
            Ok((cmd, _used)) => match cmd {
                Command::RouteRequest(rr) => {
                    print!("Route Request {:02x} Cost {}", rr.identifier, rr.path_cost);
                    match rr.destination_address {
                        network::commands::AddressType::Singlecast(a) => {
                            print!(" Destination {}", a)
                        }
                        network::commands::AddressType::Multicast(a) => print!(" Group {}", a),
                    }
                    if let Some(address) = rr.destination_ieee_address {
                        print!(" Destination {}", address);
                    }
                    println!();
                }
                Command::RouteReply(rr) => {
                    print!(
                        "Route Reply Identifier {:02x} Orginator {} Responder {} Path cost {}",
                        rr.identifier, rr.orginator_address, rr.responder_address, rr.path_cost
                    );
                    if let Some(address) = rr.orginator_ieee_address {
                        print!(" Orginator {}", address);
                    }
                    if let Some(address) = rr.responder_ieee_address {
                        print!(" Responder {}", address);
                    }
                    println!();
                }
                Command::NetworkStatus(ns) => {
                    println!(
                        "Network Status Destination {} Status {:?}",
                        ns.destination, ns.status
                    );
                }
                Command::Leave(leave) => {
                    println!(
                        "Leave {}{}{}",
                        if leave.rejoin { "Rejoin " } else { "" },
                        if leave.request { "Request " } else { "" },
                        if leave.remove_children {
                            "Remove children "
                        } else {
                            ""
                        },
                    );
                }
                Command::RouteRecord(rr) => {
                    print!("Route Record ");
                    for address in rr.entries() {
                        print!("{} ", address);
                    }
                    println!();
                }
                Command::RejoinRequest(rr) => {
                    println!("Rejoin Request{:?}", rr);
                }
                Command::RejoinResponse(rr) => {
                    println!("Rejoin Response {:?}", rr);
                }
                Command::LinkStatus(ls) => {
                    print!("Link Status ");
                    if ls.first_frame && !ls.last_frame {
                        print!("First ");
                    } else if !ls.first_frame && ls.last_frame {
                        print!("Last ");
                    }
                    for entry in ls.entries() {
                        print!(
                            "{} Incoming {} Outgoing {} ",
                            entry.address, entry.incoming_cost, entry.outgoing_cost
                        );
                    }
                    println!();
                }
                Command::NetworkReport(nr) => {
                    println!(
                        "Network Conflict {} {}",
                        nr.extended_pan_identifier, nr.pan_identifier
                    );
                }
                Command::NetworkUpdate(nu) => {
                    println!(
                        "Network Update {} {}",
                        nu.extended_pan_identifier, nu.pan_identifier
                    );
                }
                Command::EndDeviceTimeoutRequest(edtr) => {
                    println!("End-device Timeout Request, Timeout {:?}", edtr.timeout);
                }
                Command::EndDeviceTimeoutResponse(edtr) => {
                    println!(
                        "End-device Timeout Response, {:?} {} {}",
                        edtr.status,
                        if edtr.mac_keep_alive {
                            "MAC keep alive"
                        } else {
                            ""
                        },
                        if edtr.end_device_keep_alive {
                            "End device keep alive"
                        } else {
                            ""
                        },
                    );
                }
            },
            Err(e) => {
                println!("Failed to decode network command, {:?}", e);
            }
        }
    }

    fn parse_network_frame(&mut self, payload: &[u8]) {
        match NetworkHeader::unpack(payload) {
            Ok((network_frame, used)) => {
                print!("NWK TYP {:?} ", network_frame.control.frame_type);
                print!("VER {} ", network_frame.control.protocol_version);
                match network_frame.control.discover_route {
                    DiscoverRoute::EnableDiscovery => {
                        print!("DSC ");
                    }
                    DiscoverRoute::SurpressDiscovery => {}
                }
                if network_frame.control.security {
                    print!("SEC ");
                }
                print!("DST {} ", network_frame.destination_address);
                print!("SRC {} ", network_frame.source_address);
                print!("RAD {} ", network_frame.radius);
                print!("SEQ {} ", network_frame.sequence_number);
                if let Some(dst) = network_frame.destination_ieee_address {
                    print!("DST {} ", dst);
                }
                if let Some(src) = network_frame.source_ieee_address {
                    print!("SRC {} ", src);
                }
                if let Some(mc) = network_frame.multicast_control {
                    print!("MC {:?} RAD {} MAX {}", mc.mode, mc.radius, mc.max_radius);
                }
                if let Some(srf) = network_frame.source_route_frame {
                    print!("SRF I {}", srf.index);
                    for address in srf.entries() {
                        print!(" {}", address);
                    }
                }
                println!();
                let mut processed_payload = [0u8; 256];
                let length = if network_frame.control.security {
                    self.security
                        .decrypt(&payload, used, &mut processed_payload)
                } else {
                    let length = payload.len() - used;
                    processed_payload[..length].copy_from_slice(&payload[used..]);
                    length
                };
                if length > 0 {
                    match network_frame.control.frame_type {
                        network::header::FrameType::Data | network::header::FrameType::InterPan => {
                            self.parse_application_service_frame(&processed_payload[..length])
                        }
                        network::header::FrameType::Command => {
                            self.parse_network_command(&processed_payload[..length]);
                        }
                    }
                }
            }
            Err(ref e) => {
                print!("Failed to decode network frame, ");
                match e {
                    psila_data::Error::NotEnoughSpace => {
                        print!("Not enough space");
                    }
                    psila_data::Error::WrongNumberOfBytes => {
                        print!("Wrong number of bytes");
                    }
                    psila_data::Error::UnknownFrameType => {
                        print!("Unknown frame type");
                    }
                    psila_data::Error::BrokenRelayList => {
                        print!("Broken relay list");
                    }
                    psila_data::Error::UnknownNetworkCommand => {
                        print!("Unknown network command");
                    }
                    psila_data::Error::UnknownDeliveryMode => {
                        print!("Unknown delivery mode");
                    }
                    _ => {
                        print!("{:?}", e);
                    }
                }
                print!(" Payload: ");
                for b in payload.iter() {
                    print!("{:02x}", b);
                }
                println!();
            }
        }
    }

    fn parse_mac(&mut self, packet: &[u8]) {
        use mac::Address;
        match mac::Frame::decode(packet, false) {
            Ok(frame) => {
                print!("802.15.4");
                match frame.header.frame_type {
                    mac::FrameType::Acknowledgement => {
                        print!(" TYPE: Acknowledgement");
                    }
                    mac::FrameType::Beacon => {
                        print!(" TYPE: Beacon");
                    }
                    mac::FrameType::Data => {
                        print!(" TYPE: Data");
                    }
                    mac::FrameType::MacCommand => {
                        print!(" TYPE: Command");
                    }
                }
                print!(
                    "{}",
                    if frame.header.frame_pending {
                        " PEND"
                    } else {
                        ""
                    }
                );
                print!("{}", if frame.header.ack_request { " ACK" } else { "" });
                print!(
                    "{}",
                    if frame.header.pan_id_compress {
                        " CMPR"
                    } else {
                        ""
                    }
                );
                print!(" SEQ: {}", frame.header.seq);
                match frame.header.destination {
                    Address::Short(i, a) => {
                        print!(" DST: {:04x}:{:04x}", i.0, a.0);
                    }
                    Address::Extended(i, a) => {
                        print!(" DST: {:04x}:{:016x}", i.0, a.0);
                    }
                    Address::None => {
                        print!(" DST: None");
                    }
                }
                match frame.header.source {
                    Address::Short(i, a) => {
                        print!(" SRC: {:04x}:{:04x}", i.0, a.0);
                    }
                    Address::Extended(i, a) => {
                        print!(" SRC: {:04x}:{:016x}", i.0, a.0);
                    }
                    Address::None => {
                        print!(" SRC: None");
                    }
                }
                match frame.content {
                    mac::FrameContent::Acknowledgement => {
                        // Nothing here
                        println!();
                    }
                    mac::FrameContent::Beacon(beacon) => {
                        print!(" Beacon ");
                        if beacon.superframe_spec.beacon_order != BeaconOrder::OnDemand {
                            print!(
                                "Beacon order {:?} Superframe order {:?} Final CAP slot {}",
                                beacon.superframe_spec.beacon_order,
                                beacon.superframe_spec.superframe_order,
                                beacon.superframe_spec.final_cap_slot
                            )
                        }
                        let coordinator = if beacon.superframe_spec.pan_coordinator {
                            "Coordinator"
                        } else {
                            "Device"
                        };
                        let association_permit = if beacon.superframe_spec.association_permit {
                            "Permit association"
                        } else {
                            "Deny association"
                        };
                        print!("\"{}\" \"{}\"", coordinator, association_permit);
                        if beacon.superframe_spec.battery_life_extension {
                            print!("\"Battery life extension\"");
                        }
                        if beacon.guaranteed_time_slot_info.permit {
                            print!(
                                "GTS slots {}",
                                beacon.guaranteed_time_slot_info.slots().len()
                            )
                        }
                        println!();
                        match BeaconInformation::unpack(frame.payload) {
                            Ok((bi, _)) => {
                                let router = if bi.router_capacity { "Router" } else { "" };
                                let end_device = if bi.end_device_capacity {
                                    "End Device"
                                } else {
                                    ""
                                };
                                println!("Protocol {:?} Stack {:?} Version {} {} Depth {} {} Address {} TX offset {:08x} Update {:02x}",
	                                     bi.protocol_indentifier,
	                                     bi.stack_profile,
	                                     bi.network_protocol_version,
	                                     router,
	                                     bi.device_depth,
	                                     end_device,
	                                     bi.extended_pan_address,
	                                     bi.tx_offset,
	                                     bi.network_update_identifier,
	                            );
                            }
                            Err(e) => {
                                print!("Failed to parse beacon information, {:?}", e);
                                print!(" Payload: ");
                                for b in frame.payload.iter() {
                                    print!("{:02x}", b);
                                }
                                println!();
                            }
                        }
                    }
                    mac::FrameContent::Data => {
                        println!();
                        self.parse_network_frame(frame.payload);
                    }
                    mac::FrameContent::Command(command) => {
                        print!(" Command ");
                        match command {
                            mac::command::Command::AssociationRequest(cmd) => {
                                print!("Association request ");
                                if cmd.full_function_device {
                                    print!("FFD ");
                                } else {
                                    print!("RFD ");
                                }
                                if cmd.mains_power {
                                    print!("Mains power ");
                                }
                                if cmd.idle_receive {
                                    print!("Idle Rx ");
                                }
                                if cmd.frame_protection {
                                    print!("Secure ");
                                }
                                if cmd.allocate_address {
                                    print!("Allocate address ");
                                }
                            }
                            mac::command::Command::AssociationResponse(address, status) => {
                                print!("Association response {:04x} {:?}", address.0, status);
                            }
                            mac::command::Command::DisassociationNotification(cmd) => {
                                print!("Disassociation ");
                                match cmd {
                                    mac::command::DisassociationReason::CoordinatorLeave => {
                                        print!("requested to leave");
                                    }
                                    mac::command::DisassociationReason::DeviceLeave => {
                                        print!("leave");
                                    }
                                }
                            }
                            mac::command::Command::BeaconRequest => {
                                print!("Beacon request");
                            }
                            mac::command::Command::DataRequest => {
                                print!("Data request");
                            }
                            _ => {
                                print!("{:?}", command);
                            }
                        }
                        println!();
                    }
                }
            }
            Err(e) => {
                print!("Unknown Packet, ");
                match e {
                    mac::DecodeError::NotEnoughBytes => {
                        println!("NotEnoughBytes");
                    }
                    mac::DecodeError::InvalidFrameType(_) => {
                        println!("InvalidFrameType");
                    }
                    mac::DecodeError::SecurityNotSupported => {
                        println!("SecurityNotSupported");
                    }
                    mac::DecodeError::InvalidAddressMode(_) => {
                        println!("Invalid Address Mode");
                    }
                    mac::DecodeError::InvalidFrameVersion(_) => {
                        println!("InvalidFrameVersion");
                    }
                    mac::DecodeError::InvalidValue => {
                        println!("InvalidValue");
                    }
                }
            }
        }
    }

    pub fn parse_packet(&mut self, packet: &[u8]) {
        self.parse_mac(packet);
    }
}
