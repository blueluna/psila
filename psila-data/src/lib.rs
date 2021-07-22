//! # Psila - A Z**bee crate
//!
//! This crate contains multiple sub-systems of the Z**bee standard.
//!
//!

#![warn(missing_docs)]
#![cfg_attr(feature = "core", no_std)]

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate hash32_derive;

#[macro_use]
mod utils;

pub mod application_service; // APS
pub mod cluster_library; // ZCL
pub mod common;
pub mod device_profile; // ZDP
pub mod error;
pub mod network; // NWK
pub mod pack;
pub mod security;

pub use common::address::{
    ExtendedAddress, ExtendedPanIdentifier, GroupIdentifier, NetworkAddress, PanIdentifier,
    ShortAddress,
};
pub use common::capability_information::CapabilityInformation;
pub use common::key::Key;
pub use common::link_quality_to_cost;
pub use error::Error;

pub use utils::clear;

#[cfg(all(test, not(feature = "core")))]
mod tests {
    use ieee802154::mac::{self};

    use super::application_service::ApplicationServiceHeader;
    use super::network::NetworkHeader;
    use super::pack::Pack;
    use super::security::{self, SecurityHeader};

    #[test]
    fn interpan_frame() {
        let data = [
            0x41, 0x88, 0xf5, 0xbb, 0xbb, 0xbb, 0xeb, 0x9a, 0xca, 0x67, 0xf6, 0xc1, 0xcf, 0x66,
            0x25, 0x36, 0x6f, 0x94, 0x9f, 0x30, 0x22, 0x32, 0x9f, 0x3f, 0xc1, 0xb2, 0x79, 0x3c,
            0x11, 0x11, 0x31, 0x2b, 0xca, 0x41, 0x55, 0xa5, 0x42, 0x52, 0x39, 0xd1, 0xa0, 0xe9,
            0x12, 0x67, 0x4c, 0xf4, 0x8d, 0xce, 0xa0, 0xa0, 0x70, 0x0f, 0x0b, 0xcd, 0xbc, 0x0a,
            0xf4,
        ];
        let mac = mac::Frame::decode(&data[..], false).unwrap();
        let payload = mac.payload;
        let (_nwk, used) = NetworkHeader::unpack(&payload[..]).unwrap();
        let payload = &payload[used..];
        println!();
        let (security_header, used) = SecurityHeader::unpack(&payload[..]).unwrap();
        assert!(security_header.control.level == security::SecurityLevel::Integrity32);
        let payload = &payload[used..payload.len() - 4];
        let (aps, used) = ApplicationServiceHeader::unpack(&payload[..]).unwrap();
        let payload = &payload[used..];
        println!(
            "APS {:04x} {:04x}",
            aps.profile.unwrap(),
            aps.cluster.unwrap()
        );
        let (security_header, used) = SecurityHeader::unpack(&payload[..]).unwrap();
        assert!(security_header.control.level == security::SecurityLevel::Integrity64);
        let payload = &payload[used..payload.len() - 8];
        println!("SEC {:?}", security_header);
        for b in &payload[..] {
            print!("{:02x}", b);
        }
        println!();
    }
}
