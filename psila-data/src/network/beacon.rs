use core::convert::TryFrom;

use byteorder::{ByteOrder, LittleEndian};

use crate::common::address::ExtendedPanIdentifier;
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

// 3.6.7 NWK Information in the MAC Beacons

extended_enum!(
    /// Protocol identifier
    ProtocolIdentifier, u8,
    /// Zigbee protocol
    Zigbee => 0x00,
    /// Reserved by the zigbee alliance
    ZigbeeReserved => 0xff,
);

/// Stack proifile
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StackProfile {
    /// Network specific stack profile
    NetworkSpecific = 0x00,
    /// Zigbee home stack profile
    ZigbeeHome = 0x01,
    /// Zigbee pro stack profile
    ZigbeePro = 0x02,
}

impl TryFrom<u8> for StackProfile {
    type Error = crate::error::Error;

    fn try_from(v: u8) -> Result<Self, Error> {
        match v & 0b0000_1111 {
            0x00 => Ok(StackProfile::NetworkSpecific),
            0x01 => Ok(StackProfile::ZigbeeHome),
            0x02 => Ok(StackProfile::ZigbeePro),
            _ => Err(Error::InvalidValue),
        }
    }
}

impl From<StackProfile> for u8 {
    fn from(v: StackProfile) -> Self {
        match v {
            StackProfile::NetworkSpecific => 0x00,
            StackProfile::ZigbeeHome => 0x01,
            StackProfile::ZigbeePro => 0x02,
        }
    }
}

impl PartialEq<StackProfile> for u8 {
    fn eq(&self, other: &StackProfile) -> bool {
        match *other {
            StackProfile::NetworkSpecific => *self == 0x00,
            StackProfile::ZigbeeHome => *self == 0x01,
            StackProfile::ZigbeePro => *self == 0x02,
        }
    }
}

/// Beacon informaion sent with 802.15.4 beacon frames
pub struct BeaconInformation {
    /// Protocol identifier, describes the proticol used by this node
    pub protocol_indentifier: ProtocolIdentifier,
    /// Stack profile, describes which stack is used by this node
    pub stack_profile: StackProfile,
    /// Network protocol version used by this node
    pub network_protocol_version: u8,
    /// Node capable to act as an router
    pub router_capacity: bool,
    /// Device depth, zero indicates that this is a coordinator
    pub device_depth: u8,
    /// Node capable of accepting joins from other end devices
    pub end_device_capacity: bool,
    /// 64-bit Extended PAN identifier
    pub extended_pan_address: ExtendedPanIdentifier,
    /// `0x00ffffff` for beacon-less networks. Number of symbols between device
    /// beacon and parent beacon.
    pub tx_offset: u32,
    /// Network update identifier
    pub network_update_identifier: u8,
}

impl Pack<BeaconInformation, Error> for BeaconInformation {
    fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 15 {
            return Err(Error::WrongNumberOfBytes);
        }
        let protocol_indentifier = ProtocolIdentifier::try_from(data[0])?;
        let stack_profile = StackProfile::try_from(data[1])?;
        let network_protocol_version = (data[1] >> 4) & 0x0f;
        let router_capacity = (data[2] & 0b0000_0100) == 0b0000_0100;
        let device_depth = (data[2] & 0b0111_1000) >> 3;
        let end_device_capacity = (data[2] & 0b1000_0000) == 0b1000_0000;
        let extended_pan_address = ExtendedPanIdentifier::unpack(&data[3..=10])?;
        let tx_offset = LittleEndian::read_u32(&data[11..=14]) & 0x00ff_ffff;
        let network_update_identifier = data[14];

        Ok((
            BeaconInformation {
                protocol_indentifier,
                stack_profile,
                network_protocol_version,
                router_capacity,
                device_depth,
                end_device_capacity,
                extended_pan_address,
                tx_offset,
                network_update_identifier,
            },
            15,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_beacon_information() {
        let data = [
            0x00, 0x22, 0x84, 0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00, 0xff, 0xff, 0xff,
            0x00,
        ];
        let (bi, used) = BeaconInformation::unpack(&data).unwrap();
        assert_eq!(used, 15);
        assert_eq!(bi.protocol_indentifier, ProtocolIdentifier::Zigbee);
        assert_eq!(bi.stack_profile, StackProfile::ZigbeePro);
        assert_eq!(bi.network_protocol_version, 2);
        assert_eq!(bi.router_capacity, true);
        assert_eq!(bi.device_depth, 0);
        assert_eq!(bi.end_device_capacity, true);
        assert_eq!(
            bi.extended_pan_address,
            [0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00]
        );
        assert_eq!(bi.tx_offset, 0x00ff_ffff);
        assert_eq!(bi.network_update_identifier, 0);
    }
}
