use crate::pack::{Pack, PackFixed};
use crate::Error;
use crate::{CapabilityInformation, ExtendedAddress, NetworkAddress};

// 2.4.3.1.11 Device_annce
/// Device Announce
///
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceAnnounce {
    /// Network address of the device
    pub network_address: NetworkAddress,
    /// Extended (IEEE) address of the device
    pub extended_address: ExtendedAddress,
    /// Device capabileties
    pub capability: CapabilityInformation,
}

impl Pack<DeviceAnnounce, Error> for DeviceAnnounce {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 11 {
            Err(Error::WrongNumberOfBytes)
        } else {
            self.network_address.pack(&mut data[0..2])?;
            self.extended_address.pack(&mut data[2..10])?;
            data[10] = self.capability.into();
            Ok(11)
        }
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 11 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let network_address = NetworkAddress::unpack(&data[0..2])?;
            let extended_address = ExtendedAddress::unpack(&data[2..10])?;
            let capability = CapabilityInformation::from(data[10]);
            Ok((
                Self {
                    network_address,
                    extended_address,
                    capability,
                },
                11,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_device_announce() {
        let data = [
            0x7b, 0xc0, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x80,
        ];
        let (da, used) = DeviceAnnounce::unpack(&data[..]).unwrap();
        assert_eq!(used, 11);
        assert_eq!(da.network_address, [0x7b, 0xc0]);
        assert_eq!(
            da.extended_address,
            [0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00]
        );
        assert_eq!(da.capability.alternate_pan_coordinator, false);
        assert_eq!(da.capability.router_capable, false);
        assert_eq!(da.capability.mains_power, false);
        assert_eq!(da.capability.idle_receive, false);
        assert_eq!(da.capability.frame_protection, false);
        assert_eq!(da.capability.allocate_address, true);

        let data = [
            0x6a, 0x6a, 0xc1, 0xe9, 0x1f, 0x00, 0x00, 0xff, 0x0f, 0x00, 0x8e,
        ];
        let (da, used) = DeviceAnnounce::unpack(&data[..]).unwrap();
        assert_eq!(used, 11);
        assert_eq!(da.network_address, [0x6a, 0x6a]);
        assert_eq!(
            da.extended_address,
            [0xc1, 0xe9, 0x1f, 0x00, 0x00, 0xff, 0x0f, 0x00]
        );
        assert_eq!(da.capability.alternate_pan_coordinator, false);
        assert_eq!(da.capability.router_capable, true);
        assert_eq!(da.capability.mains_power, true);
        assert_eq!(da.capability.idle_receive, true);
        assert_eq!(da.capability.frame_protection, false);
        assert_eq!(da.capability.allocate_address, true);
    }

    #[test]
    fn pack_device_announce() {
        let mut data = [0xff; 32];
        let device_announce = DeviceAnnounce {
            network_address: NetworkAddress::new(0x8765),
            extended_address: ExtendedAddress::new(0xfedc_ba98_7654_3210),
            capability: CapabilityInformation {
                alternate_pan_coordinator: false,
                router_capable: false,
                mains_power: true,
                idle_receive: false,
                frame_protection: false,
                allocate_address: true,
            },
        };
        let used = device_announce.pack(&mut data).unwrap();
        assert_eq!(used, 11);
        assert_eq!(data[0..2], [0x65, 0x87]);
        assert_eq!(
            data[2..10],
            [0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe]
        );
        assert_eq!(data[10], 0x84);
    }
}
