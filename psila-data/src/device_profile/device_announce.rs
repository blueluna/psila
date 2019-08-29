use crate::common::address::{ExtendedAddress, NetworkAddress};
use crate::common::CapabilityInformation;
use crate::pack::{Pack, PackFixed};
use crate::Error;

// 2.4.3.1.11 Device_annce
/// Device Announce
///
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceAnnounce {
    /// Network address of the device
    pub network_address: NetworkAddress,
    /// IEEE address of the device
    pub ieee_address: ExtendedAddress,
    /// Device capabileties
    pub capability: CapabilityInformation,
}

impl Pack<DeviceAnnounce, Error> for DeviceAnnounce {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 11 {
            Err(Error::WrongNumberOfBytes)
        } else {
            self.network_address.pack(&mut data[0..2])?;
            self.ieee_address.pack(&mut data[2..10])?;
            data[10] = self.capability.into();
            Ok(11)
        }
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 11 {
            Err(Error::WrongNumberOfBytes)
        } else {
            let network_address = NetworkAddress::unpack(&data[0..2])?;
            let ieee_address = ExtendedAddress::unpack(&data[2..10])?;
            let capability = CapabilityInformation::from(data[10]);
            Ok((
                Self {
                    network_address,
                    ieee_address,
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
            da.ieee_address,
            [0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00]
        );
        assert_eq!(da.capability.pan_coordinator, false);
        assert_eq!(da.capability.full_function_device, false);
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
            da.ieee_address,
            [0xc1, 0xe9, 0x1f, 0x00, 0x00, 0xff, 0x0f, 0x00]
        );
        assert_eq!(da.capability.pan_coordinator, false);
        assert_eq!(da.capability.full_function_device, true);
        assert_eq!(da.capability.mains_power, true);
        assert_eq!(da.capability.idle_receive, true);
        assert_eq!(da.capability.frame_protection, false);
        assert_eq!(da.capability.allocate_address, true);
    }
}
