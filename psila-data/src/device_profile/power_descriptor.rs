use core::convert::TryFrom;

use crate::common::address::NetworkAddress;
use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

extended_enum!(
    /// Node power mode
    PowerMode, u8,
    /// Always on
    OnWhenIdle => 0x00,
    /// Will periodically wake up
    Periodically => 0x01,
    /// Will wake up when stimulated (button or similar)
    WhenStimulated => 0x02,
);

extended_enum!(
    /// Power source
    PowerSource, u8,
    /// Constant (mains) power
    MainsPower => 0x00,
    /// Rechargeable battery power
    RechargeableBattery => 0x01,
    /// Disposable battery power
    DisposableBattery => 0x02,
);

extended_enum!(
    /// Power level for power source
    PowerLevel, u8,
    /// Power level critical
    Critical => 0x00,
    /// Power level 33%
    Level33Percent => 0x04,
    /// Power level 66%
    Level66Percent => 0x08,
    /// Power level 100%
    Level100Percent => 0x0c,
);

// 2.3.2.4 Node Power Descriptor
/// Power descriptor for a node
#[derive(Clone, Debug, PartialEq)]
pub struct NodePowerDescriptor {
    pub mode: PowerMode,
    pub available_sources: PowerSource,
    pub current_sources: PowerSource,
    pub level: PowerLevel,
}

impl PackFixed<NodePowerDescriptor, Error> for NodePowerDescriptor {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.mode) & 0x0f | (u8::from(self.available_sources) & 0x0f) << 4;
        data[1] = u8::from(self.current_sources) & 0x0f | (u8::from(self.level) & 0x0f) << 4;
        Ok(())
    }
    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let mode = PowerMode::try_from(data[0] & 0x0f)?;
        let available_sources = PowerSource::try_from((data[0] >> 4) & 0x0f)?;
        let current_sources = PowerSource::try_from(data[1] & 0x0f)?;
        let level = PowerLevel::try_from((data[1] >> 4) & 0x0f)?;
        Ok(Self {
            mode,
            available_sources,
            current_sources,
            level,
        })
    }
}

impl Default for NodePowerDescriptor {
    fn default() -> Self {
        Self {
            mode: PowerMode::OnWhenIdle,
            available_sources: PowerSource::MainsPower,
            current_sources: PowerSource::MainsPower,
            level: PowerLevel::Level100Percent,
        }
    }
}

// 2.4.3.1.4 Power_Desc_req
/// Power descriptor request
/// Requests the power descriptor for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct PowerDescriptorRequest {
    pub address: NetworkAddress,
}

impl Pack<PowerDescriptorRequest, Error> for PowerDescriptorRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..2])?;
        Ok(2)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        Ok((Self { address }, 2))
    }
}

// 2.4.4.2.4 Power_Desc_rsp
/// Power descriptor response
/// Response to a power descriptor request
#[derive(Clone, Debug, PartialEq)]
pub struct PowerDescriptorResponse {
    pub status: Status,
    pub address: NetworkAddress,
    pub descriptor: NodePowerDescriptor,
}

impl PowerDescriptorResponse {
    pub fn failure_response(status: Status, address: NetworkAddress) -> Self {
        assert!(status != Status::Success);
        PowerDescriptorResponse {
            status,
            address,
            descriptor: NodePowerDescriptor::default(),
        }
    }
}

impl Pack<PowerDescriptorResponse, Error> for PowerDescriptorResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let size = if self.status == Status::Success { 5 } else { 3 };
        if data.len() != size {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = u8::from(self.status);
        self.address.pack(&mut data[1..3])?;
        if self.status == Status::Success {
            self.descriptor.pack(&mut data[3..5])?;
        }
        Ok(size)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 3 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let address = NetworkAddress::unpack(&data[1..3])?;
        let (descriptor, size) = if status == Status::Success {
            (NodePowerDescriptor::unpack(&data[3..5])?, 5)
        } else {
            (NodePowerDescriptor::default(), 3)
        };
        Ok((
            Self {
                status,
                address,
                descriptor,
            },
            size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_node_descriptor_request() {
        let data = [0x96, 0x1f];
        let (req, used) = PowerDescriptorRequest::unpack(&data[..]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(req.address, 0x1f96);
    }

    #[test]
    fn unpack_node_descriptor_response_success() {
        let data = [0x00, 0x96, 0x1f, 0x10, 0xc1];
        let (req, used) = PowerDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 5);
        assert_eq!(req.status, Status::Success);
        assert_eq!(req.address, 0x1f96);
        assert_eq!(req.descriptor.mode, PowerMode::OnWhenIdle);
        assert_eq!(
            req.descriptor.available_sources,
            PowerSource::RechargeableBattery
        );
        assert_eq!(
            req.descriptor.current_sources,
            PowerSource::RechargeableBattery
        );
        assert_eq!(req.descriptor.level, PowerLevel::Level100Percent);
    }

    #[test]
    fn unpack_node_descriptor_response_error() {
        let data = [0x80, 0x96, 0x1f];
        let (req, used) = PowerDescriptorResponse::unpack(&data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(req.status, Status::InvalidRequestType);
        assert_eq!(req.address, 0x1f96);
    }

    #[test]
    fn pack_node_descriptor_response_success() {
        let descriptor = NodePowerDescriptor {
            mode: PowerMode::OnWhenIdle,
            available_sources: PowerSource::DisposableBattery,
            current_sources: PowerSource::MainsPower,
            level: PowerLevel::Critical,
        };
        let response = PowerDescriptorResponse {
            status: Status::Success,
            address: NetworkAddress::from(0x8765),
            descriptor,
        };
        let mut data = [0u8; 5];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 5);
        assert_eq!(data, [0x00, 0x65, 0x87, 0x20, 0x00]);
    }

    #[test]
    fn pack_node_descriptor_response_error() {
        let response = PowerDescriptorResponse {
            status: Status::InvalidRequestType,
            address: NetworkAddress::from(0x0123),
            descriptor: NodePowerDescriptor::default(),
        };
        let mut data = [0u8; 3];
        let used = response.pack(&mut data[..]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(data, [0x80, 0x23, 0x01]);
    }
}
