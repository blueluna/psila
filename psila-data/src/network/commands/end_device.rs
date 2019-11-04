use core::convert::TryFrom;

use crate::error::Error;
use crate::pack::Pack;

extended_enum!(
    Timeout, u8,
    Timeout10Seconds => 0x00,
    Timeout2Minutes => 0x01,
    Timeout4Minutes => 0x02,
    Timeout8Minutes => 0x03,
    Timeout16Minutes => 0x04,
    Timeout32Minutes => 0x05,
    Timeout64Minutes => 0x06,
    Timeout128Minutes => 0x07,
    Timeout256Minutes => 0x08,
    Timeout512Minutes => 0x09,
    Timeout1024Minutes => 0x0a,
    Timeout2048Minutes => 0x0b,
    Timeout4096Minutes => 0x0c,
    Timeout8192Minutes => 0x0d,
    Timeout16384Minutes => 0x0e,
);

impl Timeout {
    pub fn in_seconds(self) -> u32 {
        match self {
            Timeout::Timeout10Seconds => 10,
            Timeout::Timeout2Minutes => 60 * 2,
            Timeout::Timeout4Minutes => 60 * 4,
            Timeout::Timeout8Minutes => 60 * 8,
            Timeout::Timeout16Minutes => 60 * 16,
            Timeout::Timeout32Minutes => 60 * 32,
            Timeout::Timeout64Minutes => 60 * 64,
            Timeout::Timeout128Minutes => 60 * 128,
            Timeout::Timeout256Minutes => 60 * 256,
            Timeout::Timeout512Minutes => 60 * 512,
            Timeout::Timeout1024Minutes => 60 * 1024,
            Timeout::Timeout2048Minutes => 60 * 2048,
            Timeout::Timeout4096Minutes => 60 * 4096,
            Timeout::Timeout8192Minutes => 60 * 8192,
            Timeout::Timeout16384Minutes => 60 * 16384,
        }
    }
}

/// End-device timeout request
///
/// Request for timeout configuration. If the end device do not communicate
/// within the timeout, the device can be removed from the neighbor table.
#[derive(Clone, Debug, PartialEq)]
pub struct EndDeviceTimeoutRequest {
    pub timeout: Timeout,
}

impl Pack<EndDeviceTimeoutRequest, Error> for EndDeviceTimeoutRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.timeout as u8;
        data[1] = 0;
        Ok(2)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let timeout = Timeout::try_from(data[0])?;
        if data[1] != 0 {
            return Err(Error::InvalidValue);
        }
        Ok((Self { timeout }, 2))
    }
}

extended_enum!(
    Status, u8,
    Success => 0x00,
    IncorrectValue => 0x01,
);

const MAC_KEEP_ALIVE: u8 = 0b0000_0001;
const END_DEVICE_KEEP_ALIVE: u8 = 0b0000_0010;

/// End-device timeout response
///
#[derive(Clone, Debug, PartialEq)]
pub struct EndDeviceTimeoutResponse {
    /// Status of the response
    pub status: Status,
    /// Parent support MAC data poll keep-alive
    pub mac_keep_alive: bool,
    /// Parent support end device timeout request keep-alive
    pub end_device_keep_alive: bool,
}

impl Pack<EndDeviceTimeoutResponse, Error> for EndDeviceTimeoutResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.status as u8;
        data[1] = if self.mac_keep_alive {
            MAC_KEEP_ALIVE
        } else {
            0
        } | if self.end_device_keep_alive {
            END_DEVICE_KEEP_ALIVE
        } else {
            0
        };
        Ok(2)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = Status::try_from(data[0])?;
        let mac_keep_alive = (data[1] & MAC_KEEP_ALIVE) == MAC_KEEP_ALIVE;
        let end_device_keep_alive = (data[1] & END_DEVICE_KEEP_ALIVE) == END_DEVICE_KEEP_ALIVE;
        Ok((
            Self {
                status,
                mac_keep_alive,
                end_device_keep_alive,
            },
            2,
        ))
    }
}
