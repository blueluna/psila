use core::convert::From;

pub mod address;
pub mod key;
pub mod profile_identifier;
pub mod types;

const CAPABILITY_PAN_COORDINATOR: u8 = 0x01;
const CAPABILITY_FFD: u8 = 0x02;
const CAPABILITY_MAINS_POWER: u8 = 0x04;
const CAPABILITY_IDLE_RECEIVE: u8 = 0x08;
const CAPABILITY_FRAME_PROTECTION: u8 = 0x40;
const CAPABILITY_ALLOCATE_ADDRESS: u8 = 0x80;

/// MAC layer capability information
///
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CapabilityInformation {
    /// Device is capable of acting as a PAN coordinator
    pub pan_coordinator: bool,
    /// Full-function device (FFD) or a reduced-function device (RFD)
    /// RFD and FFD have different function sets.
    pub full_function_device: bool,
    /// Device is connected to a mains power source or not
    pub mains_power: bool,
    /// Receive is enabled while idle
    pub idle_receive: bool,
    /// Frames are cryptographically protected
    pub frame_protection: bool,
    /// Device wish to have an short address allocated by the coordinator
    pub allocate_address: bool,
}

impl From<u8> for CapabilityInformation {
    fn from(byte: u8) -> Self {
        let pan_coordinator = byte & CAPABILITY_PAN_COORDINATOR == CAPABILITY_PAN_COORDINATOR;
        let full_function_device = byte & CAPABILITY_FFD == CAPABILITY_FFD;
        let mains_power = byte & CAPABILITY_MAINS_POWER == CAPABILITY_MAINS_POWER;
        let idle_receive = byte & CAPABILITY_IDLE_RECEIVE == CAPABILITY_IDLE_RECEIVE;
        let frame_protection = byte & CAPABILITY_FRAME_PROTECTION == CAPABILITY_FRAME_PROTECTION;
        let allocate_address = byte & CAPABILITY_ALLOCATE_ADDRESS == CAPABILITY_ALLOCATE_ADDRESS;
        Self {
            pan_coordinator,
            full_function_device,
            mains_power,
            idle_receive,
            frame_protection,
            allocate_address,
        }
    }
}

impl From<CapabilityInformation> for u8 {
    fn from(ar: CapabilityInformation) -> Self {
        let mut byte = 0u8;
        if ar.pan_coordinator {
            byte |= CAPABILITY_PAN_COORDINATOR;
        }
        if ar.full_function_device {
            byte |= CAPABILITY_FFD;
        }
        if ar.mains_power {
            byte |= CAPABILITY_MAINS_POWER;
        }
        if ar.idle_receive {
            byte |= CAPABILITY_IDLE_RECEIVE;
        }
        if ar.frame_protection {
            byte |= CAPABILITY_FRAME_PROTECTION;
        }
        if ar.allocate_address {
            byte |= CAPABILITY_ALLOCATE_ADDRESS;
        }
        byte
    }
}

#[cfg(not(feature = "core"))]
impl std::fmt::Display for CapabilityInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}{}{}",
            if self.pan_coordinator {
                "Coordinator "
            } else {
                ""
            },
            if self.full_function_device {
                "Full function "
            } else {
                "Reduced function "
            },
            if self.mains_power { "Mains power " } else { "" },
            if self.idle_receive {
                "Idle receive "
            } else {
                ""
            },
            if self.frame_protection {
                "Frame protection "
            } else {
                ""
            },
            if self.allocate_address {
                "Allocate address "
            } else {
                ""
            },
        )
    }
}
