use core::convert::From;

const CAPABILITY_ALTERNATE_PAN_COORDINATOR: u8 = 0x01;
const CAPABILITY_ROUTER_CAPABLE: u8 = 0x02;
const CAPABILITY_MAINS_POWER: u8 = 0x04;
const CAPABILITY_IDLE_RECEIVE: u8 = 0x08;
const CAPABILITY_FRAME_PROTECTION: u8 = 0x40;
const CAPABILITY_ALLOCATE_ADDRESS: u8 = 0x80;

/// MAC layer capability information
///
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CapabilityInformation {
    /// Device is capable of acting as a PAN coordinator
    pub alternate_pan_coordinator: bool,
    /// The device can act as a router
    pub router_capable: bool,
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
    /// Create `CapabilityInformation` from a byte
    fn from(byte: u8) -> Self {
        let alternate_pan_coordinator =
            byte & CAPABILITY_ALTERNATE_PAN_COORDINATOR == CAPABILITY_ALTERNATE_PAN_COORDINATOR;
        let router_capable = byte & CAPABILITY_ROUTER_CAPABLE == CAPABILITY_ROUTER_CAPABLE;
        let mains_power = byte & CAPABILITY_MAINS_POWER == CAPABILITY_MAINS_POWER;
        let idle_receive = byte & CAPABILITY_IDLE_RECEIVE == CAPABILITY_IDLE_RECEIVE;
        let frame_protection = byte & CAPABILITY_FRAME_PROTECTION == CAPABILITY_FRAME_PROTECTION;
        let allocate_address = byte & CAPABILITY_ALLOCATE_ADDRESS == CAPABILITY_ALLOCATE_ADDRESS;
        Self {
            alternate_pan_coordinator,
            router_capable,
            mains_power,
            idle_receive,
            frame_protection,
            allocate_address,
        }
    }
}

impl From<CapabilityInformation> for u8 {
    /// Create a byte from `CapabilityInformation`
    fn from(ar: CapabilityInformation) -> Self {
        let mut byte = 0u8;
        if ar.alternate_pan_coordinator {
            byte |= CAPABILITY_ALTERNATE_PAN_COORDINATOR;
        }
        if ar.router_capable {
            byte |= CAPABILITY_ROUTER_CAPABLE;
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
            if self.alternate_pan_coordinator {
                "Alternate Coordinator "
            } else {
                ""
            },
            if self.router_capable {
                "Router cabable "
            } else {
                "End device"
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
