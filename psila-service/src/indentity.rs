use core::default::Default;

use ieee802154::mac::Address;
use psila_data::{ExtendedAddress, ShortAddress};

/// Node identity
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    /// The short address of the node
    pub short: ShortAddress,
    /// The extended address of the node
    pub extended: ExtendedAddress,
}

impl Identity {
    /// Create `Identity` from extended address. will set the short address to broadcast.
    pub fn from_extended(extended_address: ExtendedAddress) -> Self {
        assert!(extended_address != ExtendedAddress::broadcast());
        Identity {
            short: psila_data::ShortAddress::broadcast(),
            extended: extended_address,
        }
    }

    /// Check if the short address has been assigned
    pub fn assigned_short(&self) -> bool {
        self.short.is_assigned()
    }

    /// Check if the extended address has been assigned
    pub fn assigned_extended(&self) -> bool {
        self.extended != ExtendedAddress::broadcast()
    }

    /// Check if the provided address was addressed to this identity
    pub fn addressed_to(&self, address: &Address) -> bool {
        match *address {
            Address::None => false,
            Address::Short(_, short_address) => {
                if self.assigned_short() {
                    self.short == short_address
                } else {
                    false
                }
            }
            Address::Extended(_, extended_address) => {
                if self.assigned_extended() {
                    self.extended == extended_address
                } else {
                    false
                }
            }
        }
    }
}

impl Default for Identity {
    /// Create `Identity` with broadcast short and extended address
    fn default() -> Self {
        Identity {
            short: ShortAddress::broadcast(),
            extended: ExtendedAddress::broadcast(),
        }
    }
}
