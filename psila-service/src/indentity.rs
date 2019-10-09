use ieee802154::mac::Address;
use psila_data::{ExtendedAddress, ShortAddress};

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub short: ShortAddress,
    pub extended: ExtendedAddress,
}

impl Identity {
    pub fn new() -> Self {
        Identity {
            short: ShortAddress::broadcast(),
            extended: ExtendedAddress::broadcast(),
        }
    }

    pub fn from_extended(extended_address: ExtendedAddress) -> Self {
        assert!(extended_address != ExtendedAddress::broadcast());
        Identity {
            short: psila_data::ShortAddress::broadcast(),
            extended: extended_address,
        }
    }

    pub fn assigned_short(&self) -> bool {
        self.short.is_assigned()
    }

    pub fn assigned_extended(&self) -> bool {
        self.extended != ExtendedAddress::broadcast()
    }

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
