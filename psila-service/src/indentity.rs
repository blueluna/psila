use psila_data::{ExtendedAddress, NetworkAddress, PanIdentifier};

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub indentifier: Option<PanIdentifier>,
    pub short: Option<NetworkAddress>,
    pub extended: Option<ExtendedAddress>,
}

impl Identity {
    pub fn new() -> Self {
        Identity {
            indentifier: None,
            short: None,
            extended: None,
        }
    }
}