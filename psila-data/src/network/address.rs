use crate::{GroupIdentifier, NetworkAddress};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressType {
    Singlecast(NetworkAddress),
    Multicast(GroupIdentifier),
}
