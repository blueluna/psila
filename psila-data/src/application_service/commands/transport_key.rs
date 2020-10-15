//! Handling of key transport

use core::convert::TryFrom;

use crate::common::address::{ExtendedAddress, EXTENDED_ADDRESS_SIZE};
use crate::common::key::{Key, KeyType, KEY_SIZE};
use crate::pack::{Pack, PackFixed};
use crate::Error;

// 4.4.9.2.3.1 Trust Center Master or Link Key Descriptor Field
/// Trust center key descriptor
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TrustCenterKey {
    /// The key
    pub key: Key,
    /// Destination address for the key
    pub destination: ExtendedAddress,
    /// Source address for the key
    pub source: ExtendedAddress,
}

/// Size of a TrustCenterKey
pub const TRUST_CENTER_KEY_SIZE: usize = KEY_SIZE + EXTENDED_ADDRESS_SIZE + EXTENDED_ADDRESS_SIZE;

impl PackFixed<TrustCenterKey, Error> for TrustCenterKey {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != TRUST_CENTER_KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        self.key.pack(&mut data[..KEY_SIZE])?;
        self.destination
            .pack(&mut data[KEY_SIZE..KEY_SIZE + EXTENDED_ADDRESS_SIZE])?;
        self.source.pack(
            &mut data[KEY_SIZE + EXTENDED_ADDRESS_SIZE
                ..KEY_SIZE + EXTENDED_ADDRESS_SIZE + EXTENDED_ADDRESS_SIZE],
        )?;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != TRUST_CENTER_KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let key = Key::unpack(&data[..KEY_SIZE])?;
        let destination =
            ExtendedAddress::unpack(&data[KEY_SIZE..KEY_SIZE + EXTENDED_ADDRESS_SIZE])?;
        let source = ExtendedAddress::unpack(
            &data[KEY_SIZE + EXTENDED_ADDRESS_SIZE
                ..KEY_SIZE + EXTENDED_ADDRESS_SIZE + EXTENDED_ADDRESS_SIZE],
        )?;
        Ok(Self {
            key,
            destination,
            source,
        })
    }
}

// 4.4.9.2.3.2 Network Key Descriptor Field
/// Network key descriptor
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct NetworkKey {
    /// The key
    pub key: Key,
    /// Key sequence number
    pub sequence: u8,
    /// Destination address for the key
    pub destination: ExtendedAddress,
    /// Source address for the key
    pub source: ExtendedAddress,
}

/// Size of a NetworkKey
pub const NETWORK_KEY_SIZE: usize = KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE + EXTENDED_ADDRESS_SIZE;

impl PackFixed<NetworkKey, Error> for NetworkKey {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != NETWORK_KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        self.key.pack(&mut data[..KEY_SIZE])?;
        data[KEY_SIZE] = self.sequence;
        self.destination
            .pack(&mut data[KEY_SIZE + 1..KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE])?;
        self.source.pack(
            &mut data[KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE
                ..KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE + EXTENDED_ADDRESS_SIZE],
        )?;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != NETWORK_KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let key = Key::unpack(&data[..KEY_SIZE])?;
        let sequence = data[KEY_SIZE];
        let destination =
            ExtendedAddress::unpack(&data[KEY_SIZE + 1..KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE])?;
        let source = ExtendedAddress::unpack(
            &data[KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE
                ..KEY_SIZE + 1 + EXTENDED_ADDRESS_SIZE + EXTENDED_ADDRESS_SIZE],
        )?;
        Ok(Self {
            key,
            sequence,
            destination,
            source,
        })
    }
}

// 4.4.9.2.3.3 Application Master and Link Key Descriptor Field
/// Application key descriptor
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ApplicationKey {
    /// The key
    pub key: Key,
    /// Address to the partner
    pub partner: ExtendedAddress,
    /// Indicates that this is the initiator of the key exchange
    pub initiator: bool,
}

/// Size of a ApplicationKey
pub const APPLICATION_KEY_SIZE: usize = KEY_SIZE + EXTENDED_ADDRESS_SIZE + 1;

impl PackFixed<ApplicationKey, Error> for ApplicationKey {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != APPLICATION_KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        self.key.pack(&mut data[..KEY_SIZE])?;
        self.partner
            .pack(&mut data[KEY_SIZE..KEY_SIZE + EXTENDED_ADDRESS_SIZE])?;
        data[KEY_SIZE + EXTENDED_ADDRESS_SIZE] = self.initiator as u8;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != APPLICATION_KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let key = Key::unpack(&data[..KEY_SIZE])?;
        let partner = ExtendedAddress::unpack(&data[KEY_SIZE..KEY_SIZE + EXTENDED_ADDRESS_SIZE])?;
        let initiator = match data[KEY_SIZE] {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidValue),
        };
        Ok(Self {
            key,
            partner,
            initiator,
        })
    }
}

// 4.4.9.2 Transport-Key Commands
/// Key-transport messages
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TransportKey {
    /// A trust center master key
    TrustCenterMasterKey(TrustCenterKey),
    /// A standard network key
    StandardNetworkKey(NetworkKey),
    /// A application master key
    ApplicationMasterKey(ApplicationKey),
    /// A application link key
    ApplicationLinkKey(ApplicationKey),
    /// A unique trust center link key
    UniqueTrustCenterLinkKey(TrustCenterKey),
    /// A hight security network key
    HighSecurityNetworkKey(NetworkKey),
}

impl TransportKey {
    fn key_type(&self) -> KeyType {
        match *self {
            TransportKey::TrustCenterMasterKey(_) => KeyType::TrustCenterMasterKey,
            TransportKey::StandardNetworkKey(_) => KeyType::StandardNetworkKey,
            TransportKey::ApplicationMasterKey(_) => KeyType::ApplicationMasterKey,
            TransportKey::ApplicationLinkKey(_) => KeyType::ApplicationLinkKey,
            TransportKey::UniqueTrustCenterLinkKey(_) => KeyType::UniqueTrustCenterLinkKey,
            TransportKey::HighSecurityNetworkKey(_) => KeyType::HighSecurityNetworkKey,
        }
    }
}

impl Pack<TransportKey, Error> for TransportKey {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let length = match *self {
            TransportKey::TrustCenterMasterKey(_) | TransportKey::UniqueTrustCenterLinkKey(_) => {
                TRUST_CENTER_KEY_SIZE
            }
            TransportKey::StandardNetworkKey(_) | TransportKey::HighSecurityNetworkKey(_) => {
                NETWORK_KEY_SIZE
            }
            TransportKey::ApplicationMasterKey(_) | TransportKey::ApplicationLinkKey(_) => {
                APPLICATION_KEY_SIZE
            }
        };
        if data.len() != (length + 1) {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.key_type().into();
        match self {
            TransportKey::TrustCenterMasterKey(k) | TransportKey::UniqueTrustCenterLinkKey(k) => {
                k.pack(&mut data[1..=TRUST_CENTER_KEY_SIZE])?
            }
            TransportKey::StandardNetworkKey(k) | TransportKey::HighSecurityNetworkKey(k) => {
                k.pack(&mut data[1..=NETWORK_KEY_SIZE])?
            }
            TransportKey::ApplicationMasterKey(k) | TransportKey::ApplicationLinkKey(k) => {
                k.pack(&mut data[1..=APPLICATION_KEY_SIZE])?
            }
        };
        Ok(1 + length)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let key_type = KeyType::try_from(data[0])?;
        match key_type {
            KeyType::TrustCenterMasterKey => {
                if data.len() < (1 + TRUST_CENTER_KEY_SIZE) {
                    return Err(Error::WrongNumberOfBytes);
                }
                let key = TrustCenterKey::unpack(&data[1..=TRUST_CENTER_KEY_SIZE])?;
                Ok((
                    TransportKey::TrustCenterMasterKey(key),
                    (1 + TRUST_CENTER_KEY_SIZE),
                ))
            }
            KeyType::StandardNetworkKey => {
                if data.len() < (1 + NETWORK_KEY_SIZE) {
                    return Err(Error::WrongNumberOfBytes);
                }
                let key = NetworkKey::unpack(&data[1..=NETWORK_KEY_SIZE])?;
                Ok((
                    TransportKey::StandardNetworkKey(key),
                    (1 + NETWORK_KEY_SIZE),
                ))
            }
            KeyType::ApplicationMasterKey => {
                if data.len() < (1 + APPLICATION_KEY_SIZE) {
                    return Err(Error::WrongNumberOfBytes);
                }
                let key = ApplicationKey::unpack(&data[1..=APPLICATION_KEY_SIZE])?;
                Ok((
                    TransportKey::ApplicationMasterKey(key),
                    (1 + APPLICATION_KEY_SIZE),
                ))
            }
            KeyType::ApplicationLinkKey => {
                if data.len() < (1 + APPLICATION_KEY_SIZE) {
                    return Err(Error::WrongNumberOfBytes);
                }
                let key = ApplicationKey::unpack(&data[1..=APPLICATION_KEY_SIZE])?;
                Ok((
                    TransportKey::ApplicationLinkKey(key),
                    (1 + APPLICATION_KEY_SIZE),
                ))
            }
            KeyType::UniqueTrustCenterLinkKey => {
                if data.len() < (1 + TRUST_CENTER_KEY_SIZE) {
                    return Err(Error::WrongNumberOfBytes);
                }
                let key = TrustCenterKey::unpack(&data[1..=TRUST_CENTER_KEY_SIZE])?;
                Ok((
                    TransportKey::UniqueTrustCenterLinkKey(key),
                    (1 + TRUST_CENTER_KEY_SIZE),
                ))
            }
            KeyType::HighSecurityNetworkKey => {
                if data.len() < (1 + NETWORK_KEY_SIZE) {
                    return Err(Error::WrongNumberOfBytes);
                }
                let key = NetworkKey::unpack(&data[1..=NETWORK_KEY_SIZE])?;
                Ok((
                    TransportKey::HighSecurityNetworkKey(key),
                    (1 + NETWORK_KEY_SIZE),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_network_key() {
        let data = [
            0x01, 0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48, 0x00,
            0x40, 0x64, 0x08, 0x00, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x38, 0x2e,
            0x03, 0xff, 0xff, 0x2e, 0x21, 0x00,
        ];
        let (key, used) = TransportKey::unpack(&data[..]).unwrap();
        assert_eq!(used, 34);
        match key {
            TransportKey::StandardNetworkKey(k) => {
                assert_eq!(
                    k.key,
                    [
                        0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48,
                        0x00, 0x40, 0x64, 0x08
                    ]
                );
                assert_eq!(k.sequence, 0);
                assert_eq!(
                    k.destination,
                    [0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00]
                );
                assert_eq!(k.source, [0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00]);
            }
            _ => unreachable!(),
        }
    }
}
