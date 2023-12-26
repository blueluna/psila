use crate::Error;
use psila_crypto::CryptoBackend;
use psila_data::{
    application_service::commands::transport_key::NetworkKey,
    network::NetworkHeader,
    pack::Pack,
    security::{CryptoProvider, KeyIdentifier, SecurityHeader, SecurityLevel},
    ExtendedAddress, Key,
};

pub struct SecurityManager<CB> {
    crypto_provider: CryptoProvider<CB>,
    default_link_key: Key,
    network_key: Option<NetworkKey>,
    security_level: SecurityLevel,
    sequence: u32,
}

impl<CB> SecurityManager<CB>
where
    CB: CryptoBackend,
{
    pub fn new(crypto_backend: CB, default_link_key: Key) -> Self {
        Self {
            crypto_provider: CryptoProvider::new(crypto_backend),
            default_link_key,
            network_key: None,
            security_level: SecurityLevel::EncryptedIntegrity32,
            sequence: 0,
        }
    }

    fn get_key(&self, header: &SecurityHeader) -> Option<Key> {
        match header.control.identifier {
            KeyIdentifier::Data => {
                #[cfg(feature = "defmt")]
                defmt::info!("Data key");
                None
            }
            KeyIdentifier::Network => self.network_key.map(|k| k.key),
            KeyIdentifier::KeyTransport => {
                #[cfg(feature = "defmt")]
                defmt::info!("Key-transport key");
                Some(self.default_link_key)
            }
            KeyIdentifier::KeyLoad => {
                #[cfg(feature = "defmt")]
                defmt::info!("Key-load key");
                Some(self.default_link_key)
            }
        }
    }

    pub fn set_network_key(&mut self, key: NetworkKey) {
        self.network_key = Some(key);
    }

    pub fn decrypt_payload(
        &mut self,
        payload: &[u8],
        secure_header_offset: usize,
        output_payload: &mut [u8],
    ) -> Result<usize, Error> {
        let (header, _used) = SecurityHeader::unpack(&payload[secure_header_offset..])?;
        let size = if let Some(key) = self.get_key(&header) {
            self.crypto_provider.decrypt_payload(
                &key.into(),
                self.security_level,
                payload,
                secure_header_offset,
                output_payload,
            )?
        } else {
            #[cfg(feature = "defmt")]
            defmt::warn!("No key found");
            0
        };
        Ok(size)
    }

    pub fn encrypt_network_payload(
        &mut self,
        source_address: ExtendedAddress,
        header: NetworkHeader,
        payload: &[u8],
        encrypted_payload: &mut [u8],
    ) -> Result<usize, Error> {
        let (key_sequence, key) = if let Some(network_key) = self.network_key {
            (network_key.sequence, network_key.key)
        } else {
            return Err(Error::CryptoError(psila_crypto::Error::InvalidKey));
        };
        let security_header = SecurityHeader::network_header(
            self.security_level,
            self.sequence,
            source_address,
            key_sequence,
        );
        let size = self.crypto_provider.encrypt_network_frame(
            header,
            &key.into(),
            security_header,
            payload,
            encrypted_payload,
        )?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(size)
    }
}
