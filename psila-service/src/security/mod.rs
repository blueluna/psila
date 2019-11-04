use crate::Error;
use log;
use psila_crypto::CryptoBackend;
use psila_data::{
    application_service::commands::transport_key::NetworkKey,
    pack::Pack,
    security::{CryptoProvider, KeyIdentifier, SecurityHeader, SecurityLevel},
    Key,
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
                log::info!("Data key");
                None
            }
            KeyIdentifier::Network => {
                log::info!("Network key");
                self.network_key.map(|k| k.key)
            }
            KeyIdentifier::KeyTransport => {
                log::info!("Key-transport key");
                Some(self.default_link_key)
            }
            KeyIdentifier::KeyLoad => {
                log::info!("Key-load key");
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
            log::warn!("No key found");
            0
        };
        log::info!("Decrypt result size {}", size);
        Ok(size)
    }

    pub fn encrypt_network_payload(&mut self) -> Result<usize, Error> {
        Ok(0)
    }
}
