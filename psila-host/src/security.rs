use std::convert::From;

use psila_crypto_rust_crypto::RustCryptoBackend;
use psila_data::application_service::commands::transport_key::NetworkKey;
use psila_data::{common::key::Key, pack::Pack, security};

pub struct SecurityService {
    pub keys: Vec<(Key, String)>,
    crypto_provider: security::CryptoProvider<RustCryptoBackend>,
}

impl SecurityService {
    pub fn new() -> Self {
        let mut keys = Vec::new();
        keys.push((
            Key::from(security::DEFAULT_LINK_KEY),
            "Default Link Key".to_string(),
        ));
        let backend = RustCryptoBackend::default();
        let crypto_provider = security::CryptoProvider::new(backend);
        SecurityService {
            keys,
            crypto_provider,
        }
    }

    fn print_header(header: &security::SecurityHeader) {
        print!(
            "Level {:?} Key Identifier {:?}",
            header.control.level, header.control.identifier
        );
        if let Some(src) = header.source {
            print!(" Source {}", src);
        }
        if let Some(seq) = header.sequence {
            print!(" Sequence {}", seq);
        }
        print!(" Counter {}", header.counter);
    }

    pub fn decrypt(&mut self, payload: &[u8], offset: usize, mut output: &mut [u8]) -> usize {
        print!("SEC ");
        match security::SecurityHeader::unpack(&payload[offset..]) {
            Ok((header, used)) => {
                Self::print_header(&header);
                print!(" {} bytes", payload.len() - offset - used);
            }
            Err(e) => {
                println!(" Failed to parse security header, {:?}", e);
                return 0;
            }
        }
        for (key, key_name) in self.keys.iter() {
            let key = (*key).into();
            let result = self.crypto_provider.decrypt_payload(
                &key,
                security::SecurityLevel::EncryptedIntegrity32,
                &payload,
                offset,
                &mut output,
            );
            match result {
                Ok(size) => {
                    if size > 0 {
                        println!(" {} bytes Key \"{}\"", size, key_name);
                        for b in &output[..size] {
                            print!("{:02x}", b);
                        }
                        println!();
                        return size;
                    }
                }
                Err(_e) => (),
            }
        }
        println!(" No valid key found");
        0
    }

    pub fn add_key(&mut self, key: [u8; 16], name: &str) {
        self.keys.push((Key::from(key), name.to_string()));
    }

    pub fn add_transport_key(&mut self, new_key: &NetworkKey) {
        for (key, _) in self.keys.iter() {
            if *key == new_key.key {
                return;
            }
        }
        self.keys
            .push((new_key.key, format!("Transport Key {}", new_key.source)));
    }
}
