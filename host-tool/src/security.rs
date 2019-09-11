use std::convert::From;

use gcrypt;
use psila_data::application_service::commands::transport_key::NetworkKey;
use psila_data::{common::key::Key, pack::Pack, security};

pub struct SecurityService {
    pub keys: Vec<(Key, String)>,
}

impl SecurityService {
    pub fn new() -> Self {
        gcrypt::init_default();
        let mut keys = Vec::new();
        keys.push((
            Key::from(security::DEFAULT_LINK_KEY),
            "Default Link Key".to_string(),
        ));
        keys.push((
            Key::from(security::LIGHT_LINK_MASTER_KEY),
            "Light Link Master Key".to_string(),
        ));
        keys.push((
            Key::from(security::LIGHT_LINK_COMMISIONING_LINK_KEY),
            "Light Link Commisioning Link Key".to_string(),
        ));
        SecurityService { keys }
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

    pub fn decrypt(&self, payload: &[u8], offset: usize, mut output: &mut [u8]) -> usize {
        print!("SEC ");
        match security::SecurityHeader::unpack(&payload[offset..]) {
            Ok((header, _used)) => Self::print_header(&header),
            Err(e) => {
                println!(" Failed to parse security header, {:?}", e);
                return 0;
            }
        }
        for (key, key_name) in self.keys.iter() {
            let key = (*key).into();
            let result = security::handle_secure_payload(
                &key,
                security::SecurityLevel::EncryptedIntegrity32,
                &payload,
                offset,
                &mut output,
            );
            match result {
                Ok(size) => {
                    if size > 0 {
                        println!(" Key \"{}\"", key_name);
                        return size;
                    }
                }
                Err(e) => {
                    println!(" Decryption failed, {:?}", e);
                }
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
