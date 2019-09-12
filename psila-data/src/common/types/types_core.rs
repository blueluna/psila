use heapless::{self, consts::U256, String, Vec};

use crate::pack::Pack;
use crate::Error;

pub type OctetString = Vec<u8, U256>;

impl Pack<OctetString, Error> for OctetString {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() <= self.len() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.len() as u8;
        data.copy_from_slice(self.as_ref());
        Ok(self.len() + 1)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let length = data[0] as usize;
        if data.len() <= length {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut value = OctetString::new();
        match value.extend_from_slice(&data[1..=length]) {
            Ok(_) => Ok((value, length + 1)),
            Err(_) => Err(Error::InvalidValue),
        }
    }
}

pub type CharacterString = String<U256>;

impl Pack<CharacterString, Error> for CharacterString {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() <= self.len() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.len() as u8;
        data.copy_from_slice(self.as_ref());
        Ok(self.len() + 1)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let length = data[0] as usize;
        if data.len() <= length {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut value = OctetString::new();
        if value.extend_from_slice(&data[1..=length]).is_err() {
            return Err(Error::InvalidValue);
        }
        match CharacterString::from_utf8(value) {
            Ok(value) => Ok((value, length + 1)),
            Err(_) => Err(Error::InvalidValue),
        }
    }
}
