use crate::common::address::{NetworkAddress, SHORT_ADDRESS_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

#[derive(Clone, Debug, PartialEq)]
pub struct RouteRecord {
    num_entries: u8,
    entries: [NetworkAddress; 32],
}

impl RouteRecord {
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }

    pub fn len(&self) -> usize {
        self.num_entries as usize
    }

    pub fn entries(&self) -> &[NetworkAddress] {
        &self.entries[..self.num_entries as usize]
    }
}

impl Pack<RouteRecord, Error> for RouteRecord {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 1 + self.num_entries as usize * 2 {
            Err(Error::WrongNumberOfBytes)
        } else {
            data[0] = self.num_entries;
            let mut offset = 1;
            for address in &self.entries[..self.num_entries as usize] {
                address.pack(&mut data[offset..offset + SHORT_ADDRESS_SIZE])?;
                offset += SHORT_ADDRESS_SIZE;
            }
            Ok(offset)
        }
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let count = data[0] as usize;
        if data.len() < 1 + (count * SHORT_ADDRESS_SIZE) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 1;
        let mut entries = [NetworkAddress::default(); 32];
        for entry in entries[..count].iter_mut() {
            *entry = NetworkAddress::unpack(&data[offset..offset + SHORT_ADDRESS_SIZE])?;
            offset += SHORT_ADDRESS_SIZE;
        }

        Ok((
            RouteRecord {
                num_entries: data[0],
                entries,
            },
            offset,
        ))
    }
}
