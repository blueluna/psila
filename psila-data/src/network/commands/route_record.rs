use crate::common::address::{ShortAddress, SHORT_ADDRESS_SIZE};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

#[derive(Clone, Debug, PartialEq)]
pub struct RouteRecord {
    pub relay_list: Vec<ShortAddress>,
}

impl Pack<RouteRecord, Error> for RouteRecord {
    fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
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
        let mut relay_list: Vec<ShortAddress> = Vec::with_capacity(count);
        for _ in 0..count {
            let address = ShortAddress::unpack(&data[offset..offset + SHORT_ADDRESS_SIZE])?;
            offset += SHORT_ADDRESS_SIZE;
            relay_list.push(address);
        }

        Ok((RouteRecord { relay_list }, offset))
    }
}
