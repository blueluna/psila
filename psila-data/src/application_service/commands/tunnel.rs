use crate::common::address::{ExtendedAddress, EXTENDED_ADDRESS_SIZE};
use crate::pack::{Pack, PackFixed};
use crate::Error;

/// Tunnel command
///
/// NOT FINISHED
///
/// This command also holds the application service and security service
/// headers.
#[derive(Clone, Debug, PartialEq)]
pub struct Tunnel {
    /// Extended address of the destination device
    destination: ExtendedAddress,
}

impl Pack<Tunnel, Error> for Tunnel {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < EXTENDED_ADDRESS_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        self.destination.pack(&mut data[..EXTENDED_ADDRESS_SIZE])?;
        Ok(EXTENDED_ADDRESS_SIZE)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < EXTENDED_ADDRESS_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let destination = ExtendedAddress::unpack(&data[..EXTENDED_ADDRESS_SIZE])?;
        Ok((Self { destination }, EXTENDED_ADDRESS_SIZE))
    }
}
