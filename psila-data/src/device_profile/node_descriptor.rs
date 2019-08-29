use crate::common::address::NetworkAddress;
// use crate::device_profile::Status;
use crate::pack::{Pack, PackFixed};
use crate::Error;

// 2.4.3.1.3 Node_Desc_req
/// Node descriptor request
/// Requests the node descriptor for a remote device
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDescriptorRequest {
    pub address: NetworkAddress,
}

impl Pack<NodeDescriptorRequest, Error> for NodeDescriptorRequest {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        self.address.pack(&mut data[0..2])?;
        Ok(2)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() != 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        Ok((Self { address }, 2))
    }
}
