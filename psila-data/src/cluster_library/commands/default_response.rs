//! Handling of default response to requests

use core::convert::TryFrom;

use crate::cluster_library::ClusterLibraryStatus;
use crate::pack::Pack;
use crate::Error;

/// Default response for request
#[derive(Clone, Debug, PartialEq)]
pub struct DefaultResponse {
    /// Command identifier from the request
    pub command: u8,
    /// Return status of the request
    pub status: ClusterLibraryStatus,
}

impl Pack<DefaultResponse, Error> for DefaultResponse {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = self.command;
        data[1] = u8::from(self.status);
        Ok(2)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let status = ClusterLibraryStatus::try_from(data[1])?;
        Ok((
            Self {
                command: data[0],
                status,
            },
            2,
        ))
    }
}
