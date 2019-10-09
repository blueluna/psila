use core::convert::From;

use psila_crypto;
use psila_data;

/// Errors
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    InvalidPanIdentifier,
    InvalidShortAddress,
    InvalidExtendedAddress,
    InvalidAddress,
    MalformedPacket,
    NotEnoughSpace,
    DataError(psila_data::Error),
    CryptoError(psila_crypto::Error),
}

impl From<psila_data::Error> for Error {
    fn from(error: psila_data::Error) -> Self {
        Self::DataError(error)
    }
}

impl From<psila_crypto::Error> for Error {
    fn from(error: psila_crypto::Error) -> Self {
        Self::CryptoError(error)
    }
}
