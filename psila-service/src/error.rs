use core::convert::From;

/// Errors
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The provided PAN identifier is invalid
    InvalidPanIdentifier,
    /// The provided short address is invalid
    InvalidShortAddress,
    /// The provided extended address is invalid
    InvalidExtendedAddress,
    /// The provided address is invalid
    InvalidAddress,
    /// Could not parse the packet
    MalformedPacket,
    /// Not enough space to complete the operation
    NotEnoughSpace,
    /// A psila-data error occurred
    DataError(psila_data::Error),
    /// A psila-crypto error occurred
    CryptoError(psila_crypto::Error),
}

impl From<psila_data::Error> for Error {
    /// From a psila-data error
    fn from(error: psila_data::Error) -> Self {
        Self::DataError(error)
    }
}

impl From<psila_crypto::Error> for Error {
    /// From a psila-crypto error
    fn from(error: psila_crypto::Error) -> Self {
        Self::CryptoError(error)
    }
}

impl From<byte::Error> for Error {
    /// From a byte error
    fn from(error: byte::Error) -> Self {
        match error {
            byte::Error::Incomplete => Error::NotEnoughSpace,
            byte::Error::BadOffset(_) => Error::MalformedPacket,
            byte::Error::BadInput { err: _ } => Error::MalformedPacket,
        }
    }
}
