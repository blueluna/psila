use core::convert::From;

use psila_crypto_trait;

/// Errors
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// Not enough space for the operation
    NotEnoughSpace,
    /// Wrong number of bytes provided to the operation
    WrongNumberOfBytes,
    /// The value provided is invalid
    InvalidValue,
    /// The code path has not been implemented
    NotImplemented,
    UnknownFrameType,
    BrokenRelayList,
    UnknownNetworkCommand,
    UnknownDeliveryMode,
    UnknownSecurityLevel,
    UnknownKeyIdentifier,
    UnknownApplicationCommandIdentifier,
    UnknownDiscoverRoute,
    UnknownClusterIdentifier,
    UnsupportedAttributeValue,
    CryptoError(psila_crypto_trait::Error),
}

impl From<psila_crypto_trait::Error> for Error {
    fn from(error: psila_crypto_trait::Error) -> Self {
        Self::CryptoError(error)
    }
}
