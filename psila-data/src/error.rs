//! # Error handling

use core::convert::From;

use psila_crypto;

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
    /// There is no short address
    NoShortAddress,
    /// There is no extended address
    NoExtendedAddress,
    /// The frame type is unknown
    UnknownFrameType,
    /// The relay list is broken
    BrokenRelayList,
    /// The network command is unknown
    UnknownNetworkCommand,
    /// The delivery mode is unknown
    UnknownDeliveryMode,
    /// The security level is unknown
    UnknownSecurityLevel,
    /// The Key indetifier is unknown
    UnknownKeyIdentifier,
    /// The application command identifier is unknown
    UnknownApplicationCommandIdentifier,
    /// The discovery route identifier is unknown
    UnknownDiscoverRoute,
    /// The cluster identifier is unknown
    UnknownClusterIdentifier,
    /// The attribute value is unsupported
    UnsupportedAttributeValue,
    /// A crypto error has occurd
    CryptoError(psila_crypto::Error),
}

impl From<psila_crypto::Error> for Error {
    fn from(error: psila_crypto::Error) -> Self {
        Self::CryptoError(error)
    }
}
