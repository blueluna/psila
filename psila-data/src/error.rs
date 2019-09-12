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
    CryptoError(u32),
}
