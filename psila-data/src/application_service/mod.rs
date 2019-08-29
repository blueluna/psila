use core::convert::TryFrom;

pub mod commands;
pub mod header;

use crate::Error;

pub use commands::Command;
pub use header::ApplicationServiceHeader;

extended_enum!(
    /// Status codes used in the application service sub-system
    ApplicationServiceStatus, u8,
    /// Request succeded
    Success => 0x00,
    /// A transmit request failed since the ASDU is too large and
    /// fragmentation is not supported.
    FrameTooLong => 0xa0,
    /// A received fragmented frame could not be defragmented at the
    /// current time.
    DefragmentationDeferred => 0xa1,
    /// A received fragmented frame could not be defragmented since
    /// the device does not support fragmentation.
    DefragmentationUnsupported => 0xa2,
    /// A parameter value was out of range.
    IllegalRequest => 0xa3,
    /// An APSME-UNBIND.request failed due to the requested
    /// binding link not existing in the binding table.
    InvalidBinding => 0xa4,
    /// An APSME-REMOVE-GROUP.request has been issued with
    /// a group identifier that does not appear in the group table.
    InvalidGroup => 0xa5,
    /// A parameter value was invalid or out of range.
    InvalidParameter => 0xa6,
    /// An APSDE-DATA.request requesting acknowledged trans-
    /// mission failed due to no acknowledgement being received.
    NoAcknowledge => 0xa7,
    /// An APSDE-DATA.request with a destination addressing mode
    /// set to 0x00 failed due to there being no devices bound to this
    /// device.
    NoBoundDevice => 0xa8,
    /// An APSDE-DATA.request with a destination addressing mode
    /// set to 0x03 failed due to no corresponding short address found
    /// in the address map table.
    NoShortAddress => 0xa9,
    /// An APSDE-DATA.request with a destination addressing mode
    /// set to 0x00 failed due to a binding table not being supported on
    /// the device.
    NotSupported => 0xaa,
    /// An ASDU was received that was secured using a link key.
    SecuredLinkKey => 0xab,
    /// An ASDU was received that was secured using a network key.
    SecuredNetworkKey => 0xac,
    /// An APSDE-DATA.request requesting security has resulted in
    /// an error during the corresponding security processing.
    SecurityFailure => 0xad,
    /// An APSME-BIND.request or APSME.ADD-GROUP.request
    /// issued when the binding or group tables, respectively, were
    /// full.
    TableFull => 0xae,
    /// An ASDU was received without any security.
    Unsecured => 0xaf,
    /// An APSME-GET.request or APSME-SET.request has been
    /// issued with an unknown attribute identifier.
    UnsupportedAttribute => 0xb0,
);
