//! # Cluster Library (ZCL)

use core::convert::TryFrom;

use crate::common::address::ShortAddress;
use crate::Error;

mod attribute;
pub mod basic;
pub mod commands;
mod frame;

pub use attribute::{AttributeDataType, AttributeValue};
pub use commands::{Command, GeneralCommandIdentifier};
pub use frame::{ClusterLibraryHeader, Direction, FrameType};

/// 16-bit attribute identifier
pub type AttributeIdentifier = ShortAddress;

extended_enum!(
    /// Cluster library status codes
    ClusterLibraryStatus, u8,
    /// Operation was successful.
    Success => 0x00,
    /// Operation was not successful.
    Failure => 0x01,
    /// The sender of the command does not have authorisation to carry out this command.
    NotAuthorised => 0x7e,
    /// A reserved field/subfield/bit contains a non-zero value.
    ReservedFieldNotZero => 0x7f,
    /// The command appears to contain the wrong fields, as detected either by the presence of one or more invalid field entries or by there being missing fields. Command not carried out.
    MalformedCommand => 0x80,
    /// The specified cluster command is not supported on the device. Command not carried out.
    UnsupportedClusterCommand => 0x81,
    /// The specified general ZCL command is not supported on the device.
    UnsupportedGeneralCommand => 0x82,
    /// A manufacturer specific unicast, cluster specific command was received with an unknown manufacturer code, or the manufacturer code was recognised but the command is not supported.
    UnsupportedManufacturerClusterCommand => 0x83,
    /// A manufacturer specific unicast, ZCL specific command was received with an unknown manufacturer code, or the manufacturer code was recognised but the command is not supported.
    UnsupportedManufacturerGeneralCommand => 0x84,
    /// At least one field of the command contains an incorrect value, according to the specification the device is implemented to.
    InvalidField => 0x85,
    /// The specified attribute does not exist on the device.
    UnsupportedAttribute => 0x86,
    /// Out of range error, or set to a reserved value. Attribute keeps its old value.
    InvalidValue => 0x87,
    /// Attempt to write a read only attribute.
    ReadOnly => 0x88,
    /// An operation failed due to an insufficient amount of free space available.
    InsufficientSpace => 0x89,
    /// An attempt to create an entry in a table failed due to a duplicate entry already being present in the table.
    DuplicateExists => 0x8a,
    /// The requested information (e.g., table entry) could not be found.
    NotFound => 0x8b,
    /// Periodic reports cannot be issued for this attribute.
    UnreportableAttribute => 0x8c,
    /// The data type given for an attribute is incorrect. Command not carried out.
    InvalidDataType => 0x8d,
    /// The selector for an attribute is incorrect.
    InvalidSelector => 0x8e,
    /// A request has been made to read an attribute that the requestor is not authorised to read. No action taken.
    WriteOnly => 0x8f,
    /// Setting the requested values would put the device in an inconsistent state on startup. No action taken.
    InconsistentStartupState => 0x90,
    /// An attempt has been made to write an attribute that is present but is defined using an out-of-band method and not over the air.
    DefinedOutOfBand => 0x91,
    /// The supplied values (e.g., contents of table cells) are inconsistent.
    Inconsistent => 0x92,
    /// The credentials presented by the device sending the command are not sufficient to perform this action.
    ActionDenied => 0x93,
    /// The exchange was aborted due to excessive response time.
    Timeout => 0x94,
    /// Failed case when a client or a server decides to abort the upgrade process.
    Abort => 0x95,
    /// Invalid OTA upgrade image (ex. failed signature validation or signer information check or CRC check).
    InvalidImage => 0x96,
    /// Server does not have data block available yet.
    WaitForData => 0x97,
    /// No OTA upgrade image available for a particular client.
    NoImageAvailable => 0x98,
    /// The client still requires more OTA upgrade image files in order to successfully upgrade.
    RequiteMoreImage => 0x99,
    /// The command has been received and is being processed.
    NotificationPending => 0x9a,
    /// An operation was unsuccessful due to a hardware failure.
    HardwareFailure => 0xc0,
    /// An operation was unsuccessful due to a software failure.
    SoftwareFailure => 0xc1,
    /// An error occurred during calibration.
    CalibrationError => 0xc2,
    /// The cluster is not supported.
    UnsupportedCluster => 0xc3,
);

/// Cluster library destination, either end-point or group.
#[derive(Clone)]
pub enum Destination
{
    /// End-point destination
    Endpoint(u8),
    /// Group destination
    Group(u16),
}
