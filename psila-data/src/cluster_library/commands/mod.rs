//! Cluster library commands

mod attributes;
mod default_response;

use core::convert::TryFrom;

use crate::pack::Pack;
use crate::Error;

pub use attributes::{
    AttributeStatus, DiscoverAttributes, DiscoverAttributesResponse, ReadAttributes,
    ReadAttributesResponse, ReportAttributes, WriteAttributeStatus, WriteAttributes,
    WriteAttributesResponse,
};
pub use default_response::DefaultResponse;

extended_enum!(
    /// Cluster library general command identifiers
    GeneralCommandIdentifier, u8,
    /// Read attributes request
    ReadAttributes => 0x00,
    /// Read attributes response
    ReadAttributesResponse => 0x01,
    /// Write attributes request
    WriteAttributes => 0x02,
    /// Write attributes undivided request
    ///
    /// Writes attributes, but do not generate error if the attribute does not exists on the device
    WriteAttributesUndivided => 0x03,
    /// Write attributes response
    WriteAttributesResponse => 0x04,
    /// Write attributes, do not generate a response
    WriteAttributesNoResponse => 0x05,
    /// Configure reporting request for attributes
    ConfigureReporting => 0x06,
    /// Report configuration response
    ConfigureReportingResponse => 0x07,
    /// Read reporting configuration request
    ReadReportingConfiguration => 0x08,
    /// Read reporting configuration response
    ReadReportingConfigurationResponse => 0x09,
    /// Report attributes
    ReportAttributes => 0x0a,
    /// Default response
    DefaultResponse => 0x0b,
    /// Discover attributes request
    DiscoverAttributes => 0x0c,
    /// Discover attributes response
    DiscoverAttributesResponse => 0x0d,
    /// Read structured attributes request
    ReadAttributesStructured => 0x0e,
    /// Write structured attributes request
    WriteAttributesStructured => 0x0f,
    /// Write structured attributes response
    WriteAttributesStructuredResponse => 0x10,
    /// Discover commands received request
    DiscoverCommandsReceived => 0x11,
    /// Discover commands received response
    DiscoverCommandsReceivedResponse => 0x12,
    /// Discover commands generated request
    DiscoverCommandsGenerated => 0x13,
    /// Discover commands generated response
    DiscoverCommandsGeneratedResponse => 0x14,
    /// Discover attributes request, extended
    DiscoverAttributesExtended => 0x15,
    /// Discover attributes response, extended
    DiscoverAttributesExtendedResponse => 0x16,
);

/// Cluster library general command
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// Read attributes request
    ReadAttributes(ReadAttributes),
    /// Read attributes response
    ReadAttributesResponse(ReadAttributesResponse),
    /// Write attributes request
    WriteAttributes(WriteAttributes),
    /// Write attributes undivided request
    ///
    /// Writes attributes, but do not generate error if the attribute does not exists on the device
    WriteAttributesUndivided(WriteAttributes),
    /// Write attributes response
    WriteAttributesResponse(WriteAttributesResponse),
    /// Write attributes, do not generate a response
    WriteAttributesNoResponse(WriteAttributes),
    /// Configure reporting request for attribtues
    ConfigureReporting,
    /// Report configuration response
    ConfigureReportingResponse,
    /// Read reporting configuration request
    ReadReportingConfiguration,
    /// Read reporting configuration response
    ReadReportingConfigurationResponse,
    /// Report attributes
    ReportAttributes(ReportAttributes),
    /// Default response
    DefaultResponse(DefaultResponse),
    /// Disover attribtues request
    DiscoverAttributes(DiscoverAttributes),
    /// Discover attributes response
    DiscoverAttributesResponse(DiscoverAttributesResponse),
    /// Read structured attributes request
    ReadAttributesStructured,
    /// Write structured attributes request
    WriteAttributesStructured,
    /// Write structured attributes response
    WriteAttributesStructuredResponse,
    /// Discover commands received request
    DiscoverCommandsReceived,
    /// Discover commands received response
    DiscoverCommandsReceivedResponse,
    /// Discover commands generated request
    DiscoverCommandsGenerated,
    /// Discover commands generated response
    DiscoverCommandsGeneratedResponse,
    /// Discover attributes request, extended
    DiscoverAttributesExtended,
    /// Discover attributes response, extended
    DiscoverAttributesExtendedResponse,
}

impl Command {
    /// pack command into byte slice
    pub fn pack(&self, data: &mut [u8]) -> Result<(usize, GeneralCommandIdentifier), Error> {
        let used = match self {
            Command::ReadAttributes(cmd) => cmd.pack(data)?,
            Command::ReadAttributesResponse(cmd) => cmd.pack(data)?,
            Command::WriteAttributes(cmd) => cmd.pack(data)?,
            Command::WriteAttributesUndivided(cmd) => cmd.pack(data)?,
            Command::WriteAttributesResponse(cmd) => cmd.pack(data)?,
            Command::WriteAttributesNoResponse(cmd) => cmd.pack(data)?,
            Command::ConfigureReporting => 0,
            Command::ConfigureReportingResponse => 0,
            Command::ReadReportingConfiguration => 0,
            Command::ReadReportingConfigurationResponse => 0,
            Command::ReportAttributes(cmd) => cmd.pack(data)?,
            Command::DefaultResponse(cmd) => cmd.pack(data)?,
            Command::DiscoverAttributes(cmd) => cmd.pack(data)?,
            Command::DiscoverAttributesResponse(cmd) => cmd.pack(data)?,
            Command::ReadAttributesStructured => 0,
            Command::WriteAttributesStructured => 0,
            Command::WriteAttributesStructuredResponse => 0,
            Command::DiscoverCommandsReceived => 0,
            Command::DiscoverCommandsReceivedResponse => 0,
            Command::DiscoverCommandsGenerated => 0,
            Command::DiscoverCommandsGeneratedResponse => 0,
            Command::DiscoverAttributesExtended => 0,
            Command::DiscoverAttributesExtendedResponse => 0,
        };
        Ok((used, self.command_identifier()))
    }
    /// unpack byte slice into command
    pub fn unpack(data: &[u8], command: GeneralCommandIdentifier) -> Result<(Self, usize), Error> {
        match command {
            GeneralCommandIdentifier::ReadAttributes => {
                let (cmd, used) = ReadAttributes::unpack(&data)?;
                Ok((Command::ReadAttributes(cmd), used))
            }
            GeneralCommandIdentifier::ReadAttributesResponse => {
                let (cmd, used) = ReadAttributesResponse::unpack(&data)?;
                Ok((Command::ReadAttributesResponse(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributes => {
                let (cmd, used) = WriteAttributes::unpack(&data)?;
                Ok((Command::WriteAttributes(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributesUndivided => {
                let (cmd, used) = WriteAttributes::unpack(&data)?;
                Ok((Command::WriteAttributesUndivided(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributesResponse => {
                let (cmd, used) = WriteAttributesResponse::unpack(&data)?;
                Ok((Command::WriteAttributesResponse(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributesNoResponse => {
                let (cmd, used) = WriteAttributes::unpack(&data)?;
                Ok((Command::WriteAttributesNoResponse(cmd), used))
            }
            GeneralCommandIdentifier::ConfigureReporting => Ok((Command::ConfigureReporting, 0)),
            GeneralCommandIdentifier::ConfigureReportingResponse => {
                Ok((Command::ConfigureReportingResponse, 0))
            }
            GeneralCommandIdentifier::ReadReportingConfiguration => {
                Ok((Command::ReadReportingConfiguration, 0))
            }
            GeneralCommandIdentifier::ReadReportingConfigurationResponse => {
                Ok((Command::ReadReportingConfigurationResponse, 0))
            }
            GeneralCommandIdentifier::ReportAttributes => {
                let (cmd, used) = ReportAttributes::unpack(&data)?;
                Ok((Command::ReportAttributes(cmd), used))
            }
            GeneralCommandIdentifier::DefaultResponse => {
                let (cmd, used) = DefaultResponse::unpack(&data)?;
                Ok((Command::DefaultResponse(cmd), used))
            }
            GeneralCommandIdentifier::DiscoverAttributes => {
                let (cmd, used) = DiscoverAttributes::unpack(&data)?;
                Ok((Command::DiscoverAttributes(cmd), used))
            }
            GeneralCommandIdentifier::DiscoverAttributesResponse => {
                let (cmd, used) = DiscoverAttributesResponse::unpack(&data)?;
                Ok((Command::DiscoverAttributesResponse(cmd), used))
            }
            GeneralCommandIdentifier::ReadAttributesStructured => {
                Ok((Command::ReadAttributesStructured, 0))
            }
            GeneralCommandIdentifier::WriteAttributesStructured => {
                Ok((Command::WriteAttributesStructured, 0))
            }
            GeneralCommandIdentifier::WriteAttributesStructuredResponse => {
                Ok((Command::WriteAttributesStructuredResponse, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsReceived => {
                Ok((Command::DiscoverCommandsReceived, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsReceivedResponse => {
                Ok((Command::DiscoverCommandsReceivedResponse, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsGenerated => {
                Ok((Command::DiscoverCommandsGenerated, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsGeneratedResponse => {
                Ok((Command::DiscoverCommandsGeneratedResponse, 0))
            }
            GeneralCommandIdentifier::DiscoverAttributesExtended => {
                Ok((Command::DiscoverAttributesExtended, 0))
            }
            GeneralCommandIdentifier::DiscoverAttributesExtendedResponse => {
                Ok((Command::DiscoverAttributesExtendedResponse, 0))
            }
        }
    }
    /// Get the commands identifier for the command
    pub fn command_identifier(&self) -> GeneralCommandIdentifier {
        match self {
            Command::ReadAttributes(_) => GeneralCommandIdentifier::ReadAttributes,
            Command::ReadAttributesResponse(_) => GeneralCommandIdentifier::ReadAttributesResponse,
            Command::WriteAttributes(_) => GeneralCommandIdentifier::WriteAttributes,
            Command::WriteAttributesUndivided(_) => {
                GeneralCommandIdentifier::WriteAttributesUndivided
            }
            Command::WriteAttributesResponse(_) => {
                GeneralCommandIdentifier::WriteAttributesResponse
            }
            Command::WriteAttributesNoResponse(_) => {
                GeneralCommandIdentifier::WriteAttributesNoResponse
            }
            Command::ConfigureReporting => GeneralCommandIdentifier::ConfigureReporting,
            Command::ConfigureReportingResponse => {
                GeneralCommandIdentifier::ConfigureReportingResponse
            }
            Command::ReadReportingConfiguration => {
                GeneralCommandIdentifier::ReadReportingConfiguration
            }
            Command::ReadReportingConfigurationResponse => {
                GeneralCommandIdentifier::ReadReportingConfigurationResponse
            }
            Command::ReportAttributes(_) => GeneralCommandIdentifier::ReportAttributes,
            Command::DefaultResponse(_) => GeneralCommandIdentifier::DefaultResponse,
            Command::DiscoverAttributes(_) => GeneralCommandIdentifier::DiscoverAttributes,
            Command::DiscoverAttributesResponse(_) => {
                GeneralCommandIdentifier::DiscoverAttributesResponse
            }
            Command::ReadAttributesStructured => GeneralCommandIdentifier::ReadAttributesStructured,
            Command::WriteAttributesStructured => {
                GeneralCommandIdentifier::WriteAttributesStructured
            }
            Command::WriteAttributesStructuredResponse => {
                GeneralCommandIdentifier::WriteAttributesStructuredResponse
            }
            Command::DiscoverCommandsReceived => GeneralCommandIdentifier::DiscoverCommandsReceived,
            Command::DiscoverCommandsReceivedResponse => {
                GeneralCommandIdentifier::DiscoverCommandsReceivedResponse
            }
            Command::DiscoverCommandsGenerated => {
                GeneralCommandIdentifier::DiscoverCommandsGenerated
            }
            Command::DiscoverCommandsGeneratedResponse => {
                GeneralCommandIdentifier::DiscoverCommandsGeneratedResponse
            }

            Command::DiscoverAttributesExtended => {
                GeneralCommandIdentifier::DiscoverAttributesExtended
            }
            Command::DiscoverAttributesExtendedResponse => {
                GeneralCommandIdentifier::DiscoverAttributesExtendedResponse
            }
        }
    }
}
