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
    ReadAttributes => 0x00,
    ReadAttributesResponse => 0x01,
    WriteAttributes => 0x02,
    WriteAttributesUndivided => 0x03,
    WriteAttributesResponse => 0x04,
    WriteAttributesNoResponse => 0x05,
    ConfigureReporting => 0x06,
    ConfigureReportingResponse => 0x07,
    ReadReportingConfiguration => 0x08,
    ReadReportingConfigurationResponse => 0x09,
    ReportAttributes => 0x0a,
    DefaultResponse => 0x0b,
    DiscoverAttributes => 0x0c,
    DiscoverAttributesResponse => 0x0d,
    ReadAttributesStructured => 0x0e,
    WriteAttributesStructured => 0x0f,
    WriteAttributesStructuredResponse => 0x10,
    DiscoverCommandsReceived => 0x11,
    DiscoverCommandsReceivedResponse => 0x12,
    DiscoverCommandsGenerated => 0x13,
    DiscoverCommandsGeneratedResponse => 0x14,
    DiscoverAttributesExtended => 0x15,
    DiscoverAttributesExtendedResponse => 0x16,
);

/// Cluster library general command
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    ReadAttributes(ReadAttributes),
    ReadAttributesResponse(ReadAttributesResponse),
    WriteAttributes(WriteAttributes),
    WriteAttributesUndivided(WriteAttributes),
    WriteAttributesResponse(WriteAttributesResponse),
    WriteAttributesNoResponse(WriteAttributes),
    ConfigureReporting,
    ConfigureReportingResponse,
    ReadReportingConfiguration,
    ReadReportingConfigurationResponse,
    ReportAttributes(ReportAttributes),
    DefaultResponse(DefaultResponse),
    DiscoverAttributes(DiscoverAttributes),
    DiscoverAttributesResponse(DiscoverAttributesResponse),
    ReadAttributesStructured,
    WriteAttributesStructured,
    WriteAttributesStructuredResponse,
    DiscoverCommandsReceived,
    DiscoverCommandsReceivedResponse,
    DiscoverCommandsGenerated,
    DiscoverCommandsGeneratedResponse,
    DiscoverAttributesExtended,
    DiscoverAttributesExtendedResponse,
}

impl Command {
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
